"""Builds fictional WatchGuard Policy Manager exports (current + older), a Policy Usage CSV and a denied-traffic CSV
for testing Firewall-Map.html. Everything is invented: RFC 5737 documentation IPs, RFC 2606 .example names."""
import os,random,datetime,csv
from xml.sax.saxutils import escape as X
OUT=os.path.dirname(os.path.abspath(__file__))   # writes next to this script

# ---------- interfaces: name, ip, mask, vlan, zone (1 trusted, 2 external, 3 optional, 8 custom) ----------
IFACES_NOW=[('LAN','10.110.0.1','255.255.255.0',10,1),('Staff','10.120.0.1','255.255.252.0',20,1),('Servers','10.130.0.1','255.255.255.0',30,1),
  ('Secure-DB','10.131.0.1','255.255.255.0',31,8),('Wireless','10.140.0.1','255.255.255.0',40,1),('Guest-WiFi','10.141.0.1','255.255.255.0',41,3),
  ('DMZ','10.150.0.1','255.255.255.0',50,3),('Mgmt','10.105.0.1','255.255.255.0',5,1),('Factory','10.160.0.1','255.255.255.0',60,8),
  ('CCTV','10.170.0.1','255.255.255.0',70,3),('Internet-Primary','203.0.113.2','255.255.255.248',100,2),('Internet-Backup','192.0.2.2','255.255.255.252',101,2)]
BUILTIN_IF=['Any','Any-External','Any-Trusted','Any-Optional','Firebox','Any-BOVPN','Any-MUVPN','SSL-VPN','Any-Multicast']

# ---------- named aliases: name -> list of members ----------
# member forms: ('host',ip) ('net',ip,mask) ('range',a,b) ('fqdn',name) ('alias',name) ('user',group) ('iface',name)
def aliases(older):
  A={
   'Domain-Controllers':[('host','10.130.0.11'),('host','10.130.0.12')]+([] if older else [('host','10.130.0.13')]),
   'DC01':[('host','10.130.0.11'),('fqdn','dc01.corp.example')],'DC02':[('host','10.130.0.12'),('fqdn','dc02.corp.example')],
   'App-Server':[('host','10.130.0.20'),('fqdn','app01.corp.example')],
   'Web-Servers':[('host','10.130.0.30'),('host','10.130.0.31')],
   'WEB_SRV':[('host','10.130.0.30'),('host','10.130.0.31')],                   # same addresses as Web-Servers (tidy-up check)
   'DB-Servers':[('range','10.131.0.10','10.131.0.11')],
   'Backup-Server':[('host','10.130.0.40')],'MES-Server':[('host','10.160.0.20')],'NTP-Server':[('host','10.105.0.10')],
   'Monitoring-Server':[('host','10.105.0.20'),('fqdn','monitor.corp.example')],
   'Printers':[('range','10.110.0.200','10.110.0.220')],
   'CCTV-NVR':[('host','10.170.0.10')],'PLC-Range':[('range','10.160.0.100','10.160.0.150')],'Factory-HMI':[('host','10.160.0.30')],
   'Engineering-PCs':[('host','10.120.1.50'),('host','10.120.1.51')],'IT-Admin-PCs':[('host','10.105.0.50'),('host','10.105.0.51')],
   'Partner-IPs':[('net','198.51.100.0','255.255.255.240')],
   'MSP-Support':[('net','198.51.100.64','255.255.255.248'),('host','192.0.2.200')],
   'OS-Updates':[('fqdn','*.windowsupdate.example'),('fqdn','*.update.example')],
   'SaaS-App':[('fqdn','app.saas.example')],'Cloud-Backup':[('fqdn','backup.storage.example')],
   'Staff-Devices':[('alias','Staff'),('alias','LAN'),('alias','Wireless'),('user','VPN-Users')],
   'Old-Mail-Server':[('host','10.130.0.90')],'Old-FTP-Host':[('host','10.150.0.99')],    # unused aliases
  }
  if not older: A['Jump-Host']=[('host','10.150.0.40')]
  return A

# ---------- static NAT: name -> (external ip, internal ip) ----------
def nats(older):
  N={'Portal':('203.0.113.3','10.150.0.20'),'SFTP':('203.0.113.4','10.150.0.30'),'Mail':('203.0.113.5','10.130.0.90')}
  if not older: N['RDP-Jump']=('203.0.113.6','10.150.0.40')
  else: N['Old-FTP']=('203.0.113.7','10.150.0.99')
  return N

# ---------- policies ----------
# (name, action, from[], to[], service ports[], options)  ports: 'tcp/443', 'udp/53', 'tcp/5000-5010', 'tcp/any', 'udp/any', 'icmp', 'any'
# from/to items: alias names, 'NAT:<name>', 'ip:<addr>', 'user:<group>'
def policies(older):
  P=[
   ('Finance to SaaS - HTTPS-proxy','Proxy',['user:Finance'],['SaaS-App'],['tcp/443'],dict(tags=['Proxy'],proxy='HTTPS-proxy')),
   ('Internet Health Check','Allow',['Monitoring-Server'],['ip:198.51.100.53'],['tcp/53','udp/53','tcp/443'],dict(tags=['Monitoring'])),
   ('App to DB','Allow',['App-Server'],['DB-Servers'],['tcp/1433'],dict(tags=['SQL'])),
   ('Staff to Servers 8443','Allow',['Staff-Devices'],['Servers'],['tcp/8443'],{}),
   ('Staff to App Server 8443','Allow',['Staff-Devices'],['App-Server'],['tcp/8443'],{}),       # never reached: covered by the policy above
   ('Staff to Web Servers','Allow',['Staff-Devices'],['Web-Servers'],['tcp/80','tcp/443'],{}),
   ('Staff Internet - HTTPS-proxy' if not older else 'Internet - HTTPS-proxy','Proxy',['Staff-Devices'],['Any-External'],['tcp/443'],dict(tags=['WebTraffic'],proxy='HTTPS-proxy')),
   ('Staff Internet - HTTP-proxy','Proxy',['Staff-Devices'],['Any-External'],['tcp/80'],dict(tags=['WebTraffic'],proxy='HTTP-proxy')),
   ('Guest WiFi Internet','Allow',['Guest-WiFi'],['Any-External'],['tcp/80','tcp/443'] if older else ['tcp/any','udp/any'],dict(log=False,tags=['Guest'])),
   ('Block Guest to Internal','Block',['Guest-WiFi'],['Any-Trusted'],['any'],{}),
   ('AD Services','Allow',['Any-Trusted','Factory'],['Domain-Controllers'],['tcp/53','udp/53','tcp/88','udp/88','tcp/389','tcp/445','tcp/135'],dict(tags=['AD'])),
   ('DNS Outbound','Allow',['Domain-Controllers'],['Any-External'],['tcp/53','udp/53'],{}),
   ('OS Updates','Allow',['Any'],['OS-Updates'],['tcp/80','tcp/443'],{}),
   ('Print Services','Allow',['Staff-Devices'],['Printers'],['tcp/9100','tcp/445'],dict(tags=['Print'])),
   ('Print Services copy','Allow',['Staff-Devices'],['Printers'],['tcp/9100','tcp/445'],dict(tags=['Print'])),   # duplicate
   ('RDP to Servers','Allow',['Staff-Devices'],['Servers'],['tcp/3389'],{}),
   ('IT Admin Full Access','Allow',['IT-Admin-PCs'],['Any'],['tcp/any','udp/any'],dict(log=False)),
   ('Backup to Cloud','Allow',['Backup-Server'],['Cloud-Backup'],['tcp/443'],dict(tags=['Backup'])),
   ('Backup Server to DB','Allow',['Backup-Server'],['DB-Servers'],['tcp/445','tcp/1433'],dict(tags=['Backup'])),
   ('CCTV Viewing','Allow',['Staff-Devices'],['CCTV-NVR'],['tcp/443','tcp/554'],{}),
   ('CCTV Cloud Upload','Allow',['CCTV'],['Any-External'],['tcp/443'],{}),
   ('Factory PLC Access','Allow',['Engineering-PCs'],['PLC-Range'],['tcp/44818','udp/44818','tcp/502'],dict(tags=['Factory'])),
   ('Factory to MES','Allow',['Factory'],['MES-Server'],['tcp/8080'],dict(tags=['Factory'])),
   ('Engineering to HMI RDP','Allow',['ip:10.120.1.55'],['Factory-HMI'],['tcp/3389'],{}),                 # typed-in IP
   ('Inbound Web Portal','Allow',['Any-External'],['NAT:Portal'],['tcp/443'],dict(tags=['Incoming'])),
   ('Inbound SFTP - Partner','Allow',['Partner-IPs'],['NAT:SFTP'],['tcp/22'],dict(tags=['Incoming'])),
   ('WatchGuard Web UI','Allow',['Any-Trusted','MSP-Support'],['Firebox'],['tcp/8080'],{}),
   ('WatchGuard','Allow',['Any-Trusted'],['Firebox'],['tcp/4105','tcp/4117','tcp/4118'],dict(log=False)),
   ('SSL VPN','Allow',['Any-External'],['Firebox'],['tcp/443'],dict(log=False,ips=False)),
   ('VPN Users to Internal','Allow',['user:VPN-Users'],['Any-Trusted'],['tcp/any','udp/any'],dict(tags=['VPN'])),
   ('Ping','Allow',['Any-Trusted'],['Any'],['icmp'],{}),
   ('NTP','Allow',['Any-Trusted'],['NTP-Server'],['udp/123'],{}),
   ('Monitoring SNMP','Allow',['Monitoring-Server'],['Any-Trusted'],['udp/161'],{}),
   ('Old Mail Inbound','Allow',['Any-External'],['NAT:Mail'],['tcp/25'],dict(enabled=older)),            # switched off since
   ('TEST any any delete me','Allow',['ip:10.120.1.99'],['Any'],['any'],dict(enabled=False)),
  ]
  if not older:
    P+= [
     ('**** Temp Rule 7 ****','Allow',['Staff-Devices'],['DB-Servers'],['tcp/any'],dict(tags=['Review'])),
     ('Vendor RDP - TEMP','Allow',['Any'],['NAT:RDP-Jump'],['tcp/3389'],dict(log=False,ips=False,tags=['Incoming'])),
     ('BGP Peering','Allow',['Any'],['Firebox'],['tcp/179'],dict(log=False)),
    ]
  else:
    P+= [('Inbound FTP - Legacy','Allow',['Any-External'],['NAT:Old-FTP'],['tcp/21'],dict(tags=['Incoming'])),
         ('Legacy File Access','Allow',['Staff-Devices'],['Old-FTP-Host'],['tcp/21'],{})]
  P+= [('Unhandled Internal Packet','Block',['Any-Trusted','Any-Optional'],['Any'],['any'],{}),
       ('Unhandled External Packet','Block',['Any'],['Any'],['any'],{})]
  if older:  # different order in the older file: Ping sat near the top
    i=[p[0] for p in P].index('Ping');P.insert(2,P.pop(i))
  return P

# ---------- XML writing ----------
def mask_of(ip,mask):return f'<ip-network-addr>{ip}</ip-network-addr><ip-mask>{mask}</ip-mask>'
def ag_member(m):
  k=m[0]
  if k=='host':return f'<member><type>1</type><host-ip-addr>{m[1]}</host-ip-addr></member>'
  if k=='net':return f'<member><type>2</type>{mask_of(m[1],m[2])}</member>'
  if k=='range':return f'<member><type>3</type><start-ip-addr>{m[1]}</start-ip-addr><end-ip-addr>{m[2]}</end-ip-addr></member>'
  if k=='fqdn':return f'<member><type>8</type><domain>{X(m[1])}</domain></member>'
  raise ValueError(m)
def proto(p):return {'tcp':6,'udp':17,'icmp':1,'any':0}[p]
def svc_xml(name,ports,proxy=''):
  mem=[]
  for p in ports:
    if p=='any':mem.append('<member><type>1</type><protocol>0</protocol><server-port>0</server-port></member>')
    elif p=='icmp':mem.append('<member><type>1</type><protocol>1</protocol><icmp-type>8</icmp-type><icmp-code>0</icmp-code></member>')
    else:
      pr,pt=p.split('/')
      if pt=='any':mem.append(f'<member><type>1</type><protocol>{proto(pr)}</protocol><server-port>0</server-port></member>')
      elif '-' in pt:a,b=pt.split('-');mem.append(f'<member><type>2</type><protocol>{proto(pr)}</protocol><start-server-port>{a}</start-server-port><end-server-port>{b}</end-server-port></member>')
      else:mem.append(f'<member><type>1</type><protocol>{proto(pr)}</protocol><server-port>{pt}</server-port></member>')
  return f'  <service><name>{X(name)}</name><description>{X(name)}</description><property>0</property><proxy-type>{proxy}</proxy-type><service-item>{"".join(mem)}</service-item><idle-timeout>0</idle-timeout></service>\n'

def build(older):
  A=aliases(older);N=nats(older);P=policies(older)
  ags=[];als=[];svcs=[];natx=[];pols=[];absp=[]
  tup=lambda addr,itf='Any',user='Any':f'<alias-member><type>1</type><user>{X(user)}</user><address>{X(addr)}</address><interface>{X(itf)}</interface></alias-member>'
  ref=lambda n:f'<alias-member><type>2</type><alias-name>{X(n)}</alias-name></alias-member>'
  # built-in aliases
  for b in BUILTIN_IF:
    addr='Firebox' if b=='Firebox' else 'Any'
    als.append(f'  <alias><name>{b}</name><description>{b}</description><property>4</property><alias-member-list>{tup(addr,b if b!="Any" else "Any")}</alias-member-list></alias>\n')
  ags.append('  <address-group><name>Firebox</name><description /><property>4</property><addr-group-member><member><type>1</type><host-ip-addr>0.0.0.0</host-ip-addr></member></addr-group-member></address-group>\n')
  # interface aliases
  for (n,*_) in IFACES_NOW:
    als.append(f'  <alias><name>{n}</name><description /><property>0</property><alias-member-list>{tup("Any",n)}</alias-member-list></alias>\n')
  # named aliases
  for n,mem in A.items():
    parts=[];k=0
    for m in mem:
      if m[0]=='alias':parts.append(ref(m[1]))
      elif m[0]=='user':parts.append(tup('Any','Any',m[1]+'.1'))
      else:
        k+=1;g=f'{n}.{k}.alm';ags.append(f'  <address-group><name>{X(g)}</name><description /><property>16</property><addr-group-member>{ag_member(m)}</addr-group-member></address-group>\n');parts.append(tup(g))
    als.append(f'  <alias><name>{X(n)}</name><description /><property>0</property><alias-member-list>{"".join(parts)}</alias-member-list></alias>\n')
  # NAT
  for n,(ext,intl) in N.items():
    ags.append(f'  <address-group><name>{n}.1.snat</name><description /><property>16</property><addr-group-member>{ag_member(("host",ext))}</addr-group-member></address-group>\n')
    ags.append(f'  <address-group><name>{n}.2.snat</name><description /><property>16</property><addr-group-member>{ag_member(("host",intl))}</addr-group-member></address-group>\n')
    als.append(f'  <alias><name>{n}.snat</name><description /><property>32</property><alias-member-list>{tup(n+".1.snat","Any-External")}</alias-member-list></alias>\n')
    natx.append(f'  <nat><name>{n}</name><property>0</property><type>7</type><algorithm>0</algorithm><proxy-arp>0</proxy-arp><nat-item><member><addr-type>4</addr-type><port>0</port><ext-addr-name>{n}.1.snat</ext-addr-name><interface>Any-External</interface><addr-name>{n}.2.snat</addr-name></member></nat-item></nat>\n')
  # policies
  for (name,action,frm,to,ports,o) in P:
    svcs.append(svc_xml(name,ports,o.get('proxy','')))
    side=[]
    for sname,items in (('from',frm),('to',to)):
      parts=[];k=0
      for it in items:
        if it.startswith('NAT:'):parts.append(ref(it[4:]+'.snat'))
        elif it.startswith('user:'):parts.append(tup('Any','Any',it[5:]+'.1'))
        elif it.startswith('ip:'):
          k+=1;g=f'{name}.{k}.pcy';ags.append(f'  <address-group><name>{X(g)}</name><description /><property>16</property><addr-group-member>{ag_member(("host",it[3:]))}</addr-group-member></address-group>\n');parts.append(tup(g))
        else:parts.append(ref(it))
      an=f'{name}.1.{sname}';als.append(f'  <alias><name>{X(an)}</name><description /><property>16</property><alias-member-list>{"".join(parts)}</alias-member-list></alias>\n');side.append(an)
    en='true' if o.get('enabled',True) else 'false'
    tags=''.join(f'<tag>{X(t)}</tag>' for t in o.get('tags',[]))
    desc=o.get('desc','Policy added on 2025-03-01T09:00:00+13:00.' if name.startswith(('Ping','NTP','DNS')) else f'{name}. Owner: IT.')
    absp.append(f'''  <abs-policy><name>{X(name)}</name><property>0</property><service>{X(name)}</service><description>{X(desc)}</description><type>Firewall</type><traffic-type>1</traffic-type><enabled>{en}</enabled><firewall>{action}</firewall><reject-action>TCP_RST</reject-action>
   <from-alias-list><alias>{X(side[0])}</alias></from-alias-list><to-alias-list><alias>{X(side[1])}</alias></to-alias-list>
   <settings><proxy>{o.get("proxy","")}</proxy><schedule>Always On</schedule><log-enabled>{"false" if o.get("log",True) is False else "true"}</log-enabled><ips-monitor-enabled>{"false" if o.get("ips",True) is False else "true"}</ips-monitor-enabled></settings>
   <policy-list><policy>{X(name)}-00</policy></policy-list><tag-list>{tags}</tag-list></abs-policy>\n''')
  # interfaces
  ifx=[f'  <interface><name>{b}</name><description>{b}</description><property>4</property></interface>\n' for b in BUILTIN_IF]
  for (n,ip,mask,vlan,zone) in IFACES_NOW:
    if older and n=='CCTV':continue
    ifx.append(f'  <interface><name>{n}</name><property>0</property><if-item-list><item><item-type>2</item-type><vlan-if><vlan-id>{vlan}</vlan-id><vif-property>{zone}</vif-property><ip>{ip}</ip><netmask>{mask}</netmask></vlan-if></item></if-item-list></interface>\n')
  saved=datetime.datetime(2025,10,1,9,30) if older else datetime.datetime(2026,10,9,9,30)
  revs=''.join(f'<revision><module-id>Policy Manager</module-id><time>{int((saved-datetime.timedelta(days=d*3)).timestamp())}</time><comment>Generated by Policy Manager</comment></revision>' for d in range(5))
  return f'''<?xml version="1.0" encoding="UTF-8"?>
<!-- FICTIONAL SAMPLE for testing Firewall-Map.html. Not a real network. Documentation IP ranges (RFC 5737) and .example names (RFC 2606). -->
<profile>
 <product-grade>2</product-grade>
 <for-version>{'12.10.4' if older else '12.12.2'}</for-version>
 <address-group-list>
{''.join(ags)} </address-group-list>
 <service-list>
{''.join(svcs)} </service-list>
 <nat-list>
  <nat><name>Dynamic-NAT</name><description>Network Address Translation</description><property>4</property><type>3</type></nat>
{''.join(natx)} </nat-list>
 <alias-list>
{''.join(als)} </alias-list>
 <interface-list>
{''.join(ifx)} </interface-list>
 <abs-policy-list>
{''.join(absp)} </abs-policy-list>
 <policy-view><view>From-To</view><ui-pm><auto-order-enabled>0</auto-order-enabled></ui-pm></policy-view>
 <revision-history>{revs}</revision-history>
</profile>
'''

def main():
  os.makedirs(os.path.join(OUT,'Policy Usage'),exist_ok=True)
  open(os.path.join(OUT,'EXAMPLE-FW01_20261009.xml'),'w',encoding='utf-8').write(build(False))
  open(os.path.join(OUT,'EXAMPLE-FW01_20251001.xml'),'w',encoding='utf-8').write(build(True))
  rnd=random.Random(42)
  # 30-day usage file for the current export
  usage={'Staff Internet - HTTPS-proxy':(9_800_000,620e9),'Staff Internet - HTTP-proxy':(2_100_000,95e9),'AD Services':(14_500_000,40e9),'DNS Outbound':(6_200_000,3e9),
    'OS Updates':(1_300_000,410e9),'Backup to Cloud':(1_800,2.4e12),'Backup Server to DB':(900,1.1e12),'Unhandled Internal Packet':(4_400_000,500e6),
    'Unhandled External Packet':(2_900_000,180e6),'Ping':(3_100_000,250e6),'App to DB':(780_000,60e9),'Staff to Web Servers':(450_000,22e9),
    'Inbound Web Portal':(120_000,9e9),'SSL VPN':(15_000,30e9),'VPN Users to Internal':(220_000,70e9),'Factory to MES':(300_000,5e9),
    'Factory PLC Access':(42_000,800e6),'Print Services':(60_000,12e9),'RDP to Servers':(9_000,4e9),'CCTV Viewing':(2_400,150e9),
    'Guest WiFi Internet':(350_000,180e9),'IT Admin Full Access':(95_000,8e9),'BGP Peering':(720,1e6),'**** Temp Rule 7 ****':(410_000,30e9),
    'NTP':(80_000,40e6),'Monitoring SNMP':(260_000,700e6),'Internet Health Check':(26_000,90e6),'WatchGuard Web UI':(35,2e6),
    'Inbound SFTP - Partner':(3,40e3),'Finance to SaaS - HTTPS-proxy':(5_100,800e6),'Engineering to HMI RDP':(4,2e6)}
  with open(os.path.join(OUT,'Policy Usage','EXAMPLE-FW01_Policy_Usage_2026-09-09T00_00_to_2026-10-08T23_59.csv'),'w',newline='',encoding='utf-8') as f:
    w=csv.writer(f);w.writerow(['name','bytes','hits','status'])
    rows=[(n,)+usage.get(n,(0,0)) for (n,*_) in policies(False)]+[('Allow-IKE-to-Firebox',0,0)]
    for n,h,b in sorted(rows,key=lambda r:-r[2]):
      w.writerow([f'{n}-00' if n!='Allow-IKE-to-Firebox' else n,int(b),int(h),'Last usage occurred before 2026-10-08 20:00:00 UTC' if h else 'Not used in selected timerange'])
  # denied traffic sample
  with open(os.path.join(OUT,'EXAMPLE-FW01_Denied_Traffic_sample.csv'),'w',newline='',encoding='utf-8') as f:
    w=csv.writer(f);w.writerow(['Time','Action','Source IP','Destination IP','Destination Port','Protocol','Policy','Count'])
    rows=[('Deny','10.141.0.%d','10.130.0.11','445','tcp','Block Guest to Internal',40),('Deny','10.160.0.%d','10.131.0.10','1433','tcp','Unhandled Internal Packet',25),
          ('Deny','203.0.113.%d','203.0.113.3','3389','tcp','Unhandled External Packet',15),('Deny','10.120.1.%d','10.170.0.10','554','udp','Unhandled Internal Packet',20),
          ('Allow','10.120.1.%d','10.130.0.30','443','tcp','Staff to Web Servers',5)]
    for act,src,dst,port,pr,pol,n in rows:
      for k in range(n):w.writerow([f'2026-10-08 {9+k%8:02d}:{k%60:02d}:00',act,(src%rnd.randint(20,40)) if '%' in src else src,dst,port,pr,pol,rnd.randint(1,40)])
  print('written to',OUT)
main()
