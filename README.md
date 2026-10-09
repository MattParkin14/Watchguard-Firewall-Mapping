<!-- ==== FILE-META ====
Version:      0.9.0
Status:       DRAFT
Project:      Watchguard-Firewall-Mapping
ProjectID:    64173fc7-2485-4012-9ed5-3e314afd53db
Summary:      Offline WatchGuard Firebox policy viewer: zone map, reachability test, risk, usage, review list, changes and clean-up, in three detail levels
Updated:      2026-10-09
Author:       Matthew
Deployed:     -
Requires:     -
Supersedes:   -
SupersededBy: -
DerivedFrom:  -
---- Changelog (newest first, max 15) ----
0.9.0  2026-10-09  Ready to publish: fictional sample files and generator, .gitignore, no built-in device link, private names removed from page and README
0.8.0  2026-10-09  Comparison rebuilt as a Changes tab: saved dates, swap, security impact, field-level +/− diffs, broader/narrower, renames, true moves, alias impact, zone paths, CSV export
0.7.0  2026-10-09  Accept decision with reviewed-on and re-review dates (accepted risks leave Fix these first until due); Accepted and re-reviews list; Can A reach B? collapsible
0.6.0  2026-10-09  Simple/Medium/Advanced levels; Can A reach B?; risk ranking; internet exposure; review list; compare exports/usage; tidy-up checks; dropped-traffic analysis
0.5.0  2026-10-09  Open Policy Usage link to WatchGuard Cloud (saveable per Firebox); how-to card on Clean-up
0.4.0  2026-10-09  Loads WatchGuard Cloud Policy Usage CSV: hits/data in every view, usage verdicts, unused paths, traffic flow in the web, usage clean-up
0.3.0  2026-10-09  New Relationship web tab: rotating 3D web of zones, objects or policies, with focus, hover and click-through
0.2.0  2026-10-09  Object lookup compares up to 8 objects side by side; selection remembered; FQDN lookup ignores capitals
0.1.0  2026-10-09  Prototype viewer (Firewall-Map.html) built against a Fireware 12.12 export
==== /FILE-META ==== -->

# WatchGuard Firewall Mapping

## Overview
Kind: time-boxed project (50_Projects). If the viewer stays in use, it moves to `10_Tools\Firewall-Map`.

The goal is to show how the policies on a WatchGuard Firebox (built against Fireware 12.12 exports) relate to each other and to the network. `Firewall-Map.html` is a single offline page. It reads a Policy Manager XML export in the browser and resolves every alias, address group, interface, user group, static NAT and service down to real addresses and ports. It then shows the result in five tabs, at three levels of detail.

### Detail levels
The **Detail** switch at the top (Simple · Medium · Advanced) applies to every tab and is remembered in the browser. Each level adds to the one before.

| Tab | Simple (overview) | Medium (working through it) | Advanced (full detail) |
|---|---|---|---|
| Zone matrix | Key tiles, matrix by policies or hits, top internet-reachable items | All colour modes (data, unused paths), disabled/broad toggles, full internet list | Empty zones, internet list as a table with NAT, IPS, logging and risk score |
| Rules | Search, *Needs attention* filter, risk badge, hits | #, tags, action/usage/review filters, sorting (risk, hits, data), data column, review badge | Risk score, *Never reached* and *Tidy-up* views, change and usage-trend badges |
| Policy detail | Plain-English summary, why it's risky, usage, From/To | Review decision, owner and note; schedule, logging, description; related policies | Score, never-reached explanation, changes since the older export, IPS, older usage |
| Object lookup | **Can A reach B?** verdict; one object's in/out diagram | Policies that could match first (user groups), later matches never reached; compare up to 8 objects | Protocol choice; near misses (policies that match two of the three parts) |
| Relationship web | Zones only, rotating, traffic flow | Objects, focus, size by, labels, broad aliases | Policies-and-objects, disabled, speed, links with no traffic |
| Clean-up | *Fix these first* (top 5), at-a-glance counts, usage summary | Top 10, review list with CSV export/import, usage lists, all clean-up lists, tidy-up summary | Top 25, never-reached, full tidy-up lists, heavy flows, dropped-traffic analysis, changes and usage trend |

### Features
- **Can A reach B?** (Object lookup, can be collapsed by clicking its heading; the page remembers): enter a source, a destination and optionally a port, e.g. 443, udp/53 or rdp. The page walks the enabled policies top to bottom, as the Firebox does in *manual order* mode (`auto-order-enabled = 0` in the export), and names the policy that decides. With no port, it lists everything allowed between the two. Hosts, aliases and FQDNs are turned into an IP. A whole VLAN or range is tested with an example address.
- **Risk ranking**: each enabled allow/proxy policy gets 0–100 points for:
  - reachable from the whole internet (30), or from specific internet addresses (10)
  - Firebox management ports open (20, or 5 if from specific addresses)
  - source Any (15), destination Any (10)
  - every port allowed (20)
  - whole networks on both sides (10)
  - logging off (10)
  - IPS off on an internet-facing policy (10)
  - temporary or test name (10)
  - web traffic out without a proxy (5)
  - no traffic in the usage file (10)
  - never reached (5)

  50+ is High and 25+ is Medium. The reasons are shown with the score.
- **Reachable from the internet** (Zone matrix): every internal address, NAT / port forward and Firebox service that a policy opens to outside. Each is marked *from anywhere* or *specific sources*.
- **Review list** (Medium and up): in a policy's detail, choose **Accept**, Tighten, Disable or Remove, and add an owner and a note (or business case).
  - *Reviewed on* is filled in when you first decide, and again if you change the decision. You can edit it.
  - *Re-review by* defaults to one year after an Accept. Set it with the date picker or the +3 months, +6 months and +1 year buttons.
  - An **accepted** policy drops out of *Fix these first*, *Needs attention* and the high-risk count until its re-review date. Within 30 days of that date it's marked *re-review soon*. After the date it comes back marked **Re-review due**.
  - The **Accepted and re-reviews** list on Clean-up shows each policy's owner, reviewed date, re-review date, status (OK, due in N days, overdue N days) and business case. The Rules tab can filter to *Accepted* or *Re-review due or soon*.
  - Saved in this browser only. **Export review list** writes `Firewall-Review-<export>-<yyyyMMdd-HHmmss>.csv` (including *Reviewed on* and *Re-review by*), and **Import review list** reads it back. Older files that say *Keep* are read as Accept. Advanced can also export every policy with its risk and usage.
- **Changes tab** (compare with an older export): click **Compare…** (top right, Medium and up), or use the button on the Changes tab, and choose an older Policy Manager XML, for example a backup copy (try `samples\EXAMPLE-FW01_20251001.xml`).
  - **Header:** both files with their real saved dates, read from the export's revision history, the time between them, and their Fireware versions. If the "older" file was saved later, the page offers **Swap**.
  - **Headline tiles:** policies before → after, added, removed, edited, now broader, renamed, moved, aliases edited, and internet-reachable before → after.
  - **Security impact first:**
    - new ways in from the internet, more ports open, and ways in that are gone
    - existing policies that now allow more (highest risk first)
    - new high-risk policies
    - zone paths opened between zones that already existed (paths involving newly added VLANs are counted separately)
    - zone paths closed
    - policies switched on or off
  - **Every change** (Medium and up): filter by Added, Removed, Edited, On/off, Renamed, Moved or Via alias, or tick *Only security-relevant*. Search, then click a row to see each field with + added / − removed aliases, addresses and ports, plus before → after for action, logging, IPS and schedule. Each row is marked **Broader**, **Narrower** or **Broader and narrower**.
    - A rename (same addresses, ports and action under a new name) is shown as one rename, not a removal plus an addition.
    - Only policies whose position really changed relative to the others count as moved.
    - Removed policies open as read-only detail from the older file.
  - **Aliases edited:** the members added or removed in each alias, and how many policies each change affects. Advanced also lists new and removed aliases.
  - **Export changes (CSV):** `Firewall-Changes-<export>-<yyyyMMdd-HHmmss>.csv`, one row per changed field, for change control.
  - The Rules tab can filter by change (added, edited, now allows more, renamed, moved, via alias). A policy's detail shows what changed since the older file. An older usage CSV (via Compare…) adds the usage trend to the Changes tab.
- **Never reached**: a policy fully covered by an enabled policy above it (same or broader source, destination and ports, always-on schedule). With the same action it's redundant. With a different action, its own action never applies.
- **Tidy-up checks**: logging off, no real description, addresses typed straight into the policy, names to tidy (***, double spaces, delete/old/copy, trailing .1), aliases holding exactly the same addresses, IPS off on internet-facing policies.
- **Dropped-traffic analysis** (Clean-up, Advanced): load any CSV of denied traffic with source and destination IP columns. Port, protocol, count, action and policy columns are used when present, and only deny/drop rows are counted when there's an action column. It shows the top sources, destinations, ports and pairs. Each top pair is run through the reachability check, which says whether no policy allows it (and the closest policy), or whether a policy allows it and the drop came from something else.

The Zone matrix stays the overview, because a real export typically resolves to hundreds of objects and over a thousand source → destination pairs, which can't be read as one flat picture.

The page only reads. It never changes the firewall or the XML file, and nothing is uploaded. The level, review list, saved Policy Usage link and last reachability test are kept in the browser's local storage.

## Policy usage overlay
Optional. In WatchGuard Cloud, open Reports › Policy Usage for the Firebox, choose the time range and export the CSV. The cloud device ID isn't in the XML export, so the page has no built-in device: **Open Policy Usage ↗** (top right) opens WatchGuard Cloud until you paste your Firebox's Policy Usage address (`https://<region>.cloud.watchguard.com/reports/fb/device/<device-id>/policy_usage`) on the Clean-up tab. It's saved in that browser only, and after that the button opens the report directly. Load it with **Load usage CSV** (or drop it on the page) after or before the XML.

- **Format:** columns `name, bytes, hits, status`. `name` is the Fireware policy name with its `-00` suffix (the `policy-list` name in the XML), so it matches the export exactly. Rows that match nothing (hidden built-ins such as Allow-IKE-to-Firebox) are listed on the Clean-up tab.
- **Time window:** read from the file name (`..._2026-10-09T00_00_to_2026-10-09T23_59.csv`). Keep the original file name.
- **Verdicts:** *No traffic* = enabled with 0 hits. *Rarely used* = under 10 hits a day. *Busy* = top 10% by hits or data. *Heavy data* = over 1 GB at over 5 MB per hit.
- **Where it shows:**
  - **Zone matrix:** colour by hits, data or *Unused paths*.
  - **Rules:** hits and data columns, sorting and filters.
  - **Object lookup:** hits in the boxes and comparison columns.
  - **Relationship web:** size by hits or data, moving dots for traffic flow, dashed links for allowed paths with no traffic.
  - **Clean-up:** policies with no traffic, broad policies carrying traffic, temporary policies still in use, heavy flows, default-deny drops, and objects only used by policies with no traffic.
- **Limits:** the CSV gives one total per policy. A policy that spans several zone pairs counts its full traffic in each matrix cell, so read cells as an upper bound. Short windows miss weekly and monthly jobs, so use a 30-day file before removing anything.

## Files
| File | Purpose |
|---|---|
| Firewall-Map.html | The viewer. Open it in Edge or Chrome and load an export. |
| samples\EXAMPLE-FW01_20261009.xml | Fictional current export for trying every feature. |
| samples\EXAMPLE-FW01_20251001.xml | Fictional older export of the same firewall, for the Changes tab. |
| samples\Policy Usage\EXAMPLE-FW01_Policy_Usage_2026-09-09T00_00_to_2026-10-08T23_59.csv | Fictional 30-day Policy Usage file for the current sample. |
| samples\EXAMPLE-FW01_Denied_Traffic_sample.csv | Fictional denied-traffic log for the dropped-traffic analysis. |
| samples\make_samples.py | Python 3 script that rebuilds the sample files. |
| .gitignore | Keeps real exports and usage files out of Git. Only `samples\` is committed. |

Your own exports (`*.xml`) and usage files (`*.csv`) are input only. **Never commit them**: an export holds the whole network layout, public IPs and the Firebox account password hashes.

### Sample files
Everything in `samples\` is invented. The fictional firewall *EXAMPLE-FW01* uses documentation IP ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), private 10.105–10.170 networks and `.example` names (RFC 2606). The files have no account section, so they hold no passwords or hashes. They're built so every feature has something to show:
- internet-facing NAT and Firebox policies, from anywhere and from specific sources
- high-risk, any-port and *Any* policies, logging off, IPS off, temporary names
- a policy that's never reached, a duplicate, aliases holding the same addresses, unused aliases
- user-group policies, disabled policies and a Block policy
- a usage file with busy, idle and heavy-data policies
- an older export with added, removed, edited, renamed, moved and switched-off policies and an edited alias

To try it, open `Firewall-Map.html`, load `EXAMPLE-FW01_20261009.xml`, then the usage CSV. Use **Compare…** for `EXAMPLE-FW01_20251001.xml`, and the Clean-up tab (Advanced) for the denied-traffic CSV. Run `python make_samples.py` in `samples\` to rebuild them.

## Usage
1. In Policy Manager, save the configuration to a file (File › Save › As File).
2. Open `Firewall-Map.html` and click **Load export XML**, or drag the XML onto the page.
3. Start in **Simple**: the Zone matrix and *Reachable from the internet*, then *Fix these first* on Clean-up. Switch to **Medium** to work through findings and record decisions, and to **Advanced** for every check.
4. In Relationship web, start with *Zones linked by policies* for the big picture, then switch to *Objects* and use **Focus** on a server or VLAN. *Policies and the objects they use* shows which policies share objects. Untick **Rotate** to hold it still.
5. To compare objects, add them in Object lookup one at a time, or paste several separated by commas. Set **Show** to *Only differences* to see where they differ, for example why one PC can reach something another can't.

## How zones are worked out
- An IP, subnet or range goes to the VLAN interface whose subnet contains it. Other private addresses go to *Other internal (routed / remote)*, and public addresses go to *Internet / External*.
- An FQDN gets the zone of its IP if a named alias pairs the name with an IP, or if an alias has the same host name. Otherwise a `.local` name goes to *Internal name (no IP known)* and any other name goes to External.
- Built-in aliases map to their own zones: Any, Any-Trusted, Any-Optional, Any-External (External), Firebox, SSL-VPN/MUVPN (Mobile VPN) and BOVPN (Branch VPN). Authentication user groups go to *Authenticated users*.
- The "#" shown is the order of the policies in the export. In manual order mode, this is the order the Firebox checks them in. If an export uses automatic order, the page shows a warning, because the Firebox then sorts by specificity.

## Known limitations
- The reachability check and *Never reached* look at addresses, ports and order. They don't model proxy actions, Application Control, IPS blocks, NAT rewriting, policy-based routing or schedules (a policy with a schedule is never treated as covering another).
- Policies limited to authenticated user groups are shown as *depends on who is logged in*, because the export doesn't say which IP a user has.
- FQDNs without a matching alias IP can't be tested by address.
- The dropped-traffic CSV format isn't fixed. Columns are found by name (source/destination IP, port, protocol, count, action, policy). If a file isn't recognised, the error lists the columns it found.
- The version shown in the footer points to this README. A static page can't read the README itself.
- Wildcard addresses are treated as a contiguous mask.
