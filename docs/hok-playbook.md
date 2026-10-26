# Hands-on-keyboard intrusion — investigation playbook

**Use when** a person, not just malware, is operating inside the estate: logged on, typing commands, moving between machines.
**Goal:** contain if they are active, reconstruct what they did, collect every IOC and IOA, and write the root cause.

New to this? Work the steps in order. Experienced? The [step overview](#step-overview) is the method on one screen.

| Step | Query | Answers |
|---|---|---|
| 0 | [`hok.kql`](../queries/hok.kql) | Is a person on this device, and are they still there? |
| 2 | [`hok-timeline.kql`](../queries/hok-timeline.kql) | What happened, in order, with ATT&CK techniques |
| 3 | [`hok-connections.kql`](../queries/hok-connections.kql) | What connected in and out — before, during, after |
| 4 | [`hok-web.kql`](../queries/hok-web.kql) | Browsing and downloads, and where files came from |
| 5 | [`hok-lateral.kql`](../queries/hok-lateral.kql) | Where they went next; where the account has been |
| 6 | [`hok-persistence.kql`](../queries/hok-persistence.kql) | What they left to come back |
| 7 | [`hok-files.kql`](../queries/hok-files.kql) | Files opened, dropped, packed, changed, deleted |
| 8 | [`hok-exfil.kql`](../queries/hok-exfil.kql) | What moved away from the device, and where |
| 9 | [`hok-iocs.kql`](../queries/hok-iocs.kql) | Every indicator from the window in one table |
| 9 | [`hok-enrich-ah.kql`](../queries/hok-enrich-ah.kql) | Global prevalence and signer per file (Advanced Hunting only) |
| 10 | [`hok-scope.kql`](../queries/hok-scope.kql) | Who else has these indicators |

All queries except `hok-enrich-ah.kql` are written for Sentinel and read Defender XDR tables. In Advanced Hunting, swap `TimeGenerated` for `Timestamp`.

---

## How it works

| | Commodity malware | Hands-on-keyboard |
|---|---|---|
| Pace | Seconds, identical every time | Bursts, then gaps of minutes or hours |
| Recon | None or scripted | `whoami`, `nltest`, `net group`, AdFind — chosen and adjusted |
| Mistakes | None | Typos, retries, wrong arguments |
| Tools | The malware | What's already there: RDP, PsExec, WMI, PowerShell, remote support tools |
| Staging | Temp folders | `C:\ProgramData`, `C:\Users\Public`, `C:\PerfLogs` |
| Reaction | None | Changes approach after a block |

**Hands-on-keyboard follows an entry, it isn't one.** Typical entries: valid credentials on VPN or RDP, an exploited internet-facing server, a loader handed over by an access broker, or a helpdesk-style call that ends with the victim installing a remote support tool.

---

## Before you start

**Rules**

1. Work in UTC.
2. Write down every query you run and when.
3. Preserve before you remediate.
4. Isolate, don't power off.
5. If they are **not** active, scope first and evict in one coordinated move — piecemeal changes tip them off.
6. Keep an investigation register. Every device and account gets a row. You are done when a full pass adds no rows.

```
INVESTIGATION REGISTER
Entity        Type     Found in        Step reached   Status      Notes
<device>      Device   alert           0–9            Isolated
<account>     Account  hok-lateral     5              Disabled
```

**Check you can see** — an empty result only counts if the data should be there.

| Need | Why | Check |
|---|---|---|
| Sensor healthy | No sensor, no data | `SensorHealthState` in `hok-scope.kql`, or the device page |
| Retention covers the window | Advanced Hunting holds 30 days; Sentinel what you set | Do `1-Before` rows exist at all? |
| Correct times | Streamed Defender events arriving 48h+ late get `TimeGenerated` set to arrival | Compare `ProcessCreationTime` with `TimeGenerated` |
| Defender for Identity | Every `Identity*` leg | `IdentityLogonEvents \| take 1` |
| Cloud apps connector | Cloud file legs | `CloudAppEvents \| take 1` |
| Script block logging | Commands typed into a console | `DeviceEvents \| where ActionType == "PowerShellCommand" \| take 1` |
| Audit policy | Account and service events | `DeviceEvents \| where ActionType in ("UserAccountCreated","ServiceInstalled") \| take 1` |

**Set the window.** Every HOK query starts with:

```kql
let IncidentStart = datetime(2026-10-05T14:32:00Z);   // first known attacker activity
let IncidentEnd = now();                               // last known activity, or now() if ongoing
let LookBefore = 7d;
let LookAfter = 1d;
```

Every row is tagged `1-Before`, `2-During` or `3-After`. **`IncidentStart` is not the alert time** — it is the first thing the attacker did. Most of this investigation is moving it earlier.

---

## Step overview

| Step | Question | Run | Time |
|---|---|---|---|
| 0 | Is a person here, now? | `hok.kql`, incident page | 15 min |
| 1 | Contain if active; preserve | Portal actions | 15 min |
| 2 | What happened? Where is T0? | `hok-timeline.kql` | 30 min |
| 3 | Connections before, during, after | `hok-connections.kql` | 30 min |
| 4 | Web activity and downloads | `hok-web.kql` | 20 min |
| 5 | Where next? | `hok-lateral.kql` | 30 min per hop |
| 6 | What did they leave? | `hok-persistence.kql`, Live Response | 15 min |
| 7 | Which files? | `hok-files.kql` | 30 min |
| 8 | What left the device? | `hok-exfil.kql` | 30 min |
| 9 | IOCs and IOAs | `hok-iocs.kql`, `hok-enrich-ah.kql` | 20 min |
| 10 | Who else? | `hok-scope.kql` | 20 min |
| 11 | Root cause | RCA template | 60 min |

Steps 2–8 repeat for every device step 5 finds.

---

## Steps

### 0. Is a person here, now? · 15 min

**Portal first:** read the incident's attack story and **Activities** tab — attack disruption may already have isolated a device or contained a user.

**Run** `hok.kql` with `DeviceCheck`. One row per device and account. Covers Windows and Linux; shells started by cron or systemd are excluded from the recon indicators.

Score — 11 indicators, 25 maximum:

| Indicator | Weight | Means |
|---|---|---|
| `Discovery burst` | 3 | 4+ different recon tools from a shell in 10 minutes |
| `Attack tool` | 3 | AdFind, SharpHound, Mimikatz, PsExec, scanners |
| `Credential access` | 3 | LSASS dumped or opened, hives saved, NTDS, Kerberos abuse |
| `Inhibit recovery` | 3 | Shadow copies or backups deleted |
| `Commands in RDP session` | 2 | Shells in an RDP session; `SourceIPs` is where the keyboard is |
| `Remote access tool` | 2 | AnyDesk, ScreenConnect, Quick Assist and similar |
| `Tunnel` | 2 | ngrok, cloudflared, chisel, reverse SSH |
| `Defence evasion` | 2 | Logs cleared, Defender excluded or off, firewall off |
| `Account created or elevated` | 2 | Local account made or added to a group |
| `Admin-port fan-out` | 2 | One process reaching 5+ internal hosts on admin ports in an hour |
| `Discovery` | 1 | Any recon command from a shell |

**Read `ActiveNow` before `HokScore`.**

| `ActiveNow` | Score | Decide |
|---|---|---|
| true | 3+ | **Contain now** (step 1, isolate first). |
| false | 6+ | Probable. Preserve, then timeline, before anything the operator could see. |
| false | 3–5 | Read `Evidence` and `Actor` — could be an admin's day. |
| false | 2 or less | Probably admin or automation. Record why. |

### 1. Contain and preserve · 15 min

If active, **isolate first** — the device stays connected to Defender, so everything below still works.

1. **Isolate** (device page). Isolation lifts itself after **7 days** — re-issue for longer cases. Offline devices are retried for 3 days. Behind PAC/WPAD proxies use selective isolation.
2. **Collect the investigation package** (device page → Action center to download). May fail on low battery or metered connections.

   | Folder | Use in step |
   |---|---|
   | `Network connections` — connections, ARP, DNS cache, firewall log | 3 |
   | `SMB sessions` — inbound and outbound | 5, 7 |
   | `Autoruns`, `Scheduled tasks`, `Services` | 6 |
   | `Prefetch files` — programs run, even if deleted | 2 |
   | `Temp Directories` | 4, 7 |
   | `Users and Groups` | 6 |
   | `Security event log` | 3 |

3. **Live Response** for more: `connections`, `processes`, `persistence`, `scheduledtasks`, `services`, `startupfolders`, `registry`, `findfile`, `fileinfo`, `getfile <path>` (up to 3 GB), `run <script>` (not on restricted-mode devices).
4. **Export the device timeline** — 7 days per export. Flag the events you rely on.
5. **Accounts:** disable now if in active use; otherwise hold until step 5 has found them all. (*Contain user* is applied only by automatic attack disruption.)
6. **Unmanaged devices** the operator uses: *Contain device* makes every onboarded device refuse their traffic.

### 2. Timeline and T0 · 30 min

**Run** `hok-timeline.kql` with `DeviceCheck` and the window.

```
01-Access        remote logons, password guessing, remote tools, exploited servers, documents
02-Execution     shells under RDP, remote tools or remote-exec services; runs from staging folders
03-Discovery     recon commands, and LDAP/SAMR queries the domain controller saw
04-Credential    LSASS, SAM/SECURITY hives, NTDS, Kerberos
05-Lateral       outbound RDP, SMB, WinRM, SSH; PsExec, WMI, remote tasks; tools pushed in
06-Persistence   services, tasks, run keys, accounts
07-Evasion       logs cleared, Defender tampered with, AV detections
08-Collection    archives built
09-Exfil         transfer tools and tunnels
10-Impact        recovery removed, services stopped, mass renames
```

**Push T0 back:** take the earliest `01-Access` or `02-Execution` row, set `IncidentStart` to it, widen `LookBefore`, rerun. Stop when the earliest row is explained (outside logon, exploited server, document, remote support session) or retention runs out — **record which**.

Gaps are information: a silent two hours mid-session usually means they were on another machine (step 5). The technique summary at the foot of the query is the IOA list.

### 3. Connections before, during, after · 30 min

**Run** `hok-connections.kql`. Summarised by window, direction and channel; internal IPs resolved to device names; internet destinations scored by `OrgDevices` (how many devices in the estate use them).

| Window | You see | It means |
|---|---|---|
| `1-Before` | `Inbound logon` / `RDP` from an internal IP | **An earlier hop.** Add `ResolvedDevice` to the register; start step 0 on it. |
| `1-Before` | `Inbound logon` from a public IP | An exposed service — often the root cause |
| any | `NewCredentials (runas /netonly)` | Credentials used from memory — treat the account as compromised |
| `2-During` | `Outbound to internet`, `OrgDevices` 1–2 | Command and control candidate |
| `2-During` | `Listening` | A backdoor or tunnel waiting |
| `2-During` | `Outbound internal` on 445/3389/5985 | Lateral movement — step 5 |
| `2-During` | Many `ConnectionFailed` internally | Scanning |
| `3-After` | Outbound from the same processes | Still connected, or persistence calling home |

- `RDP (process)` rows show where the keyboard really is, even behind a jump host.
- `ConnectionSuccess` is logged before network protection decides — a blocked site can show as a success. Check step 4's `Network protection` rows.

### 4. Web activity and downloads · 20 min

**Run** `hok-web.kql`.

```
Browsing                 one row per site per hour
Link opened from an app  a link opened from mail, chat or a document
Download (browser)       saved by the browser, with the page that linked it
Download (tool)          written by curl, certutil, bitsadmin, PowerShell
Download command         the download command, URL extracted
SmartScreen              SmartScreen warnings
Network protection       network protection blocks and audits
Safe Links click         clicks in mail, Teams, Office
```

- `Download (tool)` and `Download command` = the operator bringing tools in. URL and domain are IOCs.
- `Referrer` = the page that linked the file.
- `OrgDevices` 1–2 = a site almost nobody else visits.
- Chrome/Firefox using QUIC or Encrypted Client Hello can produce connections with no `RemoteUrl`.

### 5. Lateral movement · 30 min per hop

**Run** `hok-lateral.kql` with `DeviceCheck` (hops out) and `UserIdentityCheck` (account footprint).

| `Seen` | Evidence from | Weight |
|---|---|---|
| `From the device` | Outbound connections; remote-exec commands with the target extracted | What they tried |
| `At the destination` | Logons, SMB file drops, RDP sessions from this device | **What worked** |
| `Domain controller` | Kerberos/NTLM and LDAP/SAMR from this device | Independent of both ends |
| `Account footprint` | Every logon by the account | Where else to look |

**Every successful destination is a new device:** add it to the register and run steps 0–8 on it. Name these in the ticket: `ADMIN$`/`C$` drops then a service (PsExec-style); `NewCredentials` then network logons (credential reuse).

### 6. Persistence · 15 min

**Run** `hok-persistence.kql`.

```
Account                 local accounts created or added to a group
Service                 services created
Scheduled task          tasks created
Autorun                 run keys, Winlogon, Startup folder
Logon-screen backdoor   debugger on sethc/utilman, or the binary replaced
Remote access enabled   RDP allowed, NLA off, RDP/WinRM opened up
Remote access tool      remote support tool installed to stay
WMI subscription        WMI event subscription
LSA package             DLL loaded into LSASS
Netsh helper            DLL loaded by netsh
COM hijack              user-hive CLSID hijack
Browser extension       extension forced by policy
Web shell               script written into a web root
SSH key                 authorized_keys planted or changed
```

`Account`, `Logon-screen backdoor`, `Remote access enabled`, `Web shell` and `SSH key` need no malware to get back in — the ones a tool clean-up misses.

Telemetry shows what was **created**; Live Response `persistence` and the package's `Autoruns` show what is **there now**. Use both. If a cloud account was touched, also run [`auditlogs.kql`](../queries/auditlogs.kql) and [`devicecode-persistence.kql`](../queries/devicecode-persistence.kql).

### 7. Files · 30 min

**Run** `hok-files.kql`.

```
Opened                    shortcut written to Recent — the file was opened
Dropped                   tool or script in a staging folder
Archive written           archive created
Changed over SMB          changed on this device by another machine
Deleted                   deleted by a shell or LOLBin, or from staging
Extension changed         renamed to another extension
Labelled file             carries a sensitivity label
Written to another drive  written to a drive other than C:
Removable media           storage plugged in, device control events
Cloud <ActionType>        SharePoint/OneDrive activity by the account
```

- `Opened` is good evidence when present; absence proves nothing.
- `Changed over SMB` on a file server: `By` is the source address.
- `Labelled file` touched in the window = in disclosure scope.
- **File reads are not logged.** Someone reading documents over a share leaves only a logon. Say so in the ticket.

### 8. What left the device · 30 min

Set `InternalDomains` (for the mail leg), then **run** `hok-exfil.kql` with `DeviceCheck`. Add `UserIdentityCheck` for the account's mail and cloud channels.

| Goes to | `Movement` | Looks like |
|---|---|---|
| Another machine | `Copied to another device` | Files landing elsewhere over SMB from this device, with volume |
| Another machine | `Copy command to a share` | `robocopy`/`xcopy`/`Copy-Item` naming a share (may be the source) |
| Operator's machine | `Copied to RDP client` | Files written to `\\tsclient\` |
| USB | `Copied to USB` | Files written to a USB drive letter, with volume |
| USB | `Removable media (device control)` | Storage connected, access audited or blocked |
| Internet | `Transfer tool` | rclone, MEGA, WinSCP, cloud CLIs, upload commands |
| Internet | `Transfer tool config` | `rclone.conf` — names the destination account |
| Internet | `Archive picked up` | An archive named on a later command line, with its size |
| Internet | `Tunnel` | ngrok, cloudflared, reverse SSH |
| Internet | `Storage service (program)` | File-sharing sites reached by a program |
| Internet | `Storage service (browser)` | File-sharing sites in a browser — manual upload |
| Internet | `File-transfer protocol to the internet` | FTP, SFTP/SCP, SMB, NFS, rsync; SMTP from a non-mail program |
| Internet | `DNS from a non-resolver` | 20+ outside DNS connections an hour from a non-resolver |
| Internet | `Sustained connection` | 50+ connections an hour to one destination |
| Account | `Mail out` | Attachments mailed outside |
| Account | `Cloud sharing` | Anonymous or external sharing links |
| Account | `Cloud bulk download` | 20+ SharePoint/OneDrive downloads in an hour |

**No byte counts.** `Volume` is filled only for SMB, USB, `\\tsclient` and picked-up archives. For internet channels, estimate from archive sizes and step 7. Firewall or proxy logs in Sentinel have bytes.

| Evidence | Position |
|---|---|
| Archive picked up by a transfer tool, or copied to USB / `\\tsclient`, with volume | **Exfiltration confirmed** |
| Staged data, plus a storage service or sustained connection to a rare destination | **Probable** |
| Staged or copied internally, no outbound channel seen | **Possible; cannot be excluded** |
| No staging or movement | **No evidence** — state the telemetry limits |

### 9. IOCs and IOAs · 20 min

- **IOCs:** run `hok-iocs.kql` — alert evidence plus rare hashes, destinations, URLs, accounts, persistence names and command lines. Rows without `Alert` in `Sources` are what Defender didn't alert on. Use the `Defanged` line before pasting into a ticket.
- **File enrichment:** in Advanced Hunting, run `hok-enrich-ah.kql`. Unsigned and rare worldwide = read first.
- **IOAs:** the technique summary at the foot of `hok-timeline.kql`.
- **Blocking:** add hashes, IPs, URLs and domains as Defender indicators. Never block a Windows binary's hash. Block a remote tool's installer hash or the app by policy, not a vendor domain your IT may use.

### 10. Scope · 20 min

**Run** `hok-scope.kql` once per indicator type. The summary line gives one row per device — the scope list. New devices go into the register and back to step 0. A device with an unhealthy sensor and no hits is silent, not clean.

### 11. Root cause · 60 min

Answer, in order:

1. **How did they get in?** Vector and evidence row.
2. **Why did that work?** The missing or failed control — this is the root cause.
3. **Why did it spread?** Contributing factors.
4. **Why didn't we see it sooner?** T0 to detection.
5. **What did they get, and are they out?**

| Symptom | Root cause |
|---|---|
| Logged in over RDP with a valid password | RDP on the internet without MFA; reused password |
| Web shell ran commands | Server missing a patch for a known exploited vulnerability |
| Moved to the file server as local admin | Same local admin password everywhere |
| rclone sent 40 GB to MEGA | Nothing restricted server egress to file-sharing sites |
| Helpdesk walked a user into a remote tool | No verification for inbound support calls |

Walk backwards from impact to T0. Every link should point at a row; a link without one is an inference — mark it.

```
INCIDENT        <id> — <title>
SUMMARY         Two sentences: who, what, how far, are they out.

TIMELINE (UTC)  T0 <time> (evidence)   Detected <time>   Contained <time>   Evicted <time>
                Dwell time = Detected − T0       Time to contain = Contained − Detected

INITIAL ACCESS  <vector>  <technique>  evidence: <row>
ROOT CAUSE      <the condition that let it work>
CONTRIBUTING    <privileges, flat network, missing detections>
ATTACK PATH     <device A> --RDP as <account>--> <device B> --PsExec as <account>--> <device C>

IMPACT          Accounts / devices / data accessed / data exfiltrated (position + confidence)
IOCs / IOAs     hok-iocs.kql output; techniques by phase

WHAT WORKED     <detections and actions that held>
WHAT DIDN'T     <missed detections, missing telemetry, slow steps>
ACTIONS         <each tied to a cause, with owner and date>
CONFIDENCE      <proven / inferred / not determined, and why>
```

Every action must point at a cause.

---

## Contain and evict

When the register is complete, do it all at once:

1. Isolate every affected device.
2. Disable compromised accounts; reset; re-register MFA.
3. If a domain controller or domain admin was touched, reset `krbtgt` **twice** using a scripted process — plan it with the AD team.
4. Revoke cloud sessions for affected users.
5. Remove persistence, remote tools and tunnels; block their hashes.
6. Block network IOCs.
7. Reimage — don't clean — any device with credential access, persistence or an unknown tool.
8. Run `hok-scope.kql` with the IOC set daily and `hok.kql` estate-wide for 30 days.

## Collecting without KQL

| Tool | Gives you | Step |
|---|---|---|
| Incident attack story | Alerts and entities on one canvas | 0 |
| Incident Activities tab | What attack disruption did | 0 |
| Device timeline | Events with ATT&CK techniques, flags, process trees. Kept 90 days by default (longer than Advanced Hunting) | 2 |
| Device overview | Logged-on users, internet-facing tag, missing patches | 0, 11 |
| Investigation package | Current state snapshot | 1 |
| Live Response | Remote shell | 1, 6 |
| File page | Global prevalence, signer, deep analysis | 9 |
| User page | Defender for Identity activity, lateral movement paths | 5 |
| IP / URL pages | Everywhere it appears | 10 |
| Cloud apps activity log | Cloud activity by user, IP or app | 7, 8 |
| Action center | What has been done, by whom | 1 |
| Advanced Hunting functions | `FileProfile()`, `DeviceFromIP()`, `AssignedIPAddresses()`, `SeenBy()` | 3, 9 |

## Ticket

- T0, detection, containment — and what stopped you pushing T0 earlier
- The register: every device and account, and status
- Initial access with evidence
- Attack path, hop by hop
- Channels used: C2, remote tools, tunnels
- What left the device, where, with volume, and the exfil position
- `hok-iocs.kql` output, defanged
- ATT&CK techniques by phase
- Containment actions with times
- The RCA

## False positives

| Looks like HOK | Usually |
|---|---|
| `Discovery burst` from an IT account | An admin troubleshooting — check the ticket queue |
| `Remote access tool` on many devices | Your own support tooling |
| `Attack tool` — PsExec or Sysinternals | Admins use them; who, from where, expected? |
| `Commands in RDP session` on a jump host | That's what jump hosts are for — check the source |
| `Admin-port fan-out` from a management server | Config management, scanning, backup |
| `Discovery burst` on a Linux server | A monitoring or deployment script not run from cron — check the parent |
| `Sustained connection` to a cloud provider | Backup, sync, updates — `OrgDevices` will be high |
| `Credential access` from a security product | Add it to `LsassReaders` |

## Limits

- An empty result is only as good as the telemetry behind it.
- File reads are not logged.
- No exfil channel ≠ no exfiltration: there are no byte counts, and copies to unmanaged machines are invisible.
- `ConnectionSuccess` can appear for connections network protection then blocked.
- Nothing in `1-Before` doesn't make this device the first — check the register.
- Persistence created before retention only shows in Live Response or the package.
- Not run against live telemetry. Reviewed for KQL correctness and schema only.

## Sources

- Microsoft — [Incident Response ransomware approach](https://learn.microsoft.com/security/ransomware/incident-response-playbook-dart-ransomware-approach) (assess, scope, preserve; krbtgt reset; Quick Assist abuse)
- Microsoft — [Detecting human-operated ransomware with Defender XDR](https://learn.microsoft.com/defender-xdr/playbook-detecting-ransomware-m365-defender) (pre-ransom stages; log clearing and security tool tampering)
- Microsoft — [Take response actions on a device](https://learn.microsoft.com/defender-endpoint/respond-machine-alerts), [Live response](https://learn.microsoft.com/defender-endpoint/live-response), [Device timeline](https://learn.microsoft.com/defender-endpoint/investigate-machines#investigate-device-timeline)
- Microsoft — [Advanced hunting with Sentinel data](https://learn.microsoft.com/defender-xdr/advanced-hunting-microsoft-defender) (48-hour `TimeGenerated` note), [Network protection](https://learn.microsoft.com/defender-endpoint/network-protection), [Extend advanced hunting coverage](https://learn.microsoft.com/defender-xdr/advanced-hunting-extend-data)
- Microsoft — [FileProfile()](https://learn.microsoft.com/defender-xdr/advanced-hunting-fileprofile-function), [DeviceFromIP()](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicefromip-function), [AssignedIPAddresses()](https://learn.microsoft.com/defender-xdr/advanced-hunting-assignedipaddresses-function), [SeenBy()](https://learn.microsoft.com/defender-xdr/advanced-hunting-seenby-function)
- NIST — [SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (incident response under CSF 2.0; lessons feed back into controls)
- The DFIR Report — [thedfirreport.com](https://thedfirreport.com/) (2024–2025 cases: AdFind from batch files, AnyDesk with ID sent back, rclone to MEGA then logs cleared)
- crtvrffnrt — [Microsoft Incident Response Playbook](https://github.com/crtvrffnrt/Microsoft-Incident-Response-Playbook) (bounded timeline; entities first; preserve before remediating)
