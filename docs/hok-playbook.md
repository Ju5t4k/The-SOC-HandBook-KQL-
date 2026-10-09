# Hands-on-keyboard intrusion — end-to-end investigation

For when a person, not just malware, is operating inside the estate: someone is
logged on, typing commands, moving between machines and deciding what to do
next.

It is written for two readers. **If you are new**, work the phases in order —
each one names a query, tells you how to read it, and ends in a decision.
**If you have done this before**, the [investigation timeline](#investigation-timeline)
is the whole method on one screen and the queries stand on their own.

| Query | Phase | Answers |
|---|---|---|
| [`hok.kql`](../queries/hok.kql) | 0 | Is a person driving this device, and are they still on it? |
| [`hok-timeline.kql`](../queries/hok-timeline.kql) | 2 | What happened, in order, tagged by phase and ATT&CK technique? |
| [`hok-connections.kql`](../queries/hok-connections.kql) | 3 | What connected in and out — before, during and after? |
| [`hok-web.kql`](../queries/hok-web.kql) | 4 | Where did the browser go, and what was downloaded from where? |
| [`hok-lateral.kql`](../queries/hok-lateral.kql) | 5 | Where did they go next, and where has the account been? |
| [`hok-persistence.kql`](../queries/hok-persistence.kql) | 6 | What did they leave so they can come back? |
| [`hok-files.kql`](../queries/hok-files.kql) | 7 | What did they open, drop, pack, change and delete? |
| [`hok-exfil.kql`](../queries/hok-exfil.kql) | 8 | What moved away from the device, and where did it go? |
| [`hok-iocs.kql`](../queries/hok-iocs.kql) | 9 | Every indicator from the window, in one table |
| [`hok-enrich-ah.kql`](../queries/hok-enrich-ah.kql) | 9 | Global prevalence and signer for every file (Advanced Hunting only) |
| [`hok-scope.kql`](../queries/hok-scope.kql) | 10 | Who else has any of these indicators? |

Every query except `hok-enrich-ah.kql` is written for Sentinel (`TimeGenerated`)
and reads only Defender XDR tables. To run one in Advanced Hunting, swap
`TimeGenerated` for `Timestamp` — see the [repository README](../README.md).
`hok-enrich-ah.kql` is the reverse: Advanced Hunting only, because it uses
functions Sentinel does not have.

---

## What you are looking at

Commodity malware runs the same chain on every machine it lands on, seconds
apart, with no one watching. A hands-on-keyboard operator is a person, and
people leave a different shape in the telemetry.

| | Commodity malware | Hands-on-keyboard |
|---|---|---|
| Pace | Seconds, identical every time | Bursts of activity, then gaps of minutes or hours |
| Recon | None, or a fixed script | `whoami`, `nltest`, `net group`, AdFind — chosen, repeated, adjusted |
| Mistakes | None | Typos, retried commands, a tool run with the wrong arguments |
| Tools | The malware itself | Whatever is already there: RDP, PsExec, WMI, PowerShell, remote support tools |
| Staging | Temp folders | `C:\ProgramData`, `C:\Users\Public`, `C:\PerfLogs` |
| Reaction | None | Changes approach after something is blocked |
| Goal | Run the payload | Find the valuable systems and data, then act on them |

**Hands-on-keyboard is a phase, not an entry vector.** Something got the
operator in first: valid credentials on VPN or RDP, an exploited internet-facing
server, a commodity loader handed over by an access broker, or a helpdesk call
that ended with the victim running a remote support tool. Microsoft's incident
response team documented exactly that last pattern with Quick Assist in May
2024. Phase 2 exists to find which one.

---

## Where this method comes from

This playbook is assembled from published practice rather than invented. What
was taken from each:

| Source | Principle | Where it shows up here |
|---|---|---|
| Microsoft Incident Response (DART) ransomware approach | Assess first: how was it found, when did it start, what logs exist, **is the actor still active**. Isolate, don't power off. Feed the investigation into compromise recovery. | Phase 0 `ActiveNow`; Phase 1 order; containment |
| Microsoft — detecting human-operated ransomware with Defender XDR | The pre-ransom stages (initial access, recon, credential theft, lateral movement, persistence) are where it can still be stopped. Watch for log clearing and security tools being disabled. | The timeline's ten phases; `Defence evasion` weighted in `hok.kql` |
| NIST SP 800-61 Rev. 3 (April 2025) | Incident response as part of risk management under CSF 2.0 — every incident should improve preparation, not just close. | Phase 11, RCA actions tied to causes |
| Published intrusion reports (The DFIR Report, 2024–2025) | What operators actually do: AdFind run from a batch file for AD recon, AnyDesk installed by script with its ID sent back to the operator, rclone to MEGA followed by clearing the event logs. | Tool and pattern lists in every query |
| Community Microsoft IR playbooks | Bound the timeline around the alert before chasing leads. Identify entities first. Preserve artefacts before destructive remediation. | Window tags; investigation register; Phase 1 |

Links are at the end.

---

## Before you start

### Ground rules

1. **Work in UTC.** Every query and every portal view uses it. Convert once, in
   the final report.
2. **Write down every query you run and when.** The RCA depends on it, and so
   does anyone who picks up the incident after you.
3. **Preserve before you remediate.** Collect the investigation package and
   export the timeline before you delete, uninstall or reimage anything.
4. **Isolate, don't power off.** Isolation keeps the device connected to
   Defender, so you can still collect from it. Powering off loses memory and
   live connections and stops nothing else the operator has.
5. **Don't tip them off unless they are active.** A person watching will notice
   an account being reset or a tool vanishing, and will either dig in deeper or
   go straight to impact. If they are not active, scope first and evict in one
   coordinated move.
6. **Keep one investigation register.** Every device and account you find gets
   a row. Every hop in Phase 5 adds rows. You are done when no new rows appear.

```
INVESTIGATION REGISTER
Entity        Type     Found in        Phase reached   Status      Notes
<device>      Device   alert           0–9             Isolated
<account>     Account  hok-lateral     5               Disabled
```

### Check what you can see

An empty result only means something if the data should have been there.
Check these before you trust a blank.

| You need | Why | How to check |
|---|---|---|
| The device onboarded and its sensor healthy | No sensor, no telemetry, no result | `SensorHealthState` and `OnboardingStatus` in `hok-scope.kql` output, or the device page |
| Retention covering the window | Advanced Hunting holds 30 days; Sentinel holds what you configured per table | Set `IncidentStart` and see whether `1-Before` rows exist at all |
| Correct event times | When Defender tables are streamed to Sentinel, events arriving more than 48 hours late get `TimeGenerated` set to ingestion time. A laptop that was offline for days will show its events on the day it reconnected. | For processes, `ProcessCreationTime` is the device's own clock — compare it with `TimeGenerated` when the timeline looks wrong |
| Defender for Identity | Every `Identity*` leg — the domain controller's view of authentication and LDAP recon — depends on it | `IdentityLogonEvents \| take 1` |
| The Defender for Cloud Apps / Microsoft 365 connector | Cloud file and sharing legs read `CloudAppEvents` | `CloudAppEvents \| take 1` |
| PowerShell script block logging | Commands typed into an open console have no command line anywhere else | `DeviceEvents \| where ActionType == "PowerShellCommand" \| take 1` |
| Windows audit policy | Microsoft documents that local account changes and service installs need advanced audit policy to appear in `DeviceEvents` | `DeviceEvents \| where ActionType in ("UserAccountCreated","ServiceInstalled") \| take 1` |

### Set the window

Every HOK query starts with the same four values:

```kql
let IncidentStart = datetime(2026-10-05T14:32:00Z);   // first known attacker activity
let IncidentEnd = now();                               // last known activity, or now() if ongoing
let LookBefore = 7d;                                   // how far before T0 to look
let LookAfter = 1d;                                    // how far after the end to look
```

and tags every row with a `Window`: `1-Before`, `2-During` or `3-After`.

**`IncidentStart` is not the alert time.** The alert is when Defender noticed.
T0 is when the operator first did something, and it is almost always earlier.
Much of this investigation is pushing T0 backwards until you reach the way they
got in. Start with the alert time, and move it every time Phase 2 shows you
something earlier.

---

## Investigation timeline

The whole method on one screen.

| Phase | Question | Run | Time box |
|---|---|---|---|
| 0 | Is this a person, and are they still here? | `hok.kql`, incident page | 15 min |
| 1 | Contain if active; preserve either way | Portal actions | 15 min |
| 2 | What happened, in order? Where is T0? | `hok-timeline.kql` | 30 min |
| 3 | What connected in and out, before, during and after? | `hok-connections.kql` | 30 min |
| 4 | What did the browser do, and what came down from the web? | `hok-web.kql` | 20 min |
| 5 | Where did they go next? | `hok-lateral.kql` | 30 min per hop |
| 6 | What did they leave behind? | `hok-persistence.kql`, Live Response | 15 min |
| 7 | Which files did they touch? | `hok-files.kql` | 30 min |
| 8 | What moved away from the device, and where to? | `hok-exfil.kql` | 30 min |
| 9 | What are the IOCs and IOAs? | `hok-iocs.kql`, `hok-enrich-ah.kql` | 20 min |
| 10 | Who else? | `hok-scope.kql` | 20 min |
| 11 | Why did it happen, and what changes? | The RCA template | 60 min |

Phases 2 to 8 repeat for every device Phase 5 finds. The time boxes are for the
first device; later ones go faster because you know what you are looking for.

---

### Phase 0 — Is this a person, and are they still here? · 15 minutes

**In the portal first.** Open the incident and read the attack story. Check the
**Activities** tab — automatic attack disruption may already have isolated a
device or contained a user, and you need to know that before you act.

**Then run `hok.kql`** with `DeviceCheck` set. It returns one row per device and
account, scored on eleven indicators (25 at most):

| Indicator | Weight | What it means |
|---|---|---|
| `Discovery burst` | 3 | Four or more different recon tools from a shell inside ten minutes |
| `Attack tool` | 3 | AdFind, SharpHound, Mimikatz, PsExec, network scanners and similar |
| `Credential access` | 3 | LSASS dumped or opened, hives saved, NTDS copied, Kerberos abused |
| `Inhibit recovery` | 3 | Shadow copies or backups deleted — the step before encryption |
| `Commands in RDP session` | 2 | Shells run inside an RDP session; `SourceIPs` is where the keyboard is |
| `Remote access tool` | 2 | AnyDesk, ScreenConnect, Quick Assist and the rest |
| `Tunnel` | 2 | ngrok, cloudflared, chisel, reverse SSH |
| `Defence evasion` | 2 | Logs cleared, Defender excluded or switched off, firewall dropped |
| `Account created or elevated` | 2 | Local accounts made or added to a group |
| `Admin-port fan-out` | 2 | One process reaching five or more internal hosts on admin ports in an hour |
| `Discovery` | 1 | Any recon command typed into a shell |

Read `ActiveNow` before `HokScore`.

| `ActiveNow` | `HokScore` | Do this |
|---|---|---|
| true | 3 or more | **Contain now** — Phase 1, isolate first. A person at the keyboard reacts to what you do. |
| false | 6 or more | **Probable hands-on-keyboard.** Preserve, then build the timeline before doing anything the operator could see. |
| false | 3–5 | Suspicious. Read `Evidence` and `Actor`: an administrator's normal day can look like this. |
| false | 2 or less | Probably administration or automation. Record why and keep watching. |

`ActiveNow` means activity in the last hour (`ActiveWindow`). `MinutesSinceLast`
tells you how stale it is.

### Phase 1 — Contain and preserve · 15 minutes

Order matters. If the operator is active, isolate first — isolation keeps the
device talking to Defender, so everything below still works afterwards.

1. **Isolate the device** (device page → *Isolate device*). Things to know:
   - Isolation is **lifted automatically after seven days**. If the
     investigation runs longer, re-issue it.
   - If the device is offline, Defender retries for up to three days, then
     stops. Re-issue it when the device comes back.
   - On networks with web proxies, PAC or WPAD, a fully isolated device may not
     recover. Use selective isolation there.
2. **Collect the investigation package** (device page → *Collect investigation
   package*, then download from the Action center). It is a snapshot of the
   device's current state, and several phases use it:

   | Folder | Use it in |
   |---|---|
   | `Network connections` — active connections, ARP cache, DNS cache, ipconfig, firewall log | Phase 3 — the ARP cache names other hosts this one has been talking to |
   | `SMB sessions` — inbound and outbound | Phases 5 and 7 — who is reading this device's shares right now |
   | `Autoruns`, `Scheduled tasks`, `Services` | Phase 6 — what is there now, not just what telemetry saw created |
   | `Prefetch files` | Phase 2 — evidence a program ran, even if it has since been deleted |
   | `Temp Directories` | Phases 4 and 7 — dropped files per user |
   | `Users and Groups` | Phase 6 — local group membership after any changes |
   | `Security event log` | Phase 3 — logons the sensor may not have shipped |
   | `Processes`, `Installed programs` | Phase 6 — remote access tools installed as software |

   Collection can fail on low battery or a metered connection.
3. **Open Live Response** if you need more than the package. The commands that
   matter most here:

   | Command | Gives you |
   |---|---|
   | `connections` | Active connections right now |
   | `processes` | Running processes |
   | `persistence` | Every known persistence method on the device |
   | `scheduledtasks`, `services`, `startupfolders`, `registry` | Persistence, one type at a time |
   | `findfile`, `fileinfo` | Locate and inspect a tool the timeline named |
   | `getfile <path>` | Download it for analysis (up to 3 GB) |
   | `run <script>` | Run a PowerShell script from the library, for anything else |

   Devices onboarded in restricted mode do not allow `run`.
4. **Export the device timeline** (device page → *Timeline* → *Export*). Each
   export covers up to seven days, so export the incident window in pieces.
   Flag the events you rely on — flags filter the view later and build a clean
   breach timeline.
5. **Accounts.** If an account is being used by the operator right now, disable
   it. If not, hold until Phase 5 has found every account, and do them together.
   *Contain user* exists in Defender, but only automatic attack disruption
   applies it; you cannot trigger it by hand.
6. **Unmanaged devices** the operator is using can be cut off with *Contain
   device*: every onboarded device then refuses traffic to and from it.

### Phase 2 — Build the timeline and find T0 · 30 minutes

Run **`hok-timeline.kql`** with `DeviceCheck` and the window set. It returns one
table, oldest first, every row tagged with a phase and an ATT&CK technique:

```
01-Access        remote logons, password guessing, remote tools, exploited servers, documents
02-Execution     shells under RDP, remote tools or remote-exec services; runs from staging folders
03-Discovery     recon commands, and LDAP or SAMR queries the domain controller saw
04-Credential    LSASS, SAM and SECURITY hives, NTDS, Kerberos
05-Lateral       outbound RDP, SMB, WinRM and SSH; PsExec, WMI, remote tasks; files pushed in over SMB
06-Persistence   services, scheduled tasks, run keys, accounts created
07-Evasion       logs cleared, Defender tampered with, firewall off; AV detections
08-Collection    archives built
09-Exfil         transfer tools and tunnels
10-Impact        recovery removed, services stopped, files mass-renamed
```

Read it top to bottom. Then push T0 back:

1. Take the earliest `01-Access` or `02-Execution` row.
2. Set `IncidentStart` to it, widen `LookBefore`, and run again.
3. Repeat until the earliest row has an explanation — a logon from an outside
   address, an exploited server, a document, a remote support session — or until
   you reach the end of retention. **Write down which one stopped you.** "We
   reached retention" is a legitimate finding and belongs in the RCA.

Gaps in the timeline are information. A two-hour silence in the middle of a
busy evening usually means the operator was working on another machine — which
Phase 5 will show you.

The technique summary at the foot of the file is your IOA list for Phase 9.

### Phase 3 — Connections before, during and after · 30 minutes

Run **`hok-connections.kql`**. It summarises every connection to and from the
device by window, direction and channel, resolves internal addresses to device
names, and counts how many devices in the estate talk to each internet
destination (`OrgDevices`). Browsers are left out on purpose; they are in Phase 4.

Read it by window.

**`1-Before` — how they arrived.**

| You see | It means | Next |
|---|---|---|
| `Inbound logon` / `RDP` from an internal address | Someone came from another device. `ResolvedDevice` names it. | That device is an earlier hop. Add it to the register and start Phase 0 on it. |
| `Inbound logon` from a public address | An internet-exposed service accepted a logon | Find the service; this is often the root cause |
| `NewCredentials (runas /netonly)` | A process given different network credentials — a common pass-the-hash pattern | Treat the account as compromised |
| `Inbound authentication` (Defender for Identity) | The domain controller saw this device authenticated to from elsewhere | Cross-check against the logon rows |

**`2-During` — what they used.**

| You see | It means |
|---|---|
| `Outbound to internet` with `OrgDevices` of 1 or 2 | A destination nothing else in the estate uses. Command and control lives here. |
| `Listening` | Something opened a port and waited. Backdoors and tunnels listen. |
| `Outbound internal` on 445, 3389, 5985 | Lateral movement — take it to Phase 5 |
| Many `ConnectionFailed` to internal hosts | Scanning |

**`3-After` — are they still here?** Anything outbound after `IncidentEnd` from
the same processes is either the operator still connected or persistence
calling home.

Two details that catch people out:

- `Inbound session` / `RDP (process)` comes from process telemetry, and its
  remote address is where the keyboard actually is — even when the logon events
  only show a jump host.
- Defender logs `ConnectionSuccess` at the TCP layer, before network protection
  decides. A connection that was blocked can still show as a success. Check
  Phase 4's `Network protection` rows before concluding something got through.

`ResolvedDevice` is built from what each device reported across the window, so
with DHCP it can name more than one machine. In Advanced Hunting,
`DeviceFromIP()` answers the same question for an exact moment — see
`hok-enrich-ah.kql`.

### Phase 4 — Web activity and downloads · 20 minutes

Run **`hok-web.kql`**.

```
Browsing                 one row per site per hour, with OrgDevices
Link opened from an app  a link opened in the browser from mail, chat or a document
Download (browser)       a file the browser saved, its URL, and the page that linked to it
Download (tool)          a file written by curl, certutil, bitsadmin, PowerShell and similar
Download command         the download command itself, with the URL pulled out
SmartScreen              what SmartScreen warned about
Network protection       what network protection blocked or audited
Safe Links click         links clicked in mail, Teams or Office, and whether they were let through
```

What to look for:

- **`Download (tool)` and `Download command`** are the operator bringing their
  kit in. The URL is an IOC; so is the domain.
- **`Referrer`** on a browser download is the page that linked to the file —
  usually the lure, not the payload host.
- **`OrgDevices` of 1 or 2** on a browsing row is a site almost nobody else in
  the estate visits.
- **`Safe Links click`** with *clicked through the warning* means the user was
  told and went anyway.

Network protection identifies the site for non-Edge browsers from the TLS
handshake, so it needs TCP and an unencrypted ClientHello. Chrome or Firefox
using QUIC or Encrypted Client Hello can produce connections with no
`RemoteUrl`. Absence of a site here is weaker evidence in those browsers.

### Phase 5 — Lateral movement · 30 minutes per hop

Run **`hok-lateral.kql`** with `DeviceCheck` for hops out of the device, and
`UserIdentityCheck` for everywhere the compromised account has been. Fill in
both if you can.

The `Seen` column tells you whose evidence it is:

| `Seen` | Evidence from | Weight |
|---|---|---|
| `From the device` | The source: connections out, remote-execution command lines with the target pulled out | What they tried |
| `At the destination` | The other device: logons from this one, files pushed in over SMB, RDP sessions from this one | **What worked** |
| `Domain controller` | Defender for Identity: Kerberos and NTLM from this device, LDAP and SAMR recon | Independent of both endpoints |
| `Account footprint` | Every logon by the account, anywhere | Where else to look |

**Every destination with a successful row is a new device.** Add it to the
register and run Phases 0 to 8 on it. Stop when a full pass adds nothing new.

Patterns worth naming in the ticket:

- Files written to `ADMIN$` or `C$` followed by a service on the destination:
  PsExec or something built like it.
- `NewCredentials` logons followed by network logons elsewhere: credentials
  being used from memory.
- `Account footprint` rows on servers the user never normally touches.

### Phase 6 — What did they leave behind? · 15 minutes

Run **`hok-persistence.kql`** with `DeviceCheck` and the window set. It looks
for what an operator leaves so they can come back — which is mostly not malware:

```
Account                 local accounts created or added to a group
Service                 services created, as the sensor saw them and as they were typed
Scheduled task          tasks created, the same two ways
Autorun                 run keys, Winlogon values, the Startup folder
Logon-screen backdoor   a debugger on sethc, utilman and the like, or the binary replaced
Remote access enabled   RDP allowed, network-level authentication off, RDP or WinRM opened up
Remote access tool      a remote support tool installed as a service or into Program Files
WMI subscription        code bound to a WMI event — nothing on disk to find
LSA package             a DLL loaded into LSASS that sees every password
Netsh helper            a DLL loaded whenever netsh runs
COM hijack              a user-hive CLSID pointed at the operator's code
Browser extension       an extension forced on through policy
Web shell               script files written into a web root
SSH key                 an authorized_keys file planted or changed
```

Five of these need no malware at all to get back in: `Account`,
`Logon-screen backdoor`, `Remote access enabled`, `Web shell` and `SSH key`. They
are the ones a clean-up that only removes files and tools will miss, and they
are filtered together at the foot of the query.

Telemetry tells you what was *created*. Live Response `persistence` and the
investigation package's `Autoruns` tell you what is *there now*. Use both;
something created before your retention window will only show in the second.

Add to the register:

- Every account from the `Account` rows
- Every remote access tool — it is persistence and a way in at the same time
- Any cloud identity changes: if a domain or Entra account was touched, run
  [`auditlogs.kql`](../queries/auditlogs.kql) and the device code
  [persistence query](../queries/devicecode-persistence.kql) for MFA methods,
  consent and app credentials

### Phase 7 — File usage · 30 minutes

Run **`hok-files.kql`**.

```
Opened                    a shortcut written to Recent — the file was opened
Dropped                   a tool or script landing in a staging folder
Archive written           an archive created
Changed over SMB          a file changed on this device by another machine
Deleted                   deleted by a shell or LOLBin, or out of a staging folder
Extension changed         renamed to a different extension
Labelled file             a file carrying a sensitivity label
Written to another drive  written to a drive other than C:
Removable media           storage plugged in, and what device control recorded
Cloud <ActionType>        SharePoint and OneDrive activity by the account
```

How to read it:

- **`Opened`** relies on Windows writing a shortcut into `Recent` when a file is
  opened. When it is there, it is good evidence. When it is absent, it proves
  nothing.
- **`Changed over SMB`** is the file-server view. On a server, run it there and
  read `By` — it names the address the change came from.
- **`Labelled file`** sets the disclosure scope. If a labelled file was touched
  in the window, it is in scope.
- **`Removable media`**: Microsoft audits plug-and-play connections by default.
  `RemovableStoragePolicyTriggered` events are capped at 300 per device per day
  in Advanced Hunting; the device control report has the rest.

`DeviceFileEvents` records files being created, modified, renamed and deleted.
**It does not record files being read.** An operator who reads documents over a
share without copying them leaves a logon and nothing else. Say so in the ticket
rather than letting an empty result imply nothing was accessed.

### Phase 8 — What moved away from the device? · 30 minutes

Run **`hok-exfil.kql`** with `DeviceCheck` set. Every row is something leaving
the device, and `Destination` says where it went. Add `UserIdentityCheck` to
include the account's own channels as well — and set `InternalDomains` first,
because it ships as `contoso.com` and without it every outbound mail looks
external.

Data can leave a device four ways. Read them in this order, because the first
three are steps operators take before the fourth.

**To another machine on the network** — staging, usually on a server, before it
leaves the estate:

| Movement | Looks like |
|---|---|
| `Copied to another device` | Files landing on another machine over SMB from this one, seen at the far end. `Volume` gives files and bytes. |
| `Copy command to a share` | `robocopy`, `xcopy`, `Copy-Item` naming a share. The share can be the source — read `Evidence`. |
| `Copied to RDP client` | Files written to `\\tsclient\` — the drive of the machine the RDP session came from. The operator's own computer. |

**To removable media:**

| Movement | Looks like |
|---|---|
| `Copied to USB` | Files written to a drive letter that was USB storage in the window, with `Volume` |
| `Removable media (device control)` | Storage connected, and what device control audited or blocked |

**To the internet:**

| Movement | Looks like |
|---|---|
| `Transfer tool` | rclone, MEGA, WinSCP, cloud CLIs, `curl -T`, PowerShell uploads. `Destination` holds the URL or the rclone remote name. |
| `Transfer tool config` | `rclone.conf` written — it names the remote account |
| `Archive picked up` | An archive built on the device, then named on a later command line. The hand-off from staging to sending, with the archive's size. |
| `Tunnel` | ngrok, cloudflared, reverse SSH |
| `Storage service (program)` | MEGA, Dropbox, file-drop sites, Telegram, Discord reached by something other than a browser |
| `Storage service (browser)` | The same sites in a browser. Uploading by hand looks exactly like this. |
| `File-transfer protocol to the internet` | FTP, SFTP/SCP, SMB, NFS, rsync, or SMTP from something that is not a mail client |
| `DNS from a non-resolver` | Twenty or more DNS connections an hour to an outside server from something other than the Windows resolver |
| `Sustained connection` | Fifty or more connections in an hour from one process to one public destination |

**From the account, wherever it was used** (`From` = `Account`, only with
`UserIdentityCheck`):

| Movement | Looks like |
|---|---|
| `Mail out` | Attachments mailed to outside addresses |
| `Cloud sharing` | Anonymous links and external sharing created |
| `Cloud bulk download` | Twenty or more SharePoint or OneDrive downloads in an hour |

**Defender records connections, not bytes.** `Volume` is filled in only where
file sizes exist — files copied over SMB, to USB or to `\\tsclient`, and archives
that were picked up. For internet channels, estimate from what was available to
take: the archive sizes, and the files Phase 7 shows in the folders that were
worked through. If firewall or proxy logs are in Sentinel, they carry byte
counts.

`OrgDevices` on the internet rows is how many devices in the estate use that
destination. A destination only this device uses is the one to read first.

State your position plainly:

| Evidence | Position |
|---|---|
| Archive picked up by a transfer tool, or copied to USB or `\\tsclient`, with volume | **Exfiltration confirmed.** The content is the archive's or the copy's source. |
| Archive staged, sustained connection or storage service to a rare destination | **Exfiltration probable.** |
| Files staged or copied to another device, no outbound channel seen | **Staged; exfiltration possible and cannot be excluded.** |
| No staging or movement seen | **No evidence** — and state the retention and telemetry limits that bound that. |

### Phase 9 — IOCs and IOAs · 20 minutes

**IOCs.** Run **`hok-iocs.kql`**. It gathers, for the device and account in the
window:

- everything Defender's own alerts named (`Sources` = `Alert`)
- rare files — on three devices or fewer across the estate (`RareThreshold`)
- known attack tools by name, wherever they are
- rare internet destinations reached by something other than a browser
- download URLs and the pages that linked to them
- accounts that logged on remotely, and their source addresses
- accounts created or promoted, services and scheduled tasks installed
- autorun registry values pointing outside system folders
- the command lines that did the damage

Rows found on the device but not in any alert (`Sources` without `Alert`) are
what Defender did not tell you about. Use the `Defanged` variant at the foot of
the file before pasting into a ticket or chat.

**Enrich the files.** In Advanced Hunting, run **`hok-enrich-ah.kql`**. It
passes every file the device ran or wrote through `FileProfile()`, which adds
Microsoft's global view: how many machines in the world have it, when it was
first seen, who signed it and whether there is a detection name. Unsigned and
almost nowhere else in the world is where to start reading.

**IOAs.** Uncomment the technique summary at the foot of `hok-timeline.kql`.
It returns the ATT&CK techniques observed in each phase — the behaviours, which
outlast any hash or address the operator can change.

**Blocking.** Add hashes, IPs, URLs and domains as Defender indicators. Two
cautions:

- Never block a LOLBin's hash — it is Windows.
- A remote support tool's vendor domain may be one your own IT uses. Block the
  installer's hash, or the application by policy, rather than the vendor.

### Phase 10 — Scope · 20 minutes

Run **`hok-scope.kql`** once per indicator type — hash, IP, domain, account,
command, file name, service or task name. Uncomment the summary line for one row
per device; that is the scope list for the ticket.

Any new device here goes into the register and back through Phase 0.

Read `SensorHealthState` and `OnboardingStatus`. A device that is not healthy
and shows no hits is not clean — it is silent.

### Phase 11 — Root cause analysis · 60 minutes

The RCA answers five questions, in this order:

1. **How did they get in?** The initial access vector, with the evidence row.
2. **Why did that work?** The control that was missing or failed. This is the
   root cause.
3. **Why did it go as far as it did?** The contributing factors.
4. **Why didn't we see it sooner?** The detection gap: T0 to detection.
5. **What did they get, and are they out?**

**Separate the cause from the symptom.** The attacker's action is not the root
cause; the condition that allowed it is.

| Symptom (what happened) | Root cause (why it could) |
|---|---|
| The operator logged in over RDP with a valid password | RDP exposed to the internet with no MFA; the password was reused from a breach |
| A web shell ran commands on the server | The server was missing a patch for a known exploited vulnerability |
| The operator moved to the file server with a local admin account | The same local admin password on every server |
| rclone uploaded 40 GB to MEGA | Nothing restricted outbound traffic from servers to file-sharing services |
| The helpdesk walked the user through installing a remote support tool | No verification step for inbound support calls |

Work it from the timeline: start at the impact and walk backwards, hop by hop,
to T0. Every link in the chain should point at a row. A link without a row is an
inference — mark it as one.

```
INCIDENT        <id> — <title>
SUMMARY         Two sentences: who, what, how far it got, and whether they are out.

TIMELINE (UTC)  T0 (first attacker activity)  <time>   evidence: <query + row>
                Detected                      <time>
                Contained                     <time>
                Evicted                       <time>
                Dwell time = Detected − T0          Time to contain = Contained − Detected

INITIAL ACCESS  <vector>  <ATT&CK technique>  evidence: <row>
ROOT CAUSE      <the condition that made the initial access work>
CONTRIBUTING    <what let it spread: privileges, flat network, missing detections>

ATTACK PATH     <device A> --RDP as <account>--> <device B> --PsExec as <account>--> <device C>

IMPACT          Accounts compromised:  <list>
                Devices touched:       <list>
                Data accessed:         <folders, labelled files>
                Data exfiltrated:      <position from Phase 8, and confidence>

IOCs / IOAs     hok-iocs.kql output attached; ATT&CK techniques by phase attached

WHAT WORKED     Detections that fired, actions that held
WHAT DIDN'T     Detections that did not fire; telemetry that was missing; slow steps

ACTIONS         Each one tied to the root cause or a contributing factor, with an owner and a date
CONFIDENCE      Proven / inferred / could not be determined — and why for the last
```

**Every action must point at a cause.** "Reset all passwords" is not an RCA
action unless credential reuse is in the causes. NIST SP 800-61 Rev. 3 frames
this as feeding the incident back into governance and protection, not just
closing it.

---

## Containment and eviction

With a hands-on-keyboard operator, eviction is one coordinated move, not a
series of fixes. A person watching will notice piecemeal changes and either dig
in deeper or go straight to impact.

When the register is complete, in this order and close together:

1. **Isolate every affected device** that is not already isolated.
2. **Disable every compromised account.** Reset it, and re-register MFA.
3. **If a domain controller or a domain admin account was touched**, Microsoft's
   incident response guidance is to reset the `krbtgt` password **twice in quick
   succession**, using a scripted process. Plan this with your AD team — it is
   not a step to improvise.
4. **Revoke cloud sessions** for affected users. See the
   [device code playbook](devicecode-playbook.md) for why a password reset alone
   is not enough.
5. **Remove persistence, remote access tools and tunnels**, and block their
   hashes as indicators so they cannot simply be reinstalled.
6. **Block the network IOCs**: C2, download hosts, exfil destinations.
7. **Reimage, don't clean**, any device where credential access, persistence or
   an unidentified tool was found.
8. **Watch for the return.** Run `hok-scope.kql` with the full IOC set daily,
   and `hok.kql` across the estate, for at least 30 days.

---

## Collecting without KQL — the Defender portal

Not everything needs a query.

| Tool | Where | What it gives you | Phase |
|---|---|---|---|
| Attack story and incident graph | Incident page | The alerts, entities and their relationships on one canvas | 0 |
| Activities tab | Incident page | Actions attack disruption took automatically — contained users, isolated devices | 0 |
| Device timeline | Device page → Timeline | Every event, with ATT&CK techniques, process trees, flags and *Hunt for related events*. Retained longer than Advanced Hunting's 30 days — 90 days by default. Export up to 7 days at a time. | 2 |
| Device overview | Device page | Logged-on users, internet-facing tag, missing patches — an unpatched internet-facing server is often the root cause | 0, 11 |
| Investigation package | Device page → response actions | Current state: connections, ARP, DNS cache, SMB sessions, autoruns, tasks, services, prefetch, temp files, security log | 1 |
| Live Response | Device page → response actions | A remote shell: `connections`, `processes`, `persistence`, `getfile` | 1, 6 |
| File page | Any file link | Global prevalence, signer, deep analysis, download for sandboxing | 9 |
| User page | Any account link | Defender for Identity activity and lateral movement paths | 5 |
| IP and URL pages | Any address link | Everywhere in the estate the address or URL appears | 10 |
| Defender for Cloud Apps activity log | Cloud apps → Activity log | Cloud activity by user, IP or app, with filters | 7, 8 |
| Action center | Top of any device page | What has already been done, by whom, and whether it worked | 1 |
| Advanced Hunting functions | Advanced Hunting | `FileProfile()`, `DeviceFromIP()`, `AssignedIPAddresses()`, `SeenBy()` — in `hok-enrich-ah.kql` | 3, 9 |

---

## For the ticket

- T0, detection time, containment time — and what stopped you pushing T0 back further
- The investigation register: every device and account, and its status
- The initial access vector, with the evidence row
- The attack path, hop by hop, with method and account
- Every connection channel used: C2, remote access tools, tunnels
- What moved away from the device, to where, with volume where known — and the exfiltration position with its confidence
- The `hok-iocs.kql` output, defanged
- The ATT&CK techniques observed, by phase
- Containment and eviction actions, with times
- The RCA

---

## Common false positives

| Looks like hands-on-keyboard | Actually |
|---|---|
| `Discovery burst` from an IT account | An administrator troubleshooting. Check the ticket queue for the same time. |
| `Remote access tool` on many devices | Your own support tooling. Check whether it is the version and path IT deploys. |
| `Attack tool` — PsExec or Sysinternals | Administrators use them. Who ran it, from where, and was it expected? |
| `Commands in RDP session` on a jump host | That is what jump hosts are for. The source address is the question. |
| `Admin-port fan-out` from a management server | Configuration management, vulnerability scanning, backup agents |
| `Sustained connection` to a cloud provider | Backup, sync or update traffic. `OrgDevices` high means it is normal for the estate. |
| `Archive written` by a backup tool | Scheduled backups. Check the process and the schedule. |
| `Credential access` from a security product | EDR, vulnerability scanners and backup agents open LSASS. Extend `LsassReaders`. |

`OrgDevices` and the `Actor` column settle most of these. An operator's tools
and destinations are rare in the estate; administrators' are everywhere.

---

## What none of this proves

Stated plainly, because these are the assumptions that close incidents early:

- **An empty result is only as good as the telemetry behind it.** Check sensor
  health, retention and the coverage table before reading a blank as clean.
- **No file events does not mean no files were read.** Defender does not log
  reads.
- **No exfil channel does not mean no exfiltration.** Defender has no byte
  counts, and encrypted traffic to a common cloud service looks like everything
  else. A copy to another machine is only visible if that machine is onboarded.
- **A `ConnectionSuccess` is not proof the connection was allowed.** Network
  protection decides after the TCP handshake.
- **Nothing in `1-Before` does not mean the device was the first.** The operator
  may have come from a machine you have not looked at yet — that is what the
  register is for.
- **No persistence found does not mean none exists.** Anything created before
  retention will only show in Live Response or the investigation package.
- **A clean device does not mean a clean account.** Credentials taken here can
  be used anywhere.

None of these queries have been run against live telemetry — they are reviewed
for KQL correctness and schema accuracy only. Test them in your own tenant.

---

## Sources

- Microsoft Learn — [Microsoft Incident Response team ransomware approach and best practices](https://learn.microsoft.com/security/ransomware/incident-response-playbook-dart-ransomware-approach)
- Microsoft Learn — [Detecting human-operated ransomware attacks with Microsoft Defender XDR](https://learn.microsoft.com/defender-xdr/playbook-detecting-ransomware-m365-defender)
- Microsoft Learn — [Take response actions on a device](https://learn.microsoft.com/defender-endpoint/respond-machine-alerts) (isolation, investigation package, containment)
- Microsoft Learn — [Investigate entities on devices using live response](https://learn.microsoft.com/defender-endpoint/live-response)
- Microsoft Learn — [Investigate devices: the device timeline](https://learn.microsoft.com/defender-endpoint/investigate-machines#investigate-device-timeline)
- Microsoft Learn — [Advanced hunting with Microsoft Sentinel data in the Defender portal](https://learn.microsoft.com/defender-xdr/advanced-hunting-microsoft-defender) (the `Timestamp` / `TimeGenerated` 48-hour note)
- Microsoft Learn — [Use network protection](https://learn.microsoft.com/defender-endpoint/network-protection) (TCP handshake and QUIC caveats)
- Microsoft Learn — [Extend advanced hunting coverage with the right settings](https://learn.microsoft.com/defender-xdr/advanced-hunting-extend-data) (audit policy)
- Microsoft Learn — [FileProfile()](https://learn.microsoft.com/defender-xdr/advanced-hunting-fileprofile-function), [DeviceFromIP()](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicefromip-function), [AssignedIPAddresses()](https://learn.microsoft.com/defender-xdr/advanced-hunting-assignedipaddresses-function), [SeenBy()](https://learn.microsoft.com/defender-xdr/advanced-hunting-seenby-function)
- NIST — [SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- The DFIR Report — [thedfirreport.com](https://thedfirreport.com/), intrusion write-ups from 2024–2025 (the AdFind, AnyDesk and rclone patterns)
- crtvrffnrt — [Microsoft Incident Response Playbook](https://github.com/crtvrffnrt/Microsoft-Incident-Response-Playbook)
