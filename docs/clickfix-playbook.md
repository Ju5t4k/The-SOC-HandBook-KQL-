# ClickFix — end-to-end investigation

For when an alert, a user report or a threat-intel hit points at ClickFix and
you have to work out what actually happened.

Six queries support this playbook. Each phase below names the one to run.

| Query | Phase |
|---|---|
| [`clickfix.kql`](../queries/clickfix.kql) | 0 — confirm |
| [`clickfix-paste.kql`](../queries/clickfix-paste.kql) | 1 — confirm when phase 0 is empty |
| [`clickfix-timeline.kql`](../queries/clickfix-timeline.kql) | 2 — reconstruct |
| [`clickfix-impact.kql`](../queries/clickfix-impact.kql) | 5 — what the payload took |
| [`clickfix-persistence.kql`](../queries/clickfix-persistence.kql) | 8 — what is still there |
| [`clickfix-scope.kql`](../queries/clickfix-scope.kql) | 9 — who else |

---

## What you are looking at

ClickFix is social engineering, not an exploit. A page — a fake CAPTCHA, a
"fix this browser error" banner, a fake Teams or Word update prompt — silently
writes a command to the clipboard and instructs the victim to paste it
somewhere that will run it.

Nothing is downloaded. Nothing is clicked. No macro runs, no vulnerability is
exploited, no attachment is opened. **The user executes the payload with their
own hands**, which is why mail filtering, web filtering and attachment sandboxes
all have nothing to catch. By the time anything is detectable, code is already
running as the user.

### Where they are told to paste

This is the part that decides whether you find it. Win+R is the original and
still the most common, but it is one surface of six, and it is the only one
that leaves a clean registry artefact.

| Surface | How the lure words it | What it leaves | Where to look |
|---|---|---|---|
| **Win+R Run dialog** | "Press Win+R, Ctrl+V, Enter" | `RunMRU` value, `explorer.exe` parent | `DeviceRegistryEvents` |
| **Explorer address bar** | "Open This PC, click the path bar, paste" | `TypedPaths` value, `explorer.exe` parent | `DeviceRegistryEvents` |
| **File-open dialog** ("FileFix") | "Upload your file — paste the path we gave you" | nothing readable; the dialog MRUs are binary | parent process chain only |
| **An open console** | "Open PowerShell and paste this" | **no process command line at all** | `DeviceEvents`, `ActionType == "PowerShellCommand"` |
| **Browser protocol handler** | nothing to paste; one click | browser is the parent process | `DeviceProcessEvents` |
| **macOS / Linux Terminal** | "Paste this into Terminal" | the shell's own command line | `DeviceProcessEvents` |

Two consequences worth internalising:

- **The console variant leaves no command line.** The process is
  `powershell.exe` with no arguments; the payload was typed into the window
  after it opened. Without PowerShell script block logging there is no record
  of what ran — only that a console was opened by the desktop.
- **Empty is not clean.** Four of the six surfaces above produce no registry
  artefact. `clickfix.kql` returning nothing rules out one surface, not six.

---

## The attack timeline

What the attacker does, and what it leaves behind.

| When | Attacker action | Telemetry | Table |
|---|---|---|---|
| T−days | Lure staged: malvertising, SEO poisoning, compromised site, phishing link, QR code | Mail delivery, Safe Links click | `EmailUrlInfo`, `UrlClickEvents` |
| T+0s | Victim loads the page; JavaScript writes the payload to the clipboard | Browser connection to lure host | `DeviceNetworkEvents`, `DeviceEvents` |
| T+30s | Victim pastes into whichever surface the lure named | **`RunMRU` or `TypedPaths` write, or nothing** | `DeviceRegistryEvents` |
| T+31s | First stage runs | **`explorer.exe` or a browser → LOLBin** | `DeviceProcessEvents` |
| T+32s | First stage fetches second stage | Outbound HTTP from a non-browser process | `DeviceNetworkEvents` |
| T+40s | Loader written to disk | File create, `FileOriginUrl` populated | `DeviceFileEvents` |
| T+2m | Persistence established | Run key, COM hijack, scheduled task, startup file | `DeviceRegistryEvents`, `DeviceProcessEvents` |
| T+3m | Defences excluded or disabled | `Add-MpPreference`, tampering events | `DeviceProcessEvents`, `DeviceEvents` |
| T+5m | Infostealer runs: browser credentials, cookies, **session tokens** | Browser killed, credential stores copied, archive staged | `DeviceFileEvents`, `DeviceProcessEvents` |
| T+6m | Collection posted to a dead drop | Non-browser process to Telegram, Discord, a paste site | `DeviceNetworkEvents` |
| T+10m | Remote access tooling installed as a second stage | RMM binary written and run | `DeviceFileEvents`, `DeviceProcessEvents` |
| T+1h–24h | Stolen token replayed from attacker infrastructure | **Non-interactive** sign-in, new ASN, no matching device | `AADNonInteractiveUserSignInLogs` |
| T+1h–days | Mailbox rules, mass download, onward phishing | Rule creation, bulk file access | `OfficeActivity` |
| T+days | Lateral movement, data theft, ransomware staging | — | — |

**The step that matters most is T+5m.** ClickFix is overwhelmingly an
infostealer delivery mechanism. Cleaning the endpoint does nothing about a
session token that was stolen and is already in use somewhere else.

---

## Investigation timeline

> The timeline query tags its own rows `1-Lure` through `9-Cloud`. Those are
> labels on the data. They are not the playbook phases below, which are numbered
> separately.

### Phase 0 — Confirm · 5 minutes

Run **`clickfix.kql`**. Set `DeviceCheck` to the hostname from the alert.

Read `PasteMatch` first. It holds the pasted text where that exact string also
appears in a command line — the paste and the execution, tied together.

| `PasteMatch` | `ClickFixScore` | Verdict |
|---|---|---|
| Not empty | any | **Confirmed.** The user pasted that exact command. Go to Phase 2. |
| Empty | ≥ 5 | **Probable.** Continue, but look for an admin or deployment-tool explanation. |
| Empty | 2–4 | Suspicious. Check `ParentIsExplorer`, `ParentIsBrowser` and who the account is. |
| Empty | ≤ 1 | Nothing found **on this surface**. Go to Phase 1 before closing. |

`PasteSurfaces` tells you which dialog it came from — `Win+R` or
`Explorer address bar`. `ClickFixScore` runs to 15 across 11 indicators.

Record the `EventTime` of the highest-scoring row. That is your **pivot time**
and every later phase hangs off it.

### Phase 1 — The other paste surfaces · 10 minutes

Run this when Phase 0 is empty or weak and you still believe it happened.

Run **`clickfix-paste.kql`** with `DeviceCheck` set. It covers every surface in
the table above, and labels each row with the one it thinks was used:

```
Win+R                                matched against the RunMRU write
Explorer address bar                 matched against the TypedPaths write
Browser spawned                      a shell started by the browser, not the desktop
Console typed or pasted              script block logging caught what had no command line
Interactive shell, no command line   a console opened by the desktop with no arguments
Unix shell                           macOS or Linux, fetch-and-run in one line
Other                                nothing here explains it — read the row yourself
```

A surface suffixed `(unmatched)` means a paste landed within two minutes of the
execution but the two strings are not the same. That is usually coincidence —
somebody used Win+R for something unrelated just before — so treat it as
context, not as evidence.

Two columns carry the argument:

- **`TextMatch`** — the pasted text and the executed command are the same
  string. This is proof, not inference.
- **`SecondsFromPaste`** — paste to execution. ClickFix is a human hitting
  Enter, so it is single-digit seconds. A gap of minutes is somebody working.

`Interactive shell, no command line` with nothing after it is the ambiguous
case, and it is common. It means a console was opened from the desktop and you
cannot see what was typed into it. That is a gap in logging, not a clean
result — see Phase 5 before you decide it was nothing.

### Phase 2 — Reconstruct · 15 minutes

Run **`clickfix-timeline.kql`**. Set `PivotTime` to the value from Phase 0 or 1,
`DeviceCheck` to the host, `UserIdentityCheck` to the user.

It returns one table, oldest first, tagged by phase:

```
1-Lure         the lure — browsing, and Safe Links clicks from mail or Teams
2-Paste        the RunMRU or TypedPaths write, and console commands
3-Execution    what explorer.exe or the browser spawned
4-Download     what that process fetched, from where
5-Disk         what was written to disk, and its FileOriginUrl
6-Persistence  persistence written in the window
7-Defence      what AV or ASR did, if anything
8-Identity     sign-ins, token use and directory changes for the user
9-Cloud        M365 activity in the window
```

Read it top to bottom. It is the incident narrative, in order, and it is what
goes in the ticket.

Widen `BeforeWindow` to `6h` if phase 1 is empty — users often browse for a
while before they act on the lure.

### Phase 3 — The lure

From the `1-Lure` rows, take the host the user was on immediately before the
`2-Paste` row.

Decide whether it was **malvertising** (ad network in the referrer chain),
**SEO poisoning** (search engine → fake download page), a **compromised
legitimate site**, a **phishing link**, or a **QR code** — `UrlClickEvents`
rows tell you it came through mail or Teams rather than through browsing, and
`EmailUrlInfo.UrlLocation` of `QRCode` tells you it was scanned off a screen or
a printout, usually on a phone you have no telemetry for.

That decision drives whether you block one domain or raise a wider problem.

If phase 1 is empty in both browser and mail telemetry, the lure arrived
outside anything you log — a personal device, a printed QR code, a phone call.
Ask the user. They will usually tell you, because at this point they know
something went wrong.

### Phase 4 — The payload

From `4-Download` and `5-Disk`:

- Every distinct external host contacted by a non-browser process
- Every file written, with its `SHA256` and its `FileOriginUrl`

`FileOriginUrl` is worth calling out — it ties a file on disk directly back to
the URL it came from, which is the cleanest single line of evidence you will
get.

Submit the hashes. If a hash is unknown to everything, treat it as targeted
rather than as harmless.

### Phase 5 — What it took · the phase that sets the blast radius

Run **`clickfix-impact.kql`** with `DeviceCheck` set. This is T+5m from the
attack timeline, and it is the phase that decides whether the incident ends at
the endpoint.

```
Credential store     a browser password or cookie database copied out of the profile
Browser killed       the browser stopped first, so the locked database could be read
LSASS access         credential theft that is not about the browser
Staged archive       collected data zipped up in a temp directory
Exfil channel        a non-browser process posting to Telegram, Discord or a paste site
Remote access tool   RMM tooling installed as a second stage
Discovery            host and domain reconnaissance run by a LOLBin
Defence tampering    exclusions added, real-time protection disabled, tampering events
```

Three of these change what you do next:

- **`Credential store`** is the finding. Defender does not log file *reads*, so
  the artefact is the **copy** — a new file called `Login Data`, `Cookies` or
  `key4.db` created by something that is not the browser. If this row exists,
  assume every session cookie in that browser profile is in someone else's
  hands and go to Phase 7 immediately.
- **`Remote access tool`** means the attacker has hands-on access and does not
  need the stolen token at all. It is also not malware, so nothing will flag it
  and nothing will quarantine it. Removing it is a separate job from the reimage.
- **`Defence tampering`** tells you the rest of your telemetry is suspect from
  that timestamp forward. An exclusion path added at T+3m explains a quiet
  T+5m.

Tune this one before you trust it. If your organisation deploys any of the RMM
tools in the list legitimately, that row will be noisy; if it deploys none of
them, a single hit is the whole incident.

### Phase 6 — Defensive reaction

The `7-Defence` rows tell you whether anything stopped it.

**Blocked is not the same as prevented.** A detection at the third stage still
means stages one and two ran to completion. Read what was blocked and when,
against the rest of the timeline, before concluding the attack failed.

Empty here is common and means nothing either way — particularly if Phase 5
found `Defence tampering`.

### Phase 7 — Identity impact · the phase people skip

Rows tagged `8-Identity` and `9-Cloud`.

ClickFix usually delivers an infostealer, and infostealers take **session
cookies and refresh tokens**. A stolen token is used from the attacker's own
infrastructure and does not need the password or the second factor.

The timeline reads `AADNonInteractiveUserSignInLogs` as well as `SigninLogs`,
and that matters: **replaying a stolen token is not an interactive sign-in.**
It never appears in `SigninLogs`. If you only look there, token replay is
invisible and the account looks quiet.

On those rows, read:

- `IncomingTokenType` — a primary refresh token in use from an address the user
  has never signed in from
- The ASN — the same token used from two autonomous systems inside an hour is
  the whole argument

Then pivot to [`signinlogs.kql`](../queries/signinlogs.kql) for the user:

- Sign-ins from an IP with `DaysIpSeenByUser` of 0 or 1
- `NewToUser` of 3 or 4 — new IP, new device, new location, new agent at once

Then [`officeactivity.kql`](../queries/officeactivity.kql), looking for
`DaysUserSignedInFromIP` of 0 — activity with no sign-in behind it, which is
what token replay looks like from the data side.

Then [`auditlogs.kql`](../queries/auditlogs.kql) for MFA method registration,
app consent and secret additions by that account.

**If a token was stolen, a password reset does not end the incident.** You have
to revoke sessions.

### Phase 8 — What is still there · the reimage decision

Run **`clickfix-persistence.kql`** with `DeviceCheck` set.

It returns nine kinds of foothold:

```
Registry-Autorun        Run, RunOnce, Winlogon, IFEO
Task-Service            schtasks, sc, at, reg, wmic, bitsadmin from the command line
Service-Task-Installed  services and tasks as the sensor saw them, not as a command line
PowerShell-Persistence  scheduled tasks, services, profile.ps1, WMI subscriptions
Startup-Folder          files dropped into the Startup folder
LOLBin-Write            executables written by a LOLBin into user-writable paths
COM-Hijack              a user-hive CLSID pointed at attacker code
Shell-Hijack            AppInit_DLLs, Userinit, Shell, User Shell Folders
Browser-Extension       forced extension installs and native messaging hosts
```

The last three are the ones that survive a tidy-up. Everybody checks Run keys.
A `COM-Hijack` under `HKCU\Software\Classes\CLSID` is as durable and nobody
looks, and a `Browser-Extension` comes back down on its own the moment the user
signs into browser sync on a rebuilt machine.

Anything here written by a LOLBin in the incident window is attacker
persistence until proven otherwise. Filter with `| where SetBy in~ (LolBins)`
to separate it from legitimate installers.

Nothing found does not mean nothing is there — it means nothing was found in
telemetry you have. If phases 4–7 were serious, reimage regardless.

### Phase 9 — Scope · who else

Run **`clickfix-scope.kql`** with whichever indicator you have: `UrlCheck`,
`HashCheck`, `CommandCheck` or `IPCheck`.

It searches seven ways across the estate:

```
Command        the same command line on another device
Paste          the same text in Win+R or the Explorer address bar
Network        traffic to the same host
File           the same file on disk, or the same FileOriginUrl
Execution      the same file executed
Mail delivery  who else received a message carrying the lure URL
Url click      who else clicked it, and who clicked through the warning page
```

The two mail hits answer a question endpoint telemetry cannot. Endpoint data
shows who *opened* the lure. `Mail delivery` shows who *received* it — which is
the population still at risk — and `Url click` shows who clicked through a Safe
Links warning to reach it anyway.

Use the summarize variant at the bottom of the file to get the campaign shape
day by day. One device is an incident. Fifteen across three departments in an
hour is a campaign, and that changes who you wake up.

Check `SensorHealthState` and `OnboardingStatus` on the results. A device with
an unhealthy sensor that shows no hits is not clean — it is silent.

---

## Containment

In this order, because the order matters:

1. **Isolate the device.** Not shut down — isolate. Shutting down destroys
   memory evidence and does not stop a stolen token.
2. **Revoke the user's sessions.** Revoke refresh tokens, not just a password
   reset. A password reset alone leaves a stolen session working.
3. **Reset the password** and re-register MFA if any auth-method change appears
   in `auditlogs.kql`.
4. **Remove any remote access tooling** found in Phase 5, and block it by
   indicator. It is signed, legitimate software; nothing else on this list
   touches it.
5. **Check for mailbox rules** before you close anything — a forwarding rule
   survives every other step on this list.
6. **Reverse any defence tampering.** Remove the exclusion paths, re-enable
   real-time protection, and re-check the telemetry you collected while they
   were in force.
7. **Block the indicators**: lure domain, payload host, file hashes, exfil
   destination.
8. **Reimage** if persistence was found, if credential theft is suspected, or if
   the payload is unidentified. Have the user sign out of browser sync
   everywhere first, or a forced extension comes straight back.

---

## For the ticket

Pull these from the queries and paste them in:

- Pivot time, the paste surface, and the `PasteMatch` string — the proof
- The lure URL, and whether it arrived by browsing, mail or QR code
- Every payload host and every SHA256, with `FileOriginUrl`
- Every row from `clickfix-impact.kql`, and explicitly whether a credential
  store was copied
- Persistence found, with its location
- Every account and device from `clickfix-scope.kql`, and how many people
  received the lure without clicking
- Whether sessions were revoked, and when

---

## Common false positives

| Looks like ClickFix | Actually |
|---|---|
| High score, no `PasteMatch`, admin account | Someone genuinely using Win+R for their job |
| `explorer.exe` → `powershell.exe`, clean command line | A user double-clicking a `.ps1` |
| Encoded PowerShell on many devices | Deployment tooling — check `DevicesRanThisCommand` |
| `mshta` from `explorer.exe` | A legacy line-of-business app |
| `Interactive shell, no command line` on a developer's machine | A developer opening a terminal |
| `Remote access tool` across many devices at once | Your own IT tooling — tune `RmmNames` |
| `Credential store` written by a backup or sync agent | Endpoint backup software reading the profile |
| `TypedPaths` write with a UNC path | Someone typing a file share into Explorer |

`DevicesRanThisCommand` is the quickest discriminator. ClickFix generates a
command unique to the victim. Admin tooling appears everywhere.

---

## What none of this proves

Stated plainly, because these are the assumptions that close incidents early:

- **Empty `PasteMatch` does not mean no paste.** It covers two of the six
  surfaces. The other four leave nothing to match against.
- **No command line does not mean no command.** A console opened with no
  arguments is the paste-into-terminal variant, and without script block
  logging there is no record of what was typed.
- **A blocked payload does not mean nothing ran.** Earlier stages completed.
- **A clean endpoint does not mean a clean account.** Tokens leave with the
  data, not with the process.
- **No sign-in anomaly does not mean no token replay.** Replay is
  non-interactive and never reaches `SigninLogs`.
- **No persistence found does not mean no persistence.** It means none was
  found in the telemetry you have.
- **`clickfix-impact.kql` finding nothing does not mean nothing was taken.**
  Defender does not log file reads. It logs the copy, and a stealer that reads
  in place leaves no row at all.

None of these queries have been run against live telemetry — they are reviewed
for KQL correctness and schema accuracy only. Test them in your own tenant.
