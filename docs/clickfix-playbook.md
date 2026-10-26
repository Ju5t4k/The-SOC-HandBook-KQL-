# ClickFix — investigation playbook

**Use when** an alert, a user report or a threat-intel hit points at ClickFix (fake CAPTCHA / "fix this error" pages).
**Goal:** prove the paste, find the payload, decide whether credentials left with it.

| Step | Query |
|---|---|
| 1 Confirm | [`clickfix.kql`](../queries/clickfix.kql) |
| 2 Other paste surfaces | [`clickfix-paste.kql`](../queries/clickfix-paste.kql) |
| 3 Reconstruct | [`clickfix-timeline.kql`](../queries/clickfix-timeline.kql) |
| 5 What it took | [`clickfix-impact.kql`](../queries/clickfix-impact.kql) |
| 7 Persistence | [`clickfix-persistence.kql`](../queries/clickfix-persistence.kql) |
| 8 Scope | [`clickfix-scope.kql`](../queries/clickfix-scope.kql) |

---

## How the attack works

- A web page writes a command to the clipboard and tells the victim to paste it somewhere that runs it.
- **The user runs the payload themselves.** No exploit, no attachment, no macro — mail and web filters have nothing to catch.
- The payload is usually an **infostealer**. Browser cookies and refresh tokens leave with it, so a clean device does not mean a clean account.

### Where victims are told to paste

| Surface | Lure says | Leaves | Where |
|---|---|---|---|
| Win+R | "Press Win+R, Ctrl+V, Enter" | `RunMRU` value, `explorer.exe` parent | `DeviceRegistryEvents` |
| Explorer address bar | "Click the path bar, paste" | `TypedPaths` value, `explorer.exe` parent | `DeviceRegistryEvents` |
| File-open dialog ("FileFix") | "Paste this path to upload" | Nothing readable | Parent process only |
| Open console | "Open PowerShell and paste" | **No command line at all** | `DeviceEvents` `PowerShellCommand` (needs script block logging) |
| Browser protocol handler | One click, no paste | Browser as parent | `DeviceProcessEvents` |
| macOS / Linux Terminal | "Paste into Terminal" | Shell command line | `DeviceProcessEvents` |

Only the first two leave text you can match. **An empty `clickfix.kql` rules out two surfaces, not six.**

## Attack timeline

| When | Attacker | Telemetry | Table |
|---|---|---|---|
| T+0 | Victim loads the lure page | Browser connection, or a Safe Links click | `DeviceNetworkEvents`, `UrlClickEvents` |
| T+30s | Victim pastes | `RunMRU` / `TypedPaths` write, or nothing | `DeviceRegistryEvents` |
| T+31s | First stage runs | `explorer.exe` or browser → LOLBin | `DeviceProcessEvents` |
| T+32s | Second stage downloaded | LOLBin outbound | `DeviceNetworkEvents` |
| T+40s | Loader written | File with `FileOriginUrl` | `DeviceFileEvents` |
| T+2m | Persistence | Run key, task, COM hijack | `DeviceRegistryEvents` |
| T+5m | **Stealer runs** | Browser killed, credential store copied | `DeviceFileEvents`, `DeviceProcessEvents` |
| T+1h–24h | **Stolen token replayed** | Non-interactive sign-in, new ASN | `AADNonInteractiveUserSignInLogs` |

---

## Steps

### 1. Confirm · 5 min

**Run** `clickfix.kql` with `DeviceCheck`.

**Read first:** `PasteMatch` — the pasted text that also appears in a command line.

| `PasteMatch` | Score | Decide |
|---|---|---|
| not empty | any | **Confirmed.** Go to step 3. |
| empty | 5+ | Probable. Rule out admin or deployment tools, then step 3. |
| empty | 2–4 | Suspicious. Check `ParentIsExplorer`, `ParentIsBrowser` and the account. |
| empty | 1 or less | Nothing on these surfaces. **Go to step 2 before closing.** |

Score — 11 indicators, 15 maximum:

| Weight | Indicator |
|---|---|
| +3 | `PasteHits` — the pasted text ran verbatim |
| +2 | `ParentIsExplorer` — started by the desktop |
| +2 | A paste exists on the device in the window |
| +1 | `HasDownload` — download-and-run words |
| +1 | `HasStealth` — hidden window, bypass, encoded |
| +1 | `HasLure` — captcha, verify, robot, ✅ |
| +1 | `HasBase64` — long base64 run |
| +1 | `LongCommand` — over 200 characters |
| +1 | `ParentIsBrowser` — started by a browser |
| +1 | `BareShell` — console opened with no arguments from the desktop or a browser |
| +1 | Command seen on 2 devices or fewer in the estate |

Record `EventTime` as the **pivot time**.

### 2. Other paste surfaces · 10 min

Run this when step 1 is empty or weak.

**Run** `clickfix-paste.kql` with `DeviceCheck`. Each row gets a `Surface`:

```
Win+R                                matched to the RunMRU write
Explorer address bar                 matched to the TypedPaths write
Browser spawned                      a shell started by the browser
Console typed or pasted              script block logging caught it
Interactive shell, no command line   a console opened from the desktop, nothing visible typed
Unix shell                           macOS or Linux fetch-and-run
Other                                nothing explains it — read the row
```

- `TextMatch` true = proof. `SecondsFromPaste` in single digits = a person hitting Enter.
- `(unmatched)` after a surface = a paste happened within two minutes but the text differs. Usually coincidence.
- `Interactive shell, no command line` with nothing after it means **logging gap**, not clean. Go to step 5.

### 3. Reconstruct · 15 min

**Run** `clickfix-timeline.kql` with `PivotTime`, `DeviceCheck`, `UserIdentityCheck`.

```
1-Lure         browsing and Safe Links clicks before the paste
2-Paste        RunMRU/TypedPaths writes and console commands
3-Execution    what the desktop and the LOLBins ran
4-Download     downloads by LOLBins or programs in user folders
5-Disk         files from the web, executables, scripts, archives
6-Persistence  autoruns written in the window
7-Defence      AV, ASR and tamper events
8-Identity     sign-ins, token use, directory changes
9-Cloud        Microsoft 365 activity
```

If `1-Lure` is empty, widen `BeforeWindow` to `6h`.

### 4. Lure and payload

- **Lure:** the site in `1-Lure` just before `2-Paste`. Malvertising, SEO poisoning, compromised site, phishing link or QR code? That decides whether you block a domain or raise a wider issue. A `Safe Links click` row means it came by mail or Teams.
- **Payload:** every host in `4-Download`, every file and `FileOriginUrl` in `5-Disk`. Submit the hashes. Unknown to everything = treat as targeted.

### 5. What it took · 15 min

**Run** `clickfix-impact.kql` with `DeviceCheck`.

```
Credential store     a browser password or cookie database copied by something else
Browser killed       browser stopped to unlock its database
LSASS access         LSASS opened or read
Staged archive       data packed in a staging folder
Exfil channel        a program posting to Telegram, Discord or a paste site
Remote access tool   remote support tool run or installed
Discovery            recon launched by a LOLBin
Defence tampering    exclusions, protection off, tamper events
```

- **`Credential store`** → assume every session cookie in that browser is stolen. Go to step 6 now.
- **`Remote access tool`** → the attacker has hands-on access. Work it with the [hands-on-keyboard playbook](hok-playbook.md).
- **`Defence tampering`** → telemetry after that time is suspect.

### 6. Identity · the step people skip

Rows `8-Identity` in the timeline, then:

- **Token replay is non-interactive** — it only appears in `AADNonInteractiveUserSignInLogs`, never in `SigninLogs`. Look for a new IP/ASN using the user's session.
- [`signinlogs.kql`](../queries/signinlogs.kql): IPs with `DaysIpSeenByUser` of 0–1.
- [`officeactivity.kql`](../queries/officeactivity.kql): `DaysUserSignedInFromIP` of 0.
- [`auditlogs.kql`](../queries/auditlogs.kql): MFA methods, consent, secrets added.

### 7. Persistence · the reimage decision

**Run** `clickfix-persistence.kql` with `DeviceCheck`.

```
Registry-Autorun        Run keys, Winlogon Userinit/Shell, IFEO debuggers
Task-Service            tasks and services from the command line
Service-Task-Installed  services and tasks as the sensor recorded them
PowerShell-Persistence  tasks, services, profiles, WMI from PowerShell
Startup-Folder          files in a Startup folder
LOLBin-Write            executables a LOLBin wrote to user folders
COM-Hijack              user-hive CLSID pointed at attacker code
Shell-Hijack            AppInit and service DLLs, startup shell folders
Browser-Extension       forced extensions and native messaging hosts
```

Anything a LOLBin wrote in the window is the attacker's until proven otherwise. If step 5 found theft, reimage regardless.

### 8. Scope

**Run** `clickfix-scope.kql` with `UrlCheck`, `HashCheck`, `CommandCheck` or `IPCheck`.

```
Command        same command on another device
Paste          same text in Win+R or the address bar
Network        traffic to the same host
File           same file, or same FileOriginUrl
Execution      same file run
Mail delivery  who was sent the lure — including those who have not clicked
Url click      who clicked, and who clicked through the warning
```

One device is an incident; fifteen in an hour is a campaign. A device with an unhealthy sensor and no hits is silent, not clean.

---

## Contain

1. **Isolate the device.** Don't shut it down.
2. **Revoke the user's sessions** — a password reset alone leaves stolen tokens working.
3. Reset the password; re-register MFA if methods changed.
4. Remove remote access tools and block them by hash.
5. Check mailbox rules.
6. Reverse Defender exclusions and re-check telemetry from that period.
7. Block the lure domain, payload hosts, hashes and exfil destinations.
8. Reimage if persistence, credential theft or an unidentified payload was found. Have the user sign out of browser sync first, or forced extensions come back.

## Ticket

- Pivot time, paste surface, `PasteMatch` text
- Lure URL, and how it arrived (browsing, mail, QR)
- Payload hosts and SHA256s with `FileOriginUrl`
- Every `clickfix-impact.kql` row — and plainly whether a credential store was copied
- Persistence found
- Devices and accounts from scope, and how many received the lure without clicking
- When sessions were revoked

## False positives

| Looks like ClickFix | Usually |
|---|---|
| High score, no `PasteMatch`, admin account | An admin using Win+R for work |
| `explorer.exe` → `powershell.exe`, clean command | A user double-clicking a `.ps1` |
| Encoded PowerShell on many devices | Deployment tooling — check `DevicesRanThisCommand` |
| Interactive shell, no command line, developer | A developer opening a terminal |
| Remote access tool on many devices | Your own IT tooling |
| Credential store written by a backup agent | Backup software reading the profile |

## Limits

- Empty `PasteMatch` covers two of six surfaces only.
- A console with no command line and no script block logging has no record of what was typed.
- A blocked payload doesn't mean earlier stages failed.
- Defender doesn't log file reads. A stealer that reads in place leaves no `Credential store` row.
- Not run against live telemetry. Reviewed for KQL correctness and schema only.
