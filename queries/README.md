# Queries

| File | Table | What it does |
|---|---|---|
| [`signinlogs.kql`](signinlogs.kql) | `SigninLogs` | Was this account used, and by whom. Job details, new-starter check, and day-counts for the IP, device, location, user agent and application |
| [`auditlogs.kql`](auditlogs.kql) | `AuditLogs` | What did they change once they were in. Actor and target on every row, old and new values unpacked, and how routine the operation is for that actor |
| [`officeactivity.kql`](officeactivity.kql) | `OfficeActivity` | What did they actually do to the data. Exchange, SharePoint, OneDrive and Teams activity with the source address scored against the account's sign-ins |
| [`clickfix.kql`](clickfix.kql) | `DeviceProcessEvents` | One-shot ClickFix triage. Scores a process against the fake-CAPTCHA pattern and proves the paste from the `RunMRU` and `TypedPaths` registry keys |
| [`clickfix-paste.kql`](clickfix-paste.kql) | `DeviceProcessEvents`, `DeviceEvents`, `DeviceRegistryEvents` | The paste surfaces Win+R is not — the Explorer address bar, a browser-spawned shell, a console with no command line, a macOS Terminal. Run it when `clickfix.kql` is empty |
| [`clickfix-timeline.kql`](clickfix-timeline.kql) | `Device*`, `UrlClickEvents`, `SigninLogs`, non-interactive, `AuditLogs`, `OfficeActivity` | The ClickFix incident as one timeline, tagged by phase: lure, paste, execution, download, disk, persistence, defence, identity, cloud |
| [`clickfix-impact.kql`](clickfix-impact.kql) | `Device*` | What the payload took. Browser credential stores, LSASS, staged archives, exfil channels, RMM tooling and defence tampering |
| [`clickfix-persistence.kql`](clickfix-persistence.kql) | `Device*` | What was left behind — run keys, tasks, services, startup folder, LOLBin drops, COM and shell hijacks, browser extensions. The reimage decision |
| [`clickfix-scope.kql`](clickfix-scope.kql) | `Device*`, `EmailUrlInfo`, `UrlClickEvents` | Blast radius. Give it a URL, hash, command or IP and it finds every other device and user hit the same way — and everyone who was sent the lure but has not clicked yet |
| [`devicecode.kql`](devicecode.kql) | `SigninLogs` | Device code phishing triage. Finds `AuthenticationProtocol == "deviceCode"` sign-ins and scores them, including whether the issued token was later used from a different ASN |
| [`devicecode-timeline.kql`](devicecode-timeline.kql) | `SigninLogs`, non-interactive, service principal, `AuditLogs`, `OfficeActivity` | The device code incident as one timeline: delivery, code entry, token use, service principals, directory changes, cloud activity |
| [`devicecode-persistence.kql`](devicecode-persistence.kql) | `AuditLogs`, `OfficeActivity`, service principal | What survives a password reset — MFA methods, app consent, service principal credentials, mailbox rules |
| [`devicecode-scope.kql`](devicecode-scope.kql) | `SigninLogs`, non-interactive | Blast radius by IP, ASN, app or user agent. ASN is the one that finds the campaign |
| [`bec.kql`](bec.kql) | `OfficeActivity` | BEC triage. Scores mailbox rules, forwarding and delegation for the hide-and-redirect pattern, against outbound volume and whether the actor signed in from that address |
| [`bec-timeline.kql`](bec-timeline.kql) | `SigninLogs`, `OfficeActivity`, `EmailEvents`, `AuditLogs` | The BEC as one timeline: access, reconnaissance, mailbox change, outbound fraud, the hijacked thread, directory changes, files |
| [`bec-persistence.kql`](bec-persistence.kql) | `OfficeActivity`, `AuditLogs` | Rules, forwarding, delegation, tenant-wide transport rules and directory footholds — everything a password reset leaves behind |
| [`bec-scope.kql`](bec-scope.kql) | `OfficeActivity`, `EmailEvents`, `SigninLogs` | Other mailboxes forwarding to the same place, and every outside party who received the fraudulent thread |
| [`attachment.kql`](attachment.kql) | `EmailAttachmentInfo`, `EmailEvents`, `Device*` | Attachment triage. Joins the mail verdict to the endpoint on `SHA256` — did it land, did it run |
| [`attachment-timeline.kql`](attachment-timeline.kql) | `Email*`, `UrlClickEvents`, `Device*` | Delivery, attachment, links, clicks, ZAP and endpoint execution on one timeline, keyed off a message id or a hash |
| [`attachment-scope.kql`](attachment-scope.kql) | `Email*`, `Device*` | Everyone who received the same file, sender or subject, and every device it reached or ran on |
| [`hok.kql`](hok.kql) | `Device*` | Hands-on-keyboard triage. Is a person driving this device, and are they still on it? Eleven indicators, scored, with `ActiveNow` |
| [`hok-timeline.kql`](hok-timeline.kql) | `Device*`, `IdentityQueryEvents` | The intrusion on one device in ten phases, every row tagged with an ATT&CK technique — the IOA list |
| [`hok-connections.kql`](hok-connections.kql) | `Device*`, `IdentityLogonEvents` | Every connection in and out, tagged before, during and after, with internal addresses resolved and internet destinations scored for rarity |
| [`hok-web.kql`](hok-web.kql) | `Device*`, `UrlClickEvents` | Browsing, downloads with the page that linked them, command-line downloads, SmartScreen, network protection, Safe Links |
| [`hok-lateral.kql`](hok-lateral.kql) | `Device*`, `Identity*` | Hops out of the device seen from both ends and from the domain controller, plus everywhere the account logged on |
| [`hok-files.kql`](hok-files.kql) | `DeviceFileEvents`, `DeviceEvents`, `CloudAppEvents` | Files opened, dropped, archived, changed over SMB, deleted, renamed, labelled, copied to removable media, pulled from SharePoint |
| [`hok-exfil.kql`](hok-exfil.kql) | `Device*`, `CloudAppEvents`, `EmailEvents` | Transfer tools, tunnels, storage services, sustained connections, removable media, cloud downloads and sharing, mail out |
| [`hok-iocs.kql`](hok-iocs.kql) | `AlertEvidence`, `Device*` | Every indicator from the window in one table — alert evidence plus rare hashes, destinations, URLs, accounts, persistence names and command lines |
| [`hok-scope.kql`](hok-scope.kql) | `Device*`, `Identity*`, `CloudAppEvents`, `Email*` | Any indicator from `hok-iocs.kql`, swept across the estate |
| [`hok-enrich-ah.kql`](hok-enrich-ah.kql) | Advanced Hunting only | `FileProfile()` on every file the device ran or wrote: global prevalence, first seen, signer |

The first three are identity and activity tables and run in sequence.

The `clickfix-*`, `devicecode-*`, `bec-*`, `attachment-*` and `hok-*` files are
threat-specific and meant to be worked in order. Each set has a playbook carrying the attack timeline, the
phase-by-phase investigation, the containment order and the ticket checklist:

- [`../docs/clickfix-playbook.md`](../docs/clickfix-playbook.md) — endpoint
  side, fake-CAPTCHA paste-and-run execution
- [`../docs/devicecode-playbook.md`](../docs/devicecode-playbook.md) — identity
  side, OAuth device code phishing
- [`../docs/bec-playbook.md`](../docs/bec-playbook.md) — mailbox side, business
  email compromise and invoice fraud
- [`../docs/attachment-playbook.md`](../docs/attachment-playbook.md) — mail and
  endpoint, malicious attachments
- [`../docs/hok-playbook.md`](../docs/hok-playbook.md) — a person operating
  inside the estate: connections, web, files, lateral movement, exfiltration,
  IOCs and IOAs, and the root cause analysis


## The order to run them in

Most tickets arrive as "look at this account" or "look at this address".
Either way:

```
1. signinlogs.kql       Did they get in, from where, and is any of it new
                        for this account?
2. auditlogs.kql        What did they change, and in what order?
3. officeactivity.kql   What did they touch, and what did they leave behind?
```

Step 3 is the one people skip, and it is the one that decides whether the
incident is over. A password reset closes step 1. It does nothing at all about
a forwarding rule.

## How to run one

Fill in the `CHECK` values at the top and run. They use `contains`, so a
partial value works and a blank one matches everything.

```kql
let TimeToCheck = 30d;
let UserIdentityCheck = "";      // <- put the account here
let IPtoCheck = "";
```

Swap `contains` for `=~` if you need an exact match — useful when a username
is a substring of other usernames.

## Reading the output

The recurring column is a **day count** — `DaysIpSeenByUser`,
`DaysOpSeenByActor`, `DaysUserSignedInFromIP`, `DaysClientSeenByUser`. Each
answers "on how many days of the window has this account used this thing".

A 1 means today is the first day. A 25 out of 30 means it is routine. One new
dimension is a new phone or a holiday. Four at once is a different person.

Two columns are worth calling out because they cross tables, and that is where
the answer usually is:

- **`DaysActorSeenFromIP`** (auditlogs) — how many days the person who made a
  directory change has *signed in* from the address they made it from. An
  administrator works from the address they always use. A 0 on a
  privilege-granting operation is the finding.
- **`DaysUserSignedInFromIP`** (officeactivity) — same idea for M365 activity.
  Zero means the session was established some other way: a stolen token, a
  mailbox delegation, or an application acting for the user.

## Cost

Left completely blank, these read the whole tenant and join it to itself
several times. Fine on a small workspace, expensive on a large one. Put
something in one of the `CHECK` values, or shorten `TimeToCheck`, before
running one wide.
