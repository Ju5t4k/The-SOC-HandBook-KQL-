# ClickFix — end-to-end investigation

For when an alert, a user report or a threat-intel hit points at ClickFix and
you have to work out what actually happened.

Four queries support this playbook. Each phase below names the one to run.

| Query | Phase |
|---|---|
| [`clickfix.kql`](../queries/clickfix.kql) | 0 — confirm |
| [`clickfix-timeline.kql`](../queries/clickfix-timeline.kql) | 1–5 — reconstruct |
| [`clickfix-persistence.kql`](../queries/clickfix-persistence.kql) | 6 — what is still there |
| [`clickfix-scope.kql`](../queries/clickfix-scope.kql) | 7 — who else |

---

## What you are looking at

ClickFix is social engineering, not an exploit. A page — a fake CAPTCHA, a
"fix this browser error" banner, a fake Teams or Word update prompt — silently
writes a command to the clipboard and instructs the victim to press **Win+R**,
paste, and hit Enter.

Nothing is downloaded. Nothing is clicked. No macro runs, no vulnerability is
exploited, no attachment is opened. **The user executes the payload with their
own hands**, which is why mail filtering, web filtering and attachment sandboxes
all have nothing to catch. By the time anything is detectable, code is already
running as the user.

Two artefacts make it provable:

- The Run dialog belongs to `explorer.exe`, so the first process is **spawned by
  explorer.exe**.
- The pasted text is written to **`HKCU\...\Explorer\RunMRU`**.

Neither is subtle once you know to look.

---

## The attack timeline

What the attacker does, and what it leaves behind.

| When | Attacker action | Telemetry | Table |
|---|---|---|---|
| T−days | Lure staged: malvertising, SEO poisoning, compromised site, phishing link | — | — |
| T+0s | Victim loads the page; JavaScript writes the payload to the clipboard | Browser connection to lure host | `DeviceNetworkEvents`, `DeviceEvents` |
| T+30s | Victim presses Win+R, Ctrl+V, Enter | **`RunMRU` value written** | `DeviceRegistryEvents` |
| T+31s | First stage runs | **`explorer.exe` → LOLBin** | `DeviceProcessEvents` |
| T+32s | First stage fetches second stage | Outbound HTTP from a non-browser process | `DeviceNetworkEvents` |
| T+40s | Loader written to disk | File create, `FileOriginUrl` populated | `DeviceFileEvents` |
| T+2m | Persistence established | Run key, scheduled task, startup file | `DeviceRegistryEvents`, `DeviceProcessEvents` |
| T+5m | Infostealer runs: browser credentials, cookies, **session tokens** | AV detection, LSASS access, file reads | `DeviceEvents` |
| T+1h–24h | Stolen token replayed from attacker infrastructure | Sign-in from a new IP with no matching device | `SigninLogs` |
| T+1h–days | Mailbox rules, mass download, onward phishing | Rule creation, bulk file access | `OfficeActivity` |
| T+days | Lateral movement, data theft, ransomware staging | — | — |

**The step that matters most is T+5m.** ClickFix is overwhelmingly an
infostealer delivery mechanism. Cleaning the endpoint does nothing about a
session token that was stolen and is already in use somewhere else.

---

## Investigation timeline

### Phase 0 — Confirm · 5 minutes

Run **`clickfix.kql`**. Set `DeviceCheck` to the hostname from the alert.

Read `RunMRUMatch` first.

| `RunMRUMatch` | `ClickFixScore` | Verdict |
|---|---|---|
| Not empty | any | **Confirmed.** The user pasted that exact command into Win+R. Go to Phase 1. |
| Empty | ≥ 5 | **Probable.** Continue, but look for an admin or deployment-tool explanation. |
| Empty | 2–4 | Suspicious. Check `ParentIsExplorer` and who the account is. |
| Empty | ≤ 1 | Likely not ClickFix. Close with a note. |

Record the `EventTime` of the highest-scoring row. That is your **pivot time**
and every later phase hangs off it.

> An empty result is not an all-clear. `RunMRU` only records the Run dialog. If
> the user was told to paste into an already-open PowerShell window — a
> documented variant — there will be no registry artefact at all. Fall back to
> `ClickFixScore` and the `explorer.exe` parent.

### Phase 1 — Reconstruct · 15 minutes

Run **`clickfix-timeline.kql`**. Set `PivotTime` to the value from Phase 0,
`DeviceCheck` to the host, `UserIdentityCheck` to the user.

It returns one table, oldest first, tagged by phase:

```
1-Lure         the lure page the command was copied from
2-Paste        the RunMRU write — the paste itself
3-Execution    what explorer.exe spawned
4-Download     what that process fetched, from where
5-Disk         what was written to disk, and its FileOriginUrl
6-Persistence  persistence written in the window
7-Defence      what AV or ASR did, if anything
8-Identity     sign-ins for the user in the window
9-Cloud        M365 activity in the window
```

Read it top to bottom. It is the incident narrative, in order, and it is what
goes in the ticket.

Widen `BeforeWindow` to `6h` if phase 1 is empty — users often browse for a
while before they act on the lure.

### Phase 2 — The lure

From the `1-Lure` rows, take the host the user was on immediately before the
`2-Paste` row.

Decide whether it was **malvertising** (ad network in the referrer chain),
**SEO poisoning** (search engine → fake download page), a **compromised
legitimate site**, or a **phishing link**. That decision drives whether you
block one domain or raise a wider problem.

If phase 1 is empty, the lure may have been delivered outside the browser — a
Teams message, a QR code, a personal device. Ask the user. They will usually
tell you, because at this point they know something went wrong.

### Phase 3 — The payload

From `4-Download` and `5-Disk`:

- Every distinct external host contacted by a non-browser process
- Every file written, with its `SHA256` and its `FileOriginUrl`

`FileOriginUrl` is worth calling out — it ties a file on disk directly back to
the URL it came from, which is the cleanest single line of evidence you will
get.

Submit the hashes. If a hash is unknown to everything, treat it as targeted
rather than as harmless.

### Phase 4 — Defensive reaction

The `7-Defence` rows tell you whether anything stopped it.

**Blocked is not the same as prevented.** A detection at the third stage still
means stages one and two ran to completion. Read what was blocked and when,
against the rest of the timeline, before concluding the attack failed.

Empty here is common and means nothing either way.

### Phase 5 — Identity impact · the phase people skip

Rows tagged `8-Identity` and `9-Cloud`.

ClickFix usually delivers an infostealer, and infostealers take **session
cookies and refresh tokens**. A stolen token is used from the attacker's own
infrastructure and does not need the password or the second factor.

Pivot to [`signinlogs.kql`](../queries/signinlogs.kql) for the user and check:

- Sign-ins from an IP with `DaysIpSeenByUser` of 0 or 1
- `NewToUser` of 3 or 4 — new IP, new device, new location, new agent at once
- Non-interactive sign-ins from an address that never signed in interactively

Then [`officeactivity.kql`](../queries/officeactivity.kql), looking for
`DaysUserSignedInFromIP` of 0 — activity with no sign-in behind it, which is
what token replay looks like from the data side.

Then [`auditlogs.kql`](../queries/auditlogs.kql) for MFA method registration,
app consent and secret additions by that account.

**If a token was stolen, a password reset does not end the incident.** You have
to revoke sessions.

### Phase 6 — What is still there · the reimage decision

Run **`clickfix-persistence.kql`** with `DeviceCheck` set.

It returns five kinds of foothold:

```
Registry-Autorun        Run, RunOnce, Winlogon, IFEO
Task-Service            schtasks, sc, at, reg, wmic from the command line
PowerShell-Persistence  scheduled tasks, services, profile.ps1, WMI subscriptions
Startup-Folder          files dropped into the Startup folder
LOLBin-Write            executables written by a LOLBin into user-writable paths
```

Anything here written by a LOLBin in the incident window is attacker
persistence until proven otherwise. Filter with `| where SetBy in~ (LolBins)`
to separate it from legitimate installers.

Nothing found does not mean nothing is there — it means nothing was found in
telemetry you have. If phases 3–5 were serious, reimage regardless.

### Phase 7 — Scope · who else

Run **`clickfix-scope.kql`** with whichever indicator you have: `UrlCheck`,
`HashCheck`, `CommandCheck` or `IPCheck`.

It searches five ways across the whole estate — the same command, the same
`RunMRU` entry, traffic to the same host, the same file on disk, the same file
executed — and joins device context so you can see who was hit.

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
4. **Check for mailbox rules** before you close anything — a forwarding rule
   survives every other step on this list.
5. **Block the indicators**: lure domain, payload host, file hashes.
6. **Reimage** if persistence was found, if credential theft is suspected, or if
   the payload is unidentified.

---

## For the ticket

Pull these from the queries and paste them in:

- Pivot time and the `RunMRUMatch` string — the proof
- The lure URL
- Every payload host and every SHA256, with `FileOriginUrl`
- Persistence found, with its location
- Every account and device from `clickfix-scope.kql`
- Whether sessions were revoked, and when

---

## Common false positives

| Looks like ClickFix | Actually |
|---|---|
| High score, no `RunMRUMatch`, admin account | Someone genuinely using Win+R for their job |
| `explorer.exe` → `powershell.exe`, clean command line | A user double-clicking a `.ps1` |
| Encoded PowerShell on many devices | Deployment tooling — check `DevicesRanThisCommand` |
| `mshta` from `explorer.exe` | A legacy line-of-business app |

`DevicesRanThisCommand` is the quickest discriminator. ClickFix generates a
command unique to the victim. Admin tooling appears everywhere.

---

## What none of this proves

Stated plainly, because these are the assumptions that close incidents early:

- **Empty `RunMRU` does not mean no paste.** It only covers the Run dialog.
- **A blocked payload does not mean nothing ran.** Earlier stages completed.
- **A clean endpoint does not mean a clean account.** Tokens leave with the
  data, not with the process.
- **No persistence found does not mean no persistence.** It means none was
  found in the telemetry you have.

None of these queries have been run against live telemetry — they are reviewed
for KQL correctness and schema accuracy only. Test them in your own tenant.
