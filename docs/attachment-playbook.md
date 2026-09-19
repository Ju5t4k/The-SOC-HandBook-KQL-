# Malicious attachment — end-to-end investigation

For when a detonation verdict, a user report or a threat-intel hit points at an
attachment and you have to work out who got it, who opened it, and whether it
ran.

| Query | Phase |
|---|---|
| [`attachment.kql`](../queries/attachment.kql) | 0 — confirm |
| [`attachment-timeline.kql`](../queries/attachment-timeline.kql) | 1–4 — reconstruct |
| [`attachment-scope.kql`](../queries/attachment-scope.kql) | 5 — who else |

---

## What you are looking at

An attachment investigation has one structural problem: **mail telemetry and
endpoint telemetry are separate systems that do not talk to each other.**

Defender for Office 365 tells you a file was delivered. Defender for Endpoint
tells you a file appeared on disk. Nothing joins them automatically — you have
to do it yourself, on `SHA256`, and that join is where most of the value of this
playbook sits. A file that was delivered and is now on an endpoint is a
different incident from one that sat unopened in a junk folder.

The second problem is that **delivery is not final**. `DeliveryLocation` is
where the message went at the time. `LatestDeliveryLocation` is where it is
now. ZAP may have pulled it out of the inbox an hour later, or an admin may
have released it from quarantine into the inbox. Reading only the first will
tell you the wrong story in both directions.

And the modern shape is rarely a `.exe`. It is a container — `.iso`, `.img`,
`.zip`, `.7z`, `.one` — whose contents the mail stack cannot see, or a document
that only fetches the payload once opened.

---

## The attack timeline

| When | Attacker action | Telemetry | Table |
|---|---|---|---|
| T+0 | Message sent with attachment | Delivery verdict, authentication result | `EmailEvents` |
| T+0 | Attachment recorded and hashed | `SHA256`, file type, threat verdict | `EmailAttachmentInfo` |
| T+0 | Links in the same message recorded | URLs and domains | `EmailUrlInfo` |
| T+min | User opens the message, clicks a link | Safe Links click, click-through | `UrlClickEvents` |
| T+min | User saves or extracts the attachment | **File on disk, same `SHA256`** | `DeviceFileEvents` |
| T+min | User opens it. Code runs | **Process created, same `SHA256`** | `DeviceProcessEvents` |
| T+min | Second stage fetched | Outbound from a non-browser process | `DeviceNetworkEvents` |
| T+hrs | ZAP retracts the message, or an admin releases it | `ActionType`, `ActionResult` | `EmailPostDeliveryEvents` |

**The line that changes everything is the `SHA256` crossing from mail to
endpoint.** Above it you have a mail hygiene problem. Below it you have an
endpoint incident, and the clock is running.

---

## Investigation timeline

### Phase 0 — Confirm · 5 minutes

Run **`attachment.kql`**. Set `HashCheck` or `FileNameCheck` if you have one,
`RecipientCheck` if you have a user, or leave blank to sweep the window.

Read `WasExecuted` and `ReachedEndpoint` first.

| Signal | `AttachmentScore` | Verdict |
|---|---|---|
| `WasExecuted` true | any | **Endpoint incident.** The file ran. Go to Phase 1, then hand to endpoint response. |
| `ReachedEndpoint` true | any | **Treat as live.** The file is on a machine. Go to Phase 1. |
| `MalwareVerdict` and `ReachedInbox` | any | **Delivered despite detection.** Pull it, then check the endpoint. |
| neither | ≥ 6 | Suspicious. Work it. |
| neither | ≤ 3 | Note and close. |

The score is built from nine indicators:

| Weight | Indicator |
|---|---|
| +3 | `WasExecuted` — the hash ran on an endpoint |
| +3 | `ReachedEndpoint` — the hash is on disk somewhere |
| +3 | `MalwareVerdict` **and** `ReachedInbox` — detected and delivered anyway |
| +2 | `RiskyType` — executable, script, shortcut or container extension |
| +2 | `ClickCount` above zero — a link in the same message was clicked |
| +1 | `MalwareVerdict` — any malware or phish verdict on the attachment |
| +1 | `AuthFailed` — SPF, DKIM or DMARC failed |
| +1 | `IsFirstContact` — first ever exchange with this sender |
| +1 | `Campaign` — five or more recipients got the same hash |

Record the `NetworkMessageId` and the `SHA256`. Both feed the next phase.

### Phase 1 — Reconstruct · 10 minutes

Run **`attachment-timeline.kql`** with `MessageCheck` set to the
`NetworkMessageId`, or `HashCheck` to the `SHA256`. It resolves either into the
set of affected messages and follows them across both systems.

```
1-Delivery       where it went, and where it is now
2-Attachment     the file, its hash and its verdict
3-Links          URLs in the same message
4-Click          Safe Links clicks and click-throughs
5-Post delivery  ZAP, quarantine release, admin action
6-On disk        the same hash on an endpoint, with FileOriginUrl
7-Executed       the same hash running
```

Phases 1–5 are the mail story. Phases 6–7 are the endpoint story. The whole
point of the query is that they are in one table, in time order, joined on the
hash.

### Phase 2 — Delivery reality

From `1-Delivery`, compare `DeliveryAction`/`DeliveryLocation` against
`LatestDeliveryAction`/`LatestDeliveryLocation`.

Then read `5-Post delivery` to find out why they differ. Three cases matter:

- **Blocked then released.** Somebody in your organisation let it through.
  Find out who and why.
- **Delivered then ZAPped.** The control worked late. Establish whether the
  user opened it in the gap.
- **Delivered and still in the inbox.** It is live right now. Pull it.

### Phase 3 — Did anyone interact

`4-Click` covers links in the same message, not the attachment itself.
**There is no telemetry for opening an attachment** — that is the gap this
phase exists to make explicit.

What you have instead is inference: `6-On disk` means somebody saved or
extracted it, and `7-Executed` means somebody opened it. An empty `6-On disk`
with the message still in the inbox means probably not yet — not definitely
not.

`IsClickedThrough` true means the user was shown a warning and continued.
Treat that account as needing the same attention as the endpoint.

### Phase 4 — Endpoint impact

From `6-On disk` and `7-Executed`:

- Which devices, and what `FolderPath` — a container extracted into `%TEMP%`
  and run is the classic shape
- `FileOriginUrl`, which ties the file on disk back to where it came from
- `ProcessCommandLine` for the execution, and the initiating process

If the file ran, this stops being an attachment investigation. Pivot to
[`clickfix-timeline.kql`](../queries/clickfix-timeline.kql) with the device and
the execution time — it reconstructs post-execution activity regardless of how
the file arrived.

### Phase 5 — Scope · who else

Run **`attachment-scope.kql`** with `HashCheck`, `SenderCheck`, `SubjectCheck`
or `FileNameCheck`.

```
Delivered   every mailbox that received the same file or sender
Message     every message matching the subject or sender
OnDisk      the same hash written anywhere in the estate
Executed    the same hash executed anywhere in the estate
```

Search by **hash first, then sender, then subject** — in that order, because
each is broader and noisier than the last. Campaigns vary the filename and keep
the lure, or vary the lure and keep the payload; `EmailClusterId` on the
`Message` rows groups messages Microsoft already considers related.

`OnDisk` and `Executed` rows with no matching `Delivered` row are the important
ones: the same file reached a machine by some route other than mail.

---

## Containment

1. **Purge the message** from every mailbox that still has it, including
   forwarded copies.
2. **Isolate any device** where `WasExecuted` is true. Isolate, not shut down.
3. **Block the hash**, and the sender, and any payload host from `FileOriginUrl`.
4. **Reset credentials** for anyone who executed it — assume an infostealer ran
   and treat the account as compromised, not just the machine.
5. **Check quarantine release history** if the message was released. The
   process that allowed it is the finding.
6. **Warn the recipients** who still have it, so they do not open it during
   remediation.

---

## For the ticket

- `NetworkMessageId`, `SHA256`, filename and file type
- Delivery location at the time and now, and what changed it
- Every recipient, and which of them still hold it
- Every device the hash reached, and which executed it
- `FileOriginUrl` and any payload host
- Whether the message was ever released from quarantine, and by whom

---

## Common false positives

| Looks malicious | Actually |
|---|---|
| Risky extension, no verdict | A developer mailing a `.ps1`, a designer mailing an `.iso` |
| Hash on many endpoints | A legitimate internal document, or a shared installer |
| `AuthFailed` on a known sender | A misconfigured supplier — common, and worth telling them |
| High score, single recipient, internal sender | An internal process nobody documented |

`RecipientsOfHash` and `SendersOfHash` sort most of this quickly. A file sent by
one external sender to twenty people is a campaign. A file sent by twenty
internal people to each other is a business process.

---

## What none of this proves

- **No `DeviceFileEvents` row does not mean the file never landed.** It means
  no onboarded device recorded it. An unmanaged or offline machine records
  nothing.
- **A clean verdict is a verdict at a point in time.** Detonation that found
  nothing at 09:00 says nothing about the payload the C2 served at 11:00.
- **Quarantine is not deletion.** A quarantined message can still be released.
- **There is no "user opened the attachment" event.** Execution is inferred
  from the hash appearing on disk and in a process. Absence is not proof.

None of these queries have been run against live telemetry — they are reviewed
for KQL correctness and schema accuracy only. Test them in your own tenant.
