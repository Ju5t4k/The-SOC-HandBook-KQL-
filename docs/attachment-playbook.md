# Malicious attachment — investigation playbook

**Use when** a detonation verdict, a user report or a threat-intel hit points at an attachment.
**Goal:** who got it, whether it reached a device, whether it ran.

| Step | Query |
|---|---|
| 1 Confirm | [`attachment.kql`](../queries/attachment.kql) |
| 2 Reconstruct | [`attachment-timeline.kql`](../queries/attachment-timeline.kql) |
| 6 Scope | [`attachment-scope.kql`](../queries/attachment-scope.kql) |

---

## How the attack works

- **Mail and endpoint telemetry don't join themselves.** Defender for Office says it was delivered; Defender for Endpoint says a file appeared. The link is `SHA256`, and the queries make it for you.
- **Delivery isn't final.** `DeliveryLocation` is where it went; `LatestDeliveryLocation` is where it is now. ZAP may have pulled it, or an admin released it.
- The payload is rarely a plain `.exe`. Expect a container (`.iso`, `.img`, `.zip`, `.7z`, `.one`) or a document that fetches the payload when opened.
- **Files inside an archive get a new hash when extracted.** The mail-side hash is the archive; what ran may not match it.

## Attack timeline

| When | Attacker | Telemetry | Table |
|---|---|---|---|
| T+0 | Mail sent | Verdict, authentication | `EmailEvents` |
| T+0 | Attachment hashed | `SHA256`, type, verdict | `EmailAttachmentInfo` |
| T+min | Link clicked | Click, click-through | `UrlClickEvents` |
| T+min | File saved or extracted | **Same `SHA256` on disk** | `DeviceFileEvents` |
| T+min | File opened, code runs | **Same `SHA256` as a process** | `DeviceProcessEvents` |
| T+hrs | ZAP retracts, or admin releases | Post-delivery action | `EmailPostDeliveryEvents` |

Above the `SHA256` crossing to the endpoint: a mail problem. Below it: an endpoint incident.

---

## Steps

### 1. Confirm · 5 min

**Run** `attachment.kql` with `HashCheck`, `FileNameCheck` or `RecipientCheck`, or blank to sweep.

**Read first:** `WasExecuted`, `ReachedEndpoint`.

| Signal | Score | Decide |
|---|---|---|
| `WasExecuted` | any | **Endpoint incident.** It ran. Step 2, then step 5. |
| `ReachedEndpoint` | any | **Live.** It is on a machine. Step 2. |
| `MalwareVerdict` + `ReachedInbox` | any | Delivered despite detection. Purge it, then check endpoints. |
| neither | 6+ | Suspicious. Work it. |
| neither | 3 or less | Note and close. |

Score — 9 indicators, 17 maximum:

| Weight | Indicator |
|---|---|
| +3 | `WasExecuted` — the hash ran on a device |
| +3 | `ReachedEndpoint` — the hash is on disk |
| +3 | `MalwareVerdict` **and** `ReachedInbox` — detected and delivered anyway |
| +2 | `RiskyType` — executable, script, shortcut or container |
| +2 | A link in the same message was clicked |
| +1 | `MalwareVerdict` — malware or phish verdict on the attachment |
| +1 | `AuthFailed` — DMARC or composite authentication failed |
| +1 | `IsFirstContact` — first mail from this sender |
| +1 | `Campaign` — five or more recipients got the same hash |

Record `NetworkMessageId` and `SHA256`.

### 2. Reconstruct · 10 min

**Run** `attachment-timeline.kql` with `MessageCheck`, `HashCheck` or `RecipientCheck`.

```
1-Delivery       where it went, and where it is now
2-Attachment     the file, hash and verdict
3-Links          URLs in the same message
4-Click          Safe Links clicks
5-Post delivery  ZAP, quarantine release, admin action
6-On disk        the hash on a device, with FileOriginUrl
7-Executed       the hash running
```

Rows 1–5 are mail; 6–7 are endpoint — one table, in time order.

### 3. Where the message is now

Compare `DeliveryLocation` with `LatestDeliveryLocation`, then read `5-Post delivery`:

- **Blocked, then released** — someone let it through. Find who and why.
- **Delivered, then ZAPped** — the control worked late. Did the user open it in the gap?
- **Delivered and still there** — live now. Purge it.

### 4. Did anyone open it

- **There is no "attachment opened" event.** `6-On disk` means saved or extracted; `7-Executed` means opened.
- `4-Click` is links in the message, not the attachment.
- `IsClickedThrough` = the user saw a warning and continued. Treat the account like the device.

### 5. Endpoint impact

From `6-On disk` and `7-Executed`: which devices, which `FolderPath`, `FileOriginUrl`, and the command line.

If it ran, run [`hok.kql`](../queries/hok.kql) and [`clickfix-impact.kql`](../queries/clickfix-impact.kql) on the device from the execution time — they cover what any payload does next, however it arrived.

### 6. Scope

**Run** `attachment-scope.kql` — hash first, then sender, then subject (each is broader than the last).

```
Delivered   mailboxes that got the same file or sender
Message     messages with the same subject or sender
OnDisk      the hash on disk anywhere
Executed    the hash run anywhere
```

`OnDisk` or `Executed` with no `Delivered` row = the file reached a device some other way.

---

## Contain

1. Purge the message from every mailbox, including forwarded copies.
2. Isolate any device where it ran. Isolate, don't shut down.
3. Block the hash, the sender, and any host in `FileOriginUrl`.
4. Reset credentials for anyone who ran it — assume an infostealer.
5. If it was released from quarantine, review who released it and why.
6. Warn recipients who still have it.

## Ticket

- `NetworkMessageId`, `SHA256`, file name and type
- Delivery location then and now, and what changed it
- Every recipient, and who still has it
- Every device it reached, and which ran it
- `FileOriginUrl` and payload hosts
- Quarantine release, if any, and by whom

## False positives

| Looks malicious | Usually |
|---|---|
| Risky extension, no verdict | A developer's script or a designer's disk image |
| Hash on many devices | A shared internal document or installer |
| `AuthFailed` on a known sender | A misconfigured supplier |
| High score, one recipient, internal sender | An undocumented internal process |

`RecipientsOfHash` and `SendersOfHash` sort most of these.

## Limits

- No `DeviceFileEvents` row means no onboarded device recorded it — not that it never landed.
- A clean verdict is a point in time. The payload served later may differ.
- Quarantine isn't deletion; quarantined mail can be released.
- Extracted archive contents have new hashes and will not match the attachment.
- Not run against live telemetry. Reviewed for KQL correctness and schema only.
