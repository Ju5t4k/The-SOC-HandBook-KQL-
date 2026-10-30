# Device code phishing — investigation playbook

**Use when** a device code sign-in appears in an alert, a hunt or a user report, or a user reports being asked to enter a code at `microsoft.com/devicelogin`.
**Goal:** decide whether a token was stolen, find how the attacker set it up, what the token reached, and remove every way back in.

| Step | Query |
|---|---|
| 1 Confirm | [`devicecode.kql`](../queries/devicecode.kql) |
| 2 Reconstruct | [`devicecode-timeline.kql`](../queries/devicecode-timeline.kql) |
| 3 Before the code | [`devicecode-timeline.kql`](../queries/devicecode-timeline.kql) phases `0` and `1-Lure`, [`devicecode-persistence.kql`](../queries/devicecode-persistence.kql) `1-Before pivot` |
| 4 What the token did | [`devicecode-timeline.kql`](../queries/devicecode-timeline.kql) phases `4`, `8`, `9`, `10` |
| 5 Other footholds | [`devicecode-timeline.kql`](../queries/devicecode-timeline.kql) phases `5`, `6` |
| 6 Persistence | [`devicecode-persistence.kql`](../queries/devicecode-persistence.kql) |
| 7 Scope | [`devicecode-scope.kql`](../queries/devicecode-scope.kql) |

---

## How the attack works

The attacker asks Microsoft for a device code, gets the victim to type it into the real `microsoft.com/devicelogin`, and receives the victim's tokens. The victim completes real MFA. **The sign-in is clean** — right user, right MFA, right IP, Conditional Access passes. What gives it away is around it: the set-up before, and the token's use after.

Three variants, each with a different trace:

| Variant | Client app in the sign-in | What follows | Indicator |
|---|---|---|---|
| **Token theft** | A Microsoft public client (Office, Teams, Azure CLI, PowerShell) | Refresh token used from the attacker's network in the **same session** | `TokenMoved` |
| **Device and PRT** (Storm-2372, 2025) | Microsoft Authentication Broker | Token for the Device Registration Service, an attacker device registered, then a Primary Refresh Token — which survives password reset and can satisfy "compliant device" policies | `BrokerToDrs`, `DeviceAdded` |
| **Attacker's own app** | A multi-tenant app owned by neither Microsoft nor you | Consent to the app; the app then works on its own | `NonMicrosoftApp`, `AppConsent` |

**Before the code** the attacker usually:

- builds rapport for hours or days — Teams chats, email threads, fake meeting invitations, sometimes on WhatsApp or Signal (invisible to you);
- sends the code or the `devicelogin` link, often more than once, because **a code expires after 15 minutes**;
- sometimes prepares in your tenant first, if they already hold an account: an app, a secret on an existing app, a new owner.

**After the code** the attacker typically searches the mailbox through Graph for words like *password*, *admin*, *credentials*, *VPN*; reads mail and files; registers a device or adds an MFA method to stay; and sends the same lure to colleagues from the victim's mailbox.

## Attack timeline

| When | Attacker | Telemetry | Table |
|---|---|---|---|
| T−days | Contacts the victim, builds trust | External Teams chats, mail threads | `MessageEvents`, `OfficeActivity`, `EmailEvents` |
| T−days | (If already inside) creates an app, adds a secret or owner | App changes | `AuditLogs` |
| T−hours | Sends the code or link; re-sends as codes expire | `devicelogin` URL in mail or Teams; clicks; browser opened from Outlook/Teams; failed device code attempts | `EmailUrlInfo`, `MessageUrlInfo`, `UrlClickEvents`, `DeviceEvents`, `SigninLogs` |
| T+0 | Victim enters the code | `AuthenticationProtocol == "deviceCode"`, success, victim's IP | `SigninLogs` |
| T+minutes | Uses the refresh token | Non-interactive sign-ins, **same SessionId, different ASN**; Device Registration Service token | `AADNonInteractiveUserSignInLogs` |
| T+minutes | Searches and reads | Graph calls in the same session; mail reads from the attacker's address | `MicrosoftGraphActivityLogs`, `OfficeActivity` |
| T+hours | Registers a device, gets a PRT | `Add device`, `Register device`, then sign-ins from that device | `AuditLogs`, `SigninLogs` |
| T+hours | Adds MFA methods, consents apps, sets mail rules | Directory and mailbox changes | `AuditLogs`, `OfficeActivity` |
| T+hours | Phishes colleagues from the victim's mailbox | Internal mail with links | `EmailEvents` |
| T+days | Consented app works on its own | Service principal sign-ins | `AADServicePrincipalSignInLogs` |

A refresh token lasts 90 days by default and **survives a password reset**. A registered device's PRT survives **session revocation** too.

## Data this playbook needs

| Table | Connector | Without it you lose |
|---|---|---|
| `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AuditLogs` | Microsoft Entra ID | Everything. Non-interactive logs are what prove `TokenMoved` |
| `IdentityInfo` | UEBA | Job title and roles only |
| `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents` | Defender XDR (Defender for Office 365 P2) | Mail lures and clicks |
| `MessageEvents`, `MessageUrlInfo` | Defender XDR (Defender for Office 365, Teams) // VERIFY in your connector | Teams lures |
| `DeviceEvents` | Defender XDR (Defender for Endpoint) | Browser opened to `devicelogin` from Outlook or Teams |
| `OfficeActivity` | Microsoft 365 | Mail rules, mail reads, Teams chats |
| `MicrosoftGraphActivityLogs` | Entra diagnostic setting *MicrosoftGraphActivityLogs* | **What the token did in Graph.** Turn it on now if it is off — it cannot be back-filled |

---

## Steps

### 1. Confirm · 5 min

**Run** `devicecode.kql`. Blank to sweep, or set `UserIdentityCheck`.

**Read first:** `TokenMoved`, `BrokerToDrs`, `DeviceAdded`, then `LureBefore`, `AppConsent`, `NonMicrosoftApp`.

| Signal | Decide |
|---|---|
| `TokenMoved` | **Compromise.** The token from this sign-in was used from another network in the same session. Steps 2–7. |
| `BrokerToDrs` | **Compromise — device variant.** The code was used to reach the Device Registration Service. Expect `DeviceAdded`. Step 5 first. |
| `DeviceAdded` | **Compromise.** A device or passwordless credential was registered for this account after the sign-in. Step 5 first. |
| `NonMicrosoftApp` or `AppConsent` | **Compromise — app variant** unless the app is one you approved. Step 6, method `App`. |
| `LureBefore`, sign-in succeeded | **Compromise** until the user explains the link. A failed sign-in with `LureBefore` means the user was targeted: warn them, run step 7. |
| none of the above, score 10+ | Probable. Continue. |
| none, score 5–9 | Check for a legitimate reason: CLI, headless server, meeting room device. |
| none, score 4 or less | Likely legitimate. Note and close. |

Score — 13 indicators, 24 maximum:

| Weight | Indicator |
|---|---|
| +3 | The sign-in succeeded |
| +3 | `TokenMoved` — token used from a different ASN in the same `SessionId` |
| +3 | `BrokerToDrs` — Authentication Broker client reaching the Device Registration Service |
| +2 | `DeviceAdded` — device or passwordless credential registered after the sign-in |
| +2 | `LureBefore` — a device code link was mailed, sent on Teams or clicked in the 24 hours before |
| +2 | `AppConsent` — the user consented to an app between 1 hour before and 24 hours after |
| +2 | `NonMicrosoftApp` — the client app is owned by neither Microsoft nor your tenant |
| +2 | `FirstDcForUser` — first device code sign-in for this user in 90 days |
| +1 | `AbusedApp` — commonly abused public client |
| +1 | `NewIpForUser` — address new for this account |
| +1 | `Unmanaged` — device neither managed nor compliant |
| +1 | `HighValue` — Graph, Exchange, SharePoint, ARM, Key Vault or Device Registration Service |
| +1 | `RareDcForApp` — 3 users or fewer have ever used device code with this client app |

`FailedDcBefore` is not scored: it counts failed or expired device code attempts by the user in the 24 hours before. More than zero means codes were being re-sent.

Record `EventTime` (the **pivot time**) and `SessionId`.

### 2. Reconstruct · 15 min

**Run** `devicecode-timeline.kql` with `PivotTime` and `UserIdentityCheck`.

```
0-Prior code       device code attempts by the user in the 7 days before
0-Prior apps       apps created, consented or given secrets anywhere in the tenant in the 7 days before
1-Lure             device code links mailed, sent on Teams, clicked, or opened in a browser
1-Delivery         all inbound mail and Teams chats in the 4 hours before
2-Code entry       the device code sign-in, with its session id and the app's owning tenant
3-Sign-ins         the user's other interactive sign-ins
4-Token use        non-interactive sign-ins — where the token went
5-Service principal  apps this user created, consented to or gave a secret, signing in on their own
6-Device           devices and passwordless credentials registered
6-Device sign-in   sign-ins from a device registered in the window
7-Directory        every other directory change, by or about the user
8-Cloud            Microsoft 365 activity
8-Mail read        mail read, one row per address per hour
9-Graph            Graph calls made with the user's tokens, per address and session
10-Outbound        mail with links sent by the user after the pivot
```

**Read first:** put `2-Code entry` next to `4-Token use` rows with the **same session id**. Same user, same session, different IP and ASN, minutes apart — that is the proof. Screenshot both rows.

### 3. Before the code · 15 min

The set-up tells you whether this was targeted, how long it ran, and whether someone already inside the tenant prepared it.

**Read** the timeline's `0-Prior code`, `0-Prior apps` and `1-Lure` rows, and `devicecode-persistence.kql` rows with `Window = 1-Before pivot`.

| What you see | What it means | Next |
|---|---|---|
| `1-Lure` from an external sender, hours or days before | The delivery route. Usually Teams or mail; a phone call or WhatsApp leaves nothing | Record sender, time, URL. Scope by sender (step 7) |
| `1-Lure` with `opened ... from outlook.exe / ms-teams.exe` | The user followed the link from the message | Confirms the path from lure to code |
| `0-Prior code` failures before the success | Codes re-sent as they expired: someone was coaching the user | Strong sign of a live operator |
| `0-Prior apps` by an account other than the victim, close to the pivot | Possible preparation from an account already compromised | Investigate that account with this playbook |
| `1-Before pivot` MFA method or group change on the victim | Something changed the account before the phish | Ask the user and the service desk; treat as suspicious |
| No lure found | The link arrived another way — chat app, phone, a QR code in an image, or text not parsed as a URL | **Ask the user** how they got the code |

### 4. What the token did · 20 min

- `4-Token use`: every `ResourceDisplayName`, IP and ASN the token reached. A Graph token is the whole mailbox, OneDrive and directory read.
- `9-Graph`: calls per address and session. `Searches` above zero from the attacker's address means mailbox or file searches. `Paths` shows what: `/me/messages`, `/users`, `/drives/...`.
- `8-Mail read`: mail read per address per hour. Reads from the token's IP are the disclosure evidence.
- `10-Outbound`: mail with links the victim sent after the pivot. Internal device code phishing. Every recipient goes into step 7.

Treat everything the token touched as disclosed.

### 5. Other footholds

- `6-Device` after the pivot → **attacker device**. Its Primary Refresh Token survives revocation and the password reset, and can satisfy "compliant device" Conditional Access.
- `6-Device sign-in` → the attacker device in use. Note the IP and ASN; they join step 7.
- `5-Service principal` for an app you don't recognise → **consent abuse**. App access survives token revocation.
- Watch for `Add Windows Hello for Business credential`, `Add passwordless phone sign-in credential`, `Add Passkey (device-bound)`.

### 6. Persistence · the revocation decision

**Run** `devicecode-persistence.kql` with `PivotTime` and `UserIdentityCheck`.

```
Directory          MFA methods, roles, groups, CA policies and named locations, federation, password resets
App                applications, service principals, secrets, owners, consent, permission grants
Device             devices, Windows Hello, passkeys, platform credentials
Mailbox            inbox rules, forwarding, delegation, transport rules
Service principal  sign-ins by apps this user created, consented to, gave a secret or owns — after that grant
```

`Window` splits each row into `1-Before pivot` (set-up) and `2-After pivot` (the attacker's changes). `Device`, `App` and `Service principal` survive session revocation. Anything after the pivot is the attacker's until proven otherwise.

### 7. Scope

**Run** `devicecode-scope.kql` with `IPCheck`, `ASNCheck`, `AppCheck`, `UserAgentCheck` or `SenderCheck`. With every check blank it lists everyone sent a device code link.

```
DeviceCode         other device code sign-ins matching the indicator
TokenUse           token use from the same infrastructure, any user
DeviceRegistered   devices registered from the same address
Graph              Graph calls from the same address, any user
Lure               everyone sent a device code link (all, or from SenderCheck)
```

Use **`ASNCheck`** first. Attackers change IPs easily and hosting providers rarely. One ASN against three unrelated users in a day is a campaign. Then `SenderCheck` with the lure's sender, and the recipients of any `10-Outbound` mail.

---

## Contain

1. **Revoke the user's sessions** (`Revoke-MgUserSignInSession` or Entra → user → Revoke sessions). A password reset alone leaves the refresh token working.
2. Reset the password.
3. Remove MFA methods registered since the pivot.
4. **Delete or disable every device registered since the pivot.** Revocation does not touch its PRT.
5. **Remove app consents, secrets and owners** added since the pivot — and any found in `1-Before pivot` that nobody can explain.
6. Remove mailbox rules and forwarding.
7. Purge internal phishing sent from the victim's mailbox (`10-Outbound`) and warn the recipients.
8. Block the attacker ASN in Conditional Access if your policy allows.
9. **Block the device code flow** with a Conditional Access policy (*Authentication flows → Device code flow*) for everyone who does not need it.

## Ticket

- Pivot time, session id, and the `2-Code entry` row (app, owning tenant)
- The `4-Token use` rows with the different IP/ASN — the proof
- How and when the code was delivered (`1-Lure`), by whom, and how many attempts (`0-Prior code`)
- Resources the token reached, Graph searches made, mail read from the attacker's address
- Devices registered since the pivot, and whether removed
- Persistence found, before and after the pivot
- Internal phishing sent, and recipients warned
- Users, senders and ASNs from scope
- **When sessions were revoked**

## False positives

| Looks suspicious | Usually |
|---|---|
| Azure CLI/PowerShell, developer, recurring | Headless server or build agent |
| VS Code, engineer, recurring | Remote development sign-in |
| Shared device, same IP every time | Meeting room panel or Teams Rooms device |
| Many users, one app, one day | A rollout |
| `LureBefore` from your own IT | Setup instructions for a device that signs in with a code |
| `NonMicrosoftApp` | A vendor app you approved — check it against your enterprise apps list |

`DaysDcSeenByUser` and `UsersUsingDcForApp` settle most of these. Weekly for three months is a job. First time ever, unmanaged device, after a lure, is the one to look at.

## Limits

- A clean sign-in proves nothing — clean is what this attack produces.
- No ASN change does not mean no theft: an attacker exiting through the victim's provider shows no divergence.
- Lures are matched on `devicelogin` and `deviceauth` in URLs. A code in plain text, an image, a QR code, a phone call or a chat app outside Microsoft 365 is not seen.
- `AppOwnerTenantId` is used for `NonMicrosoftApp`; check it is populated in your workspace. If empty, the indicator never fires.
- The Graph phase needs the `MicrosoftGraphActivityLogs` diagnostic setting, and only covers time since it was turned on.
- Device registrations logged by the Device Registration Service carry no IP, so scope by IP misses them.
- Revoking sessions does not remove consented apps or registered devices.
- A failed device code attempt still means someone was asked for a code.
- Not run against live telemetry. Reviewed for KQL correctness and schema only.

## Sources

- [Microsoft — Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/) — the Authentication Broker / Device Registration Service / PRT variant, and Graph mail searches after compromise.
- [Microsoft Learn — MicrosoftGraphActivityLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs) — `SessionId`, `SignInActivityId`.
- [Microsoft Learn — Verify first-party Microsoft applications](https://learn.microsoft.com/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in) — Microsoft's app-owner tenant `f8cdef31-a31e-4b4a-93e4-5f571e91255a`.
