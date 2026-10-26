# Device code phishing — investigation playbook

**Use when** a device code sign-in appears in an alert, a hunt or a user report.
**Goal:** decide whether a token was stolen, find what it reached, and remove every way back in.

| Step | Query |
|---|---|
| 1 Confirm | [`devicecode.kql`](../queries/devicecode.kql) |
| 2 Reconstruct | [`devicecode-timeline.kql`](../queries/devicecode-timeline.kql) |
| 5 Persistence | [`devicecode-persistence.kql`](../queries/devicecode-persistence.kql) |
| 6 Scope | [`devicecode-scope.kql`](../queries/devicecode-scope.kql) |

---

## How the attack works

- The attacker requests a device code from Microsoft and sends it to the victim with a pretext (Teams meeting, MFA re-registration, IT check).
- The victim types it into the real `microsoft.com/devicelogin` and completes real MFA.
- The attacker's device receives an access token and a **refresh token**.
- **The sign-in is clean** — right user, right MFA, right IP, Conditional Access passes. Nothing fails.
- What gives it away is **afterwards**: the same session's token used from a different network.
- Codes last about 15 minutes, so the phish and the sign-in are close together.

## Attack timeline

| When | Attacker | Telemetry | Table |
|---|---|---|---|
| T−min | Requests a code | Nothing — happens outside your tenant | — |
| T+0 | Sends the code | Inbound mail or Teams chat | `EmailEvents`, `OfficeActivity` |
| T+1–15m | Victim enters the code | `AuthenticationProtocol == "deviceCode"`, success, victim's IP | `SigninLogs` |
| T+minutes | Uses the refresh token | Non-interactive sign-ins, **same SessionId, different ASN** | `AADNonInteractiveUserSignInLogs` |
| T+hours | Registers a device | `Add device`, `Register device`, Windows Hello, passkey | `AuditLogs` |
| T+hours | Adds MFA methods, consents apps, sets mail rules | Directory and mailbox changes | `AuditLogs`, `OfficeActivity` |
| T+days | Consented app works on its own | Service principal sign-ins | `AADServicePrincipalSignInLogs` |

A refresh token lasts 90 days by default and **survives a password reset**.

---

## Steps

### 1. Confirm · 5 min

**Run** `devicecode.kql`. Blank to sweep, or set `UserIdentityCheck`.

**Read first:** `TokenMoved`, `DeviceAdded`, `OtherASNsAfter`.

| Signal | Score | Decide |
|---|---|---|
| `TokenMoved` | any | **Compromise.** The token from this sign-in was used from another network in the same session. Go to step 2. |
| `DeviceAdded` | any | **Compromise.** The account registered a device after this sign-in. Go to step 2, then step 4. |
| neither | 7+ | Probable. Continue. |
| neither | 4–6 | Check for a legitimate reason: CLI, headless server, shared device. |
| neither | 3 or less | Likely legitimate. Note and close. |

Score — 9 indicators, 15 maximum:

| Weight | Indicator |
|---|---|
| +3 | The sign-in succeeded |
| +3 | `TokenMoved` — token used from a different ASN in the same `SessionId` |
| +2 | `DeviceAdded` — device or passwordless credential registered after the sign-in |
| +2 | `FirstDcForUser` — first device code sign-in for this user in 90 days |
| +1 | `AbusedApp` — commonly abused public client |
| +1 | `NewIpForUser` — address new for this account |
| +1 | `Unmanaged` — device neither managed nor compliant |
| +1 | `HighValue` — Graph, Exchange, SharePoint, ARM or Key Vault |
| +1 | Device code rare in the tenant (3 users or fewer) |

Record `EventTime` (the **pivot time**) and `SessionId`.

### 2. Reconstruct · 15 min

**Run** `devicecode-timeline.kql` with `PivotTime` and `UserIdentityCheck`.

```
1-Delivery           inbound mail and Teams chats around the phish
2-Code entry         the device code sign-in, with its session id
3-Sign-ins           the user's other interactive sign-ins
4-Token use          non-interactive sign-ins — where the token went
5-Service principal  applications signing in on their own
6-Device             devices and passwordless credentials registered
7-Directory          every other directory change
8-Cloud              Microsoft 365 activity, mail reads excluded
```

**Read first:** put `2-Code entry` next to `4-Token use` rows with the **same session id**. Same user, same session, different IP and ASN, minutes apart — that is the proof. Screenshot both rows.

### 3. Delivery and reach

- **How the code arrived:** `1-Delivery`. Usually Teams or a phone call, because someone has to talk the victim through it. If nothing shows, ask the user.
- **What the token reached:** every `ResourceDisplayName`, IP and ASN in `4-Token use`, and what `8-Cloud` shows was read. Treat everything it touched as disclosed — a Graph token is the whole mailbox and OneDrive.

### 4. Other footholds

- `5-Service principal` after the pivot, for an app you don't recognise → **consent abuse**. App access survives token revocation.
- `6-Device` after the pivot → **attacker device**. Its Primary Refresh Token survives revocation and the password reset, and can satisfy "compliant device" Conditional Access.
- Watch for `Add Windows Hello for Business credential`, `Add passwordless phone sign-in credential`, `Add Passkey (device-bound)`.

### 5. Persistence · the revocation decision

**Run** `devicecode-persistence.kql` with `UserIdentityCheck`.

```
Directory          MFA methods, roles, consent, SP credentials, CA changes
Device             devices, Windows Hello, passkeys, platform credentials
Mailbox            inbox rules, forwarding, delegation, transport rules
Service principal  sign-ins by apps this user consented to, after the consent
```

`Device` and `Service principal` survive session revocation. Anything timestamped after the pivot is the attacker's until proven otherwise.

### 6. Scope

**Run** `devicecode-scope.kql` with `IPCheck`, `ASNCheck`, `AppCheck` or `UserAgentCheck`.

```
DeviceCode   other device code sign-ins matching the indicator
TokenUse     token use from the same infrastructure, any user
```

Use **`ASNCheck`** first. Attackers change IPs easily and hosting providers rarely. One ASN against three unrelated users in a day is a campaign.

---

## Contain

1. **Revoke the user's sessions** (`Revoke-MgUserSignInSession` or Entra → user → Revoke sessions). A password reset alone leaves the refresh token working.
2. Reset the password.
3. Remove MFA methods registered since the pivot.
4. **Delete or disable any device registered since the pivot.** Revocation does not touch its PRT.
5. **Remove app consents and SP credentials** added since the pivot.
6. Remove mailbox rules and forwarding.
7. Block the attacker ASN in Conditional Access if your policy allows.
8. **Block the device code flow** with a Conditional Access policy (*Authentication flows → Device code flow*) for everyone who does not need it.

## Ticket

- Pivot time, session id, and the `2-Code entry` row
- The `4-Token use` rows with the different IP/ASN — the proof
- Resources the token reached
- How the code was delivered, by whom
- Devices registered since the pivot, and whether removed
- Persistence found, with times relative to the pivot
- Users and ASNs from scope
- **When sessions were revoked**

## False positives

| Looks suspicious | Usually |
|---|---|
| Azure CLI/PowerShell, developer, recurring | Headless server or build agent |
| VS Code, engineer, recurring | Remote development sign-in |
| Shared device, same IP every time | Meeting room panel |
| Many users, one app, one day | A rollout |

`DaysDcSeenByUser` and `UsersUsingDcInOrg` settle most of these. Weekly for three months is a job. First time ever, unmanaged device, is the one to look at.

## Limits

- A clean sign-in proves nothing — clean is what this attack produces.
- No ASN change does not mean no theft: an attacker exiting through the victim's provider shows no divergence.
- Revoking sessions does not remove consented apps or registered devices.
- A failed device code attempt still means someone was asked for a code.
- Not run against live telemetry. Reviewed for KQL correctness and schema only.
