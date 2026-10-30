# Device code phishing — incident response playbook

**Use when** a device code alert fires (DC-01 to DC-15), a user reports entering a code at `microsoft.com/devicelogin` for someone else, or a hunt finds a device code sign-in nobody can explain.

Companion documents: [threat overview and TTPs](devicecode-ttps.md) · [detections](../detections/device-code/README.md) · [coverage matrix](devicecode-coverage.md) · [review of the previous version](devicecode-review.md).

---

## Quick reference

**What happened.** Someone persuaded the user to type a code at `microsoft.com/devicelogin`. The user signed in and passed MFA on the real Microsoft page. The attacker's script received the user's tokens. Nothing failed, so the sign-in looks clean.

**First 15 minutes**

1. Run the [triage query](#31-confirm-the-device-code-flow) for the user. Note `TimeGenerated`, `AppDisplayName`, `IPAddress`, `SessionId`.
2. Run the [token-use query](#33-what-happened-next). The same `SessionId` used from another ASN = **stolen token**.
3. Ask the user: *did you enter a code, for what, who sent it?*
4. If stolen, or the user can't explain it: **contain now** (below), then investigate.

**Containment order** — do not stop at the password ([details](#6-containment)):

| # | Action | Why first |
|---|---|---|
| 1 | Revoke sessions | Kills refresh tokens; a password reset alone may not |
| 2 | Disable attacker-registered devices | A device keeps working after revocation |
| 3 | Remove MFA methods added since the pivot | Otherwise they sign in again |
| 4 | Remove app consents and credentials | Apps keep access on their own |
| 5 | Reset the password | Closes the original credential |
| 6 | Remove mailbox rules and forwarding | Stops the quiet leak and BEC |
| 7 | Block the IPs/ASN; block device code flow | Stops the next attempt |

**Severity at a glance**

| You see | Severity |
|---|---|
| Lure received, no sign-in | Low |
| Device code sign-in, user unapproved or first time | Medium |
| Token replayed, or device / MFA / app / mailbox change after the code | High |
| Any of the above for a privileged user, or more than one user compromised, or data accessed | Critical |

---

## 1. Purpose, scope and severity

**Purpose.** Decide whether a device code sign-in gave an attacker the user's tokens. Find everything they did and everything they left. Remove it, and close the policy gap that let it happen.

**In scope:** Microsoft Entra ID accounts and Microsoft 365 data reached with tokens from the OAuth 2.0 device authorization grant. That covers all three variants in the [threat overview](devicecode-ttps.md): token theft, the Authentication Broker device-and-PRT technique, and the attacker's own app.

**Out of scope:** endpoint malware (use the [hands-on-keyboard playbook](hok-playbook.md)), payment fraud handling (use the [BEC playbook](bec-playbook.md)), and Azure resource compromise beyond identifying it (escalate to cloud response).

**Severity**

| Severity | Criteria | Response target |
|---|---|---|
| Low | Lure delivered or clicked, no successful device code sign-in | Same day: warn the user, block the sender |
| Medium | Successful device code sign-in that is unapproved, first-time, or from a new location, with no evidence of token use elsewhere | 4 hours: triage, confirm with the user |
| High | Token replay (DC-08), or a device, MFA method, app or mailbox change after the code (DC-04 to DC-07, DC-09), or Graph abuse (DC-10) | 1 hour: contain, then investigate |
| Critical | High plus any of: privileged role, more than one user compromised (DC-15), confirmed access to sensitive data, internal phishing sent | Immediately: contain, open a major incident, notify legal/privacy |

**ATT&CK mapping** (full detail in the [TTPs document](devicecode-ttps.md))

| Tactic | Techniques |
|---|---|
| Initial access | T1566.002 Spearphishing Link, T1566.003 Spearphishing via Service, T1078.004 Cloud Accounts |
| Credential access | T1528 Steal Application Access Token |
| Defense evasion / lateral movement | T1550.001 Application Access Token |
| Persistence | T1098.005 Device Registration, T1556.006 MFA modification, T1098.001 Additional Cloud Credentials, T1671 Cloud Application Integration, T1136.003 Cloud Account |
| Collection | T1114.002 Remote Email Collection, T1114.003 Email Forwarding Rule, T1530 Data from Cloud Storage, T1213.002 SharePoint |
| Discovery | T1087.004 Cloud Account, T1069.003 Cloud Groups, T1526 Cloud Service Discovery |
| Lateral movement / impact | T1534 Internal Spearphishing, T1657 Financial Theft |

---

## 2. Prerequisites

### Logs and connectors

| Table | Connector or setting | Licence | Without it |
|---|---|---|---|
| `SigninLogs` | Microsoft Entra ID connector | Entra ID P1/P2 | **Nothing works** |
| `AADNonInteractiveUserSignInLogs` | Entra ID connector, non-interactive category ticked | Entra ID P1/P2 | No token-replay evidence (DC-08) |
| `AuditLogs` | Entra ID connector | Any Entra tier | No device, MFA, app or CA changes |
| `AADServicePrincipalSignInLogs` | Entra ID connector | Entra ID P1/P2 | No view of what a consented app did |
| `AADUserRiskEvents`, `AADRiskyUsers` | Entra ID connector, risk categories | **Entra ID P2** | No DC-13 |
| `MicrosoftGraphActivityLogs` | Entra diagnostic setting *MicrosoftGraphActivityLogs* | Entra ID P1/P2 // VERIFY your tenant's requirement | No DC-10; you won't know what Graph calls the token made. **Not on by default, no back-fill** |
| `OfficeActivity` | Microsoft 365 connector (Exchange, SharePoint, Teams) | Microsoft 365; `MailItemsAccessed` needs Audit Standard | No mailbox or file evidence from the audit log |
| `CloudAppEvents` | Microsoft Defender XDR connector | Defender for Cloud Apps + Microsoft 365 app connector | Defender variants; second source for DC-09/DC-11 |
| `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents` | Defender XDR connector | Defender for Office 365 P2 | No lure evidence (DC-12) |
| `MessageEvents`, `MessageUrlInfo` | Defender XDR connector (Teams tables) // VERIFY offered in your connector | Defender for Office 365 | No Teams lure evidence |
| `IdentityInfo`, `BehaviorAnalytics` | Sentinel UEBA | Sentinel | Optional enrichment (DC-02, DC-03) |
| `DeviceEvents` | Defender XDR connector | Defender for Endpoint P2 | No "browser opened to devicelogin" evidence |
| `EntraIdSignInEvents` | Advanced Hunting only (not a Sentinel table) | **Entra ID P2** | No Defender variants |

### Retention

- Entra admin centre keeps sign-in and audit logs for 30 days (P1/P2). Send them to Sentinel.
- Sentinel: keep the tables above for **at least 90 days** in the analytics tier. Refresh tokens last 90 days by default, and the attacker may wait. Archive for a year if you can.
- Advanced Hunting keeps 30 days.
- Detections baseline on up to 14 days (the Sentinel rule limit). Hunting runs can use 30–90.

### Roles

| Task | Least-privileged role |
|---|---|
| Run queries | Microsoft Sentinel Reader; Security Reader (Defender) |
| Update incidents | Microsoft Sentinel Responder |
| Revoke sessions, block sign-in, reset password | User Administrator (Privileged Authentication Administrator for admins) |
| Remove authentication methods | Authentication Administrator (Privileged Authentication Administrator for admins) |
| Disable or delete devices | Cloud Device Administrator |
| Remove consents, app credentials | Cloud Application Administrator or Application Administrator |
| Mailbox rules, forwarding, permissions | Exchange Administrator |
| Named locations and CA policies | Conditional Access Administrator |

Tools: Microsoft Graph PowerShell (`Microsoft.Graph`) and Exchange Online PowerShell (`ExchangeOnlineManagement`).

### Watchlists to create before you need them

| Watchlist | `SearchKey` | Used by |
|---|---|---|
| `DeviceCodeAllowedUsers` | UPN of each approved device code user | DC-01, DC-03, DC-14a |

---

## 3. Triage — first 15 minutes

### 3.1 Confirm the device code flow

**Question:** did this user complete a device code sign-in, with which app, from where, and with what MFA?

```kql
// Sentinel. Device code sign-ins for one user, newest first.
let lookback = 7d;
let target_user = "<UPN>";
SigninLogs
| where TimeGenerated > ago(lookback)
| where UserPrincipalName =~ target_user
| where AuthenticationProtocol =~ "deviceCode" or OriginalTransferMethod =~ "deviceCodeFlow" or ResultType == "50199"
| extend Country = tostring(LocationDetails.countryOrRegion),
         MfaMethods = strcat_array(extract_all(@'"authenticationMethod":"([^"]+)"', tostring(AuthenticationDetails)), ", ")
| project TimeGenerated, ResultType, ResultDescription, AuthenticationProtocol, AppDisplayName, AppId, AppOwnerTenantId, ResourceDisplayName,
          IPAddress, AutonomousSystemNumber, Country, UserAgent, AuthenticationRequirement, MfaMethods, ConditionalAccessStatus,
          RiskLevelDuringSignIn, SessionId, CorrelationId
| sort by TimeGenerated desc
```

**Read:**

| Column | Normal | Bad |
|---|---|---|
| `ResultType` | `0` | `0` after one or more `50199` rows: the pause while someone typed a code |
| `AppDisplayName` / `AppId` | The tool the user says they used (Azure CLI, Teams Rooms) | Microsoft Office or Authentication Broker when the user wasn't setting up a device |
| `AppOwnerTenantId` | `f8cdef31-…` (Microsoft) or your tenant | Any other tenant: an attacker's app |
| `ResourceDisplayName` | What the tool needs | **Device Registration Service** with the Broker app: the device-and-PRT technique |
| `IPAddress` / `AutonomousSystemNumber` | The user's usual network | Usually still the user's network. The code is typed by the victim, so a normal IP here proves nothing |

Record `TimeGenerated` (the **pivot time**) and `SessionId`.

The scored investigation query [`queries/devicecode.kql`](../queries/devicecode.kql) gives the same rows with 13 indicators added. Use it when sweeping many users.

### 3.2 Decision tree

```
Device code sign-in found?
├─ No ──────────────────────────── Lure only? → Low: warn user, block sender (5.9). Close.
└─ Yes
   ├─ Did the user enter it themselves, knowingly, for a tool or device they use?
   │   ├─ Yes, and it matches a legitimate case below ─── Benign. Add to DeviceCodeAllowedUsers if recurring. Close.
   │   └─ No / unsure / "IT asked me to" / "it was for a meeting" ── continue
   ├─ Token used from another ASN in the same session (3.3)? ── Yes → High. Contain (6), then 5.x.
   ├─ Device, MFA method, app or mailbox change after the pivot (3.3)? ── Yes → High. Contain (6).
   ├─ Broker app → Device Registration Service? ── Yes → High. Go to 5.4 first.
   └─ None of the above ── Medium. Revoke sessions as a precaution, complete 5.1–5.9, re-check in 24 h.
```

**Legitimate device code use**

| Case | What it looks like | How to confirm |
|---|---|---|
| Teams Rooms, Teams displays, Surface Hub | Resource account, Teams or "Teams – Device Admin Agent" client, office IP, recurring | Account is a known room resource |
| Azure CLI `az login --use-device-code`, Azure PowerShell, Graph PowerShell `-UseDeviceCode` | Developer or admin, Azure CLI/PowerShell/Graph CLI client, recurring | Ask the user; check their history (DC-03 would not fire for a regular user) |
| VS Code / remote development, Codespaces | Engineer, recurring | Same |
| Smart TVs, consoles (Xbox), streaming apps signing in to Microsoft apps | Consumer devices; corporate accounts should rarely do this | Ask the user |
| IoT and kiosk devices, shared devices with no keyboard | Service account, fixed IP | Device owner confirms |

A legitimate case has three things: the user remembers doing it, the app matches the tool, and it recurs. A one-off device code sign-in to Microsoft Office after a message from someone else is not legitimate, whatever the user thought they were doing.

### 3.3 What happened next

**Question:** was the token used from somewhere else, and did anything change straight after?

```kql
// Sentinel. Everything in the device code session, plus sensitive changes by or for the user, from the pivot on.
let pivot = datetime(<pivot time>);
let target_user = "<UPN>";
let session = "<SessionId>";
union
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated between (pivot .. (pivot + 2d))
        | where SessionId == session or (UserPrincipalName =~ target_user and OriginalTransferMethod =~ "deviceCodeFlow")
        | project TimeGenerated, What = strcat("Token use: ", AppDisplayName, " -> ", ResourceDisplayName), IPAddress, ASN = tostring(AutonomousSystemNumber),
                  Detail = strcat(UserAgent, " | ", ResultType, " | session ", SessionId)),
    (AuditLogs
        | where TimeGenerated between (pivot .. (pivot + 2d))
        | where tostring(InitiatedBy) has target_user or tostring(TargetResources) has target_user
        | project TimeGenerated, What = OperationName, IPAddress = tostring(InitiatedBy.user.ipAddress), ASN = "",
                  Detail = strcat(tostring(TargetResources[0].displayName), " | by ", coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)))),
    (OfficeActivity
        | where TimeGenerated between (pivot .. (pivot + 2d))
        | where UserId =~ target_user
        | where Operation in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox", "Add-MailboxPermission", "Add-RecipientPermission")
        | project TimeGenerated, What = Operation, IPAddress = ClientIP, ASN = "", Detail = substring(Parameters, 0, 300))
| sort by TimeGenerated asc
```

**Read:** token use from an `ASN` other than the pivot sign-in's, minutes after it, is the proof of theft. Any `Add device`, `Register device`, `User registered security info`, `Consent to application` or inbox rule after the pivot is persistence. Screenshot those rows for the ticket.

DC-04 runs this check automatically for every device code sign-in.

---

## 4. Scoping

Work through every line. Each row names the query and the setting to use.

| # | Question | Run | Bad looks like |
|---|---|---|---|
| S1 | All sign-ins for the user since a week before the pivot | [`queries/signinlogs.kql`](../queries/signinlogs.kql) with `UserIdentityCheck = "<UPN>"` | IPs, ASNs, countries or agents with a day count of 1 |
| S2 | Everything from the attacker IP, any user | [`queries/devicecode-scope.kql`](../queries/devicecode-scope.kql) with `IPCheck = "<IP>"` | Other users with `DeviceCode` or `TokenUse` hits |
| S3 | Everything from the attacker ASN, any user | Same, `ASNCheck = "<ASN>"` | Unrelated users on a hosting ASN the same day |
| S4 | Same user agent, any user | Same, `UserAgentCheck` | Script agents across users |
| S5 | Everyone sent the lure | Same, all checks blank, or `SenderCheck = "<sender>"` | Recipients who then have a `DeviceCode` row |
| S6 | All sessions and tokens | [DC-08](../detections/device-code/DC-08-device-code-token-replay.kql) with `follow = 13d` and `| where UserPrincipalName =~ "<UPN>"` | Any row |
| S7 | Devices registered | [DC-05](../detections/device-code/DC-05-device-registered-after-device-code.kql) with `alert_window = 13d` | Any device registered after the pivot |
| S8 | Auth methods added | [DC-06](../detections/device-code/DC-06-auth-method-after-device-code.kql) with `alert_window = 13d` | Methods the user didn't add |
| S9 | App consents and credentials | [DC-07](../detections/device-code/DC-07-app-consent-after-device-code.kql) with `alert_window = 13d` | Unknown apps, high-risk scopes |
| S10 | Mailbox rules, forwarding, delegates | [DC-09](../detections/device-code/DC-09-mailbox-rule-after-device-code.kql) with `alert_window = 13d` | Forward, delete or move rules |
| S11 | Graph, SharePoint, Exchange activity | [DC-10](../detections/device-code/DC-10-graph-abuse-after-device-code.kql) and [DC-11](../detections/device-code/DC-11-bulk-access-after-device-code.kql) with `alert_window = 13d` | Search calls, bulk reads from the attacker IP |
| S12 | Internal phishing sent | [DC-16](../queries/devicecode-timeline.kql) phase `10-Outbound`; [DC-12](../detections/device-code/DC-12-device-code-lure-delivery.kql) with `alert_window = 13d`, kind `Internal mail` | Mail with links from the victim to colleagues |
| S13 | Everything before and after, one view | [DC-16](../queries/devicecode-timeline.kql) with `PivotTime`, `UserIdentityCheck`, `IPCheck` | See 5.13 |
| S14 | What persists, before and after | [`queries/devicecode-persistence.kql`](../queries/devicecode-persistence.kql) with `PivotTime`, `UserIdentityCheck` | Any `2-After pivot` row in `Device`, `App`, `Service principal` |

To run a detection as an investigation query: open its `.kql`, change `alert_window` (and `follow` where present) to cover the period, and add `| where UserPrincipalName =~ "<UPN>"` at the end. Anything longer than 14 days runs fine in Logs; only scheduled rules are capped.

---

## 5. Investigation

Each step answers one question. The detection file is the exact query; the instructions say what to change for an investigation run.

### 5.1 Device code sign-in

**Question:** which app, which resource, which MFA, and was there a prompt first?
**Run:** [DC-01](../detections/device-code/DC-01-device-code-sign-in.kql) with `alert_window = 7d`, plus `| where UserPrincipalName =~ "<UPN>"`. Defender: [DC-01 Defender](../detections/device-code/DC-01-device-code-sign-in.defender.kql).
**Expect:** one row per code entry. `ClientKind` names the client type.
**Bad:** `ClientKind = Broker to Device Registration Service` or `Third-party app`; `ConfirmPromptFirst = true` on a client the user doesn't use; failed rows (`ResultType` not `0`) before a success, meaning codes were re-sent until one worked.

### 5.2 New location or agent

**Question:** is this the user's normal network, device and app?
**Run:** [DC-02](../detections/device-code/DC-02-device-code-new-location-or-agent.kql) with `alert_window = 7d`, `baseline = 30d`; [DC-03](../detections/device-code/DC-03-device-code-first-time-or-unapproved.kql) with `alert_window = 7d`, `baseline = 90d`.
**Expect:** no rows for a legitimate regular user.
**Bad:** `NewDimensions` includes ASN or Country; `Reason = First device code use`. The code entry usually comes from the victim's own network, so a clean DC-02 does **not** clear the incident. Check 5.3.

### 5.3 Token replay

**Question:** did the token leave the victim's network?
**Run:** [DC-08](../detections/device-code/DC-08-device-code-token-replay.kql) with `alert_window = 7d`, `follow = 7d`, plus the user filter. Defender: [DC-08 Defender](../detections/device-code/DC-08-device-code-token-replay.defender.kql).
**Expect:** no rows.
**Bad:** `token used from another ASN` (the proof); `FOCI app-hopping` (one refresh token turned into Office, Teams, Azure CLI tokens); `tool user agent`; `SingleFactorUses > 0` (tokens used with no fresh MFA, which is expected after theft). Record `OtherIPs` and `OtherAsns` as IOCs.

### 5.4 Device registration

**Question:** did the attacker register or join a device, and so hold a PRT?
**Run:** [DC-05](../detections/device-code/DC-05-device-registered-after-device-code.kql) with `alert_window = 7d`, plus the user filter. Defender: [DC-05 Defender](../detections/device-code/DC-05-device-registered-after-device-code.defender.kql).
**Expect:** none, or a device the user can name and hold up.
**Bad:** `BrokerPath = true`; a device name not in your naming scheme; registration minutes after the code. Then run [DC-16](../queries/devicecode-timeline.kql) phase `6-Device sign-in` to see the device being used.

### 5.5 Authentication methods

**Question:** did the attacker add a way to sign in again, or remove the user's?
**Run:** [DC-06](../detections/device-code/DC-06-auth-method-after-device-code.kql) with `alert_window = 7d`.
**Bad:** any method the user didn't add; `FromOtherIP = true`; `Removed = true` for the user's own method.

### 5.6 Apps and consent

**Question:** did the attacker get an app access that outlives the session?
**Run:** [DC-07](../detections/device-code/DC-07-app-consent-after-device-code.kql) with `alert_window = 7d`; then [`queries/devicecode-persistence.kql`](../queries/devicecode-persistence.kql) method `Service principal` to see what the app did.
**Bad:** an unknown app, `HighRiskScope = true`, consent minutes after the code, a new secret on any service principal.

### 5.7 Mailbox rules

**Question:** is mail being hidden or forwarded?
**Run:** [DC-09](../detections/device-code/DC-09-mailbox-rule-after-device-code.kql) with `alert_window = 7d`. Confirm live state with `Get-InboxRule -Mailbox <UPN>` and `Get-Mailbox <UPN> | fl Forwarding*`.
**Bad:** `HidesOrForwards = true`; rules on words like invoice, payment, password; forwarding to an external address. Open the [BEC playbook](bec-playbook.md) for the finance side.

### 5.8 Graph, files and mail

**Question:** what did the token read? This is the disclosure question.
**Run:** [DC-10](../detections/device-code/DC-10-graph-abuse-after-device-code.kql) and [DC-11](../detections/device-code/DC-11-bulk-access-after-device-code.kql) with `alert_window = 7d`; [DC-16](../queries/devicecode-timeline.kql) phases `8-Mail read` and `9-Graph`.
**Bad:** `Searches > 0` from the attacker IP (Storm-2372 searched for *password, admin, credentials, teamviewer, anydesk, secret, ministry, gov*); directory enumeration; downloads from an IP outside the user's. List every item in `SampleItems`/`SamplePaths` for the disclosure assessment.

### 5.9 Lure delivery

**Question:** how did the code reach the user, and who else got it?
**Run:** [DC-12](../detections/device-code/DC-12-device-code-lure-delivery.kql) with `alert_window = 14d` and `IncludeSubjectLures = true`; filter on the user, then on the sender.
**Bad:** an external sender; a QR code; a Teams message from an external tenant; `Internal mail`, which means another account is compromised. If nothing shows, **ask the user**: WhatsApp, Signal, phone and printed QR codes leave no trace in these logs.

### 5.10 Risk detections

**Question:** did Identity Protection see it?
**Run:** [DC-13](../detections/device-code/DC-13-risk-on-device-code-user.kql) with `alert_window = 7d` and `MinRiskLevel` including `low`.
**Bad:** `anomalousToken`, `unfamiliarFeatures`, `anonymizedIPAddress` or threat-intelligence detections on an IP other than the code entry's (`SameIP = false`).

### 5.11 Conditional Access gap

**Question:** why wasn't this blocked?
**Run:** [DC-14a](../detections/device-code/DC-14a-device-code-not-blocked.kql) for the user's sign-in; [DC-14b](../detections/device-code/DC-14b-device-code-ca-posture.kql) for the policy state. If DC-14b returns nothing, export the policies:

```powershell
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy -All |
  Where-Object { $_.Conditions.AuthenticationFlows.TransferMethods -match 'deviceCodeFlow' } |
  Select-Object DisplayName, State,
    @{n='ExcludeUsers';e={$_.Conditions.Users.ExcludeUsers -join ','}},
    @{n='ExcludeGroups';e={$_.Conditions.Users.ExcludeGroups -join ','}},
    @{n='ExcludeApps';e={$_.Conditions.Applications.ExcludeApplications -join ','}},
    @{n='Grant';e={$_.GrantControls.BuiltInControls -join ','}}
```

**Bad:** `Gap = NoBlockPolicy`; a block policy in report-only; the user in an exclusion group; `ExcludesDrs = true` without device registration restricted (section 8).

### 5.12 Campaign scope

**Question:** who else was hit?
**Run:** [DC-15](../detections/device-code/DC-15-device-code-campaign.kql) with `lookback = 14d`, `alert_window = 14d`; [`queries/devicecode-scope.kql`](../queries/devicecode-scope.kql) with the attacker IP, ASN and sender.
**Bad:** other users in `UserList` with `SucceededUsers > 0`. Each one is a new incident: link them and run this playbook for each.

### 5.13 Timeline

**Question:** what is the full story, in order?
**Run:** [DC-16 — `queries/devicecode-timeline.kql`](../queries/devicecode-timeline.kql) with `PivotTime`, `UserIdentityCheck = "<UPN>"`, and `IPCheck = "<IP>"` for the attacker address.

```
0-Prior code / 0-Prior apps   set-up in the 7 days before: earlier code attempts, app changes anywhere
1-Lure / 1-Delivery           device code links, clicks, mail and Teams around the phish
2-Code entry                  the device code sign-in
3-Sign-ins / 4-Token use      interactive sign-ins; refresh-token use, with origin=deviceCodeFlow
5-Service principal           apps the user consented to, signing in on their own
6-Device / 6-Device sign-in   devices registered, and sign-ins from them
7-Directory / 8-Cloud         directory and Microsoft 365 changes
8-Mail read / 9-Graph         what was read
10-Outbound                   internal phishing sent
11-Risk                       Identity Protection detections
```

Put `2-Code entry` and the first `4-Token use` from another ASN side by side in the ticket. That pair is the proof.

---

## 6. Containment

**Order matters.** A password reset alone leaves the attacker in. Depending on how the token was issued, refresh tokens can outlive a password change. A registered device stays registered after every token is revoked, and a consented app never needed the user's password. Cut access first, remove footholds second, then reset.

Access tokens already issued stay valid until they expire (typically 60–90 minutes), unless the resource enforces Continuous Access Evaluation.

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All","UserAuthenticationMethod.ReadWrite.All","Directory.AccessAsUser.All","Device.ReadWrite.All","DelegatedPermissionGrant.ReadWrite.All","AppRoleAssignment.ReadWrite.All","Application.ReadWrite.All"
$upn = "<UPN>"
```

| # | Action | Command | Reversible |
|---|---|---|---|
| 1 | Optional, if active: block sign-in | `Update-MgUser -UserId $upn -AccountEnabled:$false` | Yes |
| 2 | **Revoke sessions** (all refresh tokens and session cookies) | `Revoke-MgUserSignInSession -UserId $upn` | Yes (user signs in again) |
| 3 | **Find and disable attacker devices** | `Get-MgUserRegisteredDevice -UserId $upn` and `Get-MgUserOwnedDevice -UserId $upn`, then `Update-MgDevice -DeviceId <DeviceObjectId> -AccountEnabled:$false`; delete after evidence capture with `Remove-MgDevice -DeviceId <DeviceObjectId>` | Disable yes; delete no |
| 4 | **Remove MFA methods added since the pivot** | `Get-MgUserAuthenticationMethod -UserId $upn`, then the matching cmdlet, e.g. `Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod`, `Remove-MgUserAuthenticationPhoneMethod`, `Remove-MgUserAuthenticationFido2Method`, `Remove-MgUserAuthenticationWindowsHelloForBusinessMethod`, `Remove-MgUserAuthenticationTemporaryAccessPassMethod` | No (re-register) |
| 5 | **Remove consent grants and app access** | `Get-MgUserOauth2PermissionGrant -UserId $upn` then `Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <id>`; `Get-MgUserAppRoleAssignment -UserId $upn` then `Remove-MgUserAppRoleAssignment -UserId $upn -AppRoleAssignmentId <id>` | No |
| 6 | **Disable rogue service principals, remove credentials** | `Update-MgServicePrincipal -ServicePrincipalId <id> -AccountEnabled:$false`; `Remove-MgServicePrincipalPassword -ServicePrincipalId <id> -KeyId <keyId>` | Disable yes |
| 7 | Reset the password | Entra admin centre → user → Reset password, or `Update-MgUser -UserId $upn -PasswordProfile @{ ForceChangePasswordNextSignIn = $true; Password = "<generated>" }` | No |
| 8 | **Remove mailbox rules, forwarding, delegates** (Exchange Online PowerShell) | `Get-InboxRule -Mailbox $upn` then `Remove-InboxRule -Mailbox $upn -Identity <rule>`; `Set-Mailbox $upn -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false`; `Get-MailboxPermission $upn` then `Remove-MailboxPermission`; `Remove-RecipientPermission` | No |
| 9 | Block attacker IPs | Named location: `New-MgIdentityConditionalAccessNamedLocation` with the IP ranges, plus a CA policy that blocks it. Prefer ASN-level blocking at your proxy if the actor rotates IPs | Yes |
| 10 | Require reauthentication | Revocation (2) forces it. For privileged users also set a CA sign-in frequency policy | Yes |
| 11 | Re-enable the user once 2–8 are done | `Update-MgUser -UserId $upn -AccountEnabled:$true` | — |

**Do not** delete devices, apps or rules before capturing them (section 7, evidence). Disabling preserves the evidence and stops the attacker.

**Isolating the user** means steps 1–2: block sign-in and revoke sessions. Hold step 11 until eradication is verified.

---

## 7. Eradication and recovery

### Evidence to capture before deleting anything

- Export of the DC-16 timeline, DC-08 replay rows, DC-05/06/07/09 results (CSV to the case store, **not** to this repo).
- Device objects: `Get-MgDevice -DeviceId <id> | ConvertTo-Json -Depth 5`.
- Consent grants and service principals: `Get-MgServicePrincipal -ServicePrincipalId <id> | ConvertTo-Json -Depth 5`.
- Inbox rules: `Get-InboxRule -Mailbox <UPN> | fl *`.
- The lure message (Defender → Explorer → download) and any QR images.

### Verify nothing remains

- [ ] `Get-MgUserRegisteredDevice` / `Get-MgUserOwnedDevice` list only devices the user holds.
- [ ] `Get-MgUserAuthenticationMethod` lists only methods the user registered, confirmed with them.
- [ ] `Get-MgUserOauth2PermissionGrant` and `Get-MgUserAppRoleAssignment` list only expected apps.
- [ ] No new app registrations or service principal credentials since the pivot ([`queries/devicecode-persistence.kql`](../queries/devicecode-persistence.kql) method `App`).
- [ ] `Get-InboxRule`, mailbox forwarding and permissions are clean.
- [ ] Re-run DC-08 and DC-10 for the user over the last 24 hours: no rows.
- [ ] No sign-ins from the attacker IPs/ASN for any user since containment ([`queries/devicecode-scope.kql`](../queries/devicecode-scope.kql)).

### Re-enrol MFA safely

1. Verify identity out of band (in person, or video with ID, or manager confirmation). Don't use a phone number or email the attacker could have changed.
2. Issue a single-use, short-lived Temporary Access Pass.
3. Have the user register a phishing-resistant method (passkey / FIDO2 / Windows Hello) under the TAP.
4. Confirm the method list afterwards.

### Review CA and Intune state

- Run DC-14b and fix the device code policy (section 8).
- If an attacker device was registered: check Intune for an enrolled device with the same name, and check that it never reached compliance. Device compliance changes need Intune logs, which this playbook doesn't cover ([gap](devicecode-ttps.md#gaps)).

---

## 8. Hardening

| Control | How | Notes |
|---|---|---|
| **Block device code flow** | CA policy: all users, all resources, Conditions → Authentication flows → Device code flow, Grant → Block. Report-only first, then On ([Microsoft Learn](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-authentication-flows)) | Exclude break-glass and an approved-exceptions group only. Review the group quarterly |
| Allow-list exceptions narrowly | Teams Rooms: exclude resource accounts by group, restrict by device filter or named location ([Microsoft Learn](https://learn.microsoft.com/entra/identity/conditional-access/policy-teams-devices-device-code-flow)) | Never add ordinary users to the exception group |
| **Device Registration Service exclusion** | Microsoft's Teams device guidance excludes the Device Registration Service from the block policy. That reopens the Broker → DRS path | If you exclude it, also restrict device registration (next row) and alert with DC-05 |
| Restrict device registration and join | Entra → Devices → Device settings: limit who may join/register; CA user action **Register or join devices** requiring MFA from a compliant or trusted location | Directly targets Storm-2372 |
| Protect security info registration | CA user action **Register security information**: require a trusted location or TAP | Stops attacker MFA registration from their network |
| Restrict user consent | Entra → Enterprise apps → Consent and permissions: verified publishers and low-risk permissions only, or none; turn on the admin consent workflow | Removes the attacker's-own-app variant |
| Token protection | CA session control **Require token protection for sign-in sessions** where supported | Binds tokens to the device; check client support |
| Phishing-resistant MFA | Authentication strengths requiring passkeys / FIDO2 / Windows Hello for sensitive apps and admins | Doesn't stop device code alone; the victim still signs in. Combine with the block |
| Risk-based policies | Sign-in risk and user risk policies (Entra ID P2) | Covers anomalous token detections |
| Graph activity logging | Turn on the `MicrosoftGraphActivityLogs` diagnostic setting | Without it, 5.8 can't be answered |
| Awareness | "Microsoft, IT and meeting hosts will never ask you to enter a code at microsoft.com/devicelogin. If anyone does, report it." | URL checks don't help: the page is genuine. Teach the behaviour, not the URL |

---

## 9. Communications and escalation

| Who | When | What |
|---|---|---|
| SOC lead | Medium and above | Incident opened, severity, containment status |
| Affected user and their manager | At containment | What happened, what changed for them, how to re-enrol |
| Identity / Entra team | High and above | Containment actions 2–7, device and app removals |
| Messaging / Exchange team | Mailbox findings | Rule and forwarding removals, purge of internal phishing |
| CISO | Critical; any privileged account | Scope, data accessed, business impact |
| Legal, privacy / DPO | Any confirmed access to personal or regulated data (5.8) | Facts for the notification decision. GDPR: a personal data breach likely to risk individuals must be reported to the supervisory authority within 72 hours of awareness. Check sector rules (NIS2, DORA, HIPAA, state laws) |
| Finance | Mailbox rules on finance terms, or internal mail to finance | Freeze payment and bank-detail changes requested since the pivot |
| Communications | Campaign across many users | Staff warning |

**Evidence handling.** Export query results to the case store with the query text and run time. Record who ran what, when. Hash exported files. Don't paste tenant data into tickets that leave the security team, and never commit results to this repository (CI rejects `*.csv`).

**Escalate to Critical** when: a privileged role holder is affected; DC-15 shows more than one successful victim; 5.8 shows sensitive data was read; internal phishing reached finance or executives.

---

## 10. Post-incident

### Lessons learned

```text
Incident:            <ID>                      Date closed: <date>
Initial vector:      <email / Teams / QR / WhatsApp / phone / unknown>
Variant:             <token theft / device and PRT / attacker's app>
Time to detect:      <pivot → first alert>     Detected by: <DC-xx / user report / hunt>
Time to contain:     <first alert → revocation>
What worked:
What didn't:
Policy gap (DC-14):  <no block / exclusion / report-only / DRS excluded>
Actions:             <owner, due date>
```

### Detection tuning checklist

- [ ] Add confirmed-legitimate users to `DeviceCodeAllowedUsers`.
- [ ] Add corporate egress ASNs/IPs to `KnownEgressAsns` / `KnownEgressIPs` in DC-02, DC-08, DC-15.
- [ ] If the attacker's client ID wasn't in `AbusedClients`, add it (DC-01, Defender DC-01) and to the [lookup](devicecode-ttps.md#client-id-lookup).
- [ ] Note which detection fired first and which should have; adjust thresholds (DC-10, DC-11) from what the attacker actually did.
- [ ] Record any `// VERIFY` assumption you confirmed or disproved, and fix the query.
- [ ] Bump the rule `version` and run `python3 tools/check_rules.py --sync`.

### IOC record

| Type | Value | First seen | Last seen | Source (DC-xx / query) | Action taken |
|---|---|---|---|---|---|
| IP | `<IP>` | | | DC-08 | Named location block |
| ASN | `<ASN>` | | | DC-15 | Proxy block / watch |
| User agent | `<UA>` | | | DC-08 / DC-10 | Hunt |
| Client app ID | `<AppId>` | | | DC-01 | Added to AbusedClients |
| Device | `<DeviceId>` | | | DC-05 | Disabled, deleted |
| App / service principal | `<AppId>` | | | DC-07 | Consent removed, SP disabled |
| Sender | `<address>` | | | DC-12 | Blocked |
| Lure URL / domain | `<URL>` | | | DC-12 | Blocked |

---

## Appendix A — Query index

| ID | File | Type | Question | Section | Severity |
|---|---|---|---|---|---|
| DC-01 | [`DC-01-device-code-sign-in`](../detections/device-code/DC-01-device-code-sign-in.kql) · [Defender](../detections/device-code/DC-01-device-code-sign-in.defender.kql) | Rule | Did someone enter a device code? | [5.1](#51-device-code-sign-in) | Low (dynamic) |
| DC-02 | [`DC-02-device-code-new-location-or-agent`](../detections/device-code/DC-02-device-code-new-location-or-agent.kql) | Rule | From somewhere new? | [5.2](#52-new-location-or-agent) | Medium |
| DC-03 | [`DC-03-device-code-first-time-or-unapproved`](../detections/device-code/DC-03-device-code-first-time-or-unapproved.kql) | Rule | By someone who never does this? | [5.2](#52-new-location-or-agent) | Medium |
| DC-04 | [`DC-04-device-code-then-sensitive-action`](../detections/device-code/DC-04-device-code-then-sensitive-action.kql) | Rule | Then something sensitive changed? | [3.3](#33-what-happened-next) | High |
| DC-05 | [`DC-05-device-registered-after-device-code`](../detections/device-code/DC-05-device-registered-after-device-code.kql) · [Defender](../detections/device-code/DC-05-device-registered-after-device-code.defender.kql) | Rule | Then a device was registered? | [5.4](#54-device-registration) | High |
| DC-06 | [`DC-06-auth-method-after-device-code`](../detections/device-code/DC-06-auth-method-after-device-code.kql) | Rule | Then an MFA method changed? | [5.5](#55-authentication-methods) | High |
| DC-07 | [`DC-07-app-consent-after-device-code`](../detections/device-code/DC-07-app-consent-after-device-code.kql) · [Defender](../detections/device-code/DC-07-app-consent-after-device-code.defender.kql) | Rule | Then an app got access? | [5.6](#56-apps-and-consent) | High |
| DC-08 | [`DC-08-device-code-token-replay`](../detections/device-code/DC-08-device-code-token-replay.kql) · [Defender](../detections/device-code/DC-08-device-code-token-replay.defender.kql) | Rule | Was the token replayed? | [5.3](#53-token-replay) | High |
| DC-09 | [`DC-09-mailbox-rule-after-device-code`](../detections/device-code/DC-09-mailbox-rule-after-device-code.kql) · [Defender](../detections/device-code/DC-09-mailbox-rule-after-device-code.defender.kql) | Rule | Then mail was hidden or forwarded? | [5.7](#57-mailbox-rules) | High |
| DC-10 | [`DC-10-graph-abuse-after-device-code`](../detections/device-code/DC-10-graph-abuse-after-device-code.kql) | Rule | What did Graph calls read? | [5.8](#58-graph-files-and-mail) | Medium |
| DC-11 | [`DC-11-bulk-access-after-device-code`](../detections/device-code/DC-11-bulk-access-after-device-code.kql) · [Defender](../detections/device-code/DC-11-bulk-access-after-device-code.defender.kql) | Rule | Were files or mail taken in bulk? | [5.8](#58-graph-files-and-mail) | Medium |
| DC-12 | [`DC-12-device-code-lure-delivery`](../detections/device-code/DC-12-device-code-lure-delivery.kql) · [Defender](../detections/device-code/DC-12-device-code-lure-delivery.defender.kql) | Rule | How did the lure arrive? | [5.9](#59-lure-delivery) | Medium |
| DC-13 | [`DC-13-risk-on-device-code-user`](../detections/device-code/DC-13-risk-on-device-code-user.kql) | Rule | Did Identity Protection see it? | [5.10](#510-risk-detections) | Medium |
| DC-14a | [`DC-14a-device-code-not-blocked`](../detections/device-code/DC-14a-device-code-not-blocked.kql) | Rule (daily) | Why wasn't it blocked? | [5.11](#511-conditional-access-gap) | Low |
| DC-14b | [`DC-14b-device-code-ca-posture`](../detections/device-code/DC-14b-device-code-ca-posture.kql) | Hunting | What do our policies say? | [5.11](#511-conditional-access-gap) | — |
| DC-15 | [`DC-15-device-code-campaign`](../detections/device-code/DC-15-device-code-campaign.kql) · [Defender](../detections/device-code/DC-15-device-code-campaign.defender.kql) | Rule | Who else? | [5.12](#512-campaign-scope) | High |
| DC-16 | [`queries/devicecode-timeline.kql`](../queries/devicecode-timeline.kql) | Investigation | The whole story, in order | [5.13](#513-timeline) | — |

Investigation queries kept from the previous version: [`devicecode.kql`](../queries/devicecode.kql) (scored triage), [`devicecode-persistence.kql`](../queries/devicecode-persistence.kql) (before/after persistence), [`devicecode-scope.kql`](../queries/devicecode-scope.kql) (blast radius).

## Appendix B — Glossary

| Term | Meaning |
|---|---|
| Device code flow | OAuth 2.0 device authorization grant (RFC 8628): sign in on one device by entering a code shown on another |
| Code entry | The interactive sign-in where the victim types the code: `AuthenticationProtocol = deviceCode` |
| Pivot time | The code entry's time; everything is measured before and after it |
| Refresh token | Long-lived token (90 days by default) that gets new access tokens without a prompt |
| PRT | Primary Refresh Token: a device-bound token that gives SSO to all apps; an attacker gets one by registering a device |
| FOCI | Family of client IDs: Microsoft public clients whose refresh tokens can be redeemed for each other |
| Authentication Broker | Microsoft client `29d9ed98-…`; its tokens can reach the Device Registration Service |
| Device Registration Service (DRS) | Resource `01cb2876-…` that registers and joins devices in Entra ID |
| Protocol tracking | Entra marks a session that began with device code; `OriginalTransferMethod = deviceCodeFlow` stays on later refreshes |
| `SessionId` | Shared by the code entry and every token refresh from it: the join key for replay |
| CAE | Continuous Access Evaluation: lets supporting resources reject a token before expiry after revocation |
| TAP | Temporary Access Pass: time-limited code to register a new MFA method |
| `50199` | Sign-in error for a confirmation prompt; before a success in one session, it marks the pause while a code is typed |

## Appendix C — References

- [Microsoft Threat Intelligence — Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- [Microsoft Learn — Conditional Access: authentication flows](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows)
- [Microsoft Learn — Block authentication flows with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-authentication-flows)
- [Microsoft Learn — Restrict device code flow for Teams devices](https://learn.microsoft.com/entra/identity/conditional-access/policy-teams-devices-device-code-flow)
- [Microsoft Learn — Microsoft identity platform and the OAuth 2.0 device authorization grant flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-device-code)
- [Microsoft Learn — Revoke user access in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/users/users-revoke-access)
- [Microsoft Learn — MicrosoftGraphActivityLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs)
- [Microsoft Learn — EntraIdSignInEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-entraidsigninevents-table)
- [Microsoft Learn — Sentinel analytics rule YAML](https://learn.microsoft.com/azure/sentinel/isv/sentinel-analytic-rules-creation)
- [Secureworks — family-of-client-ids research](https://github.com/secureworks/family-of-client-ids-research)
- [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
- Volexity, Proofpoint, Huntress, Push Security: see [sources in the TTPs document](devicecode-ttps.md#sources).

## Appendix D — Limits and assumptions

- **Not run against live telemetry.** Every query was checked against Microsoft Learn schemas and linted (`tools/lint_kql.py`, `tools/check_rules.py`), not executed. Run each over 14 days before enabling it.
- Lines marked `// VERIFY` depend on values that vary by tenant or connector: `AppOwnerTenantId` population, Teams tables in the connector, UEBA insight names, CA policy JSON property names, Entra operation names in `CloudAppEvents`, Graph diagnostic licence.
- The code entry usually comes from the victim's own network. Location-based checks (DC-02) miss most cases; replay (DC-08) and follow-on actions (DC-04 to DC-07, DC-09) carry the detection.
- Defender variants infer device code from a `50199` prompt; they miss failed attempts and can match other confirmation flows.
- WhatsApp, Signal, phone and printed QR lures, the attacker's code request, and payment fraud aren't visible in these logs.
- Tools that spoof browser user agents defeat the user-agent checks.
