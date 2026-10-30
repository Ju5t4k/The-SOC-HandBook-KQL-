# Device code phishing — threat overview and TTPs

Companion to the [device code playbook](devicecode-playbook.md). Each technique below lists what it looks like in the logs, which table and field shows it, which detection covers it, and which playbook step investigates it. **Gap** marks a technique no detection covers.

Detections live in [`detections/device-code/`](../detections/device-code/README.md). Coverage in one grid: [`devicecode-coverage.md`](devicecode-coverage.md).

## How the attack works

The OAuth 2.0 device authorization grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) lets a device with no keyboard sign in: the device shows a short code, the user enters it on another device at `microsoft.com/devicelogin`, and the device receives tokens. The attacker plays the device. They request a code from Microsoft for a client of their choice, get the victim to enter it, and receive the victim's access and refresh tokens. The victim completes real MFA on the real Microsoft page, so the sign-in looks clean.

A code expires after about 15 minutes. Early campaigns sent pre-generated codes and lost many to expiry. Current kits (SquarePhish2, EvilTokens, Tycoon 2FA's device code module) generate the code only when the victim opens the link, which removes that limit.

## Sources

| Source | What it adds | Read |
|---|---|---|
| [Microsoft Threat Intelligence — Storm-2372 (Feb 2025, updated 2026)](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/) | Lures via WhatsApp, Signal and fake Teams invites; the Authentication Broker → Device Registration Service → PRT technique; Graph mail searches; internal phishing; hunting queries | Primary, read in full |
| [Secureworks — family-of-client-ids research](https://github.com/secureworks/family-of-client-ids-research) | FOCI: refresh tokens shared across Microsoft public clients; the client ID list below | Primary, read in full |
| [Microsoft Learn — Authentication flows](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows) | Protocol tracking (`OriginalTransferMethod`), the Device Registration Service exception | Primary |
| Volexity (Feb 2025): APT29/CozyLarch, UTA0304, UTA0307 | Fake secure-chat and Element lures; on-the-fly code generation | Secondary coverage only ([Infosecurity](https://www.infosecurity-magazine.com/news/russian-microsoft-device-code/)); volexity.com unreachable from the build environment |
| [Proofpoint — device code phishing evolution](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover) | QR codes and buttons; SquarePhish2, EvilTokens; TA2723, TA4903, UNK_AcademicFlare | Secondary coverage only ([The Hacker News](https://thehackernews.com/2025/12/russia-linked-hackers-use-microsoft-365.html)) |
| [Huntress — device code phishing is still evolving](https://www.huntress.com/blog/device-code-phishing-evolving-threats) | 2026 waves on Railway and BL Networks infrastructure; EvilTokens | Secondary coverage only ([Expert Insights](https://expertinsights.com/news/huntress-device-code-phishing-surge-ai)) |
| [Push Security](https://pushsecurity.com/blog/topics/detection-and-response) | Device code phishing page volume in 2026; detect on protocol and downstream session, not the sign-in alone | Secondary coverage only |
| [Elastic — Entra ID ADRS token request by Microsoft Authentication Broker](https://detection.fyi/elastic/detection-rules/integrations/azure/persistence_entra_id_suspicious_adrs_token_request/) | Authentication Broker and Device Registration Service IDs | Published rule |

Proofpoint, Huntress and Volexity pages could not be opened from the build environment. Their details here come from press coverage and are marked as such. Re-check figures against the originals before quoting them.

---

## Client ID lookup

Device code phishing uses public clients. These need no secret, are pre-consented in every tenant, and many are FOCI members whose refresh token works for every other member.

| Application | Client ID | FOCI | Why it matters | Source |
|---|---|---|---|---|
| Microsoft Authentication Broker | `29d9ed98-a469-4536-ade2-f981bc1d605e` | — | Its token can reach the Device Registration Service → attacker device → PRT (Storm-2372) | Elastic rule; Microsoft Storm-2372 post (name only) |
| Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Yes | Common default in device code kits; Graph, Exchange, SharePoint scopes | Secureworks |
| Microsoft Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Yes | Default in GraphRunner and many scripts; ARM and Graph | Secureworks |
| Microsoft Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` | Yes | ARM and Graph | Secureworks |
| Microsoft Teams | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | Yes | Teams and Graph; blends in | Secureworks |
| Outlook Mobile | `27922004-5251-4030-b22d-91ecd9a37ea4` | Yes | Mail | Secureworks |
| Microsoft Authenticator App | `4813382a-8fa7-425e-ab75-3b753aab3abb` | Yes | Can lead to authentication method changes | Secureworks |
| OneDrive SyncEngine | `ab9b8c07-8f02-4f72-87fa-80105867a763` | Yes | Files | Secureworks |
| OneDrive | `b26aadf8-566f-4478-926f-589f601d9c74` | Yes | Files | Secureworks |
| OneDrive iOS App | `af124e86-4e96-495a-b70a-90f90ab96707` | Yes | Files | Secureworks |
| Visual Studio | `872cd9fa-d31f-45e0-9eab-6e460a02d1f1` | Yes | Developer tooling | Secureworks |
| Microsoft Intune Company Portal | `9ba1a5c7-f17a-4de9-a1f1-6178c8d51223` | Yes | Device enrolment context | Secureworks |
| Office UWP PWA | `0ec893e0-5785-4de6-99da-4ed124e5296c` | Yes | Office web | Secureworks |
| Microsoft Edge | `ecd6b820-32c2-49b6-98a6-444530e5a77a` | Yes | One of three Edge IDs in the FOCI list | Secureworks |
| Microsoft Teams – Device Admin Agent | `87749df4-7ccf-48f8-aa87-704bad0e0e16` | Yes | Legitimate Teams Rooms device code client | Secureworks |
| Microsoft Graph Command Line Tools | `14d82eec-204b-4c2f-b7e8-296a70dab67e` | Not in list | `Connect-MgGraph -UseDeviceCode` | [Microsoft Learn](https://learn.microsoft.com/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in) |
| Device Registration Service (resource) | `01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9` | — | The **resource** a device-registering token is issued for | [Microsoft Learn](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows) |

Microsoft's first-party apps are owned by tenant `f8cdef31-a31e-4b4a-93e4-5f571e91255a` (`SigninLogs.AppOwnerTenantId`). A device code sign-in to an app owned by any other tenant except yours is a third-party app, often the attacker's.

Secureworks lists 37 FOCI clients and says the list is not complete. The detections hold the subset above in a `let` list; extend it from your own `SigninLogs` (`AuthenticationProtocol == "deviceCode"`, distinct `AppId`).

---

## 1. Initial access — the lure and the code

**ATT&CK:** T1566.002 Spearphishing Link, T1566.003 Spearphishing via Service, T1528 Steal Application Access Token, T1078.004 Valid Accounts: Cloud Accounts.

- Delivered by email, Teams chat, fake Teams or Zoom meeting invites ("the meeting ID is the code"), WhatsApp or Signal after days of rapport, QR codes in mail or PDFs, and buttons on lookalike pages (Storm-2372, Volexity, Proofpoint).
- The lure points at `microsoft.com/devicelogin`, `aka.ms/devicelogin` or `login.microsoftonline.com/common/oauth2/deviceauth`, or at an attacker page that shows a freshly generated code and then redirects there.
- In the sign-in log the code entry is an interactive sign-in with `AuthenticationProtocol = deviceCode`. Microsoft's hunting query looks for error `50199` (a confirmation prompt) followed by success in the same session, the pause while a user types a code.

| TTP | In the logs | Table.field | Detection | Playbook |
|---|---|---|---|---|
| Lure by email, link | `devicelogin`/`deviceauth` URL in a message | `EmailUrlInfo.Url`, `EmailEvents` | [DC-12](../detections/device-code/DC-12-device-code-lure-delivery.kql) | [5.9](devicecode-playbook.md#59-lure-delivery) |
| Lure by QR code | URL extracted from a QR image | `EmailUrlInfo.UrlLocation == "QRCode"` | [DC-12](../detections/device-code/DC-12-device-code-lure-delivery.kql) | [5.9](devicecode-playbook.md#59-lure-delivery) |
| Lure by Teams chat | URL in an external Teams message | `MessageUrlInfo.Url`, `MessageEvents.IsExternalThread` | [DC-12](../detections/device-code/DC-12-device-code-lure-delivery.kql) | [5.9](devicecode-playbook.md#59-lure-delivery) |
| Lure clicked | Safe Links click on the URL | `UrlClickEvents.Url`, `UrlChain` | [DC-12](../detections/device-code/DC-12-device-code-lure-delivery.kql) | [5.9](devicecode-playbook.md#59-lure-delivery) |
| Fake meeting or document lure (no URL to match) | Subject/sender patterns only | `EmailEvents.Subject` | [DC-12](../detections/device-code/DC-12-device-code-lure-delivery.kql) (weak) | [5.9](devicecode-playbook.md#59-lure-delivery) |
| Lure by WhatsApp, Signal, SMS, phone | Nothing | — | **Gap** — ask the user | [3.2](devicecode-playbook.md#32-decision-tree) |
| Code entered | Interactive sign-in, device code protocol | `SigninLogs.AuthenticationProtocol`, `OriginalTransferMethod` | [DC-01](../detections/device-code/DC-01-device-code-sign-in.kql) | [5.1](devicecode-playbook.md#51-device-code-sign-in) |
| Code entry pause | `50199` then `0` in one session | `SigninLogs.ResultType`, `SessionId` | [DC-01](../detections/device-code/DC-01-device-code-sign-in.kql) | [5.1](devicecode-playbook.md#51-device-code-sign-in) |
| User never uses device code / not approved | First device code sign-in in the baseline, or not in the approved group | `SigninLogs` + watchlist | [DC-03](../detections/device-code/DC-03-device-code-first-time-or-unapproved.kql) | [5.2](devicecode-playbook.md#52-new-location-or-agent) |
| Code generated by the attacker | Happens outside your tenant | — | **Gap** — not logged | — |

## 2. Abused client IDs

**ATT&CK:** T1528, T1550.001 Use Alternate Authentication Material: Application Access Token.

- Attackers pick public, pre-consented Microsoft clients from the [lookup](#client-id-lookup). Office and Azure CLI are kit defaults; the Authentication Broker is chosen when the goal is a device and a PRT.
- Some campaigns use a multi-tenant app the attacker registered. It needs consent, and its owner tenant is not Microsoft's.

| TTP | In the logs | Table.field | Detection | Playbook |
|---|---|---|---|---|
| Kit-default public client | `AppId` in the abused list | `SigninLogs.AppId` | [DC-01](../detections/device-code/DC-01-device-code-sign-in.kql) | [5.1](devicecode-playbook.md#51-device-code-sign-in) |
| Authentication Broker for device registration | Broker `AppId`, resource = Device Registration Service | `SigninLogs.AppId`, `ResourceId` | [DC-05](../detections/device-code/DC-05-device-registered-after-device-code.kql) | [5.4](devicecode-playbook.md#54-device-registration) |
| Attacker's own app | `AppOwnerTenantId` not Microsoft, not yours | `SigninLogs.AppOwnerTenantId` | [DC-01](../detections/device-code/DC-01-device-code-sign-in.kql), [DC-07](../detections/device-code/DC-07-app-consent-after-device-code.kql) | [5.6](devicecode-playbook.md#56-apps-and-consent) |

## 3. Token theft and replay

**ATT&CK:** T1528, T1550.001, T1078.004.

- The attacker receives an access token (about an hour) and a refresh token (90 days by default, survives a password reset). With the Broker client, they can also get a PRT once a device is registered.
- **Replay:** the refresh token is used from the attacker's infrastructure. Those sign-ins are non-interactive, carry the **same `SessionId`**, and keep `OriginalTransferMethod = deviceCodeFlow` (protocol tracking). No MFA prompt appears: the victim already satisfied it.
- **FOCI pivot:** a family refresh token for one client is redeemed for another (Azure CLI → Office → Teams), so one session shows several `AppId`s in quick succession.

| TTP | In the logs | Table.field | Detection | Playbook |
|---|---|---|---|---|
| Refresh from a second IP/ASN | Same `SessionId`, different `IPAddress`/ASN | `AADNonInteractiveUserSignInLogs.SessionId`, `AutonomousSystemNumber` | [DC-08](../detections/device-code/DC-08-device-code-token-replay.kql) | [5.3](devicecode-playbook.md#53-token-replay) |
| Device-code-derived refresh from new IP | `OriginalTransferMethod = deviceCodeFlow`, IP never seen for the user | `AADNonInteractiveUserSignInLogs.OriginalTransferMethod` | [DC-08](../detections/device-code/DC-08-device-code-token-replay.kql) | [5.3](devicecode-playbook.md#53-token-replay) |
| FOCI app-hopping | ≥3 distinct `AppId`s in one device code session | `AADNonInteractiveUserSignInLogs.AppId`, `SessionId` | [DC-08](../detections/device-code/DC-08-device-code-token-replay.kql) | [5.3](devicecode-playbook.md#53-token-replay) |
| No MFA on token use | `AuthenticationRequirement = singleFactorAuthentication` on replay | `AADNonInteractiveUserSignInLogs.AuthenticationRequirement` | [DC-08](../detections/device-code/DC-08-device-code-token-replay.kql) (column) | [5.3](devicecode-playbook.md#53-token-replay) |
| PRT use from the attacker's device | Sign-ins with `IncomingTokenType = primaryRefreshToken` from the new device | `SigninLogs.DeviceDetail`, `IncomingTokenType` | [DC-16](../queries/devicecode-timeline.kql) phase `6-Device sign-in` | [5.13](devicecode-playbook.md#513-timeline) |

## 4. Post-compromise persistence

**ATT&CK:** T1098.005 Account Manipulation: Device Registration, T1556.006 Modify Authentication Process: Multi-Factor Authentication, T1098.001 Additional Cloud Credentials, T1671 Cloud Application Integration, T1136.003 Create Account: Cloud Account, T1564.008 Email Hiding Rules, T1114.003 Email Forwarding Rule.

- **Device registration or Entra join** with the Broker client, giving the attacker a PRT that survives session revocation and can satisfy "compliant or joined device" policies (Storm-2372).
- **New authentication method** (Authenticator, phone, FIDO2, TAP, Windows Hello) so the attacker can sign in again on their own.
- **New app, consent, or secret** on a service principal.
- **Mailbox rules, forwarding, delegates** to hide replies and keep reading mail.

| TTP | In the logs | Table.field | Detection | Playbook |
|---|---|---|---|---|
| Device registered or joined | `Add device`, `Register device`, `Add registered owner/users to device`, often logged by Device Registration Service | `AuditLogs.OperationName`, `TargetResources` | [DC-05](../detections/device-code/DC-05-device-registered-after-device-code.kql) | [5.4](devicecode-playbook.md#54-device-registration) |
| Device compliance manipulation | Intune compliance changes | `IntuneAuditLogs` (not in scope) | **Gap** — needs the Intune connector | [8](devicecode-playbook.md#8-hardening) |
| Authentication method added | `User registered security info`, `Admin registered security info`, passkey/WHfB adds | `AuditLogs.OperationName` | [DC-06](../detections/device-code/DC-06-auth-method-after-device-code.kql) | [5.5](devicecode-playbook.md#55-authentication-methods) |
| Consent, app role, SP credential | `Consent to application`, `Add app role assignment…`, `Add service principal credentials` | `AuditLogs.OperationName` | [DC-07](../detections/device-code/DC-07-app-consent-after-device-code.kql) | [5.6](devicecode-playbook.md#56-apps-and-consent) |
| New cloud account (privileged victim) | `Add user` | `AuditLogs.OperationName` | [DC-04](../detections/device-code/DC-04-device-code-then-sensitive-action.kql) | [3.3](devicecode-playbook.md#33-what-happened-next) |
| Inbox rule, forwarding, delegate | `New-InboxRule`, `Set-Mailbox -ForwardingSmtpAddress`, `Add-MailboxPermission` | `OfficeActivity.Operation`, `CloudAppEvents.ActionType` | [DC-09](../detections/device-code/DC-09-mailbox-rule-after-device-code.kql) | [5.7](devicecode-playbook.md#57-mailbox-rules) |

## 5. Discovery and exfiltration

**ATT&CK:** T1087.004 Cloud Account Discovery, T1069.003 Cloud Groups, T1526 Cloud Service Discovery, T1114.002 Remote Email Collection, T1530 Data from Cloud Storage, T1213.002 Sharepoint.

- Graph enumeration of users, groups and apps; mailbox searches for words like *password, admin, credentials, secret, teamviewer, anydesk* (Storm-2372); mass mail reads and file downloads.
- Tooling: GraphRunner, ROADtools/roadtx, TokenTactics, AADInternals. Defaults are easy to change; Python `aiohttp` and `requests`, Go, curl and PowerShell user agents appear when operators don't bother.

| TTP | In the logs | Table.field | Detection | Playbook |
|---|---|---|---|---|
| Graph enumeration | Many `/users`, `/groups`, `/directoryObjects` calls in minutes | `MicrosoftGraphActivityLogs.RequestUri` | [DC-10](../detections/device-code/DC-10-graph-abuse-after-device-code.kql) | [5.8](devicecode-playbook.md#58-graph-files-and-mail) |
| Mail search | `$search` or `/search/query` calls | `MicrosoftGraphActivityLogs.RequestUri` | [DC-10](../detections/device-code/DC-10-graph-abuse-after-device-code.kql) | [5.8](devicecode-playbook.md#58-graph-files-and-mail) |
| Tool user agent | python, aiohttp, axios, node-fetch, Go, curl, PowerShell | `MicrosoftGraphActivityLogs.UserAgent`, sign-in `UserAgent` | [DC-10](../detections/device-code/DC-10-graph-abuse-after-device-code.kql), [DC-08](../detections/device-code/DC-08-device-code-token-replay.kql) | [5.8](devicecode-playbook.md#58-graph-files-and-mail) |
| Mass file download | `FileDownloaded`, `FileSyncDownloadedFull` volume | `OfficeActivity.Operation`, `CloudAppEvents.ActionType` | [DC-11](../detections/device-code/DC-11-bulk-access-after-device-code.kql) | [5.8](devicecode-playbook.md#58-graph-files-and-mail) |
| Mass mail access | `MailItemsAccessed` volume from a new IP | `OfficeActivity.Operation` | [DC-11](../detections/device-code/DC-11-bulk-access-after-device-code.kql) | [5.8](devicecode-playbook.md#58-graph-files-and-mail) |

## 6. Lateral movement and fraud

**ATT&CK:** T1534 Internal Spearphishing, T1657 Financial Theft.

- More device code lures sent from the victim's mailbox to colleagues (Storm-2372).
- Password reset attempts, payment and bank-detail change requests (BEC).

| TTP | In the logs | Table.field | Detection | Playbook |
|---|---|---|---|---|
| Internal lures from the victim | Intra-org mail from the victim with `devicelogin` links | `EmailEvents.EmailDirection`, `EmailUrlInfo.Url` | [DC-12](../detections/device-code/DC-12-device-code-lure-delivery.kql) | [5.9](devicecode-playbook.md#59-lure-delivery) |
| Self-service password reset after compromise | `Reset password (self-service)` and similar | `AuditLogs.OperationName` | [DC-04](../detections/device-code/DC-04-device-code-then-sensitive-action.kql) | [3.3](devicecode-playbook.md#33-what-happened-next) |
| Payment fraud | Mail content | — | **Gap** — see the [BEC playbook](bec-playbook.md) | [9](devicecode-playbook.md#9-communications-and-escalation) |

## 7. Infrastructure indicators

**ATT&CK:** T1090.003 Multi-hop Proxy, T1583.003 Virtual Private Server.

- Hosting, VPN and residential proxy ASNs; proxies chosen near the target's country (Storm-2372); PaaS infrastructure such as Railway (Huntress, secondary).
- The same IP or ASN across several users in a short time is a campaign.

| TTP | In the logs | Table.field | Detection | Playbook |
|---|---|---|---|---|
| New IP, ASN, country or agent for the user | Not seen for this user in the baseline | `SigninLogs.IPAddress`, `AutonomousSystemNumber`, `LocationDetails`, `UserAgent`; `BehaviorAnalytics.ActivityInsights` | [DC-02](../detections/device-code/DC-02-device-code-new-location-or-agent.kql) | [5.2](devicecode-playbook.md#52-new-location-or-agent) |
| Impossible travel, anonymous IP, threat intel | Identity Protection detections | `AADUserRiskEvents.RiskEventType` | [DC-13](../detections/device-code/DC-13-risk-on-device-code-user.kql) | [5.10](devicecode-playbook.md#510-risk-detections) |
| Campaign infrastructure | One IP/ASN, many users, device code | `SigninLogs.IPAddress`, `AutonomousSystemNumber` | [DC-15](../detections/device-code/DC-15-device-code-campaign.kql) | [5.12](devicecode-playbook.md#512-campaign-scope) |
| Session/IP mismatch between code entry and token use | Different ASN, same session | `SessionId`, `AutonomousSystemNumber` | [DC-08](../detections/device-code/DC-08-device-code-token-replay.kql) | [5.3](devicecode-playbook.md#53-token-replay) |
| Device code allowed by policy | Sign-in succeeded; no CA block | `SigninLogs.ConditionalAccessPolicies` | [DC-14a](../detections/device-code/DC-14a-device-code-not-blocked.kql), [DC-14b](../detections/device-code/DC-14b-device-code-ca-posture.kql) | [5.11](devicecode-playbook.md#511-conditional-access-gap) |

## Gaps

| Gap | Why | Mitigation |
|---|---|---|
| Lures over WhatsApp, Signal, SMS or phone | Outside Microsoft 365 | User interview; awareness |
| Code generation | Happens at Microsoft's endpoint before any sign-in | Block device code flow |
| Device compliance manipulation | Needs Intune logs, not in the required list | Add the Intune connector (`IntuneAuditLogs`, `IntuneDevices`) |
| Payment fraud | Content, not telemetry | BEC playbook, finance controls |
| Tools that spoof browser user agents | UA is attacker-controlled | Rely on session and IP signals (DC-08), not UA |
| Device code in Defender Advanced Hunting | `EntraIdSignInEvents` has no protocol column | Use Sentinel tables; Defender variants use the `50199` pattern |
