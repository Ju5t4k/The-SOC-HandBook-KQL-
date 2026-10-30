# Device code phishing — coverage

What the device code detections cover, by ATT&CK technique and by data source, and what they cannot see. The technique-to-log detail behind each row is in [`devicecode-ttps.md`](devicecode-ttps.md); the detection index is in [`detections/device-code/README.md`](../detections/device-code/README.md); the investigation steps are in the [playbook](devicecode-playbook.md).

Coverage here means a query exists that looks for the behaviour. It does not mean the query has been run against a live tenant. Nothing in this set has been yet.

**Key.** **Covered**: a scheduled rule fires on the behaviour itself. **Partial**: a rule sees part of it, or only through a correlated signal, or only with optional data. **Hunt**: a hunting query or the timeline shows it, but nothing alerts. **Gap**: not visible in the logs this set uses.

## By technique

| Tactic | Technique | Sentinel | Defender XDR | Playbook | Coverage | Notes |
|---|---|---|---|---|---|---|
| Initial access | T1566.002 Spearphishing Link | DC-12, DC-01, DC-15 | DC-12, DC-01, DC-15 | [5.9](devicecode-playbook.md#59-lure-delivery), [5.1](devicecode-playbook.md#51-device-code-sign-in) | Covered | Mail links and QR codes by URL; lures that use a redirector or a fake meeting page without `devicelogin` in the URL are only caught at the sign-in |
| Initial access | T1566.003 Spearphishing via Service | DC-12 | DC-12 | [5.9](devicecode-playbook.md#59-lure-delivery) | Partial | Teams only. WhatsApp, Signal, SMS and phone lures are outside Microsoft 365 |
| Initial access, persistence | T1078.004 Valid Accounts: Cloud Accounts | DC-01, DC-02, DC-03, DC-13, DC-14a, DC-15, DC-08 | DC-01, DC-08, DC-15 | [5.1](devicecode-playbook.md#51-device-code-sign-in), [5.2](devicecode-playbook.md#52-new-location-or-agent) | Covered | DC-02 and DC-03 need 14 days of history in the workspace |
| Credential access | T1528 Steal Application Access Token | DC-01, DC-02, DC-03, DC-07, DC-08, DC-14a | DC-01, DC-07, DC-08 | [5.1](devicecode-playbook.md#51-device-code-sign-in), [5.3](devicecode-playbook.md#53-token-replay) | Covered | Defender variants infer device code from `50199` then success; failed attempts are not seen |
| Defence evasion, lateral movement | T1550.001 Application Access Token | DC-08 | DC-08 | [5.3](devicecode-playbook.md#53-token-replay) | Covered | Defender variant compares IP and country only (no ASN column) |
| Persistence | T1098.005 Device Registration | DC-05, DC-04, DC-06 | DC-05 | [5.4](devicecode-playbook.md#54-device-registration) | Covered | Intune compliance changes after registration are a gap (no Intune logs in scope) |
| Persistence | T1098.001 Additional Cloud Credentials | DC-07, DC-04 | DC-07 | [5.6](devicecode-playbook.md#56-apps-and-consent) | Covered | |
| Persistence, credential access | T1556.006 Multi-Factor Authentication | DC-06, DC-04 | — | [5.5](devicecode-playbook.md#55-authentication-methods) | Covered | No Defender variant: Advanced Hunting has no `AuditLogs` equivalent with the method detail |
| Defence evasion | T1556.009 Conditional Access Policies | DC-14b | — | [5.11](devicecode-playbook.md#511-conditional-access-gap) | Hunt | Posture check, not an alert. Policy changes by the attacker are in DC-04's sensitive operations |
| Persistence | T1136.003 Cloud Account | DC-04 | — | [3.3](devicecode-playbook.md#33-what-happened-next) | Covered | Only matters when the victim can create users |
| Persistence | T1671 Cloud Application Integration | DC-07 | DC-07 | [5.6](devicecode-playbook.md#56-apps-and-consent) | Covered | An app consented *before* the code is in the timeline (DC-16) and `devicecode-persistence.kql`, not a rule |
| Collection | T1114.003 Email Forwarding Rule | DC-09, DC-04 | DC-09 | [5.7](devicecode-playbook.md#57-mailbox-rules) | Covered | Tenant-wide transport rules: see the [BEC playbook](bec-playbook.md) |
| Defence evasion | T1564.008 Email Hiding Rules | DC-09 | DC-09 | [5.7](devicecode-playbook.md#57-mailbox-rules) | Covered | |
| Collection | T1114.002 Remote Email Collection | DC-10, DC-11 | DC-11 | [5.8](devicecode-playbook.md#58-graph-files-and-mail) | Partial | DC-10 needs the Graph activity diagnostic setting; DC-11 needs `MailItemsAccessed` auditing. Thresholds are guesses |
| Discovery | T1087.004 Cloud Account Discovery | DC-10 | — | [5.8](devicecode-playbook.md#58-graph-files-and-mail) | Partial | Only with Graph activity logs. Enumeration through other APIs is not seen |
| Discovery | T1069.003 Cloud Groups | DC-10 | — | [5.8](devicecode-playbook.md#58-graph-files-and-mail) | Partial | As above |
| Discovery | T1526 Cloud Service Discovery | DC-10 | — | [5.8](devicecode-playbook.md#58-graph-files-and-mail) | Partial | As above |
| Collection | T1530 Data from Cloud Storage | DC-11 | DC-11 | [5.8](devicecode-playbook.md#58-graph-files-and-mail) | Covered | Volume-based; a patient attacker stays under the threshold |
| Collection | T1213.002 SharePoint | DC-11 | DC-11 | [5.8](devicecode-playbook.md#58-graph-files-and-mail) | Covered | As above |
| Lateral movement | T1534 Internal Spearphishing | DC-12 | DC-12 | [5.9](devicecode-playbook.md#59-lure-delivery) | Covered | Intra-org mail and Teams with a device code URL |
| Command and control | T1090.003 Multi-hop Proxy | DC-15 | DC-15 | [5.12](devicecode-playbook.md#512-campaign-scope) | Partial | Clusters many users on one IP or ASN; does not identify proxies or VPS ranges as such |
| Impact | T1657 Financial Theft | — | — | [9](devicecode-playbook.md#9-communications-and-escalation) | Gap | Content, not telemetry. Hand over to the BEC playbook |
| — | Code generation by the attacker | — | — | — | Gap | Happens at Microsoft's endpoint before any sign-in; nothing in the tenant's logs |
| — | PRT use from the attacker's device | DC-16 phase 6 | — | [5.13](devicecode-playbook.md#513-timeline) | Hunt | Sign-ins with `IncomingTokenType` = `primaryRefreshToken` from the new device. No rule; DC-05 alerts on the registration that makes it possible |

## By data source

What each detection reads. If a source is missing, every detection with a dot in its column is blind or partly blind. None of them errors on an empty table, so check ingestion, not alert volume.

| Detection | Sign-in | Non-interactive | Audit | Risk | Graph activity | Office | Cloud apps | Mail and clicks | Teams messages |
|---|---|---|---|---|---|---|---|---|---|
| DC-01 | ● |  |  |  |  |  |  |  |  |
| DC-02 | ● | ● |  |  |  |  |  |  |  |
| DC-03 | ● |  |  |  |  |  |  |  |  |
| DC-04 | ● |  | ● |  |  | ● |  |  |  |
| DC-05 | ● | ● | ● |  |  |  |  |  |  |
| DC-06 | ● |  | ● |  |  |  |  |  |  |
| DC-07 | ● |  | ● |  |  |  |  |  |  |
| DC-08 | ● | ● |  |  |  |  |  |  |  |
| DC-09 | ● |  |  |  |  | ● | ● |  |  |
| DC-10 | ● |  |  |  | ● |  |  |  |  |
| DC-11 | ● |  |  |  |  | ● | ● |  |  |
| DC-12 |  |  |  |  |  |  |  | ● | ● |
| DC-13 | ● |  |  | ● |  |  |  |  |  |
| DC-14a | ● |  |  |  |  |  |  |  |  |
| DC-14b |  |  | ● |  |  |  |  |  |  |
| DC-15 | ● |  |  |  |  |  |  |  |  |

"Mail and clicks" is `EmailEvents`, `EmailUrlInfo` and `UrlClickEvents`. "Risk" includes `AADRiskyUsers`. DC-09 and DC-11 read both `OfficeActivity` and `CloudAppEvents`, so either source alone is enough. DC-09 de-duplicates the two; DC-11 counts each separately and keeps the higher count, so the thresholds hold with both on.

Optional sources: UEBA (`BehaviorAnalytics`, `IdentityInfo`) adds context to DC-02 and DC-03; both run without it.

### Single points of failure

| Missing | Effect |
|---|---|
| `SigninLogs` | Everything except DC-12 and DC-14b goes blind. Nothing else can identify a device code sign-in |
| `AADNonInteractiveUserSignInLogs` | No token replay (DC-08), no Device Registration Service token in DC-05, a weaker baseline in DC-02. This is where most of the attacker's activity lands |
| Graph activity diagnostic setting | No DC-10. Not on by default and does not back-fill; turn it on before an incident |
| Defender for Office 365 P2 | No lure detection (DC-12) and no click correlation in the DC-01 Defender variant |
| Entra ID P2 | No DC-13 and no Defender variants (`EntraIdSignInEvents`) |

## Gaps

| Gap | Why | What to do instead |
|---|---|---|
| Lures over WhatsApp, Signal, SMS or phone | Outside Microsoft 365 | Ask the user how the code reached them ([3.2](devicecode-playbook.md#32-decision-tree)); awareness training |
| Code generation | At Microsoft's endpoint, before any sign-in | Block device code flow with Conditional Access ([8](devicecode-playbook.md#8-hardening)) |
| Device compliance manipulation after registration | Needs Intune logs (`IntuneAuditLogs`, `IntuneDevices`), not in scope | Add the Intune connector; review the device in Intune during [7](devicecode-playbook.md#7-eradication-and-recovery) |
| Payment fraud | Mail content, not telemetry | [BEC playbook](bec-playbook.md); finance call-back controls |
| Tools that spoof a browser user agent | The agent string is attacker-controlled | Rely on session and network signals (DC-08), not the agent |
| Device code in Advanced Hunting | `EntraIdSignInEvents` has no protocol column | Use the Sentinel rules; Defender variants infer from `50199` |
| Failed or abandoned code entries in Advanced Hunting | The `50199` inference needs a success | Sentinel `SigninLogs` with `AuthenticationProtocol` |
| Low-and-slow collection | Volume thresholds in DC-10 and DC-11 | Run DC-16 over the whole post-pivot window for any confirmed victim |
