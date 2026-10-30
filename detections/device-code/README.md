# Device code phishing detections

Sixteen Sentinel detections for OAuth device code phishing, plus eight Defender XDR Advanced Hunting variants. Each one links to the playbook step that investigates its alert.

- Playbook: [`docs/devicecode-playbook.md`](../../docs/devicecode-playbook.md)
- What the attack looks like in the logs: [`docs/devicecode-ttps.md`](../../docs/devicecode-ttps.md)
- Coverage by ATT&CK technique, with gaps: [`docs/devicecode-coverage.md`](../../docs/devicecode-coverage.md)
- File convention and the checker: [`../README.md`](../README.md)

None of these has been run against a live workspace. Treat every threshold as a starting point and tune it on your own data before you turn on alerting (see [Before you enable](#before-you-enable)).

## Index

Schedule is query frequency / query period. Tables are the Sentinel tables named in `requiredDataConnectors`.

| ID | Detection | Type | Severity | Schedule | Tables | Tactics | Defender variant | Playbook |
|---|---|---|---|---|---|---|---|---|
| DC-01 | [Device code sign-in](DC-01-device-code-sign-in.kql) · [yaml](DC-01-device-code-sign-in.yaml) | Rule | Low | 1h / 2h | `SigninLogs` | InitialAccess, CredentialAccess | [Yes](DC-01-device-code-sign-in.defender.kql) | [5.1](../../docs/devicecode-playbook.md#51-device-code-sign-in) |
| DC-02 | [Device code sign-in from new IP, ASN, country or agent](DC-02-device-code-new-location-or-agent.kql) · [yaml](DC-02-device-code-new-location-or-agent.yaml) | Rule | Medium | 1h / 14d | `AADNonInteractiveUserSignInLogs`, `SigninLogs` | InitialAccess, CredentialAccess | — | [5.2](../../docs/devicecode-playbook.md#52-new-location-or-agent) |
| DC-03 | [Device code sign-in by first-time or unapproved user](DC-03-device-code-first-time-or-unapproved.kql) · [yaml](DC-03-device-code-first-time-or-unapproved.yaml) | Rule | Medium | 1h / 14d | `SigninLogs` | InitialAccess, CredentialAccess | — | [5.2](../../docs/devicecode-playbook.md#52-new-location-or-agent) |
| DC-04 | [Device code sign-in followed by sensitive action](DC-04-device-code-then-sensitive-action.kql) · [yaml](DC-04-device-code-then-sensitive-action.yaml) | Rule | High | 1h / 2h | `AuditLogs`, `OfficeActivity`, `SigninLogs` | Persistence, PrivilegeEscalation, DefenseEvasion, Collection | — | [3.3](../../docs/devicecode-playbook.md#33-what-happened-next) |
| DC-05 | [Device registered after device code sign-in](DC-05-device-registered-after-device-code.kql) · [yaml](DC-05-device-registered-after-device-code.yaml) | Rule | High | 1h / 2d | `AADNonInteractiveUserSignInLogs`, `AuditLogs`, `SigninLogs` | Persistence, PrivilegeEscalation | [Yes](DC-05-device-registered-after-device-code.defender.kql) | [5.4](../../docs/devicecode-playbook.md#54-device-registration) |
| DC-06 | [Authentication method changed after device code sign-in](DC-06-auth-method-after-device-code.kql) · [yaml](DC-06-auth-method-after-device-code.yaml) | Rule | High | 1h / 2d | `AuditLogs`, `SigninLogs` | Persistence, CredentialAccess, DefenseEvasion | — | [5.5](../../docs/devicecode-playbook.md#55-authentication-methods) |
| DC-07 | [App consent or credential after device code sign-in](DC-07-app-consent-after-device-code.kql) · [yaml](DC-07-app-consent-after-device-code.yaml) | Rule | High | 1h / 2d | `AuditLogs`, `SigninLogs` | Persistence, CredentialAccess | [Yes](DC-07-app-consent-after-device-code.defender.kql) | [5.6](../../docs/devicecode-playbook.md#56-apps-and-consent) |
| DC-08 | [Token replay from a device code session](DC-08-device-code-token-replay.kql) · [yaml](DC-08-device-code-token-replay.yaml) | Rule | High | 1h / 2d | `AADNonInteractiveUserSignInLogs`, `SigninLogs` | CredentialAccess, DefenseEvasion, LateralMovement | [Yes](DC-08-device-code-token-replay.defender.kql) | [5.3](../../docs/devicecode-playbook.md#53-token-replay) |
| DC-09 | [Mailbox rule or forwarding after device code sign-in](DC-09-mailbox-rule-after-device-code.kql) · [yaml](DC-09-mailbox-rule-after-device-code.yaml) | Rule | High | 1h / 2d | `CloudAppEvents`, `OfficeActivity`, `SigninLogs` | Collection, DefenseEvasion | [Yes](DC-09-mailbox-rule-after-device-code.defender.kql) | [5.7](../../docs/devicecode-playbook.md#57-mailbox-rules) |
| DC-10 | [Graph API abuse after device code sign-in](DC-10-graph-abuse-after-device-code.kql) · [yaml](DC-10-graph-abuse-after-device-code.yaml) | Rule | Medium | 1h / 2d | `MicrosoftGraphActivityLogs`, `SigninLogs` | Discovery, Collection | — | [5.8](../../docs/devicecode-playbook.md#58-graph-files-and-mail) |
| DC-11 | [Mass download or mail access after device code sign-in](DC-11-bulk-access-after-device-code.kql) · [yaml](DC-11-bulk-access-after-device-code.yaml) | Rule | Medium | 1h / 2d | `CloudAppEvents`, `OfficeActivity`, `SigninLogs` | Collection | [Yes](DC-11-bulk-access-after-device-code.defender.kql) | [5.8](../../docs/devicecode-playbook.md#58-graph-files-and-mail) |
| DC-12 | [Device code lure delivered or clicked](DC-12-device-code-lure-delivery.kql) · [yaml](DC-12-device-code-lure-delivery.yaml) | Rule | Medium | 1h / 1h | `EmailEvents`, `EmailUrlInfo`, `MessageEvents`, `MessageUrlInfo`, `UrlClickEvents` | InitialAccess, LateralMovement | [Yes](DC-12-device-code-lure-delivery.defender.kql) | [5.9](../../docs/devicecode-playbook.md#59-lure-delivery) |
| DC-13 | [Identity Protection risk on a device code user](DC-13-risk-on-device-code-user.kql) · [yaml](DC-13-risk-on-device-code-user.yaml) | Rule | Medium | 1h / 2d | `AADRiskyUsers`, `AADUserRiskEvents`, `SigninLogs` | InitialAccess | — | [5.10](../../docs/devicecode-playbook.md#510-risk-detections) |
| DC-14a | [Device code sign-in not blocked by Conditional Access](DC-14a-device-code-not-blocked.kql) · [yaml](DC-14a-device-code-not-blocked.yaml) | Rule | Low | 1d / 1d | `SigninLogs` | DefenseEvasion, InitialAccess, CredentialAccess | — | [5.11](../../docs/devicecode-playbook.md#511-conditional-access-gap) |
| DC-14b | [Conditional Access posture for device code flow](DC-14b-device-code-ca-posture.kql) · [yaml](DC-14b-device-code-ca-posture.yaml) | Hunting | — | — | `AuditLogs` | DefenseEvasion | — | [5.11](../../docs/devicecode-playbook.md#511-conditional-access-gap) |
| DC-15 | [Device code campaign from one IP or ASN](DC-15-device-code-campaign.kql) · [yaml](DC-15-device-code-campaign.yaml) | Rule | High | 1h / 1d | `SigninLogs` | InitialAccess, CommandAndControl | [Yes](DC-15-device-code-campaign.defender.kql) | [5.12](../../docs/devicecode-playbook.md#512-campaign-scope) |
| DC-16 | [Device code timeline](../../queries/devicecode-timeline.kql) | Investigation query | — | Manual | Sign-in, audit, Office, mail, Teams, Graph and risk tables | All | — | [5.13](../../docs/devicecode-playbook.md#513-timeline) |

DC-16 lives in `queries/` with the other investigation queries. It takes a user, an IP or both and a pivot time, so it does not run on a schedule.

## How they fit together

| Stage | Detections | Signal |
|---|---|---|
| Lure arrives | DC-12 | A `devicelogin` or `deviceauth` URL in mail, a QR code or Teams, or a click on one |
| Code entered | DC-01, DC-02, DC-03 | Any device code sign-in, then what is new or unapproved about it |
| Policy let it through | DC-14a, DC-14b | No Conditional Access block on the sign-in; the tenant's policy posture |
| Token used | DC-08, DC-13, DC-15 | Replay from another network, FOCI app-hopping, risk detections, one source hitting many users |
| Foothold | DC-04, DC-05, DC-06, DC-07 | Device registered (PRT path), MFA method added, app consented, other sensitive changes |
| Collection | DC-09, DC-10, DC-11 | Mailbox rules, Graph enumeration and mail search, bulk file or mail access |

DC-01 is deliberately broad and Low. The follow-on rules (DC-04 to DC-11) are High or Medium because they need a device code sign-in *and* a suspicious action by the same user. When DC-01 is too noisy, keep it as a hunting query and rely on the follow-on rules.

## Before you enable

1. **Run DC-14b** (hunting) to see whether any Conditional Access policy already blocks device code flow, and who is excluded.
2. **Run DC-01 over 14 days** as a query and list who uses device code legitimately: Teams Rooms resource accounts, Azure CLI or Graph PowerShell users, kiosk or shared devices.
3. **Create the `DeviceCodeAllowedUsers` watchlist** with those UPNs as `SearchKey`. In DC-01, DC-03 and DC-14a, swap the `dynamic([])` line for the `_GetWatchlist` line in the comment above it.
4. **Fill the egress lists.** Set `KnownEgressIPs` and `KnownEgressAsns` in DC-02, DC-08 and DC-15 to your offices, VPN and proxy, so a roaming user on the corporate network does not look new.
5. **Set `ExcludedSenders`** in DC-12 to whoever sends legitimate device code instructions (IT, the Teams Rooms vendor).
6. **Check the data** for each rule against the table below. A rule whose table is empty is not covering anything, and it will not error.

## Data needed

| Table | How it gets to Sentinel | Licence | Used by |
|---|---|---|---|
| `SigninLogs`, `AADNonInteractiveUserSignInLogs` | Microsoft Entra ID connector, sign-in and non-interactive sign-in logs ticked | Entra ID P1 or P2 for export | All but DC-12 and DC-14b |
| `AuditLogs` | Microsoft Entra ID connector, audit logs | Any | DC-04 to DC-07, DC-14b |
| `AADUserRiskEvents`, `AADRiskyUsers` | Microsoft Entra ID connector, risk logs | Entra ID P2 | DC-13 |
| `MicrosoftGraphActivityLogs` | Entra diagnostic setting, `MicrosoftGraphActivityLogs` category, to the workspace | Entra ID P1 or P2 (VERIFY for your tenant); not on by default, no back-fill | DC-10 |
| `OfficeActivity` | Microsoft 365 connector (Exchange, SharePoint) | Unified audit log on; `MailItemsAccessed` needs audit for the mailbox | DC-04, DC-09, DC-11 |
| `CloudAppEvents` | Defender XDR connector | Defender for Cloud Apps with the Microsoft 365 app connector | DC-09, DC-11 |
| `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents` | Defender XDR connector | Defender for Office 365 P2 (`UrlClickEvents` needs Safe Links) | DC-12 |
| `MessageEvents`, `MessageUrlInfo` | Defender XDR connector | Defender for Office 365 P2 with Teams protection | DC-12 |
| `IdentityInfo`, `BehaviorAnalytics` | UEBA | Optional | DC-02, DC-03 (both run without it) |
| `EntraIdSignInEvents` | Advanced Hunting only | Entra ID P2 | Every `.defender.kql` |

## Defender XDR variants

`EntraIdSignInEvents` has no `AuthenticationProtocol` or `OriginalTransferMethod` column, so Advanced Hunting cannot see device code directly. The `.defender.kql` files infer it the way Microsoft's Storm-2372 hunting query does: error `50199` (the "are you trying to sign in" prompt) followed by a success in the same `SessionId` within 15 minutes. This misses failed attempts and any device code sign-in without that prompt. Use the Sentinel rules where you have them.

To make a variant a custom detection rule, keep `Timestamp` and `ReportId` in the output (they all do) and map the entities in the rule wizard.

## Changing a detection

Edit the `.kql`, then run `python3 tools/check_rules.py --sync` to copy the query body into the YAML, and `python3 tools/check_rules.py` and `python3 tools/lint_kql.py queries detections` to check. Bump `version` in the YAML. CI runs the same checks.
