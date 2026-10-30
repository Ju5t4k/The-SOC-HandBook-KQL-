# Device code phishing — review of the previous playbook

Review of `docs/devicecode-playbook.md` and `queries/devicecode*.kql` as of commit `dab8562`, written before the rebuild on branch `rebuild/device-code-playbook`.

## What was there

| File | Role |
|---|---|
| `docs/devicecode-playbook.md` | Seven-step playbook: confirm, reconstruct, before the code, what the token did, footholds, persistence, scope |
| `queries/devicecode.kql` | Triage: scores every device code sign-in on 13 indicators |
| `queries/devicecode-timeline.kql` | Timeline for one user, 15 phases from set-up to after |
| `queries/devicecode-persistence.kql` | Persistence list, split before and after the pivot |
| `queries/devicecode-scope.kql` | Blast radius by IP, ASN, app, user agent or lure sender |

The investigation queries are sound and are kept. What follows is what the rebuild fixes.

## Wrong

1. **Unsourced client IDs.** The list of abused apps in `devicecode.kql` held seven GUIDs with no names. One (`aebc6443-…`, labelled VS Code elsewhere) can't be confirmed against a public source. The rebuild uses only IDs confirmed by Microsoft Learn, Secureworks' FOCI research or a published detection rule, each with its source ([TTPs — client ID lookup](devicecode-ttps.md#client-id-lookup)).
2. **Defender XDR equivalence assumed.** The README said the queries work in Advanced Hunting by swapping `TimeGenerated` for `Timestamp`. For sign-ins that is false. `EntraIdSignInEvents` (the Advanced Hunting table, which replaced `AADSignInEventsBeta` in October 2026) has no `AuthenticationProtocol` or `OriginalTransferMethod` column, so device code sign-ins can't be filtered directly there. The rebuild gives Defender variants built on what that table does have (error `50199` followed by success in the same session, as in Microsoft's own hunting query) and says where they are weaker.
3. **Baselines too long to deploy.** The triage query baselines over 90 days. Sentinel scheduled rules can look back 14 days at most, so it could never become a rule.

## Weak

1. **Nothing deployable.** No rule files, entity mappings, severities, schedules or custom details. An analyst had to run every query by hand.
2. **Detection and triage mixed.** One scoring query did both jobs. Its 13 weights are judgement, not measured against data, and a single score hides which signal fired.
3. **Persistence listed, not detected.** New MFA methods, consents, devices and mailbox rules were shown in a list, but nothing alerted on them following a device code sign-in.
4. **Containment in prose.** Steps were listed without commands, without who runs them, and without why the order matters.
5. **Protocol tracking unused.** Microsoft records `OriginalTransferMethod = deviceCodeFlow` on later refreshes from a device code session. The old queries matched on session id only, so a session id that changed while the session stayed device-code-derived was missed.

## Missing

| Gap | Fixed by |
|---|---|
| Family-of-client-IDs (FOCI) pivot: one refresh token used across several Microsoft apps | DC-08 |
| Tool user agents (python, aiohttp, axios, node-fetch, Go, curl, PowerShell) | DC-08, DC-10 |
| Identity Protection risk (`AADUserRiskEvents`, `AADRiskyUsers`) | DC-13 |
| UEBA (`BehaviorAnalytics`) first-time country, ISP, app | DC-02 enrichment |
| `CloudAppEvents` as a Defender path for mailbox, file and directory events | DC-05, 06, 07, 09, 11 Defender variants |
| Campaign detection: one IP or ASN across several users | DC-15 |
| Conditional Access gap and posture check | DC-14 |
| Mass download and mail export as detections | DC-11 |
| QR-code lures (`EmailUrlInfo.UrlLocation == "QRCode"`) | DC-12 |
| The `50199` → success pattern Microsoft uses to spot the pause while a code is typed | DC-01, DC-12 |
| Self-service password reset after compromise | DC-04 |
| Prerequisites: licences, connectors, retention, roles | Playbook |
| Triage decision tree with legitimate device code use (Teams Rooms, Xbox, smart TVs, CLI, IoT) | Playbook |
| Eradication checklist, hardening, comms and legal, post-incident templates | Playbook |
| Coverage matrix and a changelog | `docs/devicecode-coverage.md`, `CHANGELOG.md` |

## Kept

- The four investigation queries in `queries/`. They answer questions a rule can't (a full user timeline, a before/after persistence list), and the playbook still uses them. `devicecode-timeline.kql` is upgraded in place to become DC-16.
- The house style: fill-in `let` variables at the top, one leg per `union` line, commented variants at the foot.

## Out of reach in these logs

These stay gaps whatever the queries do, and the playbook says so:

- Lures sent by WhatsApp, Signal, SMS or phone.
- The attacker requesting the code (it happens outside your tenant).
- Payment fraud itself (see the [BEC playbook](bec-playbook.md)).
- Device compliance manipulation, which needs Intune logs (`IntuneAuditLogs`, `IntuneDevices`). Those aren't in the required table list.
