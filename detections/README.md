# Detections

Scheduled analytics rules and hunting queries for Microsoft Sentinel, grouped by threat. Each detection belongs to a playbook in [`../docs`](../docs) and links back to the step that investigates it.

| Folder | Threat | Playbook |
|---|---|---|
| [`device-code/`](device-code/README.md) | Device code phishing | [`devicecode-playbook.md`](../docs/devicecode-playbook.md) |

The investigation queries in [`../queries`](../queries/README.md) are different. They take an account, address or device and answer questions about it. Detections run on a schedule and raise alerts.

## Files

Each detection is two or three files with the same name:

| File | What |
|---|---|
| `DC-NN-<slug>.kql` | **The source.** A header comment, then the query |
| `DC-NN-<slug>.yaml` | Sentinel metadata in the [Azure-Sentinel template format](https://learn.microsoft.com/azure/sentinel/isv/sentinel-analytic-rules-creation), with the same query body inline |
| `DC-NN-<slug>.defender.kql` | Optional Defender XDR Advanced Hunting variant (`Timestamp`, Defender table names). Header only, no YAML |

A YAML with `kind: Scheduled` is an analytics rule. A YAML without `kind` is a hunting query and must not carry rule-only fields (`severity`, `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`, `alertDetailsOverride`).

### The header

Every detection `.kql` starts with a comment block. The checker rejects a file missing any of these:

```
//DC-NN Short name
//
// Logic:           what the query looks for, in two or three lines
// Tuning:          the let values to change first, and what each does
// False positives: what fires that isn't an attack, and how to tell
// Data:            tables, the connector or diagnostic setting each needs, and the licence
// Lookback:        rule period and frequency, and a volume or cost caution
// Playbook:        link to the playbook section that investigates this alert
// ATT&CK:          technique IDs
//
```

The query follows the house style: every value to change is a `let` at the top, filters run early, and only needed columns are projected.

## Editing a detection

1. Edit the `.kql`.
2. Run `python3 tools/check_rules.py --sync`. This copies the query body into the YAML `query: |` block and then checks everything.
3. Bump `version` in the YAML (`a.b.c`).
4. Run `python3 tools/lint_kql.py queries detections`.

CI runs both checks on every pull request.

## What the checker enforces

`tools/check_rules.py`:

- the `.kql` header has every field, and every `.kql` has a `.yaml` (except `.defender.kql`);
- the YAML query is identical to the `.kql` body;
- `id` is a GUID, unique across the folder;
- `name` ≤ 100 characters, `description` ≤ 255;
- `tactics` are Sentinel tactic names, `relevantTechniques` look like `T1234` or `T1234.001`;
- every `dataTypes` entry appears in the query;
- rules only: `queryPeriod` ≤ 14d and ≥ `queryFrequency`; 1–10 entity mappings with 1–3 fields each; ≤ 20 custom details with keys ≤ 20 characters; ≤ 3 placeholders in each alert-override format; every mapped column, custom detail column and placeholder appears in the query;
- `version` is `a.b.c`.

It does not run the query. Nothing in this folder has been executed against a workspace; see each playbook's Limits section.

## Deploying

Import a YAML through the Sentinel content hub ("Import" in Analytics), with the [Sentinel repositories](https://learn.microsoft.com/azure/sentinel/ci-cd) feature, or convert it to an ARM template with your existing pipeline. Before enabling a rule:

1. Run the `.kql` over 14 days in Logs and read what it returns.
2. Fill in its allowlists (`let` values or the watchlists named in the header).
3. Enable it, then review the first week of alerts against the playbook's false-positive table.

## Connector IDs used

| `connectorId` | Data types |
|---|---|
| `AzureActiveDirectory` | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`, `AADRiskyUsers`, `AADUserRiskEvents`, `MicrosoftGraphActivityLogs` |
| `Office365` | `OfficeActivity` |
| `MicrosoftThreatProtection` | `CloudAppEvents`, `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`, `MessageEvents`, `MessageUrlInfo` |
| `BehaviorAnalytics` | `BehaviorAnalytics`, `IdentityInfo` |

`MicrosoftGraphActivityLogs` arrives through an Entra ID diagnostic setting, not a connector page. Confirm the `connectorId` your deployment tooling expects for it.
