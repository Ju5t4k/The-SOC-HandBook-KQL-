# The SOC Handbook — KQL

[![Hygiene](https://github.com/Ju5t4k/The-SOC-HandBook-KQL-/actions/workflows/hygiene.yml/badge.svg)](https://github.com/Ju5t4k/The-SOC-HandBook-KQL-/actions/workflows/hygiene.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

KQL queries for SOC analysts working in Microsoft Sentinel and Defender XDR.

## Layout

```
queries/      investigation queries — see queries/README.md for the index
detections/   scheduled Sentinel rules and hunting queries, with Defender XDR
              variants — see detections/README.md
docs/         playbooks and reference
tools/        the checks CI runs: KQL lint and detection rule checks
```

See [CHANGELOG.md](CHANGELOG.md) for what changed recently.

### Playbooks

- [ClickFix](docs/clickfix-playbook.md) — fake-CAPTCHA paste-and-run. Eight
  steps from the paste to the reimage decision.
- [Device code phishing](docs/devicecode-playbook.md) — OAuth device code
  token theft, the device-and-PRT variant, and the attacker's own app. A
  15-minute triage, thirteen investigation steps and ordered containment,
  backed by sixteen [detections](detections/device-code/README.md), a
  [TTP reference](docs/devicecode-ttps.md) and a
  [coverage matrix](docs/devicecode-coverage.md).
- [Business email compromise](docs/bec-playbook.md) — mailbox takeover and
  invoice fraud. Seven steps; check tenant-wide transport rules.
- [Malicious attachment](docs/attachment-playbook.md) — the `SHA256` join from
  mail to endpoint. Six steps.
- [Hands-on-keyboard intrusion](docs/hok-playbook.md) — a person operating on
  a device. Twelve steps from "are they still here" to root cause, plus
  collection from the Defender portal without a query.
- [Teams vishing and helpdesk impersonation](docs/teams-vishing-playbook.md) —
  mail flood, a Teams call from fake IT, Quick Assist or another remote tool,
  then recon, staging, lateral movement and Rclone. Ten steps, each with a KQL
  ladder from L1 to expert, written to teach.
- [PHP2Shell and Node2Shell](docs/webrce-playbook.md) — the October 2026 PHP
  and Node.js remote code execution bugs. Which servers are exposed, was one
  exploited, and the hand-off to the hands-on-keyboard playbook.

## Using these

Paste a query into Logs (Sentinel) or Advanced Hunting (Defender XDR) and run
it. Nothing here needs installing.

Queries are written for **Sentinel** unless the query says otherwise. On
**Defender XDR Advanced Hunting** the time column on `Device*` tables is
`Timestamp` rather than `TimeGenerated`, and lookback is capped at 30 days.

## Checks

CI runs these on every push. Run them before you commit:

```
python3 tools/lint_kql.py queries detections
python3 tools/check_rules.py          # needs pyyaml
```

## Licence

[MIT](LICENSE).
