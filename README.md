# The SOC Handbook — KQL

[![Hygiene](https://github.com/Ju5t4k/The-SOC-HandBook-KQL-/actions/workflows/hygiene.yml/badge.svg)](https://github.com/Ju5t4k/The-SOC-HandBook-KQL-/actions/workflows/hygiene.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

KQL queries for SOC analysts working in Microsoft Sentinel and Defender XDR.

## Layout

```
queries/    the queries — see queries/README.md for the index
docs/       playbooks and reference
```

### Playbooks

- [ClickFix](docs/clickfix-playbook.md) — fake-CAPTCHA paste-and-run. Eight
  steps from the paste to the reimage decision.
- [Device code phishing](docs/devicecode-playbook.md) — OAuth device code
  token theft. Six steps; revoking sessions matters more than the password.
- [Business email compromise](docs/bec-playbook.md) — mailbox takeover and
  invoice fraud. Seven steps; check tenant-wide transport rules.
- [Malicious attachment](docs/attachment-playbook.md) — the `SHA256` join from
  mail to endpoint. Six steps.
- [Hands-on-keyboard intrusion](docs/hok-playbook.md) — a person operating on
  a device. Twelve steps from "are they still here" to root cause, plus
  collection from the Defender portal without a query.

## Using these

Paste a query into Logs (Sentinel) or Advanced Hunting (Defender XDR) and run
it. Nothing here needs installing.

Queries are written for **Sentinel** unless the query says otherwise. On
**Defender XDR Advanced Hunting** the time column on `Device*` tables is
`Timestamp` rather than `TimeGenerated`, and lookback is capped at 30 days.

## Licence

[MIT](LICENSE).
