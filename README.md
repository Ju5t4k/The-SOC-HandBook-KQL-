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

- [ClickFix — end-to-end investigation](docs/clickfix-playbook.md) — attack
  timeline, seven investigation phases with the query for each, containment
  order, and what an empty result does not prove.
- [Device code authentication — end-to-end investigation](docs/devicecode-playbook.md)
  — attack timeline, six investigation phases with the query for each,
  containment order, and why revoking sessions matters more than resetting the
  password.

## Using these

Paste a query into Logs (Sentinel) or Advanced Hunting (Defender XDR) and run
it. Nothing here needs installing.

Queries are written for **Sentinel** unless the query says otherwise. On
**Defender XDR Advanced Hunting** the time column on `Device*` tables is
`Timestamp` rather than `TimeGenerated`, and lookback is capped at 30 days.

## Licence

[MIT](LICENSE).
