# Changelog

Notable changes to the handbook. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Queries are versioned individually in their own `VERSION:` header field, as
`YYYY.MM.DD`. This file tracks the repository.

## [Unreleased]

### Planned
- Endpoint coverage — the `Device*` tables, in the same shape
- Email coverage — `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`,
  `UrlClickEvents`
- Alert coverage — `AlertInfo`, `AlertEvidence`, `SecurityIncident`

## [0.1.0] — 2026-09-02

First release. Eight queries across the three tables every investigation starts
from.

### Added
- `queries/signinlogs.kql` — full sign-in investigation; failure, spray and
  brute-force analysis with result codes decoded; the token and service
  principal sign-ins the interactive table hides
- `queries/auditlogs.kql` — full directory-change investigation with old and
  new values unpacked from `modifiedProperties`; privilege and credential
  timeline for one account
- `queries/officeactivity.kql` — full activity investigation; mailbox rules,
  forwarding and delegation with the rule definition read out of `Parameters`;
  file download and sharing burst measured against the account's own normal
- `tools/validate.py` — CI check on header metadata, the four prose sections,
  the FILL IN block, a visible time bound, and index coverage
- `docs/kql-gotchas.md` — the mistakes that produce a wrong answer rather than
  an error, which is to say the ones the validator cannot catch
- Standard repository furniture: licence, contributing guide, security policy,
  code of conduct, issue and pull request templates, CI workflow

### Notes
- Every query follows one shape: a FILL IN block of `let` statements, a stack
  of CONTEXT blocks that pre-answer the follow-up questions, then MAIN.
- There are no L1 / L2 / L3 tiers, deliberately. See the History section of the
  README.
- Nothing here has been run against live telemetry. Reviewed for KQL
  correctness and schema accuracy only.

[Unreleased]: https://github.com/Ju5t4k/The-SOC-HandBook-KQL-/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Ju5t4k/The-SOC-HandBook-KQL-/releases/tag/v0.1.0
