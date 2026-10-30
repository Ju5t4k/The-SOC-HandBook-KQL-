# Changelog

Notable changes to the handbook. Newest first. Dates are when the change was written; nothing listed here has been run against a live workspace unless it says so.

## 2026-10-30 — Device code phishing rebuild

### Added

- **Detections.** A new [`detections/`](detections/README.md) folder for scheduled rules and hunting queries, separate from the investigation queries. Each detection is a `.kql` (the source, with a header covering logic, tuning, false positives, data, lookback, playbook link and ATT&CK) and a Sentinel analytics rule YAML carrying the same query.
- **Sixteen device code detections**, DC-01 to DC-15 (DC-14 split into a rule and a hunting query), plus eight Defender XDR Advanced Hunting variants. Index: [`detections/device-code/README.md`](detections/device-code/README.md).
- **[`docs/devicecode-ttps.md`](docs/devicecode-ttps.md)**: how the attack works, a sourced client ID lookup, and a per-technique table of which log, table and field shows each step and which detection looks for it.
- **[`docs/devicecode-coverage.md`](docs/devicecode-coverage.md)**: coverage by ATT&CK technique and by data source, single points of failure, and gaps.
- **[`docs/devicecode-review.md`](docs/devicecode-review.md)**: what was wrong, weak and missing in the previous playbook and queries, and what was kept.
- **`tools/check_rules.py`**: checks every detection's header, that the YAML query matches the `.kql` body (`--sync` copies it across), GUID uniqueness, and the Sentinel limits on periods, entity mappings, custom details and alert overrides.
- **`tools/lint_kql.py`**: catches unbalanced brackets, `!matches`, `distinct` with a rename, `join ... on ... and`, unused `let`s, trailing whitespace and missing commas between `union` legs.
- Both tools run in the Hygiene workflow.

### Changed

- **[`docs/devicecode-playbook.md`](docs/devicecode-playbook.md)** rewritten as a full IR playbook. It now has:
  - a one-page quick reference;
  - prerequisites with connector and licence needs;
  - a 15-minute triage with a decision tree that includes legitimate device code use;
  - scoping;
  - thirteen investigation steps, each tied to a detection;
  - containment commands in order;
  - eradication and recovery, hardening, communications, and post-incident templates.
- **`queries/devicecode-timeline.kql`** (now also DC-16):
  - can pivot on an IP as well as a user;
  - shows `OriginalTransferMethod` on token use;
  - adds Identity Protection risk events;
  - no longer pulls every service principal row when no user is set.

### Fixed

- Client IDs in the old playbook that had no source are removed. Each ID now cites Secureworks' FOCI list or Microsoft Learn.
- The old playbook assumed Advanced Hunting could see device code directly. It cannot: `EntraIdSignInEvents` has no protocol column. The Defender variants infer device code from error `50199` followed by success.
- The old 90-day baseline cannot be a Sentinel rule (query period is capped at 14 days). DC-02 and DC-03 use 14 days.
