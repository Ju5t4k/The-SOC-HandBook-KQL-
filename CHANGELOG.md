# Changelog

Notable changes to this repository. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `queries/auditlogs.kql` — AuditLogs UserPrincipal query. Directory
  changes with the actor and the target on every row, `modifiedProperties`
  unpacked into old and new values, operation rarity per actor and tenant-wide,
  and the actor's sign-in history from the address the change was made from.
- `queries/officeactivity.kql` — OfficeActivity UserPrincipal query. Exchange, SharePoint, OneDrive and Teams activity with `ClientIP` cleaned of
  its port, operation and workload rarity per user, and the account's sign-in
  history from the source address.
- `queries/signinlogs.kql` — SigninLogs UserPrincipal query. Sign-in
  investigation for a user, IP or device, joined to IdentityInfo for job
  details, AuditLogs for a new-starter check, and day-counts for the address,
  device, location, user agent and application.

### Fixed
- `signinlogs.kql` — day counts now bin by day rather than counting
  day-of-month, so `TimeToCheck` is safe to raise above 31d; `DeviceShort` and
  `Identity` survive to the output; `UniqueEvents` counts events in a session
  rather than always returning 1; `make_set` capped; `fullouter` join reduced to
  `leftouter`. The changes are listed in the file header.
- Repository scaffolding — licence, contributing guide, security policy, code
  of conduct, pull request template, CI hygiene check.

[Unreleased]: https://github.com/Ju5t4k/The-SOC-HandBook-KQL-/commits/main
