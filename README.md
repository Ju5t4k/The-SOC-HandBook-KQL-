# The SOC Handbook — KQL

[![Validate](https://github.com/Ju5t4k/The-SOC-HandBook-KQL-/actions/workflows/validate.yml/badge.svg)](https://github.com/Ju5t4k/The-SOC-HandBook-KQL-/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

KQL investigation queries for Microsoft Sentinel and Defender XDR.

Not a detection library. Detections tell you something happened. These answer
the question you get asked next, which is always some version of **"okay, so
what actually went on with this account?"**

Every query takes an identifier — a user, an address, a device — and gives you
back the surrounding context in the same result set, so you are not opening
eight tabs to answer one ticket.

---

## Start here

| File | Answers |
|---|---|
| [`queries/signinlogs.kql`](queries/signinlogs.kql) | Was this account used, and by whom |
| [`queries/auditlogs.kql`](queries/auditlogs.kql) | What did they change once they were in |
| [`queries/officeactivity.kql`](queries/officeactivity.kql) | What did they actually do to the data |

[`queries/README.md`](queries/README.md) is the index, and gives the order to
run them in.

Paste a query into Logs, put your account name in the first `let`, run it.
That is the whole workflow.

---

## How every query in this repo is built

One shape, used everywhere. Learn it once.

```kql
// ===== FILL IN — leave blank for "everything" ================================
let TimeToCheck       = 30d;   // the window you are investigating
let BaselineToCheck   = 90d;   // how far back "normal" is measured
let UserIdentityCheck = "";    // <- put the account here and run
let IPtoCheck         = "";
let DeviceToCheck     = "";
// =============================================================================

// --- CONTEXT: how well known is this address? --------------------------------
let IPDaysOrg = SigninLogs
    | where TimeGenerated > ago(BaselineToCheck)
    | summarize DaysIPSeenInOrg = dcount(bin(TimeGenerated, 1d)) by OrgIP = IPAddress;

// --- MAIN --------------------------------------------------------------------
SigninLogs
| where TimeGenerated > ago(TimeToCheck)
| where UserPrincipalName contains UserIdentityCheck
| join kind=leftouter IPDaysOrg on $left.IPAddress == $right.OrgIP
| project-reorder TimeGenerated, UserPrincipalName, IPAddress, DaysIPSeenInOrg
| sort by TimeGenerated desc
```

### 1. The FILL IN block

Every identifier and every knob is in one block at the top. You should never
have to read a query to run it — put your value in the right `let` and press go.

The filters use `contains`, a case-insensitive substring match. Two
consequences, both deliberate:

- **A partial value works.** `"jane"` matches `jane.doe@contoso.com`. You rarely
  have the full UPN when the ticket arrives.
- **Blank means everything.** `contains ""` is true for every row, so an empty
  `let` is not a filter at all. Leave them all blank and the query sweeps the
  tenant; fill one in and it becomes an entity investigation. Same query, both
  jobs.

If you want an exact match instead, swap `contains` for `=~`.

### 2. The CONTEXT blocks

Each one is a `let` that pre-answers a question you were about to ask anyway —
how new is this IP, who else uses it, what is this person's job, how many days
has this device been seen — and gets joined onto every row of the result.

This is the whole point of the repo. A sign-in row on its own tells you almost
nothing. The same row with *"this address has been seen on 1 day out of 90, by
1 user, and the account is a Global Administrator"* beside it tells you
everything.

Where a CONTEXT block needs a table you may not have (`IdentityInfo` requires
UEBA or Defender for Identity), the comment above it says so, and the block is
safe to delete.

### 3. MAIN

The table the query is actually about, filtered, joined, then `project-reorder`
rather than `project` — the useful columns come first, but every column the
table carries is still there when you need one nobody thought of in advance.

---

## Reading the results

The recurring pattern in the output is a **day count**: `DaysIPSeenByUser`,
`DaysDeviceSeenByUser`, `DaysLocationSeenByUser`, `DaysOperationSeenByUser`.
Each answers "on how many days of the baseline window has this account used
this thing".

A 1 means today is the first day. A 60 out of 90 means it is routine. One new
dimension is a new phone or a holiday. Four new dimensions at once is a
different person.

That is deliberately not a score, a risk rating or a verdict. It is the number
you would have worked out by hand, worked out for you.

---

## Cost warning

Left completely blank, these queries read the whole tenant and join it to
itself up to ten times. On a small workspace that is fine. On a large one it is
not.

Fill in at least one identifier, or drop `TimeToCheck`, before running one
blank against a big tenant.

---

## Platform notes

Written for **Microsoft Sentinel** — `TimeGenerated`, `SigninLogs`,
`AuditLogs`, `OfficeActivity`.

On **Defender XDR Advanced Hunting** the equivalents are `AADSignInEventsBeta`
and `CloudAppEvents`, the time column is `Timestamp`, and lookback is capped at
30 days. Where a query depends on the difference, the header says so.

Placeholders only — `<upn>`, `contoso.com`, `203.0.113.10`. No real tenant
data, ever. See [SECURITY.md](SECURITY.md).

---

## Repository layout

```
queries/            the handbook. One file per source table.
  README.md         the index, and the order to run them in
docs/               background reading
tools/validate.py   CI check on the header blocks
CONTRIBUTING.md     how to add a query
```

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). The short version: copy the shape of
the query above the one you are adding, fill in every header field, add it to
`queries/README.md`, and run `python3 tools/validate.py` before you open a PR.

## Status

Early. The three baseline identity and activity tables are covered — eight
queries. Endpoint (`Device*`), email (`Email*`, `UrlClickEvents`) and the alert
tables are next, in the same shape. See [CHANGELOG.md](CHANGELOG.md).

**None of these have been run against live telemetry.** They are reviewed for
KQL correctness and schema accuracy. Test in your own tenant before you rely on
one.

### History

This repo replaces an earlier attempt that split 141 queries across L1 / L2 /
L3 tiers. The tiering was the mistake: nobody arrives at a ticket knowing
whether their question is an L1 or an L3 question — they arrive with an account
name and a deadline, and splitting the same table across three folders by
assumed seniority meant the analyst who needed the deeper query was the least
likely to find it.

That version is preserved as text in
[`Ju5t4k/KQL-Detections`](https://github.com/Ju5t4k/KQL-Detections) under
`archive/handbook-v1/`. There is working KQL in there for endpoint, email,
cloud app and alert tables that has not been ported yet — worth lifting from,
but port it into the shape above rather than pasting it back as it is.

## Licence

[MIT](LICENSE).
