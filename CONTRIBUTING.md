# Contributing

Adding a query is a small job. Adding a *useful* one means the header and the
context blocks, not the KQL.

## Adding a query

1. Pick the file for the table your query reads from. One file per source table.
   A new SigninLogs query goes in `queries/signinlogs.kql` whatever it is about.
2. Copy the whole shape of the query above it — header, `FILL IN` block,
   `CONTEXT` blocks, `MAIN`. Consistency is the feature.
3. Fill in every header field. CI rejects an incomplete one.
4. Add a row to [`queries/README.md`](queries/README.md). The name in the index
   must match the `QUERY:` line exactly — CI checks that too.
5. Run `python3 tools/validate.py`.

## The header

```
// -----------------------------------------------------------------------------
// QUERY:    A sentence naming what it answers, on ONE line
// VERSION:  YYYY.MM.DD
// TABLES:   Every table the query reads, including the context blocks
// ATT&CK:   T0000 Technique Name, or "n/a" for pure context queries
//
// FILL IN:
//   Which of the CHECK values to use, and what combining them gets you.
//
// WHAT YOU GET:
//   The columns that are not obvious, and what each one is measuring.
//
// HOW TO READ IT:
//   Name the column that decides the verdict. Say what a bad result looks like
//   next to a normal one. This is the section an analyst reads at 2am.
//
// MODIFY IT:
//   - At least two. Each must name a specific change AND its specific outcome.
// -----------------------------------------------------------------------------
```

Bad `MODIFY IT` entries: "adjust the time range as needed", "tune for your
environment". If it does not name a change and what that change gets you, cut it.

## The three parts

**FILL IN** — every identifier and knob, in one block at the top, so the query
can be run without being read. Use `contains` with an empty-string default:
blank means no filter, so the same query serves both a single-entity
investigation and a tenant-wide sweep.

Exception: use `==` for values where substring matching would be wrong.
`ResultType contains "0"` also matches 50053 and 50403.

**CONTEXT** — one `let` per question you want pre-answered, each time-bounded,
each joined into MAIN. Name the right-hand join key distinctly (`OrgIP`,
`SiUserKey`, `DdDeviceKey`) so joins do not produce `IPAddress1` / `IPAddress2`
and leave the reader guessing. Comment any block that needs a table not everyone
is licensed for.

**MAIN** — the table the query is about. `project-reorder` over `project`
wherever the raw row is still worth having.

## KQL rules

The full list of mistakes that produce a wrong answer rather than an error is
in [`docs/kql-gotchas.md`](docs/kql-gotchas.md). Read it once before your first
query. The ones that come up most:

- Every query is time-bounded, on the first line after the table, and on both
  sides of every join.
- `ResultType` in `SigninLogs` is a **string**. `"0"` is success.
- `dcount(bin(TimeGenerated, 1d))` counts days.
  `dcount(datetime_part("day", TimeGenerated))` counts day-of-month and silently
  caps at 31. This one is quiet and wrong.
- `mv-apply` and `mv-expand` over an **empty** array drop the row. If those rows
  matter, substitute `dynamic([{}])` first.
- `summarize` cannot group by a dynamic column and `distinct` cannot take one.
  Flatten with `strcat_array(x, ", ")`.
- `make_set` over a column that is already a set produces nested arrays. Keep
  CONTEXT blocks flat when the outer query has to aggregate them.
- `has` matches whole terms. `AnonymousLinkCreated` is one term, so
  `has "AnonymousLink"` is false — that needs `contains`.
- Booleans do not add. `toint(x <= 1) + toint(y <= 1)`.
- Cap every `make_set` / `make_list` with a second argument.
- Never string-match raw JSON to reach a field inside a dynamic column. It finds
  the right event and the wrong field, and it breaks the moment Microsoft
  reorders a property. Expand the array and read the field by name.
- Comment intent, not syntax.

## No customer data

| Use | Not |
|---|---|
| `<upn>`, `<username>` | a real UPN |
| `<device>` | a real hostname |
| `203.0.113.10` (TEST-NET-3) | a real public IP |
| `contoso.com` | your actual domain |

`10.0.0.0/8` and other RFC1918 ranges are fine as examples. Subnet ranges
specific to your organisation are not. CI does not catch this — reviewers must.

## Before you submit

Read [SECURITY.md](SECURITY.md) if you have not — the short version is that no
real UPN, hostname, public IP, tenant ID or query output goes in a commit, an
issue or a PR description.

Run the query. Confirm it returns rows, does not time out on the default
`TimeToCheck`, and that every `MODIFY IT` entry works when applied. Say in the
PR which platform you tested on.

## Review checklist

- [ ] Header complete, `QUERY:` on one line
- [ ] `FILL IN` block present, identifiers default to `""`
- [ ] Every CONTEXT `let` time-bounded and joined into MAIN
- [ ] Join keys named distinctly, no `Column1` / `Column2` in the output
- [ ] At least two specific `MODIFY IT` entries
- [ ] Listed in `queries/README.md` under the exact same name
- [ ] No customer data
- [ ] `python3 tools/validate.py` passes
- [ ] Actually run against real data
