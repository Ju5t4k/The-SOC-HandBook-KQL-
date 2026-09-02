# Contributing

## Adding a query

1. Put it in `queries/`.
2. Give it a comment header saying what it looks for, how to read the output,
   and what to change to get a different answer. A query without that is a
   query only its author can use.
3. Open a pull request.

## Ground rules

- **Time-bound everything.** `| where TimeGenerated > ago(...)` on the first
  line after the table, and on both sides of every join. An unbounded query on
  a large workspace is a self-inflicted outage.
- **Put tunable values in a `let` at the top**, so the query can be changed
  without being read end to end.
- **Comment the intent, not the syntax.** `// exclude the backup service
  account` is useful; `// filter the account` is not.
- **No tenant data.** Placeholders only. See [SECURITY.md](SECURITY.md).
- **Say whether you have run it.** A query that has never been executed is
  worth having, but the reader needs to know which they are looking at.

## Before you open a PR

- Run the query, or say plainly that you have not.
- Note which platform you tested on — Sentinel, Defender Advanced Hunting, or
  both.
- Check the diff for anything real: usernames, hostnames, public IPs, tenant
  IDs, query output.
