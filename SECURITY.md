# Security

## What is in this repository

KQL text. Nothing here executes anywhere — no build, no runtime, no
dependencies beyond a Python script that reads comment headers in CI. There is
no attack surface in the usual sense.

The risk in a repository like this runs the other way: it is a place where
somebody accidentally commits **their own tenant's data**.

## Never commit

- Real user principal names, display names or email addresses
- Real hostnames, device IDs or device names
- Real public IP addresses belonging to your organisation or a third party
- Tenant IDs, subscription IDs, workspace IDs, object IDs
- Internal subnet ranges specific to your organisation
- Query **output** — results, exports, CSVs, screenshots of the results pane
- Anything from an active investigation

Use placeholders instead:

| Use | Not |
|---|---|
| `<upn>`, `<username>` | a real UPN |
| `<device>` | a real hostname |
| `203.0.113.10` (TEST-NET-3, RFC 5737) | a real public IP |
| `contoso.com` | your actual domain |
| `<sha256>`, `<guid>` | a real hash or ID |

`10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16` are fine as generic
examples. Ranges specific to your organisation are not.

The same applies to issues and pull request descriptions. A redacted example is
always enough to explain a problem with a query.

**CI does not catch this.** Reviewers must.

## If tenant data has already been committed

Open an issue saying only *"sensitive data in commit `<sha>`"* — do not repeat
the data in the issue. It will be removed from history and the branch
force-pushed. Treat anything that reached a public commit as disclosed and
handle it under your own incident process; rewriting history does not un-clone
it.

## Reporting a problem with a query

A query that returns the wrong answer is a correctness bug, not a security
issue — open a normal issue using the "Query correction" template. That
includes queries that miss events, because a detection gap is worth discussing
in the open where other people can see the reasoning.

If you believe something in this repository actively creates risk for the
people running it — a query that would leak data out of a tenant, for example —
raise it privately through GitHub's
[private vulnerability reporting](https://github.com/Ju5t4k/The-SOC-HandBook-KQL-/security/advisories/new)
rather than in a public issue.

## Running these queries safely

Left blank, several of these queries read the whole tenant and join it to
itself repeatedly. On a large workspace that is expensive and can affect other
users of the same cluster. Fill in an identifier or shorten `TimeToCheck`
before running one against production at scale.
