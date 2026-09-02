## What this changes

<!-- One or two sentences. If it adds a query, name the question it answers. -->

## Type

- [ ] New query
- [ ] Correction to an existing query
- [ ] Documentation
- [ ] Tooling / CI

## Checklist

<!-- Delete the query section if this PR does not touch a .kql file. -->

**For any change**

- [ ] `python3 tools/validate.py` passes
- [ ] No tenant data — placeholders only (see [SECURITY.md](../SECURITY.md))

**For a query change**

- [ ] Header complete, `QUERY:` on one line, `VERSION:` bumped to today
- [ ] `FILL IN` block present, identifiers default to `""`
- [ ] Every CONTEXT `let` is time-bounded and joined into MAIN
- [ ] Join keys named distinctly — no `Column1` / `Column2` in the output
- [ ] At least two `MODIFY IT` entries, each naming a change and its outcome
- [ ] Listed in [`queries/README.md`](../queries/README.md) under the exact
      same name

## Testing

<!--
Which platform did you run this on — Sentinel, Defender Advanced Hunting, or
both? Did it return rows? Did it complete inside the default TimeToCheck?

If you have NOT run it, say so. That is allowed and it is better than implying
otherwise — it just changes how the review is done.

Do not paste real results. Describe them.
-->

Platform:
Ran successfully:
Notes:
