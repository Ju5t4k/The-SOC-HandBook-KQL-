# KQL gotchas

Mistakes that produce a **wrong answer rather than an error**. Those are the
dangerous ones — a query that fails to compile gets fixed in thirty seconds, a
query that quietly returns 80% of the rows gets trusted for a year.

Everything here is something that has actually gone wrong in this repo or its
predecessor. The validator cannot catch any of it.

---

## Counting days

```kql
// WRONG — counts day-of-month, silently caps at 31
| summarize Days = dcount(datetime_part("day", TimeGenerated)) by IPAddress

// RIGHT
| summarize Days = dcount(bin(TimeGenerated, 1d)) by IPAddress
```

`datetime_part("day", ...)` returns 1–31. Over a 90-day baseline the 3rd of
January and the 3rd of February are the same value, so your "days seen" count
tops out at 31 and every long-standing address looks less established than it
is. There is no error. The number is just wrong, and wrong in the direction
that makes rare things look common.

---

## `ResultType` is a string

```kql
| where ResultType == 0      // WRONG — compares string to int
| where ResultType == "0"    // RIGHT
```

And when filtering by substring:

```kql
| where ResultType contains "0"    // WRONG — also matches 50053, 50403, 700016
| where ResultType == "0"          // RIGHT
```

`contains` is a substring test. Almost every Entra failure code contains a `0`.

---

## `has` matches whole terms

```kql
| where Operation has "AnonymousLink"        // FALSE for AnonymousLinkCreated
| where Operation contains "AnonymousLink"   // TRUE
```

`has` is fast because it works on the tokenised index, and tokens break on
punctuation and case boundaries are *not* one of them.
`AnonymousLinkCreated` is a single token, so `has "AnonymousLink"` does not
match it. Use `has` for whole words in free text like command lines. Use
`contains` for prefixes of a single identifier.

---

## `mv-expand` and `mv-apply` drop rows on an empty array

```kql
// Any event with no modifiedProperties vanishes entirely
| mv-apply P = TargetResources.modifiedProperties on ( summarize ... )

// Keeps the row, with blank values
| extend PropList = iff(array_length(todynamic(TargetResources.modifiedProperties)) > 0,
                        todynamic(TargetResources.modifiedProperties),
                        dynamic([{}]))
| mv-apply P = PropList on ( summarize ... )
```

This is the worst one on the list, because the rows that disappear are not
random — they are systematically the events of one particular kind. You get a
result that looks complete and is missing a category.

---

## `summarize` cannot group by a dynamic column

```kql
| summarize ... by DeviceList          // ERROR — DeviceList is a make_set result
| extend DeviceList = strcat_array(DeviceList, ", ")
| summarize ... by DeviceList          // fine
```

Same for `distinct`. This one does error, which makes it the safe kind of
mistake — but it bites specifically when you `mv-expand`, join, and then
re-summarize, which is a common enrichment pattern.

---

## `make_set` over a set gives you nested arrays

```kql
// Produces [["a","b"],["c"]] — technically valid, useless to read
| summarize Domains = make_set(UrlDomains, 10) by Sender
```

If a CONTEXT block pre-aggregates into a set and the outer query has to
aggregate again, either keep the CONTEXT block flat (one row per key per value)
or flatten with `strcat_array` first.

---

## A join `on` clause takes commas, not `and`

```kql
| join kind=leftouter H on $left.User == $right.U and $left.IP == $right.I   // WRONG
| join kind=leftouter H on $left.User == $right.U, $left.IP == $right.I      // RIGHT
```

---

## Booleans do not add

```kql
| extend Score = (A <= 1) + (B <= 1)                    // ERROR
| extend Score = toint(A <= 1) + toint(B <= 1)          // RIGHT
```

---

## `max_of` propagates null; `coalesce` does not

```kql
| extend Ratio = Files / max_of(NormalPerDay, 1.0)      // null when no baseline
| extend Ratio = Files / coalesce(NormalPerDay, 1.0)    // 1.0 when no baseline
```

After a `leftouter` join, every enrichment column can be null. `max_of(null, x)`
is null, so a single missing baseline blanks the whole column rather than
falling back.

---

## Do not string-match raw JSON to reach a field

```kql
// WRONG — finds the right event and the wrong field, and breaks silently
// the moment Microsoft reorders a property
| where tostring(TargetResources) contains "AccountEnabled"
| extend Value = extract('"newValue":"\\\\"(.*?)\\\\""', 1, tostring(TargetResources))

// RIGHT
| mv-expand TargetResources
| extend Upn = tostring(TargetResources.userPrincipalName)
```

Dynamic columns are structured. Read them by name. Every `extract()` against a
JSON blob is a future silent failure.

---

## `ipv4_is_private` returns null on unparseable input

```kql
| where not(ipv4_is_private(RemoteIP))     // drops rows where the result is null
| where ipv4_is_private(RemoteIP) == false // keeps only genuine public addresses
```

`not(null)` is null, which is not true, so the row is dropped. If the column
ever contains a hostname, an IPv6 address or an empty string — and it will —
those rows silently disappear.

---

## Negative array indexing does not exist

```kql
| extend Ext = split(FileName, ".")[-1]                  // always null
| extend Ext = extract(@"\.([^.]+)$", 1, FileName)       // RIGHT
```

---

## Cap every `make_set`

```kql
| summarize Users = make_set(UserPrincipalName)          // unbounded
| summarize Users = make_set(UserPrincipalName, 50)      // bounded
```

The default limit is high enough to make a result unreadable and a query
expensive, and low enough that you cannot rely on it being complete either. Set
it explicitly so the number is a decision rather than an accident.

---

## Both sides of a join need a time bound

```kql
| join kind=leftouter (
    SigninLogs                              // reads full retention
    | summarize ... by IPAddress
  ) on IPAddress
```

The outer query being bounded does not bound the inner one. On a large
workspace this is the difference between four seconds and a timeout.
