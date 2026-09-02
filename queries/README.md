# Queries

| File | Table | What it does |
|---|---|---|
| [`signinlogs.kql`](signinlogs.kql) | `SigninLogs` | Sign-in investigation for a user, IP or device, with job details, new-starter check, and day-counts for the IP, device, location, user agent and application |

## How to run one

Fill in the `CHECK` values at the top and run. They use `contains`, so a
partial value works and a blank one matches everything.

```kql
let TimeToCheck = 30d;
let UserIdentityCheck = "";      // <- put the account here
let IPtoCheck = "";
let DeviceDetailtoCheck = "";
```

Left completely blank, a query like this reads the whole tenant and joins it to
itself several times. Fine on a small workspace, expensive on a large one — put
something in one of the `CHECK` values, or shorten `TimeToCheck`, before running
it wide.
