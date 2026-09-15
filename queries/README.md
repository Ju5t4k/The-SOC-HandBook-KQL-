# Queries

| File | Table | What it does |
|---|---|---|
| [`signinlogs.kql`](signinlogs.kql) | `SigninLogs` | Was this account used, and by whom. Job details, new-starter check, and day-counts for the IP, device, location, user agent and application |
| [`auditlogs.kql`](auditlogs.kql) | `AuditLogs` | What did they change once they were in. Actor and target on every row, old and new values unpacked, and how routine the operation is for that actor |
| [`officeactivity.kql`](officeactivity.kql) | `OfficeActivity` | What did they actually do to the data. Exchange, SharePoint, OneDrive and Teams activity with the source address scored against the account's sign-ins |
| [`clickfix.kql`](clickfix.kql) | `DeviceProcessEvents` | One-shot ClickFix investigation. Scores a process against the Win+R fake-CAPTCHA pattern and proves the paste from the `RunMRU` registry key. **Comments in Polish** |

The first three are identity and activity tables and run in sequence.
`clickfix.kql` is different — it is threat-specific and endpoint-side, for when
an alert already points at ClickFix and you need the whole picture in one run.
Its comments are written in Polish.

## The order to run them in

Most tickets arrive as "look at this account" or "look at this address".
Either way:

```
1. signinlogs.kql       Did they get in, from where, and is any of it new
                        for this account?
2. auditlogs.kql        What did they change, and in what order?
3. officeactivity.kql   What did they touch, and what did they leave behind?
```

Step 3 is the one people skip, and it is the one that decides whether the
incident is over. A password reset closes step 1. It does nothing at all about
a forwarding rule.

## How to run one

Fill in the `CHECK` values at the top and run. They use `contains`, so a
partial value works and a blank one matches everything.

```kql
let TimeToCheck = 30d;
let UserIdentityCheck = "";      // <- put the account here
let IPtoCheck = "";
```

Swap `contains` for `=~` if you need an exact match — useful when a username
is a substring of other usernames.

## Reading the output

The recurring column is a **day count** — `DaysIpSeenByUser`,
`DaysOpSeenByActor`, `DaysUserSignedInFromIP`, `DaysClientSeenByUser`. Each
answers "on how many days of the window has this account used this thing".

A 1 means today is the first day. A 25 out of 30 means it is routine. One new
dimension is a new phone or a holiday. Four at once is a different person.

Two columns are worth calling out because they cross tables, and that is where
the answer usually is:

- **`DaysActorSeenFromIP`** (auditlogs) — how many days the person who made a
  directory change has *signed in* from the address they made it from. An
  administrator works from the address they always use. A 0 on a
  privilege-granting operation is the finding.
- **`DaysUserSignedInFromIP`** (officeactivity) — same idea for M365 activity.
  Zero means the session was established some other way: a stolen token, a
  mailbox delegation, or an application acting for the user.

## Cost

Left completely blank, these read the whole tenant and join it to itself
several times. Fine on a small workspace, expensive on a large one. Put
something in one of the `CHECK` values, or shorten `TimeToCheck`, before
running one wide.
