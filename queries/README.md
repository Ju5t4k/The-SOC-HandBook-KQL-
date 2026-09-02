# Query Index

Every query in the handbook. There are no tiers — a query is a query, and the
one you want is the one whose name matches the question you have been asked.

Names are stable. Use them in ticket notes so the next analyst knows exactly
what you ran.

## SigninLogs — [`signinlogs.kql`](signinlogs.kql)

*Was this account used, and by whom.*

| Query | Answers |
|---|---|
| SigninLogs — full sign-in investigation | Every sign-in for a user, IP, device, app or location, each row scored against what is normal for that account. **Start here.** |
| SigninLogs — failure analysis, spray and brute force | Which sources are attacking, which accounts are targeted, and — the only column that matters — whether anything succeeded. |
| Token and service principal sign-ins the interactive table hides | Non-interactive and service principal sign-ins, scored against the addresses the account actually signs in from. Token theft lives here. |

## AuditLogs — [`auditlogs.kql`](auditlogs.kql)

*What did they change once they were in.*

| Query | Answers |
|---|---|
| AuditLogs — full directory-change investigation | Every directory change by or to an account, with old and new values unpacked, and the actor's sign-in behaviour beside it. |
| AuditLogs — privilege and credential timeline for one account | Directory changes and sign-ins on one timeline, restricted to the operations that change someone's power or their ability to authenticate. |

## OfficeActivity — [`officeactivity.kql`](officeactivity.kql)

*What did they actually do to the data.*

| Query | Answers |
|---|---|
| OfficeActivity — full activity investigation | Every audited M365 action for an account or address, with the source scored and the sign-in behind it checked. |
| OfficeActivity — mailbox rules, forwarding and delegation, unpacked | Rule and permission changes with the rule definition read out of `Parameters` — forwarding targets, hiding folders, granted rights. |
| OfficeActivity — file access, download and sharing burst | Bulk download and external sharing, measured against the account's own normal daily volume rather than a fixed threshold. |

---

## The order to run them in

Most investigations arrive as "look at this account" or "look at this address".
Either way:

```
1. SigninLogs — full sign-in investigation
       Did they get in, from where, and is any of it new for this account?

2. Token and service principal sign-ins the interactive table hides
       Is there a session that never shows up in step 1?

3. AuditLogs — privilege and credential timeline for one account
       What did they change, and in what order?

4. OfficeActivity — full activity investigation
       What did they touch?

5. OfficeActivity — mailbox rules, forwarding and delegation, unpacked
       What did they leave behind so they can come back?
```

Step 5 is the one people skip, and it is the one that decides whether the
incident is over. A password reset closes step 1. It does nothing at all about
a forwarding rule.
