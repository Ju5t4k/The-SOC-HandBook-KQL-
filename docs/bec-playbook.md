# Business email compromise — end-to-end investigation

For when a mailbox rule, a forwarding address, a supplier complaint or a
finance query points at BEC and you have to work out what was read, what was
sent, and what is still set.

| Query | Phase |
|---|---|
| [`bec.kql`](../queries/bec.kql) | 0 — confirm |
| [`bec-timeline.kql`](../queries/bec-timeline.kql) | 1–4 — reconstruct |
| [`bec-persistence.kql`](../queries/bec-persistence.kql) | 5 — what is still set |
| [`bec-scope.kql`](../queries/bec-scope.kql) | 6 — who else |

---

## What you are looking at

BEC is a fraud, not a malware incident. There is usually no payload at all.
The attacker gets into a mailbox, reads it until they understand how the
business pays people, then either redirects an existing payment or starts a new
one from a thread the recipient already trusts.

The four shapes, in rough order of how often they show up:

- **Invoice redirect** — an existing supplier thread is hijacked and new bank
  details are sent from the real mailbox.
- **CEO fraud** — an urgent request to an individual in finance, usually
  impersonating a director by display name.
- **Payroll diversion** — an HR mailbox asked to change an employee's bank
  details.
- **Onward phishing** — the mailbox is used to phish its own contacts, because
  mail from a known sender gets read.

**The defining artefact is the mailbox rule.** Not because the rule causes
damage, but because the attacker needs the real owner not to see the replies.
A rule that moves anything containing "invoice" to RSS Feeds and marks it read
is not a configuration mistake. Nobody does that by accident.

The second artefact is silence. The victim often notices nothing at all until a
supplier calls about an unpaid invoice they already paid.

---

## The attack timeline

| When | Attacker action | Telemetry | Table |
|---|---|---|---|
| T−days | Credentials obtained — phish, infostealer, token theft, password reuse | Sign-in from a new address, or nothing at all | `SigninLogs` |
| T+0 | First access to the mailbox | Sign-in, often with no MFA prompt if a token was stolen | `SigninLogs`, non-interactive |
| T+min–hrs | **Reading and searching the mailbox** | `MailItemsAccessed`, `SearchQueryInitiatedExchange` | `OfficeActivity` |
| T+hrs | **Rule created** to hide replies from the owner | `New-InboxRule`, `Set-InboxRule` | `OfficeActivity` |
| T+hrs | Forwarding or delegation added | `Set-Mailbox`, `Add-MailboxPermission` | `OfficeActivity` |
| T+hrs–days | Thread hijacked; fraudulent mail sent from the real mailbox | Outbound mail, often to a first-contact recipient | `EmailEvents` |
| T+days | Replies land in the hiding folder; owner sees nothing | — | — |
| T+days–weeks | Payment made. Discovery is usually external | — | — |

**The step that matters most is the reading.** `MailItemsAccessed` volume tells
you what the attacker learned, and that determines your disclosure position —
not the rule, and not the fraudulent mail.

---

## Investigation timeline

### Phase 0 — Confirm · 5 minutes

Run **`bec.kql`**. Leave the `CHECK` fields blank to sweep, or set
`UserIdentityCheck` if you have a name.

Read `ExternalForward`, `HidingRule` and `ThirdParty` first.

| Signal | `BecScore` | Verdict |
|---|---|---|
| `ExternalForward` true | any | **Treat as compromise.** Mail is leaving the tenant. Go to Phase 1 now. |
| `HidingRule` and `FinanceRule` | any | **Treat as compromise.** This is the invoice-fraud rule and it has no benign form. |
| `ThirdParty` true | ≥ 5 | **Probable.** Somebody other than the owner changed this mailbox. |
| neither | ≥ 6 | Suspicious. Work it. |
| neither | ≤ 3 | Usually a user doing something ordinary badly. Note and close. |

The score is built from seven indicators:

| Weight | Indicator |
|---|---|
| +3 | `ExternalForward` — forwarding target outside `InternalDomains` |
| +3 | `HidingRule` — moves to a hiding folder, deletes, or marks read |
| +2 | `FinanceRule` — rule keywords match invoice, payment, bank, payroll |
| +2 | `ThirdParty` — the actor is not the mailbox owner |
| +2 | `NoSignInFromIP` — no successful sign-in from the address that made the change |
| +2 | `OutboundSpike` — outbound volume more than triple the baseline |
| +1 | `Delegation` — mailbox or folder permission granted |

Record the `EventTime` of the highest-scoring row as your **pivot time**.

> `InternalDomains` at the top of the query is `contoso.com` — **change it to
> your own accepted domains before you trust `ExternalForward`.** Left as it
> ships, every internal forward reads as external.

### Phase 1 — Reconstruct · 20 minutes

Run **`bec-timeline.kql`** with `PivotTime` from Phase 0. `AfterWindow`
defaults to 7d because BEC plays out over days, not minutes.

```
1-Access          sign-ins, interactive and token
2-Recon           mail read and searched — what they learned
3-Mailbox change  the rule, the forward, the delegation
4-Outbound        what was sent, and to whom
5-Inbound         the thread being hijacked, and the replies
6-Directory       MFA, consent, roles
7-Files           SharePoint and OneDrive, where invoices also live
```

Work `3-Mailbox change` back to `1-Access` to establish how they got in, then
forward into `4-Outbound` to establish what they did with it.

### Phase 2 — How they got in

From `1-Access`, find the first session that is not the user's. Compare the
address and ASN against the account's normal.

If there is no anomalous sign-in at all, the access was probably token-based.
Go to [`devicecode-playbook.md`](devicecode-playbook.md) and run
[`signinlogs.kql`](../queries/signinlogs.kql) for the account — a token used
from another network produces no failed sign-in and no risk detection.

A BEC with no explicable sign-in is not a BEC with no compromise. It is a BEC
where you have not found the compromise yet.

### Phase 3 — What they read · the disclosure question

The `2-Recon` rows are the ones your legal and privacy people will ask about.

`MailItemsAccessed` is only logged with the right licensing and mailbox
auditing enabled. **Check whether it is on before you read an empty result as
good news** — this is the single most common way a BEC investigation
under-reports.

Volume matters more than content here. An attacker who read four messages
targeted one payment. An attacker who ran searches and bound thousands of items
took the mailbox.

### Phase 4 — What they sent

From `4-Outbound`, list every message sent during the window, especially to
`IsFirstContact` recipients — a first-ever exchange with an external party,
from a mailbox under someone else's control, is the fraud attempt itself.

For each one, get the recipient organisation on the phone. Do not email them:
the thread is compromised and the attacker may still be reading it.

`5-Inbound` shows the thread they hijacked. Read it to work out which payment
was targeted and whether it has already gone out.

### Phase 5 — What is still set · the revocation decision

Run **`bec-persistence.kql`**.

```
Mailbox-Rule    inbox rules, including disabled ones
Forwarding      Set-Mailbox forwarding, auto-reply
Delegation      mailbox and folder permissions, send-as, send-on-behalf
Transport-Rule  tenant-wide mail flow rules
Directory       MFA methods, consent, roles, registered devices
```

**`Transport-Rule` is the one that catches people out.** It is tenant-wide, it
is invisible from the mailbox, and it survives deleting the mailbox rules,
resetting the password and revoking sessions. Check it even when the mailbox
looks clean.

### Phase 6 — Scope · who else

Run **`bec-scope.kql`** with `ForwardTargetCheck`, `IPCheck`, `SubjectCheck` or
`SenderCheck`.

Results are tagged by how they matched:

```
Forward         another mailbox forwarding to the same target
MailboxChange   another mailbox changed from the same address
MailRecipient   everyone who received the thread, inside or outside
SignIn          other accounts signed into from the same address
```

The `External` column separates the outside parties on `MailRecipient` rows,
and those are the people who need a phone call.

---

## Containment

1. **Revoke sessions**, then reset the password. A reset alone leaves stolen
   tokens working.
2. **Remove the rules, forwarding and delegation** — and check for disabled
   rules, which are trivially re-enabled.
3. **Check tenant-wide transport rules.** Separate system, separate place.
4. **Review MFA methods, app consents and registered devices** for anything
   added since the pivot.
5. **Warn the recipients by telephone.** Not by email.
6. **Tell finance to halt the payment** before anything else if one is in
   flight — this is the only step with a deadline.
7. **Preserve the mailbox** before remediating if fraud has occurred. It is
   evidence and there may be a police report or an insurance claim.

---

## For the ticket

- Pivot time and the rule definition in full
- How they got in, or an explicit statement that it is not yet established
- `MailItemsAccessed` volume, or a note that mailbox auditing was off
- Every outbound message sent during the window, and its recipients
- Whether a payment was attempted, its value, and whether it was stopped
- Persistence found, including transport rules
- Who was warned, when, and by what channel

---

## Common false positives

| Looks like BEC | Actually |
|---|---|
| Forward to a personal address | A user breaking policy, not an attacker. Still a finding |
| Rule moving mail to a folder | Ordinary inbox management — unless it also hides or deletes |
| Delegation to a colleague | A PA or a shared mailbox arrangement |
| Outbound spike | A mail merge, a newsletter, a genuinely busy week |
| Third-party mailbox change | Helpdesk or a migration tool. Check the actor |

`ThirdParty` plus `NoSignInFromIP` is the combination worth trusting. Either on
its own has an innocent explanation.

---

## What none of this proves

- **An empty `2-Recon` does not mean nothing was read.** It usually means
  mailbox auditing was not enabled.
- **A clean mailbox does not mean a clean tenant.** Transport rules live
  elsewhere.
- **Removing the rule does not end the incident.** If the access route is still
  open the rule comes back.
- **No fraudulent mail found does not mean no fraud.** The attacker may have
  been reading and waiting for the right invoice.

None of these queries have been run against live telemetry — they are reviewed
for KQL correctness and schema accuracy only. Test them in your own tenant.
