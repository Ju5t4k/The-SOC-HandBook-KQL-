# Business email compromise — investigation playbook

**Use when** a mailbox rule, a forwarding address, a supplier complaint or a finance query points at BEC.
**Goal:** establish how they got in, what they read, what they sent, and what is still set.

| Step | Query |
|---|---|
| 1 Confirm | [`bec.kql`](../queries/bec.kql) |
| 2 Reconstruct | [`bec-timeline.kql`](../queries/bec-timeline.kql) |
| 6 Persistence | [`bec-persistence.kql`](../queries/bec-persistence.kql) |
| 7 Scope | [`bec-scope.kql`](../queries/bec-scope.kql) |

**Before you run anything:** set `InternalDomains` in `bec.kql` and `bec-scope.kql` to your accepted domains. It ships as `contoso.com`; left as is, every internal forward counts as external.

---

## How the attack works

- No malware. The attacker gets into a mailbox, reads it until they understand how the business pays, then redirects a payment from a thread the recipient already trusts.
- Shapes: **invoice redirect** (hijacked supplier thread), **CEO fraud**, **payroll diversion**, **onward phishing** from the mailbox.
- **The defining artefact is the mailbox rule** — it hides the replies from the owner. A rule moving "invoice" mail to RSS Feeds and marking it read has no innocent form.
- Victims usually notice nothing until a supplier chases an invoice they already paid.

## Attack timeline

| When | Attacker | Telemetry | Table |
|---|---|---|---|
| T−days | Gets credentials or a token | New sign-in address, or nothing | `SigninLogs` |
| T+0 | First access | Sign-in, often token-based with no MFA prompt | `SigninLogs`, non-interactive |
| T+min–hrs | **Reads and searches the mailbox** | `MailItemsAccessed`, `SearchQueryInitiatedExchange` | `OfficeActivity` |
| T+hrs | **Creates a rule** to hide replies | `New-InboxRule`, `Set-InboxRule` | `OfficeActivity` |
| T+hrs | Adds forwarding or delegation | `Set-Mailbox`, `Add-MailboxPermission` | `OfficeActivity` |
| T+hrs–days | Sends the fraud from the real mailbox | Outbound mail, often first contact | `EmailEvents` |
| T+days–weeks | Payment made; discovered externally | — | — |

What they **read** sets your disclosure position — not the rule.

---

## Steps

### 1. Confirm · 5 min

**Run** `bec.kql`. Blank to sweep, or set `UserIdentityCheck`.

**Read first:** `ExternalForward`, `HidingRule`, `ThirdParty`.

| Signal | Score | Decide |
|---|---|---|
| `ExternalForward` | any | **Compromise.** Mail is leaving the tenant. Go to step 2. |
| `HidingRule` + `FinanceRule` | any | **Compromise.** The invoice-fraud rule. |
| `ThirdParty` | 5+ | Probable. Someone other than the owner changed the mailbox. |
| neither | 6+ | Suspicious. Work it. |
| neither | 3 or less | Usually ordinary inbox management. Note and close. |

Score — 7 indicators, 15 maximum:

| Weight | Indicator |
|---|---|
| +3 | `ExternalForward` — forward target with an `@` outside `InternalDomains` |
| +3 | `HidingRule` — moves to a hiding folder, deletes, or marks read on keyword match |
| +2 | `FinanceRule` — rule words match invoice, payment, bank, payroll |
| +2 | `ThirdParty` — actor is not the mailbox owner |
| +2 | `NoSignInFromIP` — no successful sign-in in 90 days from the address that made the change |
| +2 | `OutboundSpike` — busiest day in the window above 3× the daily average before it |
| +1 | `Delegation` — mailbox or folder permission granted |

Record `EventTime` as the **pivot time**.

### 2. Reconstruct · 20 min

**Run** `bec-timeline.kql` with `PivotTime`. `AfterWindow` is 7 days because BEC plays out over days.

```
1-Access          sign-ins, interactive and token
2-Recon           mail read and searched
3-Mailbox change  the rule, the forward, the delegation
4-Outbound        mail sent, and Send / SendAs / SendOnBehalf
5-Inbound         the hijacked thread and the replies
6-Directory       MFA, consent, roles
7-Files           SharePoint and OneDrive
```

Work back from `3-Mailbox change` to `1-Access` (how), then forward into `4-Outbound` (what they did).

### 3. How they got in

- In `1-Access`, find the first session that is not the user's. Compare address and ASN to normal with [`signinlogs.kql`](../queries/signinlogs.kql).
- **No odd sign-in at all** usually means a stolen token — see the [device code playbook](devicecode-playbook.md).
- "Not yet established" is an acceptable finding. "No compromise" is not.

### 4. What they read · the disclosure question

- `2-Recon` rows are what legal and privacy will ask about.
- **Check mailbox auditing is on before trusting an empty result.** `MailItemsAccessed` needs the right licence and auditing. This is the most common way BEC under-reports.
- Volume matters: four messages = one targeted payment. Searches and thousands of binds = the whole mailbox.

### 5. What they sent

- From `4-Outbound`, list every message in the window, especially to first-contact recipients.
- **Phone** each recipient organisation. Do not email — the thread is compromised.
- Read `5-Inbound` to find which payment was targeted and whether it has gone.

### 6. What is still set · the revocation decision

**Run** `bec-persistence.kql`.

```
Mailbox-Rule    inbox rules, including disabled ones
Forwarding      Set-Mailbox forwarding, auto-replies
Delegation      mailbox and folder permissions
Transport-Rule  tenant-wide mail flow rules — always returned
Directory       MFA methods, consent, roles, registered devices
```

**Transport rules** are tenant-wide, invisible from the mailbox, and survive the rule clean-up, password reset and session revocation. The query always returns them, whatever user you filter on.

### 7. Scope

**Run** `bec-scope.kql` with `ForwardTargetCheck`, `IPCheck`, `SubjectCheck` or `SenderCheck`.

```
Forward         another mailbox forwarding to the same target
MailboxChange   another mailbox changed from the same address
MailRecipient   everyone who received the thread
SignIn          other accounts signed in from the same address
```

`External` is set on `MailRecipient` rows only. Those are the outside parties to phone.

---

## Contain

1. **If a payment is in flight, tell finance to stop it.** This is the only step with a deadline.
2. Revoke sessions, then reset the password.
3. Remove rules (including disabled ones), forwarding and delegation.
4. Remove any transport rule the attacker created.
5. Remove MFA methods, consents and devices added since the pivot.
6. Phone the recipients.
7. Preserve the mailbox before clean-up if fraud occurred — police and insurers will want it.

## Ticket

- Pivot time and the full rule definition
- How they got in, or "not yet established"
- `MailItemsAccessed` volume, or a note that auditing was off
- Every outbound message in the window, with recipients
- Payment attempted? Value? Stopped?
- Persistence found, including transport rules
- Who was warned, when, by what channel

## False positives

| Looks like BEC | Usually |
|---|---|
| Forward to a personal address | A policy breach, not an attacker — still a finding |
| Rule moving mail to a folder | Inbox management, unless it also hides or deletes |
| Delegation to a colleague | A PA or shared-mailbox arrangement |
| Outbound spike | Mail merge, newsletter, busy week |
| Third-party mailbox change | Helpdesk or migration tool — check the actor |

`ThirdParty` + `NoSignInFromIP` together is the combination to trust.

## Limits

- An empty `2-Recon` usually means auditing was off, not that nothing was read.
- A clean mailbox does not mean a clean tenant — transport rules live elsewhere.
- Removing the rule does not end it if the access route is still open.
- Rules created in Outlook appear as `UpdateInboxRules` and may not carry the parameters `bec.kql` scores. Read those rows by hand.
- Not run against live telemetry. Reviewed for KQL correctness and schema only.
