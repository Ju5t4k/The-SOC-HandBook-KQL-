# Teams vishing and helpdesk impersonation (Quick Assist) — investigation playbook

**The attacker buries a user in spam, calls them on Teams as "IT Support" to fix it, and gets them to open Quick Assist. Ten minutes later they are running commands on your network.**

---

## When to use this playbook

**Use it when any of these fire:**

| Trigger | Where it comes from |
|---|---|
| A user reports a Teams call or chat from "Help Desk", "IT Support" or similar, from outside the company | User report, Teams *Report a concern* |
| A user reports hundreds of newsletter sign-ups or spam in a short time | User report, service desk ticket |
| Mail bombing detection on a mailbox | Defender for Office 365 (`DetectionMethods` contains mail bombing) |
| Remote support tool launched or installed on a workstation | Defender for Endpoint alert on remote monitoring and management (RMM) software; the Level 3/4 rules in step 3 |
| External Teams contact followed by an RMM launch | The analytics rules recommended in [Detection engineering](#detection-engineering-recommendations) |

**Severity:**

| What you can confirm | Severity | Why |
|---|---|---|
| Mail flood only | Low | Precursor. Warn the user, watch for the call |
| Flood **and** external Teams contact posing as IT | Medium | The lure is live. Call the user before the attacker does |
| A remote support session was opened in the window | High | The attacker may have had control of the desktop |
| Recon, PowerShell staging or a backdoor after the session | Critical | Hands-on-keyboard intrusion. Hand off now (see below) |
| Any of the above for an admin, or a user with Azure roles | Raise one level | Faster route to the domain or the cloud |

**Hand-offs:**

- **Step 4 or step 5 confirmed** → also open the [Hands-on-keyboard intrusion playbook](hok-playbook.md). Keep this one for the Teams and RMM scope; run the intrusion from there.
- **Exfiltration, shadow-copy deletion or encryption seen** → Ransomware (endpoint) playbook *(not yet in this handbook — follow your ransomware runbook)*.
- **The user holds Azure roles** → Cloud ransomware playbook *(not yet in this handbook)*. Treat their sessions and tokens as compromised in Azure too.

## How the attack works

| Phase | Attacker | Telemetry | MITRE ATT&CK |
|---|---|---|---|
| T−hours | Signs the user's address up to hundreds of newsletters and lists | Inbound mail spike, many senders | (Precursor — denial of the inbox) |
| T−minutes | Messages or calls from an external tenant as "Help Desk" | `MessageEvents`, `CallActivityEvents`, `CloudAppEvents` | T1566.004, T1656 |
| T+0 | Talks the user into Quick Assist, AnyDesk, ScreenConnect or similar | `DeviceProcessEvents`, `DeviceNetworkEvents` | T1219 |
| T+1–10 min | Recon: `whoami`, `nltest`, `net group`, `ipconfig`, `systeminfo` | `DeviceProcessEvents`, `DeviceEvents` | T1033, T1016, T1082, T1482, T1069.002 |
| T+5–30 min | PowerShell or `curl` pulls a payload; DLL side-loaded by a signed binary | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceImageLoadEvents` | T1059.001, T1105, T1574.002 |
| T+30 min | Persistence: run key, scheduled task, service | `DeviceRegistryEvents`, `DeviceEvents` | T1547.001, T1053.005, T1543.003 |
| T+hours | Lateral movement to servers and domain controllers | `DeviceNetworkEvents`, `DeviceLogonEvents` | T1021, T1569.002 |
| T+hours–days | Archives data and uploads with Rclone; access sold or ransomware deployed | `DeviceProcessEvents`, `DeviceFileEvents`, firewall logs | T1560.001, T1567.002 |

Public reporting links this pattern to Storm-1811 and Black Basta affiliates (Microsoft, 2024) and to several groups since. Display names seen include "Help Desk", "Help Desk IT", "Help Desk Support" and "IT Support", often from `*.onmicrosoft.com` tenants created for the purpose.

> **Key point for every step after step 3.** Quick Assist gives the attacker the user's own desktop. Anything they type runs as the user, under `explorer.exe` or a shell they opened, **not** under `QuickAssist.exe`. Searching for children of Quick Assist finds nothing. Use the session's time window instead. ScreenConnect, AnyDesk and NetSupport are different: their built-in command features do run commands as children of the tool, often as SYSTEM.

---

## Prerequisites

### Log sources

| Table | Product and licence | Into Sentinel via | If missing |
|---|---|---|---|
| `EmailEvents` | Defender for Office 365 Plan 2 (advanced hunting) | Microsoft Defender XDR connector | Exchange message trace; no fallback in KQL |
| `MessageEvents` | Defender for Office 365, Teams protection. Preview from 2025 // VERIFY plan and GA status | Defender XDR connector // VERIFY the table is offered in your connector | `CloudAppEvents` Teams audit (step 2, Level 3) |
| `CallActivityEvents` | Defender for Office 365 // VERIFY plan | Defender XDR connector // VERIFY | `CloudAppEvents` `CallParticipantDetail`, or the user's account |
| `CloudAppEvents` | Defender for Cloud Apps with the Microsoft 365 app connector; unified audit log on | Defender XDR connector | `OfficeActivity` (Teams operations) via the Microsoft 365 connector |
| `AuditLogs` | Microsoft Entra ID (any tier) | Microsoft Entra ID connector | Entra admin centre audit log |
| `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `DeviceEvents` | Defender for Endpoint Plan 2, Defender for Business, or Defender for Servers Plan 2 | Defender XDR connector (tick each table) | Device timeline export, Live Response |
| `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceNetworkInfo` | As above. **Used in steps 6 and 7** in addition to the list above | Defender XDR connector | Same |
| `CommonSecurityLog` (optional) | Firewall or proxy over CEF | CEF via AMA connector | Needed for **bytes** sent; Defender for Endpoint does not record bytes |

### Retention

- Advanced Hunting keeps **30 days**. The flood and the first contact can be days before the alert, and Level 4 baselines need 30 days. Run long lookbacks in Sentinel.
- Sentinel: keep the tables above **90 days or more** in the Analytics tier. Baselines in Level 4 queries assume 30 days of history.

### Permissions

| Task | Role |
|---|---|
| Run the queries | Sentinel Reader (workspace) / Security Reader (Defender) |
| Isolate a device, collect a package, Live Response | Defender for Endpoint *Active remediation actions* (e.g. Security Operator) |
| Revoke sessions, reset password | Entra User Administrator (Privileged Authentication Administrator for admins) |
| Block an external domain in Teams | Teams Administrator |
| Remove apps, restrict Quick Assist | Intune Administrator or endpoint team |

### How to read the queries

- Every query targets the **Sentinel workspace** (`TimeGenerated`) unless its header says otherwise.
- **Advanced Hunting:** replace `TimeGenerated` with `Timestamp`. For `CallActivityEvents` in Advanced Hunting the time column is `ActivityTimestamp` // VERIFY.
- `AdditionalFields` is `dynamic` in Sentinel and `string` in Advanced Hunting. Every query wraps it in `todynamic()` so both work.
- Placeholders: `user@contoso.com`, `<device>`, `contoso.com`, `datetime(2026-10-28T09:00:00Z)`. Replace before running.
- `// VERIFY` marks a column, value or table that depends on licence, connector version or a schema change. Check it once in your tenant.

---

## Steps

### 1. Inbox flooding that precedes the call

**Step goal:** Was this mailbox flooded, when did the flood start and stop, and does the flood look like sign-up spam rather than a normal busy inbox? The flood's start time anchors the whole investigation.

#### Level 1 (Basic)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 2d;
let target_user = "user@contoso.com";
EmailEvents
| where TimeGenerated > ago(lookback)
| where RecipientEmailAddress =~ target_user
| where EmailDirection == "Inbound"
| project TimeGenerated, SenderFromAddress, Subject, DeliveryLocation, ThreatTypes, DetectionMethods
| order by TimeGenerated asc
```

**Why this query:** It lists every email the user received in the last two days, oldest first. Look at the row count and the times. A normal user gets tens of emails a day spread out; a flood is hundreds in an hour from different senders, with subjects like "Confirm your subscription" or "Welcome to". `DeliveryLocation` shows whether the filter caught them (Junk folder) — a flood is a flood even if it all went to Junk.

#### Level 2 (Intermediate)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 2d;
let window = 15m;
let min_emails = 50;            // emails in one window
let min_senders = 20;           // distinct sending domains in one window
let SignupWords = dynamic(["confirm","subscription","subscribe","verify","welcome","newsletter","registration","activate","unsubscribe"]);
EmailEvents
| where TimeGenerated > ago(lookback)
| where EmailDirection == "Inbound"
| summarize Emails = count(),
            Senders = dcount(SenderFromDomain),
            Subjects = dcount(Subject),
            SignupLike = countif(Subject has_any (SignupWords)),
            MailBombingVerdicts = countif(tostring(DetectionMethods) has "Mail bombing"),   // VERIFY exact value in DetectionMethods
            Junked = countif(DeliveryLocation in ("Junk folder", "Quarantine"))
            by RecipientEmailAddress, Window = bin(TimeGenerated, window)
| where Emails >= min_emails and Senders >= min_senders
| extend SignupShare = round(100.0 * SignupLike / Emails, 0)
| order by Emails desc
```

**Why this query:** It counts mail per recipient in 15-minute buckets across the whole tenant, so you find every flooded mailbox, not just the one reported.

- **Normal:** a shared mailbox or a sales inbox can get 50 emails in 15 minutes, but from a few senders with repeated subjects.
- **A hit:** 50+ emails from 20+ different domains, nearly as many distinct subjects as emails, and a high `SignupShare`.
- `MailBombingVerdicts` counts Defender's own mail-bombing verdict, rolled out in 2025. Check the exact string once (`EmailEvents | where DetectionMethods has "bomb" | take 5`).
- Tune `min_emails` and `min_senders` to your tenant. Shared mailboxes and distribution lists produce benign hits; list them and exclude.

#### Level 3 (Advanced)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
// Flooded mailboxes, and whether an external Teams contact followed.
let lookback = 3d;
let window = 15m;
let min_emails = 50;
let min_senders = 20;
let follow_up = 6h;             // how long after the flood a call still counts
let SignupWords = dynamic(["confirm","subscription","subscribe","verify","welcome","newsletter","registration","activate"]);
// Optional allowlist of shared mailboxes. Create the watchlist first, or delete this line and its use below.
let NoisyMailboxes = _GetWatchlist('FloodAllowlist') | project Mailbox = tolower(SearchKey);
let Floods = materialize(
    EmailEvents
    | where TimeGenerated > ago(lookback)
    | where EmailDirection == "Inbound"
    | summarize Emails = count(), Senders = dcount(SenderFromDomain), SignupLike = countif(Subject has_any (SignupWords))
                by Recipient = tolower(RecipientEmailAddress), Window = bin(TimeGenerated, window)
    | where Emails >= min_emails and Senders >= min_senders
    | where Recipient !in ((NoisyMailboxes))
    | summarize FloodStart = min(Window), FloodEnd = max(Window) + window, PeakPerWindow = max(Emails),
                TotalEmails = sum(Emails), MaxSenders = max(Senders), SignupLike = sum(SignupLike)
                by Recipient);
// External Teams messages to the same people. MessageEvents only holds external threads (and internal ones with URLs).
let ExternalTeams = MessageEvents
    | where TimeGenerated > ago(lookback)
    | where IsExternalThread == true
    | mv-expand Rcpt = RecipientDetails
    | extend Recipient = tolower(tostring(Rcpt.RecipientSmtpAddress))
    | where Recipient in ((Floods | project Recipient))
    | summarize FirstTeamsContact = min(TimeGenerated), ExternalSenders = make_set(SenderEmailAddress, 10), SenderNames = make_set(SenderDisplayName, 10) by Recipient;
Floods
| join kind=leftouter ExternalTeams on Recipient
| extend TeamsAfterFlood = isnotnull(FirstTeamsContact) and FirstTeamsContact between (FloodStart .. FloodEnd + follow_up)
| project Recipient, FloodStart, FloodEnd, TotalEmails, PeakPerWindow, MaxSenders, SignupLike, TeamsAfterFlood, FirstTeamsContact, SenderNames, ExternalSenders
| order by TeamsAfterFlood desc, TotalEmails desc
```

**Why this query:** It targets the attacker's sequence, not just the volume: flood first, then an external Teams message to the same person within six hours.

- `materialize()` stores the flood list once; `MessageEvents` is then read only for flooded recipients.
- `leftouter` keeps floods with no Teams contact. A flood with no contact yet is still a warning: the call may come later or by phone.
- **False positives:** a marketing mailbox hit by a real campaign, then a partner chat. `SenderNames` settles it — "IT Support" from an unknown tenant is not a partner.
- **Pivot next:** take `FirstTeamsContact` and the sender into step 2.

#### Level 4 (Expert / L3)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp, and keep baseline <= 30d.
// Flood as a statistical anomaly per mailbox against its own hourly history.
let baseline = 14d;
let step = 1h;
let min_peak = 40;              // ignore anomalies below this many emails in an hour
// Only build series for mailboxes that had a busy hour today. Keeps the series small.
let Candidates = EmailEvents
    | where TimeGenerated > ago(1d)
    | where EmailDirection == "Inbound"
    | summarize Emails = count() by RecipientEmailAddress, bin(TimeGenerated, step)
    | where Emails >= min_peak
    | distinct RecipientEmailAddress;
EmailEvents
| where TimeGenerated > ago(baseline)
| where EmailDirection == "Inbound"
| where RecipientEmailAddress in ((Candidates))
| make-series Emails = count() default = 0 on TimeGenerated from ago(baseline) to now() step step by RecipientEmailAddress
| extend (Anomaly, Score, Expected) = series_decompose_anomalies(Emails, 3.0, -1, "linefit")   // threshold 3, auto seasonality
| mv-expand TimeGenerated to typeof(datetime), Emails to typeof(long), Anomaly to typeof(int), Score to typeof(double), Expected to typeof(double)
| where TimeGenerated > ago(1d)
| where Anomaly == 1 and Emails >= min_peak
| extend TimesNormal = round(Emails / max_of(Expected, 1.0), 1)
| project TimeGenerated, RecipientEmailAddress, Emails, Expected = round(Expected, 1), TimesNormal, Score = round(Score, 1)
| order by Score desc
```

**Why this query:**

- **Technique:** precursor to T1566.004 (Spearphishing Voice) and T1656 (Impersonation). The flood itself is not an ATT&CK technique; it creates the pretext.
- **Why a per-mailbox baseline:** a fixed threshold (Level 2) fires daily on shared mailboxes and misses a quiet user who gets 30 emails in an hour. `series_decompose_anomalies` learns each mailbox's daily and weekly rhythm (seasonality `-1` = auto-detect) and flags hours outside it. Threshold `3.0` is the usual starting point; raise it if too noisy.
- **Evasion and blind spots:** a slow flood over a day stays inside the baseline; floods sent to a personal address and forwarded arrive as one sender; floods sent by phone or SMS are invisible here.
- **Cost:** `make-series` over every mailbox for 14 days is expensive. `Candidates` limits it to mailboxes that were busy today, which in most tenants is under 1%.
- **As a scheduled rule:** query frequency 1 hour, lookback 14 days (the scheduled-rule maximum). Entity mapping: Mailbox → `RecipientEmailAddress`. Severity Low on its own; correlate with step 2 for Medium/High.

#### Decision point

| Output | Call | Next |
|---|---|---|
| Hundreds of emails, many senders, sign-up subjects, then external Teams contact | **True positive** — precursor | Step 2 with `FirstTeamsContact`. Call the user on a known number and tell them IT will not contact them on Teams from outside |
| Flood, no Teams contact yet | **True positive** — precursor | Warn the user and the service desk. Re-run step 2 in an hour |
| Shared mailbox, campaign replies, one sender domain | **False positive** | Add to `FloodAllowlist` |
| User signed up to something themselves | **Benign true positive** | Close; note in the ticket |

---

### 2. External Teams chats and calls from new tenants posing as IT

**Step goal:** Who contacted the user from outside, from which tenant, under what name, and is that tenant new to you? Did they call, and did the user accept the chat?

#### Level 1 (Basic)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 3d;
let target_user = "user@contoso.com";
MessageEvents
| where TimeGenerated > ago(lookback)
| where IsExternalThread == true
| where tostring(RecipientDetails) has target_user
| project TimeGenerated, SenderDisplayName, SenderEmailAddress, SenderType, MessageSubject, ThreatTypes, DeliveryAction, SafetyTip, ThreadId
| order by TimeGenerated asc
```

**Why this query:** It lists Teams messages from outside the company to the user. Read `SenderDisplayName` and `SenderEmailAddress` together: "IT Support" sent from `something.onmicrosoft.com` is not your IT department. `SafetyTip` shows whether Teams warned the user. Record the `ThreadId`; the call usually comes in the same conversation.

#### Level 2 (Intermediate)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 7d;
let HelpdeskPattern = @"(?i)(help\s*desk|service\s*desk|it\s*(support|help|team|dept|department|admin)|tech(nical)?\s*support|support\s*team|security\s*team|microsoft|administrator)";
MessageEvents
| where TimeGenerated > ago(lookback)
| where IsExternalThread == true
| extend SenderDomain = tolower(tostring(split(SenderEmailAddress, "@")[1]))
| extend ImpersonatesIT = SenderDisplayName matches regex HelpdeskPattern or SenderEmailAddress matches regex HelpdeskPattern,
         OnMicrosoft = SenderDomain endswith ".onmicrosoft.com"
| where ImpersonatesIT or OnMicrosoft
| mv-expand Rcpt = RecipientDetails
| summarize Messages = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Recipients = make_set(tolower(tostring(Rcpt.RecipientSmtpAddress)), 50), Names = make_set(SenderDisplayName, 10)
            by SenderEmailAddress, SenderDomain, ImpersonatesIT, OnMicrosoft
| extend RecipientCount = array_length(Recipients)
| order by ImpersonatesIT desc, RecipientCount desc
```

**Why this query:** It sweeps the whole tenant for external senders whose name or address claims to be IT, or who send from a default `*.onmicrosoft.com` domain.

- `matches regex` with `\s*` catches "HelpDesk", "Help Desk" and "Help  Desk" in one pattern; `has` would need every spelling.
- **Normal:** partners chat from their own domains with personal names. Some legitimate small tenants still use `onmicrosoft.com`, so `OnMicrosoft` alone is weak.
- **A hit:** `ImpersonatesIT` true, a domain you have never worked with, and several `Recipients` — the same "help desk" messaging many staff is a campaign.

#### Level 3 (Advanced)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp (CallActivityEvents: ActivityTimestamp, VERIFY).
// Every external contact route, against a 30-day baseline of tenants you already talk to.
let lookback = 3d;
let baseline = 30d;
let InternalDomains = dynamic(["contoso.com", "contoso.onmicrosoft.com"]);     // every domain you own
let HelpdeskPattern = @"(?i)(help\s*desk|service\s*desk|it\s*(support|help|team|dept|department|admin)|tech(nical)?\s*support|support\s*team|security\s*team|microsoft|administrator)";
let OrgPattern = @"(?i)contoso";                                                 // your brand, to catch contoso-support.onmicrosoft.com
let KnownDomains = toscalar(
    MessageEvents
    | where TimeGenerated between (ago(baseline) .. ago(lookback))
    | where IsExternalThread == true
    | summarize make_set(tolower(tostring(split(SenderEmailAddress, "@")[1])), 50000));
let Contacts = union isfuzzy=true
    (MessageEvents
        | where TimeGenerated > ago(lookback)
        | where IsExternalThread == true
        | mv-expand Rcpt = RecipientDetails
        | project TimeGenerated, Source = "Teams message", External = tolower(SenderEmailAddress), ExternalName = SenderDisplayName, Target = tolower(tostring(Rcpt.RecipientSmtpAddress))),
    (CallActivityEvents
        | where TimeGenerated > ago(lookback)
        | project TimeGenerated, Source = "Teams call", External = tolower(OriginatorUpn), ExternalName = strcat(OriginatorUserDisplayName, " (", ActivityInitiatorTenantDisplayName, ")"), Target = tolower(ActivityRecipientUpn)),
    // Teams audit: chats created, message requests accepted. Field names inside RawEventData follow the Office 365 audit schema. // VERIFY
    (CloudAppEvents
        | where TimeGenerated > ago(lookback)
        | where Application == "Microsoft Teams"
        | where ActionType in ("ChatCreated", "MemberAdded", "UserAccepted")
        | mv-expand Member = RawEventData.Members
        | project TimeGenerated, Source = strcat("Audit ", ActionType), External = tolower(tostring(Member.UPN)), ExternalName = tostring(Member.DisplayName), Target = tolower(tostring(RawEventData.UserId))),
    // B2B guests created for "chat with people not using Teams". Guest UPNs look like name_domain.com#EXT#@contoso.onmicrosoft.com.
    (AuditLogs
        | where TimeGenerated > ago(lookback)
        | where OperationName =~ "Invite external user"
        | extend GuestUpn = tolower(tostring(TargetResources[0].userPrincipalName))
        | project TimeGenerated, Source = "Guest invite", External = iff(GuestUpn has "#ext#", replace_regex(extract(@"^(.+)#ext#", 1, GuestUpn), @"_([^_]+)$", @"@\1"), GuestUpn), ExternalName = tostring(TargetResources[0].displayName), Target = tolower(tostring(InitiatedBy.user.userPrincipalName)))
;
Contacts
| extend Domain = tostring(split(External, "@")[1])
| where isnotempty(Domain) and Domain !in (InternalDomains)
| where tostring(split(Target, "@")[1]) in (InternalDomains)            // only contacts aimed at your users
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Sources = make_set(Source, 6),
            Targets = make_set(Target, 50), Names = make_set(ExternalName, 10), Externals = make_set(External, 10) by Domain
| extend NewDomain = Domain !in (KnownDomains),
         ImpersonatesIT = strcat_array(Names, " | ") matches regex HelpdeskPattern,
         MimicsOrg = Domain matches regex OrgPattern,
         OnMicrosoft = Domain endswith ".onmicrosoft.com",
         TargetCount = array_length(Targets)
| where NewDomain or ImpersonatesIT or MimicsOrg
| project FirstSeen, Domain, NewDomain, ImpersonatesIT, MimicsOrg, OnMicrosoft, TargetCount, Names, Externals, Sources, Targets, LastSeen
| order by ImpersonatesIT desc, NewDomain desc, TargetCount desc
```

**Why this query:** The attacker can arrive by message, by call, or as a guest. This query joins the four routes into one row per external domain.

- **Attacker behaviour:** a fresh tenant, a help-desk display name, a call shortly after a chat, often the same tenant against several staff.
- **Why `union isfuzzy=true`:** `CallActivityEvents` and `MessageEvents` are not in every workspace. Fuzzy union runs whatever exists.
- **Why `toscalar` for the baseline:** comparing one domain against a list is cheap; joining two large tables to do the same is not.
- `Sources` containing `Audit UserAccepted` means the user clicked *Accept* on the message request. `Teams call` means a call was placed.
- **False positives:** new suppliers and auditors appear as `NewDomain`; real Microsoft support contacts do not arrive through Teams chat from `onmicrosoft.com`.
- **Pivot next:** the time of the first call or accepted chat is the start of step 3's window.

#### Level 4 (Expert / L3)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp (CallActivityEvents: ActivityTimestamp, VERIFY); keep baseline <= 30d.
// Scores each external domain + target pair: flood before contact, impersonation, new tenant, call placed, campaign spread.
let lookback = 3d;
let baseline = 30d;
let flood_min = 50;
let follow_up = 6h;
let InternalDomains = dynamic(["contoso.com", "contoso.onmicrosoft.com"]);
let HelpdeskPattern = @"(?i)(help\s*desk|service\s*desk|it\s*(support|help|team|dept|department|admin)|tech(nical)?\s*support|support\s*team|security\s*team|microsoft|administrator)";
let OrgPattern = @"(?i)contoso";
let KnownDomains = toscalar(
    MessageEvents
    | where TimeGenerated between (ago(baseline) .. ago(lookback))
    | where IsExternalThread == true
    | summarize make_set(tolower(tostring(split(SenderEmailAddress, "@")[1])), 50000));
let Floods = EmailEvents
    | where TimeGenerated > ago(lookback)
    | where EmailDirection == "Inbound"
    | summarize Emails = count(), Senders = dcount(SenderFromDomain) by Recipient = tolower(RecipientEmailAddress), Window = bin(TimeGenerated, 15m)
    | where Emails >= flood_min and Senders >= 20
    | summarize FloodStart = min(Window), FloodEnd = max(Window) + 15m by Recipient;
let Contacts = union isfuzzy=true
    (MessageEvents
        | where TimeGenerated > ago(lookback)
        | where IsExternalThread == true
        | mv-expand Rcpt = RecipientDetails
        | project TimeGenerated, Kind = "Message", External = tolower(SenderEmailAddress), ExternalName = SenderDisplayName, Target = tolower(tostring(Rcpt.RecipientSmtpAddress))),
    (CallActivityEvents
        | where TimeGenerated > ago(lookback)
        | project TimeGenerated, Kind = "Call", External = tolower(OriginatorUpn), ExternalName = OriginatorUserDisplayName, Target = tolower(ActivityRecipientUpn));
let Pairs = Contacts
    | extend Domain = tostring(split(External, "@")[1])
    | where isnotempty(Domain) and Domain !in (InternalDomains)
    | where tostring(split(Target, "@")[1]) in (InternalDomains)
    | summarize FirstContact = min(TimeGenerated), Kinds = make_set(Kind, 2), Names = make_set(ExternalName, 5) by Domain, Target;
let DomainSpread = Pairs | summarize DomainTargets = dcount(Target) by Domain;
Pairs
| join kind=leftouter Floods on $left.Target == $right.Recipient
| join kind=leftouter DomainSpread on Domain
| extend FloodFirst = isnotnull(FloodStart) and FirstContact between (FloodStart .. FloodEnd + follow_up),
         ImpersonatesIT = strcat_array(Names, " | ") matches regex HelpdeskPattern,
         NewDomain = Domain !in (KnownDomains),
         MimicsOrg = Domain matches regex OrgPattern,
         Called = set_has_element(Kinds, "Call"),
         OnMicrosoft = Domain endswith ".onmicrosoft.com"
// 7 indicators, 14 at most.
| extend Score = 3 * toint(FloodFirst) + 3 * toint(ImpersonatesIT) + 2 * toint(NewDomain) + 2 * toint(MimicsOrg) + 2 * toint(Called) + toint(OnMicrosoft) + toint(DomainTargets >= 3)
| where Score >= 5
| project FirstContact, Score, Target, Domain, Names, FloodFirst, ImpersonatesIT, NewDomain, MimicsOrg, Called, OnMicrosoft, DomainTargets, FloodStart
| order by Score desc, FirstContact asc
```

**Why this query:**

- **Techniques:** T1566.004 (Spearphishing Voice), T1656 (Impersonation), T1534-adjacent use of collaboration tools from outside.
- **Why a score, not a rule per signal:** each signal alone is noisy (new tenants appear daily; "Support" is a common word). Together they are rare. The weights favour the two signals that separate this attack from business chat: flood first (+3) and an IT-themed name (+3). A threshold of 5 needs at least two strong signals.
- **Evasion and blind spots:** a personal-looking display name ("Mark from IT" passes, "Mark" does not); calls from a phone number (PSTN) have no tenant; a compromised **partner** tenant is not new and not `onmicrosoft.com`. External contacts to personal phones are invisible.
- **Cost:** `KnownDomains` reads 30 days of external `MessageEvents` once; everything else reads 3 days. Fine hourly for most tenants.
- **As a scheduled rule:** frequency 1 hour, lookback 3 days (baseline 14 days if your rule limit forces it). Entities: Account → `Target`, DNS → `Domain`. Severity High when `FloodFirst` and `ImpersonatesIT` are both true, else Medium. Suppress per `Target` + `Domain` for 24 hours.

#### Decision point

| Output | Call | Next |
|---|---|---|
| IT-themed name, new or `onmicrosoft.com` tenant, after a flood | **True positive** | Block the domain now (see [Contain](#10-contain)), call the user, step 3 |
| Same tenant contacting several staff | **True positive — campaign** | Step 9 scope immediately, warn all `Targets` |
| Known partner domain, named person, business topic | **False positive** | Note the domain; consider allowlisting |
| User contacted a vendor's real support through Teams | **Benign true positive** | Confirm with the user and the vendor contact on file |

---

### 3. Remote support tool launches tied to the user and window

**Step goal:** Did a remote support session start on the user's device after the contact, which tool was it, and was it installed for the occasion?

#### Level 1 (Basic)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 2d;
let target_device = "<device>";
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where DeviceName startswith target_device
| where FileName in~ ("quickassist.exe", "anydesk.exe", "teamviewer.exe", "teamviewer_service.exe", "screenconnect.windowsclient.exe", "screenconnect.clientservice.exe", "client32.exe", "rustdesk.exe")
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by TimeGenerated asc
```

**Why this query:** It shows when a remote support program started on the device, who started it, and from where. Compare `TimeGenerated` to the Teams contact time from step 2. A launch a few minutes after the call is the session. `FolderPath` in `Downloads` or `AppData` means the tool was just downloaded, not installed by IT. ScreenConnect's service runs as SYSTEM, so filter on the device, not the user.

#### Level 2 (Intermediate)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 7d;
let RmmPattern = @"(?i)^(quickassist|anydesk|teamviewer|teamviewer_service|tv_w32|tv_x64|screenconnect\.[a-z.]+|client32|rustdesk|srservice|strwinclt|ateraagent|meshagent|rutserv|rfusclient|za_connect|zaservice|supremo|supremoservice|ninjarmmagent|action1_agent|lmiguardiansvc|dwagent|remote access)\.exe$";
// Product names catch renamed binaries.
let RmmProducts = dynamic(["AnyDesk", "TeamViewer", "ScreenConnect", "NetSupport", "RustDesk", "Splashtop", "Quick Assist", "Atera", "SimpleHelp", "Supremo", "Remote Utilities", "Zoho Assist", "LogMeIn"]);
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where FileName matches regex RmmPattern or ProcessVersionInfoProductName has_any (RmmProducts)
| extend Tool = tolower(coalesce(ProcessVersionInfoProductName, FileName))           // coalesce skips empty strings
| extend UserWritable = FolderPath matches regex @"(?i)\\(users|programdata|windows\\temp)\\"
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Launches = count(),
            Accounts = make_set(AccountName, 10), Paths = make_set(FolderPath, 5), Parents = make_set(InitiatingProcessFileName, 5),
            Hashes = make_set(SHA256, 5), FromUserWritable = max(toint(UserWritable))
            by DeviceName, Tool
| order by FirstSeen desc
```

**Why this query:** One row per device and tool, across the tenant.

- `ProcessVersionInfoProductName` catches `AnyDesk.exe` renamed to `update.exe`; the file name alone would miss it.
- `FromUserWritable = 1` means it ran from a user folder: downloaded in the session rather than deployed.
- **Normal:** your sanctioned tool on many devices for months, started by its service.
- **A hit:** a tool you do not use, first seen today, from `Downloads`, started by the browser or `explorer.exe`.

#### Level 3 (Advanced)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
// RMM process launches and RMM network traffic on the user's devices, around the Teams contact.
let lookback = 3d;
let target_user = "user@contoso.com";
let contact_time = datetime(2026-10-28T09:12:00Z);   // first call or accepted chat from step 2
let before = 30m;
let after = 3h;
let target_sam = tostring(split(target_user, "@")[0]);   // VERIFY: assumes sAMAccountName equals the UPN prefix
let RmmPattern = @"(?i)^(quickassist|anydesk|teamviewer|teamviewer_service|tv_w32|tv_x64|screenconnect\.[a-z.]+|client32|rustdesk|srservice|strwinclt|ateraagent|meshagent|rutserv|rfusclient|za_connect|zaservice|supremo|supremoservice|ninjarmmagent|action1_agent|lmiguardiansvc|dwagent|remote access)\.exe$";
let RmmProducts = dynamic(["AnyDesk", "TeamViewer", "ScreenConnect", "NetSupport", "RustDesk", "Splashtop", "Quick Assist", "Atera", "SimpleHelp", "Supremo", "Remote Utilities", "Zoho Assist", "LogMeIn"]);
let RmmDomains = dynamic(["remoteassistance.support.services.microsoft.com", "anydesk.com", "teamviewer.com", "screenconnect.com", "netsupportsoftware.com", "rustdesk.com", "splashtop.com", "atera.com", "zohoassist.com", "logmein.com"]);
// Devices the user signed in to interactively.
let UserDevices = DeviceLogonEvents
    | where TimeGenerated > ago(lookback)
    | where AccountName =~ target_sam
    | where LogonType in ("Interactive", "RemoteInteractive", "CachedInteractive", "Unlock")
    | distinct DeviceId;
union
    (DeviceProcessEvents
        | where TimeGenerated between (contact_time - before .. contact_time + after)
        | where DeviceId in ((UserDevices))
        | where FileName matches regex RmmPattern or ProcessVersionInfoProductName has_any (RmmProducts)
        | project TimeGenerated, DeviceName, Kind = "Process", Account = AccountName, Evidence = strcat(FileName, " | ", FolderPath, " | parent ", InitiatingProcessFileName), SHA256),
    (DeviceNetworkEvents
        | where TimeGenerated between (contact_time - before .. contact_time + after)
        | where DeviceId in ((UserDevices))
        | where RemoteUrl has_any (RmmDomains)
        | project TimeGenerated, DeviceName, Kind = "Network", Account = InitiatingProcessAccountName, Evidence = strcat(InitiatingProcessFileName, " > ", RemoteUrl, " ", RemoteIP, ":", RemotePort))
| extend MinutesAfterContact = datetime_diff("minute", TimeGenerated, contact_time)
| order by TimeGenerated asc
```

**Why this query:** It answers "did a session start because of that call" by tying three things together: the user's devices (from `DeviceLogonEvents`), the contact time (from step 2), and RMM evidence from two angles.

- **Why network as well as process:** Quick Assist is part of Windows and its process start alone means little. A connection to `remoteassistance.support.services.microsoft.com` minutes after an external call is the session. Network evidence also catches portable tools whose process events were missed.
- **Why `union` and not `join`:** process and network rows are separate evidence; the analyst reads them in time order.
- **False positives:** your service desk using Quick Assist with this user that morning — check the service desk ticket queue for the same time.
- **Pivot next:** the first row with `MinutesAfterContact >= 0` is the **session start**. Carry it into steps 4 and 5.

#### Level 4 (Expert / L3)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp, baseline <= 30d.
// RMM tools running on a device for the first time, scored by how rare they are in the estate.
let baseline = 30d;
let recent = 1d;
let RmmPattern = @"(?i)^(quickassist|anydesk|teamviewer|teamviewer_service|tv_w32|tv_x64|screenconnect\.[a-z.]+|client32|rustdesk|srservice|strwinclt|ateraagent|meshagent|rutserv|rfusclient|za_connect|zaservice|supremo|supremoservice|ninjarmmagent|action1_agent|lmiguardiansvc|dwagent|remote access)\.exe$";
let RmmProducts = dynamic(["AnyDesk", "TeamViewer", "ScreenConnect", "NetSupport", "RustDesk", "Splashtop", "Quick Assist", "Atera", "SimpleHelp", "Supremo", "Remote Utilities", "Zoho Assist", "LogMeIn"]);
// Sanctioned tools. Better: _GetWatchlist('ApprovedRMM') | summarize make_set(tolower(SearchKey))
let Sanctioned = dynamic(["teamviewer"]);
let Rmm = materialize(
    DeviceProcessEvents
    | where TimeGenerated > ago(baseline)
    | where FileName matches regex RmmPattern or ProcessVersionInfoProductName has_any (RmmProducts)
    | extend Tool = tolower(coalesce(ProcessVersionInfoProductName, FileName)),
             UserWritable = FolderPath matches regex @"(?i)\\(users|programdata|windows\\temp)\\"
    | project TimeGenerated, DeviceId, DeviceName, Tool, FolderPath, AccountName, SHA256, UserWritable, InitiatingProcessFileName);
let OrgPrevalence = Rmm | where TimeGenerated <= ago(recent) | summarize PriorDevices = dcount(DeviceId) by Tool;
let DeviceHistory = Rmm | where TimeGenerated <= ago(recent) | distinct DeviceId, Tool;
Rmm
| where TimeGenerated > ago(recent)
| join kind=leftanti DeviceHistory on DeviceId, Tool                     // first time on this device
| summarize FirstRun = min(TimeGenerated), Runs = count(), Paths = make_set(FolderPath, 5), Accounts = make_set(AccountName, 5),
            Parents = make_set(InitiatingProcessFileName, 5), Hashes = make_set(SHA256, 5), FromUserWritable = max(toint(UserWritable))
            by DeviceId, DeviceName, Tool
| join kind=leftouter OrgPrevalence on Tool
| extend PriorDevices = coalesce(PriorDevices, 0)
| extend IsSanctioned = Tool has_any (Sanctioned)
// 4 indicators, 8 at most.
| extend Score = 3 * toint(PriorDevices == 0) + toint(PriorDevices between (1 .. 3)) + 2 * FromUserWritable + 2 * toint(not(IsSanctioned))
| project FirstRun, Score, DeviceName, Tool, PriorDevices, FromUserWritable, IsSanctioned, Accounts, Parents, Paths, Hashes, Runs
| order by Score desc, FirstRun asc
```

**Why this query:**

- **Technique:** T1219 (Remote Access Software).
- **First-seen logic:** the question for detection is not "is AnyDesk running" but "has AnyDesk ever run here, or anywhere". `leftanti` against the device's own 30-day history keeps only first runs; `OrgPrevalence` says whether the estate has ever seen the tool.
- **Quick Assist blind spot:** Quick Assist is on every Windows device, so first-seen and prevalence say little about it. That is why step 3 Level 3 correlates it with the Teams contact. Keep both rules.
- **Evasion:** portable tools renamed and stripped of version info; browser-based tools (no process); RMM run inside a VM. Pair this with network detections on the vendors' relay domains.
- **Cost:** 30 days of RMM-filtered process events is small. The regex runs on every process start, so filter on `FileName` first as written.
- **As a scheduled rule:** frequency 1 hour, lookback 14 days (rule maximum) with `recent = 1h`. Entities: Host → `DeviceName`, Account → `Accounts`, File hash → `Hashes`. Severity Medium; High when `PriorDevices == 0` and `FromUserWritable == 1`.

#### Decision point

| Output | Call | Next |
|---|---|---|
| RMM session within minutes of the external contact | **True positive** | **Isolate the device** (see [Contain](#10-contain)), then steps 4–8 using the session start |
| Unsanctioned tool, first seen, from `Downloads`, no ticket | **True positive** until proven otherwise | Ask the user; continue to step 4 |
| Service desk session matching a ticket and a known technician | **Benign true positive** | Note the ticket number |
| Sanctioned tool, long history, started by its service | **False positive** | Add to the allowlist watchlist |

---

### 4. First-minute reconnaissance

**Step goal:** What did the operator run in the first minutes of the session? Recon proves a person is on the device and shows what they were after (the domain, admins, trusts).

> **Escalate:** if this step shows recon after the session start, open the [Hands-on-keyboard intrusion playbook](hok-playbook.md) now.

#### Level 1 (Basic)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 1d;
let target_device = "<device>";
let ReconBins = dynamic(["whoami.exe", "nltest.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "quser.exe", "query.exe", "qwinsta.exe", "tasklist.exe", "hostname.exe", "arp.exe", "route.exe", "netstat.exe", "nslookup.exe", "dsquery.exe", "klist.exe", "setspn.exe"]);
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where DeviceName startswith target_device
| where FileName in~ (ReconBins)
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Why this query:** It lists built-in Windows commands people use to look around: who am I, what network, what domain, who are the admins. Users almost never type these. Read the commands in order: `whoami /all`, then `nltest /dclist:`, then `net group "domain admins" /domain` is someone mapping the domain.

#### Level 2 (Intermediate)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 2d;
let ReconBins = dynamic(["whoami.exe", "nltest.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "quser.exe", "query.exe", "qwinsta.exe", "tasklist.exe", "hostname.exe", "arp.exe", "route.exe", "netstat.exe", "nslookup.exe", "dsquery.exe", "klist.exe", "setspn.exe"]);
let PsRecon = dynamic(["Get-ADUser", "Get-ADComputer", "Get-ADGroupMember", "Get-ADDomain", "Get-ADDomainController", "Get-ADTrust", "Get-NetIPConfiguration", "Get-LocalGroupMember", "adsisearcher", "DirectorySearcher", "Get-NetTCPConnection", "Win32_ComputerSystem"]);
union
    (DeviceProcessEvents
        | where TimeGenerated > ago(lookback)
        | where FileName in~ (ReconBins) or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any (PsRecon))
        | project TimeGenerated, DeviceName, AccountName, Tool = tolower(FileName), Command = ProcessCommandLine),
    // PowerShell cmdlets logged inside a session, including ones typed interactively.
    (DeviceEvents
        | where TimeGenerated > ago(lookback)
        | where ActionType == "PowerShellCommand"
        | extend Cmd = tostring(todynamic(AdditionalFields).Command)
        | where Cmd has_any (PsRecon)
        | project TimeGenerated, DeviceName, AccountName = InitiatingProcessAccountName, Tool = strcat("ps:", Cmd), Command = Cmd)
| summarize Start = min(TimeGenerated), Tools = dcount(Tool), ToolList = make_set(Tool, 20), Commands = make_set(Command, 30) by DeviceName, AccountName, Window = bin(TimeGenerated, 10m)
| extend Burst = Tools >= 4
| order by Burst desc, Tools desc
```

**Why this query:** It groups recon into 10-minute windows per device and account.

- The `DeviceEvents` leg adds `PowerShellCommand`: cmdlets run inside PowerShell, which a process event alone never shows.
- **Normal:** one `ipconfig` from a user fixing Wi-Fi; a monitoring agent running `systeminfo` daily.
- **A hit:** `Burst` — four or more different recon tools in 10 minutes, especially domain-level ones (`nltest`, `net group /domain`, `Get-AD*`) from a non-IT user.

#### Level 3 (Advanced)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
// Recon in the first 30 minutes of each remote support session, numbered in the order it happened.
let lookback = 2d;
let first_minutes = 30m;
let RmmPattern = @"(?i)^(quickassist|anydesk|teamviewer|teamviewer_service|screenconnect\.[a-z.]+|client32|rustdesk|srservice|ateraagent|meshagent|rutserv|za_connect|supremo|dwagent|remote access)\.exe$";
let ReconBins = dynamic(["whoami.exe", "nltest.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "quser.exe", "query.exe", "qwinsta.exe", "tasklist.exe", "hostname.exe", "arp.exe", "route.exe", "netstat.exe", "nslookup.exe", "dsquery.exe", "klist.exe", "setspn.exe"]);
let PsRecon = dynamic(["Get-ADUser", "Get-ADComputer", "Get-ADGroupMember", "Get-ADDomain", "Get-ADDomainController", "Get-ADTrust", "Get-NetIPConfiguration", "Get-LocalGroupMember", "adsisearcher", "DirectorySearcher"]);
let Sessions = materialize(
    DeviceProcessEvents
    | where TimeGenerated > ago(lookback)
    | where FileName matches regex RmmPattern
    | summarize SessionStart = min(TimeGenerated), RmmTool = take_any(FileName) by DeviceId, DeviceName, Hour = bin(TimeGenerated, 1h));
let Recon = union
    (DeviceProcessEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceId in ((Sessions | project DeviceId))
        | where FileName in~ (ReconBins) or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any (PsRecon))
        | project TimeGenerated, DeviceId, AccountName, ReconTool = tolower(FileName), Command = ProcessCommandLine, Parent = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)),
    (DeviceEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceId in ((Sessions | project DeviceId))
        | where ActionType == "PowerShellCommand"
        | extend Cmd = tostring(todynamic(AdditionalFields).Command)
        | where Cmd has_any (PsRecon)
        | project TimeGenerated, DeviceId, AccountName = InitiatingProcessAccountName, ReconTool = "powershell cmdlet", Command = Cmd, Parent = InitiatingProcessFileName);
Sessions
| join kind=inner Recon on DeviceId
| where TimeGenerated between (SessionStart .. SessionStart + first_minutes)
| extend SecondsAfterStart = datetime_diff("second", TimeGenerated, SessionStart)
| sort by DeviceId asc, SessionStart asc, TimeGenerated asc
| extend Seq = row_number(1, prev(DeviceId) != DeviceId or prev(SessionStart) != SessionStart)   // restart numbering per session
| project DeviceName, RmmTool, SessionStart, Seq, SecondsAfterStart, AccountName, ReconTool, Command, Parent
```

**Why this query:** It targets the operator's checklist in the first minutes after they take control.

- **Why anchor on the session:** recon on its own has false positives; recon within seconds of a remote session starting does not. `SecondsAfterStart` and `Seq` show the operator's order of work.
- **Why `Parent` matters:** under Quick Assist the parent is `explorer.exe` or `cmd.exe` (the operator is using the user's desktop). Under ScreenConnect's command feature the parent is `ScreenConnect.ClientService.exe` and the account is SYSTEM.
- **False positives:** a real service desk technician running `ipconfig` and `whoami` to diagnose. Domain enumeration (`nltest /domain_trusts`, `net group "domain admins"`) is not diagnosis.
- **Pivot next:** step 5 for the same session window.

#### Level 4 (Expert / L3)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp, baseline <= 30d.
// Recon tools never used before by this account on this device, scored; domain recon weighs more.
let baseline = 30d;
let recent = 1d;
let ReconBins = dynamic(["whoami.exe", "nltest.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "quser.exe", "query.exe", "qwinsta.exe", "tasklist.exe", "hostname.exe", "arp.exe", "route.exe", "netstat.exe", "nslookup.exe", "dsquery.exe", "klist.exe", "setspn.exe"]);
// Management agents that run recon legitimately. Add yours.
let MgmtParents = dynamic(["CcmExec.exe", "SenseIR.exe", "MonitoringHost.exe", "AgentExecutor.exe", "IntuneManagementExtension.exe"]);
let DomainRecon = @"(?i)(nltest|/domain|dsquery|setspn|domain_trusts|dclist|domain admins|enterprise admins)";
let Recon = materialize(
    DeviceProcessEvents
    | where TimeGenerated > ago(baseline)
    | where FileName in~ (ReconBins)
    | where InitiatingProcessFileName !in~ (MgmtParents)
    | project TimeGenerated, DeviceId, DeviceName, AccountName, ReconTool = tolower(FileName), ProcessCommandLine);
let Known = Recon | where TimeGenerated <= ago(recent) | distinct DeviceId, AccountName, ReconTool;
Recon
| where TimeGenerated > ago(recent)
| join kind=leftanti Known on DeviceId, AccountName, ReconTool
| summarize Start = min(TimeGenerated), NewTools = dcount(ReconTool), Tools = make_set(ReconTool, 20), Commands = make_set(ProcessCommandLine, 30),
            DomainHits = countif(ProcessCommandLine matches regex DomainRecon)
            by DeviceId, DeviceName, AccountName, Window = bin(TimeGenerated, 15m)
| where NewTools >= 3
| extend Score = NewTools + 3 * toint(DomainHits > 0) + 2 * toint(AccountName !in~ ("system", "local service", "network service"))
| project Start, Score, DeviceName, AccountName, NewTools, DomainHits, Tools, Commands
| order by Score desc
```

**Why this query:**

- **Techniques:** T1033 (System Owner/User Discovery), T1016 (System Network Configuration Discovery), T1082 (System Information Discovery), T1482 (Domain Trust Discovery), T1069.002 (Domain Groups), T1087.002 (Domain Account).
- **Why first-seen per account and device:** helpdesk staff and admins run these tools every day, so a raw count punishes the wrong people. "Three tools this account has never run on this device, inside 15 minutes" is rare for everyone.
- **Thresholds:** `NewTools >= 3` in 15 minutes; domain-level recon adds 3; an interactive user account adds 2 (an operator using the victim's session runs as the user).
- **Evasion and blind spots:** recon through .NET or LDAP queries inside a custom binary creates no process; slow recon spread over hours; recon from a C2 beacon injected into a trusted process (the parent looks normal). `DeviceEvents` `PowerShellCommand` covers some in-PowerShell recon — add it as in Level 3 if volume allows.
- **Cost:** 30 days of process events filtered to 18 file names is moderate. Run hourly, not every 5 minutes.
- **As a scheduled rule:** frequency 1 hour, lookback 14 days with `recent = 1h`. Entities: Host → `DeviceName`, Account → `AccountName`. Severity High; Critical if an RMM session started on the device in the previous hour.

#### Decision point

| Output | Call | Next |
|---|---|---|
| Recon burst within minutes of the RMM session start | **True positive — hands-on-keyboard** | Isolate if not done. **Escalate to the [HOK playbook](hok-playbook.md).** Continue step 5 here |
| `ipconfig` / `whoami` only, matching a service desk ticket | **Benign true positive** | Note it |
| Monitoring agent or script as parent, daily pattern | **False positive** | Add the parent to `MgmtParents` |

---

### 5. PowerShell download-and-execute and suspicious children of the remote tool

**Step goal:** Did the operator bring tools onto the device? This step finds the download, the encoded command and the process that ran the payload.

> **Escalate:** a confirmed download-and-execute here means [HOK playbook](hok-playbook.md) now, if not already.

#### Level 1 (Basic)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 1d;
let target_device = "<device>";
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where DeviceName startswith target_device
| where FileName in~ ("powershell.exe", "pwsh.exe", "curl.exe", "bitsadmin.exe", "certutil.exe")
| where ProcessCommandLine has_any ("-encodedcommand", "DownloadString", "DownloadFile", "Invoke-WebRequest", "iwr", "IEX", "Invoke-Expression", "Start-BitsTransfer", "FromBase64String", "-w hidden", "bypass", "http")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Why this query:** It shows PowerShell and download tools being told to fetch something from the internet or run hidden code. Look for a web address (`http...`) in the command and a file saved to `C:\Users\Public`, `C:\ProgramData` or `AppData`. A long block of random letters after `-enc` is an encoded command; Level 2 decodes it.

#### Level 2 (Intermediate)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 1d;
let target_device = "<device>";
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where DeviceName startswith target_device
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
// -e, -enc, -EncodedCommand and every abbreviation in between.
| extend Encoded = extract(@"(?i)\s-e[a-z]*\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
// PowerShell encodes as UTF-16LE; strip the null bytes to read it.
| extend Decoded = iff(isnotempty(Encoded), replace_regex(base64_decode_tostring(Encoded), @"\x00", ""), "")
| extend Text = strcat(ProcessCommandLine, " ", Decoded)
| extend Download = Text matches regex @"(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer|net\.webclient|curl(\.exe)?\s|wget\s)",
         Execute = Text matches regex @"(?i)(\biex\b|invoke-expression|start-process|rundll32|regsvr32|\.invoke\()",
         Hidden = Text matches regex @"(?i)(-w(indowstyle)?\s+h(idden)?\b|-nop\b|-noprofile|bypass|-noni\b)"
| where Download or Execute or isnotempty(Encoded)
| project TimeGenerated, AccountName, InitiatingProcessFileName, Download, Execute, Hidden, ProcessCommandLine, Decoded
| order by TimeGenerated asc
```

**Why this query:** It decodes encoded commands so you can read them, then labels what each command does.

- `Download` **and** `Execute` together is the staging pattern: fetch and run in one line.
- **Normal:** management tools also use `-EncodedCommand` (Intune, SCCM, some RMM). They run from their agent as parent and repeat daily.
- **A hit:** an encoded command from `explorer.exe` or the remote tool, minutes after the session start, that decodes to a URL plus `iex`.

#### Level 3 (Advanced)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
// Staging processes, with the addresses they contacted and the files they wrote, joined on the exact process.
let lookback = 2d;
let target_device = "<device>";
let RmmParents = dynamic(["screenconnect.clientservice.exe", "screenconnect.windowsclient.exe", "anydesk.exe", "teamviewer.exe", "teamviewer_service.exe", "client32.exe", "rustdesk.exe", "ateraagent.exe", "rutserv.exe", "srservice.exe", "quickassist.exe"]);
let StagingBins = dynamic(["powershell.exe", "pwsh.exe", "cmd.exe", "curl.exe", "bitsadmin.exe", "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "wscript.exe", "cscript.exe"]);
let DownloadExec = @"(?i)(https?://|downloadstring|downloadfile|invoke-webrequest|\biwr\b|start-bitstransfer|-urlcache|/transfer\s|\s-o\s|\biex\b|-enc)";
let Staging = materialize(
    DeviceProcessEvents
    | where TimeGenerated > ago(lookback)
    | where DeviceName startswith target_device
    | where InitiatingProcessFileName in~ (RmmParents) or (FileName in~ (StagingBins) and ProcessCommandLine matches regex DownloadExec)
    | project TimeGenerated, DeviceId, DeviceName, AccountName, ProcessUniqueId, FileName, ProcessCommandLine, Parent = InitiatingProcessFileName, GrandParent = InitiatingProcessParentFileName);
// Join on the process's unique id, not the PID: Windows reuses PIDs.
let Net = DeviceNetworkEvents
    | where TimeGenerated > ago(lookback)
    | where DeviceId in ((Staging | project DeviceId))
    | where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
    | summarize Destinations = make_set(strcat(coalesce(RemoteUrl, RemoteIP), ":", RemotePort), 10) by DeviceId, ProcessUniqueId = InitiatingProcessUniqueId;
let Files = DeviceFileEvents
    | where TimeGenerated > ago(lookback)
    | where DeviceId in ((Staging | project DeviceId))
    | where ActionType in ("FileCreated", "FileRenamed")
    | summarize FilesWritten = make_set(FolderPath, 10), FileHashes = make_set(SHA256, 10) by DeviceId, ProcessUniqueId = InitiatingProcessUniqueId;
Staging
| join kind=leftouter Net on DeviceId, ProcessUniqueId
| join kind=leftouter Files on DeviceId, ProcessUniqueId
| extend FromRmm = Parent in~ (RmmParents)
| project TimeGenerated, DeviceName, AccountName, FromRmm, GrandParent, Parent, FileName, ProcessCommandLine, Destinations, FilesWritten, FileHashes
| order by TimeGenerated asc
```

**Why this query:** It targets ingress tool transfer and execution, and proves each step with a second table.

- **Two entry routes:** children of RMM tools (ScreenConnect, AnyDesk, NetSupport run commands as children of their service) and download-shaped command lines from any parent (Quick Assist, where the operator types into the user's own shell).
- **Why the joins are built this way:** `leftouter` keeps a staging command even if it never connected (blocked by network protection, or it failed). The process-unique-id join ties the connection and the file to the exact process; a PID join would pick up unrelated processes that reused the number.
- **False positives:** software installers and update agents writing to `ProgramData`; developer `curl` downloads. Check `GrandParent` — `explorer.exe > powershell.exe` with a URL during a remote session is not an update.
- **Pivot next:** hashes in `FileHashes` and addresses in `Destinations` go to step 9; DLLs and executables written go to step 6.

#### Level 4 (Expert / L3)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp, baseline <= 30d.
// Download/execute command lines that are rare across the estate: shape seen on 2 devices or fewer in 30 days.
let baseline = 30d;
let recent = 1d;
let StagingBins = dynamic(["powershell.exe", "pwsh.exe", "cmd.exe", "curl.exe", "bitsadmin.exe", "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe"]);
let DownloadExec = @"(?i)(https?://|downloadstring|downloadfile|invoke-webrequest|\biwr\b|start-bitstransfer|-urlcache|/transfer\s|\biex\b|-enc)";
let Candidates = materialize(
    DeviceProcessEvents
    | where TimeGenerated > ago(baseline)
    | where FileName in~ (StagingBins)
    | where ProcessCommandLine matches regex DownloadExec
    // Replace GUIDs and numbers so per-device variants of one command collapse to one shape.
    | extend Shape = replace_regex(tolower(ProcessCommandLine), @"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d+", "#")
    | project TimeGenerated, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, Shape, InitiatingProcessFileName);
let Prevalence = Candidates | summarize Devices = dcount(DeviceId), FirstSeenInOrg = min(TimeGenerated) by Shape;
Candidates
| where TimeGenerated > ago(recent)
| join kind=inner Prevalence on Shape
| where Devices <= 2
| extend NewInOrg = FirstSeenInOrg > ago(recent),
         InteractiveParent = InitiatingProcessFileName in~ ("explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe")
| extend Score = 3 * toint(NewInOrg) + 2 * toint(InteractiveParent) + toint(ProcessCommandLine matches regex @"(?i)(-enc|frombase64string)") + toint(ProcessCommandLine matches regex @"(?i)\\(users\\public|programdata|appdata)\\")
| project TimeGenerated, Score, DeviceName, AccountName, InitiatingProcessFileName, FileName, Devices, NewInOrg, ProcessCommandLine
| order by Score desc, TimeGenerated asc
```

Advanced Hunting pivot (Defender portal only): global prevalence of the files written in Level 3.

```kql
// Advanced Hunting only (FileProfile is not available in Sentinel). Time column: Timestamp.
let lookback = 2d;
let target_device = "<device>";
DeviceFileEvents
| where Timestamp > ago(lookback)
| where DeviceName startswith target_device
| where ActionType == "FileCreated"
| where FolderPath matches regex @"(?i)\\(users\\public|programdata|appdata\\(local|roaming))\\"
| where FileName matches regex @"(?i)\.(exe|dll|ps1|bat|cmd|vbs|js|zip|7z)$"
| distinct SHA1, FileName, FolderPath
| invoke FileProfile("SHA1", 1000)
| project FileName, FolderPath, GlobalPrevalence, GlobalFirstSeen, Signer, SignatureState, ThreatName, SHA1
| order by GlobalPrevalence asc
```

**Why this query:**

- **Techniques:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1027 (Obfuscated Files or Information), T1218 (System Binary Proxy Execution) for `rundll32`/`regsvr32`/`mshta`.
- **Why rarity over a deny-list of strings:** attackers change URLs and file names per victim, but management tools run the same command shape on hundreds of devices. "Download-and-execute shape seen on two devices or fewer in 30 days" removes management noise without listing every agent.
- **Normalisation:** replacing digits and GUIDs collapses per-device variants of one script. Too aggressive and two different attacks collapse together; for a hunt this is acceptable.
- **Evasion:** downloads by a custom binary or via `msiexec /i https://...` (included); living-off-the-land through `winget` or Store apps; payload fetched by the RMM tool's own file-transfer feature (no command line at all — check `DeviceFileEvents` where `InitiatingProcessFileName` is the RMM tool).
- **Defender + Sentinel:** `FileProfile()` exists only in Advanced Hunting. Run the rarity query in Sentinel for the 30-day window, then pivot to Advanced Hunting for global prevalence and signer.
- **Cost:** the regex runs only on 10 binaries; 30 days is affordable hourly in most tenants.
- **As a scheduled rule:** frequency 1 hour, lookback 14 days with `recent = 1h`. Entities: Host, Account, Process command line. Severity High when `Score >= 4`.

#### Decision point

| Output | Call | Next |
|---|---|---|
| URL + execute from the user's shell or the RMM tool during the session; file written to a user folder | **True positive** | Isolate, collect the files (Live Response `getfile`), [HOK playbook](hok-playbook.md), step 6 |
| Encoded command from a management agent, many devices, daily | **False positive** | Allowlist the parent |
| Developer `curl` of a package, no execute, known site | **Benign true positive** | Note it |

---

### 6. DLL side-loading and persistence after the session

**Step goal:** What did the operator leave so they can come back without the user? Look for signed programs copied into user folders with a DLL beside them, and for run keys, tasks and services created after the session start.

`DeviceRegistryEvents` and `DeviceImageLoadEvents` are used in this step in addition to the core list.

#### Level 1 (Basic)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 2d;
let target_device = "<device>";
DeviceEvents
| where TimeGenerated > ago(lookback)
| where DeviceName startswith target_device
| where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated", "ServiceInstalled")
| project TimeGenerated, ActionType, AccountName = InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated asc
```

**Why this query:** It lists scheduled tasks and services created on the device. Any created after the remote session started deserve a look. Open `AdditionalFields`: it holds the task or service name and, for tasks, the command it runs.

#### Level 2 (Intermediate)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 2d;
let target_device = "<device>";
let UserPaths = @"(?i)\\(users\\[^\\]+\\appdata|users\\public|programdata|windows\\temp)\\";
union
    (DeviceEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceName startswith target_device
        | where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated", "ServiceInstalled")
        | extend AF = todynamic(AdditionalFields)
        | extend Name = coalesce(tostring(AF.TaskName), tostring(AF.ServiceName)),
                 TaskXml = tostring(AF.TaskContent)
        | extend Payload = iff(ActionType startswith "ScheduledTask",
                               strcat(extract(@"(?is)<Command>(.*?)</Command>", 1, TaskXml), " ", extract(@"(?is)<Arguments>(.*?)</Arguments>", 1, TaskXml)),
                               strcat(FolderPath, " ", tostring(AF.ServiceAccount), " ", tostring(AF.ServiceStartType)))   // VERIFY service field names
        | project TimeGenerated, Method = ActionType, Name, Payload, By = InitiatingProcessFileName),
    (DeviceRegistryEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceName startswith target_device
        | where ActionType == "RegistryValueSet"
        | where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Policies\Explorer\Run")
        | project TimeGenerated, Method = "Run key", Name = RegistryValueName, Payload = RegistryValueData, By = InitiatingProcessFileName)
| extend PointsToUserFolder = Payload matches regex UserPaths,
         ScriptHost = Payload matches regex @"(?i)(rundll32|regsvr32|mshta|wscript|cscript|powershell|cmd\.exe)"
| order by TimeGenerated asc
```

**Why this query:** It extracts what each persistence item actually runs.

- The task's `<Command>` and `<Arguments>` come out of the task XML with `extract`; the run key's value is the command.
- **Normal:** Windows, Office, browsers and your agents create tasks under `Program Files` constantly.
- **A hit:** `PointsToUserFolder` (something in `AppData`, `Public` or `ProgramData`) or `ScriptHost` (`rundll32` loading a DLL from `AppData`), created after the session start.

#### Level 3 (Advanced)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
// Side-loading: an executable in a user-writable folder loads a DLL from the same folder, both written recently.
// Then: does any persistence point at that folder?
let lookback = 3d;
let fresh = 1d;                 // how recently the files must have been written
let UserPaths = @"(?i)^c:\\(users\\[^\\]+\\appdata|users\\public|programdata|windows\\temp)\\";
let Dropped = materialize(
    DeviceFileEvents
    | where TimeGenerated > ago(fresh)
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FolderPath matches regex UserPaths
    | where FileName endswith ".dll" or FileName endswith ".exe"
    | extend Dir = tolower(tostring(parse_path(FolderPath).DirectoryPath))
    | summarize DroppedAt = min(TimeGenerated), Files = make_set(FileName, 20), Writers = make_set(InitiatingProcessFileName, 5) by DeviceId, Dir);
let SideLoads = DeviceImageLoadEvents
    | where TimeGenerated > ago(lookback)
    | where FolderPath matches regex UserPaths
    | where FileName endswith ".dll"
    | extend DllDir = tolower(tostring(parse_path(FolderPath).DirectoryPath)),
             ExeDir = tolower(tostring(parse_path(InitiatingProcessFolderPath).DirectoryPath))
    | where DllDir == ExeDir                                       // the program loads a DLL sitting beside it
    | summarize FirstLoad = min(TimeGenerated), Dlls = make_set(FileName, 10), DllHashes = make_set(SHA256, 10),
                Host = take_any(InitiatingProcessFileName), HostCompany = take_any(InitiatingProcessVersionInfoCompanyName)
                by DeviceId, DeviceName, Dir = DllDir;
let Persistence = union
    (DeviceRegistryEvents
        | where TimeGenerated > ago(lookback)
        | where ActionType == "RegistryValueSet"
        | where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Policies\Explorer\Run")
        | project DeviceId, PersistTime = TimeGenerated, Method = "Run key", Payload = tolower(RegistryValueData)),
    (DeviceEvents
        | where TimeGenerated > ago(lookback)
        | where ActionType in ("ScheduledTaskCreated", "ServiceInstalled")
        | project DeviceId, PersistTime = TimeGenerated, Method = ActionType, Payload = tolower(strcat(tostring(todynamic(AdditionalFields).TaskContent), " ", FolderPath)));
SideLoads
| join kind=inner Dropped on DeviceId, Dir
| join kind=leftouter (Persistence) on DeviceId
| extend PersistsHere = isnotempty(Payload) and indexof(Payload, Dir) >= 0
| summarize FirstLoad = min(FirstLoad), Host = take_any(Host), HostCompany = take_any(HostCompany), Dlls = take_any(Dlls), DllHashes = take_any(DllHashes),
            Files = take_any(Files), Writers = take_any(Writers), DroppedAt = min(DroppedAt),
            PersistMethods = make_set_if(Method, PersistsHere, 5), PersistedAt = minif(PersistTime, PersistsHere)
            by DeviceName, Dir
| extend Persisted = array_length(PersistMethods) > 0
| order by Persisted desc, FirstLoad asc
```

**Why this query:** It targets the pattern used by many of these intrusions: copy a legitimately signed program (often a Microsoft, Teams or OneDrive binary) into `AppData`, put a malicious DLL with the name it expects beside it, and register the program to start at logon.

- **Why the joins are built this way:** `inner` with `Dropped` keeps only folders whose files were written recently — old installs in `AppData` (Teams, Zoom) drop out. `leftouter` with `Persistence` keeps side-loads that have no persistence yet, and `PersistsHere` checks whether any persistence item names the folder.
- `HostCompany` showing "Microsoft Corporation" for a binary in `AppData\Local\Temp\x\` is the tell: the signed host is real, the folder is not where it belongs.
- **False positives:** per-user installers (Teams, Zoom, Slack, browsers) load their own DLLs from `AppData`. They are written once at install and updated by the vendor's updater (`Writers`). A host written by `powershell.exe` or `curl.exe` minutes after a remote session is not an install.
- **Pivot next:** `DllHashes` to step 9 and to the Level 4 prevalence check; persistence entries go into eradication.

#### Level 4 (Expert / L3)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp, baseline <= 30d.
// DLLs loaded from user-writable folders whose hash is new to the estate and seen on very few devices.
let baseline = 30d;
let recent = 1d;
let UserPaths = @"(?i)^c:\\(users\\[^\\]+\\appdata|users\\public|programdata|windows\\temp)\\";
let Loads = materialize(
    DeviceImageLoadEvents
    | where TimeGenerated > ago(baseline)
    | where FolderPath matches regex UserPaths
    | where FileName endswith ".dll"
    | project TimeGenerated, DeviceId, DeviceName, FileName, FolderPath, SHA256, Host = InitiatingProcessFileName, HostCompany = InitiatingProcessVersionInfoCompanyName, HostFolder = InitiatingProcessFolderPath);
let Prevalence = Loads | summarize Devices = dcount(DeviceId), FirstSeenInOrg = min(TimeGenerated) by SHA256;
Loads
| where TimeGenerated > ago(recent)
| join kind=inner Prevalence on SHA256
| where Devices <= 3 and FirstSeenInOrg > ago(recent)
| extend SameFolder = tostring(parse_path(FolderPath).DirectoryPath) =~ tostring(parse_path(HostFolder).DirectoryPath),
         SignedVendorHost = HostCompany has_any ("Microsoft", "Google", "Adobe", "Zoom", "Cisco", "Citrix")    // a trusted name in a user folder
| extend Score = 2 * toint(SameFolder) + 2 * toint(SignedVendorHost) + toint(Devices == 1)
| summarize FirstLoad = min(TimeGenerated), Score = max(Score), Devices = max(Devices), Hosts = make_set(Host, 5), Folders = make_set(FolderPath, 5) by DeviceName, FileName, SHA256
| order by Score desc, FirstLoad asc
```

**Why this query:**

- **Techniques:** T1574.002 (DLL Side-Loading), T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task), T1543.003 (Windows Service).
- **Why hash prevalence:** a side-loaded payload is usually unique to the victim or campaign; legitimate per-user DLLs exist on hundreds of devices. "New to the estate today and on three devices or fewer" removes nearly all installer noise.
- **Thresholds:** `Devices <= 3` allows for the same payload on a few victims in one campaign. `SignedVendorHost` uses the company name in the version info. That is not a signature check: version info can be forged. Confirm signing with `FileProfile()` in Advanced Hunting (step 5 pivot) or `DeviceFileCertificateInfo` // VERIFY that table is enabled in your connector.
- **Evasion:** DLLs loaded from a folder outside the regex (`C:\Intel\`, `C:\Users\x\Music\`); reflective loading (no image-load event); payloads that reuse a common legitimate hash name with different content (the hash catches it).
- **Cost:** `DeviceImageLoadEvents` is one of the largest tables. Filtering on folder first is essential; consider 14 days if 30 is slow.
- **As a scheduled rule:** frequency 1 hour, lookback 14 days, `recent = 1h`. Entities: Host, File hash, File name. Severity High when `Score >= 4`.

#### Decision point

| Output | Call | Next |
|---|---|---|
| Signed host in a user folder, fresh DLL beside it, run key or task pointing there, after the session | **True positive** | Collect the folder (Live Response), block the hashes, record persistence for eradication, step 7 |
| Per-user app (Teams, Zoom) updated by its updater | **False positive** | Note the updater as a known writer |
| Task created by the user's own admin script with a ticket | **Benign true positive** | Note it |

---

### 7. Lateral movement towards domain controllers and high-value servers

**Step goal:** Did the operator leave the workstation? Which servers did it connect to over admin protocols, and did those servers record a logon or a remote execution from it?

#### Level 1 (Basic)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 2d;
let target_device = "<device>";
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where DeviceName startswith target_device
| where RemoteIPType == "Private"
| where RemotePort in (135, 445, 3389, 5985, 5986, 22)
| project TimeGenerated, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated asc
```

**Why this query:** It lists connections from the user's computer to other company machines on the ports used for remote administration: file shares (445), remote desktop (3389), PowerShell remoting (5985/5986), RPC (135) and SSH (22). A normal user's PC talks to file servers on 445 all day; it rarely opens remote desktop or PowerShell remoting to a server.

#### Level 2 (Intermediate)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 2d;
let target_device = "<device>";
let HighValue = dynamic(["dc01", "dc02", "fs01", "sql01"]);   // short names; better: a watchlist
let IpToName = DeviceNetworkInfo
    | where TimeGenerated > ago(lookback)
    | mv-expand Addr = todynamic(IPAddresses)
    | extend IP = tostring(Addr.IPAddress)
    | where isnotempty(IP)
    | summarize Name = take_any(DeviceName) by IP;
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where DeviceName startswith target_device
| where RemoteIPType == "Private" and RemotePort in (135, 445, 3389, 5985, 5986, 22)
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt", "ConnectionFailed")
| join kind=leftouter IpToName on $left.RemoteIP == $right.IP
| extend Target = coalesce(Name, RemoteIP)
| summarize First = min(TimeGenerated), Last = max(TimeGenerated), Connections = count(), Ports = make_set(RemotePort, 6), Processes = make_set(InitiatingProcessFileName, 6)
            by Target, Hour = bin(TimeGenerated, 1h)
| extend HighValueTarget = tostring(split(Target, ".")[0]) in~ (HighValue)
| order by HighValueTarget desc, First asc
```

**Why this query:** It turns raw connections into "which machine, on which ports, by which program, per hour", with addresses resolved to names from `DeviceNetworkInfo`.

- **Normal:** `System` (kernel SMB) to file servers on 445; `svchost.exe` to domain controllers.
- **A hit:** `mstsc.exe`, `powershell.exe`, `wsmprovhost.exe`, `psexec.exe` or an unknown binary reaching a domain controller or many servers in one hour after the session.

#### Level 3 (Advanced)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
// Both ends: what the source connected to, and what each target recorded — logons and remote execution.
let lookback = 3d;
let target_device = "<device>";
let AdminPorts = dynamic([135, 445, 3389, 5985, 5986, 22]);
let HighValue = dynamic(["fs01", "sql01"]);                   // or: _GetWatchlist('HighValueAssets') | project SearchKey
// Source device addresses.
let SrcIPs = DeviceNetworkEvents
    | where TimeGenerated > ago(lookback)
    | where DeviceName startswith target_device
    | where isnotempty(LocalIP) and LocalIP !startswith "127." and LocalIP != "::1"
    | distinct LocalIP;
// Domain controllers found from telemetry: devices accepting both Kerberos (88) and LDAP (389).
let DCList = toscalar(
    DeviceNetworkEvents
    | where TimeGenerated > ago(lookback)
    | where ActionType == "InboundConnectionAccepted" and LocalPort in (88, 389)
    | summarize Ports = dcount(LocalPort) by DeviceName
    | where Ports == 2
    | summarize make_set(DeviceName, 500));
let TargetLogons = DeviceLogonEvents
    | where TimeGenerated > ago(lookback)
    | where RemoteIP in ((SrcIPs))
    | where ActionType == "LogonSuccess" and LogonType in ("Network", "RemoteInteractive")
    | project TimeGenerated, Target = DeviceName, Side = "Target logon", Evidence = strcat(LogonType, " as ", AccountDomain, "\\", AccountName, " from ", RemoteIP);
let Targets = TargetLogons | distinct Target;
union
    (TargetLogons),
    // Remote execution artefacts on the targets: PsExec-style services and WinRM sessions.
    (DeviceEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceName in ((Targets))
        | where ActionType == "ServiceInstalled"
        | extend ServiceName = tostring(todynamic(AdditionalFields).ServiceName)
        | where ServiceName has_any ("PSEXESVC", "PAExec", "RemCom") or FolderPath matches regex @"(?i)\\(admin\$|windows\\temp|programdata)\\"
        | project TimeGenerated, Target = DeviceName, Side = "Target service", Evidence = strcat(ServiceName, " | ", FolderPath)),
    (DeviceProcessEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceName in ((Targets))
        | where InitiatingProcessFileName =~ "wsmprovhost.exe"
        | project TimeGenerated, Target = DeviceName, Side = "Target WinRM", Evidence = strcat(AccountName, " ran ", ProcessCommandLine)),
    // The source side: admin-port connections that succeeded, and tools that move laterally.
    (DeviceNetworkEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceName startswith target_device
        | where RemoteIPType == "Private" and RemotePort in (AdminPorts) and ActionType == "ConnectionSuccess"
        | summarize First = min(TimeGenerated), Connections = count() by RemoteIP, RemotePort, InitiatingProcessFileName
        | project TimeGenerated = First, Target = RemoteIP, Side = "Source connection", Evidence = strcat(InitiatingProcessFileName, " > ", RemoteIP, ":", RemotePort, " x", Connections)),
    (DeviceProcessEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceName startswith target_device
        | where FileName in~ ("psexec.exe", "psexec64.exe", "paexec.exe", "mstsc.exe", "wmic.exe", "winrs.exe") or ProcessCommandLine matches regex @"(?i)(invoke-command|enter-pssession|new-pssession|\\\\[^\\]+\\(admin|c)\$)"
        | project TimeGenerated, Target = "(see command)", Side = "Source tool", Evidence = ProcessCommandLine)
| extend IsDC = Target in (DCList), IsHighValue = tostring(split(Target, ".")[0]) in~ (HighValue)
| order by TimeGenerated asc
```

**Why this query:** It targets lateral movement with remote services (T1021) and service execution (T1569.002), confirmed from the receiving end.

- **Why both ends:** the source shows intent (a connection on 445); the target shows success (a logon, a `PSEXESVC` service, a WinRM process). A connection with no target logon is an attempt.
- **Why derive DCs from telemetry:** naming conventions lie and watchlists go stale. Any device that accepts Kerberos and LDAP is acting as a domain controller.
- **False positives:** the user's machine mapping drives (Network logons to file servers — expected); IT admins working from this device (check whose account logged on).
- **Pivot next:** every `Target` gets the same treatment as the first device: steps 4–6 and the [HOK playbook](hok-playbook.md).

#### Level 4 (Expert / L3)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp, baseline <= 30d.
// Admin-port paths (source device -> destination -> port) never used in the last 30 days, with fan-out and DC reach.
let baseline = 30d;
let recent = 1d;
let AdminPorts = dynamic([135, 445, 3389, 5985, 5986, 22]);
let DCList = toscalar(
    DeviceNetworkEvents
    | where TimeGenerated > ago(7d)
    | where ActionType == "InboundConnectionAccepted" and LocalPort in (88, 389)
    | summarize Ports = dcount(LocalPort) by DeviceName
    | where Ports == 2
    | summarize make_set(DeviceName, 500));
let IpToName = DeviceNetworkInfo
    | where TimeGenerated > ago(7d)
    | mv-expand Addr = todynamic(IPAddresses)
    | extend IP = tostring(Addr.IPAddress)
    | where isnotempty(IP)
    | summarize Name = take_any(DeviceName) by IP;
let Conns = materialize(
    DeviceNetworkEvents
    | where TimeGenerated > ago(baseline)
    | where RemoteIPType == "Private" and RemotePort in (AdminPorts)
    | where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
    | where InitiatingProcessFileName !in~ ("system", "svchost.exe")              // background SMB and RPC
    | project TimeGenerated, DeviceId, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName);
let Known = Conns | where TimeGenerated <= ago(recent) | distinct DeviceId, RemoteIP, RemotePort;
Conns
| where TimeGenerated > ago(recent)
| join kind=leftanti Known on DeviceId, RemoteIP, RemotePort
| join kind=leftouter IpToName on $left.RemoteIP == $right.IP
| extend Target = coalesce(Name, RemoteIP)
| summarize FirstSeen = min(TimeGenerated), NewTargets = dcount(RemoteIP), Targets = make_set(Target, 25), Ports = make_set(RemotePort, 6), Processes = make_set(InitiatingProcessFileName, 6)
            by DeviceName
| extend TouchesDC = array_length(set_intersect(Targets, DCList)) > 0,
         RemoteShellPorts = set_has_element(Ports, 3389) or set_has_element(Ports, 5985) or set_has_element(Ports, 5986)
| extend Score = 3 * toint(TouchesDC) + 2 * toint(NewTargets >= 5) + 2 * toint(RemoteShellPorts) + toint(NewTargets >= 2)
| where Score >= 3
| order by Score desc
```

**Why this query:**

- **Techniques:** T1021.001 (RDP), T1021.002 (SMB/Admin Shares), T1021.006 (WinRM), T1569.002 (Service Execution), T1046 (Network Service Discovery) for fan-out.
- **Why first-seen paths:** workstations have stable admin-port habits (their file servers, their print server). A workstation that opens RDP or WinRM to a domain controller for the first time in 30 days is rare everywhere. Excluding `System` and `svchost.exe` removes most SMB and RPC background noise at the cost of missing kernel-level SMB copies — `DeviceLogonEvents` on the targets (Level 3) covers that gap.
- **Evasion:** movement over HTTPS tunnels or the RMM tool itself (no admin port); using a server the device already talks to; credential use from a different device (look at `IdentityLogonEvents` if Defender for Identity is deployed).
- **Cost:** admin-port traffic for 30 days across the estate is the heaviest query in this playbook. Filter ports first, as written; run every 1–2 hours; drop to 14 days if needed.
- **As a scheduled rule:** frequency 1 hour, lookback 14 days with `recent = 1h`. Entities: Host → `DeviceName` (source), Host → `Targets` (destination). Severity High when `TouchesDC`.

#### Decision point

| Output | Call | Next |
|---|---|---|
| Logons or remote execution on servers or DCs from the victim device after the session | **True positive** | Isolate the targets, reset the accounts used, extend the [HOK playbook](hok-playbook.md) to each target |
| Connections only, no target logons | **True positive — attempt** | Check the targets anyway; block the source |
| Drive mappings to the user's usual file servers | **False positive** | — |
| An IT admin working from this device, with a ticket | **Benign true positive** | Confirm with the admin |

---

### 8. Data staging and exfiltration

**Step goal:** Did data leave? Find the archives, the upload tool (often Rclone, sometimes renamed) and where it sent the data.

> **Escalate:** exfiltration, shadow-copy deletion or encryption → Ransomware (endpoint) playbook *(not yet in this handbook)*.

#### Level 1 (Basic)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 7d;
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where FileName =~ "rclone.exe" or ProcessVersionInfoOriginalFileName =~ "rclone.exe" or ProcessVersionInfoProductName =~ "Rclone"
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```

**Why this query:** Rclone is a free tool that copies files to cloud storage. It has legitimate uses, but on a user's workstation after a remote session it is almost always data theft. The original file name and product name catch it even when renamed. In `ProcessCommandLine`, look for `copy` or `sync` and a destination such as `mega:` or `s3:`.

#### Level 2 (Intermediate)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 7d;
let RclonePattern = @"(?i)\s(copy|sync|move)\s.*\s(--transfers|--multi-thread-streams|--max-age|--ignore-existing|--no-check-certificate|--config)\b";
let ArchivePattern = @"(?i)(\b(7z|7za|7zr|rar|winrar)(\.exe)?\s+a\s|compress-archive|tar(\.exe)?\s+-?c|makecab)";
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| extend IsRclone = FileName =~ "rclone.exe" or ProcessVersionInfoOriginalFileName =~ "rclone.exe" or ProcessVersionInfoProductName =~ "Rclone" or ProcessCommandLine matches regex RclonePattern,
         IsArchive = ProcessCommandLine matches regex ArchivePattern
| where IsRclone or IsArchive
| extend Renamed = IsRclone and FileName !~ "rclone.exe"
| summarize First = min(TimeGenerated), Last = max(TimeGenerated), Runs = count(), Archives = countif(IsArchive), Uploads = countif(IsRclone), AnyRenamed = max(toint(Renamed)),
            Commands = make_set(ProcessCommandLine, 20)
            by DeviceName, AccountName
| order by Uploads desc, Archives desc
```

**Why this query:** It catches the two halves of theft — packing (7-Zip, WinRAR, `tar`, `Compress-Archive`) and shipping (Rclone, even renamed, by its distinctive flags).

- `AnyRenamed = 1` means Rclone ran under another name: someone was hiding it.
- **Normal:** developers and backup jobs use `tar` and 7-Zip; IT may use Rclone on servers.
- **A hit:** archives in `C:\Users\Public` or `ProgramData` followed by Rclone with a cloud destination, on the victim's device or a server it reached in step 7.

#### Level 3 (Advanced)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
// One timeline per device: archives written, upload tools run, connections to cloud storage — joined on the process.
let lookback = 7d;
let target_device = "<device>";
let StorageDomains = dynamic(["mega.nz", "mega.co.nz", "mega.io", "dropboxapi.com", "dropbox.com", "s3.amazonaws.com", "backblazeb2.com", "storage.googleapis.com", "drive.google.com", "box.com", "pcloud.com", "gofile.io", "transfer.sh", "temp.sh", "anonfiles.com", "sendspace.com"]);
let UploadTools = @"(?i)^(rclone|restic|megacmd|mega-put|megasync|winscp|pscp|psftp|filezilla|curl|azcopy|aws|gsutil)(\.exe)?$";
let ArchivePattern = @"(?i)\.(zip|7z|rar|tar|gz|cab)$";
union
    (DeviceFileEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceName startswith target_device
        | where ActionType in ("FileCreated", "FileModified") and FileName matches regex ArchivePattern
        | project TimeGenerated, Stage = "1-Archive", Process = InitiatingProcessFileName, Detail = strcat(FolderPath, " (", format_bytes(FileSize, 1), ")")),
    (DeviceProcessEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceName startswith target_device
        | where FileName matches regex UploadTools or ProcessVersionInfoProductName =~ "Rclone"
        | project TimeGenerated, Stage = "2-Upload tool", Process = FileName, Detail = ProcessCommandLine),
    (DeviceNetworkEvents
        | where TimeGenerated > ago(lookback)
        | where DeviceName startswith target_device
        | where RemoteUrl has_any (StorageDomains)
        | summarize First = min(TimeGenerated), Connections = count(), Until = max(TimeGenerated) by Process = InitiatingProcessFileName, RemoteUrl
        | project TimeGenerated = First, Stage = "3-Cloud storage", Process, Detail = strcat(RemoteUrl, " x", Connections, " until ", format_datetime(Until, "yyyy-MM-dd HH:mm")))
| order by TimeGenerated asc
```

**Why this query:** It targets archive-then-upload (T1560.001 then T1567.002) as one ordered story on one device.

- **Why `union`, not `join`:** the three stages are often run by different processes (7-Zip writes, Rclone reads and uploads), so a process join would break the chain. Time order is the link.
- `format_bytes(FileSize, 1)` shows archive sizes. Large archives in a user folder, then a storage connection by an upload tool, is the finding.
- **Blind spot:** **Defender for Endpoint records connections, not bytes.** How much left is not in these tables. Use the firewall or proxy (`CommonSecurityLog`, Level 4) or the cloud provider for volume.
- **False positives:** OneDrive or Dropbox sync clients (process names `OneDrive.exe`, `Dropbox.exe`) — expected; browser downloads from Google Drive.
- **Pivot next:** destinations and hashes to step 9; a confirmed upload means legal and privacy notification processes start.

#### Level 4 (Expert / L3)

```kql
// Sentinel only (CommonSecurityLog). Requires a firewall or proxy that reports SentBytes over CEF.
// Outbound volume per internal source address as a time series; flags hours far above that source's normal.
let baseline = 14d;
let step = 1h;
let min_mb = 500.0;             // ignore anomalies under this many MB in an hour
let Candidates = CommonSecurityLog
    | where TimeGenerated > ago(1d)
    | where SentBytes > 0
    | where ipv4_is_private(SourceIP) and not(ipv4_is_private(DestinationIP))
    | summarize SentMB = sum(SentBytes) / 1048576.0 by SourceIP, bin(TimeGenerated, step)
    | where SentMB >= min_mb
    | distinct SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(baseline)
| where SourceIP in ((Candidates))
| where SentBytes > 0 and not(ipv4_is_private(DestinationIP))
| make-series Sent = sum(SentBytes) default = 0 on TimeGenerated from ago(baseline) to now() step step by SourceIP
| extend (Anomaly, Score, Expected) = series_decompose_anomalies(Sent, 3.0, -1, "linefit")
| mv-expand TimeGenerated to typeof(datetime), Sent to typeof(long), Anomaly to typeof(int), Score to typeof(double), Expected to typeof(double)
| where TimeGenerated > ago(1d) and Anomaly == 1
| extend SentMB = round(Sent / 1048576.0, 0), ExpectedMB = round(Expected / 1048576.0, 0)
| where SentMB >= min_mb
| project TimeGenerated, SourceIP, SentMB, ExpectedMB, Score = round(Score, 1)
| order by Score desc
```

**Why this query:**

- **Techniques:** T1567.002 (Exfiltration to Cloud Storage), T1048 (Exfiltration Over Alternative Protocol), T1030 (Data Transfer Size Limits — Rclone's chunking keeps each transfer small, which is why volume per hour matters more than per connection).
- **Why a series per source:** a backup server sends terabytes every night and a laptop sends megabytes. A single byte threshold fires on one and misses the other. `series_decompose_anomalies` judges each source against its own hourly and daily pattern.
- **Why `CommonSecurityLog`:** Defender for Endpoint does not record bytes. If you have no CEF firewall, the closest fallback is a series of **connection counts** per device to `StorageDomains` from `DeviceNetworkEvents` — weaker, but it catches Rclone's many parallel connections.
- **Evasion:** slow exfiltration below the baseline over days; exfiltration through the RMM tool's file transfer (traffic to the RMM vendor, which looks normal in volume); uploads through a proxy that NATs every source to one address.
- **Cost:** firewall logs are large. `Candidates` limits the series to sources that sent 500 MB+ in an hour today. `ipv4_is_private` skips IPv6 — add an IPv6 condition if your egress is IPv6.
- **As a scheduled rule:** frequency 1 hour, lookback 14 days. Entities: IP → `SourceIP` (map to a host with `DeviceNetworkInfo`). Severity Medium; High if the source is a device from this incident.

#### Decision point

| Output | Call | Next |
|---|---|---|
| Archive in a user folder, then Rclone or another upload tool to cloud storage | **True positive — exfiltration** | Ransomware (endpoint) playbook, legal/privacy, block the destinations, preserve the Rclone config file (`rclone.conf`) |
| Archive only, no upload seen | **True positive — staging** | Check firewall/proxy for volume; keep looking |
| OneDrive / Dropbox sync client, normal volume | **False positive** | — |
| IT backup with Rclone on a server, scheduled, known destination | **Benign true positive** | Allowlist by server and destination |

---

### 9. Scope the campaign

**Step goal:** Who else was targeted or compromised? Find other recipients of the same external tenant, other users who received the flood, other devices with the same tool, hashes or destinations.

#### Level 1 (Basic)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
let lookback = 14d;
let attacker_domain = "contoso-helpdesk.onmicrosoft.com";
MessageEvents
| where TimeGenerated > ago(lookback)
| where SenderEmailAddress endswith attacker_domain
| mv-expand Rcpt = RecipientDetails
| project TimeGenerated, SenderDisplayName, SenderEmailAddress, Recipient = tostring(Rcpt.RecipientSmtpAddress), DeliveryAction
| order by TimeGenerated asc
```

**Why this query:** It lists everyone in the company who got a Teams message from the attacker's domain. Each `Recipient` needs a call: did they reply, accept a call, or open a remote session?

#### Level 2 (Intermediate)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp (CallActivityEvents: ActivityTimestamp, VERIFY).
let lookback = 14d;
let attacker_domains = dynamic(["contoso-helpdesk.onmicrosoft.com"]);
union isfuzzy=true
    (MessageEvents
        | where TimeGenerated > ago(lookback)
        | where tostring(split(SenderEmailAddress, "@")[1]) in~ (attacker_domains)
        | mv-expand Rcpt = RecipientDetails
        | project TimeGenerated, Kind = "Message", External = SenderEmailAddress, Target = tolower(tostring(Rcpt.RecipientSmtpAddress))),
    (CallActivityEvents
        | where TimeGenerated > ago(lookback)
        | where tostring(split(OriginatorUpn, "@")[1]) in~ (attacker_domains)
        | project TimeGenerated, Kind = strcat("Call ", ActivityType, " ", ActivityStatus), External = OriginatorUpn, Target = tolower(ActivityRecipientUpn))
| where isnotempty(Target)
| summarize First = min(TimeGenerated), Last = max(TimeGenerated), Contacts = count(), Kinds = make_set(Kind, 10), Senders = make_set(External, 10) by Target
| extend WasCalled = tostring(Kinds) has "Call"
| order by WasCalled desc, First asc
```

**Why this query:** One row per targeted user, with whether they were only messaged or also called. Users who were called go to the top: a call is the step before a remote session. The attacker often rotates sender accounts inside one tenant, so scope by **domain**, not by sender address.

#### Level 3 (Advanced)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
// Every entity touched by any indicator from this incident, with the signals that touched it.
let lookback = 14d;
let attacker_domains = dynamic(["contoso-helpdesk.onmicrosoft.com"]);
let ioc_hashes = dynamic(["<sha256-1>", "<sha256-2>"]);
let ioc_ips = dynamic(["203.0.113.10"]);
let ioc_urls = dynamic(["payload.example.net"]);
let rmm_tool = @"(?i)^(anydesk|screenconnect\.[a-z.]+|client32)\.exe$";      // the tool used in this incident
let flood_min = 50;
union isfuzzy=true
    (MessageEvents
        | where TimeGenerated > ago(lookback)
        | where tostring(split(SenderEmailAddress, "@")[1]) in~ (attacker_domains)
        | mv-expand Rcpt = RecipientDetails
        | project TimeGenerated, Entity = tolower(tostring(Rcpt.RecipientSmtpAddress)), EntityType = "User", Signal = "Teams contact"),
    (EmailEvents
        | where TimeGenerated > ago(lookback)
        | where EmailDirection == "Inbound"
        | summarize Emails = count(), Senders = dcount(SenderFromDomain) by Entity = tolower(RecipientEmailAddress), bin(TimeGenerated, 15m)
        | where Emails >= flood_min and Senders >= 20
        | project TimeGenerated, Entity, EntityType = "User", Signal = "Mail flood"),
    (DeviceProcessEvents
        | where TimeGenerated > ago(lookback)
        | where SHA256 in (ioc_hashes) or FileName matches regex rmm_tool
        | project TimeGenerated, Entity = DeviceName, EntityType = "Device", Signal = iff(SHA256 in (ioc_hashes), "IOC hash executed", "Same RMM tool")),
    (DeviceFileEvents
        | where TimeGenerated > ago(lookback)
        | where SHA256 in (ioc_hashes)
        | project TimeGenerated, Entity = DeviceName, EntityType = "Device", Signal = "IOC hash on disk"),
    (DeviceNetworkEvents
        | where TimeGenerated > ago(lookback)
        | where RemoteIP in (ioc_ips) or RemoteUrl has_any (ioc_urls)
        | project TimeGenerated, Entity = DeviceName, EntityType = "Device", Signal = "IOC destination")
| summarize First = min(TimeGenerated), Last = max(TimeGenerated), Signals = make_set(Signal, 10), Events = count() by Entity, EntityType
| extend SignalCount = array_length(Signals)
| order by SignalCount desc, First asc
```

**Why this query:** It turns the incident's indicators into a list of every user and device they touched, and how many different ways.

- **Why one union with `Signal` labels:** a user with "Mail flood" + "Teams contact" is a target; a device with "Same RMM tool" + "IOC hash executed" is compromised. Counting distinct signals ranks who to handle first.
- **False positives:** "Same RMM tool" on devices where IT legitimately uses that tool; "Mail flood" on shared mailboxes.
- **Pivot next:** each device with an execution or destination signal runs steps 4–8; each targeted user gets a call and, if they accepted a session, step 3.

#### Level 4 (Expert / L3)

```kql
// Sentinel, several workspaces (MSSP or multi-region). The same scope across workspaces, scored per user.
// In the Defender portal with several workspaces onboarded, Advanced Hunting can query each workspace the same way. // VERIFY
let lookback = 14d;
let attacker_domains = dynamic(["contoso-helpdesk.onmicrosoft.com"]);
let flood_min = 50;
let Teams = union isfuzzy=true
        workspace("<workspace-a>").MessageEvents,
        workspace("<workspace-b>").MessageEvents
    | where TimeGenerated > ago(lookback)
    | where tostring(split(SenderEmailAddress, "@")[1]) in~ (attacker_domains)
    | mv-expand Rcpt = RecipientDetails
    | summarize FirstContact = min(TimeGenerated) by User = tolower(tostring(Rcpt.RecipientSmtpAddress));
let Floods = union isfuzzy=true
        workspace("<workspace-a>").EmailEvents,
        workspace("<workspace-b>").EmailEvents
    | where TimeGenerated > ago(lookback)
    | where EmailDirection == "Inbound"
    | summarize Emails = count(), Senders = dcount(SenderFromDomain) by User = tolower(RecipientEmailAddress), Window = bin(TimeGenerated, 15m)
    | where Emails >= flood_min and Senders >= 20
    | summarize FloodStart = min(Window) by User;
let Sessions = union isfuzzy=true
        workspace("<workspace-a>").DeviceProcessEvents,
        workspace("<workspace-b>").DeviceProcessEvents
    | where TimeGenerated > ago(lookback)
    | where FileName in~ ("quickassist.exe", "anydesk.exe", "screenconnect.windowsclient.exe", "client32.exe", "teamviewer.exe")
    | where isnotempty(AccountUpn)
    | summarize FirstRmm = min(TimeGenerated), Devices = make_set(DeviceName, 5) by User = tolower(AccountUpn);
Teams
| join kind=leftouter Floods on User
| join kind=leftouter Sessions on User
| extend FloodBefore = isnotnull(FloodStart) and FloodStart <= FirstContact,
         RmmAfter = isnotnull(FirstRmm) and FirstRmm between (FirstContact .. FirstContact + 1d)
| extend Priority = case(RmmAfter, "1 - Session opened", FloodBefore, "2 - Flooded and contacted", "3 - Contacted")
| project Priority, User, FirstContact, FloodStart, FirstRmm, Devices
| order by Priority asc, FirstContact asc
```

**Why this query:**

- **Techniques:** scope for T1566.004 and T1219 across the whole target population.
- **Why cross-workspace:** campaigns hit every tenant a provider manages, and large companies split regions into workspaces. `workspace()` runs one query across them; `isfuzzy=true` keeps going if one workspace lacks a table.
- **Why priority bands, not a score:** the actions differ by band — band 1 needs an incident and isolation, band 2 needs a phone call now, band 3 needs a warning. A numeric score hides that.
- **Blind spots:** `AccountUpn` is empty for some local and service processes, so a session started as SYSTEM (ScreenConnect) shows no user; join through `DeviceLogonEvents` (step 3 Level 3) for those. Users contacted on personal phones or WhatsApp are invisible.
- **Cost:** cross-workspace queries multiply cost by the number of workspaces and are limited (100 workspaces per query). Keep the lookback tight.
- **As a scheduled rule:** not recommended cross-workspace. Use it as a saved hunting query during campaigns; deploy step 2 Level 4 as the per-workspace rule.

#### Decision point

| Output | Call | Next |
|---|---|---|
| Other users contacted by the same tenant | **True positive — campaign** | Warn each user by phone; block the domain tenant-wide (step 10) |
| Other devices with the hash, RMM tool or destination | **True positive — more victims** | Open a linked incident per device; run steps 3–8 |
| Same RMM tool, sanctioned, no other signal | **False positive** | — |

---

### 10. Contain

**Step goal:** Cut every route the attacker has: the external tenant, the device, the user's sessions, the remote tool, and the policies that let the call happen. Then prove each one is holding.

The actions are under [Containment and eradication](#containment-and-eradication). The queries here verify them.

#### Level 1 (Basic)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
// Has the blocked domain reached anyone since the block?
let blocked_at = datetime(2026-10-28T12:00:00Z);
let blocked_domain = "contoso-helpdesk.onmicrosoft.com";
MessageEvents
| where TimeGenerated > blocked_at
| where SenderEmailAddress endswith blocked_domain
| project TimeGenerated, SenderDisplayName, SenderEmailAddress, DeliveryAction, RecipientDetails
```

**Why this query:** After you block the attacker's domain in Teams, this should return **nothing**. Any row means the block is not working, is not yet applied, or the attacker moved to a new domain (re-run step 2).

#### Level 2 (Intermediate)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp.
// Remote tools still running or calling home anywhere, after removal.
let removed_at = datetime(2026-10-28T13:00:00Z);
let RmmPattern = @"(?i)^(anydesk|screenconnect\.[a-z.]+|client32|rustdesk)\.exe$";     // the tools you removed
let RmmDomains = dynamic(["anydesk.com", "screenconnect.com", "netsupportsoftware.com", "rustdesk.com"]);
union
    (DeviceProcessEvents
        | where TimeGenerated > removed_at
        | where FileName matches regex RmmPattern
        | project TimeGenerated, DeviceName, Evidence = strcat("process ", FileName, " ", FolderPath)),
    (DeviceNetworkEvents
        | where TimeGenerated > removed_at
        | where RemoteUrl has_any (RmmDomains)
        | project TimeGenerated, DeviceName, Evidence = strcat("network ", InitiatingProcessFileName, " > ", RemoteUrl))
| summarize Last = max(TimeGenerated), Events = count(), Evidence = make_set(Evidence, 5) by DeviceName
```

**Why this query:** It checks that the removed remote tools are really gone across the estate, not only on the first device. Expected result: empty. A row means a copy survived (another user profile, a service, a scheduled reinstall) or another device is involved.

#### Level 3 (Advanced)

```kql
// Sentinel. Advanced Hunting: TimeGenerated -> Timestamp (CallActivityEvents: ActivityTimestamp, VERIFY).
// One row per control: Holding / FAILING for blocks, Done / NOT DONE for one-off actions.
let contained_at = datetime(2026-10-28T12:00:00Z);
let target_user = "user@contoso.com";
let blocked_domains = dynamic(["contoso-helpdesk.onmicrosoft.com"]);
let ioc_hashes = dynamic(["<sha256-1>"]);
let RmmPattern = @"(?i)^(anydesk|screenconnect\.[a-z.]+|client32)\.exe$";
union isfuzzy=true
    (MessageEvents
        | where TimeGenerated > contained_at
        | where tostring(split(SenderEmailAddress, "@")[1]) in~ (blocked_domains)
        | summarize Hits = count(), Last = max(TimeGenerated) | extend Control = "Teams messages from blocked domain", Expect = "none"),
    (CallActivityEvents
        | where TimeGenerated > contained_at
        | where tostring(split(OriginatorUpn, "@")[1]) in~ (blocked_domains)
        | summarize Hits = count(), Last = max(TimeGenerated) | extend Control = "Teams calls from blocked domain", Expect = "none"),
    (DeviceProcessEvents
        | where TimeGenerated > contained_at
        | where FileName matches regex RmmPattern or SHA256 in (ioc_hashes)
        | summarize Hits = count(), Last = max(TimeGenerated) | extend Control = "RMM tool or payload executing", Expect = "none"),
    // One-off actions: these should have happened, so Hits > 0 is good. // VERIFY operation names in your tenant
    (AuditLogs
        | where TimeGenerated > contained_at - 1d
        | where OperationName has_any ("Reset user password", "Reset password", "Invalidate all refresh tokens", "Revoke")
        | where tostring(TargetResources) has target_user
        | summarize Hits = count(), Last = max(TimeGenerated) | extend Control = "Password reset / sessions revoked", Expect = "some"),
    // The attacker may have added their own MFA method during the session.
    (AuditLogs
        | where TimeGenerated > contained_at - 7d
        | where OperationName in ("User registered security info", "User changed default security info")
        | where tostring(InitiatedBy) has target_user or tostring(TargetResources) has target_user
        | summarize Hits = count(), Last = max(TimeGenerated) | extend Control = "MFA methods registered in the last 7 days (review each)", Expect = "review")
| extend Status = case(Expect == "none", iff(Hits == 0, "Holding", "FAILING"),
                       Expect == "some", iff(Hits > 0, "Done", "NOT DONE"),
                       iff(Hits == 0, "Nothing to review", "REVIEW"))
| project Control, Status, Hits, Last
```

**Why this query:** It is a containment checklist that checks itself.

- **Which attacker behaviour:** return through a new sender in the same tenant, a surviving tool, or an MFA method they registered while they had the desktop.
- **Why `summarize` without `by`:** it always returns one row per control, even when there are no events, so "0 hits" is shown rather than an empty result that could mean anything.
- **False positives:** `REVIEW` on MFA registrations the user made themselves — confirm with them.
- **Pivot next:** any `FAILING` or `NOT DONE` reopens the matching action.

#### Level 4 (Expert / L3)

Level 4 adds no value here. Containment verification checks known indicators against a known time. Baselines and anomaly models answer "is this unusual", which is the wrong question once you know exactly what to look for. Use Level 3 above, and turn it into a **re-entry rule** so the incident reopens if the attacker returns:

```kql
// Sentinel scheduled rule. Indicators from closed incidents of this type, kept in a watchlist.
// Watchlist 'TeamsVishingIOCs' columns: SearchKey (the value), Type (Domain | Hash | RmmTool). // create it first
let lookback = 1h;
let Iocs = _GetWatchlist('TeamsVishingIOCs') | project Value = tolower(SearchKey), Type = tostring(Type);
let Domains = toscalar(Iocs | where Type == "Domain" | summarize make_set(Value, 1000));
let Hashes = toscalar(Iocs | where Type == "Hash" | summarize make_set(Value, 5000));
union isfuzzy=true
    (MessageEvents
        | where TimeGenerated > ago(lookback)
        | where tolower(tostring(split(SenderEmailAddress, "@")[1])) in (Domains)
        | mv-expand Rcpt = RecipientDetails
        | project TimeGenerated, Entity = tolower(tostring(Rcpt.RecipientSmtpAddress)), Evidence = strcat("Teams message from ", SenderEmailAddress)),
    (DeviceProcessEvents
        | where TimeGenerated > ago(lookback)
        | where tolower(SHA256) in (Hashes)
        | project TimeGenerated, Entity = DeviceName, Evidence = strcat("IOC hash ran: ", FileName, " ", FolderPath)),
    (DeviceFileEvents
        | where TimeGenerated > ago(lookback)
        | where tolower(SHA256) in (Hashes)
        | project TimeGenerated, Entity = DeviceName, Evidence = strcat("IOC hash written: ", FolderPath))
```

**Why this query:** Rule frequency 1 hour, lookback 1 hour. Entities: Account or Host → `Entity`. Severity High. Add every domain and hash from each closed incident to the watchlist; the rule then covers the next campaign from the same actor.

#### Decision point

| Output | Call | Next |
|---|---|---|
| All controls `Holding` / `Done`, MFA review clean | Contained | Eradication and recovery |
| `FAILING` on Teams | Block not applied, or a new domain | Re-check the block; re-run step 2 for new domains |
| `FAILING` on RMM/payload | Tool survived or a new victim | Step 9 for that device |
| `REVIEW` with an MFA method the user did not add | **Account compromise** | Remove the method, revoke again, check sign-ins from that method |

---

## Containment and eradication

### Actions

| Action | How | Approver | Reversible? |
|---|---|---|---|
| Block the external domain in Teams | Teams admin centre → External access → block domain; or `Set-CsTenantFederationConfiguration -BlockedDomains`. Defender for Office 365 Tenant Allow/Block List can also block Teams domains // VERIFY in your tenant | SOC lead; Teams admin executes | Yes |
| Isolate the device | Defender for Endpoint → Isolate device (selective isolation keeps Outlook/Teams if needed) | SOC on-call (workstation); service owner (server) | Yes |
| Collect evidence | Investigation package; Live Response `getfile` (up to 3 GB) for payloads, `rclone.conf`, RMM logs | SOC | — |
| Revoke the user's sessions and reset the password | Entra → user → Revoke sessions; reset password. Revoke **before** reset | SOC lead; identity team executes | Revoke: yes (user signs in again). Reset: user impact |
| Remove MFA methods added during the incident | Entra → user → Authentication methods | Identity team | Yes |
| Remove unapproved RMM tools | Live Response `remediate` or Intune uninstall; then block their hashes and relay domains | Endpoint team, after evidence collection | **No** — collect logs first |
| Block payload hashes and C2 | Defender indicators (file hash, URL/domain, IP) | SOC | Yes |
| Restrict Quick Assist | Uninstall: `Get-AppxPackage -Name MicrosoftCorporationII.QuickAssist \| Remove-AppxPackage -AllUsers`; or block `remoteassistance.support.services.microsoft.com` (this also breaks Intune Remote Help). Move support to Intune Remote Help | CISO / IT operations | Yes |
| Restrict external Teams access | Allow-list federation to known partners; turn off chat with unmanaged (consumer) Teams accounts; review "chat with people not using Teams" | CISO / collaboration owner | Yes; business impact |
| Reimage | Rebuild any device with persistence, side-loading or credential access | Service owner | **No** — take the evidence first |

**Not reversible, do last:** uninstalling tools, reimaging, and deleting files. Each destroys evidence. Collect first.

**You cannot delete the attacker's Teams messages** when the thread belongs to their tenant (`IsOwnedThread == false` in `MessageEvents`). Blocking the domain and warning the user is the control.

### Evidence to preserve

- Investigation package from the victim device and each lateral target (before isolation lifts or reimage).
- RMM logs: AnyDesk `ad.trace` and `connection_trace.txt` (`%AppData%\AnyDesk`, `%ProgramData%\AnyDesk`); TeamViewer `Connections_incoming.txt`; ScreenConnect client logs. **Quick Assist keeps almost nothing locally** — the user's account of the session matters.
- Dropped files, side-loaded DLLs and their host binaries, `rclone.conf` (holds the attacker's cloud credentials — share with the provider for takedown).
- Screenshots of the Teams chat from the user (display name, tenant, timestamps) and the message IDs from `MessageEvents`.
- Exports of every query result used for a decision, with the query text.
- Device timeline export (7 days per export; export the whole incident window).

### Recovery

1. Reimage or restore devices with persistence or tools; clean-installing over the top is not enough.
2. Return the user with a new password, fresh MFA registration (verified in person or by a known channel) and a briefing on the lure.
3. Lift isolation only after the containment query (step 10 Level 3) shows `Holding` everywhere for 24 hours.
4. Keep the re-entry rule (step 10 Level 4) and the step 2 Level 4 rule enabled.

### Closure criteria

- [ ] Every targeted user identified (step 9) and contacted; every session opened is investigated.
- [ ] Every device with RMM, payload, side-loading or persistence is reimaged or proven clean.
- [ ] No lateral movement, or each target investigated through the [HOK playbook](hok-playbook.md).
- [ ] Exfiltration ruled out, or the ransomware/data-breach process is running.
- [ ] Attacker domains blocked in Teams; IOCs in Defender indicators and the `TeamsVishingIOCs` watchlist.
- [ ] Sessions revoked, password reset, MFA methods reviewed.
- [ ] Containment query shows `Holding` / `Done` for 24 hours.
- [ ] Quick Assist and external Teams access decisions recorded (changed, or accepted risk with owner).

---

## False positives and legitimate activity

| Looks suspicious | Usually legitimate when | How to tell |
|---|---|---|
| Mail flood | A shared mailbox, a campaign reply storm, a real newsletter sign-up spree | One or few sender domains; mailbox type; user confirms |
| External "Support" in Teams | A vendor's real support desk you have a contract with | Domain is the vendor's own, not `onmicrosoft.com`; a ticket exists on your side |
| New external tenant | New supplier, auditor or customer | Named person, business topic, sponsor in your company |
| Quick Assist launch | Your service desk helping the user | Ticket with matching time; technician's account; internal Teams contact, not external |
| AnyDesk / TeamViewer | Sanctioned tool, or a contractor's tool approved by IT | Long history, deployed by your software tooling, runs as a service |
| `whoami`, `ipconfig` | Real troubleshooting | No domain enumeration; matches a ticket |
| Encoded PowerShell | Intune, SCCM, RMM agents | Parent is the agent; same command shape on many devices |
| DLLs loaded from `AppData` | Teams, Zoom, Slack, browsers (per-user installs) | Written by the vendor's installer/updater; common hash across the estate |
| Admin ports to servers | Drive mappings; IT admins | `System` process on 445 to usual file servers; admin account with a ticket |
| Rclone | IT backup or migration on servers | Server, schedule, known destination, documented |

---

## Detection engineering recommendations

| Rule | Source | Type | Frequency / lookback | Severity | Tactics (techniques) | Entities |
|---|---|---|---|---|---|---|
| Mail flood then external IT-themed Teams contact | Step 2 Level 4 | Analytics rule | 1 h / 3 d | High (score ≥ 8), Medium (≥ 5) | Initial Access (T1566.004), Defense Evasion (T1656) | Account, DNS |
| External Teams contact from new tenant posing as IT | Step 2 Level 3 | Analytics rule | 1 h / 3 d (baseline 14–30 d) | Medium | Initial Access (T1566.004) | Account, DNS |
| Per-mailbox inbound mail anomaly | Step 1 Level 4 | Hunting query / Low rule | 1 h / 14 d | Low | (Precursor) | Mailbox |
| RMM tool first seen on device | Step 3 Level 4 | Analytics rule | 1 h / 14 d | Medium; High from user folder | Command and Control (T1219) | Host, Account, File hash |
| RMM launch within 3 h of external Teams contact | Step 3 Level 3 generalised to all users (join step 2 output on user) | Analytics rule | 1 h / 1 d | High | Command and Control (T1219) | Host, Account |
| Recon burst by account new to the tools | Step 4 Level 4 | Analytics rule | 1 h / 14 d | High | Discovery (T1033, T1016, T1082, T1482, T1069.002) | Host, Account |
| Rare download-and-execute command | Step 5 Level 4 | Analytics rule | 1 h / 14 d | High | Execution (T1059.001), Command and Control (T1105) | Host, Account |
| Fresh DLL side-load in a user folder | Step 6 Level 4 (Level 3 for persistence link) | Analytics rule | 1 h / 14 d | High | Persistence, Privilege Escalation, Defense Evasion (T1574.002, T1547.001, T1053.005) | Host, File hash |
| New admin-port paths reaching a DC | Step 7 Level 4 | Analytics rule | 1–2 h / 14 d | High | Lateral Movement (T1021.001/.002/.006) | Host (source), Host (target) |
| Rclone or renamed Rclone | Step 8 Level 2 | Analytics rule / Defender custom detection | 1 h / 1 d | High | Exfiltration (T1567.002) | Host, Account |
| Outbound volume anomaly | Step 8 Level 4 | Hunting query | 1 h / 14 d | Medium | Exfiltration (T1567.002, T1030) | IP |
| Re-entry of known IOCs | Step 10 Level 4 | Analytics rule | 1 h / 1 h | High | — | Account, Host |

Group the alerts from steps 3–8 into one incident per host (Sentinel alert grouping by Host entity, 24 hours) so an intrusion arrives as one incident, not seven.

---

## Common analyst mistakes

1. **Closing the mail flood as spam.** The flood is the setup. A flooded user should be warned before the call, not after.
2. **Looking for children of `QuickAssist.exe`.** The operator types into the user's own desktop. Commands appear under `explorer.exe` or a shell. Use the session window.
3. **Filtering ScreenConnect or AnyDesk activity by the user.** Their services run as SYSTEM. Filter by device.
4. **Blocking the sender, not the domain.** Attackers rotate accounts inside one tenant. Block the domain, and watch for the next one.
5. **Uninstalling the RMM tool before collecting its logs.** Its connection logs hold the attacker's ID and IP.
6. **Resetting the password without revoking sessions,** or without checking for MFA methods added during the session.
7. **Treating "no Rclone" as "no exfiltration".** The RMM tool's own file transfer, browsers and cloud sync clients move data too, and Defender for Endpoint records no bytes.
8. **Scoping by the one reported user.** The same tenant usually contacts many staff. Step 9 is not optional.
9. **Not talking to the user.** They saw the session. Ask what the "technician" did, what they typed, and whether they entered a password or approved an MFA prompt.
10. **Forgetting B2B guests.** With "chat with people not using Teams", the attacker can appear as a guest inside your tenant. Check `AuditLogs` for `Invite external user`.

---

## Incident checklist

Copy into the incident comments.

```text
Teams vishing / helpdesk impersonation — checklist
[ ] 1  Flood: start ____ end ____ emails ____ (or none)
[ ] 2  Contact: domain ____ display name ____ first contact ____ call placed Y/N accepted Y/N
[ ] 3  Session: tool ____ start ____ device ____ (service desk ticket checked: none / #____)
[ ] 4  Recon after session Y/N  -> if Y: HOK playbook opened ____
[ ] 5  Staging: URLs ____ hashes ____ files collected Y/N
[ ] 6  Persistence/side-load: items ____ folder ____
[ ] 7  Lateral movement: targets ____ (each investigated Y/N)
[ ] 8  Exfiltration: archives Y/N  upload tool Y/N  destination ____  -> ransomware/legal process Y/N
[ ] 9  Scope: users contacted ____ users with sessions ____ other devices ____
[ ] 10 Containment: domain blocked ____ device isolated ____ sessions revoked ____ password reset ____
       MFA methods reviewed ____ RMM removed (after evidence) ____ IOCs added to Defender + watchlist ____
[ ]    Containment query all Holding/Done for 24 h ____
[ ]    User briefed; Quick Assist / external Teams decision recorded ____
[ ]    Azure roles held by the user? Y/N -> cloud playbook
```

---

## Limits

- `MessageEvents` and `CallActivityEvents` were in preview in 2025; columns, values and Sentinel availability may change. Lines that depend on them are marked `// VERIFY`.
- Calls placed from a phone number, or to a personal phone, leave nothing in these tables.
- Quick Assist keeps no local record of who connected. Microsoft can't share the helper's identity. The user's account of the session is evidence.
- Defender for Endpoint records connections, not bytes. Volume needs firewall or proxy logs.
- The `CloudAppEvents` Teams fields inside `RawEventData` follow the Office 365 audit schema and differ between operations; check one record of each `ActionType` before relying on a field.
- Not run against live telemetry. Reviewed for KQL correctness and schema only.

## Sources

- [Microsoft — Threat actors misusing Quick Assist in social engineering attacks leading to ransomware](https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/) — Storm-1811, display names, the email bombing → Teams → Quick Assist chain.
- [Red Canary — Storm-1811 and Black Basta](https://redcanary.com/blog/threat-intelligence/storm-1811-black-basta/) — post-access tradecraft.
- [Microsoft Learn — MessageEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-messageevents-table) and [CallActivityEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-callactivityevents-table).
- [Microsoft Learn — Defender for Office 365 support for Teams](https://learn.microsoft.com/defender-office-365/mdo-support-teams-about).
- [Microsoft Learn — Teams activities in the audit log](https://learn.microsoft.com/purview/audit-log-activities#teams-activities) — `UserAccepted`, `ChatCreated`, `CallParticipantDetail`.
- [Microsoft Learn — Quick Assist: disable or uninstall](https://learn.microsoft.com/windows/client-management/client-tools/quick-assist#disable-quick-assist-within-your-organization).
- [Message center MC1096885 — Mail Bombing detection in Defender for Office 365](https://mc.merill.net/message/MC1096885).
