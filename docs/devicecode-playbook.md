# Device code authentication — end-to-end investigation

For when a device code sign-in shows up in an alert, a hunt or a user report and
you have to work out whether a token walked out of the building.

Four queries support this playbook. Each phase below names the one to run.

| Query | Phase |
|---|---|
| [`devicecode.kql`](../queries/devicecode.kql) | 0 — confirm |
| [`devicecode-timeline.kql`](../queries/devicecode-timeline.kql) | 1–4 — reconstruct |
| [`devicecode-persistence.kql`](../queries/devicecode-persistence.kql) | 5 — what is keeping them in |
| [`devicecode-scope.kql`](../queries/devicecode-scope.kql) | 6 — who else |

---

## What you are looking at

The OAuth 2.0 device authorization grant exists for devices that cannot show a
browser — a TV, a CLI on a headless server, a conference room panel. The device
asks Entra ID for a code, shows it to you, and you type that code into
`microsoft.com/devicelogin` on a phone or laptop. The device then polls until
you finish, and collects the tokens.

The flow never checks that the device asking for the code and the person typing
it are in the same room.

So the attacker requests a code, sends it to the victim with a plausible
story — join this Teams meeting, re-register your MFA, IT needs you to verify —
and the victim types it into the genuine Microsoft page. The victim
authenticates properly, passes real MFA, satisfies real Conditional Access. The
attacker's poll returns an access token and a **refresh token**.

**The sign-in looks perfect, because it is.** Real user, real password, real
second factor, real corporate IP, compliant device, `ConditionalAccessStatus`
of success. There is no failed logon, no impossible travel, no risk detection at
the moment of compromise. That is exactly why it gets past detections built to
look for something going wrong.

What gives it away is not the sign-in. It is the **divergence afterwards**: the
same identity, the same token, suddenly used from a different network.

Codes are typically valid for around fifteen minutes, so the phish and the
sign-in sit close together in time.

---

## The attack timeline

| When | Attacker action | Telemetry | Table |
|---|---|---|---|
| T−min | Attacker requests a device code from the authorization endpoint | **Nothing.** This happens against Microsoft, outside your tenant | — |
| T+0 | Code sent to the victim — email, Teams, SMS, phone call | Message delivery, if it came through your tenant | `OfficeActivity` |
| T+1–15m | Victim enters the code and completes MFA | **`AuthenticationProtocol == "deviceCode"`, `ResultType` 0, victim's own IP** | `SigninLogs` |
| T+1–15m | Attacker's poll returns access + refresh tokens | Nothing distinct — the token issue is part of the same sign-in | — |
| T+minutes | Refresh token used from attacker infrastructure | **Non-interactive sign-ins, different IP and ASN, same user** | `AADNonInteractiveUserSignInLogs` |
| T+minutes–hrs | Mail read, files enumerated, directory queried | Resource access under the stolen token | `OfficeActivity`, non-interactive |
| T+hours | **Device registered** to obtain a Primary Refresh Token | `Add device`, `Register device`, Windows Hello / passkey added | `AuditLogs` |
| T+hours | MFA method registered, app consent granted, secrets added | Directory changes by the victim's account | `AuditLogs` |
| T+hours | Mailbox rules, forwarding, onward phishing | Rule creation | `OfficeActivity` |
| T+days | Consented application signs in on its own | Service principal sign-ins | `AADServicePrincipalSignInLogs` |

**The step that matters most is T+minutes.** A refresh token is good for
90 days by default and survives a password reset. If you only reset the
password, the attacker keeps working.

---

## Investigation timeline

### Phase 0 — Confirm · 5 minutes

Run **`devicecode.kql`**. Leave the `CHECK` fields blank to sweep, or set
`UserIdentityCheck` if you already have a name.

Read `TokenMoved`, `DeviceAdded` and `OtherASNsAfter` first.

| Signal | `DeviceCodeScore` | Verdict |
|---|---|---|
| `TokenMoved` true | any | **Treat as compromise.** A token issued here is being used from another network. Go to Phase 1 now. |
| `DeviceAdded` true | any | **Treat as compromise.** A device was registered by this account in the window. Go to Phase 1, then Phase 4. |
| neither | ≥ 7 | **Probable.** Successful device code, first time for this user, unmanaged device. Continue. |
| neither | 4–6 | Suspicious. Check whether the user has a legitimate reason — CLI, headless server, shared device. |
| neither | ≤ 3 | Likely legitimate. Note and close. |

Record the `EventTime` of the highest-scoring row. That is your **pivot time**.

The score is built from nine indicators:

| Weight | Indicator |
|---|---|
| +3 | The sign-in succeeded |
| +3 | `TokenMoved` — token later used from a different ASN |
| +2 | `DeviceAdded` — this account registered a device in the window |
| +2 | `FirstDcForUser` — this user has not used device code before |
| +1 | `AbusedApp` — a commonly abused public client |
| +1 | `NewIpForUser` — address unfamiliar for this account |
| +1 | `Unmanaged` — device neither managed nor compliant |
| +1 | `HighValue` — resource is Graph, Exchange, SharePoint, ARM or Key Vault |
| +1 | Device code is rare tenant-wide (≤ 3 users) |

> `TokenMoved` and `DeviceAdded` both look across the whole `TimeToCheck`
> window rather than strictly after the sign-in, so they are strong pointers
> rather than timed correlations. `DevicesAddedNames`, `DeviceOpsUsed` and
> `FirstDeviceAdded` give you the detail. Phase 1 is what establishes the actual
> order of events.

### Phase 1 — Reconstruct · 15 minutes

Run **`devicecode-timeline.kql`**. Set `PivotTime` to the value from Phase 0 and
`UserIdentityCheck` to the user.

One table, oldest first, tagged by phase:

```
1-Delivery           mail and Teams around the phish
2-Code entry         the device code sign-in itself
3-Sign-ins           the user's other interactive sign-ins in the window
4-Token use          non-interactive sign-ins — where the token actually went
5-Service principal  service principal sign-ins
6-Device             devices registered, passwordless credentials added
7-Directory          every other directory change
8-Cloud              M365 activity
```

Put the `2-Code entry` row next to the `4-Token use` rows and compare
**IP and ASN**. Same identity, different network, minutes apart, is the whole
case. Screenshot those two lines for the ticket.

If phase 4 shows only the victim's own ASN, the token may not have been
redeemed by anyone else — but check Phase 5 before concluding that.

### Phase 2 — How the code was delivered

From `1-Delivery`, find how the victim received the code. Device code
phishing usually arrives by **Teams message** or a **phone call**, not email,
precisely because it needs a live conversation to talk someone through typing a
code.

If nothing appears, ask the user. They will remember — someone talked them
through it.

Establish whether the sender was external, a compromised internal account, or
out-of-band entirely. That decides whether this is one victim or a foothold you
already have.

### Phase 3 — What the token reached

From `4-Token use` and `8-Cloud`:

- Every distinct `ResourceDisplayName` the token was used against
- Every distinct IP and ASN
- Whether `IncomingTokenType` shows refresh token use
- What was read — mail, files, directory

Assume everything the token touched is disclosed. A refresh token for Microsoft
Graph is, in practice, the user's whole mailbox and their whole OneDrive.

### Phase 4 — Was it only one token

Check `3-Sign-ins` for other sign-ins in the window, `5-Service principal` for
applications signing in on their own, and `6-Device` for anything registered.

An attacker with one token often uses it to consent to an application, because
an application's access **survives token revocation**. If a service principal
sign-in appears after the device code event and you do not recognise the app,
that is now the primary problem.

The same is true of devices, and this is the one people miss. A stolen token is
enough to **register a device** in Entra ID, and a registered device is issued
its own Primary Refresh Token. That PRT is a separate credential: it survives
revoking the stolen token, it survives the password reset, and it can satisfy a
Conditional Access policy that requires a compliant or joined device — so the
control you were relying on now works *for* the attacker.

Anything in `6-Device` timestamped after the pivot is the attacker's, unless the
user can account for it. Watch for `Add Windows Hello for Business credential`,
`Add passwordless phone sign-in credential` and `Add Passkey (device-bound)`
as well as the device object itself — those are durable, MFA-satisfying
credentials bound to hardware you do not control.

### Phase 5 — What is keeping them in · the revocation decision

Run **`devicecode-persistence.kql`** with `UserIdentityCheck` set.

Four kinds of foothold, all of which outlive a password reset:

```
Device             devices registered or updated, Windows Hello, passkeys,
                   passwordless phone sign-in, platform credentials
Directory          MFA methods registered, roles added, app consent,
                   service principal credentials, CA policy changes
Mailbox            inbox rules, forwarding, mailbox delegation, transport rules
Service principal  applications signing in under granted consent
```

`Device` and `Service principal` are the two that also outlive **session
revocation**, so treat them as the ones that decide whether the incident is
actually closed.

Anything here timestamped after the device code sign-in is attacker work until
proven otherwise. An MFA method registered by the victim's own account hours
after the phish is not the victim.

### Phase 6 — Scope · who else

Run **`devicecode-scope.kql`** with whichever indicator you have: `IPCheck`,
`ASNCheck`, `AppCheck` or `UserAgentCheck`.

Results are tagged by how they matched:

```
DeviceCode   another device code sign-in from the same address, network or app
TokenUse     a token used from the same infrastructure against another user
```

**`ASNCheck` is the most useful one.** Attackers change IP address easily and
hosting provider rarely. An ASN that appears against three unrelated users in a
day is a campaign, not a coincidence.

Use the summarize variants at the bottom of the file for the day-by-day shape.

---

## Containment

In this order. The order is the point.

1. **Revoke the user's refresh tokens.** Not a password reset — revocation.
   `Revoke-MgUserSignInSession`, or Entra portal → user → Revoke sessions. A
   password reset alone leaves every issued refresh token working.
2. **Reset the password** afterwards, so a re-issued token needs the new one.
3. **Review MFA methods** and remove anything registered since the pivot time.
4. **Remove any device registered since the pivot time**, and revoke its PRT by
   disabling or deleting the device object. A device registered by the attacker
   holds a credential that step 1 does not touch.
5. **Review app consents and service principal credentials.** Application access
   survives step 1 — this is the step that actually ends it.
6. **Check mailbox rules** before closing. A forwarding rule survives everything
   above.
7. **Block the attacker ASN** in Conditional Access if the tenant's policy
   allows named-location blocking.
8. **Restrict the device code flow.** A Conditional Access policy targeting
   `Authentication flows → Device code flow` blocks this outright for users who
   have no need of it, which is nearly all of them. This is the fix, not the
   workaround.

---

## For the ticket

- Pivot time, and the `2-Code entry` row from the timeline
- The `4-Token use` rows showing the different IP and ASN — the proof
- Every resource the token reached
- How the code was delivered, and by whom
- Any device registered since the pivot, and whether it was removed
- Persistence found, with timestamps relative to the pivot
- Every user and ASN from `devicecode-scope.kql`
- **When sessions were revoked** — not just that the password was reset

---

## Legitimate device code use

Device code is a real feature with real users. Before escalating, rule these out:

| Looks suspicious | Actually |
|---|---|
| Azure CLI or Azure PowerShell, developer account, repeats weekly | A headless server or a build agent |
| Visual Studio Code, engineer, recurring | Remote development sign-in |
| Conference room or shared device, same IP each time | A meeting room panel |
| Many users, one app, same day | A rollout or an onboarding exercise |

`DaysDcSeenByUser` and `UsersUsingDcInOrg` separate these quickly. A user who
has done this weekly for three months is doing their job. A user doing it for
the first time ever, from an unmanaged device, is the one to look at.

---

## What none of this proves

- **A clean-looking sign-in proves nothing.** Real MFA and a successful
  Conditional Access evaluation are exactly what this attack produces.
- **No ASN change does not mean no theft.** An attacker on a VPN exiting through
  the same provider as the victim will not show a divergence.
- **Revoking sessions does not remove consented applications.** Those have their
  own credentials and their own sign-ins.
- **Revoking sessions does not remove a registered device.** Its Primary Refresh
  Token is a separate credential and keeps working.
- **A blocked or failed device code sign-in is still worth reading.** It means
  someone was asked for a code. The next attempt may have succeeded.

None of these queries have been run against live telemetry — they are reviewed
for KQL correctness and schema accuracy only. Test them in your own tenant.
