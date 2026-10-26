# PHP2Shell and Node2Shell — investigation playbook

**Use when** a web server running PHP, Node.js or Bun shows exploit attempts, crashes, or a web process doing something it never does.
**Goal:** find which servers are exposed, decide if one was exploited, and if so hand it to the hands-on-keyboard playbook with a start time.

| Step | Query |
|---|---|
| 0 Exposure | [`webrce-exposure.kql`](../queries/webrce-exposure.kql), [`webrce-exposure-ah.kql`](../queries/webrce-exposure-ah.kql) (Advanced Hunting) |
| 1 Confirm | [`php2shell.kql`](../queries/php2shell.kql), [`node2shell.kql`](../queries/node2shell.kql) |
| 2 Requests | [`webrce-requests.kql`](../queries/webrce-requests.kql) |
| 3 Reconstruct | [`hok-timeline.kql`](../queries/hok-timeline.kql) |
| 4 Persistence | [`hok-persistence.kql`](../queries/hok-persistence.kql) |
| 5 Reach | [`hok-connections.kql`](../queries/hok-connections.kql), [`hok-lateral.kql`](../queries/hok-lateral.kql), [`hok-exfil.kql`](../queries/hok-exfil.kql) |
| 6 Scope | [`hok-scope.kql`](../queries/hok-scope.kql), [`webrce-requests.kql`](../queries/webrce-requests.kql) |

All queries are written for Sentinel except `webrce-exposure-ah.kql`.

---

## The vulnerabilities

| | PHP2Shell | Node2Shell (also "HTTP2Shell") |
|---|---|---|
| CVE | CVE-2026-109618, CVE-2026-109619 | CVE-2026-111497 |
| Where | PHP itself: Apache `mod_php` (highest risk) and PHP-FPM | The Brotli decoder bundled in Node.js; also Bun |
| Trigger | Multipart POST using the session upload-progress field (`PHP_SESSION_UPLOAD_PROGRESS`), on by default | Request body sent with `Content-Encoding: br` to apps that decode it (Express 5, body-parser 2, Koa), or a Brotli response to `fetch()` |
| Auth | None. Runs before application code | None |
| Fixed | 8.2.35, 8.3.36, 8.4.27, 8.5.12 (21 Oct 2026). Older branches: no release | 22.23.4, 24.22.1, 26.12.1 (21 Oct 2026). 20, 23, 25: no fix. Bun 1.4.4 |
| In the wild | Attempts from 17 Oct 2026, four days before the fix. Reports of confirmed code execution are disputed | Public proof of concept, unreliable. No confirmed exploitation as of 26 Oct 2026 |

What this means for detection:

- **The exploit runs below the application.** Application logs show little or nothing.
- **Most attempts crash the worker** rather than run code. A crash after a POST is the attempt.
- **Success shows as the web process doing something new:** starting a shell, fetching a file, writing a script, calling out.
- Gateway access logs do not record request headers or bodies. You only see the upload field or `Content-Encoding: br` if a WAF rule matched and logged it.

## Attack timeline

| When | Attacker | Telemetry | Table |
|---|---|---|---|
| T−days | Scans for PHP or Node | Requests, sometimes with the CVE in the user agent | `AGWAccessLogs`, `W3CIISLog`, `CommonSecurityLog` |
| T+0 | Sends the exploit POST | WAF match on the field or header; backend drops the connection | `AGWFirewallLogs`, `AzureDiagnostics`, `AGWAccessLogs` |
| T+0 | Worker crashes (most attempts) | `segfault`, `SIGSEGV`, `exited on signal 11`, service restarts | `Syslog`, `Event`, `DeviceProcessEvents` |
| T+seconds | Code runs as the web user | Worker starts `sh`, `id`, `curl`, `wget` | `DeviceProcessEvents` |
| T+minutes | Second stage | File in `/tmp` or `/dev/shm`, new outbound address | `DeviceFileEvents`, `DeviceNetworkEvents` |
| T+minutes | Stays | Web shell in the web root, cron entry, SSH key | `DeviceFileEvents` |
| T+hours | Uses the server | Coin miner, credential theft from `.env` and config, lateral movement | `Device*` |

---

## Steps

### 0. Exposure · first hour, before anything else

**Run** `webrce-exposure.kql` in Sentinel. If you have Defender Vulnerability Management, also run `webrce-exposure-ah.kql` in Advanced Hunting — those tables do not reach Sentinel.

**Read first:** `Status`, `InternetFacing`.

| Status | Decide |
|---|---|
| `Vulnerable` + internet-facing | Patch today. Run step 1 on it now. |
| `No fix: unsupported branch` | Upgrade to a supported branch. Apply the mitigations below until then. |
| `Branch only` | Path shows `8.3` but not the patch level. Check the package version: distros backport fixes without changing the upstream number. |
| `Unknown` | Version not in the path. Run `php -v` or `node -v` on the server. |
| `Fixed` | Confirm every worker was restarted after the update. |

**Patching is not enough until the workers restart.** PHP-FPM pools, Apache and Node processes keep the old code in memory.

Mitigations until patched:

- PHP: `session.upload_progress.enabled = 0`, then restart all workers. On 8.5, also `fatal_error_backtraces = Off`.
- PHP: a WAF rule blocking multipart requests that carry `PHP_SESSION_UPLOAD_PROGRESS`. Log-only first if any app uses upload progress bars.
- Node: reject or strip request bodies with `br` in `Content-Encoding` at the proxy, WAF or middleware. Match case-insensitively, including inside lists.
- Node: for outbound calls, remove `br` from `Accept-Encoding` **and** refuse Brotli responses. A hostile server can send Brotli anyway.

Name any WAF rule you create, and put the name in `CustomRules` in step 1.

### 1. Confirm · 10 min

**Run** `php2shell.kql` or `node2shell.kql`. Blank to sweep every server, or set `DeviceCheck`.

**Read first:** `Verdict`, `FirstAttempt`, `FirstAction`.

| Verdict | Decide |
|---|---|
| `Post-exploitation` | **Compromise.** Take it out of the load balancer pool or isolate it, then step 2. |
| `Unusual PHP activity` / `Unusual Node activity` | Read `Evidence`. If `FirstAction` is after `FirstAttempt`, treat as compromise. Otherwise check for a deploy or CMS update at that time. |
| `Attempt only` | Check step 0. Vulnerable: patch now and re-run daily for a week. Fixed: note and close. |
| `Server` starts with `host:` | A WAF hit that did not resolve to a device. Find the backend in step 2 (`Backend` column) and re-run with `DeviceCheck`. |

PHP2Shell score — 12 indicators, 26 maximum:

| Weight | Indicator |
|---|---|
| +3 | `Reverse shell` — `/dev/tcp`, `nc -e`, `bash -i`, `mkfifo`, socket one-liners |
| +3 | `Download from PHP` — `curl`, `wget`, `chmod +x`, `base64 -d`, `certutil` |
| +3 | `Recon from PHP` — `id`, `whoami`, `uname -a`, `/etc/passwd` |
| +3 | `Persistence from PHP` — cron, SSH keys, systemd units, startup files, new users |
| +2 | `Script written by PHP` — `.php`, `.phtml`, `.phar` written by the worker (cache folders excluded) |
| +2 | `Payload in temp` — a child of PHP wrote to `/tmp`, `/var/tmp`, `/dev/shm` |
| +2 | `New outbound` — internet address the PHP tree never used in the 30-day baseline |
| +2 | `New child of PHP` — a program PHP never started on this server in the baseline |
| +2 | `Defender alert` — alert on a PHP server naming the CVE, a web shell or the web server |
| +2 | `Exploit request` — WAF/IPS match, your custom rule, or the CVE in the user agent |
| +1 | `Worker crash` — segfault, signal 11, heap corruption |
| +1 | `Backend dropped POST` — gateway logged `ERRORINFO_UPSTREAM_CLOSED_CONNECTION` on a POST |

Node2Shell score — 12 indicators, 25 maximum. Same weights with `from Node` in place of `from PHP`, no `Script written` indicator, and:

| Weight | Indicator |
|---|---|
| +1 | `Restart loop` — the Node service started three or more times in ten minutes under systemd, pm2 or a container runtime |

`New child of Node` also counts `node -e` / `node --eval`: Node starting Node is normal, Node running inline code is not.

Record `Server`, `FirstAttempt` and `FirstAction`. `FirstAction` is the **pivot time** if the verdict is not `Attempt only`.

### 2. Requests · 15 min

**Run** `webrce-requests.kql` with `SourceIPCheck` from `SourceIPs`. Or with `HostCheck` to see everything that hit the site.

**Read first:** POSTs just before `FirstAction`, `Error`, `Waf`, `UserAgent`.

- POST followed by `ERRORINFO_UPSTREAM_CLOSED_CONNECTION` is an attempt that crashed the worker.
- The last request before `FirstAction` is the likely successful one. Record its time, path and source.
- Use the summary line at the foot (one row per attacker) to see how many sites each address hit.

Behind Front Door or another proxy, `ClientIP` on the gateway is the proxy. Take the client from the Front Door or CEF rows.

### 3. Reconstruct · 30 min

**Run** `hok-timeline.kql` with `IncidentStart` = the pivot time and `DeviceCheck` = the server.

**Read first:** `01-Access` rows tagged `T1190` (the web process starting a shell), then everything after in order.

From here the incident is a hands-on-keyboard intrusion. Work the [HOK playbook](hok-playbook.md) from step 2.

### 4. Persistence · 15 min

**Run** `hok-persistence.kql` on the server.

**Read first:** `Web shell` (Windows and Linux web roots), `SSH key`, cron and systemd rows. Every one written after the pivot gets removed and its hash goes into scope.

A web shell survives patching. **Patching a compromised server does not end the incident.**

### 5. Reach · 30 min

**Run** `hok-connections.kql`, `hok-lateral.kql` and `hok-exfil.kql` on the server.

Web servers hold secrets: database passwords, API keys, cloud credentials in `.env` and config files, managed identity tokens. Assume every secret readable by the web user is stolen if the verdict was `Post-exploitation`.

### 6. Scope · 20 min

1. Run `php2shell.kql` / `node2shell.kql` blank: every other server with a verdict above `Attempt only`.
2. Run `hok-scope.kql` with the attacker IPs, file hashes and outbound addresses.
3. Run `webrce-requests.kql` with each attacker IP and use the `by Host, Backend` summary: every server they reached.

---

## Contain

1. **Take the server out of service:** remove it from the load balancer pool, or isolate it in Defender. Isolation cuts the site; pool removal keeps the box reachable for collection.
2. Collect before changing anything: investigation package, or Live Response `getfile` on the web shell, temp files and web server logs.
3. Patch, then **restart every worker**.
4. Remove web shells, cron entries, SSH keys and units found in step 4.
5. **Rotate every secret the web app could read:** database, API keys, storage keys, service principal secrets.
6. With `Post-exploitation`, rebuild from a known-good image rather than clean in place.
7. Block attacker IPs at the WAF only after checking them: early attempts came through shared anonymisation infrastructure.

## Ticket

- Server, runtime and version, and patch status at the time of the attack
- `FirstAttempt`, `FirstAction`, and the request that preceded `FirstAction`
- Verdict and indicators with their evidence
- Attacker IPs and user agents
- Web shells, persistence and second-stage files with hashes
- Secrets rotated, and when
- Other servers from scope

## False positives

| Looks suspicious | Usually |
|---|---|
| `PHP_SESSION_UPLOAD_PROGRESS` in a request | A real upload progress bar. Check the app. |
| `Script written by PHP` | WordPress, Drupal or Joomla updating itself. Check the time against change records. |
| `New child of PHP` | The app shelling out: ImageMagick, `sendmail`, `git`, PDF tools. Recurring after a deploy. |
| `New child of Node` | Build tools (`npm`, `next build`) on a host that also builds. |
| `Restart loop` | A deploy, or an unrelated crash bug or out-of-memory. |
| `Worker crash` alone | Common bugs crash PHP too. Matters next to an attempt. |
| `Exploit request` alone | Internet-wide scanning. Most public exploits never reach code execution. |

## Run as a detection

Both detection queries work as Sentinel scheduled rules:

- Query frequency 1 hour, `TimeToCheck = 1h`, `BaselineToCheck = 14d` (the longest a scheduled rule can look back, so the baseline is 14 days rather than 30).
- Add `| where Verdict != "Attempt only"` to alert on action, or keep `Attempt only` at low severity on vulnerable servers.
- Entity mapping: `Server` → Host.

## Limits

- Exploitation can run entirely inside the PHP or Node process. If the attacker never starts a program, writes a file or opens a new connection, these queries see only the attempt.
- Gateway access logs carry no request headers or bodies. Without a WAF rule that logs them, the upload field and `Content-Encoding: br` are invisible.
- The outbound path for Node2Shell (a Brotli response to `fetch()`) passes no WAF. Look for a crash or restart loop right after a `New outbound` row.
- Containers: process events need Defender on the host or Defender for Containers. Pod-only telemetry is not covered here.
- Python's Brotli package, Envoy and Istio share the Node2Shell bug. `node2shell.kql` covers Node.js and Bun only.
- Version checks read the path or Defender's inventory. Distro backports and un-restarted workers make both unreliable.
- Exploit details were still disputed between vendors on 26 Oct 2026. Recheck the PHP and Node.js advisories before closing.
- Not run against live telemetry. Reviewed for KQL correctness and schema only.

## Sources

Checked 26 Oct 2026.

- PHP security advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp, and the Node.js October 2026 security release — the authority for versions and mitigations.
- [watchTowr — PHP2Shell](https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/) — in-the-wild attempts, most not reaching code execution.
- [Tenable — PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [Sansec — PHP2Shell](https://sansec.io/research/php2shell) and [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/) — upload-progress trigger, affected configurations.
- [AWS — WAF mitigations for PHP2Shell](https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/)
- [BleepingComputer — PHP2Shell exploited in the wild](https://www.bleepingcomputer.com/news/security/php2shell-security-flaws-now-sucessfully-exploited-in-the-wild/)
- [Aikido — Node2Shell](https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497) and [Sysdig — detecting Node2Shell](https://www.sysdig.com/blog/node2shell-cve-2026-111497-detecting-the-node-js-brotli-rce) — request-body and `fetch()` paths, affected frameworks.
- [Microsoft Learn — Application Gateway error info](https://learn.microsoft.com/azure/application-gateway/monitor-application-gateway-reference#resource-logs) — `ERRORINFO_UPSTREAM_CLOSED_CONNECTION`.
- [Microsoft Learn — Defender XDR tables not in Sentinel](https://learn.microsoft.com/azure/sentinel/connect-microsoft-365-defender#which-defender-xdr-tables-arent-supported-in-microsoft-sentinel) — why exposure needs Advanced Hunting.
