# Hardening release: what changed and why

Builds with the same `javac -d out $(find src -name "*.java")`. Run all checks with
`java -cp out com.threatdetection.testing.DetectionTestSuite` (57 checks, includes the 91-case rule self-test).

## The five code-level corrections
| # | Problem | Fix |
|---|---------|-----|
| 1 | Sysmon event 3 used `DestinationPort` in both branches of the direction test. | Direction is now explicit. `ip` = the remote peer, `remotePort` = the peer's port, `localPort` = this host's port. `port` stays the *service* port (outbound: remote port; inbound: the local port that was hit, which is what scan logic must count). Note: for inbound events `DestinationPort` was already the right number for scanning; the real defect was that the peer's port was thrown away and the code was misleading. |
| 2 | Missing/invalid IP in 4624/4625 became `127.0.0.1`. | The address stays empty and `ipMissing=true`; the dashboard shows "[source address unavailable]". Nothing is attributed to localhost and the core engine is not fed an invented address. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is unwrapped. A genuine reported loopback is kept. |
| 3 | Hard-coded blacklist in `ThreatDetectionEngine`. | `intelligence/ThreatIntelService`: blocklist files (`-Daegis.blacklist.file`, IP or CIDR + label, auto-reload), runtime add/remove with expiry, per-entry source in every alert. **Empty by default.** The three old addresses survive only as labelled `DEMO-SAMPLE` entries in the isolated simulator lane and in tests (`-Daegis.intel.demo=true` to load them anywhere). |
| 4 | False positives. | `--` and SQL words in prose: weak phrases (`insert into`, `select * from`, `exec(`, `sleep(`, `benchmark(`) now need SQL syntax around them; `union select` needs word boundaries. Bot rule: a bare GET of a known health path (no query, no body) by curl/wget/empty UA is not flagged; sqlmap/nikto/etc. still are, and curl doing real work still is. 14 negative cases added (`testing/FalsePositiveTestSuite`) and the old "documented false positive" case now asserts the fix. |
| 5 | "Blocking" was a Java map. | `response/WindowsFirewallAdapter` (netsh advfirewall), see below. The in-memory block stays as the first line of defence. |

## Windows Firewall response
* `-Daegis.fw.response=off|dry-run|enforce`. **Default dry-run**: decisions are audited, no rule is created.
* `enforce` needs Windows *and* an elevated process (`net session` check); otherwise it downgrades to dry-run and says why.
* Temporary rules only (1 min to 24 h, default 10 min), removed by a scheduler; rule table saved to `aegis-data/firewall-rules.tsv` and re-armed or cleaned after a restart.
* Never blocks: allowlisted/internal/own addresses, malformed values (no shell, argument list only), multicast/broadcast. Rule cap `-Daegis.fw.max` (500).
* Rollback: `POST /aegis/api/response/unblock?ip=` and `/rollback`.
* Audit: `aegis-data/response-audit.log`, SHA-256 hash-chained (tamper-evident, verified in `/aegis/api/response`).
* Only the LIVE lane is attached. The simulator / Attack Lab can never touch the OS firewall.

## New pipeline pieces (existing modules kept)
* `normalization/` EventValidator + EventNormalizer: tidy addresses, sane timestamps, bounded text, control characters stripped, duplicate Windows records dropped.
* `correlation/` EntityResolver, MitreMap, AttackChainEngine: distributed brute force on one account, password spraying, success after failures, slow wide port scans (>=100 ports/10 min HIGH, >=500 CRITICAL and blocked), multi-stage chains (3+ ATT&CK tactics per address/host). These close two gaps the previous release listed as "not fixed".
* `decision/ConfidenceEngine` + `response/ResponsePolicyEngine`: severity and confidence are separate. CRITICAL + confidence >= 0.7 => BLOCK; CRITICAL below that => queued for analyst approval; HIGH => investigate; protected addresses never reach block/approve. `-Daegis.response.confidence`, `-Daegis.response.approval=true`.
* New endpoints: `GET /aegis/api/chains`, `/aegis/api/pipeline`, `/aegis/api/response`; `POST .../response/approve|reject|unblock|rollback` (write-guarded like the other write endpoints).

## Not done / limits
* No UI panels yet for chains, approvals or the audit trail: they are API-only.
* No behaviour-baseline rewrite (existing `BehaviorAnomalyDetector` kept) and no `ContextualRiskEngine`; confidence + policy cover that role in a simpler way.
* Firewall enforcement was tested against a fake `netsh` runner, not on a real Windows machine. Try `dry-run` first, then `enforce` in an elevated prompt on a test box.
* Unusual-but-valid ingestion sources (Apache/Nginx, firewall logs) already existed; no new collectors were added.
* Chain thresholds are starting points, not tuned on your traffic.
