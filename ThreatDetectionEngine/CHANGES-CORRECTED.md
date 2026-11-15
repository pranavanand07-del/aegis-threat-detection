# Corrected version - what was wrong and what changed

Every item below was **reproduced against the original code first** (numbers are from a test harness, not guesses)
and re-checked after the fix. The self-test grew from 65 to 74 cases; all pass.

| # | Defect in the original | Evidence (before -> after) | Fix |
|---|---|---|---|
| 1 | The "last 10 seconds" query **deleted** data that the "last minute" query needs, so `BEHAVIOR_ANOMALY` never saw a real per-minute rate | 100 requests in 40 s: 60 s count was 100, then **0** after one 10 s query -> 100 | `IpActivityTracker` windows are read-only; old data is trimmed only by its own retention |
| 2 | Anomaly baseline updated on every event, including attack traffic (baseline poisoning), with no learning period | a new IP was "normal" after its first request | One observation per 10 s slot, abnormal minutes never folded in, 3-observation learning period |
| 3 | SQLi/XSS signatures matched raw text only (evasion) and `--` matched ordinary text (false positive) | `UNION/**/SELECT` scored **0**; `/blog/my--first--post` scored **40** -> 40 and 0 | New `InputNormalizer` (URL-decode up to 3 layers, strip comments, fold whitespace); `--` only counts after a quote or SQL keyword |
| 4 | Impossible travel was tracked **per IP**. One IP never changes country, so it could only fire on made-up data | same account, IN then US from two IPs: **0** -> 35 | State is per account |
| 5 | No allowlist: an internal gateway/admin PC could be auto-blocked | 192.168.1.1 was blocked after a noisy scan -> not blocked | `Allowlist` (loopback, private ranges, this host's own addresses, `-Daegis.allowlist`) |
| 6 | Every request *rejected* by an existing block was counted as a new CRITICAL alert | 937 "critical alerts" from one attacker -> 7 | `ThreatResult.repeatOfBlock`; not counted as a detection |
| 7 | Expired blocks stayed in the dashboard's blocked list until that IP sent traffic again | stale entries | Background sweeper removes expired blocks |
| 8 | The tracker table grew forever (one entry per source IP, including spoofed ones) | unbounded memory | Bounded table (`-Dtracking.max`, default 100,000) with idle eviction |
| 9 | Replayed log lines were all stamped "now", so detection windows ignored when things really happened, and a replayed 2-day-old attack would trigger a live block | | `LogEvent` accepts the log line's own timestamp; events older than 5 minutes never trigger a block |
| 10 | Simulators and the Attack Lab ran through the **same engine, trackers and block list** as real traffic | a lab IP typed by a user could be blocked for real | Separate sandbox lane (own engine, trackers, block list). Lab events are labelled channel `attack-lab` |
| 11 | `/api/event` accepted events from anyone who could reach the port, from any address, with open CORS. Since events decide who gets blocked, that lets a stranger get any IP blocked | | API binds to 127.0.0.1 by default (`-Dbind=0.0.0.0` to expose it). Write endpoints accept local requests only, or require `X-API-Key` when `-Daegis.api.key` is set. 64 KB body limit, wildcard CORS removed |

## Behaviour changes you will notice
* The simulator still runs by default, but on its own isolated engine. `/classic` and `/api/stats` show the **live lane only**; simulated data appears on `/`, `/aegis` and `/map`, always labelled Simulated.
* The API listens on 127.0.0.1 only. For LAN access: `-Dbind=0.0.0.0 -Daegis.api.key=SECRET`.

## Not fixed here (needs the new features in the enhanced version)
Distributed brute force on one account (80 failures over 40 IPs still scores 0), a 1000-port scan that is never blocked
because each event is scored alone, the hard-coded blacklist, and state that is lost on restart.
