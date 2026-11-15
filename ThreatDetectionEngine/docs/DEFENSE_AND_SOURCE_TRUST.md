# AEGIS defense layer and source trust

## Safety rules that are enforced in code (and tested)
* Never deletes a file. Quarantine = move + metadata; restore puts the bytes back. Only inside configured roots; OS folders refused.
* Never blocks permanently. Every firewall/session/account/rate-limit action expires (default 15 min, hard cap 24 h) and is undone by a sweeper; leftovers from a crash are undone at startup.
* A heuristic score alone never triggers an automatic action: CRITICAL + OBSERVED data + at least 2 distinct rules (or a threat-intel feed hit) + the action type allowed by policy.
* API (unverified) and SIMULATED events never trigger automatic actions; simulated events are ignored entirely and never sent to third-party services.
* Private/internal/own/allowlisted addresses are never blocked, even by an analyst. Protected accounts (Administrator, SYSTEM, root, the user running AEGIS, ...) are never locked.
* Account locking and file quarantine always need an analyst unless you opt in (`-Daegis.defense.auto=...`), because an attacker who can trigger them could lock out or disrupt the real user.
* Circuit breaker: more than 10 automatic actions a minute (spoofed-source flood) or 100 active blocks -> further actions wait for an analyst.
* Replayed history (events older than 5 minutes) never triggers a response.

## What each action really does
| Action | Mechanism |
|---|---|
| Firewall block | `netsh advfirewall firewall add rule name=AEGIS-block-<ip> dir=in action=block remoteip=<ip>`; removed with `delete rule`. No shell, IP validated. Needs Administrator. |
| Quarantine | Files.move into `aegis-data/quarantine/<id>.quarantined` + `.meta` (path, SHA-256, reason). |
| Session revocation / account lock / rate limit | AEGIS keeps the lists; the protected application asks `GET /aegis/api/defense/check?type=session|account|ip&id=...` and refuses when `allowed:false`. AEGIS cannot reach inside other applications. |
| Escalation | Console, `defense-escalations.log`, optional JSON webhook (background thread, 3 s/5 s timeouts). One notice per actor per 10 min. |
| Recovery | 15-second sweeper undoes expired actions and writes `RESTORE_*` audit records; unapproved proposals lapse after 60 min. |

## Audit trail
`aegis-data/defense-audit.tsv`: seq, time, operator, action, target, level, mode, result, reason, event id, previous hash, hash (SHA-256 chain).
Editing, deleting or reordering any line breaks `verify`. It is tamper-evident, not tamper-proof: someone who can rewrite the whole file
can rebuild the chain, so forward the lines to remote/WORM storage for real immutability. Operator names are self-declared (`X-Operator`) and
marked `(local, unverified)` unless `-Daegis.api.key` is set.

## Source trust
OBSERVED / API / SIMULATED describe where an event came from. ENRICHED is a separate layer on the event (`enrichments[]`), because enrichment adds
context to an event rather than being a place events come from. Enrichment never changes a score and never overrides the source label.
Verdicts are MALICIOUS, SUSPICIOUS, MAPPED or NO_DATA. There is no "clean": absence of reports is not proof of safety.

## Integrations
| Integration | How | Offline behaviour |
|---|---|---|
| Wazuh | Tails `alerts.json` (OBSERVED) or `POST /aegis/api/ingest?type=wazuh` (API). Level 4-6/7-9/10-11/12+ -> 10/25/40/55 points, so Wazuh alone cannot cause an automatic response. | File missing -> source shown as waiting/error |
| AbuseIPDB | Key via property or env. Free tier ~1000/day (budget 900). | Skipped, `OFFLINE`/`TIMEOUT`, event un-enriched |
| VirusTotal | IP, file hash, URL. Free tier 4/min (gate 15.5 s, budget 450/day). | Same |
| MaxMind GeoLite2 | Existing CSV loader reads `GeoLite2-City-Blocks-IPv4.csv` (network + latitude + longitude). | Observed IPs are simply not plotted |
| MITRE ATT&CK | Technique per rule from `RuleCatalog` (approximate, local) plus Wazuh's own ids. | Always available |

Caching: 6 h for answers, 2 min for failures, 20,000 entries. Circuit breaker: 3 consecutive failures pause a provider for 2 min.
Only public IPs are sent out; internal ones never leave the machine.

## Limits (stated honestly)
* The Windows Firewall path builds and validates the exact netsh commands, but it was not executed against a real Windows Firewall during development (the build sandbox is Linux). Test with `-Daegis.defense.mode=enforce` in an Administrator terminal on a throwaway address first.
* Enrichment results are in memory only (not persisted across restarts); defense decisions use the event's own score and rules, not the enrichment.
* The original engine's 10-minute in-memory block list (`AutoResponseService`) is unchanged and is separate from the firewall layer.
* GeoLite2: only the Blocks CSV is read, so country/city names are empty unless the CSV contains them; coordinates work. Not tested with a real MaxMind file.
