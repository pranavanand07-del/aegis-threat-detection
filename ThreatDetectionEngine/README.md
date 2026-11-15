# Real-Time Cybersecurity Threat Detection in Java

A weighted risk-scoring threat detection engine, built with **plain Java (JDK 21)**
— no Maven, no Spring Boot, no internet connection needed. Just `javac` + `java`.
That means it compiles and runs immediately in VS Code with zero dependency
headaches, which is exactly what you want walking into a lab demo or an interview.

## How it works

```
Event (login / request / port hit / download)
        │
        ▼
IpActivityTracker (per-IP rolling history: failed logins, request
        │           rate, ports touched, last country, baseline traffic)
        ▼
11 Detectors run independently, each returns a risk score:
  Blacklist · Brute Force · SQL Injection · XSS · DDoS · Port Scan ·
  Bot User-Agent · Impossible Login · Malware Download · Suspicious
  Time · Behavior Anomaly (traffic-spike vs. the IP's own baseline)
        ▼
RiskScoreEngine sums every triggered rule's score
        ▼
ThreatClassifier: 0-20 SAFE · 21-50 LOW · 51-80 MEDIUM · 81-100 HIGH · 100+ CRITICAL
        ▼
AutoResponseService: CRITICAL → block the IP for 10 minutes automatically
        ▼
Live dashboard (http://localhost:8080) polls the stats API every 2s
```

## Project structure

```
src/com/threatdetection/
  Main.java                     entry point — starts server + simulator
  model/                        LogEvent, ThreatResult, EventType, ThreatLevel, DetectionOutcome
  tracking/                     IpActivityTracker (per-IP state), TrackingStore
  detector/                     11 independent Detector implementations
  engine/                       RiskScoreEngine, ThreatClassifier, ThreatDetectionEngine
  response/                     AutoResponseService (auto IP blocking)
  storage/                      InMemoryStore (swap for MySQL/JDBC when you extend it)
  server/                       ApiServer (built-in HttpServer, no framework) + dashboard HTML
  simulator/                    TrafficSimulator — generates live demo traffic automatically
```

## Run it in VS Code

1. Install the **Extension Pack for Java** in VS Code (if you don't have it).
2. Open this folder (`ThreatDetectionEngine`) in VS Code.
3. Open `src/com/threatdetection/Main.java` and click **Run** above `main`
   — or use the terminal:

```bash
cd ThreatDetectionEngine
javac -d out $(find src -name "*.java")
java -cp out com.threatdetection.Main
```

4. Open **http://localhost:8080** in your browser. You'll see live traffic
   (normal + simulated attacks) flowing into the dashboard immediately —
   the built-in `TrafficSimulator` generates events every ~0.8s so you don't
   need Postman just to see it work.

## Manually trigger specific attacks (for a live demo)

```bash
# Brute force (run this 6+ times quickly, or use a loop)
for i in {1..6}; do curl -s -X POST http://localhost:8080/api/event \
  -d "ip=9.9.9.9&eventType=LOGIN_FAILED&username=admin"; done

# SQL Injection
curl -X POST http://localhost:8080/api/event \
  -d "ip=8.8.4.4&eventType=HTTP_REQUEST&endpoint=/search&body=id=1' OR 1=1 --"

# XSS
curl -X POST http://localhost:8080/api/event \
  -d "ip=8.8.4.4&eventType=HTTP_REQUEST&endpoint=/comment&body=<script>document.cookie</script>"

# Port scan (several distinct ports from the same IP within a minute)
for p in 21 22 23 25 53 80 443 3306; do curl -s -X POST http://localhost:8080/api/event \
  -d "ip=6.6.6.6&eventType=PORT_ACCESS&port=$p"; done

# Malware download
curl -X POST http://localhost:8080/api/event \
  -d "ip=7.7.7.7&eventType=DOWNLOAD_REQUEST&file=payload.exe"

# Known-blacklisted IP (see ThreatDetectionEngine.java for the demo list)
curl -X POST http://localhost:8080/api/event -d "ip=1.2.3.4&eventType=HTTP_REQUEST"
```

Every response comes back as JSON with the risk score, threat level, and the
exact rules that fired — and it shows up on the dashboard in real time.

## Why this is stronger than a simple rule-based checker

Instead of one hardcoded `if (failedLogins > 5) block();`, every event is
scored against **11 independent signals** and the scores are summed. A
request only becomes CRITICAL when enough evidence stacks up — which mirrors
how real SOC / SIEM tools (Splunk, Wazuh, enterprise WAFs) actually work, and
it's far more resistant to both false positives and evasion than any single
rule.

The `BehaviorAnomalyDetector` also demonstrates **anomaly-based** detection
(comparing an IP's current request rate to its own rolling baseline) on top
of the **signature-based** detectors — a distinction interviewers will
specifically listen for.

## Extending it further (good "what's next" talking points)

- Swap `InMemoryStore` for MySQL via JDBC (schema: `logs`, `threats`,
  `blocked_ips`, `alerts`) — the interface is already isolated so this is a
  drop-in change.
- Move the hardcoded blacklist into a `blacklist` table or an external
  threat-intel feed.
- Add JWT-based auth to the dashboard/API with Spring Security if you migrate
  to Spring Boot.
- Add a `RuleConfig` loaded from a JSON/YAML file so risk weights can change
  without recompiling.
- Add unit tests per detector (JUnit 5) — each `Detector` is a pure function
  of `(LogEvent, IpActivityTracker)`, so they're trivial to test in isolation.

## Live Cyber Threat Map (new)

Open **http://localhost:8080/map** (also linked from the main dashboard).

| Mode | What it shows |
|------|---------------|
| Global Threat Map | Where attacks originate, animated routes into your server, click a marker for details |
| India Threat Map | State/city concentration of Indian sources |
| Target Map | Which endpoints, accounts, ports and files are being attacked |
| Attack Flow | Source -> Detection Engine -> Target, with blocked vs passed counts |

Marker popup: location (approximate), IP, threat type, risk, attack count, first/last seen, status (BLOCKED / ACTIVE).

- Fully offline: a built-in demo geo database and world outline, no API key or internet needed.
- The protected server location defaults to New Delhi. Change it with
  `java -Dtarget.lat=12.97 -Dtarget.lon=77.59 -Dtarget.city=Bengaluru -cp out com.threatdetection.Main`
- Extra worldwide demo attackers run by default; disable with `-Dgeo.demo=false`.
- For real geolocation, implement `geo/GeoIpProvider` (e.g. with MaxMind GeoLite2) and pass it to `ThreatMapService` in `Main`.
- IP geolocation is approximate (VPNs, proxies, ISP hubs). The UI never claims an exact attacker location.
- Existing detectors, scoring, blocking, API and dashboard are unchanged; the map only observes results.

---

# AEGIS module (added)

AEGIS is an additive layer: every original feature (detectors, scoring, auto-block, `/`, `/map`, `/api/*`,
PDF report, phishing checker) behaves exactly as before. AEGIS observes events and adds a new page and
log-ingestion sources. Open **http://localhost:8080/aegis**.

Code is organized by module under `com.threatdetection.aegis`:
`rules/` (extra detection rules), `ingest/` (log parsers + collectors), `intel/` (IP classification, reputation),
`geo/` (GeoIP), `storage/` (store + persistence), `web/` (API + page).

## What it adds
| Area | Feature |
|---|---|
| Dashboard | Severity counts, incidents, blocked IPs, ingestion rate, system health, risk chart, per-source status, time-range selector |
| Detection | Web access-log analysis (Apache/Nginx), firewall logs (Windows `pfirewall.log`, Linux netfilter/UFW), Windows Security log, Sysmon, path traversal, Log4Shell/command-injection/recon probes, repeated-connection and sensitive-port rules, explainable per-rule score breakdown (core vs aegis rules) |
| Map / intel | Internal vs external IP, offline threat-intel feeds, local reputation, attack sources and targets, time-range filter, playback, observed / API / simulated labelling, location quality labels |

Brute force and port scan are still done by the original detectors; ingested log lines are fed to them.

## Configuration (all optional, JVM system properties)
```
-Daegis.web.log=/var/log/nginx/access.log        web access log(s), comma separated
-Daegis.fw.log=/var/log/ufw.log                  firewall log (pfirewall.log or netfilter format)
-Daegis.win.security=true                        Windows Security log (Windows only, run as Administrator)
-Daegis.win.sysmon=true                          Sysmon log (Windows with Sysmon installed)
-Daegis.ingest.fromStart=true                    replay existing log content (default: only new lines)
-Daegis.intel.feeds=malicious:drop.txt,suspicious:tor.txt   feed files: one IP or IPv4 CIDR per line
-Daegis.geo.csv=geoip.csv                        GeoIP CSV (needs start/end IP or CIDR + latitude + longitude)
-Daegis.persist=false  /  -Daegis.data.dir=./aegis-data      alert persistence (default on)
```
Example: `java -Daegis.web.log=access.log -Daegis.fw.log=fw.log -cp out com.threatdetection.Main`

You can also push data over HTTP (counted as **API**, not Observed):
`curl -X POST "localhost:8080/aegis/api/ingest?type=web" --data-binary @access.log`  (`type=web|firewall|winxml`)

## Data honesty
* **Observed** = read from a real log source. **API** = submitted over HTTP, unverified. **Simulated** = built-in generators.
* Locations are estimates. Without `-Daegis.geo.csv`, observed/API events are **not plotted** (the original offline
  table is demo data); simulated events use demo locations and are drawn hollow/dashed.
* Reputation is `NO_DATA` unless you load a feed - an unknown IP is never reported as clean.
* Sysmon/Windows rules are behavioural heuristics and can produce false positives from admin tooling.

## Endpoints
`/aegis` page; `/aegis/api/overview|alerts|incidents|intel|events` (params `from`, `to` epoch ms or `range` minutes,
`level`, `source`, `q`, `limit`); `POST /aegis/api/ingest`.

---

# Platform website (new) - open http://localhost:8080/

`/` is now a full project website served by the same Java process (no extra dependencies, works offline apart from optional web fonts).
The original dashboard is still at `/classic`.

| Section | What it does |
|---|---|
| Hero | Live "latest decision": risk ruler plus every rule that added points |
| How it decides | Six-step pipeline with file names; scoring bands; worked examples |
| Rules | All 36 rules: trigger, points, attack-chain stage, MITRE ATT&CK technique, known weaknesses |
| Campaigns | Links events per attacker across a 5-stage chain (observe-only, advisory) |
| Attack lab | Fires real attacks through the real pipeline; shows per-step explanation and campaign risk |
| Live | KPIs, alert chart, top rules, recent detections, data sources (Observed / API / Simulated) |
| Proof | 65-case self-test run against the live rule code, plus limits we state ourselves |

New code: `src/com/threatdetection/platform/` (`RuleCatalog`, `CampaignAnalyzer`, `SelfTest`, `PlatformApi`, generated `PlatformHtml`).
Website source: `site-src/` (`style.css`, `body.html`, `app.js`). After editing, run `python3 site-src/build_page.py` to regenerate `PlatformHtml.java`.

New endpoints: `GET /api/platform/model|summary|campaigns|selftest`, `POST /api/platform/analyze`.

Changes to existing behaviour (small):
* `BotDetector` no longer adds "missing User-Agent" points to `PORT_ACCESS` events (firewall records have no HTTP headers).
* `/` serves the platform site; the old dashboard moved to `/classic`.

---

# Defense layer and source trust (added)

Full details: `docs/DEFENSE_AND_SOURCE_TRUST.md`. Everything is additive; with no new settings the engine only
*decides and records* (DRY_RUN) and talks to no outside service.

## Defensive response  (`/aegis/defense`, `/aegis/api/defense/*`)
| Level | What AEGIS does |
|---|---|
| LOW / MEDIUM | Monitor only |
| HIGH | Escalate to the administrator, propose an action, **wait for an analyst** |
| CRITICAL | Escalate; run a **reversible, time-limited** action only if policy allows, the data is OBSERVED, and 2+ distinct rules fired |

Actions: Windows Firewall block, file quarantine (moved, never deleted), session revocation, temporary account lock,
rate limiting, administrator escalation (console, `defense-escalations.log`, optional webhook). Temporary actions expire
and are undone automatically (also after a restart). Every decision goes to `aegis-data/defense-audit.tsv`, a hash-chained
log (operator, time, action, target, level, mode, result, reason); `GET /aegis/api/defense/audit?verify=1` re-checks the chain.

```
-Daegis.defense.mode=dryrun|enforce|off     default dryrun (nothing is changed on the machine)
-Daegis.defense.ttl.minutes=15              temporary action length (max 1440)
-Daegis.defense.auto=firewall,session,rate  what may run without an analyst (add lock, quarantine to opt in)
-Daegis.defense.quarantine.roots=C:\Users\me\Downloads   folders whose files may be quarantined (empty = off)
-Daegis.defense.webhook=https://...         optional escalation webhook
-Daegis.defense.protected.accounts=a,b      accounts that are never locked
```
Windows Firewall rules need an Administrator process. Run the policy tests with:
`java -cp out com.threatdetection.aegis.defense.DefenseSelfTest`

## Source trust and optional integrations
| Tag | Meaning |
|---|---|
| OBSERVED | Read from a configured local log (including Wazuh `alerts.json`) |
| API | Submitted over HTTP, unverified |
| SIMULATED | Generated by the simulators; never acted on, never sent to a third party |
| ENRICHED | Extra intelligence attached to an event (context only) |

```
-Daegis.wazuh.alerts=/var/ossec/logs/alerts/alerts.json   Wazuh alerts (also: POST /aegis/api/ingest?type=wazuh)
-Daegis.abuseipdb.key=...  (or env ABUSEIPDB_API_KEY)      AbuseIPDB reputation
-Daegis.vt.key=...         (or env VT_API_KEY)             VirusTotal IP / hash / URL
-Daegis.geo.csv=GeoLite2-City-Blocks-IPv4.csv              MaxMind GeoLite2 (CSV) for location
-Daegis.enrich=false  /  -Daegis.enrich.minLevel=MEDIUM
```
MITRE ATT&CK techniques are attached offline from `RuleCatalog`. Lookups are cached, rate-limited, time-limited and run
in the background; an unreachable service just leaves the event un-enriched, and "no data" is never shown as "safe".
Lookups: `GET /aegis/api/trust` (status), `GET /aegis/api/enrich?ip=|hash=|url=`.
Intel self-test: `java -cp out com.threatdetection.aegis.intel.EnrichmentSelfTest`

---

# Hardening release (added)

See `CHANGES-HARDENING.md`. Quick start for the new options:
```
-Daegis.blacklist.file=blocklist.txt        your own blocklist (IP or CIDR [label] per line)
-Daegis.fw.response=dry-run|enforce|off     Windows Firewall response (default dry-run; enforce needs Administrator)
-Daegis.response.confidence=0.7             auto-block threshold; below it a block waits for approval
-Daegis.response.approval=true              every block needs analyst approval
-Daegis.chain.autoblock=true                correlated CRITICAL findings may trigger an application block (default: OFF)
```
Tests: `java -cp out com.threatdetection.testing.DetectionTestSuite`


---

# Audit hardening release (read before upgrading)

## Breaking / behaviour changes
| Change | What you need to do |
|---|---|
| **All write endpoints now need an API key.** Loopback alone is no longer accepted. | Scripts send `X-API-Key: <key>` (or `Authorization: Bearer <key>`). Set `-Daegis.api.key=...` (or env `AEGIS_API_KEY`), or use the random per-run key in `aegis-data/api-key.txt`. The dashboards fetch it automatically from `/api/session` (disabled when you set your own key; the page then asks for it once per browser session). |
| Browser writes must be same-origin | Cross-site `Origin` / `Sec-Fetch-Site`, unknown `Host`, and unsupported `Content-Type` are refused (403 / 415). Extra hosts/origins: `-Daegis.allowed.hosts=a,b`, `-Daegis.allowed.origins=http://x:8080`. |
| `/api/event` validates input | Missing/invalid `ip`, unknown `eventType`, non-numeric or out-of-range `port` (0-65535), over-long fields now return **400** instead of being silently changed into another event. |
| `aegis.chain.autoblock` default is now **false** | Set `-Daegis.chain.autoblock=true` to restore automatic blocking on CRITICAL attack chains. |
| One firewall for the whole product | The Defense layer no longer runs netsh itself; it uses the shared adapter (rule name `AEGIS-BLOCK-<ip>-IN`). Real OS enforcement is controlled **only** by `-Daegis.fw.response=enforce`. Defense in `enforce` mode with the adapter in dry-run reports the action as FAILED ("not enforced"), never as applied. |

## New / documented limits
* `POST /api/event` body: 64 KB. Pushed log batches (`/aegis/api/ingest`): `-Daegis.max.body` (default 2 MB, max 32 MB) -> **413** when exceeded.
* Write rate limit per client: `-Daegis.api.rate` requests/s (default 50, burst 100) -> **429**.
* HTTP server: 16 workers + queue of 256; request time limit 20 s, response 60 s, idle 30 s. **Backpressure:** when workers and queue are full the accepting thread serves the request itself, so new connections wait in the OS backlog (128) or are refused; accepted requests are never dropped silently.
* Alert files rotate at 50 MB into `alerts.tsv.1 ... .N` (`-Daegis.rotate.keep`, default 5). Only the archive beyond that is deleted, and the deletion is logged.
* In-memory block table cap: `-Daegis.block.max` (default 50 000), enforced atomically.

## API additions (backward compatible)
`POST /api/event` keeps `blocked` (application-level block) and adds `appBlocked`, `osFirewall` (`NOT_ATTEMPTED | NOT_ATTACHED | APPLIED | ALREADY_BLOCKED | DRY_RUN | AWAITING_APPROVAL | NO_ACTION | REFUSED | FAILED | DISABLED`) and `osFirewallEnforced` (true only when a real firewall rule exists).

## Build and test (no build tool; plain JDK 21)
```
find src -name "*.java" > srcs.txt && javac -Xlint:all -d out @srcs.txt
java -cp out com.threatdetection.testing.HardeningTestSuite     # audit regression tests (fake netsh, loopback HTTP)
java -cp out com.threatdetection.testing.DetectionTestSuite     # rules, mapper, intel, adapter, correlation
java -cp out com.threatdetection.aegis.defense.DefenseSelfTest
java -cp out com.threatdetection.aegis.intel.EnrichmentSelfTest
```
