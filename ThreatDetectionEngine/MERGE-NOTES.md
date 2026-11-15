# Merge notes: AEGIS Corrected + Defense + Hardened

Base: AEGIS-1-Corrected. Both Defense and Hardened were built on it, so this is a three-way merge.

## What is included
* **Corrected** (base): platform site, AEGIS pipeline, offline geo, threat map.
* **Defense**: `aegis/defense/*` (escalation, reversible actions, quarantine, hash-chained audit),
  `aegis/intel/*` (AbuseIPDB, VirusTotal, MITRE), Wazuh ingest, `/aegis/defense` page, `EnrichApi`.
* **Hardened**: `normalization/*`, `correlation/*` (attack chains), `decision/ConfidenceEngine`,
  `intelligence/ThreatIntelService`, `response/*` (policy engine, Windows firewall adapter, audit),
  `testing/*`, tighter SQLi / Bot / Blacklist detectors, `AegisResponseApi`.

## Files that both branches edited (merged by hand, both changes kept)
`Aegis.java`, `AegisPipeline.java`, `AegisSignal.java`, `README.md`.
All other files came from exactly one branch, unchanged.

## Verified
* Compiles with JDK 21, no errors.
* `DetectionTestSuite` 57/57, `DefenseSelfTest` 43/43, `EnrichmentSelfTest` 20/20,
  platform self-test 91/91 (served at `/api/platform/selftest`).
* Server smoke test: web + Wazuh ingestion works; Defense queued a HIGH event for analyst approval;
  Hardened audit chain intact; no exceptions in the log.

## Known overlap (read before using enforce mode)
Defense and Hardened each have their own Windows Firewall blocker and audit log:
| | Defense | Hardened |
|---|---|---|
| Switch | `-Daegis.defense.mode` | `-Daegis.fw.response` |
| Rule name | `AEGIS-block-<ip>` | `AEGIS-BLOCK-<ip>` |
| Audit | `aegis-data/defense-audit.tsv` | in-memory chain, `/aegis/api/response` |

Both default to dry-run. Windows rule names are case-insensitive, so **enforce only one of them at a time**,
otherwise they can collide on the same IP. Merging them into one blocker is a sensible next step.
