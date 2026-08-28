# Roadmap & Status

Status legend: ✅ done · 🟡 partial · ⬜ not started

## Phase 1 — MVP (detection core) ✅

The complete detect pipeline, runnable from a single machine.

- ✅ Iterative trusted walk (root → TLD → authoritative), with referral caching
  and CNAME following — `trusted_walk.py`
- ✅ Resolver probe with latency, `AD` flag, retries — `resolver_query.py`
- ✅ Directional set comparison → seven verdicts — `comparator.py`
- ✅ SQLite storage backend — `storage/sqlite_store.py`
- ✅ CLI: `check`, `run-once`, `alerts`, `report`, `serve` — `__main__.py`
- ✅ Unit test suite (25 tests) — `tests/`

## Phase 2 — Telemetry & dashboards 🟡

- ✅ Prometheus exporter on `:9109` — `metrics.py`
- ✅ Self-contained HTML report (`argus report`) — `report.py`
- ✅ Docker Compose stack (Argus + Prometheus + Grafana) with a provisioned
  dashboard — `docker-compose.yml`, `grafana/`
- ✅ TTL freshness tracking (`stale_ttl`) — `comparator._ttl_health`
- ⬜ Run the Grafana stack end-to-end (needs Docker Desktop installed)
- ⬜ Alerting rules (e.g. Prometheus Alertmanager → email/Slack)

## Phase 3 — DNSSEC 🟡

- ✅ Signed + broken-zone probes → posture classification — `dnssec.py`
- ⬜ Per-resolver posture scoring trended over time in Grafana
- ⬜ Validate the trusted walk *itself* with DNSSEC (defends against on-path
  forgery of ground truth)

## Phase 4 — Heuristics ⬜

- ⬜ Response-timing anomaly modelling (off-path injection hints)
- ⬜ Out-of-bailiwick record detection
- ⬜ Query-flood / burst rules

## Phase 5 — Multi-vantage ⬜

- 🟡 Vantage labelling already present on every sample (`vantage` field)
- ✅ Single-node consensus heuristic separating GeoDNS from poisoning
  (`systemic_suspects`) — the approximation of true multi-vantage voting
- ⬜ Several real probe nodes per ISP
- ⬜ Cross-vantage consensus voting

## Phase 6 — National dashboard ⬜

- ⬜ Resolver software fingerprinting
- ⬜ Matching fingerprints against known CVEs
- ⬜ Public reporting portal

## Validation status (evaluation harness) ✅

- ✅ Lab attacker: a loopback-only malicious resolver — `evaluation/malicious_resolver.py`
- ✅ Attack demo proving true-positive detection (DISJOINT, EXTRANEOUS, PHANTOM
  caught; honest control not flagged) — `evaluation/run_attack_demo.py`

## Suggested next steps

1. Install Docker Desktop and bring up the Grafana dashboard (finishes Phase 2).
2. Add Sri Lankan bank / government domains to the watch-list once each is
   confirmed to have a stable address set.
3. DNSSEC-validate the trusted walk (Phase 3 hardening).
4. Stand up a second vantage point to begin real consensus voting (Phase 5).
