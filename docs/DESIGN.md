# Design & Architecture

## Design goals

1. **Ground truth without a second cache.** Never verify one resolver by asking
   another; walk the authoritative hierarchy directly.
2. **No false positives on legitimate load balancing.** Compare address *sets*
   directionally, not first-IP equality.
3. **Health over time, not a one-off verdict.** Correctness, freshness,
   availability and DNSSEC posture, all as time series.
4. **A well-behaved network client.** Low, configurable query rates; Argus only
   ever sends ordinary DNS queries.
5. **Runs from a laptop to a national fleet.** SQLite and a console for a single
   node; Prometheus/Grafana/Influx and Docker for many vantage points — same
   detection core throughout.

## Component overview

```
                        ┌─────────────────────────────┐
   config/ ───────────► │  config.py    (Settings)    │
   (yaml + watchlist)   └─────────────┬───────────────┘
                                      │
                        ┌─────────────▼───────────────┐
                        │  scheduler.py  (Monitor)     │  the sweep loop
                        └───┬───────────────┬──────────┘
              ground truth  │               │  direct answer
                 ┌──────────▼────┐   ┌───────▼──────────┐
                 │ trusted_walk  │   │ resolver_query   │
                 │ root→TLD→auth │   │ ask the resolver │
                 └──────────┬────┘   └───────┬──────────┘
                            └──────┬──────────┘
                            ┌──────▼──────┐
                            │ comparator  │  set comparison → Verdict
                            └──────┬──────┘
                     ┌────────────┼────────────┬───────────────┐
              ┌──────▼─────┐ ┌────▼─────┐ ┌────▼──────┐  ┌──────▼──────┐
              │ storage/   │ │ metrics  │ │ report.py │  │ dnssec.py   │
              │ sqlite|inf │ │ Prom     │ │ HTML page │  │ posture     │
              └────────────┘ └──────────┘ └───────────┘  └─────────────┘
```

## Module responsibilities

| Module | Responsibility |
| --- | --- |
| `models.py` | Dataclasses and the `Verdict` / `DnssecPosture` enums. No behaviour beyond derived properties; the shared vocabulary for every stage. |
| `config.py` | Defaults + YAML overrides + env vars → a resolved `Settings`. Loads `resolvers.yaml` and `watchlist.txt`. |
| `trusted_walk.py` | Iterative root→TLD→authoritative resolution. The ground-truth half. |
| `resolver_query.py` | One recursive query to a resolver under test, timed. The direct half. |
| `comparator.py` | Two answers → a `Verdict`, plus the GeoDNS consensus heuristic. The research core. |
| `dnssec.py` | Signed + broken-zone probes → a per-resolver `DnssecPosture`. |
| `scheduler.py` | Owns the probes and store; runs one sweep or loops forever. |
| `storage/` | Pluggable backends: `sqlite` (default), `influx` (optional), `none`. |
| `metrics.py` | Prometheus exporter, labelled by resolver and ISP. |
| `report.py` | Renders a sweep into a single self-contained HTML dashboard. |
| `__main__.py` | The `argus` CLI. |
| `evaluation/` | The lab attacker and attack demo — validation only, never imported by the detector. |

## Key design decisions (and the reasoning)

- **Ground truth is collected once per sweep, then shared across all resolvers.**
  Cheaper on the root servers, and *more correct*: every resolver is judged
  against the same authoritative snapshot, so a record that changes mid-sweep
  cannot make one ISP look poisoned relative to another.
  *(`scheduler._collect_ground_truth`.)*

- **Set comparison is directional.** A subset is benign; an unpublished address
  is the signal. This single choice is what makes the tool usable against
  real CDN-hosted domains.

- **Failed measurements are `ERROR`, never alerts.** The comparator checks for
  errors on either side *first*. A broken measurement masquerading as a
  detection would be the worst kind of false positive.

- **DNSSEC needs two probes, not one.** Setting `AD` proves nothing on its own;
  the resolver must also *refuse* a broken zone.

- **The attacker lives outside the product.** `evaluation/` is never imported by
  `argus/`; the detector has no dependency on its own test attacker.

- **Storage receives already-classified samples.** Backends never decide what is
  healthy, so changing the database can never change a verdict.

## Data model

`Comparison` is the atomic sample — one resolver, one domain, one record type,
one verdict — carrying both source answers and the derived fields (`unpublished`,
`missing`, `ttl_ratio`, `stale_ttl`). It flattens to a row via `to_row()` for any
storage backend, keeping backends ignorant of the detection logic.

## Deployment shapes

- **Single node (development / a report):** SQLite + the CLI. Zero external
  services. `python -m argus report` produces a shareable HTML page.
- **Fleet (national monitoring):** Docker Compose runs Argus + Prometheus +
  Grafana; several probe nodes each carry a `vantage` label, and consensus
  across vantages separates localized poisoning from legitimate geo-routing.
