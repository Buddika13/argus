# Argus

**A DNS Caching-Server Health and Cache-Poisoning Monitoring System**

> Status legend used throughout this document:
> ✅ **Implemented & tested** · 🟡 **Partial / in progress** · ⬜ **Future work**

A single-vantage research prototype (Python + SQLite) that continuously monitors
caching/recursive DNS resolvers, independently verifies their answers against the
authoritative DNS hierarchy, monitors resolver health, and flags DNS integrity
anomalies using deliberately cautious, multi-stage verification.

No machine learning. No external dataset. No Docker.

---

## 1. Project title

**Argus: A DNS Caching-Server Health and Cache-Poisoning Monitoring System.**
(A final-year Computer Networking / Security research project. The name refers to
the many-eyed watchman of Greek myth.)

## 2. Project overview

For each monitored resolver and each watch-list domain, Argus:

1. queries the resolver (the *direct path*);
2. independently resolves the same name by walking Root → TLD → Authoritative
   itself (the *verification path*);
3. compares the two answers as sets;
4. runs a multi-stage verification engine before assigning a final,
   conservatively-worded classification;
5. records health metrics (availability, latency, correctness, freshness) and
   DNSSEC posture;
6. stores everything in SQLite and renders an HTML dashboard.

The current prototype has been run against **public control resolvers**
(Google, Cloudflare, Quad9) from a **single vantage point**.

## 3. Research problem

DNS has no built-in way for a client to distinguish a genuine answer from a
forged one, which is what makes **cache poisoning** possible: an attacker injects
a false record into a caching resolver, and every downstream user is silently
misdirected while the domain name still looks correct. There is limited
continuous, independent monitoring of the *health and answer integrity* of the
caching resolvers that ordinary users depend on.

## 4. Motivation

Users rarely choose or audit their ISP's DNS resolver. A poisoned or misbehaving
resolver affects many people at once. A monitoring system that continuously and
independently checks resolver answers — while being careful not to cry "attack"
at every difference — would give operators and researchers visibility they
currently lack. Getting the **false-positive behaviour** right is as important as
detection, because CDNs and geo-load-balancing make naïve comparison unreliable.

## 5. Objectives

| # | Objective | Status |
|---|---|---|
| 1 | Query a monitored resolver and record answer, TTL, RCODE, latency | ✅ |
| 2 | Independently verify via Root → TLD → Authoritative | ✅ |
| 3 | Compare resolver vs authoritative as sets (A and AAAA) | ✅ |
| 4 | Avoid treating every mismatch as poisoning | ✅ |
| 5 | Classify integrity anomalies with multi-stage verification | ✅ |
| 6 | Monitor availability, latency, correctness, freshness | ✅ |
| 7 | Assess DNSSEC posture | ✅ |
| 8 | Store historical results | ✅ |
| 9 | Provide a dashboard | ✅ |
| 10 | Support multiple resolvers | ✅ (tested on 3 controls) |
| 11 | Monitor Sri Lankan ISP resolvers | 🟡 supported, **not yet tested** on real ISPs |
| 12 | Multi-vantage national deployment | ⬜ |

## 6. System architecture ✅

Single Python process, one module per component, backed by a local SQLite file:

```
        ┌──────────────── Scheduler (sweep loop) ────────────────┐
        │                                                        │
   probe.py                                              verifier.py
   (direct query)                                 (Root→TLD→Authoritative walk)
        │                                                        │
        └───────────────► comparison.py ◄────────────────────────┘
                                │  (set comparison → classification)
                                ▼
                        verification.py  (multi-stage anomaly engine)
                                │
             ┌──────────────────┼───────────────────┬───────────────┐
        integrity.py        dnssec.py           storage.py        dashboard.py
      (health metrics)   (DNSSEC posture)     (SQLite, 9 tables)  (HTML view)
```

## 7. DNS monitoring workflow ✅

One **sweep**: resolve ground truth once per `(domain, record type)`; then, for
each enabled resolver, query → compare → (if suspicious) verify → build a health
record → store; finally aggregate per-resolver health metrics. Sweeps run once
(`run-once`) or continuously (`serve`) with graceful shutdown and per-query
error isolation (one failing resolver never stops the sweep).

## 8. Direct resolver verification ✅

`probe.py` sends an ordinary recursive query (RD=1) to the monitored resolver and
records the answer set, minimum TTL, RCODE, response time, and the AD flag.
Handles A / AAAA / CNAME and the failure modes timeout, SERVFAIL, NXDOMAIN,
connection error, and malformed response (never raises). *Tested (unit + live).*

## 9. Authoritative DNS verification ✅

`verifier.py` resolves each name **itself**, iteratively, from the 13 built-in
root server addresses, following referrals with recursion disabled. Out-of-
bailiwick glue is resolved by our **own** sub-walk (not a recursive resolver), so
ground truth does not depend on another cache. CNAME chains are followed.
*Tested (live).* ⚠️ The walk is **not yet DNSSEC-validated** (see Limitations).

## 10. DNS response comparison ✅

`comparison.py` compares answers as **sets**, directionally: the danger signal is
an address the resolver returned that the authoritative servers never published.
Classes: `NORMAL`, `BENIGN_DIFFERENCE`, `ANOMALY` (Stage-1 only),
`POSSIBLE_CACHE_POISONING`, `VERIFICATION_FAILED`. A failed measurement is
`VERIFICATION_FAILED`, never an alert. *17 unit tests.*

## 11. Multi-IP handling ✅

A and AAAA are compared as order-independent sets. A resolver returning a
**subset** of authoritative addresses (normal CDN/load-balancing) is
`BENIGN_DIFFERENCE`, not an anomaly. *Tested.*

## 12. Health monitoring ✅

`integrity.py` computes raw, transparent metrics per resolver — availability %,
average latency, timeout/SERVFAIL/error rates, correctness rate, anomaly rate,
freshness status — each with a documented formula. There is **no opaque
composite health score**. *Tested.*

## 13. DNSSEC ✅ (posture) · 🟡 (full validation)

`dnssec.py` determines, using safe public test zones (`dnssec-tools.org`,
`dnssec-failed.org`): whether a zone is signed, whether a resolver **validates**
(AD on a signed zone, SERVFAIL on a bogus zone), and a per-response security
status (SECURE / INSECURE / BOGUS / INDETERMINATE). Results are stored and shown
on the dashboard. *15 unit tests + live data.*
🟡 It does **not** perform full local RRSIG-chain validation; signedness is
judged via a reference resolver. DNSSEC is used as *supporting* evidence only.

## 14. Anomaly detection ✅

`verification.py` runs a multi-stage engine over a Stage-1 mismatch: re-walk the
hierarchy, cross-check independent control resolvers, consider DNSSEC, and check
persistence across repeated queries. Only a persistent, uncorroborated,
poisoning-shaped result becomes `POSSIBLE_CACHE_POISONING`. **The system never
claims to prove an attack — the strongest label is "possible".** *Tested,
including an injected forged answer (controlled unit test) that is correctly
detected as `POSSIBLE_CACHE_POISONING`.*

## 15. Database ✅

`storage.py` — SQLite, 9 tables (`resolvers`, `domains`, `query_results`,
`authoritative_results`, `comparisons`, `health_metrics`, `anomalies`, `alerts`,
`dnssec_status`) plus a `monitoring_events` view for historical analysis.
Parameterised queries; schema creation is idempotent and never deletes data.
*Tested.*

## 16. Dashboard ✅

`dashboard.py` — a self-contained HTML page (no server required) showing system
status, per-resolver health (availability, latency, correctness, freshness,
DNSSEC), recent queries, anomalies, and possible-poisoning events. A **live
auto-refreshing** mode (`argus dashboard`) re-reads the database on every
request. Clear "No data available" state. *Tested.*

## 17. Technology stack

- **Language:** Python 3.10+ (developed on 3.12)
- **DNS:** [`dnspython`](https://www.dnspython.org/)
- **Config:** `PyYAML`
- **Storage:** SQLite (standard library)
- **Dashboard:** standard-library `http.server` + self-contained HTML/CSS
- **Analysis (optional):** `matplotlib` for evaluation graphs
- No ML, no external dataset, no Docker.

## 18. Installation

```bash
git clone https://github.com/Buddika13/argus.git
cd argus
python -m venv .venv
# Windows:
.venv\Scripts\python.exe -m pip install -r requirements.txt
# Linux/macOS:
# source .venv/bin/activate && pip install -r requirements.txt
```

## 19. Configuration

| File | Purpose |
|---|---|
| `config/config.yaml` | Sweep interval, timeouts, DNSSEC toggle, thresholds, DB path |
| `config/resolvers.yaml` | Monitored resolvers + controls. **ISP IPs are placeholders** (RFC 5737 documentation range); replace with real addresses and set `enabled: true`. No real ISP IP is hard-coded. |
| `config/watchlist.txt` | Monitored domains |
| `.env` (optional) | `ARGUS_VANTAGE` — this probe node's name |

## 20. How to run

```bash
python -m argus status        # configuration + database readiness
python -m argus run-once      # one monitoring sweep
python -m argus report        # write report.html and open it
python -m argus dashboard     # live auto-refreshing dashboard (http://127.0.0.1:8080)
python -m argus serve         # continuous monitoring (Ctrl+C to stop)
```

Database helper: `python scripts/init_db.py [--with-sample-data]`.

## 21. Example ACTUAL output

Real output from the current code (single query traced through the pipeline):

```
(2) DNS QUERY PERFORMED : cloudflare.com A @ 8.8.8.8 (google)
(3) TARGET RESOLVER RESP: rcode=NOERROR
(5) A RECORDS FOUND     : ['104.16.132.229', '104.16.133.229']
(6) TTL                 : 300
(7) RESPONSE TIME       : 65.9 ms   AD=True
(4) AUTHORITATIVE VERIFY: rcode=NOERROR  records=[...same...]  ttl=300
    delegation chain    : . -> com. | com. -> cloudflare.com.
(8) COMPARISON RESULT   : NORMAL -- resolver answer set matches authoritative
```

A real sweep summary (3 control resolvers, 4 domains, A+AAAA):

```
sweep done — 24 queries, 0 anomalies, 0 failures
```

Real DNSSEC status (stored during a sweep):

```
google  cloudflare.com  signed=1 posture=VALIDATING security=SECURE
google  google.com      signed=0 posture=VALIDATING security=INSECURE
```

## 22. Testing ✅

Automated suite (`python -m unittest discover -s tests -p "test_*.py"`):

```
Ran 75 tests ... OK
```

Coverage includes: the direct probe (incl. timeout/SERVFAIL/NXDOMAIN/malformed),
the comparison engine (all classes), health metrics, the GeoDNS consensus logic,
DNSSEC assessment, the SQLite layer, the scheduler (incl. resilience and an
injected-poisoning detection case), and the full backend→database→dashboard flow.

## 23. Experimental evaluation

A clean, coherent dataset was collected (`scripts/collect_eval.py`): **6 sweeps,
144 queries, 3 control resolvers, 0 failures**, from a single vantage point.
Eight research graphs were generated from this real data (`scripts/graph_eval.py`
→ `graphs/`). Actual results:

| Metric | Result |
|---|---|
| Availability | 100% (all three resolvers) |
| Query success | 100% (144/144 NOERROR) |
| Mean latency | Cloudflare 26 ms, Quad9 66 ms, Google 80 ms |
| Correctness | Quad9 100%, Google 97.9%, Cloudflare 95.8% |
| TTL / freshness | all ratios ≤ 1.0 (no inflation observed) |
| DNSSEC | controls VALIDATING; signed zones SECURE, unsigned INSECURE |
| Integrity anomalies | 3, all on GeoDNS domains (google.com / microsoft.com) |

**Interpretation (deliberately cautious).** The three anomalies were flagged at
most as `POSSIBLE_CACHE_POISONING`; because they occurred on geo-distributed
domains under honest resolvers from a single vantage, they are best interpreted
as **false positives**, not evidence of an attack. **No real cache-poisoning
attack was detected or proven in the live experiment** — true-positive detection
was validated only against an injected answer in a controlled unit test. This
distinction between *"integrity anomaly detected"* and *"cache poisoning proven"*
is intentional and central to the project.

## 24. Limitations

- **Single vantage point** → residual GeoDNS/CDN false positives; the dominant
  limitation.
- **ISP resolvers not yet tested** — `resolvers.yaml` ships placeholder IPs;
  results so far concern public control resolvers only.
- **No proven poisoning** — detection of a real attack was not demonstrated
  live; only an injected lab case in unit tests.
- **Authoritative walk is not DNSSEC-validated** — ground truth is trusted on
  the network path.
- **DNSSEC** — posture and per-response status only, not full local RRSIG-chain
  validation.
- **Scale** — sequential sweeps and per-row commits; a research prototype, not a
  national deployment.
- **Short observation window** in the reported experiment (minutes, not days).

## 25. Ethical considerations

Argus issues only ordinary DNS queries, at a low and configurable rate, against
resolvers its operator is entitled to query. It never attempts to poison, flood,
or otherwise interfere with any resolver. Detection involving forged answers is
currently exercised only with injected answers in controlled local unit tests;
any future live-attacker experiment would target a **loopback resolver under the
author's control**. No third-party resolver, user, or production system is ever
attacked.

## 26. Future work

- ⬜ Multiple **vantage points** with cross-vantage consensus (to remove GeoDNS
  false positives).
- ⬜ **DNSSEC-validate the authoritative walk** itself.
- ⬜ Test against **real Sri Lankan ISP resolvers**.
- ⬜ Concurrency, delegation caching, and retention for larger scale.
- ⬜ A packaged **lab-attacker** harness for reproducible true-positive
  (detection) experiments.
- ⬜ Alerting integrations (email/webhook).

## 27. Research references

1. P. Mockapetris, *Domain Names — Concepts and Facilities / Implementation and
   Specification*, RFC 1034 & RFC 1035, 1987.
2. D. Kaminsky, *Black Ops 2008: It's the End of the Cache As We Know It*, Black
   Hat USA, 2008.
3. R. Arends et al., *DNS Security Introduction and Requirements / Resource
   Records / Protocol Modifications for DNSSEC*, RFC 4033–4035, 2005.
4. A. Hubert and R. van Mook, *Measures for Making DNS More Resilient against
   Forged Answers*, RFC 5452, 2009.
5. S. Son and V. Shmatikov, *The Hitchhiker's Guide to DNS Cache Poisoning*,
   SecureComm, 2010.
6. V. Le Pochat et al., *Tranco: A Research-Oriented Top Sites Ranking Hardened
   Against Manipulation*, NDSS, 2019.

*(Please verify and format these to your institution's citation style.)*

## 28. Author information

- **Author:** [Your Name] — final-year Computer Networking / Security project
- **GitHub:** [@Buddika13](https://github.com/Buddika13) · repository:
  <https://github.com/Buddika13/argus>
- **Contact:** madushanibuddika65@gmail.com
- **Institution / Supervisor:** [University / Department] · [Supervisor name]

*(Fill in the bracketed fields. Remove the email here if you prefer not to
publish it.)*

---

## License

Add a license of your choice (e.g. MIT) as `LICENSE` before publishing.
