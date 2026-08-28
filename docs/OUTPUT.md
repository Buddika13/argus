# Example Output

All output below is **real** — captured from actual runs on a development
machine against the live internet and the lab attacker. Addresses reflect DNS at
the time of capture and will differ when you run it.

## 1. Single check (`argus check`)

```
> python -m argus check example.com --resolver 1.1.1.1

example.com  A
  trusted : ['104.20.23.154', '172.66.147.243']  rcode=NOERROR
    chain : . -> com. | com. -> example.com.
  1.1.1.1        : ['104.20.23.154', '172.66.147.243']  rcode=NOERROR  58 ms  AD=True
  VERDICT : MATCH
```

The resolver's set equals the set from our own root→TLD→authoritative walk, so
the verdict is `MATCH`.

## 2. Attack validation (`evaluation/run_attack_demo.py`)

This is the key result: Argus versus a deliberately poisoned lab resolver.

```
==================================================================================
ARGUS ATTACK VALIDATION  —  real trusted walk vs. a poisoned lab resolver
==================================================================================
(lab attacker listening on 127.0.0.1:52140)

### example.com   (attacker mode: disjoint)
  truth (real walk): ['104.20.23.154', '172.66.147.243']  rcode=NOERROR
  attacker returned: ['6.6.6.6']  rcode=NOERROR
  ARGUS VERDICT    : DISJOINT  <== ALERT
    forged/unpublished addresses caught: ['6.6.6.6']

### github.com   (attacker mode: extraneous)
  truth (real walk): ['20.205.243.166']  rcode=NOERROR
  attacker returned: ['20.205.243.166', '6.6.6.6']  rcode=NOERROR
  ARGUS VERDICT    : EXTRANEOUS  <== ALERT
    forged/unpublished addresses caught: ['6.6.6.6']

### wikipedia.org   (attacker mode: truthful)
  truth (real walk): ['103.102.166.224']  rcode=NOERROR
  attacker returned: ['103.102.166.224']  rcode=NOERROR
  ARGUS VERDICT    : MATCH
    expected         : MATCH  (honest -> no false alarm)

### no-such-name-argus-test-zzz.com   (attacker mode: phantom)
  truth (real walk): (none)  rcode=NXDOMAIN
  attacker returned: ['6.6.6.6']  rcode=NOERROR
  ARGUS VERDICT    : PHANTOM  <== ALERT

----------------------------------------------------------------------------------
TALLY : {'DISJOINT': 1, 'EXTRANEOUS': 1, 'MATCH': 1, 'PHANTOM': 1}
ALERTS RAISED: 3  (poisoning attempts detected)
```

Interpretation:

- Full hijack → `DISJOINT` ✅
- Partial injection (real IP + one forged) → `EXTRANEOUS` ✅
- Answer for a non-existent name → `PHANTOM` ✅
- Honest answer from the same resolver → `MATCH`, **no false alarm** ✅

## 3. Full sweep (`argus run-once`)

With the cleaned watch-list (stable domains only), a sweep of the control
resolvers is clean:

```
============================================================
Sweep finished in 20.0s — 30 samples
Tally: {'MATCH': 30}
Likely poisoning (real alerts): 0
============================================================
```

If CDN-giant domains (google.com, facebook.com) are enabled, the consensus
heuristic separates their systemic disagreement from real poisoning:

```
Likely poisoning (real alerts): 0
Systemic disagreements (likely GeoDNS/CDN, not poisoning): facebook.com/A, google.com/A, google.com/AAAA
```

## 4. Unit tests (`python -m unittest discover -s tests -v`)

```
Ran 25 tests in 0.039s

OK
```

Covering: every verdict, TTL freshness, the GeoDNS consensus heuristic, config
and watch-list loading, and the lab attacker's response crafting.

## 5. Prometheus metrics (`argus serve`, then GET :9109/metrics)

```
argus_samples_total{isp="Google",resolver="google",verdict="MATCH"} 10.0
argus_samples_total{isp="Cloudflare",resolver="cloudflare",verdict="MATCH"} 8.0
argus_alerts_total{domain="...",resolver="...",verdict="DISJOINT"} 2.0
argus_query_latency_seconds_bucket{resolver="quad9",le="0.1"} 11.0
argus_query_latency_seconds_count{resolver="quad9"} 12.0
argus_dnssec_validating{resolver="google"} 1.0
```

## 6. DNSSEC posture

```
### DNSSEC posture (real signed + deliberately-broken zone probes)
  google      posture=VALIDATING  signed_AD=True  broken_refused=True
  cloudflare  posture=VALIDATING  signed_AD=True  broken_refused=True
```

Both resolvers authenticate the signed zone **and** refuse the broken one — the
definition of genuine validation.

## 7. HTML dashboard (`argus report`)

`argus report` writes `report.html` and opens it in the browser: summary cards
(resolvers, samples, likely poisoning, GeoDNS suspects), a verdict-distribution
bar, a table of genuine alerts, a separate table of systemic (GeoDNS) suspects,
and a per-resolver health table with average latency and DNSSEC posture. It is a
single self-contained file — no server required.
