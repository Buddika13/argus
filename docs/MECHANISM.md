# How Argus Works — The Detection Mechanism

## The problem

DNS has no built-in way for a client to tell a genuine answer from a forged
one. That is exactly why **cache poisoning** works: an attacker injects a false
record into an ISP's caching resolver, and every user of that resolver is
silently sent to the wrong address — a fake bank, a phishing page — while their
browser shows the correct domain name.

## The insight Argus exploits

There is one asymmetry an attacker cannot overcome:

> **Only the domain's owner can define that domain's real records.**

An attacker can lie to a *cache*, but cannot change what the domain's own
**authoritative nameservers** publish. So if we read the authoritative data
ourselves — without trusting any cache — we hold ground truth to compare
against.

## Two lookups, then a comparison

For every `(domain, resolver)` pair, Argus performs two independent lookups.

### 1. The direct path — ask the resolver under test
A normal recursive query (`RD=1`, `DO=1`) to the ISP resolver, exactly like a
real user's device would send. We record the address set, the smallest TTL, the
`AD` (authenticated) flag, the response code and the latency.
*Code: `src/argus/resolver_query.py`.*

### 2. The trusted path — walk the hierarchy ourselves
We do **not** ask another recursive resolver — that would just move our trust
sideways to a second cache. Instead we resolve the name iteratively from the
root:

```
root servers        "who handles .com?"        -> referral to the com. servers
com. servers        "who handles example.com?" -> referral to example.com. servers
example.com. servers "what is example.com A?"  -> the authoritative answer
```

Queries are sent with **recursion disabled (`RD=0`)** so each server hands back a
referral we follow ourselves. The 13 root server addresses are hard-coded,
because fetching them would reintroduce the very trust we are removing. Only
nameserver *addresses* (infrastructure) are briefly cached; the final answers
are never cached, since a stale answer would become a false accusation.
*Code: `src/argus/trusted_walk.py`.*

## The comparison — sets, not first-IP

The central design decision: comparison is done on **sets of addresses**, never
first-IP-to-first-IP. Large sites behind CDNs publish many addresses and any one
resolver holds only some of them, so naive equality would flag half the internet
as poisoned.

The question that actually matters is **directional**:

> Did the resolver return an address the authoritative servers never published?

- Resolver holds **fewer** addresses than the zone → normal caching / load
  balancing. **Not an alert.**
- Resolver holds an address that is **nowhere** in the zone → nobody can
  legitimately invent this. **This is the signal.**

*Code: `src/argus/comparator.py`.*

### Verdicts

| Verdict | Meaning | Alerts? |
| --- | --- | --- |
| `MATCH` | Resolver set equals trusted set. | no |
| `SUBSET` | Resolver ⊂ trusted. Load balancing / partial cache. | no |
| `EXTRANEOUS` | Overlap **plus** unpublished addresses. Partial injection. | **yes** |
| `DISJOINT` | No overlap, both non-empty. Full hijack. | **yes** |
| `PHANTOM` | Trusted says NXDOMAIN; resolver invented an answer. | **yes** |
| `MISSING` | Trusted has records; resolver returned none. Filtering. | no |
| `ERROR` | The measurement itself failed. | no |

`ERROR` matters as much as the alerts: if the trusted walk times out, the sample
becomes `ERROR`, **never** a false accusation of poisoning.

## The three supporting health dimensions

Correctness alone is a snapshot. Argus tracks resolver *health* over time:

- **Freshness** — a cached TTL counts *down*, so it must never exceed the zone's
  published TTL. One that does was either injected with an inflated TTL (a trick
  to make poison persist) or served past expiry. Flagged as `stale_ttl`.
- **Availability** — per-query latency and failure rate.
- **DNSSEC posture** — two probes: does the resolver set `AD` on a **signed**
  zone, *and* does it return SERVFAIL for a deliberately **broken** zone? A real
  validator must do both. One that claims `AD` but still serves the broken zone
  is `AD_ONLY` — worse than not validating, because it lies to its clients.
  *Code: `src/argus/dnssec.py`.*

## Separating GeoDNS noise from real attacks

Hyper-distributed domains (Google, Facebook, Akamai) hand out different IPs per
location, so a single-vantage set comparison flags them as `DISJOINT` even when
nothing is wrong. Argus applies a **consensus heuristic**:

> If **every** resolver disagrees with our walk the same way, the odd one out is
> our single-vantage walk — the domain is geo-load-balanced, not poisoned. If
> only **one** resolver disagrees while its peers match, that is a targeted
> attack.

Systemic disagreements are reported separately from real alerts.
*Code: `systemic_suspects()` / `real_alerts()` in `comparator.py`.*

## Known limitations

1. **GeoDNS** — mitigated by the consensus heuristic above and by keeping CDN
   giants off the default watch-list; fully solved only with multiple vantage
   points (roadmap Phase 5).
2. **On-path attackers** — an adversary who can intercept traffic could forge the
   trusted walk too; the answer is DNSSEC validation *of the walk itself* (not
   yet implemented).
3. **Sampling gaps** — a poisoned entry lives only until its TTL expires; a long
   sweep interval can miss short-lived injections, motivating multi-vantage,
   higher-frequency probing.
