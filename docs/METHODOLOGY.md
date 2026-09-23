# ARGUS — Methodology

*Authoritative Resolution Ground-truth Uniformity System*
Measurement methodology for assessing the integrity and health of Sri Lankan
ISP caching resolvers.

> **Framing:** ARGUS is a **measurement study of resolver behaviour**, not a
> live attack detector. It characterises what resolvers *do* over a measurement
> window and compares it against independently-derived ground truth. A window in
> which **no divergence is found is a valid, reportable result** — evidence that
> the monitored resolvers were faithful during that window.

---

## Table of contents

1. [Purpose & research questions](#1-purpose--research-questions)
2. [Scope](#2-scope)
3. [Terminology & definitions](#3-terminology--definitions)
4. [The two-path comparison](#4-the-two-path-comparison)
5. [Measurement subjects](#5-measurement-subjects)
6. [Health dimensions](#6-health-dimensions)
7. [Signal / detection modules](#7-signal--detection-modules)
8. [Verdict engine — Tiers 0–6](#8-verdict-engine--tiers-06)
9. [Exclusion hierarchy](#9-exclusion-hierarchy)
10. [Measurement procedure](#10-measurement-procedure)
11. [Data recorded per observation](#11-data-recorded-per-observation)
12. [Evaluation & validation](#12-evaluation--validation)
13. [Operational deployment: how an ISP uses ARGUS](#13-operational-deployment-how-an-isp-uses-argus)
14. [Threats to validity & limitations](#14-threats-to-validity--limitations)
15. [Ethical constraints](#15-ethical-constraints)
16. [Reproducibility](#16-reproducibility)

---

## 1. Purpose & research questions

ARGUS independently re-derives the correct answer for a name from the DNS
hierarchy and checks each ISP caching resolver against it, producing a
reproducible integrity-and-health picture across Sri Lanka's major networks.

Proposed research questions (adapt to your dissertation):

- **RQ1 (Integrity).** Do the caching resolvers operated by major Sri Lankan
  ISPs return answers consistent with independently-derived authoritative ground
  truth, across a representative domain watchlist, over the measurement period?
- **RQ2 (Health).** What is the health profile — availability, latency, and
  TTL/freshness behaviour — of these resolvers?
- **RQ3 (DNSSEC posture).** Do these resolvers validate DNSSEC-signed answers and
  correctly reject deliberately-broken ones?
- **RQ4 (Attribution).** When divergences occur, can they be attributed to benign
  causes (GeoDNS, ISP policy) or do they constitute evidence of tampering under
  the exclusion hierarchy?

## 2. Scope

**In scope:**

- Public-facing caching resolvers of **SLT** (ASN 9329), **Dialog** (ASN 18001),
  **Mobitel** (ASN 45356), and **Hutch**.
- A small, fixed **domain watchlist** (4–6 names) spanning `.lk`, `.com`, `.net`,
  `.org`, with both DNSSEC-signed and unsigned examples.
- The four health dimensions and the signal modules in §6–§7.

**Out of scope:**

- **Broad TLD-server probing.** TLD servers are shared infrastructure, not
  measurement subjects — probing them adds no measurement value and creates
  ethics and reproducibility problems.
- **Attacking production infrastructure** of any kind (see §15).
- **Locally mirroring TLD/authoritative zones.** Ground truth is obtained by
  live iterative resolution, not by hosting a copy of the hierarchy.

## 3. Terminology & definitions

- **Caching (recursive) resolver.** The server that answers a client's query,
  caching results. Subscribers normally use their ISP's, assigned by DHCP.
- **Authoritative name server.** The server that holds the real zone data for a
  domain. **This is the only source of ground truth.**
- **Trusted path.** Iterative resolution from the root down to the authoritative
  server (`dig +trace`). Its final answer = ground truth.
- **Untrusted path.** A direct query to a caching resolver (`dig @resolver`).
  **Every caching resolver is on the untrusted side — including public ones
  (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`). Reputation is never ground truth.**
- **Bailiwick.** The zone a server is authoritative for. Records outside that
  zone appearing in a response are *out of bailiwick* and suspicious.
- **Ground-truth uniformity.** The property ARGUS measures: untrusted-path
  answers agreeing with the trusted-path answer.

## 4. The two-path comparison

For each `(resolver, domain)` pair, obtain two answers and compare them.

**Untrusted path — ask the caching resolver directly:**

```bash
dig @<resolver_ip> <domain> A +noall +answer
```

**Trusted path — walk the hierarchy from the root (ground truth):**

```bash
dig +trace <domain> A
# take the final answer returned by the authoritative name server
```

**Comparison rule — sorted IP *sets*, not first IP:**

- Extract the A/AAAA record set from each path.
- **Sort** each set and compare **set-equality**, not the first element. Many
  domains legitimately return multiple addresses (CDN / load balancing), so a
  first-IP comparison produces false mismatches.
- Record: `MATCH`, `SUBSET/SUPERSET` (partial overlap), or `DISJOINT` (no
  overlap — the strongest divergence).

## 5. Measurement subjects

### 5.1 Resolver enumeration (empirical discovery)

Do **not** copy IP lists from aggregator sites. Enumerate resolvers by
connecting to each ISP's network and discovering what it actually assigns:

```bash
# 1. Read the resolver the ISP handed you via DHCP
resolvectl status            # systemd-resolved view
cat /etc/resolv.conf         # classic view
nmcli dev show | grep DNS    # NetworkManager view

# 2. Confirm it is a recursive caching resolver
dig @<resolver_ip> example.com +stats

# 3. Classify reachability from an external vantage point (open vs closed)

# 4. Attribute ownership
whois <resolver_ip>          # cross-check ASN → SLT/Dialog/Mobitel/Hutch
```

Record each resolver in `config/resolvers.yaml` with IP, ISP/owner, ASN,
open/closed status, and side (**always** untrusted for caching resolvers).

### 5.2 Domain watchlist

A fixed **4–6 domain** list in `config/domains.yaml`, tagged by category:

- Mix of `.lk`, `.com`, `.net`, `.org`.
- At least one **DNSSEC-signed** domain and one **unsigned** domain.
- Optionally one **known-broken / test** signed name for validation probing.
- Keep the list small and stable so results are comparable across runs.

## 6. Health dimensions

Each resolver is scored on four dimensions:

- **Correctness** — untrusted answer set vs. trusted-path ground truth.
- **Freshness** — TTL behaviour: plausible values, sensible countdown between
  cached hits, no manipulated TTLs.
- **Availability / latency** — reachability, response time, error rate
  (SERVFAIL, timeouts).
- **DNSSEC validation posture** — validates signed answers; rejects broken ones.

## 7. Signal / detection modules

Modules are chosen for good false-positive properties. Each records a structured
result that feeds the verdict engine (§8).

- **IP-set divergence (primary).** Sorted set comparison (§4). Divergence is the
  headline signal but is *never* conclusive on its own (see §9).

- **TTL / freshness sanity.**
  ```bash
  dig @<resolver_ip> <domain> +noall +answer   # observe TTL, repeat to watch countdown
  ```
  Flags implausibly high/low or non-decrementing TTLs.

- **DNSSEC validation testing.** Probe a **signed** name and a **deliberately
  broken** one:
  ```bash
  dig @<resolver_ip> <signed_domain> +dnssec     # AD flag set ⇒ resolver validated
  dig @<resolver_ip> <broken_signed_name>        # SERVFAIL ⇒ validating; NOERROR+answer ⇒ NOT validating
  ```

- **Bailiwick checking (positive but suggestive).**
  ```bash
  dig @<resolver_ip> <domain> +norecurse +additional
  ```
  Inspect the Additional section for **out-of-bailiwick** records — a positive
  structural signal, but requires corroboration (Stage-4 evidence in §9).

- **Cross-resolver consensus.** Compare the untrusted answers of several
  resolvers. If one resolver disagrees with both the trusted path *and* its
  peers, the divergence is isolated to that resolver.

- **EDNS Client Subnet (ECS).**
  ```bash
  dig @<resolver_ip> <domain> +subnet=203.0.113.0/24
  ```
  Distinguishes legitimate **GeoDNS** variation from tampering by varying the
  client-subnet hint.

- **Cache snooping (RD=0).**
  ```bash
  dig @<resolver_ip> <domain> +norecurse
  ```
  Reveals whether a name is already cached (answer returned) without forcing
  recursion — useful for freshness and for observing cache state non-intrusively.

## 8. Verdict engine — Tiers 0–6

Every observation receives one tier. The ladder is **monotonic**: higher tiers
require the lower conditions to be cleared and demand progressively stronger
evidence. Escalation past a mismatch is gated by the exclusion hierarchy (§9).

| Tier | Name | Condition | Interpretation |
|---|---|---|---|
| **0** | Consistent / clean | Untrusted set == trusted-path set (sorted); no anomalies | Healthy, faithful resolver — the expected state |
| **1** | Benign variation explained | Sets differ but **fully explained** by GeoDNS / CDN / ECS / load balancing | Reconciled; not suspicious |
| **2** | Health issue (integrity unknown) | Resolver unreachable, SERVFAIL, timeout, or degraded latency | A **health** problem; correctness could not be assessed |
| **3** | Freshness / timing anomaly | Answer matches but TTL implausible, or a timing artefact is suspected | Low-grade signal; likely benign, worth logging |
| **4** | Unexplained divergence (candidate) | Set mismatch that **survived GeoDNS + timing exclusions**, no positive evidence yet | Anomaly worth investigating — **not** a poisoning claim |
| **5** | Corroborated divergence | Tier-4 mismatch **plus** a supporting structural signal (bailiwick violation, isolated cross-resolver disagreement, ECS-independent) | Strong suggestion; still not cryptographically proven |
| **6** | Conclusive tampering | Positive **cryptographic** proof — e.g. DNSSEC-validation failure on a signed name for which the resolver served a forged answer | Defensible poisoning / integrity-violation claim |

> **Reporting discipline:** the dissertation evidence panel should foreground
> **which tiers fired on which resolvers/domains**, not dashboard vanity metrics.
> Favour under-claiming: report Tiers 4–5 as *suggestive*, reserve "poisoning"
> for Tier 6.

## 9. Exclusion hierarchy

Before any divergence is characterised as tampering, it must survive five stages.
These act as **gates** on tier escalation (they decide whether a mismatch lands
at Tier 1/3 or is allowed to reach Tier 4+).

1. **Rule out GeoDNS.** Re-test with varied ECS / vantage points. If the
   difference tracks geography, classify as **Tier 1** (benign).
2. **Rule out timing artefacts.** Re-test to exclude races, mid-flight TTL
   expiry, and transient cache state. If timing-explained, classify as **Tier 3**.
3. **Rule out ISP policy interception.** Distinguish lawful/administrative
   redirection or filtering (e.g. a walled-garden / block page) from covert
   poisoning. Characterise interception honestly as *policy*, not attack.
4. **Require positive evidence.** A bare set mismatch is not proof. Demand a
   **cryptographic** (DNSSEC) or **structural** (bailiwick) positive signal to
   escalate to Tier 5/6.
5. **Characterise honestly.** Surviving cases without conclusive proof are
   reported as *suggestive* (Tier 4–5), not asserted as poisoning.

## 10. Measurement procedure

A single measurement **run**:

1. Load `config/resolvers.yaml` and `config/domains.yaml`.
2. For each `(resolver, domain)`:
   a. Query the **untrusted path** (`dig @resolver`).
   b. Compute the **trusted-path** ground truth (`dig +trace`), TTL-aware
      (re-derive when cached truth has expired).
   c. Run the applicable **signal modules** (§7).
   d. Apply the **exclusion hierarchy** (§9) and assign a **tier** (§8).
   e. Persist the observation (§11).
3. Update per-resolver **health scores** across the four dimensions.
4. Emit alerts / evidence for any Tier-2 or Tier ≥4 observation.

Runs are **scheduled** (unattended, periodic) so behaviour is measured *over
time*, not from a single snapshot. Everything runs locally; no hosted server is
required.

## 11. Data recorded per observation

- Timestamp, resolver IP + ASN/owner, domain + query type.
- Untrusted answer set; trusted-path answer set; comparison result
  (`MATCH` / `SUBSET` / `DISJOINT`).
- TTL values observed; latency; response code (NOERROR / SERVFAIL / …).
- Module outputs: DNSSEC AD/validation result, bailiwick findings, consensus
  vector, ECS behaviour, cache-snoop state.
- Exclusion-stage outcomes and the **assigned tier**.
- Raw capture reference (kept out of version control — see §15).

## 12. Evaluation & validation

You cannot ethically attack production ISP resolvers, so validation uses
infrastructure **you own and control**, with a **controlled poisoned-*state*
injection** rather than a live remote exploit. ARGUS ships **no offensive
tooling**.

- **Isolated lab.** A VM running BIND9 / Unbound with **no internet-facing
  exposure**.
- **Controlled ground truth.** Serve a lab zone / a domain you control whose
  correct answer you define.
- **Inject a labelled false state.** Configure the lab resolver / authoritative
  zone to return a **deliberately wrong IP** for that name — a deterministic,
  labelled "poisoned" observation.
- **Confirm detection.** Run the comparator against the lab resolver and verify
  ARGUS assigns the expected tier for the divergence.
- **Semi-synthetic replay dataset.** Combine **real packet captures** with
  **injected, labelled poisoning cases** to compute clean precision/recall-style
  metrics even when no live incident occurs.
- **Metrics to report.** Per-tier true/false positive behaviour on the labelled
  set; which tiers correctly fired vs. missed; exclusion-hierarchy correctness.

> A real off-path (Kaminsky-style) attack against modern resolvers is unreliable
> and non-reproducible and complicates the ethics section. Controlled injection
> gives deterministic, labelled ground truth — the stronger evaluation.

## 13. Operational deployment: how an ISP uses ARGUS

The per-resolver method is **identical** to the research mode; only two things
change — the ISP *provides* its resolver list (no enumeration needed) and it runs
from an operator vantage point.

**Setup:**

1. The ISP lists its own caching name servers in `config/resolvers.yaml` — it
   already knows its fleet, so §5.1 enumeration is unnecessary.
2. It keeps (or extends) the domain watchlist in `config/domains.yaml`.
3. ARGUS runs on a scheduler on an operator host.

**Each scheduled run, per resolver in the fleet:**

1. Untrusted-path query to that resolver (`dig @resolver`).
2. Independent trusted-path ground truth (`dig +trace`).
3. Sorted IP-set comparison + signal modules + exclusion hierarchy + tier.
4. Update the resolver's rolling **health score** (correctness / freshness /
   availability / DNSSEC).

**What the ISP gets:**

- **Continuous, independent integrity assurance** of every resolver it operates —
  derived from the root, not from the resolver's own logs. This catches a
  **poisoned resolver even when its logs look normal**.
- **Per-resolver health scoring** and a dashboard trend over time.
- **Targeted alerts** to the NOC: an unexplained divergence (Tier ≥4) or health
  failure (Tier 2) points at a *specific box* to flush / patch / investigate.
- **DNSSEC-gap visibility** — which resolvers validate and which do not, so the
  operator can act on the biggest structural exposure.

> **Dissertation note:** present ISP-integrated operation as the *intended*
> deployment (Model B) that motivates the work. What you implement and evaluate
> is external / client-vantage measurement (Model A). The measurement method is
> the same; document Model B here so the applied value is explicit.

## 14. Threats to validity & limitations

- **Vantage point.** Client-vantage measurement sees what a subscriber sees;
  results are specific to the networks and times measured.
- **GeoDNS confounding.** Legitimate geographic variation can mimic divergence;
  the ECS module and Stage-1 exclusion mitigate but do not eliminate this.
- **Policy vs. attack.** Lawful interception can resemble poisoning; Stage-3
  exclusion characterises it as policy, but attribution can remain ambiguous.
- **Absence of live incidents.** A clean measurement window is a valid result
  (measurement framing); the semi-synthetic dataset supplies attack-positive
  cases for metrics.
- **Coverage.** A small watchlist trades breadth for comparability and ethics.

## 15. Ethical constraints

- **Passive external measurement only** against production resolvers — ordinary
  queries, never attacks or attempts to alter live infrastructure.
- **All adversarial testing is confined to the isolated lab** on domains/zones
  you control.
- **Data handling.** Raw captures and secrets are git-ignored (`*.pcap`, `.env`,
  `data/`); anything committed once cannot be fully erased — keep measurement
  data out of history from the start.
- **Honest characterisation.** Suggestive findings are reported as suggestive;
  "poisoning" is reserved for Tier-6 evidence.

## 16. Reproducibility

- Configuration lives in version-controlled `config/*.yaml`; results depend only
  on the config + timestamped runs.
- Dependencies pinned via `pip freeze > requirements.txt`.
- Tooling: `dig` (from `dnsutils`) for the trusted-path walk; **dnspython** for
  programmatic queries; Ubuntu as the primary environment.
- Conventional, incremental commits provide an auditable record of independent
  work and double as dissertation evidence.
