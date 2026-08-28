#!/usr/bin/env python3
"""Live single-domain demonstration of the complete Argus workflow.

    python scripts/demo_workflow.py [domain] [resolver_ip]
    python scripts/demo_workflow.py www.google.com 8.8.8.8   (defaults)

Runs a real query through every stage — direct query, independent authoritative
verification, comparison, multi-stage anomaly detection, DNSSEC posture, and a
final health/integrity verdict — and prints the actual results. No simulated
values. Ideal for a supervisor demonstration.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.comparison import compare
from argus.dnssec import DnssecInspector
from argus.integrity import build_record, compute_metrics
from argus.models import MonitoredResolver
from argus.probe import ResolverProbe
from argus.verification import AnomalyVerifier
from argus.verifier import AuthoritativeVerifier

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "www.google.com"
RESOLVER_IP = sys.argv[2] if len(sys.argv) > 2 else "8.8.8.8"

target = MonitoredResolver("resolver-under-test", RESOLVER_IP, role="isp")
controls = [
    MonitoredResolver("google", "8.8.8.8", role="control"),
    MonitoredResolver("cloudflare", "1.1.1.1", role="control"),
    MonitoredResolver("quad9", "9.9.9.9", role="control"),
]
probe = ResolverProbe(timeout=5.0, retries=2)
verifier = AuthoritativeVerifier(timeout=5.0)
anomaly_verifier = AnomalyVerifier(probe, verifier, controls=controls, repetitions=2)
dnssec = DnssecInspector(timeout=5.0)

print("=" * 74)
print("ARGUS — complete DNS monitoring workflow")
print(f"Monitored resolver : {target.address}")
print(f"Domain             : {DOMAIN}")
print("=" * 74)

records = []
for rtype in ("A", "AAAA"):
    print(f"\n---------- {DOMAIN}  {rtype} ----------")
    direct = probe.query(target, DOMAIN, rtype)
    print(f"  DNS query        : {DOMAIN} {rtype} @ {target.address}")
    print(f"  returned records : {sorted(direct.records) or '(none)'}")
    print(f"  TTL              : {direct.min_ttl}")
    print(f"  response time    : {direct.latency_ms:.1f} ms" if direct.latency_ms
          else "  response time    : n/a")
    print(f"  response code    : {direct.rcode}  (AD flag={direct.authenticated})")

    truth = verifier.resolve(DOMAIN, rtype)
    print(f"  authoritative    : rcode={truth.rcode} records={sorted(truth.records) or '(none)'}")
    print(f"  delegation chain : {' | '.join(truth.chain) or '(direct)'}")

    result = compare(direct, truth)
    final = result.classification
    if result.classification.needs_review:
        outcome = anomaly_verifier.verify(target, direct, truth, result)
        final = outcome.classification
        print(f"  comparison       : {result.classification.value} (Stage 1)")
        print(f"  verification     : {final.value} — {outcome.reason}")
    else:
        print(f"  comparison       : {final.value} — {result.reason}")
    records.append(build_record(target, direct, result, final))

print("\n---------- DNSSEC ----------")
ds = dnssec.inspect(target, DOMAIN, "A")
print(f"  zone signed      : {ds.signed}")
print(f"  resolver posture : {ds.posture.value}")
print(f"  response security: {ds.security.value}")

print("\n---------- FINAL HEALTH / INTEGRITY STATUS ----------")
m = compute_metrics(target.name, records)
correctness = f"{m.correctness_rate*100:.0f}%" if m.correctness_rate is not None else "n/a"
alerting = any(r.classification.value == "POSSIBLE_CACHE_POISONING" for r in records)
print(f"  availability={m.availability_pct:.0f}%  avg_latency={m.avg_latency_ms:.1f}ms  "
      f"correctness={correctness}  freshness={m.freshness_status}")
print(f"  integrity verdict : {[r.classification.value for r in records]}")
print(f"  poisoning alert   : {'YES (possible — not proven)' if alerting else 'NO'}")
print("=" * 74)
