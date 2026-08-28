"""Live integration check for the Direct DNS Resolver Query module.

Uses SAFE public DNS only (Google 8.8.8.8, Cloudflare 1.1.1.1) and a reserved
TEST-NET address for the timeout case. Performs no attack of any kind — just
ordinary lookups, exactly like a normal client.

Run from the project root:

    python tests/live_probe_check.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.models import MonitoredResolver
from argus.probe import ResolverProbe

GOOGLE = MonitoredResolver(name="google", address="8.8.8.8", role="control", isp="Google")
CLOUDFLARE = MonitoredResolver(name="cloudflare", address="1.1.1.1", role="control", isp="Cloudflare")
# TEST-NET-1 (RFC 5737): reserved for documentation, never responds -> safe timeout.
DEAD = MonitoredResolver(name="test-net", address="192.0.2.1", role="control", isp="reserved")

probe = ResolverProbe(timeout=2.0, retries=1)
passed = failed = 0


def check(title: str, answer, ok: bool) -> None:
    global passed, failed
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"[{status}] {title}")
    print(f"        resolver={answer.resolver_ip}  domain={answer.domain}  type={answer.rtype}")
    print(f"        rcode={answer.rcode}  ttl={answer.min_ttl}  "
          f"time={answer.latency_ms:.0f}ms" if answer.latency_ms is not None
          else f"        rcode={answer.rcode}  ttl={answer.min_ttl}  time=n/a")
    print(f"        records={sorted(answer.records) or '(none)'}"
          + (f"  error={answer.error}" if answer.error else ""))
    print()


print("=" * 70)
print("LIVE TEST — Direct DNS Resolver Query module (safe public DNS)")
print("=" * 70)

# 1. A record
a = probe.query(GOOGLE, "example.com", "A")
check("1. A record (example.com @ 8.8.8.8)", a,
      a.rcode == "NOERROR" and len(a.records) >= 1 and a.error is None)

# 2. AAAA record
a = probe.query(GOOGLE, "example.com", "AAAA")
check("2. AAAA record (example.com @ 8.8.8.8)", a,
      a.rcode == "NOERROR" and len(a.records) >= 1 and a.error is None)

# 3. Domain with multiple IP addresses
a = probe.query(CLOUDFLARE, "one.one.one.one", "A")
check("3. Multiple A records (one.one.one.one @ 1.1.1.1)", a,
      a.rcode == "NOERROR" and len(a.records) >= 2)

# 4. NXDOMAIN
a = probe.query(GOOGLE, "this-name-should-not-exist-argus-xyz.com", "A")
check("4. NXDOMAIN (nonexistent @ 8.8.8.8)", a,
      a.rcode == "NXDOMAIN" and len(a.records) == 0 and a.error is None)

# 5. Timeout / error handling (reserved, non-responsive address)
a = probe.query(DEAD, "example.com", "A")
check("5. Timeout handling (192.0.2.1, non-responsive)", a,
      a.rcode == "TIMEOUT" and a.error is not None and len(a.records) == 0)

print("=" * 70)
print(f"RESULT: {passed} passed, {failed} failed")
print("=" * 70)
sys.exit(1 if failed else 0)
