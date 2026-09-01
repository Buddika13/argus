"""Tests for the concurrent ground-truth phase of a sweep.

Offline: fake probe and verifier, in-memory database. No network.

The sweep resolves ground truth once per (domain, record type) and shares it
across every monitored resolver. Those walks are independent, so they run
concurrently at the configured width. What must not change is the result: the
same walks happen, each is stored exactly once, and a walk that raises is
skipped rather than stopping the sweep.

    python -m unittest tests.test_concurrency -v
"""

from __future__ import annotations

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.config import Settings
from argus.models import AuthoritativeAnswer, DirectAnswer, MonitoredResolver
from argus.scheduler import Scheduler
from argus.storage import Storage

RECORDS = frozenset({"203.0.113.10"})


class FakeVerifier:
    """Records which walks ran, and how many ran at the same time."""

    def __init__(self, fail_for=(), delay=0.02):
        self.calls = []
        self.fail_for = set(fail_for)
        self.delay = delay
        self._lock = threading.Lock()
        self._active = 0
        self.peak_parallel = 0

    def resolve(self, domain, rtype):
        with self._lock:
            self._active += 1
            self.peak_parallel = max(self.peak_parallel, self._active)
            self.calls.append((domain, rtype))
        try:
            threading.Event().wait(self.delay)
            if domain in self.fail_for:
                raise RuntimeError("simulated walk failure for " + domain)
            return AuthoritativeAnswer(domain=domain, rtype=rtype, records=RECORDS,
                                       ttl=300, rcode="NOERROR",
                                       authoritative_servers=("192.0.2.53",),
                                       chain=(". -> test.",))
        finally:
            with self._lock:
                self._active -= 1


class FakeProbe:
    def __init__(self):
        self.calls = []

    def query(self, resolver, domain, rtype):
        self.calls.append((getattr(resolver, "name", resolver), domain, rtype))
        return DirectAnswer(resolver=resolver.name, domain=domain, rtype=rtype,
                            resolver_ip=resolver.address, records=RECORDS,
                            min_ttl=300, rcode="NOERROR", latency_ms=5.0)


def settings_with(concurrency: int, domains, tmpdb) -> Settings:
    raw = {
        "vantage": "test",
        "schedule": {"interval_seconds": 300, "per_resolver_delay": 0.0,
                     "concurrency": concurrency},
        "query": {"timeout_seconds": 2.0, "retries": 0, "rtypes": ["A"]},
        "verification": {"requery": True, "rewalk": True,
                         "control_crosscheck": True, "persistence": 2},
        "freshness": {"max_ttl_ratio": 1.05},
        "dnssec": {"enabled": False},
        "storage": {"path": tmpdb},
        "dashboard": {"path": "report.html"},
        "logging": {"level": "CRITICAL"},
    }
    return Settings(raw=raw,
                    resolvers=[MonitoredResolver("r1", "192.0.2.1", role="isp"),
                               MonitoredResolver("r2", "192.0.2.2", role="isp")],
                    watchlist=list(domains))


class ConcurrentGroundTruthTests(unittest.TestCase):
    def _run(self, concurrency, domains=("a.test", "b.test", "c.test", "d.test"),
             fail_for=()):
        db = Storage(":memory:")
        verifier = FakeVerifier(fail_for=fail_for)
        scheduler = Scheduler(settings_with(concurrency, domains, ":memory:"), db,
                              probe=FakeProbe(), verifier=verifier, dnssec=None)
        summary = scheduler.run_once()
        counts = db.table_counts()
        db.close()
        return summary, counts, verifier

    def test_every_walk_still_runs_exactly_once(self):
        _s, _c, verifier = self._run(concurrency=8)
        self.assertEqual(sorted(verifier.calls),
                         [("a.test", "A"), ("b.test", "A"),
                          ("c.test", "A"), ("d.test", "A")])

    def test_walks_actually_overlap(self):
        _s, _c, verifier = self._run(concurrency=4)
        self.assertGreater(verifier.peak_parallel, 1)

    def test_concurrency_one_stays_sequential(self):
        _s, _c, verifier = self._run(concurrency=1)
        self.assertEqual(verifier.peak_parallel, 1)

    def test_results_match_the_sequential_run(self):
        parallel, pcounts, _v = self._run(concurrency=8)
        serial, scounts, _v2 = self._run(concurrency=1)
        self.assertEqual(parallel["queries"], serial["queries"])
        self.assertEqual(pcounts["authoritative_results"],
                         scounts["authoritative_results"])
        self.assertEqual(pcounts["comparisons"], scounts["comparisons"])

    def test_each_walk_is_stored_once(self):
        _s, counts, _v = self._run(concurrency=8)
        self.assertEqual(counts["authoritative_results"], 4)

    def test_a_failing_walk_is_skipped_not_fatal(self):
        summary, counts, verifier = self._run(concurrency=8, fail_for=("b.test",))
        # Three domains survive, for two resolvers.
        self.assertEqual(counts["authoritative_results"], 3)
        self.assertEqual(summary["queries"], 6)
        self.assertEqual(summary["failures"], 0)

    def test_probe_never_sees_a_domain_without_ground_truth(self):
        db = Storage(":memory:")
        probe = FakeProbe()
        scheduler = Scheduler(
            settings_with(8, ("a.test", "b.test"), ":memory:"), db,
            probe=probe, verifier=FakeVerifier(fail_for=("b.test",)), dnssec=None)
        scheduler.run_once()
        db.close()
        self.assertTrue(all(domain != "b.test" for _r, domain, _t in probe.calls))


if __name__ == "__main__":
    unittest.main(verbosity=2)
