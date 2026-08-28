"""Unit tests for the monitoring scheduler (argus.scheduler).

Offline and deterministic: a fake probe and fake verifier are injected, so no
network is used. Storage is in-memory.

    python -m unittest tests.test_scheduler -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.config import Settings
from argus.models import AuthoritativeAnswer, DirectAnswer, MonitoredResolver
from argus.scheduler import Scheduler
from argus.storage import Storage


class FakeVerifier:
    """Returns fixed authoritative truth for each domain."""
    TRUTH = {"good.test": {"1.1.1.1"}, "bank.test": {"203.0.113.10"}}

    def resolve(self, domain, rtype="A"):
        return AuthoritativeAnswer(domain=domain, rtype=rtype,
                                   records=frozenset(self.TRUTH.get(domain, set())),
                                   ttl=300, rcode="NOERROR")


class FakeProbe:
    """Honest for most resolvers; one resolver is poisoned; one always fails."""
    def query(self, resolver, domain, rtype="A"):
        if resolver.name == "broken":
            raise ConnectionError("simulated resolver failure")
        records = FakeVerifier.TRUTH.get(domain, set())
        if resolver.name == "evil" and domain == "bank.test":
            records = {"6.6.6.6"}                    # injected -> POSSIBLE poisoning
        return DirectAnswer(resolver=resolver.name, domain=domain, rtype=rtype,
                            resolver_ip=resolver.address, records=frozenset(records),
                            min_ttl=300, rcode="NOERROR", latency_ms=5.0)


def _settings(resolvers):
    raw = {
        "vantage": "test",
        "schedule": {"interval_seconds": 1, "per_resolver_delay": 0.0},
        "query": {"timeout_seconds": 1.0, "retries": 0, "rtypes": ["A"]},
        "verification": {"requery": True, "rewalk": True, "control_crosscheck": True, "persistence": 2},
        "freshness": {"max_ttl_ratio": 1.05}, "dnssec": {"enabled": False},
        "storage": {"path": ":memory:"}, "dashboard": {"path": "x.html"},
        "logging": {"level": "CRITICAL"},
    }
    return Settings(raw=raw, resolvers=resolvers, watchlist=["good.test", "bank.test"])


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        import logging
        logging.disable(logging.CRITICAL)   # silence expected failure logs in tests
        self.storage = Storage(":memory:")
        self.resolvers = [
            MonitoredResolver("google", "8.8.8.8", role="control"),
            MonitoredResolver("evil", "203.0.113.9", role="isp"),
            MonitoredResolver("broken", "203.0.113.99", role="isp"),
        ]
        self.sched = Scheduler(_settings(self.resolvers), self.storage,
                               probe=FakeProbe(), verifier=FakeVerifier())

    def tearDown(self):
        self.storage.close()

    def test_sweep_runs_and_stores_results(self):
        summary = self.sched.run_once()
        counts = self.storage.table_counts()
        # 2 healthy resolvers x 2 domains = 4 successful queries; broken fails 2
        self.assertEqual(summary["queries"], 4)
        self.assertEqual(summary["failures"], 2)
        self.assertEqual(counts["query_results"], 4)
        self.assertEqual(counts["authoritative_results"], 2)   # ground truth once per domain
        self.assertEqual(counts["comparisons"], 4)

    def test_one_broken_resolver_does_not_stop_others(self):
        self.sched.run_once()
        # google + evil still produced health metrics despite `broken` failing
        self.assertIsNotNone(self.storage.metric_history("google"))
        self.assertGreaterEqual(len(self.storage.metric_history("evil")), 1)

    def test_injection_is_recorded_as_anomaly(self):
        summary = self.sched.run_once()
        self.assertEqual(summary["anomalies"], 1)              # evil @ bank.test
        anomalies = self.storage.recent_anomalies()
        self.assertEqual(anomalies[0]["resolver"], "evil")
        self.assertEqual(anomalies[0]["classification"], "POSSIBLE_CACHE_POISONING")

    def test_stop_is_graceful(self):
        self.sched.stop()
        self.assertTrue(self.sched._stop.is_set())             # loop would exit


if __name__ == "__main__":
    unittest.main(verbosity=2)
