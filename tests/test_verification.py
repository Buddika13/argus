"""Unit tests for the multi-stage anomaly detection engine (argus.verification).

Offline and deterministic: fake probe and verifier are injected. Each test
drives one final classification and checks the reasoning/evidence.

    python -m unittest tests.test_verification -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.comparison import compare
from argus.models import (AuthoritativeAnswer, Classification, DirectAnswer,
                          MonitoredResolver)
from argus.verification import AnomalyVerifier

C = Classification
TARGET = MonitoredResolver("isp", "203.0.113.9", role="isp")
CONTROLS = [MonitoredResolver("google", "8.8.8.8", role="control"),
            MonitoredResolver("cloudflare", "1.1.1.1", role="control"),
            MonitoredResolver("quad9", "9.9.9.9", role="control")]
AUTH_IPS = {"1.1.1.1"}


def _auth(records=AUTH_IPS, error=None, ttl=300):
    return AuthoritativeAnswer(domain="d.test", rtype="A",
                              records=frozenset(records), ttl=ttl, error=error)


def _direct(resolver_name, records, ad=False):
    return DirectAnswer(resolver=resolver_name, domain="d.test", rtype="A",
                        resolver_ip="x", records=frozenset(records), min_ttl=300,
                        rcode="NOERROR", latency_ms=5.0, authenticated=ad)


class FakeVerifier:
    def __init__(self, records=AUTH_IPS, error=None):
        self._records, self._error = records, error

    def resolve(self, domain, rtype="A"):
        return _auth(self._records, self._error)


class FakeProbe:
    """Answers per resolver-name from a table; supports transient behaviour."""
    def __init__(self, table, transient_for=None):
        self.table = table              # name -> set(records)
        self.transient_for = transient_for
        self._calls = {}

    def query(self, resolver, domain, rtype="A"):
        name = resolver.name
        recs = self.table.get(name, AUTH_IPS)
        if self.transient_for == name:
            # first call poisoned, subsequent calls clean
            n = self._calls.get(name, 0)
            self._calls[name] = n + 1
            recs = self.table[name] if n == 0 else AUTH_IPS
        return _direct(name, recs)


def _run(target_records, table, verifier=None, transient_for=None, reps=3, target_ad=False):
    direct = _direct("isp", target_records, ad=target_ad)
    authoritative = _auth()
    comparison = compare(direct, authoritative)
    engine = AnomalyVerifier(
        probe=FakeProbe(table, transient_for=transient_for),
        verifier=verifier or FakeVerifier(),
        controls=CONTROLS, repetitions=reps)
    return engine.verify(TARGET, direct, authoritative, comparison), comparison


class VerificationTests(unittest.TestCase):
    def test_normal_short_circuits(self):
        outcome, _ = _run({"1.1.1.1"}, {"isp": {"1.1.1.1"}})
        self.assertEqual(outcome.classification, C.NORMAL)

    def test_benign_when_controls_corroborate(self):
        # target returns 2.2.2.2 (unpublished), but controls also return it -> legitimate
        outcome, _ = _run({"2.2.2.2"}, {"isp": {"2.2.2.2"}, "google": {"2.2.2.2"},
                                        "cloudflare": {"2.2.2.2"}, "quad9": {"2.2.2.2"}})
        self.assertEqual(outcome.classification, C.BENIGN_DIFFERENCE)
        self.assertTrue(outcome.evidence["stage3_controls"]["corroborates_unexpected"])

    def test_temporary_when_not_reproduced(self):
        # target poisoned only on first query; controls clean
        outcome, _ = _run({"6.6.6.6"}, {"isp": {"6.6.6.6"}, "google": {"1.1.1.1"},
                                        "cloudflare": {"1.1.1.1"}, "quad9": {"1.1.1.1"}},
                          transient_for="isp")
        self.assertEqual(outcome.classification, C.TEMPORARY_ANOMALY)

    def test_possible_poisoning_when_persistent_and_unique(self):
        # target consistently returns 6.6.6.6; controls all clean
        outcome, _ = _run({"6.6.6.6"}, {"isp": {"6.6.6.6"}, "google": {"1.1.1.1"},
                                        "cloudflare": {"1.1.1.1"}, "quad9": {"1.1.1.1"}})
        self.assertEqual(outcome.classification, C.POSSIBLE_CACHE_POISONING)
        self.assertIn("not proven", outcome.reason)
        self.assertTrue(outcome.evidence["stage5_persistence"]["persistent"])

    def test_integrity_anomaly_for_persistent_non_poisoning_shape(self):
        # target persistently returns NO records though authoritative has some
        # (Stage-1 ANOMALY, not unpublished); controls clean
        outcome, _ = _run(set(), {"isp": set(), "google": {"1.1.1.1"},
                                   "cloudflare": {"1.1.1.1"}, "quad9": {"1.1.1.1"}})
        self.assertEqual(outcome.classification, C.DNS_INTEGRITY_ANOMALY)

    def test_verification_failed_when_no_corroboration_possible(self):
        # authoritative re-walk errors AND every control fails
        class DeadProbe:
            def query(self, resolver, domain, rtype="A"):
                if resolver.role == "control":
                    raise ConnectionError("down")
                return _direct("isp", {"6.6.6.6"})
        direct = _direct("isp", {"6.6.6.6"})
        authoritative = _auth()
        comparison = compare(direct, authoritative)
        engine = AnomalyVerifier(DeadProbe(), FakeVerifier(error="root unreachable"),
                                 CONTROLS, repetitions=2)
        outcome = engine.verify(TARGET, direct, authoritative, comparison)
        self.assertEqual(outcome.classification, C.VERIFICATION_FAILED)

    def test_evidence_records_all_stages(self):
        outcome, _ = _run({"6.6.6.6"}, {"isp": {"6.6.6.6"}, "google": {"1.1.1.1"},
                                        "cloudflare": {"1.1.1.1"}, "quad9": {"1.1.1.1"}})
        for stage in ("stage1", "stage2_authoritative", "stage3_controls",
                      "stage4_dnssec", "stage5_persistence", "decision"):
            self.assertIn(stage, outcome.evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)
