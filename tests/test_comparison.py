"""Unit tests for the DNS response comparison engine (argus.comparison).

Controlled, offline examples — synthetic DirectAnswer / AuthoritativeAnswer
objects fed straight into compare(). Each test is a claim about what does and
does not count as poisoning.

    python -m unittest tests.test_comparison -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.comparison import compare
from argus.models import AuthoritativeAnswer, Classification, DirectAnswer

C = Classification


def direct(records, rtype="A", rcode="NOERROR", ttl=300, error=None):
    return DirectAnswer(resolver="r", domain="d.test", rtype=rtype, resolver_ip="203.0.113.1",
                        records=frozenset(records), min_ttl=ttl, rcode=rcode, error=error)


def auth(records, rtype="A", rcode="NOERROR", ttl=300, error=None):
    return AuthoritativeAnswer(domain="d.test", rtype=rtype, records=frozenset(records),
                               ttl=ttl, rcode=rcode, error=error)


class NormalAndBenign(unittest.TestCase):
    def test_exact_match_is_normal(self):
        self.assertEqual(compare(direct(["1.1.1.1"]), auth(["1.1.1.1"])).classification,
                         C.NORMAL)

    def test_order_is_ignored(self):
        r = compare(direct(["1.1.1.1", "2.2.2.2"]), auth(["2.2.2.2", "1.1.1.1"]))
        self.assertEqual(r.classification, C.NORMAL)

    def test_aaaa_exact_match(self):
        r = compare(direct(["2001:db8::1", "2001:db8::2"], rtype="AAAA"),
                    auth(["2001:db8::2", "2001:db8::1"], rtype="AAAA"))
        self.assertEqual(r.classification, C.NORMAL)

    def test_subset_is_benign(self):
        r = compare(direct(["1.1.1.1"]), auth(["1.1.1.1", "1.1.1.2", "1.1.1.3"]))
        self.assertEqual(r.classification, C.BENIGN_DIFFERENCE)
        self.assertEqual(r.missing, frozenset({"1.1.1.2", "1.1.1.3"}))
        self.assertEqual(r.unpublished, frozenset())

    def test_both_nxdomain_is_normal(self):
        r = compare(direct([], rcode="NXDOMAIN"), auth([], rcode="NXDOMAIN"))
        self.assertEqual(r.classification, C.NORMAL)

    def test_cname_targets_compared_as_set(self):
        r = compare(direct(["example.com."], rtype="CNAME"),
                    auth(["example.com."], rtype="CNAME"))
        self.assertEqual(r.classification, C.NORMAL)


class PossiblePoisoning(unittest.TestCase):
    def test_partial_injection_overlap(self):
        r = compare(direct(["1.1.1.1", "6.6.6.6"]), auth(["1.1.1.1"]))
        self.assertEqual(r.classification, C.POSSIBLE_CACHE_POISONING)
        self.assertEqual(r.unpublished, frozenset({"6.6.6.6"}))
        self.assertEqual(r.matched, frozenset({"1.1.1.1"}))

    def test_full_replacement_disjoint(self):
        r = compare(direct(["6.6.6.6"]), auth(["1.1.1.1"]))
        self.assertEqual(r.classification, C.POSSIBLE_CACHE_POISONING)
        self.assertEqual(r.unpublished, frozenset({"6.6.6.6"}))
        self.assertEqual(r.matched, frozenset())

    def test_phantom_answer_for_nonexistent_name(self):
        r = compare(direct(["6.6.6.6"]), auth([], rcode="NXDOMAIN"))
        self.assertEqual(r.classification, C.POSSIBLE_CACHE_POISONING)

    def test_records_for_unpublished_type(self):
        # authoritative NODATA (name exists, no A of this type) but resolver answered
        r = compare(direct(["6.6.6.6"]), auth([], rcode="NOERROR"))
        self.assertEqual(r.classification, C.POSSIBLE_CACHE_POISONING)


class Anomalies(unittest.TestCase):
    def test_missing_records_is_anomaly(self):
        r = compare(direct([], rcode="NOERROR"), auth(["1.1.1.1"]))
        self.assertEqual(r.classification, C.ANOMALY)
        self.assertEqual(r.missing, frozenset({"1.1.1.1"}))

    def test_response_code_difference_is_anomaly(self):
        # resolver claims the name does not exist, but it does
        r = compare(direct([], rcode="NXDOMAIN"), auth(["1.1.1.1"]))
        self.assertEqual(r.classification, C.ANOMALY)
        self.assertIn("NXDOMAIN", r.reason)

    def test_inflated_ttl_on_matching_answer_is_anomaly(self):
        r = compare(direct(["1.1.1.1"], ttl=86400), auth(["1.1.1.1"], ttl=300))
        self.assertEqual(r.classification, C.ANOMALY)
        self.assertTrue(r.ttl_inflated)
        self.assertGreater(r.ttl_ratio, 1.05)

    def test_normal_ttl_not_flagged(self):
        r = compare(direct(["1.1.1.1"], ttl=250), auth(["1.1.1.1"], ttl=300))
        self.assertEqual(r.classification, C.NORMAL)
        self.assertFalse(r.ttl_inflated)


class VerificationFailures(unittest.TestCase):
    def test_authoritative_failure(self):
        r = compare(direct(["1.1.1.1"]), auth([], error="root servers unreachable"))
        self.assertEqual(r.classification, C.VERIFICATION_FAILED)

    def test_resolver_failure(self):
        r = compare(direct([], rcode="TIMEOUT", error="timeout"), auth(["1.1.1.1"]))
        self.assertEqual(r.classification, C.VERIFICATION_FAILED)

    def test_failure_is_never_poisoning(self):
        r = compare(direct(["6.6.6.6"]), auth([], error="timeout"))
        self.assertEqual(r.classification, C.VERIFICATION_FAILED)
        self.assertFalse(r.classification.needs_review)


if __name__ == "__main__":
    unittest.main(verbosity=2)
