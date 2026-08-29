"""Unit tests for the dig-based verification demonstration (scripts/dig_verify.py).

Offline: the parsers are pure functions, so they are tested against captured
`dig` output rather than by invoking dig. That means the parsing is verified on
machines without dnsutils installed, including during development on Windows.

    python -m unittest tests.test_dig_verify -v
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_PATH = os.path.join(os.path.dirname(__file__), "..", "scripts", "dig_verify.py")
_spec = importlib.util.spec_from_file_location("dig_verify", _PATH)
dig_verify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dig_verify)


SHORT_OUTPUT = """220.247.254.21
"""

SHORT_WITH_CNAME = """www.example.lk.
93.184.216.34
93.184.216.35
"""

TRACE_OUTPUT = """; <<>> DiG 9.18.30 <<>> +trace peoplesbank.lk A
;; global options: +cmd
.			518400	IN	NS	a.root-servers.net.
.			518400	IN	NS	b.root-servers.net.
;; Received 1097 bytes from 127.0.0.53#53(127.0.0.53) in 12 ms

lk.			172800	IN	NS	d.nic.lk.
lk.			172800	IN	NS	h.nic.lk.
;; Received 693 bytes from 198.41.0.4#53(a.root-servers.net.) in 220 ms

peoplesbank.lk.		86400	IN	NS	p1.ns.slt.lk.
peoplesbank.lk.		86400	IN	NS	s1.ns.slt.lk.
;; Received 180 bytes from 192.248.1.161#53(d.nic.lk.) in 20 ms

peoplesbank.lk.		3600	IN	A	220.247.254.21
;; Received 60 bytes from 203.94.84.2#53(p1.ns.slt.lk.) in 25 ms
"""


class ParseShortTests(unittest.TestCase):
    def test_single_address(self):
        self.assertEqual(dig_verify.parse_short(SHORT_OUTPUT), {"220.247.254.21"})

    def test_cname_line_is_not_an_address(self):
        self.assertEqual(dig_verify.parse_short(SHORT_WITH_CNAME),
                         {"93.184.216.34", "93.184.216.35"})

    def test_empty_output(self):
        self.assertEqual(dig_verify.parse_short(""), set())


class ParseTraceTests(unittest.TestCase):
    def setUp(self):
        self.parsed = dig_verify.parse_trace(TRACE_OUTPUT, "peoplesbank.lk", "A")

    def test_final_answer_is_extracted(self):
        self.assertEqual(self.parsed["answers"], {"220.247.254.21"})

    def test_delegation_chain_is_walked(self):
        self.assertEqual(self.parsed["zones"], [".", "lk.", "peoplesbank.lk."])
        self.assertEqual(self.parsed["chain"],
                         [". -> lk.", "lk. -> peoplesbank.lk."])

    def test_answering_server_is_recorded(self):
        self.assertEqual(self.parsed["servers"][-1], "p1.ns.slt.lk")

    def test_other_record_type_yields_nothing(self):
        parsed = dig_verify.parse_trace(TRACE_OUTPUT, "peoplesbank.lk", "AAAA")
        self.assertEqual(parsed["answers"], set())

    def test_other_domain_yields_nothing(self):
        parsed = dig_verify.parse_trace(TRACE_OUTPUT, "example.com", "A")
        self.assertEqual(parsed["answers"], set())


class ClassifyTests(unittest.TestCase):
    def test_identical_sets_report_no_poisoning(self):
        result, _reason = dig_verify.classify({"1.2.3.4"}, {"1.2.3.4"}, True, True)
        self.assertEqual(result, dig_verify.NO_POISONING)

    def test_subset_is_benign(self):
        result, reason = dig_verify.classify({"1.2.3.4"}, {"1.2.3.4", "1.2.3.5"},
                                             True, True)
        self.assertEqual(result, dig_verify.NO_POISONING)
        self.assertIn("load balancing", reason)

    def test_unpublished_address_is_possible_poisoning(self):
        result, reason = dig_verify.classify({"203.0.113.66"}, {"1.2.3.4"}, True, True)
        self.assertEqual(result, dig_verify.POSSIBLE)
        self.assertIn("203.0.113.66", reason)

    def test_unmeasurable_side_is_inconclusive(self):
        self.assertEqual(
            dig_verify.classify(set(), {"1.2.3.4"}, False, True)[0],
            dig_verify.INCONCLUSIVE)
        self.assertEqual(
            dig_verify.classify({"1.2.3.4"}, set(), True, False)[0],
            dig_verify.INCONCLUSIVE)

    def test_empty_ground_truth_is_inconclusive(self):
        self.assertEqual(
            dig_verify.classify({"1.2.3.4"}, set(), True, True)[0],
            dig_verify.INCONCLUSIVE)

    def test_non_persistent_suspicion_is_inconclusive(self):
        result, reason = dig_verify.classify({"203.0.113.66"}, {"1.2.3.4"},
                                             True, True,
                                             repeats_total=3, repeats_suspicious=1)
        self.assertEqual(result, dig_verify.INCONCLUSIVE)
        self.assertIn("1 of 3", reason)

    def test_persistent_suspicion_stays_possible(self):
        result, _reason = dig_verify.classify({"203.0.113.66"}, {"1.2.3.4"},
                                              True, True,
                                              repeats_total=3, repeats_suspicious=3)
        self.assertEqual(result, dig_verify.POSSIBLE)

    def test_verdict_is_never_stated_as_proven(self):
        for verdict in (dig_verify.NO_POISONING, dig_verify.POSSIBLE,
                        dig_verify.INCONCLUSIVE):
            self.assertNotIn("PROVEN", verdict)


class MissingDigTests(unittest.TestCase):
    def test_missing_dig_is_reported_not_raised(self):
        ok, message = dig_verify.run(["definitely-not-a-real-command-xyz"])
        self.assertFalse(ok)
        self.assertIn("dig is not installed", message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
