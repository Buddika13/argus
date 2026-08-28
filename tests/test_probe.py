"""Unit tests for the direct resolver query module (argus.probe).

Offline and deterministic: response parsing is tested with synthetic DNS
messages, and the failure modes are tested by patching the network call. No
live DNS queries are made, so these run anywhere and never flake.

Run from the project root:

    python -m unittest tests.test_probe -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from argus.models import MonitoredResolver
from argus.probe import ResolverProbe, build_answer

TARGET = "argus.probe.dns.query.udp_with_fallback"


def _response(qname: str, rtype: str, *rdata: str, ttl: int = 300,
              rcode: int = dns.rcode.NOERROR, ad: bool = False) -> dns.message.Message:
    """Build a synthetic DNS response for testing."""
    query = dns.message.make_query(qname, rtype)
    resp = dns.message.make_response(query)
    resp.set_rcode(rcode)
    if ad:
        resp.flags |= dns.flags.AD
    if rdata:
        resp.answer.append(dns.rrset.from_text(qname + ".", ttl, "IN", rtype, *rdata))
    return resp


class ParsingTests(unittest.TestCase):
    """build_answer: turning a response into a DirectAnswer."""

    def test_single_a_record(self):
        ans = build_answer(_response("example.com", "A", "1.2.3.4"),
                           "google", "8.8.8.8", "example.com", "A", 12.3)
        self.assertEqual(ans.records, frozenset({"1.2.3.4"}))
        self.assertEqual(ans.min_ttl, 300)
        self.assertEqual(ans.rcode, "NOERROR")
        self.assertEqual(ans.resolver_ip, "8.8.8.8")
        self.assertEqual(ans.rtype, "A")
        self.assertIsNone(ans.error)

    def test_multiple_a_records(self):
        ans = build_answer(_response("example.com", "A", "1.2.3.4", "5.6.7.8", "9.9.9.9"),
                           "r", "1.1.1.1", "example.com", "A", 5.0)
        self.assertEqual(ans.records, frozenset({"1.2.3.4", "5.6.7.8", "9.9.9.9"}))

    def test_multiple_aaaa_records(self):
        ans = build_answer(_response("example.com", "AAAA", "2001:db8::1", "2001:db8::2"),
                           "r", "1.1.1.1", "example.com", "AAAA", 5.0)
        self.assertEqual(len(ans.records), 2)
        self.assertIn("2001:db8::1", ans.records)

    def test_cname_record(self):
        ans = build_answer(_response("www.example.com", "CNAME", "example.com."),
                           "r", "9.9.9.9", "www.example.com", "CNAME", 5.0)
        self.assertEqual(ans.records, frozenset({"example.com."}))

    def test_min_ttl_is_smallest(self):
        resp = _response("example.com", "A", "1.2.3.4", ttl=100)
        resp.answer.append(dns.rrset.from_text("alias.example.com.", 30, "IN", "A", "5.6.7.8"))
        ans = build_answer(resp, "r", "1.1.1.1", "example.com", "A", 1.0)
        self.assertEqual(ans.min_ttl, 30)                 # smallest TTL wins
        self.assertEqual(ans.records, frozenset({"1.2.3.4", "5.6.7.8"}))

    def test_ad_flag_captured(self):
        ans = build_answer(_response("example.com", "A", "1.2.3.4", ad=True),
                           "r", "8.8.8.8", "example.com", "A", 1.0)
        self.assertTrue(ans.authenticated)

    def test_nxdomain_has_no_records(self):
        ans = build_answer(_response("nope.example.com", "A", rcode=dns.rcode.NXDOMAIN),
                           "r", "8.8.8.8", "nope.example.com", "A", 1.0)
        self.assertEqual(ans.rcode, "NXDOMAIN")
        self.assertEqual(ans.records, frozenset())
        self.assertIsNone(ans.error)                      # a valid response, not an error


class FailureModeTests(unittest.TestCase):
    """query(): error handling via a patched network call."""

    def setUp(self):
        self.probe = ResolverProbe(timeout=1.0, retries=1)
        self.resolver = MonitoredResolver(name="r", address="203.0.113.1")

    def test_servfail_is_recorded_not_errored(self):
        resp = _response("example.com", "A", rcode=dns.rcode.SERVFAIL)
        with mock.patch(TARGET, return_value=(resp, False)) as m:
            ans = self.probe.query(self.resolver, "example.com", "A")
        self.assertEqual(ans.rcode, "SERVFAIL")
        self.assertIsNone(ans.error)                      # SERVFAIL is a real answer
        self.assertEqual(m.call_count, 1)                 # not retried

    def test_timeout_is_retried_then_recorded(self):
        with mock.patch(TARGET, side_effect=dns.exception.Timeout) as m:
            ans = self.probe.query(self.resolver, "example.com", "A")
        self.assertEqual(ans.rcode, "TIMEOUT")
        self.assertIsNotNone(ans.error)
        self.assertEqual(ans.records, frozenset())
        self.assertEqual(m.call_count, 2)                 # retries=1 -> 2 attempts

    def test_connection_error_is_recorded(self):
        with mock.patch(TARGET, side_effect=ConnectionRefusedError("refused")):
            ans = self.probe.query(self.resolver, "example.com", "A")
        self.assertEqual(ans.rcode, "ERROR")
        self.assertIn("connection error", ans.error)

    def test_malformed_response_is_recorded(self):
        with mock.patch(TARGET, side_effect=dns.exception.FormError("bad wire")):
            ans = self.probe.query(self.resolver, "example.com", "A")
        self.assertEqual(ans.rcode, "MALFORMED")
        self.assertIn("malformed", ans.error)

    def test_unsupported_record_type(self):
        ans = self.probe.query(self.resolver, "example.com", "NOTATYPE")
        self.assertEqual(ans.rcode, "ERROR")
        self.assertIn("unsupported", ans.error)

    def test_accepts_bare_ip_string(self):
        resp = _response("example.com", "A", "1.2.3.4")
        with mock.patch(TARGET, return_value=(resp, False)):
            ans = self.probe.query("8.8.8.8", "example.com", "A")
        self.assertEqual(ans.resolver_ip, "8.8.8.8")
        self.assertEqual(ans.resolver, "8.8.8.8")
        self.assertEqual(ans.records, frozenset({"1.2.3.4"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
