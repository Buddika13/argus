"""Unit tests for the DNSSEC module (argus.dnssec).

Offline and deterministic: the low-level query is overridden with synthetic DNS
messages, so no real DNSSEC queries are made.

    python -m unittest tests.test_dnssec -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from argus.dnssec import BOGUS_TEST, SIGNED_TEST, DnssecInspector
from argus.models import (DnssecPosture, MonitoredResolver, SecurityStatus)


def _msg(qname, rtype, *rdata, ad=False, rcode=dns.rcode.NOERROR, ttl=300):
    q = dns.message.make_query(qname, rtype)
    r = dns.message.make_response(q)
    r.set_rcode(rcode)
    if ad:
        r.flags |= dns.flags.AD
    if rdata:
        r.answer.append(dns.rrset.from_text(qname + ".", ttl, "IN", rtype, *rdata))
    return r


# A minimal but syntactically valid DNSKEY rdata (flags proto algo base64).
DNSKEY_RDATA = "257 3 8 AwEAAQ=="


class FakeInspector(DnssecInspector):
    """DnssecInspector whose _query returns canned messages from a table."""
    def __init__(self, table):
        super().__init__()
        self.table = table            # (ip, name, rtype) -> message or None

    def _query(self, ip, name, rtype, port=53):
        return self.table.get((ip, name, rtype))


class SignednessTests(unittest.TestCase):
    def test_signed_zone_detected(self):
        insp = FakeInspector({("8.8.8.8", "iana.org", "DNSKEY"):
                              _msg("iana.org", "DNSKEY", DNSKEY_RDATA)})
        self.assertIs(insp.is_signed("iana.org"), True)

    def test_unsigned_zone_detected(self):
        insp = FakeInspector({("8.8.8.8", "plain.test", "DNSKEY"):
                              _msg("plain.test", "A")})   # no DNSKEY in answer
        self.assertIs(insp.is_signed("plain.test"), False)

    def test_undetermined_on_query_failure(self):
        self.assertIsNone(FakeInspector({}).is_signed("x.test"))


class PostureTests(unittest.TestCase):
    def _insp(self, signed_ad, bogus_servfail):
        return FakeInspector({
            ("9.9.9.9", SIGNED_TEST, "A"): _msg(SIGNED_TEST, "A", "1.2.3.4", ad=signed_ad),
            ("9.9.9.9", BOGUS_TEST, "A"):
                _msg(BOGUS_TEST, "A", rcode=dns.rcode.SERVFAIL) if bogus_servfail
                else _msg(BOGUS_TEST, "A", "6.6.6.6"),
        })

    def test_validating(self):
        self.assertEqual(self._insp(True, True).resolver_posture("9.9.9.9"),
                         DnssecPosture.VALIDATING)

    def test_ad_only_is_worse_than_not_validating(self):
        self.assertEqual(self._insp(True, False).resolver_posture("9.9.9.9"),
                         DnssecPosture.AD_ONLY)

    def test_permissive(self):
        self.assertEqual(self._insp(False, False).resolver_posture("9.9.9.9"),
                         DnssecPosture.PERMISSIVE)

    def test_unknown_on_failure(self):
        self.assertEqual(FakeInspector({}).resolver_posture("9.9.9.9"),
                         DnssecPosture.UNKNOWN)


class SecurityStatusTests(unittest.TestCase):
    def test_secure_when_signed_and_ad(self):
        insp = FakeInspector({("1.1.1.1", "iana.org", "A"):
                              _msg("iana.org", "A", "1.2.3.4", ad=True)})
        status, ad, _ = insp.response_security("1.1.1.1", "iana.org", signed=True,
                                               posture=DnssecPosture.VALIDATING)
        self.assertEqual(status, SecurityStatus.SECURE)
        self.assertTrue(ad)

    def test_insecure_when_unsigned(self):
        insp = FakeInspector({("1.1.1.1", "plain.test", "A"):
                              _msg("plain.test", "A", "1.2.3.4")})
        status, _, _ = insp.response_security("1.1.1.1", "plain.test", signed=False,
                                              posture=DnssecPosture.VALIDATING)
        self.assertEqual(status, SecurityStatus.INSECURE)

    def test_bogus_when_signed_but_servfail_at_validator(self):
        insp = FakeInspector({("1.1.1.1", "bad.test", "A"):
                              _msg("bad.test", "A", rcode=dns.rcode.SERVFAIL)})
        status, _, _ = insp.response_security("1.1.1.1", "bad.test", signed=True,
                                              posture=DnssecPosture.VALIDATING)
        self.assertEqual(status, SecurityStatus.BOGUS)

    def test_indeterminate_when_resolver_not_validating(self):
        insp = FakeInspector({("1.1.1.1", "iana.org", "A"):
                              _msg("iana.org", "A", "1.2.3.4")})
        status, _, _ = insp.response_security("1.1.1.1", "iana.org", signed=True,
                                              posture=DnssecPosture.PERMISSIVE)
        self.assertEqual(status, SecurityStatus.INDETERMINATE)


class AssessTests(unittest.TestCase):
    """assess(): pure classification from already-observed values (no query)."""
    def setUp(self):
        self.insp = FakeInspector({})

    def test_secure(self):
        sec, sup, _ = self.insp.assess("z", True, DnssecPosture.VALIDATING, ad=True, rcode="NOERROR")
        self.assertEqual(sec, SecurityStatus.SECURE)
        self.assertTrue(sup)

    def test_insecure(self):
        sec, sup, _ = self.insp.assess("z", False, DnssecPosture.VALIDATING, ad=False, rcode="NOERROR")
        self.assertEqual(sec, SecurityStatus.INSECURE)
        self.assertFalse(sup)

    def test_bogus(self):
        sec, _, _ = self.insp.assess("z", True, DnssecPosture.VALIDATING, ad=False, rcode="SERVFAIL")
        self.assertEqual(sec, SecurityStatus.BOGUS)

    def test_indeterminate_non_validating(self):
        sec, _, _ = self.insp.assess("z", True, DnssecPosture.PERMISSIVE, ad=False, rcode="NOERROR")
        self.assertEqual(sec, SecurityStatus.INDETERMINATE)


class AnomalySupportTests(unittest.TestCase):
    def setUp(self):
        self.insp = FakeInspector({})

    def test_bogus_supports_anomaly(self):
        supports, _ = self.insp.evidence_for_anomaly("x.test", SecurityStatus.BOGUS, signed=True)
        self.assertTrue(supports)

    def test_signed_zone_supports_anomaly(self):
        supports, _ = self.insp.evidence_for_anomaly("x.test", SecurityStatus.SECURE, signed=True)
        self.assertTrue(supports)

    def test_unsigned_zone_does_not_support(self):
        supports, _ = self.insp.evidence_for_anomaly("x.test", SecurityStatus.INSECURE, signed=False)
        self.assertFalse(supports)


class StorageTests(unittest.TestCase):
    def test_dnssec_status_round_trips(self):
        from argus.storage import Storage
        insp = FakeInspector({
            ("8.8.8.8", "iana.org", "DNSKEY"): _msg("iana.org", "DNSKEY", DNSKEY_RDATA),
            ("9.9.9.9", SIGNED_TEST, "A"): _msg(SIGNED_TEST, "A", "1.2.3.4", ad=True),
            ("9.9.9.9", BOGUS_TEST, "A"): _msg(BOGUS_TEST, "A", rcode=dns.rcode.SERVFAIL),
            ("9.9.9.9", "iana.org", "A"): _msg("iana.org", "A", "1.2.3.4", ad=True),
        })
        status = insp.inspect(MonitoredResolver("quad9", "9.9.9.9", role="control"), "iana.org")
        db = Storage(":memory:")
        db.insert_dnssec_status(status)
        rows = db.recent_dnssec()
        db.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["security"], "SECURE")
        self.assertEqual(rows[0]["posture"], "VALIDATING")
        self.assertEqual(rows[0]["signed"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
