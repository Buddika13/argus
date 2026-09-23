"""Unit tests for the signal modules (argus.modules) — methodology §7.

Entirely offline. The network-facing modules all accept a pre-captured DNS
message or a pre-collected answer set, which is what makes them testable without
touching a resolver, and also what makes a stored finding re-readable later
without re-running the measurement (§16).

Each test states what the module is allowed to conclude. The recurring theme is
restraint: these modules exist to *remove innocent explanations*, and a module
that over-claims is worse than no module at all.

    python -m unittest tests.test_modules -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dns.message

from argus.models import ModuleStatus
from argus.modules import (check_bailiwick, check_cache_state, check_consensus,
                           check_ecs, check_ttl)

S = ModuleStatus


def message(question="www.example.com. IN A", answer=(), authority=(),
            additional=(), flags="QR", rcode="NOERROR"):
    """Build a DNS response message from record text."""
    parts = [f"id 1234\nopcode QUERY\nrcode {rcode}\nflags {flags}",
             ";QUESTION", question, ";ANSWER", *answer,
             ";AUTHORITY", *authority, ";ADDITIONAL", *additional]
    return dns.message.from_text("\n".join(parts))


# --------------------------------------------------------------------------
# TTL / freshness
# --------------------------------------------------------------------------
class TtlModule(unittest.TestCase):
    def test_ttl_within_the_authoritative_value_is_clean(self):
        self.assertIs(check_ttl(250, 300).status, S.CLEAN)

    def test_cached_ttl_above_the_authoritative_value_is_suspicious(self):
        result = check_ttl(9000, 300)
        self.assertIs(result.status, S.SUSPICIOUS)
        self.assertIn("count down", result.detail)

    def test_small_overshoot_within_tolerance_is_clean(self):
        """A 5% allowance absorbs ordinary measurement skew."""
        self.assertIs(check_ttl(310, 300, max_ratio=1.05).status, S.CLEAN)

    def test_absurdly_long_ttl_is_suspicious_even_without_ground_truth(self):
        self.assertIs(check_ttl(31_000_000, None).status, S.SUSPICIOUS)

    def test_negative_ttl_is_suspicious(self):
        self.assertIs(check_ttl(-1, 300).status, S.SUSPICIOUS)

    def test_missing_ttl_is_unavailable_not_clean(self):
        self.assertIs(check_ttl(None, 300).status, S.UNAVAILABLE)

    def test_frozen_ttl_across_queries_is_suspicious(self):
        result = check_ttl(300, 300, repeated_ttls=[300, 300, 300])
        self.assertIs(result.status, S.SUSPICIOUS)
        self.assertIn("static answer", result.detail)

    def test_decrementing_ttl_is_clean(self):
        self.assertIs(check_ttl(280, 300, repeated_ttls=[300, 290, 280]).status,
                      S.CLEAN)

    def test_refetch_resetting_the_ttl_is_clean(self):
        """A rise back to the published value is an honest cache renewal."""
        self.assertIs(check_ttl(300, 300, repeated_ttls=[20, 10, 300]).status,
                      S.CLEAN)

    def test_ttl_rising_above_the_published_value_is_suspicious(self):
        result = check_ttl(5000, 300, repeated_ttls=[100, 5000])
        self.assertIs(result.status, S.SUSPICIOUS)

    def test_no_authoritative_ttl_still_reports_plausibility(self):
        self.assertIs(check_ttl(300, None).status, S.CLEAN)


# --------------------------------------------------------------------------
# Bailiwick
# --------------------------------------------------------------------------
class BailiwickModule(unittest.TestCase):
    def test_answer_only_response_is_clean(self):
        response = message(answer=["www.example.com. 300 IN A 93.184.216.34"])
        self.assertIs(
            check_bailiwick("203.0.113.1", "www.example.com", response=response).status,
            S.CLEAN)

    def test_glue_inside_the_zone_is_clean(self):
        response = message(
            answer=["www.example.com. 300 IN A 93.184.216.34"],
            additional=["ns1.example.com. 300 IN A 93.184.216.1"])
        self.assertIs(
            check_bailiwick("203.0.113.1", "www.example.com", response=response).status,
            S.CLEAN)

    def test_record_for_an_unrelated_name_is_suspicious(self):
        """The Kaminsky shape: an answer about one name smuggling another."""
        response = message(
            answer=["www.example.com. 300 IN A 93.184.216.34"],
            additional=["www.bank.test. 300 IN A 6.6.6.6"])
        result = check_bailiwick("203.0.113.1", "www.example.com", response=response)
        self.assertIs(result.status, S.SUSPICIOUS)
        self.assertIn("www.bank.test.", result.detail)

    def test_out_of_bailiwick_record_in_authority_is_caught(self):
        response = message(
            authority=["example.com. 300 IN NS ns1.example.com."],
            additional=["evil.attacker.test. 300 IN A 6.6.6.6"])
        self.assertIs(
            check_bailiwick("203.0.113.1", "www.example.com", response=response).status,
            S.SUSPICIOUS)

    def test_glue_for_a_delegated_nameserver_is_in_bailiwick(self):
        """Out-of-zone glue is legitimate when the response delegates to it."""
        response = message(
            authority=["example.com. 300 IN NS ns1.hoster.test."],
            additional=["ns1.hoster.test. 300 IN A 198.18.0.1"])
        self.assertIs(
            check_bailiwick("203.0.113.1", "www.example.com", response=response).status,
            S.CLEAN)

    def test_a_tld_never_becomes_a_bailiwick(self):
        """Otherwise every record ever sent would qualify and the check is vacuous."""
        response = message(
            question="example.com. IN A",
            additional=["unrelated.com. 300 IN A 6.6.6.6"])
        self.assertIs(
            check_bailiwick("203.0.113.1", "example.com", response=response).status,
            S.SUSPICIOUS)

    def test_non_address_records_are_ignored(self):
        """Only an A/AAAA payload can actually redirect traffic."""
        response = message(
            answer=["www.example.com. 300 IN A 93.184.216.34"],
            additional=["something.test. 300 IN TXT \"hello\""])
        self.assertIs(
            check_bailiwick("203.0.113.1", "www.example.com", response=response).status,
            S.CLEAN)


# --------------------------------------------------------------------------
# Cross-resolver consensus
# --------------------------------------------------------------------------
class ConsensusModule(unittest.TestCase):
    TRUTH = frozenset({"1.1.1.1"})

    def test_agreement_with_the_trusted_path_is_clean(self):
        result = check_consensus(self.TRUTH, self.TRUTH, {"a": self.TRUTH})
        self.assertIs(result.status, S.CLEAN)

    def test_no_peers_is_unavailable(self):
        result = check_consensus(frozenset({"9.9.9.9"}), self.TRUTH, {})
        self.assertIs(result.status, S.UNAVAILABLE)

    def test_lone_deviation_with_peers_agreeing_is_suspicious(self):
        result = check_consensus(frozenset({"9.9.9.9"}), self.TRUTH,
                                 {"a": self.TRUTH, "b": self.TRUTH})
        self.assertIs(result.status, S.SUSPICIOUS)
        self.assertIn("isolated", result.detail)

    def test_peers_returning_the_same_extra_address_is_benign(self):
        """If independent resolvers see it too, it is not injected."""
        odd = frozenset({"9.9.9.9"})
        result = check_consensus(odd, self.TRUTH, {"a": odd, "b": self.TRUTH})
        self.assertIs(result.status, S.BENIGN)

    def test_widespread_disagreement_is_systemic_not_poisoning(self):
        result = check_consensus(
            frozenset({"9.9.9.9"}), self.TRUTH,
            {"a": frozenset({"8.8.8.8"}), "b": frozenset({"7.7.7.7"})})
        self.assertIs(result.status, S.BENIGN)
        self.assertIn("systemic", result.detail)

    def test_peer_agreement_is_never_treated_as_proof_of_correctness(self):
        """§3: reputation is not ground truth — a peer match only isolates."""
        result = check_consensus(self.TRUTH, self.TRUTH, {"a": frozenset({"9.9.9.9"})})
        self.assertIs(result.status, S.CLEAN)
        self.assertIn("no deviation", result.detail)


# --------------------------------------------------------------------------
# EDNS Client Subnet
# --------------------------------------------------------------------------
class EcsModule(unittest.TestCase):
    def test_answer_varying_by_subnet_is_benign_geodns(self):
        result = check_ecs("203.0.113.1", "cdn.test", observed={
            "8.8.8.0/24": frozenset({"1.1.1.1"}),
            "1.1.1.0/24": frozenset({"2.2.2.2"}),
        })
        self.assertIs(result.status, S.BENIGN)
        self.assertIn("GeoDNS", result.detail)

    def test_identical_answers_remove_the_geographic_explanation(self):
        result = check_ecs("203.0.113.1", "static.test", observed={
            "8.8.8.0/24": frozenset({"1.1.1.1"}),
            "1.1.1.0/24": frozenset({"1.1.1.1"}),
        })
        self.assertIs(result.status, S.CLEAN)
        self.assertIn("geography does not explain", result.detail)

    def test_a_single_subnet_cannot_support_a_conclusion(self):
        result = check_ecs("203.0.113.1", "x.test",
                           observed={"8.8.8.0/24": frozenset({"1.1.1.1"})})
        self.assertIs(result.status, S.UNAVAILABLE)

    def test_no_data_is_unavailable(self):
        self.assertIs(check_ecs("203.0.113.1", "x.test", observed={}).status,
                      S.UNAVAILABLE)

    def test_the_module_never_reports_suspicious(self):
        """It removes an explanation; it never accuses. Only §8 concludes."""
        for observed in ({"a": frozenset({"1.1.1.1"}), "b": frozenset({"2.2.2.2"})},
                         {"a": frozenset({"1.1.1.1"}), "b": frozenset({"1.1.1.1"})}):
            self.assertIsNot(check_ecs("203.0.113.1", "x.test", observed=observed).status,
                             S.SUSPICIOUS)


# --------------------------------------------------------------------------
# Cache snooping (RD=0)
# --------------------------------------------------------------------------
class SnoopModule(unittest.TestCase):
    def test_cached_entry_is_reported_with_its_ttl(self):
        response = message(answer=["www.example.com. 120 IN A 93.184.216.34"])
        result = check_cache_state("203.0.113.1", "www.example.com", response=response)
        self.assertIs(result.status, S.CLEAN)
        self.assertTrue(result.data["cached"])
        self.assertEqual(result.data["ttl"], 120)

    def test_empty_answer_means_not_cached(self):
        result = check_cache_state("203.0.113.1", "www.example.com",
                                   response=message())
        self.assertIs(result.status, S.CLEAN)
        self.assertFalse(result.data["cached"])

    def test_refused_rd0_is_unavailable_not_a_finding(self):
        """Declining snooping is a sound configuration, not a fault."""
        result = check_cache_state("203.0.113.1", "www.example.com",
                                   response=message(rcode="REFUSED"))
        self.assertIs(result.status, S.UNAVAILABLE)

    def test_a_cache_hit_is_never_suspicious_on_its_own(self):
        response = message(answer=["www.example.com. 1 IN A 93.184.216.34"])
        self.assertIsNot(
            check_cache_state("203.0.113.1", "www.example.com", response=response).status,
            S.SUSPICIOUS)


# --------------------------------------------------------------------------
# Properties every module must hold to (module contract, argus/modules/__init__)
# --------------------------------------------------------------------------
class ModuleContract(unittest.TestCase):
    def test_every_module_names_itself_in_its_result(self):
        cases = [
            ("ttl", check_ttl(250, 300)),
            ("bailiwick", check_bailiwick("203.0.113.1", "www.example.com",
                                          response=message())),
            ("consensus", check_consensus(frozenset({"1.1.1.1"}),
                                          frozenset({"1.1.1.1"}), {"a": frozenset()})),
            ("ecs", check_ecs("203.0.113.1", "x.test", observed={})),
            ("snoop", check_cache_state("203.0.113.1", "x.test", response=message())),
        ]
        for name, result in cases:
            self.assertEqual(result.module, name)
            self.assertTrue(result.detail, f"{name} produced no explanation")

    def test_only_suspicious_counts_as_positive_evidence(self):
        self.assertTrue(check_ttl(-1, 300).is_positive_evidence)
        self.assertFalse(check_ttl(250, 300).is_positive_evidence)
        self.assertFalse(check_ecs("203.0.113.1", "x.test", observed={
            "a": frozenset({"1.1.1.1"}), "b": frozenset({"2.2.2.2"}),
        }).is_positive_evidence)

    def test_an_unreachable_resolver_never_raises(self):
        """Network failure is an observation, not an exception (§7 rule 2)."""
        for result in (
            check_bailiwick("192.0.2.1", "x.test", timeout=0.001),
            check_cache_state("192.0.2.1", "x.test", timeout=0.001),
            check_ecs("192.0.2.1", "x.test", timeout=0.001,
                      subnets=(("203.0.113.0", 24),)),
        ):
            self.assertIs(result.status, S.UNAVAILABLE)


if __name__ == "__main__":
    unittest.main()
