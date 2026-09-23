"""Unit tests for the Tier 0-6 verdict engine (argus.verdict).

Controlled, offline examples. Each test is a claim about how strong a statement
ARGUS is entitled to make given a particular set of observations, so these tests
are really assertions about the project's *reporting discipline* (methodology
§8, §9) rather than about detection mechanics.

The shape of the suite mirrors the ladder: the tiers first, then each of the
five exclusion gates, then the monotonicity property that ties them together.

    python -m unittest tests.test_verdict -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.comparison import compare
from argus.models import (AuthoritativeAnswer, Classification, DirectAnswer,
                          DnssecStatus, DnssecPosture, ExclusionStage,
                          ModuleResult, ModuleStatus, SecurityStatus,
                          SetRelation, Tier)
from argus.verdict import assign_tier, relation_of

T = Tier


def direct(records, rtype="A", rcode="NOERROR", ttl=300, error=None):
    return DirectAnswer(resolver="r", domain="d.test", rtype=rtype,
                        resolver_ip="203.0.113.1", records=frozenset(records),
                        min_ttl=ttl, rcode=rcode, error=error)


def auth(records, rtype="A", rcode="NOERROR", ttl=300, error=None):
    return AuthoritativeAnswer(domain="d.test", rtype=rtype,
                               records=frozenset(records), ttl=ttl, rcode=rcode,
                               error=error)


def module(name, status, detail="", **data):
    return ModuleResult(name, status, detail or f"{name} says {status.value}", data)


def verdict_for(resolver_records, truth_records, modules=None, ttl=300,
                auth_ttl=300, rcode="NOERROR", persistent=True, dnssec=None,
                error=None):
    """Run a full comparison and tier assignment over synthetic answers."""
    d = direct(resolver_records, ttl=ttl, rcode=rcode, error=error)
    a = auth(truth_records, ttl=auth_ttl)
    return assign_tier(compare(d, a), modules=modules, direct=d, authoritative=a,
                       dnssec=dnssec, persistent=persistent)


def signed_bogus():
    return DnssecStatus(domain="d.test", resolver="r", signed=True,
                        posture=DnssecPosture.VALIDATING,
                        security=SecurityStatus.BOGUS, ad_flag=False,
                        supports_anomaly=True)


# --------------------------------------------------------------------------
# The set-relation characterisation (§4, §11)
# --------------------------------------------------------------------------
class SetRelations(unittest.TestCase):
    def test_identical_sets_are_match(self):
        self.assertEqual(relation_of(compare(direct(["1.1.1.1"]), auth(["1.1.1.1"]))),
                         SetRelation.MATCH)

    def test_fewer_records_is_subset(self):
        self.assertEqual(
            relation_of(compare(direct(["1.1.1.1"]), auth(["1.1.1.1", "2.2.2.2"]))),
            SetRelation.SUBSET)

    def test_extra_records_alongside_valid_ones_is_superset(self):
        self.assertEqual(
            relation_of(compare(direct(["1.1.1.1", "9.9.9.9"]), auth(["1.1.1.1"]))),
            SetRelation.SUPERSET)

    def test_no_overlap_at_all_is_disjoint(self):
        self.assertEqual(
            relation_of(compare(direct(["9.9.9.9"]), auth(["1.1.1.1"]))),
            SetRelation.DISJOINT)

    def test_unmeasurable_side_is_undetermined(self):
        self.assertEqual(
            relation_of(compare(direct([], error="timeout"), auth(["1.1.1.1"]))),
            SetRelation.UNDETERMINED)


# --------------------------------------------------------------------------
# Tier 0 / 2 / 3 — the non-divergence outcomes
# --------------------------------------------------------------------------
class BaseTiers(unittest.TestCase):
    def test_matching_answer_is_tier_0(self):
        v = verdict_for(["1.1.1.1"], ["1.1.1.1"])
        self.assertEqual(v.tier, T.CLEAN)
        self.assertEqual(v.classification, Classification.NORMAL)
        self.assertFalse(v.suggestive)

    def test_timeout_is_tier_2_health_not_an_integrity_finding(self):
        v = verdict_for([], ["1.1.1.1"], rcode="TIMEOUT", error="timeout")
        self.assertEqual(v.tier, T.HEALTH_ISSUE)
        self.assertFalse(v.tier.is_divergence)

    def test_servfail_is_tier_2(self):
        self.assertEqual(verdict_for([], ["1.1.1.1"], rcode="SERVFAIL").tier,
                         T.HEALTH_ISSUE)

    def test_failed_ground_truth_walk_is_tier_2_not_clean(self):
        d = direct(["1.1.1.1"])
        a = auth([], error="no route to root servers")
        v = assign_tier(compare(d, a), direct=d, authoritative=a)
        self.assertEqual(v.tier, T.HEALTH_ISSUE)
        self.assertIn("ground truth", v.reason)

    def test_match_with_inflated_ttl_is_tier_3(self):
        v = verdict_for(["1.1.1.1"], ["1.1.1.1"], ttl=9000, auth_ttl=300)
        self.assertEqual(v.tier, T.FRESHNESS_ANOMALY)

    def test_tier_2_beats_tier_3_when_both_could_apply(self):
        """An unanswerable query has no integrity result to discuss at all."""
        v = verdict_for([], ["1.1.1.1"], rcode="SERVFAIL", ttl=9000, auth_ttl=300)
        self.assertEqual(v.tier, T.HEALTH_ISSUE)


# --------------------------------------------------------------------------
# §9 stage 1 — GeoDNS
# --------------------------------------------------------------------------
class GeoDnsGate(unittest.TestCase):
    def test_ecs_variation_caps_a_divergence_at_tier_1(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"],
                        modules={"ecs": module("ecs", ModuleStatus.BENIGN)})
        self.assertEqual(v.tier, T.BENIGN_EXPLAINED)
        self.assertFalse(v.gate(ExclusionStage.GEODNS).passed)

    def test_systemic_peer_disagreement_caps_at_tier_1(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"],
                        modules={"consensus": module("consensus", ModuleStatus.BENIGN)})
        self.assertEqual(v.tier, T.BENIGN_EXPLAINED)

    def test_subset_is_load_balancing_not_a_divergence(self):
        v = verdict_for(["1.1.1.1"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(v.tier, T.BENIGN_EXPLAINED)
        self.assertEqual(v.relation, SetRelation.SUBSET)

    def test_geodns_beats_structural_evidence(self):
        """A geographic explanation settles it before evidence is weighed."""
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], modules={
            "ecs": module("ecs", ModuleStatus.BENIGN),
            "bailiwick": module("bailiwick", ModuleStatus.SUSPICIOUS),
        })
        self.assertEqual(v.tier, T.BENIGN_EXPLAINED)


# --------------------------------------------------------------------------
# §9 stage 2 — timing
# --------------------------------------------------------------------------
class TimingGate(unittest.TestCase):
    def test_non_reproducing_divergence_is_capped_at_tier_3(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], persistent=False)
        self.assertEqual(v.tier, T.FRESHNESS_ANOMALY)
        self.assertEqual(v.classification, Classification.TEMPORARY_ANOMALY)

    def test_untested_persistence_with_bad_ttl_is_capped_at_tier_3(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], ttl=9000, auth_ttl=300,
                        persistent=None)
        self.assertEqual(v.tier, T.FRESHNESS_ANOMALY)

    def test_timing_gate_outranks_positive_evidence(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], persistent=False, modules={
            "bailiwick": module("bailiwick", ModuleStatus.SUSPICIOUS)})
        self.assertEqual(v.tier, T.FRESHNESS_ANOMALY)


# --------------------------------------------------------------------------
# §9 stage 3 — ISP policy interception
# --------------------------------------------------------------------------
class PolicyGate(unittest.TestCase):
    def test_private_address_is_characterised_as_policy_not_attack(self):
        v = verdict_for(["192.168.1.1"], ["1.1.1.1"])
        self.assertEqual(v.tier, T.BENIGN_EXPLAINED)
        self.assertIn("policy", v.reason)

    def test_loopback_sinkhole_is_policy(self):
        self.assertEqual(verdict_for(["127.0.0.1"], ["1.1.1.1"]).tier,
                         T.BENIGN_EXPLAINED)

    def test_unspecified_address_is_policy(self):
        self.assertEqual(verdict_for(["0.0.0.0"], ["1.1.1.1"]).tier,
                         T.BENIGN_EXPLAINED)

    def test_a_routable_address_is_not_policy(self):
        """An attacker needs traffic to reach them, so it must be routable.

        Note the address: RFC 5737 documentation ranges (203.0.113.0/24 and
        friends) are classified non-routable by `ipaddress`, so they would be
        read as policy filtering. A genuinely public address is needed to
        exercise this path.
        """
        v = verdict_for(["93.184.216.34"], ["1.1.1.1"])
        self.assertEqual(v.tier, T.UNEXPLAINED_DIVERGENCE)

    def test_mixed_private_and_routable_is_not_written_off_as_policy(self):
        v = verdict_for(["192.168.1.1", "93.184.216.34"], ["1.1.1.1"])
        self.assertEqual(v.tier, T.UNEXPLAINED_DIVERGENCE)


# --------------------------------------------------------------------------
# §9 stage 4 / 5 — positive evidence and honest characterisation
# --------------------------------------------------------------------------
class EvidenceGate(unittest.TestCase):
    def test_bare_mismatch_stops_at_tier_4(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"])
        self.assertEqual(v.tier, T.UNEXPLAINED_DIVERGENCE)
        self.assertTrue(v.suggestive)
        self.assertFalse(v.gate(ExclusionStage.POSITIVE_EVIDENCE).passed)
        self.assertNotIn("poisoning", v.reason.lower().replace("not a poisoning claim", ""))

    def test_bailiwick_violation_corroborates_to_tier_5(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], modules={
            "bailiwick": module("bailiwick", ModuleStatus.SUSPICIOUS)})
        self.assertEqual(v.tier, T.CORROBORATED_DIVERGENCE)
        self.assertTrue(v.suggestive)
        self.assertEqual(v.positive_evidence, ["bailiwick"])

    def test_isolated_peer_disagreement_corroborates_to_tier_5(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], modules={
            "consensus": module("consensus", ModuleStatus.SUSPICIOUS)})
        self.assertEqual(v.tier, T.CORROBORATED_DIVERGENCE)

    def test_ttl_alone_never_corroborates_a_divergence(self):
        """TTL is a freshness signal, not structural evidence of injection."""
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], modules={
            "ttl": module("ttl", ModuleStatus.SUSPICIOUS)})
        self.assertEqual(v.tier, T.UNEXPLAINED_DIVERGENCE)

    def test_tier_5_is_reported_as_suggestive_not_proven(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], modules={
            "bailiwick": module("bailiwick", ModuleStatus.SUSPICIOUS)})
        self.assertIn("suggestive", v.reason)
        self.assertIn("not proven", v.reason)


# --------------------------------------------------------------------------
# Tier 6 — the only conclusive claim
# --------------------------------------------------------------------------
class ConclusiveTier(unittest.TestCase):
    def test_signed_zone_failing_validation_reaches_tier_6(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], dnssec=signed_bogus())
        self.assertEqual(v.tier, T.CONCLUSIVE_TAMPERING)
        self.assertFalse(v.suggestive)

    def test_unsigned_zone_can_never_reach_tier_6(self):
        unsigned = DnssecStatus(domain="d.test", resolver="r", signed=False,
                                posture=DnssecPosture.VALIDATING,
                                security=SecurityStatus.INSECURE, ad_flag=False,
                                supports_anomaly=False)
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], dnssec=unsigned)
        self.assertLess(int(v.tier), int(T.CONCLUSIVE_TAMPERING))

    def test_signed_but_valid_answer_does_not_reach_tier_6(self):
        secure = DnssecStatus(domain="d.test", resolver="r", signed=True,
                              posture=DnssecPosture.VALIDATING,
                              security=SecurityStatus.SECURE, ad_flag=True,
                              supports_anomaly=False)
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], dnssec=secure)
        self.assertEqual(v.tier, T.UNEXPLAINED_DIVERGENCE)

    def test_dnssec_proof_needs_unpublished_data_actually_served(self):
        """A subset with a BOGUS status is still not proof of injection."""
        v = verdict_for(["1.1.1.1"], ["1.1.1.1", "2.2.2.2"], dnssec=signed_bogus())
        self.assertEqual(v.tier, T.BENIGN_EXPLAINED)


# --------------------------------------------------------------------------
# Properties of the ladder itself (§8)
# --------------------------------------------------------------------------
class LadderProperties(unittest.TestCase):
    def test_every_tier_has_a_label_and_an_interpretation(self):
        for tier in Tier:
            self.assertTrue(tier.label)
            self.assertTrue(tier.interpretation)

    def test_only_tiers_4_and_5_are_suggestive(self):
        self.assertEqual([t for t in Tier if t.suggestive_only],
                         [T.UNEXPLAINED_DIVERGENCE, T.CORROBORATED_DIVERGENCE])

    def test_alerting_fires_on_tier_2_and_tier_4_and_above(self):
        self.assertEqual([int(t) for t in Tier if t.needs_alert], [2, 4, 5, 6])

    def test_gates_are_recorded_in_order_for_an_escalating_case(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], modules={
            "bailiwick": module("bailiwick", ModuleStatus.SUSPICIOUS)})
        self.assertEqual([int(o.stage) for o in v.exclusions], [1, 2, 3, 4, 5])

    def test_a_capped_verdict_records_why_it_was_capped(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"],
                        modules={"ecs": module("ecs", ModuleStatus.BENIGN)})
        gate = v.gate(ExclusionStage.GEODNS)
        self.assertFalse(gate.passed)
        self.assertEqual(gate.capped_at, T.BENIGN_EXPLAINED)

    def test_evidence_export_is_json_safe_and_complete(self):
        v = verdict_for(["9.9.9.9"], ["1.1.1.1"], modules={
            "bailiwick": module("bailiwick", ModuleStatus.SUSPICIOUS)})
        import json
        payload = json.loads(json.dumps(v.as_evidence()))
        self.assertEqual(payload["tier"], 5)
        self.assertTrue(payload["suggestive"])
        self.assertEqual(payload["positive_evidence"], ["bailiwick"])
        self.assertEqual(len(payload["exclusions"]), 5)


if __name__ == "__main__":
    unittest.main()
