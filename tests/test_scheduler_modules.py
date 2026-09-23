"""Integration tests for the tier pipeline inside a sweep.

Covers the wiring the other suites deliberately switch off: that a sweep runs
the §7 signal modules, assigns a §8 tier through the §9 exclusion hierarchy,
persists the tier and its audit trail, and honours the query budget by probing
only observations that actually diverge.

Offline and deterministic. The network-facing modules are replaced with
stand-ins that record how often they were called, so the *policy* (when a module
runs) is tested without any packets.

    python -m unittest tests.test_scheduler_modules -v
"""

from __future__ import annotations

import json
import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus import scheduler as scheduler_module
from argus.config import Settings
from argus.models import (AuthoritativeAnswer, DirectAnswer, ModuleResult,
                          ModuleStatus, MonitoredResolver, Tier)
from argus.scheduler import Scheduler
from argus.storage import Storage

TRUTH = {"good.test": {"1.1.1.1"}, "bank.test": {"203.0.113.10"}}


class FakeVerifier:
    def resolve(self, domain, rtype="A"):
        return AuthoritativeAnswer(domain=domain, rtype=rtype,
                                   records=frozenset(TRUTH.get(domain, set())),
                                   ttl=300, rcode="NOERROR")


class FakeProbe:
    """`evil` serves a routable address the zone never published."""

    def query(self, resolver, domain, rtype="A"):
        records = TRUTH.get(domain, set())
        if resolver.name == "evil" and domain == "bank.test":
            records = {"93.184.216.34"}
        return DirectAnswer(resolver=resolver.name, domain=domain, rtype=rtype,
                            resolver_ip=resolver.address, records=frozenset(records),
                            min_ttl=300, rcode="NOERROR", latency_ms=5.0)


def settings(resolvers, modules=True):
    raw = {
        "vantage": "test",
        "schedule": {"interval_seconds": 1, "per_resolver_delay": 0.0},
        "query": {"timeout_seconds": 1.0, "retries": 0, "rtypes": ["A"]},
        "verification": {"requery": True, "rewalk": True,
                         "control_crosscheck": True, "persistence": 2},
        "freshness": {"max_ttl_ratio": 1.05}, "dnssec": {"enabled": False},
        "storage": {"path": ":memory:"}, "dashboard": {"path": "x.html"},
        "logging": {"level": "CRITICAL"},
        "modules": {"enabled": modules},
    }
    return Settings(raw=raw, resolvers=resolvers, watchlist=["good.test", "bank.test"])


class SpyModules:
    """Stand-ins for the three network-facing modules, counting their calls."""

    def __init__(self, bailiwick_status=ModuleStatus.CLEAN):
        self.calls: dict[str, int] = {"ecs": 0, "bailiwick": 0, "snoop": 0}
        self.bailiwick_status = bailiwick_status

    def install(self, test):
        def make(name, status):
            def fn(*args, **kwargs):
                self.calls[name] += 1
                return ModuleResult(name, status, f"{name} stand-in")
            return fn

        for name, status in (("ecs", ModuleStatus.CLEAN),
                             ("bailiwick", self.bailiwick_status),
                             ("snoop", ModuleStatus.CLEAN)):
            attr = {"ecs": "check_ecs", "bailiwick": "check_bailiwick",
                    "snoop": "check_cache_state"}[name]
            patcher = unittest.mock.patch.object(
                scheduler_module, attr, make(name, status))
            patcher.start()
            test.addCleanup(patcher.stop)


import unittest.mock  # noqa: E402  (imported after SpyModules for readability)


class TierPipeline(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.storage = Storage(":memory:")
        self.resolvers = [
            MonitoredResolver("google", "8.8.8.8", role="control"),
            MonitoredResolver("evil", "203.0.113.9", role="isp"),
        ]
        self.addCleanup(self.storage.close)
        self.addCleanup(logging.disable, logging.NOTSET)

    def sweep(self, modules=True, bailiwick_status=ModuleStatus.CLEAN,
              resolvers=None):
        spy = SpyModules(bailiwick_status)
        spy.install(self)
        sched = Scheduler(settings(resolvers or self.resolvers, modules),
                          self.storage, probe=FakeProbe(), verifier=FakeVerifier())
        return sched.run_once(), spy

    @property
    def no_controls(self):
        """Only the divergent resolver, so no peer can isolate its deviation."""
        return [MonitoredResolver("evil", "203.0.113.9", role="isp")]

    # -- tiers are produced and persisted ---------------------------------
    def test_sweep_reports_a_tier_profile(self):
        summary, _ = self.sweep()
        self.assertIn("tiers", summary)
        self.assertEqual(sum(summary["tiers"].values()), summary["queries"])

    def test_clean_answers_are_tier_0(self):
        self.sweep()
        counts = self.storage.tier_counts()
        self.assertGreaterEqual(counts.get(0, 0), 3)

    def test_the_divergent_resolver_is_recorded_above_tier_3(self):
        self.sweep()
        rows = self.storage.verdicts_at_or_above(4)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["resolver"], "evil")
        self.assertEqual(rows[0]["domain"], "bank.test")

    def test_tier_and_audit_trail_are_persisted_together(self):
        self.sweep()
        row = self.storage.verdicts_at_or_above(4)[0]
        payload = json.loads(row["verdict_json"])
        self.assertEqual(payload["tier"], row["tier"])
        # All five gates recorded, in order.
        self.assertEqual([g["stage"] for g in payload["exclusions"]], [1, 2, 3, 4, 5])
        self.assertTrue(row["tier_label"])
        self.assertEqual(row["relation"], "DISJOINT")

    def test_a_bare_divergence_stops_at_tier_4(self):
        """With nothing corroborating it, the ladder must not go further.

        Note the deliberate absence of control resolvers: with peers present,
        consensus would isolate the deviation, and §8 lists an isolated
        cross-resolver disagreement as a legitimate Tier-5 corroborator.
        """
        self.sweep(resolvers=self.no_controls, bailiwick_status=ModuleStatus.CLEAN)
        self.assertEqual(self.storage.verdicts_at_or_above(4)[0]["tier"],
                         int(Tier.UNEXPLAINED_DIVERGENCE))

    def test_isolated_peer_disagreement_alone_reaches_tier_5(self):
        """§8 names this as a corroborating structural signal in its own right."""
        self.sweep(bailiwick_status=ModuleStatus.CLEAN)
        row = self.storage.verdicts_at_or_above(5)[0]
        self.assertEqual(row["tier"], int(Tier.CORROBORATED_DIVERGENCE))
        self.assertEqual(json.loads(row["verdict_json"])["positive_evidence"],
                         ["consensus"])

    def test_structural_evidence_escalates_to_tier_5(self):
        self.sweep(bailiwick_status=ModuleStatus.SUSPICIOUS)
        row = self.storage.verdicts_at_or_above(5)[0]
        self.assertEqual(row["tier"], int(Tier.CORROBORATED_DIVERGENCE))
        self.assertIn("bailiwick", json.loads(row["verdict_json"])["positive_evidence"])

    def test_nothing_ever_reaches_tier_6_without_dnssec(self):
        self.sweep(bailiwick_status=ModuleStatus.SUSPICIOUS)
        self.assertEqual(self.storage.verdicts_at_or_above(6), [])

    # -- the query budget (§15) -------------------------------------------
    def test_network_modules_run_only_for_a_divergence(self):
        """Four observations, one divergent: each module probes exactly once."""
        _, spy = self.sweep()
        self.assertEqual(spy.calls, {"ecs": 1, "bailiwick": 1, "snoop": 1})

    def test_modules_can_be_switched_off_entirely(self):
        _, spy = self.sweep(modules=False)
        self.assertEqual(spy.calls, {"ecs": 0, "bailiwick": 0, "snoop": 0})

    def test_tiers_are_still_assigned_with_modules_disabled(self):
        """Disabling probes must not disable the verdict — only weaken it.

        The free signals (TTL, and consensus over answers already collected)
        still run, so the divergence is still found and still tiered.
        """
        summary, _ = self.sweep(modules=False)
        self.assertTrue(summary["tiers"])
        self.assertGreaterEqual(self.storage.verdicts_at_or_above(4)[0]["tier"],
                                int(Tier.UNEXPLAINED_DIVERGENCE))

    def test_without_probes_or_peers_a_divergence_cannot_be_corroborated(self):
        self.sweep(modules=False, resolvers=self.no_controls)
        self.assertEqual(self.storage.verdicts_at_or_above(4)[0]["tier"],
                         int(Tier.UNEXPLAINED_DIVERGENCE))
        self.assertEqual(self.storage.verdicts_at_or_above(5), [])

    # -- alerting --------------------------------------------------------
    def test_a_divergence_raises_an_alert_carrying_its_tier(self):
        summary, _ = self.sweep(bailiwick_status=ModuleStatus.SUSPICIOUS)
        self.assertEqual(summary["alerts"], 1)
        self.assertEqual(self.storage.table_counts()["alerts"], 1)

    def test_a_failing_module_does_not_stop_the_sweep(self):
        def boom(*args, **kwargs):
            raise RuntimeError("module exploded")

        with unittest.mock.patch.object(scheduler_module, "check_bailiwick", boom):
            sched = Scheduler(settings(self.resolvers), self.storage,
                              probe=FakeProbe(), verifier=FakeVerifier())
            with unittest.mock.patch.object(
                    scheduler_module, "check_ecs",
                    lambda *a, **k: ModuleResult("ecs", ModuleStatus.CLEAN, "x")), \
                 unittest.mock.patch.object(
                    scheduler_module, "check_cache_state",
                    lambda *a, **k: ModuleResult("snoop", ModuleStatus.CLEAN, "x")):
                summary = sched.run_once()
        self.assertEqual(summary["queries"], 4)
        self.assertTrue(self.storage.verdicts_at_or_above(4))


class TierRollups(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.storage = Storage(":memory:")
        self.addCleanup(self.storage.close)
        self.addCleanup(logging.disable, logging.NOTSET)
        spy = SpyModules()
        spy.install(self)
        Scheduler(settings([MonitoredResolver("google", "8.8.8.8", role="control"),
                            MonitoredResolver("evil", "203.0.113.9", role="isp")]),
                  self.storage, probe=FakeProbe(), verifier=FakeVerifier()).run_once()

    def test_rollup_reports_the_worst_tier_per_resolver(self):
        rows = {row["key"]: row for row in self.storage.tier_rollup("resolver")}
        self.assertEqual(rows["google"]["worst_tier"], 0)
        self.assertGreaterEqual(rows["evil"]["worst_tier"], 4)

    def test_rollup_separates_clean_from_unexplained(self):
        rows = {row["key"]: row for row in self.storage.tier_rollup("resolver")}
        self.assertEqual(rows["google"]["clean"], 2)
        self.assertEqual(rows["evil"]["corroborated"], 1)
        self.assertEqual(rows["evil"]["clean"], 1)

    def test_rollup_by_domain_is_supported(self):
        rows = {row["key"]: row for row in self.storage.tier_rollup("domain")}
        self.assertEqual(rows["good.test"]["clean"], 2)
        self.assertGreaterEqual(rows["bank.test"]["worst_tier"], 4)

    def test_an_unknown_rollup_column_is_rejected(self):
        with self.assertRaises(ValueError):
            self.storage.tier_rollup("; DROP TABLE comparisons")


if __name__ == "__main__":
    unittest.main()
