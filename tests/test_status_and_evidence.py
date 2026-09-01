"""Tests for the reported status vocabulary and the stored authoritative evidence.

Offline: an in-memory database and hand-built metric rows. No network.

    python -m unittest tests.test_status_and_evidence -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.dashboard import shell
from argus.models import AuthoritativeAnswer
from argus.storage import Storage


def health(**overrides) -> dict:
    """A health_metrics row, healthy unless overridden."""
    row = {"availability_pct": 100.0, "timeout_rate": 0.0, "servfail_rate": 0.0,
           "error_rate": 0.0, "anomaly_rate": 0.0, "possible_poisoning_rate": 0.0,
           "freshness_status": "OK"}
    row.update(overrides)
    return row


class StatusVocabularyTests(unittest.TestCase):
    def test_no_metrics_is_no_data(self):
        self.assertEqual(shell.resolver_status(None), shell.NO_DATA)

    def test_clean_metrics_are_healthy(self):
        self.assertEqual(shell.resolver_status(health()), shell.HEALTHY)

    def test_poisoning_outranks_everything(self):
        status = shell.resolver_status(
            health(possible_poisoning_rate=0.1, availability_pct=0.0,
                   timeout_rate=1.0, anomaly_rate=1.0))
        self.assertEqual(status, shell.POSSIBLE_POISONING)

    def test_zero_availability_is_unreachable(self):
        self.assertEqual(shell.resolver_status(health(availability_pct=0.0)),
                         shell.UNREACHABLE)

    def test_dominant_timeouts_are_timeout(self):
        self.assertEqual(
            shell.resolver_status(health(availability_pct=40.0, timeout_rate=0.6)),
            shell.TIMEOUT)

    def test_dominant_errors_are_error(self):
        self.assertEqual(
            shell.resolver_status(health(availability_pct=40.0, servfail_rate=0.6)),
            shell.ERROR)

    def test_anomalies_are_suspicious(self):
        self.assertEqual(shell.resolver_status(health(anomaly_rate=0.2)),
                         shell.SUSPICIOUS)

    def test_partial_availability_is_warning(self):
        self.assertEqual(shell.resolver_status(health(availability_pct=95.0)),
                         shell.WARNING)

    def test_degraded_freshness_is_warning(self):
        self.assertEqual(shell.resolver_status(health(freshness_status="DEGRADED")),
                         shell.WARNING)

    def test_every_status_has_a_tone(self):
        for status in shell.STATUS_SEVERITY:
            self.assertIn(shell.status_tone(status),
                          ("ok", "warn", "bad", "muted"), status)

    def test_severity_orders_poisoning_first_and_no_data_last(self):
        order = sorted(shell.STATUS_SEVERITY, key=shell.STATUS_SEVERITY.get)
        self.assertEqual(order[0], shell.POSSIBLE_POISONING)
        self.assertEqual(order[-1], shell.NO_DATA)


class AuthoritativeEvidenceTests(unittest.TestCase):
    """The authoritative servers and TLD must survive the round trip to SQLite."""

    def setUp(self):
        self.db = Storage(":memory:")
        self.db.upsert_domain("peoplesbank.lk")
        self.answer = AuthoritativeAnswer(
            domain="peoplesbank.lk", rtype="A",
            records=frozenset({"220.247.254.21"}), ttl=3600, rcode="NOERROR",
            authoritative_servers=("203.94.84.2", "203.115.0.18"),
            chain=(". -> lk.", "lk. -> peoplesbank.lk."))

    def tearDown(self):
        self.db.close()

    def test_servers_and_tld_are_persisted(self):
        self.db.insert_authoritative_result(self.answer)
        row = self.db._conn.execute(
            "SELECT servers, tld, chain FROM authoritative_results").fetchone()
        self.assertEqual(row["servers"], "203.94.84.2,203.115.0.18")
        self.assertEqual(row["tld"], "lk")
        self.assertIn("lk. -> peoplesbank.lk.", row["chain"])

    def test_view_exposes_the_new_columns(self):
        columns = {row[1] for row in
                   self.db._conn.execute("PRAGMA table_info(monitoring_events)")}
        for column in ("authoritative_servers", "delegation_chain", "tld"):
            self.assertIn(column, columns)

    def test_migration_is_idempotent_and_keeps_rows(self):
        self.db.insert_authoritative_result(self.answer)
        before = self.db.table_counts()
        self.db.init_schema()          # run the migration again
        self.db.init_schema()
        self.assertEqual(self.db.table_counts(), before)


class TldDerivationTests(unittest.TestCase):
    def test_tld_of_common_shapes(self):
        from argus.storage import _tld
        self.assertEqual(_tld("peoplesbank.lk"), "lk")
        self.assertEqual(_tld("cbsl.gov.lk"), "lk")
        self.assertEqual(_tld("nominet.uk"), "uk")
        self.assertEqual(_tld("example.COM."), "com")
        self.assertEqual(_tld("localhost"), "")


class DigCommandTests(unittest.TestCase):
    """The dashboard must show commands that actually reproduce a finding."""

    def test_both_paths_are_rendered(self):
        from argus.dashboard.pages import dig_commands
        html = dig_commands("peoplesbank.lk", "A", "1.1.1.1")
        self.assertIn("dig +short @1.1.1.1 peoplesbank.lk A", html)
        self.assertIn("dig +trace peoplesbank.lk A", html)

    def test_non_standard_port_is_included(self):
        from argus.dashboard.pages import dig_commands
        html = dig_commands("cloudflare.com", "A", "127.0.0.1", port=5354)
        self.assertIn("-p 5354", html)

    def test_glue_caveat_is_stated(self):
        from argus.dashboard.pages import dig_commands
        self.assertIn("glue", dig_commands("example.com", "A", "8.8.8.8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
