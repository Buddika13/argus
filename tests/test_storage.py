"""Unit tests for the database layer (argus.storage).

Uses an in-memory SQLite database, so nothing touches disk and every test is
isolated and deterministic.

    python -m unittest tests.test_storage -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus import sampledata
from argus.models import (AuthoritativeAnswer, DirectAnswer, MonitoredResolver)
from argus.storage import Storage


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.db = Storage(":memory:")

    def tearDown(self):
        self.db.close()

    def test_all_tables_exist_and_start_empty(self):
        counts = self.db.table_counts()
        self.assertEqual(set(counts), {
            "resolvers", "domains", "query_results", "authoritative_results",
            "comparisons", "health_metrics", "anomalies", "alerts", "dnssec_status",
        })
        self.assertTrue(all(v == 0 for v in counts.values()))

    def test_init_schema_is_non_destructive(self):
        self.db.upsert_resolver(MonitoredResolver("r", "1.1.1.1"))
        self.db.init_schema()                       # run again
        self.assertEqual(self.db.table_counts()["resolvers"], 1)   # data survives

    def test_upsert_resolver_updates_not_duplicates(self):
        self.db.upsert_resolver(MonitoredResolver("r", "1.1.1.1", isp="Old"))
        self.db.upsert_resolver(MonitoredResolver("r", "1.1.1.1", isp="New"))
        self.assertEqual(self.db.table_counts()["resolvers"], 1)


class MonitoringEventTests(unittest.TestCase):
    def setUp(self):
        self.db = Storage(":memory:")
        self.db.upsert_resolver(MonitoredResolver("google", "8.8.8.8", role="control"))
        self.db.upsert_domain("example.com", "global")

    def tearDown(self):
        self.db.close()

    def test_event_round_trips_through_the_view(self):
        from argus.comparison import compare
        direct = DirectAnswer(resolver="google", domain="example.com", rtype="A",
                              resolver_ip="8.8.8.8", records=frozenset({"1.2.3.4", "6.6.6.6"}),
                              min_ttl=300, rcode="NOERROR", latency_ms=12.0, observed_at=1000.0)
        auth = AuthoritativeAnswer(domain="example.com", rtype="A",
                                   records=frozenset({"1.2.3.4"}), ttl=300, observed_at=1000.0)
        result = compare(direct, auth)

        qid = self.db.insert_query_result(direct)
        aid = self.db.insert_authoritative_result(auth)
        self.db.insert_comparison(result, "google", "example.com", qid, aid, 1000.0)

        events = self.db.recent_events()
        self.assertEqual(len(events), 1)
        row = events[0]
        self.assertEqual(row["resolver"], "google")
        self.assertEqual(row["domain"], "example.com")
        self.assertEqual(row["query_type"], "A")
        self.assertEqual(row["rcode"], "NOERROR")
        self.assertEqual(row["ttl"], 300)
        self.assertEqual(row["comparison_classification"], "POSSIBLE_CACHE_POISONING")
        self.assertEqual(row["anomaly_status"], 1)
        self.assertIn("1.2.3.4", row["returned_records"])


class SampleDataTests(unittest.TestCase):
    def setUp(self):
        self.db = Storage(":memory:")
        sampledata.load(self.db, base_time=1_000_000.0)

    def tearDown(self):
        self.db.close()

    def test_every_table_is_populated(self):
        counts = self.db.table_counts()
        for table, n in counts.items():
            self.assertGreater(n, 0, f"table {table} should have sample rows")

    def test_alerts_and_anomalies_present(self):
        self.assertGreaterEqual(len(self.db.recent_anomalies()), 1)
        self.assertGreaterEqual(len(self.db.recent_alerts()), 1)

    def test_health_metrics_recorded_per_resolver(self):
        rows = self.db.metric_history("isp-demo")
        self.assertGreaterEqual(len(rows), 1)
        self.assertIn(rows[0]["freshness_status"], ("OK", "DEGRADED", "UNKNOWN"))
        self.assertIsNotNone(rows[0]["availability_pct"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
