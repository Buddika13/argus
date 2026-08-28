"""End-to-end flow test: backend -> database -> dashboard.

Proves the dashboard shows REAL data produced by the scheduler (not sample or
static data), that an empty database shows "No data available", that
auto-refresh is present, and that the live HTTP server serves the rendered page.

    python -m unittest tests.test_flow -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus import dashboard
from argus.config import Settings
from argus.models import AuthoritativeAnswer, DirectAnswer, MonitoredResolver
from argus.scheduler import Scheduler
from argus.storage import Storage

AUTH = {"good.test": {"1.1.1.1"}, "bank.test": {"203.0.113.10"}}


class FakeVerifier:
    def resolve(self, domain, rtype="A"):
        return AuthoritativeAnswer(domain=domain, rtype=rtype,
                                   records=frozenset(AUTH.get(domain, set())),
                                   ttl=300, rcode="NOERROR")


class FakeProbe:
    def query(self, resolver, domain, rtype="A"):
        records = AUTH.get(domain, set())
        if resolver.name == "evil" and domain == "bank.test":
            records = {"6.6.6.6"}                      # real injected answer
        return DirectAnswer(resolver=resolver.name, domain=domain, rtype=rtype,
                            resolver_ip=resolver.address, records=frozenset(records),
                            min_ttl=300, rcode="NOERROR", latency_ms=7.0)


def _settings(resolvers):
    raw = {"vantage": "flow", "schedule": {"interval_seconds": 1, "per_resolver_delay": 0.0},
           "query": {"timeout_seconds": 1.0, "retries": 0, "rtypes": ["A"]},
           "verification": {"requery": True, "rewalk": True, "control_crosscheck": True, "persistence": 2},
           "freshness": {"max_ttl_ratio": 1.05}, "dnssec": {"enabled": False},
           "storage": {"path": ":memory:"},
           "dashboard": {"path": "x.html"}, "logging": {"level": "CRITICAL"}}
    return Settings(raw=raw, resolvers=resolvers, watchlist=["good.test", "bank.test"])


def _run_real_sweep(storage):
    resolvers = [MonitoredResolver("google", "8.8.8.8", role="control"),
                 MonitoredResolver("evil", "203.0.113.9", role="isp", isp="TestISP")]
    Scheduler(_settings(resolvers), storage, probe=FakeProbe(), verifier=FakeVerifier()).run_once()


class FlowTests(unittest.TestCase):
    def test_dashboard_shows_real_scheduler_data(self):
        db = Storage(":memory:")
        _run_real_sweep(db)
        page = dashboard.render(db, vantage="flow")
        db.close()
        # data that only the real sweep (not sample data) would produce
        self.assertIn("evil", page)
        self.assertIn("google", page)
        self.assertIn("bank.test", page)
        self.assertIn("POSSIBLE_CACHE_POISONING", page)
        self.assertNotIn("isp-demo", page)             # sample-data marker absent

    def test_empty_database_shows_no_data(self):
        db = Storage(":memory:")
        page = dashboard.render(db)
        db.close()
        self.assertIn("No monitoring data available yet", page)

    def test_auto_refresh_meta_tag_present(self):
        db = Storage(":memory:")
        page = dashboard.render(db, refresh_seconds=15)
        db.close()
        self.assertIn('http-equiv="refresh"', page)
        self.assertIn('content="15"', page)

    def test_live_server_serves_real_data(self):
        tmp = Path(tempfile.mkdtemp()) / "flow.sqlite3"
        db = Storage(tmp)
        _run_real_sweep(db)
        db.close()

        httpd = dashboard.build_server(tmp, vantage="flow", port=0, refresh=10)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read().decode("utf-8")
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertIn("evil", body)
        self.assertIn("POSSIBLE_CACHE_POISONING", body)
        self.assertIn('http-equiv="refresh"', body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
