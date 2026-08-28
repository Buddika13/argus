"""Unit tests for the dashboard generator (argus.dashboard).

Offline: builds an in-memory database with sample data, renders the page to a
temp file, and checks the content. No network.

    python -m unittest tests.test_dashboard -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus import dashboard, sampledata
from argus.storage import Storage


class DashboardTests(unittest.TestCase):
    def _render(self, storage) -> str:
        out = Path(tempfile.mkdtemp()) / "dash.html"
        result = dashboard.generate(storage, out, vantage="test-vantage")
        self.assertTrue(result.exists())
        return result.read_text(encoding="utf-8")

    def test_renders_all_sections_with_data(self):
        db = Storage(":memory:")
        sampledata.load(db, base_time=1_000_000.0)
        page = self._render(db)
        db.close()
        for section in ("Overall system status", "Monitored resolvers",
                        "Possible cache-poisoning events", "Recent anomalies",
                        "Recent DNS queries"):
            self.assertIn(section, page)

    def test_shows_resolvers_and_findings(self):
        db = Storage(":memory:")
        sampledata.load(db, base_time=1_000_000.0)
        page = self._render(db)
        db.close()
        self.assertIn("isp-demo", page)                 # a monitored resolver
        self.assertIn("google", page)
        self.assertIn("POSSIBLE_CACHE_POISONING", page)  # a finding from sample data
        self.assertIn("test-vantage", page)

    def test_empty_database_does_not_crash(self):
        db = Storage(":memory:")
        page = self._render(db)
        db.close()
        self.assertIn("No data available", page)         # graceful empty state
        self.assertIn("No monitoring data available yet", page)  # explicit banner

    def test_is_self_contained(self):
        db = Storage(":memory:")
        sampledata.load(db, base_time=1_000_000.0)
        page = self._render(db)
        db.close()
        # no external stylesheet/script references
        self.assertNotIn("http://", page.replace("http://www.w3.org", ""))
        self.assertNotIn("<script", page)


if __name__ == "__main__":
    unittest.main(verbosity=2)
