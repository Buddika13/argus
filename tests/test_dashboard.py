"""Unit tests for the dashboard package (argus.dashboard).

Offline: builds an in-memory database with sample data, renders every page, and
checks the content. No network.

The dashboard is now a set of pages rather than one long page, so these tests
assert per page: each section appears on the page that owns it, the navigation
links every page, and every page stays self-contained.

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
from argus.dashboard import verdict
from argus.dashboard.live import render_page
from argus.storage import Storage

PAGE_KEYS = ("overview", "resolvers", "poisoning", "queries", "anomalies",
             "verification", "reports")


class DashboardTests(unittest.TestCase):
    def _db(self):
        db = Storage(":memory:")
        sampledata.load(db, base_time=1_000_000.0)
        return db

    def _page(self, db, key: str) -> str:
        return render_page(db, key, "test-vantage", {}, live=False)

    def test_generate_writes_every_page(self):
        db = self._db()
        out = Path(tempfile.mkdtemp()) / "report.html"
        result = dashboard.generate(db, out, vantage="test-vantage")
        db.close()
        self.assertTrue(result.exists())
        for _key, filename, _path, _title, _blurb in dashboard.PAGES:
            self.assertTrue((out.parent / filename).exists(), filename)

    def test_each_section_is_on_its_own_page(self):
        db = self._db()
        expected = {
            "overview": ("System totals", "Resolver status summary"),
            "resolvers": ("Availability", "Correctness"),
            "poisoning": ("Cache Poisoning Detection",),
            "queries": ("DNS Query Monitor", "Classification"),
            "anomalies": ("Anomaly Investigation", "Legitimate explanations tested"),
            "verification": ("Independent Verification", "Monitored resolver"),
            "reports": ("Daily report", "Resolver health report",
                        "Cache-poisoning detection report"),
        }
        for key, fragments in expected.items():
            page = self._page(db, key)
            for fragment in fragments:
                self.assertIn(fragment, page, key + " missing " + fragment)
        db.close()

    def test_overview_does_not_carry_the_full_query_table(self):
        db = self._db()
        overview = self._page(db, "overview")
        db.close()
        # The per-measurement table belongs to the DNS Query Monitor page.
        self.assertNotIn("Returned answer", overview)

    def test_navigation_links_every_page(self):
        db = self._db()
        page = self._page(db, "overview")
        db.close()
        for _key, filename, _path, title, _blurb in dashboard.PAGES:
            self.assertIn(filename, page)
            self.assertIn(title, page)

    def test_shows_resolvers_and_findings(self):
        db = self._db()
        resolvers = self._page(db, "resolvers")
        poisoning = self._page(db, "poisoning")
        db.close()
        self.assertIn("isp-demo", resolvers)
        self.assertIn("google", resolvers)
        self.assertIn("test-vantage", resolvers)
        self.assertIn("POSSIBLE_CACHE_POISONING", poisoning)

    def test_empty_database_does_not_crash(self):
        db = Storage(":memory:")
        pages = {key: self._page(db, key) for key in PAGE_KEYS}
        db.close()
        self.assertIn("No monitoring data available yet", pages["overview"])
        self.assertIn("No data available", pages["resolvers"])
        for key, page in pages.items():
            self.assertIn("Argus", page, key)

    def test_pages_are_self_contained(self):
        db = self._db()
        for key in PAGE_KEYS:
            page = self._page(db, key)
            self.assertNotIn("<script", page, key)
            self.assertNotIn("http://", page.replace("http://www.w3.org", ""), key)
        db.close()

    def test_query_monitor_filters_and_pages(self):
        db = self._db()
        total = db.count_events()
        self.assertGreater(total, 0)
        # An impossible filter yields nothing, without error.
        self.assertEqual(db.count_events(resolver="no-such-resolver"), 0)
        page = render_page(db, "queries", "test-vantage",
                           {"resolver": "no-such-resolver"}, live=True)
        db.close()
        self.assertIn("No data available", page)

    def test_resolver_detail_view(self):
        db = self._db()
        page = render_page(db, "resolvers", "test-vantage",
                           {"resolver": "isp-demo"}, live=True)
        db.close()
        self.assertIn("Detail &mdash; isp-demo", page)
        self.assertIn("Recent measurements", page)


class VerdictMappingTests(unittest.TestCase):
    def test_clean_classifications_report_no_poisoning(self):
        for cls in ("NORMAL", "BENIGN_DIFFERENCE"):
            self.assertEqual(verdict.verdict_of(cls), verdict.NO_POISONING)

    def test_only_poisoning_class_reports_possible_poisoning(self):
        self.assertEqual(verdict.verdict_of("POSSIBLE_CACHE_POISONING"),
                         verdict.POSSIBLE)

    def test_weak_evidence_reports_inconclusive(self):
        for cls in ("TEMPORARY_ANOMALY", "DNS_INTEGRITY_ANOMALY",
                    "VERIFICATION_FAILED", "ANOMALY", "SOMETHING_UNKNOWN"):
            self.assertEqual(verdict.verdict_of(cls), verdict.INCONCLUSIVE, cls)

    def test_every_verdict_has_a_rationale(self):
        for cls in ("NORMAL", "BENIGN_DIFFERENCE", "TEMPORARY_ANOMALY",
                    "DNS_INTEGRITY_ANOMALY", "POSSIBLE_CACHE_POISONING",
                    "VERIFICATION_FAILED"):
            self.assertTrue(verdict.rationale_of(cls))

    def test_summarise_counts_all_three_verdicts(self):
        counts = verdict.summarise(["NORMAL", "NORMAL", "POSSIBLE_CACHE_POISONING",
                                    "TEMPORARY_ANOMALY"])
        self.assertEqual(counts[verdict.NO_POISONING], 2)
        self.assertEqual(counts[verdict.POSSIBLE], 1)
        self.assertEqual(counts[verdict.INCONCLUSIVE], 1)



class VerificationFormTests(unittest.TestCase):
    """The chooser must offer only resolvers that can actually be queried."""

    def _form(self) -> str:
        db = Storage(":memory:")
        sampledata.load(db, base_time=1_000_000.0)
        page = render_page(db, "verification", "test-vantage", {}, live=True)
        db.close()
        start = page.index("<form")
        return page[start:page.index("</form>", start)]

    def test_resolver_chooser_has_no_empty_option(self):
        # An empty value submits nothing and produced a confusing error.
        form = self._form()
        chooser = form[form.index("name='resolver'"):]
        self.assertNotIn("<option value=''>", chooser)

    def test_resolver_chooser_offers_configured_resolvers(self):
        from argus.config import load_settings
        form = self._form()
        chooser = form[form.index("name='resolver'"):]
        for resolver in load_settings().resolvers:
            self.assertIn("value='" + resolver.name + "'", chooser)

    def test_record_type_is_a_required_choice(self):
        form = self._form()
        chooser = form[form.index("name='rtype'"):]
        self.assertIn("required", chooser)
        self.assertNotIn("<option value=''>", chooser)

    def test_an_unconfigured_name_is_explained(self):
        from argus.dashboard.live import run_verification
        result = run_verification("example.com", "A", "no-such-resolver-xyz")
        self.assertIn("error", result)
        self.assertIn("no-such-resolver-xyz", result["error"])
        self.assertIn("Configured resolvers", result["error"])

    def test_an_empty_name_asks_for_a_choice(self):
        from argus.dashboard.live import run_verification
        result = run_verification("example.com", "A", "")
        self.assertIn("Choose a monitored resolver", result["error"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
