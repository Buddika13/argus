"""Tests for alert delivery (argus.alerting).

Offline: a temporary directory for the log file, and an unroutable address for
the webhook so no real request is ever made.

The property that matters most is that delivery can never break monitoring: a
sweep must survive a full disk, a read-only path or a dead webhook.

    python -m unittest tests.test_alerting -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.alerting import AlertSink

EVIDENCE = {
    "stage1": {"classification": "POSSIBLE_CACHE_POISONING",
               "unpublished": ["203.0.113.66"]},
    "stage2_authoritative": {"records": ["104.16.132.229", "104.16.133.229"]},
    "stage3_controls": {"queried": ["google", "cloudflare", "quad9", "opendns"],
                        "corroborates_unexpected": False},
    "stage5_persistence": {"repetitions": 2, "reproduced": 2, "persistent": True},
    "decision": "no authoritative source or independent resolver corroborates it",
}


class FakeAlert:
    """The fields AlertSink reads from a stored Alert."""

    confirmed_at = 1_700_000_000.0
    status = "POSSIBLE_CACHE_POISONING"
    resolver = "lab-poisoned"
    domain = "cloudflare.com"
    rtype = "A"


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.summary = AlertSink.summarise(FakeAlert(), EVIDENCE)

    def test_carries_the_decisive_fields(self):
        self.assertEqual(self.summary["resolver"], "lab-poisoned")
        self.assertEqual(self.summary["domain"], "cloudflare.com")
        self.assertEqual(self.summary["unpublished"], ["203.0.113.66"])
        self.assertEqual(self.summary["authoritative"],
                         ["104.16.132.229", "104.16.133.229"])
        self.assertEqual(self.summary["reproduced"], 2)

    def test_missing_evidence_does_not_raise(self):
        summary = AlertSink.summarise(FakeAlert(), {})
        self.assertEqual(summary["unpublished"], [])
        self.assertEqual(summary["reason"], "")

    def test_line_names_what_was_returned_and_published(self):
        line = AlertSink.format_line(self.summary)
        self.assertIn("POSSIBLE_CACHE_POISONING", line)
        self.assertIn("resolver=lab-poisoned", line)
        self.assertIn("domain=cloudflare.com/A", line)
        self.assertIn("returned=203.0.113.66", line)
        self.assertIn("104.16.132.229", line)
        self.assertIn("trusted_disagreed=4", line)
        self.assertIn("persisted=2/2", line)

    def test_corroborated_event_reports_no_disagreement(self):
        evidence = dict(EVIDENCE)
        evidence["stage3_controls"] = {"queried": ["google", "quad9"],
                                       "corroborates_unexpected": True}
        line = AlertSink.format_line(AlertSink.summarise(FakeAlert(), evidence))
        self.assertIn("trusted_disagreed=0", line)


class LogFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = Path(self.dir) / "nested" / "alerts.log"

    def test_writes_a_line_and_creates_the_directory(self):
        sink = AlertSink(log_file=self.path)
        self.assertTrue(sink.send(FakeAlert(), EVIDENCE))
        self.assertTrue(self.path.exists())
        self.assertIn("lab-poisoned", self.path.read_text(encoding="utf-8"))

    def test_appends_rather_than_overwrites(self):
        sink = AlertSink(log_file=self.path)
        sink.send(FakeAlert(), EVIDENCE)
        sink.send(FakeAlert(), EVIDENCE)
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(sink.delivered, 2)

    def test_disabled_sink_writes_nothing(self):
        sink = AlertSink(log_file=self.path, enabled=False)
        self.assertFalse(sink.send(FakeAlert(), EVIDENCE))
        self.assertFalse(self.path.exists())

    def test_no_sink_configured_is_not_an_error(self):
        sink = AlertSink()
        self.assertFalse(sink.send(FakeAlert(), EVIDENCE))
        self.assertEqual(sink.failures, 0)

    def test_unwritable_path_is_reported_not_raised(self):
        # A path whose parent is an existing *file* cannot be created.
        blocker = Path(self.dir) / "blocker"
        blocker.write_text("x", encoding="utf-8")
        sink = AlertSink(log_file=blocker / "alerts.log")
        self.assertFalse(sink.send(FakeAlert(), EVIDENCE))
        self.assertEqual(sink.failures, 1)


class WebhookTests(unittest.TestCase):
    def test_unreachable_webhook_is_reported_not_raised(self):
        # 203.0.113.0/24 is RFC 5737 documentation space and routes nowhere.
        sink = AlertSink(webhook_url="http://203.0.113.9:9/hook")
        self.assertFalse(sink.send(FakeAlert(), EVIDENCE))
        self.assertEqual(sink.failures, 1)

    def test_malformed_url_is_reported_not_raised(self):
        sink = AlertSink(webhook_url="not-a-url")
        self.assertFalse(sink.send(FakeAlert(), EVIDENCE))
        self.assertEqual(sink.failures, 1)

    def test_a_failing_webhook_does_not_stop_the_log_file(self):
        directory = tempfile.mkdtemp()
        path = Path(directory) / "alerts.log"
        sink = AlertSink(log_file=path, webhook_url="http://203.0.113.9:9/hook")
        self.assertTrue(sink.send(FakeAlert(), EVIDENCE))   # log succeeded
        self.assertTrue(path.exists())
        self.assertEqual(sink.failures, 1)                  # webhook did not


if __name__ == "__main__":
    unittest.main(verbosity=2)
