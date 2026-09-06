"""Unit tests for the report generator (argus.reporting, argus.pdfdoc).

Offline: builds an in-memory database with sample data, renders every report
type in every format, and checks the bytes that come out. No network.

The PDF assertions parse the file rather than trusting its size: a PDF with a
broken cross-reference table opens as an empty document in some readers and not
at all in others, so the structure is verified here.

    python -m unittest tests.test_reporting -v
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus import pdfdoc, reporting, sampledata
from argus.storage import Storage

ALL_KINDS = [key for key, _t, _d in reporting.REPORT_TYPES]


def _parse_pdf(data: bytes) -> dict:
    """Read back the trailer and cross-reference table of a rendered PDF."""
    start = re.search(rb"startxref\s+(\d+)", data)
    assert start, "no startxref"
    offset = int(start.group(1))
    header = re.match(rb"xref\s+0 (\d+)\s+", data[offset:])
    assert header, "no xref table"
    count = int(header.group(1))
    body = data[offset + header.end():]
    entries = re.findall(rb"(\d{10}) (\d{5}) (n|f)", body[:count * 20])
    pages = re.search(rb"/Type /Pages /Kids \[(.*?)\] /Count (\d+)", data)
    return {"count": count, "entries": entries,
            "pages": int(pages.group(2)) if pages else 0}


class PdfWriterTests(unittest.TestCase):
    def _doc(self) -> bytes:
        doc = pdfdoc.PdfDocument("Test report", "Argus", ["Period: x"], "footer")
        doc.heading("1. Section")
        doc.tiles([("Checks", "10", "ok"), ("Alerts", "2", "bad")])
        doc.barchart([("a", 90.0, "ok"), ("b", 40.0, "warn")])
        doc.stacked_bar([("Match", 90, "ok"), ("Mismatch", 10, "bad")])
        doc.table(["One", "Two"], [["x", ("y", "bad")]] * 60, [1, 2], ["l", "r"])
        doc.paragraph("Some prose that is long enough to wrap across more than "
                      "a single line of the content column, several times over, "
                      "so the wrapping path is exercised properly here.")
        return doc.render()

    def test_output_is_a_pdf(self):
        data = self._doc()
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertTrue(data.rstrip().endswith(b"%%EOF"))

    def test_cross_reference_offsets_are_correct(self):
        # A wrong offset here is the difference between a file that opens and
        # one that a reader rejects, and it is invisible in the byte count.
        data = self._doc()
        parsed = _parse_pdf(data)
        self.assertEqual(len(parsed["entries"]), parsed["count"])
        for index, (offset, _gen, kind) in enumerate(parsed["entries"]):
            if kind == b"f":
                continue
            at = int(offset)
            self.assertEqual(data[at:at + len(b"%d 0 obj" % index)],
                             b"%d 0 obj" % index, "object %d" % index)

    def test_long_tables_break_across_pages(self):
        self.assertGreater(_parse_pdf(self._doc())["pages"], 1)

    def test_text_measurement_matches_alignment(self):
        # Right-aligned cells depend on this being the real width, not a guess.
        self.assertAlmostEqual(pdfdoc.width_of("ii", 10), 4.44, places=2)
        self.assertGreater(pdfdoc.width_of("WW", 10), pdfdoc.width_of("ii", 10))
        self.assertGreater(pdfdoc.width_of("Argus", 10, bold=True),
                           pdfdoc.width_of("Argus", 10))

    def test_wrapping_respects_the_column(self):
        lines = pdfdoc.wrap("word " * 40, 9.0, 120.0)
        self.assertGreater(len(lines), 1)
        for line in lines:
            self.assertLessEqual(pdfdoc.width_of(line, 9.0), 120.0)

    def test_an_unbreakable_word_is_split(self):
        lines = pdfdoc.wrap("a" * 300, 9.0, 60.0)
        self.assertGreater(len(lines), 1)
        for line in lines:
            self.assertLessEqual(pdfdoc.width_of(line, 9.0), 60.0)

    def test_parentheses_and_backslashes_are_escaped(self):
        doc = pdfdoc.PdfDocument("t")
        doc.paragraph(r"a (b) \c")
        self.assertTrue(doc.render().startswith(b"%PDF"))

    def test_characters_outside_winansi_do_not_crash(self):
        doc = pdfdoc.PdfDocument("t")
        doc.paragraph("em dash — and a CJK character 中")
        self.assertTrue(doc.render().startswith(b"%PDF"))


class ReportBuildTests(unittest.TestCase):
    def _db(self):
        db = Storage(":memory:")
        sampledata.load(db, base_time=1_000_000.0)
        return db

    def test_every_kind_renders_in_every_format(self):
        db = self._db()
        try:
            for kind in ALL_KINDS:
                report = reporting.build(db, kind, vantage="test")
                self.assertTrue(report.sections, kind)
                pdf = reporting.render(report, "pdf")
                self.assertTrue(pdf.startswith(b"%PDF"), kind)
                self.assertGreater(_parse_pdf(pdf)["pages"], 0, kind)
                csv_bytes = reporting.render(report, "csv")
                self.assertIn(b"Argus report", csv_bytes, kind)
        finally:
            db.close()

    def test_an_unknown_kind_is_refused(self):
        db = self._db()
        with self.assertRaises(ValueError):
            reporting.build(db, "not-a-report")
        db.close()

    def test_an_unknown_format_is_refused(self):
        db = self._db()
        report = reporting.build(db, "summary")
        db.close()
        with self.assertRaises(ValueError):
            reporting.render(report, "docx")

    def test_empty_database_still_produces_a_report(self):
        db = Storage(":memory:")
        try:
            for kind in ALL_KINDS:
                report = reporting.build(db, kind, vantage="test")
                self.assertTrue(reporting.render(report, "pdf").startswith(b"%PDF"))
                self.assertIn(b"Argus report", reporting.render(report, "csv"))
        finally:
            db.close()

    def test_options_select_sections(self):
        db = self._db()
        try:
            full = reporting.build(db, "summary", options=["charts", "limits"])
            bare = reporting.build(db, "summary", options=[])
            kinds_full = [s.kind for s in full.sections]
            kinds_bare = [s.kind for s in bare.sections]
            self.assertIn("bars", kinds_full)
            self.assertNotIn("bars", kinds_bare)
            self.assertIn("Limitations", [s.heading for s in full.sections])
            self.assertNotIn("Limitations", [s.heading for s in bare.sections])
        finally:
            db.close()

    def test_a_period_narrows_the_report(self):
        db = self._db()
        try:
            everything = reporting.build(db, "domains")
            nothing = reporting.build(db, "domains", since=2_000_000.0,
                                      until=2_000_100.0)
            rows_all = [s for s in everything.sections if s.kind == "table"][0]
            rows_none = [s for s in nothing.sections if s.kind == "table"][0]
            self.assertGreater(len(rows_all.payload["rows"]), 0)
            self.assertEqual(len(rows_none.payload["rows"]), 0)
        finally:
            db.close()

    def test_csv_carries_the_table_rows(self):
        db = self._db()
        try:
            report = reporting.build(db, "health", vantage="test")
            text = reporting.render(report, "csv").decode("utf-8-sig")
            self.assertIn("Health metrics", text)
            self.assertIn("isp-demo", text)
        finally:
            db.close()


class DateParsingTests(unittest.TestCase):
    def test_a_date_parses(self):
        self.assertGreater(reporting.parse_day("2026-09-01"), 0)

    def test_an_end_date_covers_the_whole_day(self):
        start = reporting.parse_day("2026-09-01")
        end = reporting.parse_day("2026-09-01", end_of_day=True)
        self.assertEqual(int(end - start), 86399)

    def test_rubbish_is_ignored_rather_than_raising(self):
        # The value arrives from a URL, so it must never be able to 500 a page.
        for value in ("", "not-a-date", "2026-13-45", "'; DROP TABLE"):
            self.assertEqual(reporting.parse_day(value), 0.0)


class SavedReportTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_saving_then_listing_finds_the_file(self):
        db = Storage(":memory:")
        sampledata.load(db, base_time=1_000_000.0)
        report = reporting.build(db, "summary", vantage="test")
        db.close()
        written = reporting.save(report, "pdf", self.dir)
        self.assertTrue(written.exists())
        listed = reporting.saved_reports(self.dir)
        self.assertEqual([x["name"] for x in listed], [written.name])
        self.assertEqual(listed[0]["format"], "PDF")

    def test_a_traversal_name_is_refused(self):
        # The name arrives straight from a query string.
        for name in ("../../etc/passwd", "..\\config\\config.yaml", "",
                     "argus-summary-20260101-000000.pdf/../x", "anything.pdf",
                     "argus-summary-20260101-000000.exe"):
            self.assertIsNone(reporting.saved_path(name, self.dir), name)

    def test_a_generated_name_resolves(self):
        db = Storage(":memory:")
        report = reporting.build(db, "summary", vantage="test")
        db.close()
        written = reporting.save(report, "csv", self.dir)
        self.assertEqual(reporting.saved_path(written.name, self.dir), written)

    def test_a_name_that_matches_but_is_absent_resolves_to_nothing(self):
        self.assertIsNone(
            reporting.saved_path("argus-summary-20200101-000000.pdf", self.dir))


if __name__ == "__main__":
    unittest.main(verbosity=2)
