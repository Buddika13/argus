"""PDF WRITER — a small document builder with no third-party dependency.

Argus deliberately runs on two libraries (dnspython, PyYAML) and local files
only, so a report generator that needed reportlab or a headless browser would
be the heaviest thing in the project. A monitoring report is headings, tables,
key/value rows and a couple of bar charts, and PDF renders all of that with the
base-14 fonts every reader already has -- no font embedding, no external tools.
So the writer lives here, in the standard library.

What it supports, and nothing more:

    A4 portrait, Helvetica and Helvetica-Bold, WinAnsi text
    headings, paragraphs, key/value blocks, stat tiles
    tables with a header row, column alignment and automatic page breaks
    vertical bar charts and stacked proportion bars
    a running header and a numbered footer on every page

Usage:

    doc = PdfDocument("DNS Monitoring Report", "Argus", ["Period: ..."])
    doc.heading("1. Executive summary")
    doc.tiles([("Total checks", "12,450", "ok")])
    doc.table(["Resolver", "Status"], rows)
    data = doc.render()          # -> bytes

Text is measured with the published Adobe metrics for the two fonts, so
wrapping, right-alignment and column fitting are exact rather than guessed.
"""

from __future__ import annotations

import time
import zlib

# A4 portrait, in PostScript points (1/72 inch).
PAGE_W, PAGE_H = 595.28, 841.89
MARGIN_X, MARGIN_TOP, MARGIN_BOTTOM = 46.0, 54.0, 46.0
CONTENT_W = PAGE_W - 2 * MARGIN_X

# Palette, matching the dashboard so a printed report and the screen agree.
INK = (0.086, 0.125, 0.169)
MUTED = (0.373, 0.420, 0.478)
RULE = (0.867, 0.890, 0.918)
BAND = (0.957, 0.965, 0.973)
ACCENT = (0.122, 0.361, 0.588)
OK = (0.067, 0.420, 0.227)
WARN = (0.541, 0.353, 0.020)
BAD = (0.690, 0.153, 0.122)
WHITE = (1.0, 1.0, 1.0)

TONES = {"ok": OK, "warn": WARN, "bad": BAD, "info": ACCENT, "muted": MUTED,
         "ink": INK}

# Adobe base-14 character widths, in 1/1000 em, for codes 32-126. Everything
# outside that range falls back to the average width, which is close enough for
# the occasional accented character in a domain name.
_W_REGULAR = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278,
    278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584,
    584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556,
    833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278,
    278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222,
    500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500,
    500, 334, 260, 334, 584)
_W_BOLD = (
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278,
    278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584,
    584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611,
    833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333,
    278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278,
    556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556,
    500, 389, 280, 389, 584)


def width_of(text: str, size: float, bold: bool = False) -> float:
    """The rendered width of a string, in points."""
    widths = _W_BOLD if bold else _W_REGULAR
    total = 0
    for ch in text:
        index = ord(ch) - 32
        total += widths[index] if 0 <= index < len(widths) else 556
    return total / 1000.0 * size


def _escape(text: str) -> str:
    """Encode for a PDF literal string in WinAnsi."""
    text = str(text).encode("cp1252", "replace").decode("cp1252")
    return (text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)"))


def wrap(text: str, size: float, max_width: float, bold: bool = False) -> list[str]:
    """Greedy word wrap to a pixel width, splitting over-long words."""
    lines, current = [], ""
    for word in str(text).split():
        candidate = (current + " " + word) if current else word
        if width_of(candidate, size, bold) <= max_width or not current:
            current = candidate
            # A single word wider than the column still has to be broken.
            while width_of(current, size, bold) > max_width and len(current) > 1:
                cut = len(current)
                while cut > 1 and width_of(current[:cut], size, bold) > max_width:
                    cut -= 1
                lines.append(current[:cut])
                current = current[cut:]
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def truncate(text: str, size: float, max_width: float, bold: bool = False) -> str:
    """Shorten to fit, with an ellipsis, for a cell that must stay on one line."""
    text = str(text)
    if width_of(text, size, bold) <= max_width:
        return text
    while text and width_of(text + "...", size, bold) > max_width:
        text = text[:-1]
    return text + "..."


class PdfDocument:
    """A flowing single-column document. Content is appended top to bottom."""

    def __init__(self, title: str, subtitle: str = "", meta: list | None = None,
                 footer: str = "") -> None:
        self.title = title
        self.subtitle = subtitle
        self.meta = meta or []
        self.footer = footer
        self._pages: list[list[str]] = []
        self._ops: list[str] = []
        self.y = 0.0
        self._start_page(first=True)

    # -- low-level drawing ------------------------------------------------

    def _op(self, op: str) -> None:
        self._ops.append(op)

    def _fill(self, colour) -> None:
        self._op("%.3f %.3f %.3f rg" % colour)

    def _stroke(self, colour) -> None:
        self._op("%.3f %.3f %.3f RG" % colour)

    def _text(self, x: float, y: float, text: str, size: float = 9.5,
              bold: bool = False, colour=INK) -> None:
        """Draw one line. `y` is measured downward from the top of the page."""
        self._fill(colour)
        self._op("BT /%s %.2f Tf 1 0 0 1 %.2f %.2f Tm (%s) Tj ET"
                 % ("F2" if bold else "F1", size, x, PAGE_H - y, _escape(text)))

    def _text_right(self, right: float, y: float, text: str, size: float = 9.5,
                    bold: bool = False, colour=INK) -> None:
        self._text(right - width_of(str(text), size, bold), y, text, size, bold, colour)

    def _rect(self, x: float, y: float, w: float, h: float, colour,
              stroke: bool = False, line_width: float = 0.6) -> None:
        if stroke:
            self._stroke(colour)
            self._op("%.2f w" % line_width)
            self._op("%.2f %.2f %.2f %.2f re S" % (x, PAGE_H - y - h, w, h))
        else:
            self._fill(colour)
            self._op("%.2f %.2f %.2f %.2f re f" % (x, PAGE_H - y - h, w, h))

    def _line(self, x1: float, y1: float, x2: float, y2: float, colour=RULE,
              line_width: float = 0.6) -> None:
        self._stroke(colour)
        self._op("%.2f w" % line_width)
        self._op("%.2f %.2f m %.2f %.2f l S"
                 % (x1, PAGE_H - y1, x2, PAGE_H - y2))

    # -- page management --------------------------------------------------

    def _start_page(self, first: bool = False) -> None:
        self._ops = []
        self.y = MARGIN_TOP
        if first:
            self._cover_header()
        else:
            self._running_header()

    def _cover_header(self) -> None:
        self._text(MARGIN_X, self.y + 13, self.title, 19, True, INK)
        self.y += 22
        if self.subtitle:
            self._text(MARGIN_X, self.y + 10, self.subtitle, 10, False, MUTED)
            self.y += 16
        self.y += 6
        for line in self.meta:
            self._text(MARGIN_X, self.y + 8, line, 8.5, False, MUTED)
            self.y += 12
        self.y += 6
        self._line(MARGIN_X, self.y, PAGE_W - MARGIN_X, self.y, ACCENT, 1.4)
        self.y += 20

    def _running_header(self) -> None:
        self._text(MARGIN_X, self.y + 8, self.title, 8.5, True, MUTED)
        self._text_right(PAGE_W - MARGIN_X, self.y + 8, self.subtitle, 8.5,
                         False, MUTED)
        self.y += 12
        self._line(MARGIN_X, self.y, PAGE_W - MARGIN_X, self.y, RULE)
        self.y += 18

    def page_break(self) -> None:
        self._pages.append(self._ops)
        self._start_page()

    def ensure(self, needed: float) -> None:
        """Start a new page unless `needed` points still fit on this one."""
        if self.y + needed > PAGE_H - MARGIN_BOTTOM:
            self.page_break()

    # -- content blocks ---------------------------------------------------

    def space(self, amount: float = 10.0) -> None:
        self.y += amount

    def heading(self, text: str, size: float = 12.0) -> None:
        self.ensure(size + 22)
        self.y += 8
        self._text(MARGIN_X, self.y + size, text, size, True, INK)
        self.y += size + 7

    def subheading(self, text: str) -> None:
        self.ensure(24)
        self.y += 4
        self._text(MARGIN_X, self.y + 9, text.upper(), 7.5, True, MUTED)
        self.y += 15

    def paragraph(self, text: str, size: float = 9.0, colour=MUTED,
                  leading: float = 12.5) -> None:
        for line in wrap(text, size, CONTENT_W):
            self.ensure(leading)
            self._text(MARGIN_X, self.y + size, line, size, False, colour)
            self.y += leading
        self.y += 3

    def kv(self, pairs, label_width: float = 130.0) -> None:
        """A block of label / value rows."""
        for label, value in pairs:
            self.ensure(15)
            self._text(MARGIN_X, self.y + 9, str(label), 8.5, False, MUTED)
            for i, line in enumerate(wrap(str(value), 9.0,
                                          CONTENT_W - label_width)):
                if i:
                    self.ensure(12)
                self._text(MARGIN_X + label_width, self.y + 9, line, 9.0, False, INK)
                self.y += 12.5
            self.y += 1.5
        self.y += 4

    def tiles(self, items) -> None:
        """A row of headline figures: (label, value, tone)."""
        if not items:
            return
        self.ensure(58)
        gap = 9.0
        w = (CONTENT_W - gap * (len(items) - 1)) / len(items)
        top = self.y
        for i, (label, value, tone) in enumerate(items):
            x = MARGIN_X + i * (w + gap)
            colour = TONES.get(tone, INK)
            self._rect(x, top, w, 48, BAND)
            self._rect(x, top, 2.4, 48, colour)
            self._text(x + 11, top + 24, str(value), 16, True, colour)
            self._text(x + 11, top + 39, truncate(str(label), 7.5, w - 20),
                       7.5, False, MUTED)
        self.y = top + 48 + 12

    def table(self, headers, rows, widths=None, aligns=None, size: float = 8.3,
              row_height: float = 15.0) -> None:
        """A table with a header row, zebra banding and page-break repetition.

        `widths` are relative and normalised to the content width; `aligns` is
        one of "l" or "r" per column. Cells are truncated to their column rather
        than wrapped, so every row is one line and the grid stays readable.
        """
        if not rows:
            self.ensure(row_height + 10)
            self._text(MARGIN_X, self.y + 9, "No data for this period.", 8.5,
                       False, MUTED)
            self.y += row_height + 6
            return

        count = len(headers)
        widths = widths or [1.0] * count
        total = float(sum(widths)) or 1.0
        cols = [w / total * CONTENT_W for w in widths]
        aligns = aligns or ["l"] * count

        def header_row() -> None:
            self._rect(MARGIN_X, self.y, CONTENT_W, row_height, BAND)
            x = MARGIN_X
            for i, head in enumerate(headers):
                label = truncate(str(head).upper(), 7.0, cols[i] - 12, True)
                if aligns[i] == "r":
                    self._text_right(x + cols[i] - 6, self.y + 10.5, label,
                                     7.0, True, MUTED)
                else:
                    self._text(x + 6, self.y + 10.5, label, 7.0, True, MUTED)
                x += cols[i]
            self.y += row_height

        self.ensure(row_height * 3)
        header_row()

        for index, row in enumerate(rows):
            if self.y + row_height > PAGE_H - MARGIN_BOTTOM:
                self.page_break()
                header_row()
            if index % 2:
                self._rect(MARGIN_X, self.y, CONTENT_W, row_height, BAND)
            x = MARGIN_X
            for i in range(count):
                cell = row[i] if i < len(row) else ""
                colour = INK
                if isinstance(cell, tuple):          # (text, tone)
                    cell, tone = cell
                    colour = TONES.get(tone, INK)
                cell = truncate(str(cell), size, cols[i] - 12)
                if aligns[i] == "r":
                    self._text_right(x + cols[i] - 6, self.y + 10.3, cell,
                                     size, False, colour)
                else:
                    self._text(x + 6, self.y + 10.3, cell, size, False, colour)
                x += cols[i]
            self._line(MARGIN_X, self.y + row_height, PAGE_W - MARGIN_X,
                       self.y + row_height, RULE, 0.4)
            self.y += row_height
        self.y += 10

    def barchart(self, items, unit: str = "%", height: float = 96.0,
                 maximum: float | None = None) -> None:
        """Vertical bars: (label, value, tone). One scale, every bar labelled."""
        items = [(str(l), v, t) for l, v, t in items
                 if isinstance(v, (int, float))]
        if not items:
            self.paragraph("Not enough data to chart.", 8.5)
            return
        self.ensure(height + 46)
        top = self.y
        top_value = maximum if maximum else max(v for _l, v, _t in items) or 1.0
        gap = 12.0
        bar_w = min(46.0, (CONTENT_W - gap * (len(items) + 1)) / len(items))
        base = top + height

        self._line(MARGIN_X, base, PAGE_W - MARGIN_X, base, RULE, 0.7)
        for i in range(1, 4):                        # light gridlines
            gy = base - height * i / 4
            self._line(MARGIN_X, gy, PAGE_W - MARGIN_X, gy, RULE, 0.3)

        x = MARGIN_X + gap
        for label, value, tone in items:
            h = max(1.5, min(1.0, value / top_value) * (height - 14))
            self._rect(x, base - h, bar_w, h, TONES.get(tone, ACCENT))
            self._text(x + (bar_w - width_of("%g%s" % (round(value, 1), unit),
                                             7.5, True)) / 2,
                       base - h - 4, "%g%s" % (round(value, 1), unit), 7.5,
                       True, TONES.get(tone, ACCENT))
            caption = truncate(label, 7.5, bar_w + gap - 4)
            self._text(x + (bar_w - width_of(caption, 7.5)) / 2, base + 11,
                       caption, 7.5, False, MUTED)
            x += bar_w + gap
        self.y = base + 24

    def stacked_bar(self, segments, total_label: str = "") -> None:
        """One proportion bar with a legend: (label, value, tone)."""
        segments = [(str(l), float(v), t) for l, v, t in segments if v]
        if not segments:
            self.paragraph("Nothing recorded for this period.", 8.5)
            return
        self.ensure(64)
        total = sum(v for _l, v, _t in segments) or 1.0
        top = self.y
        x = MARGIN_X
        for _label, value, tone in segments:
            w = value / total * CONTENT_W
            self._rect(x, top, w, 15, TONES.get(tone, ACCENT))
            x += w
        self.y = top + 24

        x = MARGIN_X
        for label, value, tone in segments:
            entry = "%s  %s (%.1f%%)" % (label, "{:,}".format(int(value)),
                                         value / total * 100)
            w = width_of(entry, 8.0) + 22
            if x + w > PAGE_W - MARGIN_X:
                x = MARGIN_X
                self.y += 13
                self.ensure(13)
            self._rect(x, self.y + 2, 7, 7, TONES.get(tone, ACCENT))
            self._text(x + 11, self.y + 8.5, entry, 8.0, False, MUTED)
            x += w
        self.y += 18
        if total_label:
            self._text(MARGIN_X, self.y + 8, total_label, 8.0, True, INK)
            self.y += 14

    # -- serialisation ----------------------------------------------------

    def render(self) -> bytes:
        """Finish the document and return the complete PDF file."""
        self._pages.append(self._ops)
        pages = self._pages
        total = len(pages)

        streams = []
        for number, ops in enumerate(pages, start=1):
            footer = list(ops)
            fy = PAGE_H - MARGIN_BOTTOM + 16
            footer.append("%.3f %.3f %.3f RG 0.40 w" % RULE)
            footer.append("%.2f %.2f m %.2f %.2f l S"
                          % (MARGIN_X, PAGE_H - fy + 10, PAGE_W - MARGIN_X,
                             PAGE_H - fy + 10))
            footer.append("%.3f %.3f %.3f rg" % MUTED)
            footer.append("BT /F1 7.50 Tf 1 0 0 1 %.2f %.2f Tm (%s) Tj ET"
                          % (MARGIN_X, PAGE_H - fy, _escape(self.footer)))
            mark = "Page %d of %d" % (number, total)
            footer.append("BT /F1 7.50 Tf 1 0 0 1 %.2f %.2f Tm (%s) Tj ET"
                          % (PAGE_W - MARGIN_X - width_of(mark, 7.5),
                             PAGE_H - fy, _escape(mark)))
            # WinAnsi, matching the font encoding: _escape has already reduced
            # the text to characters cp1252 can carry.
            streams.append(zlib.compress(
                "\n".join(footer).encode("cp1252", "replace")))

        objects: list[bytes] = []

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)                       # 1-based object number

        # 1 catalog, 2 pages, then per page: page object + content stream.
        catalog_id = add(b"")                          # placeholder, filled below
        pages_id = add(b"")
        font_regular = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                           b"/Encoding /WinAnsiEncoding >>")
        font_bold = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                        b"/Encoding /WinAnsiEncoding >>")

        page_ids = []
        for stream in streams:
            content_id = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n"
                             % len(stream) + stream + b"\nendstream")
            page_id = add(
                b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.2f %.2f] "
                b"/Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> "
                b"/Contents %d 0 R >>"
                % (pages_id, PAGE_W, PAGE_H, font_regular, font_bold, content_id))
            page_ids.append(page_id)

        objects[catalog_id - 1] = (b"<< /Type /Catalog /Pages %d 0 R >>" % pages_id)
        kids = b" ".join(b"%d 0 R" % pid for pid in page_ids)
        objects[pages_id - 1] = (b"<< /Type /Pages /Kids [%s] /Count %d >>"
                                 % (kids, len(page_ids)))

        info_id = add(b"<< /Title (%s) /Producer (Argus) /CreationDate (D:%s) >>"
                      % (_escape(self.title).encode("cp1252", "replace"),
                         time.strftime("%Y%m%d%H%M%S").encode("ascii")))

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for number, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % number + body + b"\nendobj\n"

        xref_at = len(out)
        out += b"xref\n0 %d\n" % (len(objects) + 1)
        out += b"0000000000 65535 f \n"
        for offset in offsets[1:]:
            out += b"%010d 00000 n \n" % offset
        out += (b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n"
                b"%%%%EOF\n" % (len(objects) + 1, catalog_id, info_id, xref_at))
        return bytes(out)
