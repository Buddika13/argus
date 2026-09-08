"""XLSX WRITER — real Excel workbooks, with no third-party dependency.

The Reports page offers PDF, CSV and Excel. CSV opens in Excel, but it is not
an Excel file: it carries no column widths, no header styling, no number
formatting and no sheets, and a reader who asked for Excel and received a CSV
has been given something else under the right label.

An .xlsx is a ZIP of XML parts, all of which the standard library can produce,
so the format is implemented properly here rather than faked -- the same
reasoning that put the PDF writer in `argus.pdfdoc` instead of pulling in
reportlab.

What it writes, and nothing more:

    one sheet per report section, named and ordered
    inline strings and real numbers (numbers stay numeric, so Excel can sum)
    a bold, frozen, filtered header row
    per-column widths measured from the content

Usage:

    book = Workbook()
    sheet = book.sheet("Executive summary")
    sheet.row(["Measure", "Value"], header=True)
    sheet.row(["Total checks", 1782])
    data = book.render()          # -> bytes
"""

from __future__ import annotations

import re
import zipfile
from datetime import datetime
from io import BytesIO

# Excel forbids these in a sheet name, and caps the length at 31 characters.
_BAD_SHEET = re.compile(r"[\[\]:*?/\\]")
# XML 1.0 permits almost no control characters; strip the rest rather than
# emitting a workbook Excel will refuse to open.
_BAD_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _esc(text: str) -> str:
    text = _BAD_XML.sub("", str(text))
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _column_name(index: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA."""
    name = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


class Sheet:
    """One worksheet. Rows are appended in order."""

    def __init__(self, title: str) -> None:
        self.title = title
        self._rows: list[tuple[list, bool]] = []
        self._widths: dict[int, int] = {}

    def row(self, values, header: bool = False) -> None:
        cells = list(values)
        for i, value in enumerate(cells):
            length = len(str("" if value is None else value))
            self._widths[i] = min(60, max(self._widths.get(i, 9), length + 2))
        self._rows.append((cells, header))

    def blank(self) -> None:
        self.row([])

    @property
    def _header_index(self):
        for i, (_cells, header) in enumerate(self._rows):
            if header:
                return i
        return None

    def _xml(self) -> str:
        columns = ""
        if self._widths:
            columns = "<cols>" + "".join(
                '<col min="%d" max="%d" width="%d" customWidth="1"/>'
                % (i + 1, i + 1, width)
                for i, width in sorted(self._widths.items())) + "</cols>"

        rows = ""
        for r, (cells, header) in enumerate(self._rows, start=1):
            body = ""
            for c, value in enumerate(cells):
                ref = "%s%d" % (_column_name(c), r)
                style = ' s="1"' if header else ""
                if isinstance(value, bool) or value is None or value == "":
                    if value in (None, ""):
                        body += '<c r="%s"%s/>' % (ref, style)
                        continue
                    value = str(value)
                if isinstance(value, (int, float)):
                    # Kept numeric so Excel can total and chart the column.
                    body += '<c r="%s"%s><v>%s</v></c>' % (ref, style, value)
                else:
                    body += ('<c r="%s"%s t="inlineStr"><is><t xml:space='
                             '"preserve">%s</t></is></c>'
                             % (ref, style, _esc(value)))
            rows += '<row r="%d">%s</row>' % (r, body)

        extras = ""
        index = self._header_index
        if index is not None:
            # Freeze everything above the header and let the reader filter it.
            extras = ('<sheetViews><sheetView workbookViewId="0">'
                      '<pane ySplit="%d" topLeftCell="A%d" activePane="bottomLeft"'
                      ' state="frozen"/></sheetView></sheetViews>'
                      % (index + 1, index + 2))
        auto = ""
        if index is not None and self._rows[index][0]:
            last = "%s%d" % (_column_name(len(self._rows[index][0]) - 1),
                             len(self._rows))
            auto = '<autoFilter ref="A%d:%s"/>' % (index + 1, last)

        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<worksheet xmlns="http://schemas.openxmlformats.org/'
                'spreadsheetml/2006/main">' + extras + columns
                + "<sheetData>" + rows + "</sheetData>" + auto + "</worksheet>")


class Workbook:
    """A set of sheets, serialised to a real .xlsx container."""

    def __init__(self, title: str = "Argus report") -> None:
        self.title = title
        self._sheets: list[Sheet] = []
        self._names: set[str] = set()

    def sheet(self, title: str) -> Sheet:
        """Add a sheet, with a name Excel will accept and that is unique."""
        name = _BAD_SHEET.sub(" ", str(title)).strip()[:31] or "Sheet"
        base, suffix = name, 2
        while name.lower() in self._names:
            tail = " (%d)" % suffix
            name = base[:31 - len(tail)] + tail
            suffix += 1
        self._names.add(name.lower())
        created = Sheet(name)
        self._sheets.append(created)
        return created

    def render(self) -> bytes:
        if not self._sheets:
            self.sheet("Report").row(["No data available."])

        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
            'content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxml'
            'formats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/'
            'vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.'
            'openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/'
            'vnd.openxmlformats-package.core-properties+xml"/>'
            + "".join('<Override PartName="/xl/worksheets/sheet%d.xml" '
                      'ContentType="application/vnd.openxmlformats-officedocument'
                      '.spreadsheetml.worksheet+xml"/>' % (i + 1)
                      for i in range(len(self._sheets)))
            + "</Types>")

        root_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
            '2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
            'officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/'
            'package/2006/relationships/metadata/core-properties" '
            'Target="docProps/core.xml"/>'
            "</Relationships>")

        sheets_xml = "".join(
            '<sheet name="%s" sheetId="%d" r:id="rId%d"/>'
            % (_esc(s.title), i + 1, i + 1) for i, s in enumerate(self._sheets))
        workbook = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/'
            '2006/main" xmlns:r="http://schemas.openxmlformats.org/office'
            'Document/2006/relationships"><sheets>' + sheets_xml
            + "</sheets></workbook>")

        workbook_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
            '2006/relationships">'
            + "".join('<Relationship Id="rId%d" Type="http://schemas.openxml'
                      'formats.org/officeDocument/2006/relationships/worksheet"'
                      ' Target="worksheets/sheet%d.xml"/>' % (i + 1, i + 1)
                      for i in range(len(self._sheets)))
            + '<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org'
              '/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
              % (len(self._sheets) + 1)
            + "</Relationships>")

        # Two fonts and two cell formats: plain, and bold for the header row.
        styles = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml'
            '/2006/main">'
            '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
            '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
            '<fills count="2"><fill><patternFill patternType="none"/></fill>'
            '<fill><patternFill patternType="gray125"/></fill></fills>'
            '<borders count="1"><border/></borders>'
            '<cellStyleXfs count="1"><xf/></cellStyleXfs>'
            '<cellXfs count="2"><xf xfId="0"/>'
            '<xf xfId="0" fontId="1" applyFont="1"/></cellXfs>'
            "</styleSheet>")

        core = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/'
            'package/2006/metadata/core-properties" xmlns:dc="http://purl.org/'
            'dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            "<dc:title>%s</dc:title><dc:creator>Argus</dc:creator>"
            '<dcterms:created xsi:type="dcterms:W3CDTF">%sZ</dcterms:created>'
            "</cp:coreProperties>"
            % (_esc(self.title), datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")))

        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", content_types)
            archive.writestr("_rels/.rels", root_rels)
            archive.writestr("docProps/core.xml", core)
            archive.writestr("xl/workbook.xml", workbook)
            archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
            archive.writestr("xl/styles.xml", styles)
            for i, sheet in enumerate(self._sheets):
                archive.writestr("xl/worksheets/sheet%d.xml" % (i + 1),
                                 sheet._xml())
        return buffer.getvalue()
