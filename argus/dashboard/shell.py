"""SHELL — page chrome, styling, and the formatting helpers pages share.

The dashboard is a set of small pages rather than one long scroll. This module
owns everything common to all of them: the navigation, the header, the
stylesheet, and the value formatters. It reads nothing from the database itself.

Every page is a single self-contained HTML file with no script and no external
asset, so it opens from the filesystem, over the built-in server, or from a
printed PDF with identical results. Charts and gauges are therefore inline SVG
drawn here, not a charting library.
"""

from __future__ import annotations

import html
import math
import time

# key, static filename, server path, title, purpose blurb
# The nine entries in the sidebar, in order.
NAV_PAGES = (
    ("overview", "report.html", "/", "Dashboard",
     "National view: what is monitored, what it found, and where it looked."),
    ("resolvers", "resolvers.html", "/resolvers", "Resolvers",
     "Availability, latency, correctness and freshness for every monitored "
     "caching resolver."),
    ("domains", "domains.html", "/domains", "Domains",
     "The watch-list: what is checked, how often it agreed, and when it was "
     "last seen."),
    ("verification", "verification.html", "/verification", "Monitoring",
     "Run one domain against a resolver and the authoritative hierarchy, live: "
     "the untrusted path beside the trusted one."),
    ("queries", "queries.html", "/queries", "Results",
     "Every measurement taken, searchable and filterable."),
    ("anomalies", "anomalies.html", "/anomalies", "Alerts",
     "Differences under review by severity, and the legitimate explanations "
     "each was tested against."),
    ("reports", "reports.html", "/reports", "Reports",
     "Generate PDF and CSV reports from stored monitoring data."),
    ("settings", "settings.html", "/settings", "Settings",
     "The configuration currently in force, and the file that sets each value."),
    ("help", "help.html", "/help", "Help",
     "What Argus measures, how the two resolution paths are compared, and how "
     "to read a verdict."),
)

# Reachable and generated, but not in the sidebar: the deep evidence view is
# opened from Alerts and from the Dashboard rather than browsed directly.
HIDDEN_PAGES = (
    ("poisoning", "poisoning.html", "/poisoning", "Cache Poisoning Detection",
     "Events where a resolver served data no independent source corroborates, "
     "with the full evidence behind each verdict."),
)

# Every page: what the router, the static export and the tests iterate.
PAGES = NAV_PAGES + HIDDEN_PAGES

PAGE_BY_KEY = {p[0]: p for p in PAGES}


def link(key: str, live: bool, query: str = "") -> str:
    """URL for a page, in server mode (paths) or static mode (filenames)."""
    page = PAGE_BY_KEY[key]
    base = page[2] if live else page[1]
    return base + query


# -- value formatting -------------------------------------------------------

def e(x) -> str:
    return html.escape(str(x))


def pct(x) -> str:
    return "%.0f%%" % x if isinstance(x, (int, float)) else "&mdash;"


def rate(x) -> str:
    return "%.0f%%" % (x * 100) if isinstance(x, (int, float)) else "&mdash;"


def ms(x) -> str:
    return "%.0f ms" % x if isinstance(x, (int, float)) else "&mdash;"


def ts(x) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(x)) if x else "&mdash;"


def records(value) -> str:
    """Render a stored record set, which may be empty or None."""
    if not value:
        return "<span class='muted'>(none)</span>"
    return "<span class='mono'>" + e(value) + "</span>"


# A filled circle carrying a glyph, drawn rather than typed: an emoji would
# render differently on every platform and would not take the row's colour.
_PILL_MARK = {
    "ok": '<path d="m4.6 8.2 2.2 2.2 4.6-5" />',
    "bad": '<path d="M5 5l6 6M11 5l-6 6" />',
    "warn": '<path d="M8 4.4v5.2" /><path d="M8 12h.01" />',
    "muted": '<path d="M4.8 8h6.4" />',
}


def status_pill(text: str, tone: str = "muted") -> str:
    """A compact status: a coloured disc with a white glyph, then the word."""
    mark = _PILL_MARK.get(tone, _PILL_MARK["muted"])
    return ('<span class="pill ' + tone + '">'
            '<svg class="pillmark" viewBox="0 0 16 16" aria-hidden="true">'
            '<circle cx="8" cy="8" r="8"/>'
            '<g fill="none" stroke="#fff" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round">' + mark + "</g>"
            "</svg><b>" + e(text) + "</b></span>")


def duration(ms) -> str:
    """A measured response time, at a scale that keeps its information.

    DNS answers arrive in tens of milliseconds, so rounding to whole seconds
    would print "0m 00s" against every healthy row and hide the difference
    between a 20 ms resolver and a 400 ms one. Sub-second times are therefore
    shown in milliseconds, as the reference design does; a query slow enough to
    pass a second is shown as minutes and seconds, where that reads better.
    The stored value is untouched either way.
    """
    if not isinstance(ms, (int, float)):
        return "&mdash;"
    if ms < 1000:
        return "%d ms" % int(round(ms))
    total = int(round(ms / 1000.0))
    return "%dm %02ds" % (total // 60, total % 60)


def badge(text: str, tone: str = "muted", small: bool = False) -> str:
    cls = "badge " + tone + (" tiny" if small else "")
    return '<span class="' + cls + '">' + e(text) + "</span>"


# The status vocabulary reported for a monitored resolver, most severe first.
HEALTHY = "HEALTHY"
WARNING = "WARNING"
SUSPICIOUS = "SUSPICIOUS"
POSSIBLE_POISONING = "POSSIBLE DNS CACHE POISONING"
UNREACHABLE = "UNREACHABLE"
TIMEOUT = "TIMEOUT"
ERROR = "ERROR"
NO_DATA = "NO DATA"

STATUS_SEVERITY = {POSSIBLE_POISONING: 0, UNREACHABLE: 1, TIMEOUT: 2, ERROR: 3,
                   SUSPICIOUS: 4, WARNING: 5, HEALTHY: 6, NO_DATA: 9}

_TONES = {HEALTHY: "ok", WARNING: "warn", SUSPICIOUS: "warn", TIMEOUT: "warn",
          ERROR: "warn", POSSIBLE_POISONING: "bad", UNREACHABLE: "bad",
          NO_DATA: "muted"}


def status_tone(status: str) -> str:
    return _TONES.get(status, "muted")


def sparkline(values: list) -> str:
    if len(values) < 2:
        return "<span class='muted'>&mdash;</span>"
    w, h = 88, 20
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    step = w / (len(values) - 1)
    pts = " ".join("%.1f,%.1f" % (i * step, h - (v - lo) / span * (h - 2) - 1)
                   for i, v in enumerate(values))
    return ('<svg width="%d" height="%d" viewBox="0 0 %d %d" preserveAspectRatio="none">'
            '<polyline points="%s" fill="none" stroke="currentColor" '
            'stroke-width="1.5"/></svg>' % (w, h, w, h, pts))


def resolver_status(health) -> str:
    """Transparent status derived from stored metrics; never an opaque score.

    Evaluated most-severe first, and every branch maps to one raw metric, so a
    label can always be justified from the database:

        POSSIBLE DNS CACHE POISONING  possible_poisoning_rate > 0
        UNREACHABLE                   availability 0% -- nothing answered
        TIMEOUT                       timeouts are the dominant failure mode
        ERROR                         SERVFAIL or other errors dominate
        SUSPICIOUS                    anomaly_rate > 0, none confirmed
        WARNING                       availability < 100% or freshness degraded
        HEALTHY                       available, correct, fresh, no anomalies
    """
    if health is None:
        return NO_DATA
    if (health["possible_poisoning_rate"] or 0) > 0:
        return POSSIBLE_POISONING

    availability = health["availability_pct"]
    if availability is not None and availability <= 0:
        return UNREACHABLE
    if (health["timeout_rate"] or 0) >= 0.5:
        return TIMEOUT
    if ((health["error_rate"] or 0) + (health["servfail_rate"] or 0)) >= 0.5:
        return ERROR
    if (health["anomaly_rate"] or 0) > 0:
        return SUSPICIOUS
    if (availability is not None and availability < 100) \
            or health["freshness_status"] == "DEGRADED":
        return WARNING
    return HEALTHY


def table(headers, body_rows: str, empty_cols: int = 0) -> str:
    """Wrap rows in a scrollable table with the given header cells."""
    head = "".join("<th>" + h + "</th>" for h in headers)
    if not body_rows:
        body_rows = ('<tr><td colspan="%d" class="empty">No data available.</td></tr>'
                     % (empty_cols or len(headers)))
    return ('<div class="tablewrap"><table><thead><tr>' + head +
            "</tr></thead><tbody>" + body_rows + "</tbody></table></div>")


def note(text: str, tone: str = "info") -> str:
    return '<p class="note ' + tone + '">' + text + "</p>"


# -- summary components -----------------------------------------------------

def bar(value, tone: str = "ok", suffix: str = "%") -> str:
    """A proportion drawn as a track and a fill, with the number beside it.

    `value` is a percentage 0-100, or None when the metric was never measured —
    an unmeasured metric shows an empty track rather than a misleading zero.
    """
    if not isinstance(value, (int, float)):
        return ('<div class="bar"><div class="track"></div>'
                '<span class="pv muted">&mdash;</span></div>')
    width = max(0.0, min(100.0, float(value)))
    return ('<div class="bar"><div class="track">'
            '<div class="fill ' + tone + '" style="width:%.1f%%"></div></div>'
            '<span class="pv">%.0f%s</span></div>' % (width, value, suffix))


def gauge(value, label: str, tone: str = "ok") -> str:
    """One ring gauge: a proportion of a circle, the number, and a caption.

    `value` is 0-100 or None. None draws the empty ring and an em dash, because
    "not measured" and "zero percent" are different findings.
    """
    radius, size = 33.0, 88.0
    circumference = 2 * math.pi * radius
    known = isinstance(value, (int, float))
    fraction = max(0.0, min(1.0, (value or 0) / 100.0)) if known else 0.0
    centre = size / 2
    return (
        '<div class="gauge"><svg viewBox="0 0 %(s)g %(s)g" width="%(s)g" height="%(s)g" '
        'role="img" aria-label="%(alt)s">'
        '<circle cx="%(c)g" cy="%(c)g" r="%(r)g" fill="none" stroke="currentColor" '
        'stroke-opacity=".15" stroke-width="9"/>'
        '<circle cx="%(c)g" cy="%(c)g" r="%(r)g" fill="none" class="arc %(tone)s" '
        'stroke-width="9" stroke-linecap="round" '
        'stroke-dasharray="%(on).2f %(off).2f" '
        'transform="rotate(-90 %(c)g %(c)g)"/>'
        '<text x="%(c)g" y="%(c)g" class="gv" text-anchor="middle" '
        'dominant-baseline="central">%(txt)s</text>'
        "</svg><div class='gl'>%(label)s</div></div>"
        % {"s": size, "c": centre, "r": radius, "tone": tone,
           "on": circumference * fraction, "off": circumference * (1 - fraction),
           "txt": ("%.0f%%" % value) if known else "&mdash;",
           "label": e(label),
           "alt": "%s: %s" % (label, ("%.0f percent" % value) if known else "not measured")}
    )


def donut(segments, size: float = 148.0) -> str:
    """A ring divided into proportions: (label, value, tone), plus a legend.

    Segments are laid out by accumulating dash offsets around one circle, so the
    arcs always close exactly and a rounding error cannot leave a visible gap.
    """
    segments = [(str(label), float(value), tone)
                for label, value, tone in segments if value]
    total = sum(value for _l, value, _t in segments)
    if not total:
        return "<p class='empty'>Nothing recorded for this period.</p>"

    radius = size / 2 - 13
    circumference = 2 * math.pi * radius
    centre = size / 2
    arcs, offset = "", 0.0
    for _label, value, tone in segments:
        length = value / total * circumference
        arcs += ('<circle cx="%(c).1f" cy="%(c).1f" r="%(r).1f" fill="none" '
                 'class="arc %(tone)s" stroke-width="20" '
                 'stroke-dasharray="%(on).2f %(off).2f" '
                 'stroke-dashoffset="%(shift).2f" '
                 'transform="rotate(-90 %(c).1f %(c).1f)"/>'
                 % {"c": centre, "r": radius, "tone": tone, "on": length,
                    "off": circumference - length, "shift": -offset})
        offset += length

    legend = ""
    for label, value, tone in segments:
        legend += ("<li><span class='swatch " + tone + "'></span>"
                   "<b>" + e(label) + "</b>"
                   "<span class='n'>" + "{:,}".format(int(value)) + "</span>"
                   "<span class='p'>%.1f%%</span></li>" % (value / total * 100))

    return ("<div class='donutwrap'><div class='donut'>"
            '<svg viewBox="0 0 %(s).0f %(s).0f" width="%(s).0f" height="%(s).0f" '
            'role="img" aria-label="Result distribution">%(arcs)s'
            '<text x="%(c).1f" y="%(cy).1f" class="dv" text-anchor="middle">%(t)s</text>'
            '<text x="%(c).1f" y="%(cl).1f" class="dl" text-anchor="middle">'
            "total</text></svg></div>"
            "<ul class='donutlegend'>%(legend)s</ul></div>"
            % {"s": size, "c": centre, "cy": centre - 2, "cl": centre + 14,
               "arcs": arcs, "t": "{:,}".format(int(total)), "legend": legend})


def scorecard(name: str, value, status: str, tone: str) -> str:
    """One resolver's headline metric, its name and its status."""
    shown = ("%.0f%%" % value) if isinstance(value, (int, float)) else "&mdash;"
    return ("<div class='score " + tone + "'><b class='nm'>" + e(name) + "</b>"
            "<span class='v'>" + shown + "</span>"
            "<span class='st " + tone + "'><span class='statusdot'></span>"
            + e(status) + "</span></div>")


def findings(items) -> str:
    """A marked list of statements: (text, tone)."""
    out = "<ul class='findings'>"
    for text, tone in items:
        out += ("<li><span class='fmark " + tone + "'></span>"
                "<span>" + e(text) + "</span></li>")
    return out + "</ul>"


# Series colours for the performance chart. Fixed hexes rather than theme
# tokens: an SVG stroke cannot resolve a variable that only exists per theme,
# and these six read against both the light and the dark panel.
SERIES_COLOURS = ("#2f7fd4", "#1f9d62", "#d08316", "#cc4b3c", "#8257d4", "#0e9aa7")


def linechart(series, width: int = 600, height: int = 200) -> str:
    """A multi-series time chart drawn from stored metric history.

    `series` is a list of {"name", "colour", "points": [(epoch, value), ...]}.
    One scale places every mark, tick and label; the axis text takes its colour
    from the theme so it reads on either ground.
    """
    points = [p for s in series for p in s["points"]]
    if len(points) < 2:
        return ("<p class='empty'>Not enough history yet &mdash; the chart needs "
                "at least two recorded sweeps.</p>")

    xs = [p[0] for p in points]
    x0, x1 = min(xs), max(xs)
    if x1 <= x0:
        x1 = x0 + 1
    # Scale to the 95th percentile, not the maximum. Response times are mostly
    # tens of milliseconds with the occasional multi-second timeout, and one
    # such spike flattens every ordinary line onto the axis. Points above the
    # top are drawn on it and counted underneath, so nothing is hidden.
    values = sorted(p[1] for p in points)
    top = values[max(0, int(round(0.95 * (len(values) - 1))))] or values[-1] or 1.0
    # Round the axis up to a readable step so every gridline names a real value.
    step = 10 ** math.floor(math.log10(top / 2 or 1))
    ymax = math.ceil(top / step) * step or 1.0
    clipped = sum(1 for v in values if v > ymax)

    pad_l, pad_r, pad_t, pad_b = 46, 14, 12, 26
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    def sx(x):
        return pad_l + (x - x0) / (x1 - x0) * plot_w

    def sy(y):
        return pad_t + (1 - min(1.0, y / ymax)) * plot_h

    out = ('<svg class="chart" viewBox="0 0 %d %d" preserveAspectRatio="xMidYMid meet" '
           'role="img" aria-label="Resolver response time over the recorded window">'
           % (width, height))

    for i in range(5):                                   # horizontal grid + y labels
        value = ymax * i / 4
        y = sy(value)
        out += ('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="currentColor" '
                'stroke-opacity=".14"/>' % (pad_l, y, width - pad_r, y))
        out += ('<text x="%.1f" y="%.1f" class="ax" text-anchor="end" '
                'dominant-baseline="central">%g</text>' % (pad_l - 8, y, round(value)))

    span_hours = (x1 - x0) / 3600.0
    fmt = "%H:%M" if span_hours <= 36 else "%m-%d"
    for i in range(4):                                   # x labels
        at = x0 + (x1 - x0) * i / 3
        anchor = "start" if i == 0 else ("end" if i == 3 else "middle")
        out += ('<text x="%.1f" y="%.1f" class="ax" text-anchor="%s">%s</text>'
                % (sx(at), height - 8, anchor,
                   e(time.strftime(fmt, time.localtime(at)))))

    for s in series:
        pts = sorted(s["points"])
        if len(pts) < 2:
            continue
        path = " ".join("%.1f,%.1f" % (sx(x), sy(y)) for x, y in pts)
        out += ('<polyline points="%s" fill="none" stroke="%s" stroke-width="1.8" '
                'stroke-linejoin="round" stroke-linecap="round"/>'
                % (path, s["colour"]))
        last_x, last_y = pts[-1]
        out += ('<circle cx="%.1f" cy="%.1f" r="2.8" fill="%s"/>'
                % (sx(last_x), sy(last_y), s["colour"]))

    out += "</svg>"

    legend = "".join('<span><i style="background:%s"></i>%s</span>'
                     % (s["colour"], e(s["name"])) for s in series if s["points"])
    out += '<div class="legend">' + legend + "</div>"
    if clipped:
        out += ("<p class='sub' style='margin:7px 0 0'>%d point%s above %g ms "
                "%s drawn on the top gridline; the axis follows the 95th "
                "percentile so ordinary response times stay readable.</p>"
                % (clipped, "" if clipped == 1 else "s", ymax,
                   "is" if clipped == 1 else "are"))
    return out


def kpi(tone: str, icon: str, value: str, label: str, href: str = "") -> str:
    """A headline figure, its label, and the page that explains it."""
    inner = ('<span class="ic ' + tone + '">' + icon + "</span>"
             '<span class="tx"><b class="n">' + value + '</b>'
             '<span class="l">' + e(label) + "</span></span>")
    if not href:
        return '<div class="kpi ' + tone + '">' + inner + "</div>"
    return ('<a class="kpi ' + tone + '" href="' + href + '">' + inner
            + '<span class="go" aria-hidden="true">' + ICON_CHEVRON + "</span></a>")


# -- iconography ------------------------------------------------------------
#
# Line icons drawn at 20px on a 24-unit grid, inline so a page stays a single
# self-contained file.

def _icon(paths: str, size: int = 20) -> str:
    return ('<svg width="%d" height="%d" viewBox="0 0 24 24" fill="none" '
            'stroke="currentColor" stroke-width="1.7" stroke-linecap="round" '
            'stroke-linejoin="round" aria-hidden="true">%s</svg>' % (size, size, paths))


NAV_ICONS = {
    "overview": _icon('<path d="M3 10.5 12 3l9 7.5"/><path d="M5.5 9.5V21h13V9.5"/>'
                      '<path d="M9.5 21v-6h5v6"/>', 18),
    "resolvers": _icon('<rect x="3" y="4" width="18" height="6" rx="1.6"/>'
                       '<rect x="3" y="14" width="18" height="6" rx="1.6"/>'
                       '<path d="M7 7h.01M7 17h.01"/>', 18),
    "poisoning": _icon('<path d="M12 3 4.5 6v6c0 4.6 3.1 7.9 7.5 9 4.4-1.1 7.5-4.4 '
                       '7.5-9V6z"/><path d="M12 8.5v4"/><path d="M12 16h.01"/>', 18),
    "queries": _icon('<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/>', 18),
    "anomalies": _icon('<path d="M3 13h4l2.5-7 4 14L16 13h5"/>', 18),
    "verification": _icon('<circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.5 2.5 '
                          '4.5-5"/>', 18),
    "reports": _icon('<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/>'
                     '<path d="M9 12h6M9 16h6"/>', 18),
    "domains": _icon('<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/>'
                     '<path d="M12 3c2.6 3 2.6 15 0 18-2.6-3-2.6-15 0-18z"/>', 18),
    "help": _icon('<circle cx="12" cy="12" r="9"/>'
                  '<path d="M9.4 9.2a2.7 2.7 0 1 1 3.3 3.4c-.5.2-.7.6-.7 1.1v.6"/>'
                  '<path d="M12 17.2h.01"/>', 18),
    "settings": _icon('<circle cx="12" cy="12" r="3.2"/>'
                      '<path d="M12 2.6v2.2M12 19.2v2.2M21.4 12h-2.2M4.8 12H2.6'
                      'M18.6 5.4 17 7M7 17l-1.6 1.6M18.6 18.6 17 17M7 7 5.4 '
                      '5.4"/>', 18),
}

ICON_CHEVRON = _icon('<path d="m9 5 7 7-7 7"/>', 16)
ICON_CLOCK = _icon('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>', 17)
ICON_PLAY = _icon('<path d="M7 4.5v15l13-7.5z"/>', 16)
ICON_REPORT = _icon('<rect x="3" y="5" width="18" height="16" rx="2"/>'
                    '<path d="M3 10h18M8 3v4M16 3v4"/>', 16)

KPI_ICONS = {
    "resolvers": _icon('<circle cx="12" cy="12" r="9"/><path d="m8.2 12 2.6 2.6 '
                       '5-5.4"/>', 22),
    "domains": _icon('<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/>'
                     '<path d="M12 3c2.6 2.6 2.6 15.4 0 18-2.6-2.6-2.6-15.4 0-18z"/>', 22),
    "anomalies": _icon('<path d="M12 3.5 21 20H3z"/><path d="M12 10v4"/>'
                       '<path d="M12 17h.01"/>', 22),
    "uptime": _icon('<circle cx="12" cy="12" r="9"/><path d="M12 6.5V12l3.5 2"/>', 22),
}

# -- inlined assets --------------------------------------------------------
#
# From the supplied UI package (assets/argus-logo.svg, empty-state.svg,
# sri-lanka.svg), inlined rather than linked: every Argus page must remain a
# single self-contained file that opens from the filesystem, so an <img src>
# to a sibling asset would break the static export and the printed PDF.

ASSET_LOGO = (
    '<svg class="logomark" viewBox="0 0 360 100" role="img" '
    'aria-label="Argus, National DNS Monitoring">'
    '<rect width="360" height="100" rx="18" fill="#10243b"/>'
    '<path d="M22 50 C55 12 105 12 138 50 C105 88 55 88 22 50Z" fill="none" '
    'stroke="#1687ff" stroke-width="9"/>'
    '<circle cx="80" cy="50" r="17" fill="#1687ff"/>'
    '<circle cx="80" cy="50" r="8" fill="#10243b"/>'
    '<text x="155" y="57" font-family="Arial, Helvetica, sans-serif" '
    'font-size="39" font-weight="700" fill="#ffffff">ARGUS</text>'
    '<text x="158" y="78" font-family="Arial, Helvetica, sans-serif" '
    'font-size="11" fill="#c9d7e7">National DNS Monitoring</text></svg>')

# The national outline, traced from the project's own reference map
# (assets/sri-lanka-dns-map-reference.png) by thresholding the land, taking the
# coastline row by row and simplifying it. Derived from that image rather than
# drawn by hand, so the shape is the real one; 160 points in a 0-100 box.
LANKA_PATH = ("M14.5 0.0L14.5 1.3L14.9 2.6L15.1 3.8L15.3 5.1L20.8 6.4L21.0 7.7L23.2 9.0L23.2 10.2L22.0 11.5L22.8 12.8L23.2 14.1L23.0 15.4L22.2 16.7L18.3 17.9L14.3 19.2L13.4 20.5L13.0 21.8L12.8 23.1L12.2 24.3L11.6 25.6L11.2 26.9L11.2 28.2L11.0 29.5L9.8 30.7L9.0 32.0L6.7 33.3L6.3 34.6L5.3 35.9L5.1 37.1L4.5 38.4L4.5 39.7L4.5 41.0L4.7 42.3L4.7 43.5L3.7 44.8L3.5 46.1L2.4 47.4L1.0 48.7L1.0 50.0L1.4 51.2L1.4 52.5L0.0 53.8L0.0 55.1L0.0 56.4L1.4 57.6L1.4 58.9L0.8 60.2L0.6 61.5L1.0 62.8L7.5 64.0L12.0 65.3L12.4 66.6L12.4 67.9L12.4 69.2L12.4 70.4L3.7 71.7L3.3 73.0L3.3 74.3L4.7 75.6L4.9 76.8L5.5 78.1L6.7 79.4L6.5 80.7L6.5 82.0L8.1 83.3L8.3 84.5L8.8 85.8L8.8 87.1L9.8 88.4L10.4 89.7L10.6 90.9L11.2 92.2L12.4 93.5L14.3 94.8L19.8 96.1L21.6 97.3L22.2 98.6L22.2 99.9L22.3 100.0L59.4 100.0L59.5 99.9L61.7 98.6L66.6 97.3L68.0 96.1L75.0 94.8L80.0 93.5L87.6 92.2L89.4 90.9L92.1 89.7L94.7 88.4L96.1 87.1L98.0 85.8L98.8 84.5L98.8 83.3L97.8 82.0L97.6 80.7L99.6 79.4L99.6 78.1L99.4 76.8L99.0 75.6L100.0 74.3L100.0 73.0L100.0 71.7L100.0 70.4L100.0 69.2L100.0 67.9L100.0 66.6L99.0 65.3L98.4 64.0L96.9 62.8L95.5 61.5L92.3 60.2L91.7 58.9L91.2 57.6L90.8 56.4L91.2 55.1L91.2 53.8L90.8 52.5L89.6 51.2L88.6 50.0L88.0 48.7L85.5 47.4L84.7 46.1L83.1 44.8L82.7 43.5L82.5 42.3L82.1 41.0L81.9 39.7L81.5 38.4L81.5 37.1L81.3 35.9L74.7 34.6L74.5 33.3L72.7 32.0L72.3 30.7L70.7 29.5L70.1 28.2L68.6 26.9L67.0 25.6L65.8 24.3L65.0 23.1L63.5 21.8L62.5 20.5L61.1 19.2L58.7 17.9L57.8 16.7L57.6 15.4L56.2 14.1L53.0 12.8L51.9 11.5L50.3 10.2L47.7 9.0L45.8 7.7L42.6 6.4L40.9 5.1L38.7 3.8L37.5 2.6L37.3 1.3L37.2 0.0Z")

# The trace normalised x and y to 0-100 independently. That is fine as data
# but it is not a shape: drawn in a square box the island comes out twice as
# wide as it is. Sri Lanka's bounding box is almost exactly half as wide as it
# is tall, so the horizontal axis is scaled back by that ratio wherever the
# path is drawn, and the viewBox is narrowed to match.
LANKA_ASPECT = 0.501
LANKA_BOX = "0 0 %.1f 100" % (100 * LANKA_ASPECT)


def lanka_shape(css_class: str) -> str:
    """The island path, squeezed back to its true proportions."""
    return ('<g transform="scale(%.3f 1)"><path d="%s" class="%s"/></g>'
            % (LANKA_ASPECT, LANKA_PATH, css_class))


ASSET_LANKA = (
    '<svg class="lanka" viewBox="' + LANKA_BOX + '" '
    'preserveAspectRatio="xMidYMid meet" role="img" '
    'aria-label="Map of Sri Lanka">' + lanka_shape("island") + "</svg>")


def national_map(markers: str = "") -> str:
    """The island with resolver markers, or an honest empty overlay.

    A marker is drawn only for a resolver whose configuration carries real
    coordinates. With none configured the map still renders, and says so --
    inventing positions would put fabricated infrastructure on a national map.
    """
    body = ('<div class="mapwrap"><div class="mapinner">'
            '<svg class="mapsvg" viewBox="' + LANKA_BOX + '" '
            'preserveAspectRatio="xMidYMid meet" role="img" '
            'aria-label="Monitored resolver locations in Sri Lanka">'
            + lanka_shape("landmass") + markers + "</svg></div>")
    if not markers:
        body += ("<p class='mapnote'>No resolver locations available. Add "
                 "<code>map_x</code> and <code>map_y</code> (0-100) to a "
                 "resolver in <code>config/resolvers.yaml</code> to place it.</p>")
    return body + "</div>"


ASSET_EMPTY = (
    '<svg class="emptymark" viewBox="0 0 72 72" width="60" height="60" '
    'aria-hidden="true">'
    '<rect x="3" y="3" width="66" height="66" rx="16" fill="currentColor" '
    'opacity=".12"/>'
    '<path d="M20 36h32M36 20v32" stroke="currentColor" stroke-width="6" '
    'stroke-linecap="round"/></svg>')


def empty_state(title: str, text: str = "", action: str = "") -> str:
    """The no-data panel.

    Shown wherever the database has nothing to report, so a page is never
    padded with zeroes that could be mistaken for a measurement.
    """
    return ("<div class='emptystate'>" + ASSET_EMPTY
            + "<b>" + e(title) + "</b>"
            + ("<span>" + e(text) + "</span>" if text else "")
            + (action or "") + "</div>")


EYE = ('<svg class="eye" viewBox="0 0 48 48" fill="none" stroke="currentColor" '
       'stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" '
       'aria-hidden="true">'
       '<path d="M2 24s8-13 22-13 22 13 22 13-8 13-22 13S2 24 2 24z"/>'
       '<circle cx="24" cy="24" r="6.5"/>'
       '<circle cx="24" cy="24" r="1.8" fill="currentColor" stroke="none"/></svg>')


# -- page chrome ------------------------------------------------------------

def _nav(active: str, live: bool, alerts: int = 0) -> str:
    out = ""
    for key, _file, _path, title, _blurb in NAV_PAGES:
        cls = "navlink active" if key == active else "navlink"
        count = ('<span class="navcount">' + str(alerts) + "</span>"
                 if key == "anomalies" and alerts else "")
        out += ('<a class="' + cls + '" href="' + link(key, live) + '">'
                + NAV_ICONS.get(key, "") + "<span>" + e(title) + "</span>"
                + count + "</a>")
    return out


def pagehead(title: str, blurb: str, actions: str = "") -> str:
    """The title block at the top of a page, optionally with action buttons."""
    return ('<div class="pagehead"><div class="pt">'
            '<h1 class="ptitle">' + title + '</h1>'
            '<p class="pblurb">' + blurb + "</p></div>"
            + ('<div class="actions">' + actions + "</div>" if actions else "")
            + "</div>")


def page(active: str, vantage: str, body: str, live: bool = False,
         refresh_seconds: int = 0, scope: str = "", alerts: int = 0,
         head: str = "") -> str:
    """Wrap page content in the shared chrome and return a complete document.

    `scope` is an optional summary of what is being monitored -- resolver and
    domain counts, and the interval -- so a screenshot of any page carries
    enough context to be read on its own. `alerts` puts the confirmed-event
    count on the navigation, so it is visible from every page. `head` lets a
    page replace the default title block with one of its own; every page still
    gets a title block if it supplies nothing.
    """
    key, _file, _path, title, blurb = PAGE_BY_KEY[active]
    meta_refresh = ('<meta http-equiv="refresh" content="%d">' % int(refresh_seconds)
                    if refresh_seconds and refresh_seconds > 0 else "")
    return _DOC.format(
        css=_CSS, meta_refresh=meta_refresh, eye=EYE, clock=ICON_CLOCK,
        lanka=ASSET_LANKA,
        nav=_nav(active, live, alerts), title=e(title),
        pagehead=head or pagehead(e(title), e(blurb)),
        vantage=e(vantage), scope=(" &middot; " + e(scope)) if scope else "",
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
        zone=e(time.strftime("%Z") or "local"),
        body=body,
    )


_CSS = """
:root{--bg:#f2f4f7;--panel:#fff;--ink:#16202b;--muted:#5f6b7a;--line:#dde3ea;
--rail:#0f2942;--rail2:#0b2035;--railink:#c9dcef;--railactive:#fff;--accent:#1f5c96;
--ok:#116b3a;--okbg:#e5f4ec;--warn:#8a5a05;--warnbg:#fdf2dd;
--bad:#b0271f;--badbg:#fdebe9;--grey:#5f6b7a;--greybg:#eceff3;
--info:#1f5c96;--infobg:#e6eff8;--violet:#6d4bc4;--violetbg:#eee9fa;
--shadow:0 1px 2px rgba(16,24,40,.05),0 3px 10px rgba(16,24,40,.05)}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){
--bg:#0b1016;--panel:#151b23;--ink:#e4e9ef;--muted:#8b97a5;--line:#232c37;
--rail:#0b131c;--rail2:#080f16;--railink:#8fa8c2;--railactive:#fff;--accent:#7fb0e0;
--ok:#4ade80;--okbg:#0e2419;--warn:#fbbf24;--warnbg:#2a2210;
--bad:#f87171;--badbg:#2b1315;--grey:#8b97a5;--greybg:#1c232c;
--info:#7fb0e0;--infobg:#122334;--violet:#a78bfa;--violetbg:#1e1930;
--shadow:0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.3)}}
:root[data-theme="dark"]{
--bg:#0b1016;--panel:#151b23;--ink:#e4e9ef;--muted:#8b97a5;--line:#232c37;
--rail:#0b131c;--rail2:#080f16;--railink:#8fa8c2;--railactive:#fff;--accent:#7fb0e0;
--ok:#4ade80;--okbg:#0e2419;--warn:#fbbf24;--warnbg:#2a2210;
--bad:#f87171;--badbg:#2b1315;--grey:#8b97a5;--greybg:#1c232c;
--info:#7fb0e0;--infobg:#122334;--violet:#a78bfa;--violetbg:#1e1930;
--shadow:0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.3)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14.5px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Ubuntu","Segoe UI",
Roboto,Helvetica,Arial,sans-serif;
-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
text-rendering:optimizeLegibility}
/* Digits line up in every column: counts, latencies, percentages. */
td,th,.card .n,.kpi .n,.metric .v,.pager,.bar .pv{font-variant-numeric:tabular-nums}
a{color:var(--accent);transition:color .14s ease}
.layout{display:flex;min-height:100vh;align-items:stretch}

/* sidebar */
.rail{width:238px;flex:none;color:var(--railink);padding:22px 0 22px;
display:flex;flex-direction:column;
background:linear-gradient(178deg,var(--rail) 0%,var(--rail2) 100%)}
.brand{display:flex;align-items:center;gap:12px;padding:0 20px 18px;
border-bottom:1px solid rgba(255,255,255,.1);margin-bottom:14px}
.eye{width:34px;height:34px;flex:none;color:#7fb0e0}
.brand .wm{min-width:0}
.brand .wm b{display:block;color:#fff;font-size:23px;font-weight:700;
letter-spacing:.055em;line-height:1}
.brand .wm span{display:block;font-size:10px;letter-spacing:.1em;
text-transform:uppercase;color:var(--railink);opacity:.85;margin-top:4px}
.navlink{display:flex;align-items:center;gap:12px;padding:12px 20px;
color:var(--railink);text-decoration:none;font-size:14px;
border-left:3px solid transparent;
transition:background .16s ease,color .16s ease,border-color .16s ease}
.navlink svg{flex:none;opacity:.85}
.navlink:hover{background:rgba(255,255,255,.07);color:#fff}
.navlink:hover svg{opacity:1}
.navlink:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.navlink.active{background:rgba(255,255,255,.1);color:var(--railactive);
border-left-color:#7fb0e0;font-weight:600}
.navlink.active svg{opacity:1;color:#7fb0e0}
.navcount{margin-left:auto;background:#c0392b;color:#fff;font-size:10.5px;
font-weight:700;min-width:19px;height:19px;border-radius:999px;padding:0 6px;
display:inline-flex;align-items:center;justify-content:center}
/* The quote block follows the navigation instead of being pinned to the
   bottom of a tall viewport, which left a wide empty band between them. */
.railfoot{margin:22px 14px 0;padding:18px 6px 0;
border-top:1px solid rgba(255,255,255,.09)}
.railspacer{flex:1 1 auto;min-height:8px}
.railfoot .quote{color:#fff;opacity:.9;font-size:13px;line-height:1.5;
font-style:italic}
.railfoot .caveat{font-size:10.5px;color:var(--railink);opacity:.7;
line-height:1.6;margin-top:12px}

/* main column */
.main{flex:1 1 auto;min-width:0;max-width:100%;display:flex;
flex-direction:column}
.topbar{background:var(--panel);border-bottom:1px solid var(--line);
padding:12px 26px;position:sticky;top:0;z-index:2;display:flex;
flex-wrap:wrap;gap:14px 24px;align-items:center;justify-content:space-between}
.topbar .tagline{font-size:14.5px;font-style:italic;color:var(--ink);
letter-spacing:-.005em}
.topbar .pillars{color:var(--muted);font-size:11.5px;margin-top:3px;
letter-spacing:.02em}
.topbar .stamp{display:flex;align-items:center;gap:9px;color:var(--muted);
font-size:11.5px;line-height:1.45}
.topbar .stamp svg{flex:none;opacity:.7}
.topbar .stamp b{display:block;color:var(--ink);font-size:13px;font-weight:600;
font-variant-numeric:tabular-nums}
.content{padding:24px 26px 40px;max-width:1280px;width:100%;
box-sizing:border-box;min-width:0;flex:1 1 auto}

/* page head */
.pagehead{display:flex;flex-wrap:wrap;gap:16px 24px;align-items:flex-start;
justify-content:space-between;margin-bottom:22px}
.pagehead .pt{min-width:0;flex:1 1 340px}
.ptitle{margin:0 0 5px;font-size:26px;font-weight:650;letter-spacing:-.022em;
text-wrap:balance}
.pblurb{margin:0;color:var(--muted);font-size:13.5px;max-width:68ch;
line-height:1.55}
.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.action{display:inline-flex;align-items:center;gap:8px;font-size:13px;
font-weight:600;padding:9px 16px;border-radius:8px;text-decoration:none;
border:1px solid var(--line);background:var(--panel);color:var(--ink);
box-shadow:var(--shadow);transition:border-color .16s ease,background .16s ease}
.action:hover{border-color:var(--accent)}
.action.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.action.primary:hover{filter:brightness(1.08)}
.action:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
details.runbox{margin:0 0 20px}
details.runbox>summary{list-style:none;cursor:pointer;display:inline-flex}
details.runbox>summary::-webkit-details-marker{display:none}
details.runbox .body{background:var(--panel);border:1px solid var(--line);
border-radius:10px;padding:14px 16px;margin-top:10px;box-shadow:var(--shadow);
max-width:70ch;font-size:13px;color:var(--muted)}
details.runbox .body p{margin:0 0 8px}
details.runbox .body p:last-child{margin:0}
details.runbox pre{margin:0 0 10px;background:var(--bg);border:1px solid var(--line);
border-radius:7px;padding:10px 12px;overflow-x:auto;color:var(--ink);
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}

/* section headings */
h2{font-size:11px;margin:30px 0 11px;color:var(--muted);font-weight:700;
text-transform:uppercase;letter-spacing:.1em}
h2:first-of-type{margin-top:0}

/* verdict + notes */
.verdict{display:flex;gap:12px;align-items:flex-start;border-radius:10px;
padding:14px 16px;margin-bottom:20px;background:var(--panel);
border:1px solid var(--line);box-shadow:var(--shadow)}
.verdict b{display:block;font-size:15px}
.verdict span{display:block;color:var(--muted);font-size:12.5px;margin-top:2px}
.verdict.ok{background:var(--okbg);border-color:transparent;color:var(--ok)}
.verdict.bad{background:var(--badbg);border-color:transparent;color:var(--bad)}
.verdict.warn{background:var(--warnbg);border-color:transparent;color:var(--warn)}
.verdict.ok b,.verdict.bad b,.verdict.warn b{color:inherit}
.dot{width:10px;height:10px;border-radius:50%;flex:none;margin-top:6px;
background:currentColor}
.note{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--muted);
border-radius:0 8px 8px 0;padding:11px 14px;color:var(--muted);font-size:12.5px;
margin:0 0 18px;max-width:80ch}
.note.warn{border-left-color:var(--warn)}
.note.ok{border-left-color:var(--ok)}
.note code{font-family:ui-monospace,Consolas,monospace;background:rgba(127,127,127,.14);
padding:1px 5px;border-radius:4px}

/* KPI tiles */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(212px,1fr));gap:14px}
.kpi{display:flex;align-items:center;gap:14px;padding:15px 16px;border-radius:12px;
background:var(--panel);border:1px solid var(--line);box-shadow:var(--shadow);
text-decoration:none;color:inherit;
transition:border-color .16s ease,transform .16s ease}
a.kpi:hover{border-color:var(--accent);transform:translateY(-1px)}
a.kpi:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.kpi .ic{width:46px;height:46px;border-radius:50%;flex:none;display:grid;
place-items:center}
.kpi .tx{min-width:0}
.kpi .n{display:block;font-size:25px;font-weight:700;letter-spacing:-.03em;
line-height:1.15}
.kpi .l{display:block;font-size:12px;color:var(--muted);margin-top:2px}
.kpi .go{margin-left:auto;color:var(--muted);opacity:.55;flex:none;display:flex}
.kpi.ok .ic{background:var(--okbg);color:var(--ok)}
.kpi.ok .n{color:var(--ok)}
.kpi.bad .ic{background:var(--badbg);color:var(--bad)}
.kpi.bad .n{color:var(--bad)}
.kpi.warn .ic{background:var(--warnbg);color:var(--warn)}
.kpi.warn .n{color:var(--warn)}
.kpi.info .ic{background:var(--infobg);color:var(--info)}
.kpi.muted .ic{background:var(--greybg);color:var(--grey)}
.kpi.muted .n{color:var(--muted)}

/* two-column dashboard split */
.split{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(296px,1fr);
gap:16px;align-items:start}
.col{display:flex;flex-direction:column;gap:16px;min-width:0}
@media(max-width:880px){.split{grid-template-columns:1fr}}

/* cards / panels */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(146px,1fr));gap:12px;
margin-bottom:8px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:13px 15px 15px;box-shadow:var(--shadow)}
.card .l{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;
color:var(--muted);font-weight:650}
.card .n{font-size:28px;font-weight:700;margin-top:7px;letter-spacing:-.025em;
line-height:1.15}
.card.ok .n{color:var(--ok)}.card.warn .n{color:var(--warn)}
.card.bad .n{color:var(--bad)}.card.muted .n{color:var(--muted)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:15px 17px;box-shadow:var(--shadow)}
.panel h3{margin:0 0 9px;font-size:13px;font-weight:650}
.panel.flush{padding:0;overflow:hidden}
.panel.flush h3{padding:14px 17px 11px;margin:0;border-bottom:1px solid var(--line)}
.panel.flush .tablewrap{border:none;border-radius:0;box-shadow:none;margin:0}
.panel.flush.compact .tablewrap{max-height:274px;overflow:auto}
.panel.compact .emptystate{padding:20px 12px}
.panel .foot{padding:11px 17px;border-top:1px solid var(--line);text-align:right}
.panel .foot a{font-size:12.5px;font-weight:600;text-decoration:none}
.panel .foot a:hover{text-decoration:underline}
.panel .sub{margin:-4px 0 12px;font-size:11.5px;color:var(--muted);line-height:1.5}

/* gauges */
.gauges{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));
gap:12px 8px;justify-items:center}
.gauge{text-align:center;color:var(--ink)}
.gauge svg{display:block;margin:0 auto;max-width:100%;height:auto}
.gauge .gv{font:700 17px/1 system-ui,sans-serif;fill:currentColor;
font-variant-numeric:tabular-nums}
.gauge .arc.ok{stroke:var(--ok)}
.gauge .arc.info{stroke:var(--info)}
.gauge .arc.violet{stroke:var(--violet)}
.gauge .arc.warn{stroke:var(--warn)}
.gauge .arc.bad{stroke:var(--bad)}
.gauge .arc.muted{stroke:var(--grey)}
.gauge .gl{font-size:11px;color:var(--muted);margin-top:7px;line-height:1.35;
max-width:13ch}

/* proportion bar */
.bar{display:flex;align-items:center;gap:9px;min-width:126px}
.bar .track{flex:1 1 auto;height:7px;border-radius:999px;background:var(--greybg);
overflow:hidden;min-width:52px}
.bar .fill{height:100%;border-radius:999px}
.bar .fill.ok{background:var(--ok)}
.bar .fill.warn{background:var(--warn)}
.bar .fill.bad{background:var(--bad)}
.bar .fill.muted{background:var(--grey)}
.bar .pv{font-size:12px;color:var(--muted);width:36px;text-align:right;flex:none}

/* chart */
.chart{width:100%;height:auto;color:var(--muted);display:block}
.chart .ax{font:10px/1 system-ui,sans-serif;fill:currentColor;opacity:.85}
.legend{display:flex;flex-wrap:wrap;gap:6px 15px;font-size:11.5px;
color:var(--muted);margin-top:9px}
.legend span{display:inline-flex;align-items:center}
.legend i{width:8px;height:8px;border-radius:50%;display:inline-block;
margin-right:6px;flex:none}

/* alert feed */
.feed{list-style:none;margin:0;padding:0}
.feed li{display:flex;gap:11px;padding:11px 0;border-bottom:1px solid var(--line)}
.feed li:first-child{padding-top:2px}
.feed li:last-child{border-bottom:none;padding-bottom:2px}
.feed .fi{width:22px;height:22px;border-radius:50%;flex:none;display:grid;
place-items:center;font-size:12px;font-weight:700;margin-top:1px}
.feed .fi.bad{background:var(--badbg);color:var(--bad)}
.feed .fi.warn{background:var(--warnbg);color:var(--warn)}
.feed .ft{min-width:0}
.feed b{display:block;font-size:13px;font-weight:600;line-height:1.4}
.feed span{display:block;font-size:11.5px;color:var(--muted);margin-top:2px}

/* report builder */
.reportsplit{grid-template-columns:minmax(0,1.15fr) minmax(0,1fr)}
form.builder{display:grid;gap:16px;grid-template-columns:1fr;margin:0}
@media(min-width:620px){form.builder{grid-template-columns:1fr 1fr}
form.builder .step:first-child{grid-row:span 2}}
.builder .step h4{margin:0 0 9px;font-size:11px;font-weight:700;
text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.builder .field{margin-bottom:9px}
.builder .field input{width:100%;min-width:0}
.builder .hint{margin:2px 0 0;font-size:11.5px;color:var(--muted);line-height:1.5}
.choices{display:flex;flex-direction:column;gap:2px}
.choices.row{flex-direction:row;flex-wrap:wrap;gap:4px 16px}
.choice{display:flex;gap:9px;align-items:flex-start;padding:5px 6px;
border-radius:7px;cursor:pointer;font-size:13px}
.choice:hover{background:rgba(127,127,127,.07)}
.choice input{min-width:0;width:14px;height:14px;margin:3px 0 0;flex:none;
accent-color:var(--accent)}
.choice input:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.choice b{font-weight:600;display:block;line-height:1.35}
.choice i{display:block;font-style:normal;font-size:11.5px;color:var(--muted);
line-height:1.45;margin-top:1px}
.builder-actions{display:flex;flex-wrap:wrap;gap:9px;align-items:center;
margin-top:16px}
.builder-actions button{background:var(--panel);color:var(--accent);
border-color:var(--line)}
.builder-actions button:hover{border-color:var(--accent);filter:none}
.builder-actions button.primary{background:var(--accent);color:#fff;
border-color:var(--accent)}
.builder-actions button.primary:hover{filter:brightness(1.08)}
pre.cmd{background:var(--bg);border:1px solid var(--line);border-radius:7px;
padding:11px 13px;overflow-x:auto;margin:0 0 10px;color:var(--ink);
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:11.5px;line-height:1.6;white-space:pre}

/* tables */
.tablewrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);
border-radius:10px;box-shadow:var(--shadow);margin-bottom:6px;max-width:100%;
box-sizing:border-box}
table{width:100%;border-collapse:collapse;font-size:13px;
table-layout:auto;box-sizing:border-box}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);
vertical-align:middle}
/* Cells wrap by default and only the ones that must stay on one line opt out,
   so a long detail column can no longer widen the table past its container. */
td,th{white-space:normal}
td.nowrap,th.nowrap,td.num,td.mono{white-space:nowrap}
th{color:var(--muted);font-weight:650;text-transform:uppercase;font-size:10px;
letter-spacing:.08em;background:rgba(127,127,127,.05)}
tbody tr:last-child td{border-bottom:none}
tbody tr{transition:background .14s ease}
tbody tr:hover td{background:rgba(127,127,127,.05)}
tr.dim td{opacity:.55}
td.wrap{white-space:normal;max-width:340px;min-width:150px;line-height:1.5}

/* badges + chips */
.badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:10.5px;
font-weight:700;letter-spacing:.03em}
.badge.tiny{font-size:9.5px;padding:2px 7px}
.badge.ok{background:var(--okbg);color:var(--ok)}
.badge.warn{background:var(--warnbg);color:var(--warn)}
.badge.bad{background:var(--badbg);color:var(--bad)}
.badge.muted{background:var(--greybg);color:var(--grey)}
.statusdot{display:inline-block;width:7px;height:7px;border-radius:50%;
margin-right:7px;vertical-align:1px;background:currentColor}
.st{font-size:12.5px;font-weight:600}
.st.ok{color:var(--ok)}.st.warn{color:var(--warn)}
.st.bad{color:var(--bad)}.st.muted{color:var(--grey)}
.chip{display:inline-block;font-size:9.5px;font-weight:700;padding:1px 6px;
border-radius:4px;background:var(--greybg);color:var(--grey);vertical-align:1px}

/* forms */
form.filters{display:flex;flex-wrap:wrap;gap:9px;align-items:flex-end;
background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:13px 15px;margin-bottom:14px;box-shadow:var(--shadow)}
.field{display:flex;flex-direction:column;gap:4px}
.field label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;
color:var(--muted);font-weight:650}
input,select{font:inherit;font-size:13px;padding:6px 9px;border-radius:7px;
border:1px solid var(--line);background:var(--bg);color:var(--ink);min-width:132px}
input:focus,select:focus{outline:2px solid var(--accent);outline-offset:1px}
button{font:inherit;font-size:13px;font-weight:600;padding:7px 15px;border-radius:7px;
border:1px solid transparent;background:var(--accent);color:#fff;cursor:pointer;
transition:filter .16s ease}
button:hover{filter:brightness(1.08)}
button:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
a.btn{display:inline-block;text-decoration:none;font-size:12.5px;font-weight:600;
padding:7px 13px;border-radius:7px;border:1px solid var(--line);
background:var(--panel);color:var(--accent);
transition:background .16s ease,border-color .16s ease}
a.btn:hover{border-color:var(--accent);background:var(--bg)}
a.btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
a.btn.off{color:var(--muted);opacity:.5;pointer-events:none}

/* pagination + misc */
.pager{display:flex;gap:9px;align-items:center;margin-top:12px;font-size:12.5px;
color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.small{font-size:12px}.muted{color:var(--muted)}
.empty{color:var(--muted);font-style:italic;text-align:center;padding:20px;
font-size:12.5px;margin:0}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:14px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:5px 14px;font-size:12.5px}
.kv dt{color:var(--muted)}.kv dd{margin:0}
.stages{list-style:none;margin:0;padding:0;font-size:12.5px}
.stages li{padding:8px 0;border-bottom:1px solid var(--line)}
.stages li:last-child{border-bottom:none}
.stages b{display:block;font-size:11px;text-transform:uppercase;
letter-spacing:.06em;color:var(--muted)}
footer.caveat{color:var(--muted);font-size:11.5px;margin-top:30px;
border-top:1px solid var(--line);padding-top:14px;line-height:1.7;max-width:80ch}
.appbar{display:flex;flex-wrap:wrap;gap:6px 18px;align-items:center;
justify-content:space-between;background:var(--panel);
border-top:1px solid var(--line);padding:13px 26px;font-size:11.5px;
color:var(--muted)}
.appbar .l{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center}
.appbar .l b{color:var(--ink);font-weight:650;letter-spacing:.05em}
.appbar .sep{opacity:.4}
.appbar .r{font-weight:600;color:var(--ink);opacity:.75}

/* sidebar map */
.lanka{display:block;width:100%;max-width:150px;height:auto;
margin:0 auto 16px;color:#7fb0e0}
/* The island is half as wide as it is tall, so 150px of width costs 300px of
   height. On a short screen that pushes the quote out of the rail, so it
   steps down rather than forcing the column to scroll. */
@media(max-height:900px){.lanka{max-width:118px}}
@media(max-height:780px){.lanka{max-width:88px}}
.lanka .island{fill:currentColor;opacity:.5}

/* national map panel */
.mapwrap{display:flex;flex-direction:column;align-items:center;gap:10px}
.mapinner{position:relative;display:flex;justify-content:center;width:100%}
.mapsvg{display:block;width:auto;height:auto;max-height:320px;
max-width:100%}
.mapsvg .landmass{fill:var(--accent);opacity:.22;stroke:var(--accent);
stroke-width:.6;stroke-opacity:.55}
.mapsvg .marker{fill:var(--accent);stroke:var(--panel);stroke-width:1.1}
.mapsvg .marker.bad{fill:var(--bad)}
.mapsvg .marker.warn{fill:var(--warn)}
.mapnote{font-size:11.5px;color:var(--muted);text-align:center;margin:0;
max-width:34ch;line-height:1.55}
.mapnote code{font-family:ui-monospace,Consolas,monospace;
background:rgba(127,127,127,.14);padding:1px 5px;border-radius:4px}

/* empty states */
.emptystate{display:flex;flex-direction:column;align-items:center;
justify-content:center;text-align:center;gap:7px;padding:34px 20px;
color:var(--muted)}
.emptystate .emptymark{color:var(--accent);flex:none}
.emptystate b{font-size:14px;color:var(--ink);font-weight:650;margin-top:4px}
.emptystate span{font-size:12.5px;max-width:46ch;line-height:1.55}
.emptystate .btn,.emptystate code{margin-top:6px}
.panel .emptystate{padding:26px 12px}

/* report sub-navigation */
.tabs{display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--line);
margin:0 0 18px}
.tabs a{padding:9px 14px;font-size:13px;font-weight:600;text-decoration:none;
color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-1px;
transition:color .16s ease,border-color .16s ease}
.tabs a:hover{color:var(--ink)}
.tabs a.on{color:var(--accent);border-bottom-color:var(--accent)}
.tabs a:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}

/* a small coloured disc with a word beside it: severity and status */
.dotstate{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;
font-weight:600;white-space:nowrap}
.dotstate .statusdot{width:8px;height:8px;margin:0;vertical-align:0}
.dotstate.ok{color:var(--ok)}
.dotstate.warn{color:var(--warn)}
.dotstate.bad{color:var(--bad)}
.dotstate.muted{color:var(--grey)}

/* compact status pill: coloured disc, glyph, word */
.pill{display:inline-flex;align-items:center;gap:7px;padding:3px 11px 3px 4px;
border-radius:999px;font-size:11.5px;font-weight:700;letter-spacing:.02em;
line-height:1.5;white-space:nowrap;vertical-align:middle}
.pill .pillmark{width:16px;height:16px;flex:none;display:block}
.pill b{font-weight:700}
.pill.ok{background:var(--okbg);color:var(--ok)}
.pill.ok .pillmark circle{fill:var(--ok)}
.pill.bad{background:var(--badbg);color:var(--bad)}
.pill.bad .pillmark circle{fill:var(--bad)}
.pill.warn{background:var(--warnbg);color:var(--warn)}
.pill.warn .pillmark circle{fill:var(--warn)}
.pill.muted{background:var(--greybg);color:var(--grey)}
.pill.muted .pillmark circle{fill:var(--grey)}

/* Monitoring / Domain Check */
.checkbar{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));
gap:0;background:var(--panel);border:1px solid var(--line);border-radius:10px;
box-shadow:var(--shadow);margin-bottom:16px;overflow:hidden}
.checkbar>div{padding:12px 16px;border-right:1px solid var(--line);min-width:0}
.checkbar>div:last-child{border-right:none}
.checkbar span{display:block;font-size:10px;text-transform:uppercase;
letter-spacing:.07em;color:var(--muted);font-weight:650}
.checkbar b{display:block;font-size:14px;font-weight:650;margin-top:5px}
.checkbar b i{font-style:normal;font-weight:400;color:var(--muted);
font-family:ui-monospace,Consolas,monospace;font-size:12.5px}

.paths.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));
gap:14px;margin-bottom:12px}
.pathcard{background:var(--panel);border:1px solid var(--line);border-radius:10px;
box-shadow:var(--shadow);overflow:hidden;display:flex;flex-direction:column}
.pathcard.untrusted{border-top:3px solid var(--bad)}
.pathcard.trusted{border-top:3px solid var(--ok)}
.pathhead{display:flex;gap:10px;align-items:flex-start;padding:13px 16px 11px}
.pathhead .dot{width:10px;height:10px;border-radius:50%;flex:none;margin-top:5px}
.pathcard.untrusted .pathhead .dot{background:var(--bad)}
.pathcard.trusted .pathhead .dot{background:var(--ok)}
.pathhead b{display:block;font-size:13px;font-weight:650;line-height:1.35}
.pathhead span{display:block;font-size:11.5px;color:var(--muted);margin-top:2px}
.digbox{background:#0d1620;margin:0 16px;border-radius:8px;padding:11px 13px;
overflow-x:auto;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:12px;line-height:1.75}
.digcmd{color:#7fb0e0;margin-bottom:7px;white-space:nowrap}
.digline{white-space:nowrap;color:#c9d7e7}
.digline.muted{color:#64748b}
.digline.bad{color:#f87171;white-space:normal}
.digline .dn{display:inline-block;min-width:132px;color:#e2e8f0}
.digline .dt{display:inline-block;min-width:44px;color:#94a3b8}
.digline .dc,.digline .dr{display:inline-block;min-width:32px;color:#94a3b8}
.digline .dv{color:#7fd6a0}
.digline.unexpected .dv{color:#f87171;font-weight:600}
.digline .dx{color:#f87171;margin-left:10px}
.pathfoot{margin:10px 16px 14px;font-size:11.5px;color:var(--muted);
line-height:1.55}

.compare{display:grid;grid-template-columns:1fr auto 1fr;gap:14px;
align-items:stretch;margin-bottom:14px}
@media(max-width:900px){.compare{grid-template-columns:1fr}}
.ipset{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:14px 16px;box-shadow:var(--shadow)}
.ipset h4{margin:0 0 9px;font-size:11px;text-transform:uppercase;
letter-spacing:.07em;color:var(--muted);font-weight:700}
.ipset .ips{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;
line-height:1.85}
.ipset .ips .unexpected{color:var(--bad);font-weight:600}
.ipset .sub{margin:9px 0 0;font-size:11px;color:var(--muted)}
.verdictbox{display:flex;flex-direction:column;align-items:center;
justify-content:center;text-align:center;gap:4px;min-width:190px;
border-radius:10px;padding:16px 18px;border:1px solid var(--line);
background:var(--panel)}
.verdictbox.ok{background:var(--okbg);border-color:transparent;color:var(--ok)}
.verdictbox.warn{background:var(--warnbg);border-color:transparent;color:var(--warn)}
.verdictbox.bad{background:var(--badbg);border-color:transparent;color:var(--bad)}
.verdictbox .vlabel{font-size:10px;text-transform:uppercase;letter-spacing:.09em;
font-weight:700;opacity:.75}
.verdictbox .vword{font-size:21px;font-weight:700;letter-spacing:-.02em}
.verdictbox .vnote{font-size:11.5px;line-height:1.5;color:var(--muted);
max-width:26ch;margin-top:3px}
.verdictbox.ok .vnote,.verdictbox.warn .vnote,.verdictbox.bad .vnote{color:inherit;
opacity:.82}

.kv.wide{grid-template-columns:minmax(150px,240px) minmax(0,1fr);
gap:9px 18px;font-size:13px}
.kv.wide dt{color:var(--muted)}
.kv.wide dd .badink,.badink{color:var(--bad)}
.errorcard{border-left:3px solid var(--bad);background:var(--badbg);
border-radius:0 8px 8px 0;padding:14px 16px}
.errorcard b{display:block;font-size:14px;color:var(--bad)}
.errorcard p{margin:6px 0 0;font-family:ui-monospace,Consolas,monospace;
font-size:12.5px;color:var(--ink)}
.errorcard .sub{display:block;margin-top:8px;font-size:11.5px;color:var(--muted)}
button.secondary{background:var(--panel);color:var(--accent);
border:1px solid var(--line)}
button.secondary:hover{border-color:var(--accent);filter:none}
form.filters .field.grow{flex:1 1 220px}
form.filters .field.grow input{width:100%}

/* panel head with actions, and the embedded PDF preview */
.panel-head{display:flex;flex-wrap:wrap;gap:10px 16px;align-items:flex-start;
justify-content:space-between;padding:14px 17px;border-bottom:1px solid var(--line)}
.panel-head h3{margin:0}
.panel-head .sub{margin:2px 0 0}
.panel-actions{display:flex;gap:8px;flex-wrap:wrap}
.panel-actions .action{padding:7px 12px;font-size:12.5px}
/* Sized from the viewport, not a fixed block: a PDF has no intrinsic
   height, so a hard 620px reserved the same space on a 768px-tall laptop as
   on a 1440p screen and pushed everything beside it out of view. */
.pdfview{display:block;width:100%;height:clamp(320px,56vh,640px);
min-height:0;border:0;background:var(--bg)}

/* report builder */
.builder{display:block;background:var(--panel);border:1px solid var(--line);
border-radius:10px;padding:0;margin-bottom:18px;box-shadow:var(--shadow)}
/* Three height-balanced columns that fill the card width: report types on
   the left, time period stacked over format in the middle to match that
   height, options on the right. Balanced columns leave no void on a wide
   screen. Collapses to one column when genuinely narrow. */
.builder .steps.three{display:grid;
grid-template-columns:minmax(0,1.4fr) minmax(0,1.05fr) minmax(0,0.85fr);
gap:0;align-items:stretch}
.builder .step{padding:16px 18px;border-right:1px solid var(--line);
min-width:0}
.builder .step:last-child{border-right:none}
.builder .daterange{display:flex;gap:10px;flex-wrap:wrap}
.builder .daterange .field{flex:1 1 120px}
.builder .daterange input{width:100%}
@media(max-width:860px){
  .builder .steps.three{grid-template-columns:1fr}
  .builder .step{border-right:none;border-bottom:1px solid var(--line)}
  .builder .step:last-child{border-bottom:none}
}
.builder h4{margin:0 0 10px;font-size:12px;font-weight:700;color:var(--ink);
letter-spacing:.01em}
.builder h4.next{margin-top:16px}
.choices{display:flex;flex-direction:column;gap:6px}
.choices.row{flex-direction:row;flex-wrap:wrap;gap:8px 14px}
.choice{display:flex;gap:8px;align-items:flex-start;font-size:12.5px;
cursor:pointer;line-height:1.4}
.choice input{min-width:0;margin:2px 0 0;accent-color:var(--accent);flex:none}
.choice b{font-weight:600;display:block;color:var(--ink)}
.choice i{font-style:normal;display:block;color:var(--muted);font-size:11px;
margin-top:1px}
.builder .hint{font-size:11px;color:var(--muted);margin:8px 0 0}
.builder-actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}
.builder .footer{display:flex;gap:10px;flex-wrap:wrap;align-items:center;
justify-content:flex-end;padding:12px 18px;border-top:1px solid var(--line);
background:rgba(127,127,127,.03)}
.builder .footer .builder-actions{margin:0}
.builder .footer .hint{margin:0;margin-right:auto;max-width:52ch}
.builder .field{margin-bottom:8px}
button.primary{background:var(--accent);border-color:var(--accent)}

/* filter bar */
.filterbar{display:flex;flex-wrap:wrap;gap:9px;align-items:flex-end;
margin-bottom:14px}
.filterbar .grow{flex:1 1 190px;min-width:150px}
.filterbar .grow input{width:100%}

/* the printable report sheet */
.paper{background:var(--panel);border:1px solid var(--line);border-radius:10px;
box-shadow:var(--shadow);padding:26px 28px 30px;max-width:900px}
.paper-head{display:flex;flex-wrap:wrap;gap:14px;align-items:flex-start;
justify-content:space-between;border-bottom:2px solid var(--accent);
padding-bottom:14px;margin-bottom:18px}
.paper .logomark{width:196px;height:auto;flex:none}
.paper-meta{text-align:right;font-size:11.5px;color:var(--muted);line-height:1.7}
.paper-meta b{display:block;font-size:13.5px;color:var(--ink)}
.paper h2{font-size:17px;font-weight:650;margin:22px 0 4px;letter-spacing:-.01em;
text-transform:none;color:var(--ink)}
.paper h2:first-of-type{margin-top:0}
.paper h3{font-size:13px;font-weight:650;margin:18px 0 8px}
.paper .sub{font-size:11.5px;color:var(--muted);margin:0 0 10px;line-height:1.5}

/* evidence: the two resolution paths, side by side */
.paths{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));
gap:12px;margin-bottom:12px}
.pathbox{border:1px solid var(--line);border-radius:9px;padding:12px 14px;
background:var(--bg)}
.pathbox.untrusted{border-left:3px solid var(--bad)}
.pathbox.trusted{border-left:3px solid var(--ok)}
.pathbox h4{margin:0 0 3px;font-size:11px;text-transform:uppercase;
letter-spacing:.07em;color:var(--muted);font-weight:700}
.pathbox .cmd{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,
Consolas,monospace;font-size:11.5px;color:var(--ink);margin:6px 0;
word-break:break-all}
.pathbox .ans{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:12px;color:var(--ink);line-height:1.7}
.pathbox .ans .extra{color:var(--bad);font-weight:600}
.verdictline{display:flex;flex-wrap:wrap;gap:10px;align-items:center;
padding:11px 14px;border-radius:9px;background:var(--bg);
border:1px solid var(--line);font-size:12.5px;color:var(--muted)}
.verdictline b{font-size:13px}

/* findings list */
.findings{list-style:none;margin:0;padding:0}
.findings li{display:flex;gap:10px;align-items:flex-start;padding:8px 0;
font-size:13px;line-height:1.55;border-bottom:1px solid var(--line)}
.findings li:last-child{border-bottom:none}
.fmark{width:9px;height:9px;border-radius:50%;flex:none;margin-top:6px}
.fmark.ok{background:var(--ok)}.fmark.warn{background:var(--warn)}
.fmark.bad{background:var(--bad)}.fmark.info{background:var(--accent)}
.fmark.muted{background:var(--grey)}

/* per-resolver score cards */
.scores{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));
gap:12px;margin-bottom:14px}
.score{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:13px 15px;box-shadow:var(--shadow);border-top:3px solid var(--grey)}
.score.ok{border-top-color:var(--ok)}
.score.warn{border-top-color:var(--warn)}
.score.bad{border-top-color:var(--bad)}
.score .nm{display:block;font-size:13px;font-weight:650}
.score .v{display:block;font-size:25px;font-weight:700;letter-spacing:-.03em;
margin:4px 0 3px;font-variant-numeric:tabular-nums}
.score.ok .v{color:var(--ok)}.score.warn .v{color:var(--warn)}
.score.bad .v{color:var(--bad)}.score.muted .v{color:var(--muted)}
.score .st{font-size:10.5px}

/* donut */
.donutwrap{display:flex;flex-wrap:wrap;gap:18px;align-items:center}
.donut{flex:none;color:var(--ink)}
.donut svg{display:block}
.donut .arc.ok{stroke:var(--ok)}.donut .arc.warn{stroke:var(--warn)}
.donut .arc.bad{stroke:var(--bad)}.donut .arc.info{stroke:var(--accent)}
.donut .arc.muted{stroke:var(--grey)}
.donut .dv{font:700 20px/1 system-ui,sans-serif;fill:currentColor;
font-variant-numeric:tabular-nums}
.donut .dl{font:400 9px/1 system-ui,sans-serif;fill:currentColor;opacity:.6;
text-transform:uppercase;letter-spacing:.1em}
.donutlegend{list-style:none;margin:0;padding:0;flex:1 1 190px;min-width:180px}
.donutlegend li{display:flex;align-items:center;gap:8px;font-size:12.5px;
padding:5px 0;border-bottom:1px solid var(--line)}
.donutlegend li:last-child{border-bottom:none}
.donutlegend b{font-weight:600;flex:1 1 auto}
.donutlegend .n,.donutlegend .p{font-variant-numeric:tabular-nums;
color:var(--muted);font-size:12px}
.donutlegend .p{width:52px;text-align:right}
.swatch{width:9px;height:9px;border-radius:2px;flex:none}
.swatch.ok{background:var(--ok)}.swatch.warn{background:var(--warn)}
.swatch.bad{background:var(--bad)}.swatch.info{background:var(--accent)}
.swatch.muted{background:var(--grey)}

pre.cmd{background:var(--bg);border:1px solid var(--line);border-radius:7px;
padding:11px 13px;overflow-x:auto;font-family:ui-monospace,SFMono-Regular,Menlo,
Consolas,monospace;font-size:12px;color:var(--ink);margin:0 0 10px}

@media(prefers-reduced-motion:reduce){*{transition:none!important}}
@media print{.rail,.appbar{display:none}.topbar{position:static}
body{background:#fff}.tablewrap,.card,.panel,.kpi{box-shadow:none}}
@media(max-width:820px){.layout{flex-direction:column}
.rail{width:auto;flex-direction:row;flex-wrap:wrap;padding:12px;
align-items:center}
.brand{border:none;margin:0;padding:0 14px 0 6px}
.brand .wm b{font-size:19px}
.railfoot{display:none}
.navlink{border-left:none;border-bottom:3px solid transparent;padding:8px 12px}
.navlink.active{border-left:none;border-bottom-color:#7fb0e0}
.content{padding:20px 16px 32px}.topbar{padding:12px 16px}
.appbar{padding:12px 16px}}
"""

_DOC = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus &mdash; {title}</title>{meta_refresh}<style>{css}</style></head>
<body><div class="layout">
<nav class="rail">
  <div class="brand">{eye}<div class="wm"><b>ARGUS</b>
    <span>National DNS Monitoring</span></div></div>
  {nav}
  <div class="railspacer"></div>
  <div class="railfoot">
    {lanka}
    <div class="quote">&ldquo;A safer internet for a stronger Sri Lanka&rdquo;</div>
    <div class="caveat">Single vantage point.<br>Verdicts are evidence, not proof.</div>
  </div>
</nav>
<div class="main">
  <div class="topbar">
    <div>
      <div class="tagline">Watching today for a safer tomorrow</div>
      <div class="pillars">Monitor &nbsp;&middot;&nbsp; Detect &nbsp;&middot;&nbsp; Protect</div>
    </div>
    <div class="stamp">{clock}<div><b>{generated}</b>
      vantage {vantage} ({zone}){scope}</div></div>
  </div>
  <div class="content">
    {pagehead}
    {body}
    <footer class="caveat">
      Status labels are derived from stored raw metrics, not an opaque score.
      &ldquo;Possible cache poisoning&rdquo; means a resolver persistently served data that
      no authoritative source and no independent resolver corroborates. It is
      <em>not</em> proven poisoning: from a single vantage point a forged record and
      legitimate CDN or geographic variance can look identical.
    </footer>
  </div>
  <div class="appbar">
    <div class="l"><b>ARGUS</b><span class="sep">|</span>
      <span>DNS caching-server health &amp; cache-poisoning monitor</span>
      <span class="sep">|</span><span>Sri Lanka</span></div>
    <div class="r">Monitor the DNS. Secure the future.</div>
  </div>
</div>
</div></body></html>"""
