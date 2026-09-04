"""SHELL — page chrome, styling, and the formatting helpers pages share.

The dashboard is a set of small pages rather than one long scroll. This module
owns everything common to all of them: the navigation, the header, the
stylesheet, and the value formatters. It reads nothing from the database itself.

Every page is a single self-contained HTML file with no script and no external
asset, so it opens from the filesystem, over the built-in server, or from a
printed PDF with identical results.
"""

from __future__ import annotations

import html
import time

# key, static filename, server path, title, purpose blurb
PAGES = (
    ("overview", "report.html", "/", "Overview",
     "System-wide status at a glance. Detail lives on the pages below."),
    ("resolvers", "resolvers.html", "/resolvers", "Resolver Health",
     "Availability, latency, correctness and freshness for every monitored "
     "caching resolver."),
    ("poisoning", "poisoning.html", "/poisoning", "Cache Poisoning Detection",
     "Events where a resolver served data no independent source corroborates, "
     "with the full evidence behind each verdict."),
    ("queries", "queries.html", "/queries", "DNS Query Monitor",
     "Every measurement taken, searchable and filterable."),
    ("anomalies", "anomalies.html", "/anomalies", "Anomaly Investigation",
     "Differences under review, and the legitimate explanations each was "
     "tested against."),
    ("verification", "verification.html", "/verification", "Independent Verification",
     "Query one resolver against trusted resolvers and the authoritative "
     "hierarchy, live."),
    ("reports", "reports.html", "/reports", "Reports",
     "Summaries suitable for inclusion in a written report."),
)

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


# -- page chrome ------------------------------------------------------------

def _nav(active: str, live: bool) -> str:
    out = ""
    for key, _file, _path, title, _blurb in PAGES:
        cls = "navlink active" if key == active else "navlink"
        out += ('<a class="' + cls + '" href="' + link(key, live) + '">'
                + e(title) + "</a>")
    return out


EYE = ('<svg class="eye" viewBox="0 0 48 48" fill="none" stroke="currentColor" '
       'stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" '
       'aria-hidden="true">'
       '<path d="M2 24s8-13 22-13 22 13 22 13-8 13-22 13S2 24 2 24z"/>'
       '<circle cx="24" cy="24" r="6.5"/>'
       '<circle cx="24" cy="24" r="1.8" fill="currentColor" stroke="none"/></svg>')


def page(active: str, vantage: str, body: str, live: bool = False,
         refresh_seconds: int = 0, scope: str = "") -> str:
    """Wrap page content in the shared chrome and return a complete document.

    `scope` is an optional summary of what is being monitored -- resolver and
    domain counts, and the interval -- so a screenshot of any page carries
    enough context to be read on its own.
    """
    key, _file, _path, title, blurb = PAGE_BY_KEY[active]
    meta_refresh = ('<meta http-equiv="refresh" content="%d">' % int(refresh_seconds)
                    if refresh_seconds and refresh_seconds > 0 else "")
    return _DOC.format(
        css=_CSS, meta_refresh=meta_refresh, eye=EYE,
        nav=_nav(active, live), title=e(title), blurb=e(blurb),
        vantage=e(vantage), scope=(" &middot; " + e(scope)) if scope else "",
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
        body=body,
    )


_CSS = """
:root{--bg:#f2f4f7;--panel:#fff;--ink:#16202b;--muted:#5f6b7a;--line:#dde3ea;
--rail:#12304f;--railink:#c9dcef;--railactive:#fff;--accent:#1f5c96;
--ok:#116b3a;--okbg:#e5f4ec;--warn:#8a5a05;--warnbg:#fdf2dd;
--bad:#b0271f;--badbg:#fdebe9;--grey:#5f6b7a;--greybg:#eceff3;
--shadow:0 1px 2px rgba(16,24,40,.05),0 3px 10px rgba(16,24,40,.05)}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){
--bg:#0b1016;--panel:#151b23;--ink:#e4e9ef;--muted:#8b97a5;--line:#232c37;
--rail:#0d1720;--railink:#8fa8c2;--railactive:#fff;--accent:#7fb0e0;
--ok:#4ade80;--okbg:#0e2419;--warn:#fbbf24;--warnbg:#2a2210;
--bad:#f87171;--badbg:#2b1315;--grey:#8b97a5;--greybg:#1c232c;
--shadow:0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.3)}}
:root[data-theme="dark"]{
--bg:#0b1016;--panel:#151b23;--ink:#e4e9ef;--muted:#8b97a5;--line:#232c37;
--rail:#0d1720;--railink:#8fa8c2;--railactive:#fff;--accent:#7fb0e0;
--ok:#4ade80;--okbg:#0e2419;--warn:#fbbf24;--warnbg:#2a2210;
--bad:#f87171;--badbg:#2b1315;--grey:#8b97a5;--greybg:#1c232c;
--shadow:0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.3)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14.5px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Ubuntu","Segoe UI",
Roboto,Helvetica,Arial,sans-serif;
-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
text-rendering:optimizeLegibility}
/* Digits line up in every column: counts, latencies, percentages. */
td,th,.card .n,.metric .v,.pager{font-variant-numeric:tabular-nums}
a{color:var(--accent)}
.layout{display:flex;min-height:100vh;align-items:stretch}

/* sidebar */
.rail{width:212px;flex:none;background:var(--rail);color:var(--railink);
padding:20px 0 30px;display:flex;flex-direction:column}
.brand{display:flex;align-items:center;gap:11px;padding:0 18px 18px;
border-bottom:1px solid rgba(255,255,255,.1);margin-bottom:12px}
.eye{width:31px;height:31px;flex:none;color:#7fb0e0}
.brand b{color:#fff;font-size:15.5px;line-height:1.25;font-weight:650;
letter-spacing:-.01em}
.navlink{display:block;padding:10px 18px;color:var(--railink);text-decoration:none;
font-size:13.5px;border-left:3px solid transparent;
transition:background .16s ease,color .16s ease,border-color .16s ease}
.navlink:hover{background:rgba(255,255,255,.07);color:#fff}
.navlink:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.navlink.active{background:rgba(255,255,255,.1);color:var(--railactive);
border-left-color:var(--accent);font-weight:600}
.railfoot{margin-top:auto;padding:14px 18px 0;font-size:10.5px;color:var(--railink);
opacity:.75;line-height:1.6}

/* main column */
.main{flex:1 1 auto;min-width:0;display:flex;flex-direction:column}
.topbar{background:var(--panel);border-bottom:1px solid var(--line);
padding:14px 26px;position:sticky;top:0;z-index:2}
.topbar h1{margin:0;font-size:15px;font-weight:650;letter-spacing:-.012em}
.topbar .tagline{color:var(--ink);opacity:.72;font-size:12.5px;margin-top:3px;
max-width:78ch;line-height:1.45}
.topbar .meta{color:var(--muted);font-size:11.5px;margin-top:5px}
.content{padding:24px 26px 56px;max-width:1180px}
.ptitle{margin:0 0 5px;font-size:22px;font-weight:650;letter-spacing:-.018em;
text-wrap:balance}
.pblurb{margin:0 0 24px;color:var(--muted);font-size:13.5px;max-width:68ch;
line-height:1.55}
h2{font-size:11px;margin:32px 0 11px;color:var(--muted);font-weight:700;
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

/* stat cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(146px,1fr));gap:12px;
margin-bottom:8px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:13px 15px 15px;box-shadow:var(--shadow)}
.card .l{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;
color:var(--muted);font-weight:650}
.card .n{font-size:28px;font-weight:700;margin-top:7px;letter-spacing:-.025em;
line-height:1.15;font-variant-numeric:tabular-nums}
.card.ok .n{color:var(--ok)}.card.warn .n{color:var(--warn)}
.card.bad .n{color:var(--bad)}.card.muted .n{color:var(--muted)}

/* tables */
.tablewrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);
border-radius:10px;box-shadow:var(--shadow);margin-bottom:6px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);
white-space:nowrap;vertical-align:middle}
th{color:var(--muted);font-weight:650;text-transform:uppercase;font-size:10px;
letter-spacing:.08em;background:rgba(127,127,127,.05);white-space:nowrap}
tbody tr:last-child td{border-bottom:none}
tbody tr{transition:background .14s ease}
tbody tr:hover td{background:rgba(127,127,127,.05)}
tr.dim td{opacity:.55}
td.wrap{white-space:normal;max-width:460px;line-height:1.5}

/* badges + chips */
.badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:10.5px;
font-weight:700;letter-spacing:.03em}
.badge.tiny{font-size:9.5px;padding:2px 7px}
.badge.ok{background:var(--okbg);color:var(--ok)}
.badge.warn{background:var(--warnbg);color:var(--warn)}
.badge.bad{background:var(--badbg);color:var(--bad)}
.badge.muted{background:var(--greybg);color:var(--grey)}
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
border:1px solid transparent;background:var(--accent);color:#fff;cursor:pointer}
button:hover{filter:brightness(1.08)}
button:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
a{transition:color .14s ease}
a.btn{display:inline-block;text-decoration:none;font-size:12.5px;font-weight:600;
padding:7px 13px;border-radius:7px;border:1px solid var(--line);
background:var(--panel);color:var(--accent);
transition:background .16s ease,border-color .16s ease}
a.btn:hover{border-color:var(--accent);background:var(--bg)}
a.btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
button{transition:filter .16s ease}
a.btn.off{color:var(--muted);opacity:.5;pointer-events:none}

/* pagination + misc */
.pager{display:flex;gap:9px;align-items:center;margin-top:12px;font-size:12.5px;
color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.small{font-size:12px}.muted{color:var(--muted)}
.empty{color:var(--muted);font-style:italic;text-align:center;padding:20px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:14px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:15px 17px;box-shadow:var(--shadow)}
.panel h3{margin:0 0 9px;font-size:13px;font-weight:650}
.kv{display:grid;grid-template-columns:auto 1fr;gap:5px 14px;font-size:12.5px}
.kv dt{color:var(--muted)}.kv dd{margin:0}
.stages{list-style:none;margin:0;padding:0;font-size:12.5px}
.stages li{padding:8px 0;border-bottom:1px solid var(--line)}
.stages li:last-child{border-bottom:none}
.stages b{display:block;font-size:11px;text-transform:uppercase;
letter-spacing:.06em;color:var(--muted)}
footer{color:var(--muted);font-size:11.5px;margin-top:32px;border-top:1px solid var(--line);
padding-top:14px;line-height:1.7;max-width:80ch}
@media print{.rail{display:none}.topbar{position:static}
body{background:#fff}.tablewrap,.card,.panel{box-shadow:none}}
@media(max-width:820px){.layout{flex-direction:column}
.rail{width:auto;flex-direction:row;flex-wrap:wrap;padding:12px}
.brand{border:none;margin:0;padding:0 12px 0 6px}
.railfoot{display:none}.navlink{border-left:none;border-bottom:3px solid transparent}
.navlink.active{border-left:none;border-bottom-color:var(--accent)}}
"""

_DOC = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus &mdash; {title}</title>{meta_refresh}<style>{css}</style></head>
<body><div class="layout">
<nav class="rail">
  <div class="brand">{eye}<b>Argus<br>DNS Monitor</b></div>
  {nav}
  <div class="railfoot">Single vantage point.<br>Verdicts are evidence, not proof.</div>
</nav>
<div class="main">
  <div class="topbar">
    <h1>Argus &mdash; DNS Caching-Server Health &amp; Cache-Poisoning Monitor</h1>
    <div class="tagline">Independently verifying public caching DNS resolvers
      against the authoritative DNS hierarchy</div>
    <div class="meta">vantage <b>{vantage}</b>{scope} &middot; generated {generated}</div>
  </div>
  <div class="content">
    <h1 class="ptitle">{title}</h1>
    <p class="pblurb">{blurb}</p>
    {body}
    <footer>
      Status labels are derived from stored raw metrics, not an opaque score.
      &ldquo;Possible cache poisoning&rdquo; means a resolver persistently served data that
      no authoritative source and no independent resolver corroborates. It is
      <em>not</em> proven poisoning: from a single vantage point a forged record and
      legitimate CDN or geographic variance can look identical.
    </footer>
  </div>
</div>
</div></body></html>"""
