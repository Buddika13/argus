"""DASHBOARD — static HTML generator.

Reads the database and renders a single self-contained HTML page (no server, no
Docker, no external assets). Clean, academic/research styling. Reuses the
existing storage query methods; it only reads, so it cannot affect the backend.

Resolver status is a transparent label derived from stored raw metrics — NOT an
opaque numeric score:

    NO DATA   no health metrics recorded yet
    ALERT     a possible cache-poisoning event, or possible_poisoning_rate > 0
    ANOMALY   anomaly_rate > 0 (but no confirmed poisoning)
    DEGRADED  availability < 100% or freshness DEGRADED
    HEALTHY   available, correct, fresh, no anomalies
"""

from __future__ import annotations

import html
import json
import time
from pathlib import Path

from .storage import Storage


def render(storage: Storage, vantage: str = "local", refresh_seconds: int = 0) -> str:
    """Render the dashboard HTML from the live database. Reads only."""
    resolvers = storage.list_resolvers()
    rows = [_resolver_summary(storage, r) for r in resolvers]
    counts = storage.table_counts()
    healthy = sum(1 for x in rows if x["status"] == "HEALTHY")

    # Resolvers that are actually reporting come first, most serious first;
    # unconfigured placeholders sink to the bottom instead of heading the table.
    rows.sort(key=lambda x: (_STATUS_ORDER.get(x["status"], 9), x["name"]))

    # "No data" is shown explicitly rather than invented.
    has_data = counts.get("query_results", 0) > 0 or counts.get("health_metrics", 0) > 0
    banner = "" if has_data else (
        '<div class="banner">No monitoring data available yet. Run a sweep with '
        '<code>argus run-once</code> (or <code>argus serve</code>), then reload.</div>')
    meta_refresh = (f'<meta http-equiv="refresh" content="{int(refresh_seconds)}">'
                    if refresh_seconds and refresh_seconds > 0 else "")

    return _PAGE.format(
        css=_CSS, meta_refresh=meta_refresh, banner=banner,
        verdict=_verdict(counts.get("alerts", 0), counts.get("anomalies", 0), has_data),
        vantage=_e(vantage), generated=time.strftime("%Y-%m-%d %H:%M:%S"),
        cards=_cards(counts, rows, healthy),
        resolver_rows=_resolver_table(rows),
        events=_events(storage), anomalies=_anomalies(storage), alerts=_alerts(storage),
    )


def generate(storage: Storage, output: Path, vantage: str = "local") -> Path:
    """Write a one-off static snapshot of the dashboard to a file."""
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(storage, vantage), encoding="utf-8")
    return out


def build_server(db_path, vantage: str = "local", host: str = "127.0.0.1",
                 port: int = 8080, refresh: int = 15):
    """An HTTPServer that re-renders from the database on every request.

    Each request opens its own read connection, so the page always reflects the
    latest data the backend has written — this is the live backend→DB→dashboard
    connection. Uses only the standard library (no Docker, no web framework).
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.split("?")[0] not in ("/", "/index.html"):
                self.send_error(404)
                return
            storage = Storage(db_path)
            try:
                body = render(storage, vantage, refresh_seconds=refresh).encode("utf-8")
            finally:
                storage.close()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            pass  # keep the console quiet

    return HTTPServer((host, port), Handler)


def serve(db_path, vantage: str = "local", host: str = "127.0.0.1",
          port: int = 8080, refresh: int = 15) -> None:
    httpd = build_server(db_path, vantage, host, port, refresh)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


# -- per resolver -----------------------------------------------------------
def _resolver_summary(storage: Storage, r) -> dict:
    h = storage.latest_health(r["name"])
    d = storage.latest_dnssec(r["name"])
    history = storage.metric_history(r["name"], limit=30)

    availability = h["availability_pct"] if h else None
    correctness = h["correctness_rate"] if h else None
    anomaly_rate = h["anomaly_rate"] if h else None
    poison_rate = h["possible_poisoning_rate"] if h else None
    freshness = h["freshness_status"] if h else None
    latency = h["avg_latency_ms"] if h else None
    last = h["window_end"] or h["computed_at"] if h else None

    status = _status(h, poison_rate, anomaly_rate, availability, freshness)
    dnssec = f'{d["security"]} / {d["posture"]}' if d else "—"

    return {
        "name": r["name"], "ip": r["address"], "role": r["role"], "status": status,
        "availability": availability, "correctness": correctness, "freshness": freshness,
        "latency": latency, "dnssec": dnssec, "last": last,
        "spark": _sparkline([row["availability_pct"] for row in reversed(history)
                             if row["availability_pct"] is not None]),
    }


def _status(h, poison_rate, anomaly_rate, availability, freshness) -> str:
    if h is None:
        return "NO DATA"
    if (poison_rate or 0) > 0:
        return "ALERT"
    if (anomaly_rate or 0) > 0:
        return "ANOMALY"
    if (availability is not None and availability < 100) or freshness == "DEGRADED":
        return "DEGRADED"
    return "HEALTHY"


# -- rendering helpers ------------------------------------------------------
def _e(x) -> str:
    return html.escape(str(x))


def _pct(x) -> str:
    return f"{x:.0f}%" if isinstance(x, (int, float)) else "—"


def _rate(x) -> str:
    return f"{x * 100:.0f}%" if isinstance(x, (int, float)) else "—"


def _ms(x) -> str:
    return f"{x:.0f} ms" if isinstance(x, (int, float)) else "—"


def _ts(x) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(x)) if x else "—"


def _badge(status: str) -> str:
    cls = {"HEALTHY": "ok", "DEGRADED": "warn", "ANOMALY": "warn",
           "ALERT": "bad", "NO DATA": "muted"}.get(status, "muted")
    return f'<span class="badge {cls}">{_e(status)}</span>'


def _sparkline(values: list[float]) -> str:
    if len(values) < 2:
        return '<span class="muted">—</span>'
    w, h = 90, 20
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    step = w / (len(values) - 1)
    pts = " ".join(f"{i * step:.1f},{h - (v - lo) / span * (h - 2) - 1:.1f}"
                   for i, v in enumerate(values))
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'preserveAspectRatio="none"><polyline points="{pts}" fill="none" '
            f'stroke="currentColor" stroke-width="1.5"/></svg>')


_STATUS_ORDER = {"ALERT": 0, "ANOMALY": 1, "DEGRADED": 2, "HEALTHY": 3, "NO DATA": 8}

_ICONS = {
    "resolvers": "M4 6h16M4 12h16M4 18h10",
    "healthy": "M4 12l5 5L20 6",
    "anomalies": "M12 4v9m0 4v.5M3 20h18L12 3z",
    "poisoning": "M12 3a9 9 0 100 18 9 9 0 000-18zM8 8l8 8m0-8l-8 8",
    "queries": "M4 19V9m5 10V5m5 14v-7m5 7V8",
}


def _icon(path: str) -> str:
    return ('<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="' + path + '"/></svg>')


def _verdict(alerts: int, anomalies: int, has_data: bool) -> str:
    """One unambiguous headline: is anything wrong right now?"""
    if not has_data:
        return ('<div class="verdict idle">' + _icon(_ICONS["queries"]) +
                '<div><b>Awaiting first sweep</b>'
                '<span>No measurements have been recorded yet.</span></div></div>')
    if alerts:
        plural = "event" if alerts == 1 else "events"
        return ('<div class="verdict bad">' + _icon(_ICONS["poisoning"]) +
                '<div><b>' + str(alerts) + ' possible cache-poisoning ' + plural + '</b>'
                '<span>An integrity anomaly survived every independent check. '
                'Possible &mdash; not proven.</span></div></div>')
    if anomalies:
        return ('<div class="verdict warn">' + _icon(_ICONS["anomalies"]) +
                '<div><b>' + str(anomalies) + ' integrity anomalies, none confirmed</b>'
                '<span>Differences were seen, but independent checks explained them '
                'benignly.</span></div></div>')
    return ('<div class="verdict ok">' + _icon(_ICONS["healthy"]) +
            '<div><b>All clear</b><span>Every monitored resolver agreed with the '
            'authoritative hierarchy.</span></div></div>')


def _cards(counts, rows, healthy) -> str:
    data = [
        ("neutral", len(rows), "resolvers", "resolvers"),
        ("ok", healthy, "healthy", "healthy"),
        ("warn", counts.get("anomalies", 0), "anomalies", "anomalies"),
        ("bad", counts.get("alerts", 0), "possible poisoning", "poisoning"),
        ("neutral", counts.get("query_results", 0), "queries recorded", "queries"),
    ]
    return "".join(
        '<div class="card ' + c + '"><div class="chead">' + _icon(_ICONS[i]) +
        '<span class="l">' + _e(l) + '</span></div>'
        '<div class="n">' + str(n) + '</div></div>'
        for c, n, l, i in data)


def _role_chip(role) -> str:
    is_control = (role or "").lower() == "control"
    kind = "control" if is_control else "subject"
    label = "CONTROL" if is_control else "MONITORED"
    return '<span class="chip ' + kind + '">' + label + '</span>'


def _latency_bar(value, ceiling: float) -> str:
    """A latency figure with a proportional bar, so slow resolvers stand out."""
    if not isinstance(value, (int, float)):
        return '<span class="muted">&mdash;</span>'
    width = max(3.0, min(100.0, value / ceiling * 100.0)) if ceiling else 3.0
    tone = "ok" if value < 60 else "warn" if value < 150 else "bad"
    return ('<div class="lat"><span class="v">' + "%.0f ms" % value + '</span>'
            '<span class="bar"><i class="' + tone + '" style="width:'
            + "%.0f" % width + '%"></i></span></div>')


def _resolver_table(rows) -> str:
    if not rows:
        return '<tr><td colspan="10" class="empty">No data available.</td></tr>'
    ceiling = max([x["latency"] for x in rows
                   if isinstance(x["latency"], (int, float))] or [1.0])
    out = ""
    for x in rows:
        dim = " dim" if x["status"] == "NO DATA" else ""
        out += (
            "<tr class='rrow" + dim + "'>"
            "<td><b>" + _e(x["name"]) + "</b> " + _role_chip(x.get("role")) + "</td>"
            "<td class='mono'>" + _e(x["ip"]) + "</td>"
            "<td>" + _badge(x["status"]) + "</td>"
            "<td>" + _pct(x["availability"]) + "</td>"
            "<td>" + _latency_bar(x["latency"], ceiling) + "</td>"
            "<td>" + _rate(x["correctness"]) + "</td>"
            "<td>" + _e(x["freshness"] or "—") + "</td>"
            "<td class='mono small'>" + _e(x["dnssec"]) + "</td>"
            "<td class='trend'>" + x["spark"] + "</td>"
            "<td class='small muted'>" + _ts(x["last"]) + "</td></tr>")
    return out


def _events(storage) -> str:
    rows = storage.recent_events(15)
    if not rows:
        return '<tr><td colspan="5" class="empty">No data available.</td></tr>'
    return "".join(
        "<tr><td class='small muted'>" + _ts(r["timestamp"]) + "</td>"
        "<td><b>" + _e(r["resolver"]) + "</b></td>"
        "<td>" + _e(r["domain"]) + " <span class='chip type'>"
        + _e(r["query_type"]) + "</span></td>"
        "<td class='mono small'>" + _e(r["rcode"]) + "</td>"
        "<td>" + _class_badge(r["comparison_classification"]) + "</td></tr>"
        for r in rows)


def _anomalies(storage) -> str:
    rows = storage.recent_anomalies(15)
    if not rows:
        return '<tr><td colspan="5" class="empty">No data available.</td></tr>'
    return "".join(
        "<tr><td class='small muted'>" + _ts(r["observed_at"]) + "</td>"
        "<td><b>" + _e(r["resolver"]) + "</b></td>"
        "<td>" + _e(r["domain"]) + " <span class='chip type'>"
        + _e(r["rtype"]) + "</span></td>"
        "<td>" + _class_badge(r["classification"]) + "</td>"
        "<td class='small'>" + _e(r["verification_state"]) + "</td></tr>"
        for r in rows)


def _evidence_summary(raw) -> str:
    """A readable summary of a stored evidence chain, rather than a JSON dump."""
    try:
        ev = json.loads(raw)
    except (TypeError, ValueError):
        return "<span class='mono small'>" + _e(raw) + "</span>"

    bits = []
    unpublished = (ev.get("stage1") or {}).get("unpublished") or []
    if unpublished:
        shown = ", ".join(unpublished[:3])
        more = " +%d" % (len(unpublished) - 3) if len(unpublished) > 3 else ""
        bits.append("returned <b class='badink'>" + _e(shown + more) +
                    "</b>, which the zone never published")
    controls = ev.get("stage3_controls") or {}
    if controls.get("queried") and not controls.get("corroborates_unexpected"):
        bits.append("%d independent resolvers disagreed" % len(controls["queried"]))
    persistence = ev.get("stage5_persistence") or {}
    if persistence.get("persistent"):
        bits.append("persisted across %s/%s repeats" % (
            persistence.get("reproduced", "?"), persistence.get("repetitions", "?")))
    if (ev.get("stage4_dnssec") or {}).get("zone_signed"):
        bits.append("on a DNSSEC-signed zone")
    return "; ".join(bits) or "<span class='muted'>see stored evidence</span>"


def _alerts(storage) -> str:
    rows = storage.recent_alerts(15)
    if not rows:
        return ('<tr><td colspan="4" class="empty allclear">'
                'No possible cache-poisoning events. All clear.</td></tr>')
    return "".join(
        "<tr><td class='small muted'>" + _ts(r["confirmed_at"]) + "</td>"
        "<td><b>" + _e(r["resolver"]) + "</b></td>"
        "<td>" + _e(r["domain"]) + " <span class='chip type'>"
        + _e(r["rtype"]) + "</span></td>"
        "<td class='ev'>" + _evidence_summary(r["evidence"]) + "</td></tr>"
        for r in rows)


def _class_badge(cls) -> str:
    cls = cls or "—"
    good = {"NORMAL", "BENIGN_DIFFERENCE"}
    bad = {"POSSIBLE_CACHE_POISONING", "DNS_INTEGRITY_ANOMALY"}
    kind = "ok" if cls in good else "bad" if cls in bad else \
        "warn" if cls != "—" else "muted"
    return '<span class="badge ' + kind + ' tiny">' + _e(cls) + "</span>"


# -- static template + styles ----------------------------------------------
_CSS = """
:root{--bg:#eef1f6;--card:#fff;--ink:#141a21;--muted:#65707d;--line:#dfe4ec;
--ok:#0e6b3d;--okbg:#e3f5ec;--warn:#8a5a00;--warnbg:#fdf1da;--bad:#b3261e;--badbg:#fdeceb;
--accent:#123a63;--accent2:#2f6fb0;--shadow:0 1px 2px rgba(16,24,40,.06),0 4px 14px rgba(16,24,40,.06)}
@media(prefers-color-scheme:dark){:root{--bg:#0c1015;--card:#161b22;--ink:#e6e9ee;
--muted:#8e99a6;--line:#242c36;--ok:#4ade80;--okbg:#0d2419;--warn:#fbbf24;--warnbg:#2a2210;
--bad:#f87171;--badbg:#2c1315;--accent:#8fb6e4;--accent2:#5f9bd8;
--shadow:0 1px 2px rgba(0,0,0,.4),0 6px 20px rgba(0,0,0,.35)}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.55 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
-webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px 64px}

/* masthead */
.mast{background:linear-gradient(135deg,#0d2c4d 0%,#123a63 45%,#1d5286 100%);
color:#eaf2fb;margin:0 -20px 26px;padding:26px 20px 24px;box-shadow:var(--shadow)}
.mastin{max-width:1140px;margin:0 auto;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.eye{width:38px;height:38px;flex:none;opacity:.95}
.mast h1{font-size:19px;margin:0;font-weight:650;letter-spacing:-.01em;color:#fff}
.mast .sub{color:#b6cbe4;font-size:12.5px;margin-top:2px}
.mast .sub b{color:#eaf2fb;font-weight:600}
.spacer{flex:1 1 auto}
.live{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#b6cbe4;
border:1px solid rgba(255,255,255,.28);border-radius:999px;padding:4px 11px}

/* verdict banner */
.verdict{display:flex;align-items:center;gap:13px;border-radius:12px;padding:15px 18px;
margin-bottom:20px;border:1px solid var(--line);background:var(--card);box-shadow:var(--shadow)}
.verdict .ico{width:26px;height:26px;flex:none}
.verdict b{display:block;font-size:15px;letter-spacing:-.01em}
.verdict span{display:block;color:var(--muted);font-size:12.5px;margin-top:1px}
.verdict.ok{background:var(--okbg);border-color:transparent;color:var(--ok)}
.verdict.bad{background:var(--badbg);border-color:transparent;color:var(--bad)}
.verdict.warn{background:var(--warnbg);border-color:transparent;color:var(--warn)}
.verdict.ok b,.verdict.bad b,.verdict.warn b{color:inherit}
.verdict.idle{color:var(--muted)}

h2{font-size:12px;margin:30px 0 11px;color:var(--muted);font-weight:650;
text-transform:uppercase;letter-spacing:.09em}

/* stat cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:15px 17px 17px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.card:before{content:"";position:absolute;inset:0 0 auto 0;height:3px;background:var(--muted);opacity:.5}
.card.ok:before{background:var(--ok);opacity:1}
.card.warn:before{background:var(--warn);opacity:1}
.card.bad:before{background:var(--bad);opacity:1}
.card.neutral:before{background:var(--accent2);opacity:.9}
.chead{display:flex;align-items:center;gap:7px;color:var(--muted)}
.chead .ico{width:14px;height:14px;flex:none}
.card .l{font-size:11px;text-transform:uppercase;letter-spacing:.06em;font-weight:600}
.card .n{font-size:31px;font-weight:700;letter-spacing:-.02em;margin-top:7px;
font-variant-numeric:tabular-nums}
.card.ok .n{color:var(--ok)}.card.warn .n{color:var(--warn)}.card.bad .n{color:var(--bad)}

/* tables */
.tablewrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);
border-radius:12px;box-shadow:var(--shadow)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--muted);font-weight:650;text-transform:uppercase;font-size:10.5px;
letter-spacing:.07em;background:rgba(127,127,127,.05)}
tr:last-child td{border-bottom:none}
tbody tr:hover td,.rrow:hover td{background:rgba(127,127,127,.045)}
.rrow.dim td{opacity:.5}

/* badges + chips */
.badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:10.5px;
font-weight:700;letter-spacing:.04em}
.badge.tiny{font-size:9.5px;padding:2px 7px;letter-spacing:.03em}
.badge.ok{background:var(--okbg);color:var(--ok)}
.badge.warn{background:var(--warnbg);color:var(--warn)}
.badge.bad{background:var(--badbg);color:var(--bad)}
.badge.muted{background:rgba(127,127,127,.13);color:var(--muted)}
.chip{display:inline-block;font-size:9.5px;font-weight:700;letter-spacing:.05em;
padding:1px 6px;border-radius:4px;vertical-align:1px;
background:rgba(127,127,127,.13);color:var(--muted)}
.chip.control{background:rgba(47,111,176,.14);color:var(--accent2)}
.chip.subject{background:rgba(127,127,127,.14);color:var(--muted)}

/* latency bar */
.lat{min-width:104px}
.lat .v{font-variant-numeric:tabular-nums;font-size:12.5px}
.lat .bar{display:block;height:4px;border-radius:3px;background:rgba(127,127,127,.16);
margin-top:4px;overflow:hidden}
.lat .bar i{display:block;height:100%;border-radius:3px;background:var(--muted)}
.lat .bar i.ok{background:var(--ok)}
.lat .bar i.warn{background:var(--warn)}
.lat .bar i.bad{background:var(--bad)}

.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.small{font-size:12px}.muted{color:var(--muted)}
.trend{color:var(--accent2)}
.ev{white-space:normal;max-width:520px;font-size:12.5px;line-height:1.5}
.badink{color:var(--bad)}
.empty{color:var(--muted);font-style:italic;text-align:center;padding:20px}
.empty.allclear{color:var(--ok);font-style:normal;font-weight:600}
.banner{background:var(--warnbg);color:var(--warn);border-radius:10px;
padding:13px 16px;margin-bottom:18px;font-size:13px}
.banner code{font-family:ui-monospace,Consolas,monospace;
background:rgba(0,0,0,.07);padding:1px 5px;border-radius:4px}
footer{color:var(--muted);font-size:11.5px;margin-top:34px;line-height:1.75;
border-top:1px solid var(--line);padding-top:16px}
@media print{body{background:#fff}.mast{background:#123a63!important;
-webkit-print-color-adjust:exact;print-color-adjust:exact}
.tablewrap,.card,.verdict{box-shadow:none}}
@media(max-width:640px){.mast h1{font-size:16px}.card .n{font-size:26px}}
"""

_EYE = ('<svg class="eye" viewBox="0 0 48 48" fill="none" stroke="currentColor" '
        'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M2 24s8-13 22-13 22 13 22 13-8 13-22 13S2 24 2 24z"/>'
        '<circle cx="24" cy="24" r="6.5"/><circle cx="24" cy="24" r="1.8" '
        'fill="currentColor" stroke="none"/></svg>')

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus &mdash; Monitoring Dashboard</title>{meta_refresh}<style>{css}</style></head>
<body>
<div class="mast"><div class="mastin">
  """ + _EYE + """
  <div>
    <h1>Argus &mdash; DNS Caching-Server Health &amp; Cache-Poisoning Monitor</h1>
    <div class="sub">vantage <b>{vantage}</b> &middot; generated {generated}</div>
  </div>
  <div class="spacer"></div>
  <div class="live">Independent verification</div>
</div></div>

<div class="wrap">
{banner}
{verdict}

<h2>Overall system status</h2>
<div class="cards">{cards}</div>

<h2>Monitored resolvers</h2>
<div class="tablewrap"><table>
<tr><th>Resolver</th><th>IP</th><th>Status</th><th>Availability</th><th>Avg latency</th>
<th>Correctness</th><th>Freshness</th><th>DNSSEC</th><th>Availability trend</th>
<th>Last checked</th></tr>
{resolver_rows}
</table></div>

<h2>Possible cache-poisoning events</h2>
<div class="tablewrap"><table>
<tr><th>When</th><th>Resolver</th><th>Domain</th><th>Evidence</th></tr>
{alerts}
</table></div>

<h2>Recent anomalies</h2>
<div class="tablewrap"><table>
<tr><th>When</th><th>Resolver</th><th>Domain</th><th>Classification</th><th>State</th></tr>
{anomalies}
</table></div>

<h2>Recent DNS queries</h2>
<div class="tablewrap"><table>
<tr><th>When</th><th>Resolver</th><th>Domain</th><th>RCODE</th><th>Classification</th></tr>
{events}
</table></div>

<footer>
Status labels are derived from stored raw metrics, not an opaque score. A
possible cache-poisoning event is a verified integrity anomaly that independent
checks could not explain benignly; it indicates a <em>possible</em> attack, not
a proven one. Point-in-time snapshot generated from the local database.
</footer>
</div></body></html>"""
