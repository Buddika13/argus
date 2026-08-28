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
import time
from pathlib import Path

from .storage import Storage


def render(storage: Storage, vantage: str = "local", refresh_seconds: int = 0) -> str:
    """Render the dashboard HTML from the live database. Reads only."""
    resolvers = storage.list_resolvers()
    rows = [_resolver_summary(storage, r) for r in resolvers]
    counts = storage.table_counts()
    healthy = sum(1 for x in rows if x["status"] == "HEALTHY")

    # "No data" is shown explicitly rather than invented.
    has_data = counts.get("query_results", 0) > 0 or counts.get("health_metrics", 0) > 0
    banner = "" if has_data else (
        '<div class="banner">No monitoring data available yet. Run a sweep with '
        '<code>argus run-once</code> (or <code>argus serve</code>), then reload.</div>')
    meta_refresh = (f'<meta http-equiv="refresh" content="{int(refresh_seconds)}">'
                    if refresh_seconds and refresh_seconds > 0 else "")

    return _PAGE.format(
        css=_CSS, meta_refresh=meta_refresh, banner=banner,
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


def _cards(counts, rows, healthy) -> str:
    poison = counts.get("alerts", 0)
    data = [
        ("ok", len(rows), "resolvers"),
        ("ok", healthy, "healthy"),
        ("warn", counts.get("anomalies", 0), "anomalies"),
        ("bad", poison, "possible poisoning"),
        ("muted", counts.get("query_results", 0), "queries recorded"),
    ]
    return "".join(
        f'<div class="card {c}"><div class="n">{n}</div><div class="l">{_e(l)}</div></div>'
        for c, n, l in data)


def _resolver_table(rows) -> str:
    if not rows:
        return '<tr><td colspan="10" class="empty">No data available.</td></tr>'
    out = ""
    for x in rows:
        out += (
            f"<tr><td><b>{_e(x['name'])}</b></td><td class='mono'>{_e(x['ip'])}</td>"
            f"<td>{_badge(x['status'])}</td>"
            f"<td>{_pct(x['availability'])}</td><td>{_ms(x['latency'])}</td>"
            f"<td>{_rate(x['correctness'])}</td><td>{_e(x['freshness'] or '—')}</td>"
            f"<td class='mono small'>{_e(x['dnssec'])}</td>"
            f"<td class='trend'>{x['spark']}</td>"
            f"<td class='small'>{_ts(x['last'])}</td></tr>")
    return out


def _events(storage) -> str:
    rows = storage.recent_events(15)
    if not rows:
        return '<tr><td colspan="5" class="empty">No data available.</td></tr>'
    return "".join(
        f"<tr><td class='small'>{_ts(r['timestamp'])}</td><td>{_e(r['resolver'])}</td>"
        f"<td>{_e(r['domain'])} <span class='muted'>{_e(r['query_type'])}</span></td>"
        f"<td class='mono small'>{_e(r['rcode'])}</td>"
        f"<td>{_class_badge(r['comparison_classification'])}</td></tr>"
        for r in rows)


def _anomalies(storage) -> str:
    rows = storage.recent_anomalies(15)
    if not rows:
        return '<tr><td colspan="5" class="empty">No data available.</td></tr>'
    return "".join(
        f"<tr><td class='small'>{_ts(r['observed_at'])}</td><td>{_e(r['resolver'])}</td>"
        f"<td>{_e(r['domain'])} <span class='muted'>{_e(r['rtype'])}</span></td>"
        f"<td>{_class_badge(r['classification'])}</td>"
        f"<td class='small'>{_e(r['verification_state'])}</td></tr>"
        for r in rows)


def _alerts(storage) -> str:
    rows = storage.recent_alerts(15)
    if not rows:
        return '<tr><td colspan="4" class="empty">No possible cache-poisoning events. ' \
               'All clear.</td></tr>'
    return "".join(
        f"<tr><td class='small'>{_ts(r['confirmed_at'])}</td><td>{_e(r['resolver'])}</td>"
        f"<td>{_e(r['domain'])} <span class='muted'>{_e(r['rtype'])}</span></td>"
        f"<td class='mono small'>{_e(r['evidence'])}</td></tr>"
        for r in rows)


def _class_badge(cls) -> str:
    cls = cls or "—"
    good = {"NORMAL", "BENIGN_DIFFERENCE"}
    bad = {"POSSIBLE_CACHE_POISONING", "DNS_INTEGRITY_ANOMALY"}
    kind = "ok" if cls in good else "bad" if cls in bad else "warn" if cls != "—" else "muted"
    return f'<span class="badge {kind} tiny">{_e(cls)}</span>'


# -- static template + styles ----------------------------------------------
_CSS = """
:root{--bg:#f5f6f8;--card:#fff;--ink:#1b1f24;--muted:#6b7280;--line:#e4e7eb;
--ok:#137333;--okbg:#e6f4ea;--warn:#8a6d00;--warnbg:#fdf3d0;--bad:#b3261e;--badbg:#fce8e6;
--accent:#1a3d6d;}
@media(prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--ink:#e6e8eb;
--muted:#9aa1aa;--line:#2a2f36;--okbg:#0f2417;--warnbg:#2a2410;--badbg:#2a1113;--accent:#7fa8dd;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:30px 22px 60px}
header{border-bottom:2px solid var(--accent);padding-bottom:12px;margin-bottom:22px}
h1{font-size:22px;margin:0;color:var(--accent)}
.sub{color:var(--muted);font-size:13px;margin-top:3px}
h2{font-size:15px;margin:28px 0 10px;color:var(--accent);
border-left:3px solid var(--accent);padding-left:8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.card .n{font-size:26px;font-weight:700}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.03em}
.card.ok .n{color:var(--ok)}.card.warn .n{color:var(--warn)}.card.bad .n{color:var(--bad)}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:8px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
th{background:rgba(127,127,127,.06);color:var(--muted);font-weight:600;
text-transform:uppercase;font-size:11px;letter-spacing:.03em}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600}
.badge.tiny{font-size:10px;padding:1px 6px}
.badge.ok{background:var(--okbg);color:var(--ok)}
.badge.warn{background:var(--warnbg);color:var(--warn)}
.badge.bad{background:var(--badbg);color:var(--bad)}
.badge.muted{background:rgba(127,127,127,.12);color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.small{font-size:12px}.tiny{font-size:11px}
.muted{color:var(--muted)}.trend{color:var(--accent)}
.empty{color:var(--muted);font-style:italic;text-align:center;padding:16px}
.banner{background:var(--warnbg);color:var(--warn);border:1px solid var(--line);
border-radius:8px;padding:12px 16px;margin-bottom:18px;font-size:13px}
.banner code{font-family:ui-monospace,Consolas,monospace}
footer{color:var(--muted);font-size:11px;margin-top:30px;line-height:1.7}
"""

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus — Monitoring Dashboard</title>{meta_refresh}<style>{css}</style></head>
<body><div class="wrap">
<header>
  <h1>Argus — DNS Caching-Server Health &amp; Cache-Poisoning Monitor</h1>
  <div class="sub">vantage <b>{vantage}</b> &middot; generated {generated}</div>
</header>
{banner}

<h2>Overall system status</h2>
<div class="cards">{cards}</div>

<h2>Monitored resolvers</h2>
<div class="tablewrap"><table>
<tr><th>Resolver</th><th>IP</th><th>Status</th><th>Availability</th><th>Avg latency</th>
<th>Correctness</th><th>Freshness</th><th>DNSSEC</th><th>Availability trend</th><th>Last checked</th></tr>
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
