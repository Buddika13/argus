"""PAGES — one renderer per dashboard page.

Each function returns the body HTML for its page; `shell.page` supplies the
chrome. Every value shown is read from the SQLite database through existing
`Storage` methods, or measured live on the verification page through the
existing probe / verifier / comparison modules. Nothing here invents data, and
nothing here re-decides a classification: `verdict.py` only maps stored
classifications onto the three reported verdicts.
"""

from __future__ import annotations

import json

from .. import reporting
from . import verdict
from .shell import (ASSET_LOGO, HEALTHY, ICON_CLOCK, ICON_PLAY, ICON_REPORT,
                    KPI_ICONS,
                    LANKA_ASPECT, NO_DATA, SERIES_COLOURS,
                    STATUS_SEVERITY, badge, bar, donut,
                    e, empty_state, findings, gauge, kpi, linechart, link, ms,
                    national_map, note, pagehead, pct, rate, records,
                    resolver_status, scorecard, sparkline, status_tone, table,
                    ts)

PAGE_SIZE = 25

# How many recent measurements and alerts the Overview summarises. Small on
# purpose: the Overview points at the pages that hold the full record.
OVERVIEW_ROWS = 6
OVERVIEW_ALERTS = 4

# Server routes that return a file rather than a page. Static snapshots have no
# server behind them, so the page degrades to naming the files instead.
REPORT_DOWNLOAD = "/reports/download"
REPORT_FILE = "/reports/file"


# -- shared reads -----------------------------------------------------------

def resolver_summaries(storage) -> list[dict]:
    """Per-resolver health, using the existing storage queries only."""
    out = []
    for r in storage.list_resolvers():
        health = storage.latest_health(r["name"])
        dnssec = storage.latest_dnssec(r["name"])
        history = storage.metric_history(r["name"], limit=30)
        out.append({
            "name": r["name"], "ip": r["address"], "role": r["role"],
            "isp": r["isp"], "enabled": r["enabled"],
            "status": resolver_status(health),
            "availability": health["availability_pct"] if health else None,
            "latency": health["avg_latency_ms"] if health else None,
            "correctness": health["correctness_rate"] if health else None,
            "freshness": health["freshness_status"] if health else None,
            "freshness_rate": health["freshness_ok_rate"] if health else None,
            "ad_rate": health["ad_rate"] if health else None,
            "timeouts": health["timeout_rate"] if health else None,
            "servfail": health["servfail_rate"] if health else None,
            "errors": health["error_rate"] if health else None,
            "queries": health["total_queries"] if health else None,
            "dnssec": (dnssec["security"] + " / " + dnssec["posture"]) if dnssec else "—",
            "last": (health["window_end"] or health["computed_at"]) if health else None,
            "spark": sparkline([h["availability_pct"] for h in reversed(history)
                                if h["availability_pct"] is not None]),
        })
    out.sort(key=lambda x: (STATUS_SEVERITY.get(x["status"], 9), x["name"]))
    return out


def _evidence(raw):
    try:
        return json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return {}


def dig_commands(domain: str, rtype: str, resolver_ip: str = "",
                 port: int = 53) -> str:
    """The two dig commands that reproduce a finding independently.

    Argus resolves natively rather than shelling out to dig, so these are shown
    for verification rather than executed. Note that `dig +trace` asks the local
    system resolver for out-of-bailiwick glue, whereas the trusted path here
    sub-walks from the root for it -- so +trace is the closest standard
    equivalent, not an identical procedure.
    """
    at = ("@" + resolver_ip + (" -p " + str(port) if port and port != 53 else "")
          ) if resolver_ip else "@<resolver>"
    untrusted = "dig +short " + at + " " + domain + " " + rtype
    trusted = "dig +trace " + domain + " " + rtype
    return ("<div class='panel' style='margin-top:14px'><h3>Reproduce this "
            "independently</h3>"
            "<dl class='kv'>"
            "<dt>Untrusted path</dt><dd class='mono'>" + e(untrusted) + "</dd>"
            "<dt>Trusted path</dt><dd class='mono'>" + e(trusted) + "</dd>"
            "</dl>"
            "<p class='small muted' style='margin:9px 0 0'>Argus resolves "
            "directly rather than calling dig; these commands let the same "
            "comparison be checked with standard tools. <code>dig +trace</code> "
            "resolves missing glue through the local system resolver, while the "
            "trusted path here sub-walks from the root for it.</p></div>")


def _card(tone, number, label) -> str:
    return ('<div class="card ' + tone + '"><div class="l">' + e(label) +
            '</div><div class="n">' + str(number) + "</div></div>")


def _verdict_banner(alerts: int, anomalies: int, has_data: bool) -> str:
    if not has_data:
        return ('<div class="verdict"><span class="dot"></span><div>'
                "<b>Awaiting first sweep</b><span>No measurements recorded yet. "
                "Run <code>python -m argus run-once</code>.</span></div></div>")
    if alerts:
        word = "event" if alerts == 1 else "events"
        return ('<div class="verdict bad"><span class="dot"></span><div><b>'
                + str(alerts) + " possible cache-poisoning " + word +
                "</b><span>Uncorroborated and persistent. Possible &mdash; not "
                "proven.</span></div></div>")
    if anomalies:
        # Lead with the conclusion, not the count: nothing was confirmed, and a
        # number alone reads as an alarm. Amber is kept so an investigated
        # difference stays visible rather than disappearing into a clean page.
        if anomalies == 1:
            subject, them = "1 difference was", "it"
        else:
            subject, them = "%d differences were" % anomalies, "them"
        return ('<div class="verdict warn"><span class="dot"></span><div>'
                "<b>No cache poisoning detected</b><span>"
                + subject + " investigated; independent checks explained "
                + them + " as legitimate, so no alert was raised."
                "</span></div></div>")
    return ('<div class="verdict ok"><span class="dot"></span><div>'
            "<b>No poisoning detected</b><span>Every monitored resolver agreed with "
            "the authoritative hierarchy.</span></div></div>")


# -- 1. OVERVIEW ------------------------------------------------------------

def _watchlist_size(storage) -> int:
    """How many domains are actually being monitored.

    The configuration is the authority: the domains table keeps every name ever
    recorded, so counting it would include names dropped from the watch-list.
    """
    try:
        from ..config import load_settings
        configured = len(load_settings().watchlist)
        if configured:
            return configured
    except Exception:                                  # noqa: BLE001
        pass
    return storage.table_counts().get("domains", 0)


def _mean(values):
    values = [v for v in values if isinstance(v, (int, float))]
    return sum(values) / len(values) if values else None


def _resolver_map(rows) -> str:
    """The national map, with a marker per resolver that has coordinates.

    Positions come from `map_x` / `map_y` in resolvers.yaml. Nothing is
    inferred from an IP address or a country code: a marker on a national map
    is a factual claim about where infrastructure sits, so it is drawn only
    where the operator has stated one.
    """
    try:
        from ..config import load_settings
        configured = load_settings().resolvers
    except Exception:                                  # noqa: BLE001
        configured = []
    tones = {x["name"]: status_tone(x["status"]) for x in rows}

    markers = ""
    for resolver in configured:
        if not (resolver.enabled and resolver.has_location):
            continue
        tone = tones.get(resolver.name, "muted")
        # Markers sit outside the scaled group so they stay round; the x
        # percentage the operator supplies is mapped onto the narrowed box.
        markers += ('<circle class="marker %s" cx="%.2f" cy="%.2f" r="1.9">'
                    "<title>%s (%s)</title></circle>"
                    % (tone if tone in ("bad", "warn") else "",
                       resolver.map_x * LANKA_ASPECT, resolver.map_y,
                       e(resolver.name), e(resolver.address)))
    return national_map(markers)


def _health_dimensions(rows) -> str:
    """The four integrity dimensions, averaged over resolvers that have data.

    Each ring is one stored metric, not a blend: a number here can always be
    traced back to a single column in health_metrics.
    """
    measured = [x for x in rows if x["enabled"] and x["status"] != NO_DATA]
    correctness = _mean(x["correctness"] for x in measured)
    freshness = _mean(x["freshness_rate"] for x in measured)
    availability = _mean(x["availability"] for x in measured)
    authenticated = _mean(x["ad_rate"] for x in measured)

    def as_pct(value):
        return value * 100 if isinstance(value, (int, float)) else None

    def tone(value, preferred, good=99.0, fair=90.0):
        if not isinstance(value, (int, float)):
            return "muted"
        return preferred if value >= good else ("warn" if value >= fair else "bad")

    correctness_pct, freshness_pct = as_pct(correctness), as_pct(freshness)
    ad_pct = as_pct(authenticated)

    return ("<div class='gauges'>"
            + gauge(correctness_pct, "Correctness", tone(correctness_pct, "ok"))
            + gauge(freshness_pct, "Freshness", tone(freshness_pct, "info"))
            + gauge(availability, "Availability", tone(availability, "violet"))
            + gauge(ad_pct, "DNSSEC posture",
                    "warn" if ad_pct is not None else "muted")
            + "</div>")


def _performance_chart(storage, rows) -> str:
    """Response time per resolver across the recorded window.

    Points come from health_metrics, one per resolver per sweep, so the chart
    plots exactly what was measured rather than an interpolation.
    """
    series = []
    for index, row in enumerate(x for x in rows if x["enabled"]):
        history = storage.metric_history(row["name"], limit=24)
        points = [(h["computed_at"], h["avg_latency_ms"]) for h in history
                  if h["computed_at"] and h["avg_latency_ms"] is not None]
        if points:
            series.append({"name": row["name"],
                           "colour": SERIES_COLOURS[index % len(SERIES_COLOURS)],
                           "points": points})
    if not series:
        return ("<p class='empty'>No response-time history yet &mdash; run a "
                "sweep to record the first points.</p>")

    stamps = [x for s in series for x, _y in s["points"]]
    span = (ts(min(stamps)) + " &rarr; " + ts(max(stamps)) + " &middot; "
            + str(len(stamps)) + " recorded points")
    return "<p class='sub'>" + span + "</p>" + linechart(series)


def _alert_feed(storage) -> str:
    """Confirmed events first, then anomalies still under review.

    Both appear because an empty panel says nothing about whether the system is
    working; the severity marker keeps the two apart.
    """
    items, shown = "", 0
    for a in storage.recent_alerts(OVERVIEW_ALERTS):
        items += ("<li><span class='fi bad'>!</span><div class='ft'><b>"
                  + e(a["domain"]) + " (" + e(a["rtype"]) + ")</b><span>"
                  + badge(verdict.POSSIBLE, "bad", True) + " "
                  + e(a["resolver"]) + " &nbsp;|&nbsp; "
                  + ts(a["confirmed_at"]) + "</span></div></li>")
        shown += 1
    for a in storage.recent_anomalies(OVERVIEW_ALERTS * 2):
        if shown >= OVERVIEW_ALERTS:
            break
        if a["classification"] == "POSSIBLE_CACHE_POISONING":
            continue                              # already listed as an alert
        cls = a["classification"]
        items += ("<li><span class='fi warn'>!</span><div class='ft'><b>"
                  + e(a["domain"]) + " (" + e(a["rtype"]) + ")</b><span>"
                  + badge(verdict.verdict_of(cls), verdict.tone_of(cls), True)
                  + " " + e(a["resolver"]) + " &nbsp;|&nbsp; "
                  + ts(a["observed_at"]) + "</span></div></li>")
        shown += 1
    if not items:
        return ("<p class='empty'>Nothing raised. No resolver has disagreed "
                "with the authoritative hierarchy.</p>")
    return "<ul class='feed'>" + items + "</ul>"


def _recent_results(storage, live: bool) -> str:
    rowsout = ""
    for r in storage.recent_events(OVERVIEW_ROWS):
        cls = r["comparison_classification"]
        detail = (r["verification_result"] or "").strip()
        if len(detail) > 64:
            detail = detail[:61].rstrip() + "..."
        href = link("queries", live,
                    "?resolver=" + e(r["resolver"] or "")
                    + "&amp;domain=" + e(r["domain"] or ""))
        rowsout += ("<tr><td class='small muted'>" + ts(r["timestamp"]) + "</td>"
                    "<td>" + e(r["domain"]) + " <span class='chip'>"
                    + e(r["query_type"]) + "</span></td>"
                    "<td><b>" + e(r["resolver"]) + "</b></td>"
                    "<td>" + badge(verdict.short_of(cls), verdict.tone_of(cls),
                                   True) + "</td>"
                    "<td class='wrap small muted'>" + (e(detail) or "&mdash;")
                    + "</td>"
                    "<td><a href='" + href + "'>View</a></td></tr>")
    return table(["Time", "Domain", "Resolver", "Result", "Details", ""],
                 rowsout, 6)


def head(key: str, live: bool, params: dict | None = None) -> str:
    """A page's title block, where a page wants buttons beside the title."""
    params = params or {}
    if key == "verification":
        domain = (params.get("domain") or "").strip()
        return pagehead(
            ("Domain check: " + e(domain)) if domain else "Monitoring",
            "Compare the answer from the monitored caching resolver (the "
            "untrusted path) with the trusted path walked from the root "
            "(dig +trace).")
    if key == "reports":
        return pagehead(
            "Reports",
            "Generate and view system reports and analytics, built from "
            "stored monitoring data.",
            "<a class='action' href='" + link("reports", live)
            + "?view=selection#scheduled'>" + ICON_CLOCK
            + "Scheduled reports</a>"
            "<a class='action primary' href='" + link("reports", live)
            + "?view=selection'>" + ICON_REPORT + "Generate report</a>")
    if key != "overview":
        return ""
    return pagehead(
        "Welcome to ARGUS",
        "A national DNS caching-server health and cache-poisoning monitoring "
        "system. Every answer summarised below was checked against the "
        "authoritative hierarchy, walked from the root.",
        '<a class="action" href="' + link("reports", live) + '">'
        + ICON_REPORT + "View reports</a>")


def _run_check_box() -> str:
    """How to take a fresh measurement.

    Deliberately a command rather than a working button: the dashboard server
    is a read-only view of the database, and a sweep started by a browser click
    would block it for as long as the sweep runs while writing underneath it.
    """
    return ('<details class="runbox"><summary><span class="action primary">'
            + ICON_PLAY + "Run check now</span></summary>"
            "<div class='body'>"
            "<p>The dashboard reads the database and never writes to it. Take a "
            "fresh measurement from a terminal in the project folder:</p>"
            "<pre>python -m argus run-once</pre>"
            "<p>Then reload this page. For continuous monitoring at the "
            "configured interval, run <code>python -m argus serve</code> and "
            "leave it running.</p></div></details>")


def overview(storage, live: bool) -> str:
    rows = resolver_summaries(storage)
    counts = storage.table_counts()
    # Count only resolvers actually being monitored. The resolvers table keeps
    # every name ever recorded, including disabled placeholders, and counting
    # those implied they were monitored but unhealthy.
    monitored = [x for x in rows if x["enabled"]]
    responding = [x for x in monitored
                  if isinstance(x["availability"], (int, float))
                  and x["availability"] > 0]
    alerts = counts.get("alerts", 0)
    anomalies = counts.get("anomalies", 0)
    has_data = counts.get("query_results", 0) > 0

    body = _run_check_box()
    body += _verdict_banner(alerts, anomalies, has_data)
    if not has_data:
        body += note("No monitoring data available yet. Run a sweep with "
                     "<code>argus run-once</code> (or <code>argus serve</code>), "
                     "then reload.", "warn")

    body += "<h2>System totals</h2><div class='kpis'>"
    body += kpi("ok" if monitored and len(responding) == len(monitored) else "warn",
                KPI_ICONS["resolvers"],
                "%d / %d" % (len(responding), len(monitored)),
                "Resolvers responding", link("resolvers", live))
    body += kpi("info", KPI_ICONS["domains"], str(_watchlist_size(storage)),
                "Domains monitored", link("queries", live))
    body += kpi("warn" if anomalies else "muted", KPI_ICONS["anomalies"],
                str(anomalies), "Anomalies investigated", link("anomalies", live))
    body += kpi("bad" if alerts else "ok", KPI_ICONS["uptime"], str(alerts),
                "Possible poisoning events", link("poisoning", live))
    body += "</div>"

    body += "<div class='split'><div class='col'>"

    rowsout = ""
    for x in rows:
        dim = " class='dim'" if x["status"] == NO_DATA else ""
        tone = status_tone(x["status"])
        correctness = (x["correctness"] * 100
                       if isinstance(x["correctness"], (int, float)) else None)
        rowsout += ("<tr" + dim + "><td><a href='"
                    + link("resolvers", live, "?resolver=" + x["name"])
                    + "'><b>" + e(x["name"]) + "</b></a> <span class='chip'>"
                    + e((x["role"] or "").upper()) + "</span></td>"
                    "<td class='mono'>" + e(x["ip"]) + "</td>"
                    "<td><span class='st " + tone + "'>"
                    "<span class='statusdot'></span>" + e(x["status"])
                    + "</span></td>"
                    "<td>" + bar(correctness, tone) + "</td>"
                    "<td>" + ms(x["latency"]) + "</td></tr>")
    body += ("<div class='panel flush'><h3>Resolver status summary</h3>"
             + table(["Resolver", "IP address", "Status", "Correctness",
                      "Avg response"], rowsout, 5)
             + "<div class='foot'><a href='" + link("resolvers", live)
             + "'>View all resolvers &rarr;</a></div></div>")

    body += ("<div class='panel flush'><h3>Recent monitoring results</h3>"
             + _recent_results(storage, live)
             + "<div class='foot'><a href='" + link("queries", live)
             + "'>View all measurements &rarr;</a></div></div>")

    body += "</div><div class='col'>"

    body += ("<div class='panel'><h3>Sri Lanka resolver map</h3>"
             "<p class='sub'>Markers are drawn only for resolvers whose "
             "configuration carries a real location.</p>"
             + _resolver_map(rows) + "</div>")

    body += ("<div class='panel'><h3>Health dimension overview</h3>"
             "<p class='sub'>Averaged across resolvers that have been measured. "
             "Each ring is one stored metric, never a blended score.</p>"
             + _health_dimensions(rows) + "</div>")

    body += ("<div class='panel'><h3>Resolver response time (ms)</h3>"
             + _performance_chart(storage, rows) + "</div>")

    body += ("<div class='panel'><h3>Latest findings</h3>"
             + _alert_feed(storage)
             + "<p class='small' style='margin:12px 0 0;text-align:right'><a href='"
             + link("anomalies", live) + "'>View all findings &rarr;</a></p></div>")

    return body + "</div></div>"


# -- 2. RESOLVER HEALTH -----------------------------------------------------

def resolvers(storage, live: bool, selected: str = "") -> str:
    rows = resolver_summaries(storage)
    body = ""
    rowsout = ""
    for x in rows:
        dim = " dim" if x["status"] == NO_DATA else ""
        href = link("resolvers", live, "?resolver=" + x["name"])
        rowsout += ("<tr class='" + dim.strip() + "'>"
                    "<td><a href='" + href + "'><b>" + e(x["name"]) + "</b></a> "
                    "<span class='chip'>" + e((x["role"] or "").upper()) + "</span></td>"
                    "<td class='mono'>" + e(x["ip"]) + "</td>"
                    "<td>" + badge(x["status"], status_tone(x["status"])) + "</td>"
                    "<td>" + pct(x["availability"]) + "</td>"
                    "<td>" + ms(x["latency"]) + "</td>"
                    "<td>" + rate(x["correctness"]) + "</td>"
                    "<td>" + e(x["freshness"] or "—") + "</td>"
                    "<td class='mono small'>" + e(x["dnssec"]) + "</td>"
                    "<td>" + x["spark"] + "</td>"
                    "<td class='small muted'>" + ts(x["last"]) + "</td></tr>")
    body += table(["Resolver", "IP", "Status", "Availability", "Avg latency",
                   "Correctness", "Freshness", "DNSSEC", "Trend", "Last checked"],
                  rowsout, 10)
    body += ("<p class='small muted'>Select a resolver name for its detail. Status "
             "is derived from stored metrics, most severe first: POSSIBLE DNS CACHE "
             "POISONING, UNREACHABLE, TIMEOUT, ERROR, SUSPICIOUS, WARNING, "
             "HEALTHY. Every label maps to one raw metric.</p>")

    if selected:
        match = next((x for x in rows if x["name"] == selected), None)
        if match is None:
            body += note("No resolver named <b>" + e(selected) + "</b> is configured.", "warn")
            return body
        body += "<h2>Detail &mdash; " + e(selected) + "</h2><div class='grid2'>"
        body += ("<div class='panel'><h3>Health metrics</h3><dl class='kv'>"
                 "<dt>Address</dt><dd class='mono'>" + e(match["ip"]) + "</dd>"
                 "<dt>Role</dt><dd>" + e(match["role"]) + "</dd>"
                 "<dt>Operator</dt><dd>" + e(match["isp"]) + "</dd>"
                 "<dt>Status</dt><dd>" + badge(match["status"],
                                               status_tone(match["status"])) + "</dd>"
                 "<dt>Availability</dt><dd>" + pct(match["availability"]) + "</dd>"
                 "<dt>Average latency</dt><dd>" + ms(match["latency"]) + "</dd>"
                 "<dt>Correctness</dt><dd>" + rate(match["correctness"]) + "</dd>"
                 "<dt>Freshness</dt><dd>" + e(match["freshness"] or "—") + "</dd>"
                 "<dt>Timeout rate</dt><dd>" + rate(match["timeouts"]) + "</dd>"
                 "<dt>SERVFAIL rate</dt><dd>" + rate(match["servfail"]) + "</dd>"
                 "<dt>Error rate</dt><dd>" + rate(match["errors"]) + "</dd>"
                 "<dt>Queries in window</dt><dd>"
                 + (str(match["queries"]) if match["queries"] is not None else "—")
                 + "</dd><dt>DNSSEC</dt><dd class='mono small'>" + e(match["dnssec"])
                 + "</dd></dl></div>")
        recent = ""
        for r in storage.events_for_resolver(selected, 12):
            recent += ("<tr><td class='small muted'>" + ts(r["timestamp"]) + "</td>"
                       "<td>" + e(r["domain"]) + " <span class='chip'>"
                       + e(r["query_type"]) + "</span></td>"
                       "<td class='mono small'>" + e(r["rcode"]) + "</td>"
                       "<td>" + badge(verdict.verdict_of(r["comparison_classification"]),
                                      verdict.tone_of(r["comparison_classification"]),
                                      True) + "</td></tr>")
        body += ("<div class='panel'><h3>Recent measurements</h3>"
                 + table(["When", "Domain", "RCODE", "Verdict"], recent, 4) + "</div>")
        body += "</div>"
    return body


# -- 2b. DOMAINS ------------------------------------------------------------

def domains(storage, live: bool, params: dict) -> str:
    """The watch-list, with how each domain has behaved.

    Rows come from the measurements actually recorded, so a domain that has
    never been checked is absent rather than shown with invented zeroes.
    """
    get = lambda k: (params.get(k) or "").strip()      # noqa: E731
    search, category, status = get("q").lower(), get("category"), get("status")
    try:
        from ..config import load_settings
        settings = load_settings()
        labels, watched = settings.categories, set(settings.watchlist)
    except Exception:                                  # noqa: BLE001
        labels, watched = {}, set()

    rows = []
    for r in storage.rollup("domain"):
        label = labels.get(r["key"], "")
        state = ("Mismatch" if r["poisoning"]
                 else ("Under review" if r["flagged"] else "Healthy"))
        if search and search not in r["key"].lower():
            continue
        if category and label != category:
            continue
        if status and state != status:
            continue
        rows.append((r, label, state))

    if not storage.table_counts().get("query_results", 0):
        return ("<div class='panel'>" + empty_state(
            "No monitoring data yet",
            "The watch-list holds %d domain%s, but none has been checked at "
            "this vantage point. Run  python -m argus run-once  and reload."
            % (len(watched), "" if len(watched) == 1 else "s")) + "</div>")

    tones = {"Healthy": "ok", "Under review": "warn", "Mismatch": "bad"}
    listing = ""
    for r, label, state in rows:
        check = link("verification", live, "?domain=" + e(r["key"]) + "&amp;rtype=A")
        listing += ("<tr><td><b>" + e(r["key"]) + "</b></td>"
                    "<td class='small'>" + (e(label) or
                                            "<span class='muted'>&mdash;</span>")
                    + "</td>"
                    "<td>" + "{:,}".format(r["checks"]) + "</td>"
                    "<td>" + ("<b>%d</b>" % r["flagged"] if r["flagged"] else "0")
                    + "</td>"
                    "<td class='small muted'>" + ts(r["last_seen"]) + "</td>"
                    "<td>" + badge(state, tones[state], True) + "</td>"
                    "<td><a class='btn' href='" + check + "'>Run check</a></td>"
                    "</tr>")

    body = ("<div class='kpis'>"
            + kpi("info", KPI_ICONS["domains"], str(len(rows)), "Domains listed",
                  "")
            + kpi("ok", KPI_ICONS["resolvers"],
                  str(sum(1 for _r, _l, x in rows if x == "Healthy")),
                  "Fully corroborated", "")
            + kpi("warn", KPI_ICONS["anomalies"],
                  str(sum(1 for _r, _l, x in rows if x == "Under review")),
                  "Under review", "")
            + kpi("bad" if any(x == "Mismatch" for _r, _l, x in rows) else "ok",
                  KPI_ICONS["uptime"],
                  str(sum(1 for _r, _l, x in rows if x == "Mismatch")),
                  "With a mismatch", "")
            + "</div>")

    options = sorted({c for c in labels.values() if c})
    body += ("<form class='filterbar' method='get' action='"
             + link("domains", live) + "'>"
             + _select("category", "Category", options, category)
             + _select("status", "Status", ["Healthy", "Under review",
                                            "Mismatch"], status)
             + "<div class='field grow'><label for='q'>Search</label>"
             "<input id='q' name='q' value='" + e(get("q"))
             + "' placeholder='Search domain...'></div>"
             "<button type='submit'>Filter</button>"
             "<a class='btn' href='" + link("domains", live) + "'>Reset</a>"
             "</form>")

    body += (table(["Domain", "Category", "Total checks", "Flagged",
                    "Last checked", "Status", ""], listing, 7)
             if listing else "<div class='panel'>" + empty_state(
                 "No domain matches these filters",
                 "Clear the filters to see every monitored domain.") + "</div>")
    body += ("<p class='small muted'>Categories come from the section headings "
             "in <code>config/watchlist.txt</code>. A flagged answer is a "
             "question, not a finding &mdash; the "
             "<a href='" + link("anomalies", live) + "'>Alerts</a> page shows "
             "how each was tested.</p>")
    return body


# -- 3. CACHE POISONING DETECTION -------------------------------------------

def poisoning(storage, live: bool) -> str:
    body = note("A verdict of <b>POSSIBLE_CACHE_POISONING</b> means a resolver "
                "persistently returned data that neither the authoritative servers "
                "nor any independent resolver corroborated. It is <b>not</b> proven "
                "poisoning: proof would require the resolver's own cache contents or "
                "capture of the injection, which a passive observer cannot obtain.")

    alerts = storage.recent_alerts(50)
    if not alerts:
        body += ('<div class="verdict ok"><span class="dot"></span><div><b>'
                 + verdict.NO_POISONING + "</b><span>No event has survived the "
                 "independent checks.</span></div></div>")
        body += note("To demonstrate that detection works, run "
                     "<code>python scripts/demo_hijack.py</code>, which serves a "
                     "deliberately forged answer from a resolver on loopback under "
                     "your own control.", "ok")
        return body

    for a in alerts:
        ev = _evidence(a["evidence"])
        stage1 = ev.get("stage1") or {}
        stage2 = ev.get("stage2_authoritative") or {}
        stage3 = ev.get("stage3_controls") or {}
        stage4 = ev.get("stage4_dnssec") or {}
        stage5 = ev.get("stage5_persistence") or {}
        answers = stage3.get("answers") or {}

        body += "<h2>" + ts(a["confirmed_at"]) + " &mdash; " + e(a["resolver"]) + "</h2>"
        body += "<div class='grid2'>"
        # The stored measurements behind this alert: the COMPLETE monitored
        # answer, both TTLs and both response codes. The evidence JSON keeps
        # only the unpublished subset, which is not the same thing whenever the
        # resolver returned some valid addresses alongside an unpublished one.
        m = storage.alert_measurements(a["id"])

        def field(key, fallback="—"):
            value = m[key] if m is not None and m[key] is not None else None
            return e(value) if value not in (None, "") else fallback

        monitored_answer = (m["monitored_records"] if m is not None
                            and m["monitored_records"] else "")
        if not monitored_answer:                      # pre-join alerts
            monitored_answer = ", ".join(stage1.get("unpublished") or [])
        auth_answer = (m["auth_records"] if m is not None and m["auth_records"]
                       else ", ".join(stage2.get("records") or []))
        unpublished = (m["unpublished"] if m is not None and m["unpublished"]
                       else ", ".join(stage1.get("unpublished") or []))

        ttl_line = field("monitored_ttl") + " / " + field("auth_ttl")
        if m is not None and m["ttl_ratio"] is not None:
            ttl_line += " (ratio %.2f%s)" % (
                m["ttl_ratio"], ", inflated" if m["ttl_inflated"] else "")

        body += ("<div class='panel'><h3>Observation</h3><dl class='kv'>"
                 "<dt>Timestamp</dt><dd>" + ts(a["confirmed_at"]) + "</dd>"
                 "<dt>Monitored resolver</dt><dd><b>" + e(a["resolver"]) + "</b> "
                 "<span class='mono'>" + field("resolver_ip", "") + "</span></dd>"
                 "<dt>Domain</dt><dd>" + e(a["domain"]) + "</dd>"
                 "<dt>Record type</dt><dd>" + e(a["rtype"]) + "</dd>"
                 "<dt>Monitored answer</dt><dd class='mono'>"
                 + (e(monitored_answer) or "—") + "</dd>"
                 "<dt>Authoritative answer</dt><dd class='mono'>"
                 + (e(auth_answer) or "—") + "</dd>"
                 "<dt>Unpublished by the zone</dt><dd class='mono badink'>"
                 + (e(unpublished) or "—") + "</dd>"
                 "<dt>Also matched</dt><dd class='mono'>" + field("matched") + "</dd>"
                 "<dt>Missing from answer</dt><dd class='mono'>"
                 + field("missing") + "</dd>"
                 "<dt>Authoritative server</dt><dd class='mono small'>"
                 + field("auth_servers") + "</dd>"
                 "<dt>Top-level domain</dt><dd class='mono'>"
                 + field("tld") + "</dd>"
                 "<dt>Delegation walked</dt><dd class='mono small'>"
                 + field("auth_chain") + "</dd>"
                 "<dt>RCODE (mon / auth)</dt><dd class='mono'>"
                 + field("monitored_rcode") + " / " + field("auth_rcode") + "</dd>"
                 "<dt>TTL (mon / auth)</dt><dd class='mono'>" + ttl_line + "</dd>"
                 "<dt>Independent checks</dt><dd>" + str(len(stage3.get("queried") or []))
                 + " cross-check resolvers</dd>"
                 "<dt>Persistence</dt><dd>"
                 + str(stage5.get("reproduced", "—")) + " of "
                 + str(stage5.get("repetitions", "—")) + " repeats</dd>"
                 "<dt>Classification</dt><dd>"
                 + badge(a["status"], verdict.tone_of(a["status"])) + "</dd>"
                 "<dt>Reported verdict</dt><dd>"
                 + badge(verdict.verdict_of(a["status"]),
                         verdict.tone_of(a["status"])) + "</dd></dl></div>")

        crosscheck = ""
        for name, recs in sorted(answers.items()):
            crosscheck += ("<tr><td><b>" + e(name) + "</b></td>"
                        "<td class='mono'>" + e(", ".join(recs) or "(none)") + "</td></tr>")
        if not crosscheck and stage3.get("queried"):
            crosscheck = ("<tr><td colspan='2' class='muted small'>"
                       + e(", ".join(stage3["queried"])) +
                       " were queried; per-resolver answers were not retained for "
                       "this event.</td></tr>")
        body += ("<div class='panel'><h3>Cross-check resolver answers</h3>"
                 + table(["Resolver", "Answer"], crosscheck, 2) +
                 "<p class='small muted'>" +
                 ("At least one cross-check resolver returned the same unexpected data, "
                  "which argues against poisoning."
                  if stage3.get("corroborates_unexpected")
                  else "No cross-check resolver returned the unexpected data.") +
                 "</p></div>")
        body += "</div>"

        body += ("<div class='panel' style='margin-top:14px'><h3>Evidence chain</h3>"
                 "<ul class='stages'>"
                 "<li><b>Stage 1 &mdash; comparison</b>"
                 + e(stage1.get("reason") or "—") + "</li>"
                 "<li><b>Stage 2 &mdash; independent re-walk</b>authoritative servers "
                 "returned " + e(", ".join(stage2.get("records") or []) or "—")
                 + ("; ground truth was unstable" if stage2.get("unstable")
                    else "; ground truth was stable") + "</li>"
                 "<li><b>Stage 3 &mdash; cross-check resolvers</b>"
                 + str(len(stage3.get("queried") or [])) + " queried; "
                 + ("they corroborate the unexpected data"
                    if stage3.get("corroborates_unexpected")
                    else "none corroborated the unexpected data") + "</li>"
                 "<li><b>Stage 4 &mdash; DNSSEC</b>"
                 + e(stage4.get("note") or "—") + "</li>"
                 "<li><b>Stage 5 &mdash; persistence</b>reproduced "
                 + str(stage5.get("reproduced", "—")) + " of "
                 + str(stage5.get("repetitions", "—")) + " repeats</li>"
                 "<li><b>Decision</b>" + e(ev.get("decision") or "—") + "</li>"
                 "</ul></div>")
        body += dig_commands(a["domain"], a["rtype"],
                             (m["resolver_ip"] if m is not None else "") or "")
    return body


# -- 4. DNS QUERY MONITOR ---------------------------------------------------

def _select(name, label, options, current) -> str:
    out = ("<div class='field'><label for='" + name + "'>" + e(label) + "</label>"
           "<select id='" + name + "' name='" + name + "'>"
           "<option value=''>All</option>")
    for opt in options:
        sel = " selected" if opt == current else ""
        out += "<option value='" + e(opt) + "'" + sel + ">" + e(opt) + "</option>"
    return out + "</select></div>"


def _choose(name, label, options, current) -> str:
    """A required chooser: no 'All' entry, because exactly one value is needed."""
    out = ("<div class='field'><label for='" + name + "'>" + e(label) + "</label>"
           "<select id='" + name + "' name='" + name + "' required>")
    for opt in options:
        sel = " selected" if opt == current else ""
        out += "<option value='" + e(opt) + "'" + sel + ">" + e(opt) + "</option>"
    return out + "</select></div>"


def queries(storage, live: bool, params: dict) -> str:
    get = lambda k: (params.get(k) or "").strip()  # noqa: E731
    search, resolver = get("q"), get("resolver")
    domain, rtype = get("domain"), get("rtype")
    classification, since_raw = get("classification"), get("since")
    try:
        page_no = max(1, int(params.get("page") or 1))
    except ValueError:
        page_no = 1

    since = 0.0
    if since_raw:
        import time as _time
        for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d"):
            try:
                since = _time.mktime(_time.strptime(since_raw, fmt))
                break
            except ValueError:
                continue

    filters = dict(resolver=resolver, domain=domain, rtype=rtype,
                   classification=classification, since=since, search=search)
    total = storage.count_events(**filters)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page_no = min(page_no, pages)
    rows = storage.search_events(limit=PAGE_SIZE, offset=(page_no - 1) * PAGE_SIZE,
                                 **filters)

    body = ("<form class='filters' method='get' action='" + link("queries", live) + "'>"
            "<div class='field'><label for='q'>Search</label>"
            "<input id='q' name='q' value='" + e(search) + "' "
            "placeholder='domain, resolver or address'></div>"
            + _select("resolver", "Resolver",
                      storage.distinct_events_column("resolver"), resolver)
            + _select("domain", "Domain",
                      storage.distinct_events_column("domain"), domain)
            + _select("rtype", "Record type",
                      storage.distinct_events_column("query_type"), rtype)
            + _select("classification", "Classification",
                      storage.distinct_events_column("comparison_classification"),
                      classification)
            + "<div class='field'><label for='since'>From</label>"
              "<input id='since' name='since' type='date' value='"
            + e(since_raw) + "'></div>"
              "<button type='submit'>Apply</button>"
              "<a class='btn' href='" + link("queries", live) + "'>Reset</a>"
              "</form>")

    if not live:
        body += note("Filters, search and paging are served by the built-in web "
                     "server. Start it with <code>python -m argus dashboard</code>; "
                     "this saved copy shows the most recent page only.")

    rowsout = ""
    for r in rows:
        cls = r["comparison_classification"]
        rowsout += ("<tr><td class='small muted'>" + ts(r["timestamp"]) + "</td>"
                    "<td><b>" + e(r["resolver"]) + "</b></td>"
                    "<td>" + e(r["domain"]) + "</td>"
                    "<td><span class='chip'>" + e(r["query_type"]) + "</span></td>"
                    "<td class='mono small'>" + e(r["rcode"]) + "</td>"
                    "<td>" + records(r["returned_records"]) + "</td>"
                    "<td>" + badge(cls or "—", verdict.tone_of(cls), True) + "</td></tr>")
    body += table(["When", "Resolver", "Domain", "Type", "RCODE", "Returned answer",
                   "Classification"], rowsout, 7)

    keep = ""
    for k, v in (("q", search), ("resolver", resolver), ("domain", domain),
                 ("rtype", rtype), ("classification", classification),
                 ("since", since_raw)):
        if v:
            keep += "&" + k + "=" + e(v)
    prev_cls = "btn" if page_no > 1 else "btn off"
    next_cls = "btn" if page_no < pages else "btn off"
    body += ("<div class='pager'>"
             "<a class='" + prev_cls + "' href='" + link("queries", live)
             + "?page=" + str(page_no - 1) + keep + "'>&larr; Previous</a>"
             "<a class='" + next_cls + "' href='" + link("queries", live)
             + "?page=" + str(page_no + 1) + keep + "'>Next &rarr;</a>"
             "<span>Page " + str(page_no) + " of " + str(pages) + " &middot; "
             + str(total) + " matching measurements</span></div>")
    return body


# -- 5. ANOMALY INVESTIGATION -----------------------------------------------

def anomalies(storage, live: bool, selected_id: str = "") -> str:
    body = note("A difference between a resolver and the authoritative answer is "
                "an observation, not a finding. Each one below was tested against "
                "the legitimate explanations listed at the foot of this page before "
                "any verdict was assigned.")

    rowsout = ""
    for a in storage.recent_anomalies(50):
        cls = a["classification"]
        href = link("anomalies", live, "?id=" + str(a["id"]))
        rowsout += ("<tr><td class='small muted'>" + ts(a["observed_at"]) + "</td>"
                    "<td><b>" + e(a["resolver"]) + "</b></td>"
                    "<td>" + e(a["domain"]) + "</td>"
                    "<td><span class='chip'>" + e(a["rtype"]) + "</span></td>"
                    "<td>" + badge(cls, verdict.tone_of(cls), True) + "</td>"
                    "<td>" + badge(verdict.verdict_of(cls), verdict.tone_of(cls), True)
                    + "</td>"
                    "<td class='small'>" + e(a["verification_state"]) + "</td>"
                    "<td><a class='btn' href='" + href + "'>Evidence</a></td></tr>")
    body += table(["When", "Resolver", "Domain", "Type", "Classification",
                   "Verdict", "State", ""], rowsout, 8)

    if selected_id:
        try:
            row = storage.anomaly_by_id(int(selected_id))
        except (TypeError, ValueError):
            row = None
        if row is None:
            body += note("No anomaly with that identifier is stored.", "warn")
        else:
            ev = _evidence(row["checks"])
            cls = row["classification"]
            body += "<h2>Evidence &mdash; anomaly #" + e(row["id"]) + "</h2>"
            body += ("<div class='panel'><dl class='kv'>"
                     "<dt>Observed</dt><dd>" + ts(row["observed_at"]) + "</dd>"
                     "<dt>Resolver</dt><dd><b>" + e(row["resolver"]) + "</b></dd>"
                     "<dt>Domain</dt><dd>" + e(row["domain"]) + " ("
                     + e(row["rtype"]) + ")</dd>"
                     "<dt>Classification</dt><dd>"
                     + badge(cls, verdict.tone_of(cls)) + "</dd>"
                     "<dt>Reported verdict</dt><dd>"
                     + badge(verdict.verdict_of(cls), verdict.tone_of(cls)) + "</dd>"
                     "<dt>Why</dt><dd>" + e(verdict.rationale_of(cls)) + "</dd>"
                     "<dt>State</dt><dd>" + e(row["verification_state"]) + "</dd>"
                     "<dt>Reason</dt><dd>" + e(row["reason"] or "—") + "</dd>"
                     "</dl></div>")
            if ev:
                stages = ""
                for name in ("stage1", "stage2_authoritative", "stage3_controls",
                             "stage4_dnssec", "stage5_persistence"):
                    if name not in ev:
                        continue
                    stages += ("<li><b>" + e(name.replace("_", " ")) + "</b>"
                               "<span class='mono small'>"
                               + e(json.dumps(ev[name])) + "</span></li>")
                body += ("<div class='panel' style='margin-top:14px'>"
                         "<h3>Recorded checks</h3><ul class='stages'>" + stages
                         + "</ul></div>")

    body += "<h2>Legitimate explanations tested</h2><div class='grid2'>"
    for title, text in verdict.BENIGN_EXPLANATIONS:
        body += ("<div class='panel'><h3>" + e(title) + "</h3>"
                 "<p class='small muted' style='margin:0'>" + e(text) + "</p></div>")
    body += "</div>"
    body += note("Only when every one of these is ruled out &mdash; the answer is "
                 "absent from the authoritative servers, no cross-check resolver "
                 "corroborates it, and it persists across repeated queries &mdash; "
                 "is <b>" + verdict.POSSIBLE + "</b> reported.")
    return body


# -- 6. INDEPENDENT VERIFICATION --------------------------------------------

MATCH_TONES = {"MATCH": "ok", "PARTIAL": "warn", "MISMATCH": "bad",
               "ERROR": "muted"}
MATCH_WORDS = {"MATCH": "Match", "PARTIAL": "Partial match",
               "MISMATCH": "Mismatch", "ERROR": "Error"}


def _answer_block(domain: str, rtype: str, records, ttl, highlight=()) -> str:
    """The answer section, laid out the way dig prints one.

    Argus resolves with dnspython rather than shelling out, so this is the
    measured answer formatted as dig would format it -- the same records, the
    same TTL, rendered in the familiar shape. Only one TTL is stored per
    answer (the smallest), so every row carries it.
    """
    if not records:
        return ("<div class='digline muted'>;; no records in the answer "
                "section</div>")
    out = ""
    for value in records:
        odd = " unexpected" if value in highlight else ""
        out += ("<div class='digline" + odd + "'>"
                "<span class='dn'>" + e(domain) + ".</span>"
                "<span class='dt'>" + (str(ttl) if ttl is not None else "-")
                + "</span><span class='dc'>IN</span>"
                "<span class='dr'>" + e(rtype) + "</span>"
                "<span class='dv'>" + e(value) + "</span>"
                + ("<span class='dx'>&larr; unexpected</span>" if odd else "")
                + "</div>")
    return out


def _raw_dig(part) -> str:
    """dig's own output, exactly as it printed it."""
    text = (part.get("stdout") or "").rstrip()
    if not text:
        text = (part.get("stderr") or "").rstrip() or ";; dig produced no output"
    lines = ""
    for line in text.splitlines():
        css = "digline"
        if line.lstrip().startswith(";;") or line.lstrip().startswith(";"):
            css += " muted"
        lines += "<div class='" + css + "'>" + e(line) + "</div>"
    return lines


def _path_body(part, domain, rtype, records, ttl, highlight=()):
    """Raw dig output where dig ran; the measured answer where it did not.

    Both show the same records, because both come from the same query -- the
    difference is only whether the reader is looking at dig's own text or at
    Argus's measurement printed in dig's shape.
    """
    if part and part.get("ok"):
        return _raw_dig(part), True
    if part and not part.get("ok"):
        return _raw_dig(part), True
    return _answer_block(domain, rtype, records, ttl, highlight), False


def _path_card(side: str, title: str, blurb: str, command: str,
               body: str, footer: str = "") -> str:
    return ("<div class='pathcard " + side + "'>"
            "<div class='pathhead'><span class='dot'></span>"
            "<div><b>" + e(title) + "</b><span>" + e(blurb) + "</span></div></div>"
            "<div class='digbox'><div class='digcmd'>$ " + e(command) + "</div>"
            + body + "</div>"
            + ("<p class='pathfoot'>" + footer + "</p>" if footer else "")
            + "</div>")


def _ipset(title: str, records, note: str, highlight=()) -> str:
    rows = ""
    for value in records:
        odd = " class='unexpected'" if value in highlight else ""
        rows += "<div" + odd + ">" + e(value) + "</div>"
    if not records:
        rows = "<div class='muted'>(none)</div>"
    return ("<div class='ipset'><h4>" + e(title) + "</h4>"
            "<div class='ips'>" + rows + "</div>"
            "<p class='sub'>" + note + "</p></div>")


def _check_history(storage, live: bool, domain: str, resolver: str) -> str:
    """Previous stored checks for this pair, from the monitoring record."""
    rows = storage.search_events(limit=10, domain=domain, resolver=resolver)
    if not rows:
        return ("<div class='panel'><h3>Check history</h3>"
                + empty_state("No previous checks stored",
                              "This page runs a live check; sweeps record "
                              "history. Run  python -m argus run-once  to "
                              "build one.") + "</div>")
    body = ""
    for r in rows:
        cls = r["comparison_classification"]
        body += ("<tr><td class='small muted'>" + ts(r["timestamp"]) + "</td>"
                 "<td><span class='chip'>" + e(r["query_type"]) + "</span></td>"
                 "<td class='mono small'>" + e(r["rcode"]) + "</td>"
                 "<td>" + records(r["returned_records"]) + "</td>"
                 "<td>" + badge(verdict.short_of(cls), verdict.tone_of(cls), True)
                 + "</td></tr>")
    return ("<div class='panel flush'><h3>Check history &mdash; " + e(domain)
            + " on " + e(resolver) + "</h3>"
            + table(["When", "Type", "RCODE", "Answer", "Result"], body, 5)
            + "<div class='foot'><a href='" + link("queries", live, "?domain="
            + e(domain) + "&amp;resolver=" + e(resolver))
            + "'>View all measurements &rarr;</a></div></div>")


def _domain_check(storage, live: bool, result, params: dict) -> str:
    """The Domain Check view: two paths, the comparison, and the evidence."""
    domain, rtype = result["domain"], result["rtype"]
    resolver, resolver_ip = result["resolver"], result["resolver_ip"]
    match = result["match_type"]
    tone = MATCH_TONES.get(match, "muted")
    unexpected = set(result["unpublished"])

    # -- top information card --------------------------------------------
    head = ("<div class='checkbar'>"
            "<div><span>Domain</span><b>" + e(domain) + " <span class='chip'>"
            + e(rtype) + "</span></b></div>"
            "<div><span>Resolver (untrusted path)</span><b>" + e(resolver)
            + " <i>(" + e(resolver_ip) + ")</i></b></div>"
            "<div><span>Check time</span><b>" + ts(result["checked_at"])
            + "</b></div>"
            "<div><span>Status</span><b>"
            + badge(MATCH_WORDS.get(match, match), tone) + "</b></div>"
            "<div><span>Severity</span><b>"
            + badge(result["severity"], result["severity_tone"]) + "</b></div>"
            "</div>")

    # -- the two resolution paths ----------------------------------------
    dig = result.get("dig") or {}
    dig_ok = bool(dig.get("available"))
    left_dig = dig.get("untrusted") if dig_ok else None
    right_dig = dig.get("trusted") if dig_ok else None

    untrusted_cmd = ((left_dig or {}).get("command")
                     or "dig @%s %s %s +noall +answer"
                     % (resolver_ip, domain, rtype))
    trusted_cmd = ((right_dig or {}).get("command")
                   or "dig +trace %s %s" % (domain, rtype))

    if result["direct_ok"] or left_dig:
        left_body, left_raw = _path_body(left_dig, domain, rtype,
                                         result["direct"], result["ttl"],
                                         unexpected)
        left_foot = ("Response code <b>" + e(result["rcode"]) + "</b> &middot; "
                     + ms(result["latency"]) + " &middot; TTL "
                     + (str(result["ttl"]) if result["ttl"] is not None else "&mdash;"))
    else:
        left_body = ("<div class='digline bad'>;; " + e(result["direct_error"]
                     or "the resolver did not answer") + "</div>")
        left_raw = False
        left_foot = "The monitored resolver could not be measured."

    if result["auth_ok"] or right_dig:
        right_body, right_raw = _path_body(right_dig, domain, rtype,
                                           result["authoritative"],
                                           result["auth_ttl"])
        right_foot = ("Walked " + e(" &rarr; ".join(result["chain"]) or "direct")
                      + " &middot; answered by "
                      + e(", ".join(result["auth_servers"]) or "&mdash;"))
    else:
        right_body = ("<div class='digline bad'>;; " + e(result["auth_error"]
                      or "the hierarchy could not be walked") + "</div>")
        right_raw = False
        right_foot = "Ground truth could not be established for this name."

    body = head + ("<div class='paths two'>"
            + _path_card("untrusted", "Untrusted path (direct query to the "
                         "caching server)",
                         "Query the monitored resolver directly. Never trusted.",
                         untrusted_cmd, left_body, left_foot)
            + _path_card("trusted", "Trusted path (dig +trace)",
                         "Walk the hierarchy: root → TLD → authoritative.",
                         trusted_cmd, right_body, right_foot)
            + "</div>"
            + (note("Both panels above are <b>dig's own output</b>, captured "
                    "by the backend when this check ran. The verdict below is "
                    "not read from that text: it comes from Argus's own "
                    "resolution, so the classification is the same whether or "
                    "not dig is installed. Note that <code>dig +trace</code> "
                    "fetches out-of-bailiwick glue through the local system "
                    "resolver, whereas Argus sub-walks from the root for it, "
                    "so the two paths can differ on unusual delegations.")
               if (left_raw or right_raw) else
               note("<b>" + e(dig.get("reason", "dig is not available."))
                    + "</b> The panels above therefore show the records Argus "
                    "measured, printed the way dig prints them. Install dig to "
                    "capture its raw output as reproducible evidence; the "
                    "verdict is unaffected either way.", "warn")))

    # -- comparison result ------------------------------------------------
    verdict_note = {
        "MATCH": "The resolver returned exactly the published answer set.",
        "PARTIAL": "The resolver returned a subset of the published answer. "
                   "Commonly load balancing or a partly filled cache.",
        "MISMATCH": "The resolver returned an address the zone does not "
                    "publish. This is the shape poisoning takes.",
        "ERROR": "One side could not be measured, so no comparison was "
                 "possible.",
    }[match]

    body += ("<h2>Comparison result</h2><div class='compare'>"
             + _ipset("Untrusted IP set", result["direct"],
                      "As returned by <b>" + e(resolver) + "</b>.", unexpected)
             + "<div class='verdictbox " + tone + "'>"
             "<span class='vlabel'>Result</span>"
             "<b class='vword'>" + e(MATCH_WORDS.get(match, match)) + "</b>"
             "<span class='vnote'>" + e(verdict_note) + "</span></div>"
             + _ipset("Trusted IP set", result["authoritative"],
                      "As walked from the root.")
             + "</div>")

    if unexpected:
        body += note(
            "<b>Potential DNS anomaly.</b> " + e(", ".join(sorted(unexpected)))
            + " appeared in the resolver's answer but not in the trusted "
            "answer. Argus reports this as <b>" + e(result["verdict"])
            + "</b> &mdash; " + e(verdict.rationale_of(result["classification"]))
            + ". A single mismatch is not proof of cache poisoning; the "
            "verification engine's classification is the authority.", "warn")

    # -- details -----------------------------------------------------------
    ratio = result["ttl_ratio"]
    body += ("<h2>Details</h2><div class='panel'><dl class='kv wide'>"
             "<dt>TTL (resolver)</dt><dd class='mono'>"
             + (str(result["ttl"]) + " s" if result["ttl"] is not None else "&mdash;")
             + "</dd>"
             "<dt>TTL (authoritative)</dt><dd class='mono'>"
             + (str(result["auth_ttl"]) + " s" if result["auth_ttl"] is not None
                else "&mdash;") + "</dd>"
             "<dt>TTL ratio</dt><dd class='mono'>"
             + (("%.2f" % ratio) if isinstance(ratio, float) else "&mdash;")
             + (" <b class='bad'>inflated</b>" if result["ttl_inflated"] else "")
             + "</dd>"
             "<dt>Response time</dt><dd class='mono'>" + ms(result["latency"])
             + "</dd>"
             "<dt>Response code (resolver / authoritative)</dt><dd class='mono'>"
             + e(result["rcode"]) + " / " + e(result["auth_rcode"]) + "</dd>"
             "<dt>Addresses returned</dt><dd class='mono'>"
             + str(len(result["direct"])) + " from the resolver, "
             + str(len(result["authoritative"])) + " from the trusted path</dd>"
             "<dt>Also matched</dt><dd class='mono'>"
             + (e(", ".join(result["matched"])) or "&mdash;") + "</dd>"
             "<dt>Missing from the resolver</dt><dd class='mono'>"
             + (e(", ".join(result["missing"])) or "&mdash;") + "</dd>"
             "<dt>Not published by the zone</dt><dd class='mono badink'>"
             + (e(", ".join(result["unpublished"])) or "&mdash;") + "</dd>"
             "<dt>Match type</dt><dd>" + badge(MATCH_WORDS.get(match, match),
                                               tone, True) + "</dd>"
             "<dt>Stage 1 classification</dt><dd class='mono'>"
             + e(result["stage1"]) + "</dd>"
             "<dt>Final classification</dt><dd>"
             + badge(result["classification"],
                     verdict.tone_of(result["classification"])) + "</dd>"
             "<dt>Reported verdict</dt><dd>"
             + badge(result["verdict"],
                     verdict.verdict_tone(result["verdict"])) + "</dd>"
             "<dt>Evidence</dt><dd class='wrap'>" + e(result["reason"]) + "</dd>"
             "<dt>Checked at</dt><dd class='mono'>" + ts(result["checked_at"])
             + "</dd></dl></div>")

    # -- cross-check resolvers --------------------------------------------
    rowsout = ""
    for name, info in result["controls"].items():
        rowsout += ("<tr><td><b>" + e(name) + "</b></td>"
                    "<td class='mono'>" + e(info["ip"]) + "</td>"
                    "<td class='mono'>" + e(", ".join(info["records"]) or "(none)")
                    + "</td><td>" + badge("agrees with authoritative"
                                          if info["agrees"] else "differs",
                                          "ok" if info["agrees"] else "warn",
                                          True) + "</td></tr>")
    body += ("<h2>Cross-check resolvers</h2>"
             + table(["Resolver", "IP", "Answer", "Agreement"], rowsout, 4)
             + "<p class='small muted'>Independent public recursives, asked the "
             "same question. They corroborate only &mdash; ground truth is the "
             "trusted path above.</p>")

    if (params.get("history") or "").strip():
        body += _check_history(storage, live, domain, resolver)
    return body


def verification(storage, live: bool, params: dict, result=None) -> str:
    """Monitoring / Domain Check.

    The form and the live check are unchanged -- the same probe, the same
    authoritative walk and the same comparison a sweep performs. Only the
    presentation is new: the two resolution paths side by side, the comparison
    between them, and the evidence beneath.
    """
    # The choices come from the configuration, not from the database. The
    # resolvers table keeps every name ever recorded, so offering those would
    # list resolvers that are no longer configured and cannot be queried.
    from ..config import load_settings
    try:
        settings = load_settings()
        configured, watchlist = settings.resolvers, settings.watchlist
    except Exception:                                  # noqa: BLE001
        configured, watchlist = [], []
    resolver_names = [r.name for r in configured] or         [r["name"] for r in storage.list_resolvers()]
    chosen = (params.get("resolver") or "").strip()
    domain = (params.get("domain") or "").strip()
    rtype = (params.get("rtype") or "A").strip().upper()

    form = ("<form class='filters' method='get' action='"
            + link("verification", live) + "'>"
            "<div class='field grow'><label for='domain'>Domain</label>"
            "<input id='domain' name='domain' value='" + e(domain)
            + "' list='watchlist' placeholder='"
            + e(watchlist[0] if watchlist else "example.lk")
            + "' required></div>"
            "<datalist id='watchlist'>"
            + "".join("<option value='" + e(d) + "'>" for d in watchlist)
            + "</datalist>"
            + _choose("rtype", "Record type", ["A", "AAAA"], rtype or "A")
            + _choose("resolver", "Monitored resolver", resolver_names,
                      chosen or (resolver_names[0] if resolver_names else ""))
            + "<button type='submit'>" + ICON_PLAY + "Run new check</button>"
            + ("<button type='submit' name='history' value='1' "
               "class='secondary'>Check history</button>" if domain and chosen
               else "")
            + "<a class='btn' href='" + link("queries", live)
            + "'>Back to results</a></form>")

    if not live:
        return (form + note(
            "Live verification needs the built-in server. Start it with "
            "<code>python -m argus dashboard</code>, or run the same check from "
            "the terminal with <code>python scripts/demo_workflow.py "
            "&lt;domain&gt; &lt;resolver-ip&gt;</code>.", "warn"))

    if result is None:
        return (form + "<div class='panel'>" + empty_state(
            "No check run yet",
            "Choose a domain and a resolver, then select Run new check. This "
            "page queries the resolver directly and walks the hierarchy itself; "
            "nothing is shown until both have answered.") + "</div>")

    if "error" in result:
        return (form + "<div class='panel'><div class='errorcard'>"
                "<b>The check could not be completed</b>"
                "<p>" + e(result["error"]) + "</p>"
                "<span class='sub'>Nothing was recorded. Correct the selection "
                "above and run the check again.</span></div></div>")

    return form + _domain_check(storage, live, result, params)


# -- 9. HELP ---------------------------------------------------------------

def help_page(storage, live: bool) -> str:
    """Page 9. What Argus measures and how to read what it reports.

    Written against the vocabulary the code actually uses, so a term here can
    be found in the source. The worked example is drawn from a real stored
    measurement where one exists, rather than from an invented answer.
    """
    body = ("<div class='grid2'>"
            "<div class='panel'><h3>What Argus is</h3>"
            "<p class='sub'>Argus watches public caching DNS resolvers. For "
            "each domain on the watch-list it asks a monitored resolver what "
            "the answer is, works out the answer independently, and compares "
            "the two. It is a monitoring system, not a DNS server: it holds no "
            "cache, answers no queries and has no clients.</p>"
            "<p class='sub' style='margin-bottom:0'>A caching resolver is the "
            "server your ISP hands you, which remembers answers for a while so "
            "it need not ask again. Cache poisoning is an attacker persuading "
            "that cache to store a wrong answer, so everyone using it is sent "
            "somewhere else.</p></div>"
            "<div class='panel'><h3>The two paths</h3>"
            "<p class='sub'>Every check resolves the same name twice.</p>"
            "<div class='pathbox untrusted' style='margin-bottom:10px'>"
            "<h4>Untrusted path &mdash; the monitored cache</h4>"
            "<code class='cmd'>dig @&lt;resolver-ip&gt; &lt;domain&gt;</code>"
            "<p class='sub' style='margin:6px 0 0'>What the resolver under "
            "test claims. Never treated as correct.</p></div>"
            "<div class='pathbox trusted'>"
            "<h4>Trusted path &mdash; walked from the root</h4>"
            "<code class='cmd'>dig +trace &lt;domain&gt;</code>"
            "<p class='sub' style='margin:6px 0 0'>Root &rarr; TLD &rarr; "
            "authoritative, followed by Argus itself with no cache in the way. "
            "This is the reference answer.</p></div></div></div>")

    body += ("<h2>How the comparison is decided</h2>"
             "<p class='note'>A and AAAA records are compared <b>as sets</b>, "
             "never first-address-to-first-address. A name legitimately having "
             "several addresses is normal, and the order they arrive in is "
             "not meaningful.</p>")

    rows = ""
    for result, tone, meaning in (
        ("Match", "ok", "The resolver's address set equals the trusted set."),
        ("Partial", "warn", "The resolver returned a subset of the trusted "
                            "addresses. Usually load balancing or a partly "
                            "filled cache, not an attack."),
        ("Mismatch", "bad", "The resolver returned an address the zone does "
                            "not publish. This is the shape poisoning takes, "
                            "and the only one that can escalate."),
        ("Not measured", "muted", "One side could not be reached, so no "
                                  "comparison was possible and no judgement "
                                  "is made."),
    ):
        rows += ("<tr><td>" + badge(result, tone, True) + "</td>"
                 "<td class='wrap'>" + e(meaning) + "</td></tr>")
    body += table(["Result", "What it means"], rows, 2)

    body += ("<h2>Before anything is called poisoning</h2>"
             "<p class='sub' style='max-width:80ch'>A mismatch is where the "
             "work starts. Six stages run before a verdict is issued, and any "
             "one of them can explain the difference away.</p>")
    stages = ""
    for number, name, what in (
        (1, "Compare", "The set comparison above. A match or an explained "
                       "difference stops here."),
        (2, "Re-walk the hierarchy", "Resolve independently a second time. If "
                                     "ground truth itself moved between the "
                                     "two walks, the difference may just be "
                                     "the zone changing."),
        (3, "Ask cross-check resolvers",
            "Query independent public recursives. If they see the same odd "
            "answer, it is legitimate &mdash; a content-delivery edge or a "
            "regional record, not one poisoned cache."),
        (4, "DNSSEC", "If the zone is signed, unpublished data is more "
                      "suspicious. Supporting evidence only, never proof."),
        (5, "Persistence", "Re-query several times. An answer that does not "
                           "reproduce every time is transient, not injected."),
        (6, "Decide", "Combine the evidence into one classification, stored "
                      "with the reason."),
    ):
        stages += ("<li><b>Stage " + str(number) + " &mdash; " + e(name)
                   + "</b>" + e(what) + "</li>")
    body += ("<div class='panel'><ul class='stages'>" + stages + "</ul></div>")

    body += "<h2>The three verdicts</h2><div class='grid2'>"
    for name, tone, meaning in (
        (verdict.NO_POISONING, "ok",
         "The resolver's answer was corroborated, or the difference had a "
         "legitimate explanation."),
        (verdict.INCONCLUSIVE, "warn",
         "Something was seen but the evidence supports neither conclusion. "
         "Reporting it as clean would hide a real observation; reporting it as "
         "poisoning would overstate the evidence."),
        (verdict.POSSIBLE, "bad",
         "A resolver persistently served addresses that neither the "
         "authoritative servers nor any independent resolver corroborated. "
         "Possible, never proven: proof would need the resolver's own cache "
         "contents or capture of the injection, which a passive observer "
         "cannot obtain."),
    ):
        body += ("<div class='panel'><h3>" + badge(name, tone) + "</h3>"
                 "<p class='sub' style='margin-bottom:0'>" + e(meaning)
                 + "</p></div>")
    body += "</div>"

    body += ("<h2>Legitimate reasons an answer can differ</h2>"
             "<p class='sub'>Every one of these is tested before a difference "
             "becomes a finding.</p><div class='grid2'>")
    for title, text in verdict.BENIGN_EXPLANATIONS:
        body += ("<div class='panel'><h3>" + e(title) + "</h3>"
                 "<p class='small muted' style='margin:0'>" + e(text)
                 + "</p></div>")
    body += "</div>"

    # A real recorded difference, if the database has one. Never a made-up one.
    recent = storage.recent_anomalies(1)
    body += "<h2>A worked example from this database</h2>"
    if recent:
        a = recent[0]
        body += ("<p class='sub'>The most recent difference on record, and the "
                 "verdict it received.</p>"
                 "<div class='panel'><dl class='kv'>"
                 "<dt>Observed</dt><dd>" + ts(a["observed_at"]) + "</dd>"
                 "<dt>Domain</dt><dd class='mono'>" + e(a["domain"]) + " ("
                 + e(a["rtype"]) + ")</dd>"
                 "<dt>Resolver</dt><dd>" + e(a["resolver"]) + "</dd>"
                 "<dt>Classification</dt><dd>"
                 + badge(a["classification"], verdict.tone_of(a["classification"]))
                 + "</dd><dt>Reported verdict</dt><dd>"
                 + badge(verdict.verdict_of(a["classification"]),
                         verdict.tone_of(a["classification"]))
                 + "</dd><dt>Why that verdict</dt><dd>"
                 + e(verdict.rationale_of(a["classification"])) + "</dd>"
                 "<dt>Engine's reason</dt><dd>" + e(a["reason"] or "&mdash;")
                 + "</dd></dl>"
                 "<p class='sub' style='margin:12px 0 0'>The full evidence for "
                 "every confirmed event is on the "
                 "<a href='" + link("poisoning", live) + "'>Cache Poisoning "
                 "Detection</a> page; everything under review is on "
                 "<a href='" + link("anomalies", live) + "'>Alerts</a>.</p>"
                 "</div>")
    else:
        body += ("<div class='panel'>" + empty_state(
            "No difference recorded yet",
            "When a resolver disagrees with the authoritative hierarchy, the "
            "example will be filled in from that measurement.") + "</div>")

    body += ("<h2>Running it</h2>"
             "<div class='panel'><dl class='kv'>"
             "<dt>One sweep</dt><dd><code>python -m argus run-once</code></dd>"
             "<dt>Continuous</dt><dd><code>python -m argus serve</code></dd>"
             "<dt>This dashboard</dt><dd><code>python -m argus dashboard</code>"
             "</dd>"
             "<dt>Static copy</dt><dd><code>python -m argus report</code></dd>"
             "<dt>A PDF report</dt><dd><code>python -m argus export --type "
             "summary --format pdf</code></dd>"
             "<dt>Configuration</dt><dd>See the "
             "<a href='" + link("settings", live) + "'>Settings</a> page for "
             "every value in force and the file that sets it.</dd>"
             "</dl></div>")

    body += note("Argus measures from a single vantage point. A domain that "
                 "legitimately answers differently by region can therefore "
                 "look like a disagreement, which is why the cross-check stage "
                 "exists and why content-delivery domains are kept off the "
                 "watch-list.")
    return body


# -- 7. REPORTS -------------------------------------------------------------
#
# Six views behind one navigation entry. Every figure on every one of them is
# read from the database through `reporting`, which builds a report once and
# renders it to HTML here, to PDF and to CSV for download -- so a preview can
# never show something a downloaded file does not contain.
#
# Where the database has nothing, the view shows an empty state. It never pads
# a page with zeroes, because a zero that was measured and a zero that was
# never measured mean different things.

REPORT_VIEWS = (
    ("selection", "Reports"),
    ("preview", "Report preview"),
    ("summary", "Summary"),
    ("resolver", "Resolver health"),
    ("domain", "Domain analysis"),
    ("alerts", "Alerts"),
)


def _view_link(live: bool, view: str, extra: str = "") -> str:
    return link("reports", live, "?view=" + view + extra)


def _tabs(live: bool, current: str) -> str:
    out = "<div class='tabs'>"
    for key, label in REPORT_VIEWS:
        cls = " class='on'" if key == current else ""
        out += "<a" + cls + " href='" + _view_link(live, key) + "'>" + e(label) + "</a>"
    return out + "</div>"


def _radio(name: str, value: str, label: str, current: str,
           description: str = "") -> str:
    checked = " checked" if value == current else ""
    return ("<label class='choice'><input type='radio' name='" + name
            + "' value='" + e(value) + "'" + checked + "><span><b>" + e(label)
            + "</b>" + ("<i>" + e(description) + "</i>" if description else "")
            + "</span></label>")


def _checkbox(name: str, value: str, label: str, checked: bool) -> str:
    return ("<label class='choice'><input type='checkbox' name='" + name
            + "' value='" + e(value) + "'" + (" checked" if checked else "")
            + "><span><b>" + e(label) + "</b></span></label>")


def _has_data(storage) -> bool:
    return (storage.table_counts().get("query_results", 0) or 0) > 0


def _no_data_state(live: bool) -> str:
    """Shown on every report view until a sweep has recorded something."""
    return empty_state(
        "No monitoring data yet",
        "Argus has not recorded a measurement at this vantage point. Run a "
        "sweep with  python -m argus run-once  and reload; reports are built "
        "only from stored results.",
        "<p class='small muted' style='margin:10px 0 0'>The Independent "
        "Verification page can check a single domain right now without waiting "
        "for a sweep.</p>")


# -- page 1: report selection ----------------------------------------------

def _report_form(live: bool, kind: str, since: str, until: str, fmt: str,
                 flags: dict, enabled: bool) -> str:
    """The four-step generator, as plain HTML with no script.

    Three submit buttons on one form: preview renders on this page, and the
    other two use `formaction` to send the same values to the download route.
    """
    types = "".join(_radio("kind", key, title, kind, blurb)
                    for key, title, blurb in reporting.REPORT_TYPES)
    formats = "".join(_radio("format", key, reporting.FORMAT_LABELS[key], fmt)
                      for key in reporting.FORMATS)
    options = "".join(_checkbox("options", key, label, flags.get(key, False))
                      for key, label in reporting.OPTIONS)

    if not enabled:
        actions = ("<p class='small muted' style='margin:0'>Reports need stored "
                   "measurements. Run <code>python -m argus run-once</code> "
                   "first.</p>")
    elif live:
        actions = ("<button type='submit'>Preview</button>"
                   "<button type='submit' class='primary' formaction='"
                   + REPORT_DOWNLOAD + "'>Generate &amp; download</button>")
    else:
        actions = ("<button type='submit'>Preview</button>"
                   "<span class='muted small'>Downloading needs the built-in "
                   "server: <code>python -m argus dashboard</code></span>")

    return ("<form class='builder' method='get' action='"
            + link("reports", live) + "'>"
            "<input type='hidden' name='view' value='preview'>"
            "<input type='hidden' name='opts' value='1'>"
            "<div class='steps'>"
            "<div class='step'><h4>1. Select report type</h4>"
            "<div class='choices'>" + types + "</div></div>"
            "<div class='step'><h4>2. Select time period</h4>"
            "<div class='field'><label for='since'>From</label>"
            "<input id='since' name='since' type='date' value='" + e(since)
            + "'></div>"
            "<div class='field'><label for='until'>To</label>"
            "<input id='until' name='until' type='date' value='" + e(until)
            + "'></div>"
            "<p class='hint'>Leave both empty for every measurement on "
            "record.</p>"
            "<h4 class='next'>3. Select format</h4>"
            "<div class='choices'>" + formats + "</div>"
            "<p class='hint'>Excel is a real .xlsx workbook with one sheet "
            "per section; CSV is a single flat file.</p></div>"
            "<div class='step'><h4>4. Options</h4>"
            "<div class='choices'>" + options + "</div>"
            "<div class='builder-actions'>" + actions + "</div></div>"
            "</div></form>")


def _saved_reports(live: bool) -> str:
    rows = ""
    for item in reporting.saved_reports():
        href = REPORT_FILE + "?name=" + e(item["name"])
        size = ("%.0f KB" % (item["size"] / 1024.0) if item["size"] >= 1024
                else "%d B" % item["size"])
        name = ("<a href='" + href + "'>" + e(item["name"]) + "</a>"
                if live else e(item["name"]))
        rows += ("<tr><td>" + name + "</td>"
                 "<td class='small'>" + e(item["kind"]) + "</td>"
                 "<td><span class='chip'>" + e(item["format"]) + "</span></td>"
                 "<td class='small muted'>" + ts(item["modified"]) + "</td>"
                 "<td class='small muted'>" + size + "</td>"
                 "<td>" + badge("Completed", "ok", True) + "</td></tr>")
    if not rows:
        return ("<div class='panel'><h3>Recent reports</h3>"
                + empty_state("No reports generated yet",
                              "Generated files are listed here and kept in the "
                              "reports/ folder.") + "</div>")
    body = ("<div class='panel flush'><h3>Recent reports</h3>"
            + table(["File", "Report", "Format", "Generated", "Size", "Status"],
                    rows, 6) + "</div>")
    if not live:
        body += note("Open the files directly from the <code>reports/</code> "
                     "folder, or start <code>python -m argus dashboard</code> "
                     "to download them from here.")
    return body


def _preview_pane(storage, live: bool, kind, since, until, flags) -> str:
    """The report as it will be downloaded, beside the controls that make it.

    In server mode the actual PDF is embedded, so the pager, the zoom and the
    page count are the browser's own and match the file byte for byte. A saved
    static copy has no server to fetch it from, so it falls back to rendering
    the same report as HTML.
    """
    header = ("<div class='panel-head'><div><h3>Report preview</h3>"
              "<p class='sub'>Preview the report before downloading.</p></div>")
    if not _has_data(storage):
        return ("<div class='panel'>" + header + "</div>"
                + _no_data_state(live) + "</div>")

    query = ("?kind=" + kind
             + ("&amp;since=" + e(since) if since else "")
             + ("&amp;until=" + e(until) if until else "")
             + "&amp;opts=1"
             + "".join("&amp;options=" + k for k, on in flags.items() if on))

    if live:
        header += ("<div class='panel-actions'>"
                   "<a class='action primary' href='" + REPORT_DOWNLOAD + query
                   + "&amp;format=pdf'>" + ICON_REPORT + "Download PDF</a>"
                   "<a class='action' href='" + REPORT_DOWNLOAD + query
                   + "&amp;format=csv'>CSV</a></div></div>")
        return ("<div class='panel flush'>" + header
                + "<embed class='pdfview' type='application/pdf' src='"
                + REPORT_DOWNLOAD + query + "&amp;format=pdf&amp;inline=1'>"
                "</div>")

    header += ("<span class='muted small'>Start <code>python -m argus "
               "dashboard</code> to download.</span></div>")
    report = reporting.build(
        storage, kind, since=reporting.parse_day(since),
        until=reporting.parse_day(until, end_of_day=True),
        vantage=_vantage(storage), options=flags)
    return ("<div class='panel'>" + header + "</div>"
            + _paper(storage, report, live))


def _selection(storage, live: bool, kind, since, until, fmt, flags) -> str:
    has_data = _has_data(storage)
    body = _report_form(live, kind, since, until, fmt, flags, has_data)
    if not has_data:
        return body + "<div class='panel'>" + _no_data_state(live) + "</div>"
    body += ("<div class='split'><div class='col'>"
             + _preview_pane(storage, live, kind, since, until, flags)
             + "</div><div class='col'>"
             + _saved_reports(live) + _schedule_panel(live)
             + "</div></div>")
    return body


# -- page 2: report preview -------------------------------------------------

def _evidence_panel(storage, live: bool) -> str:
    """The two resolution paths behind the most recent recorded difference.

    Both sides are stored measurements: what the monitored resolver answered,
    and what the authoritative walk returned for the same name at the same
    moment. The dig commands are the standard-tool equivalent, shown so the
    comparison can be repeated by hand -- Argus resolves natively.
    """
    rows = storage.recent_anomalies(1)
    if not rows:
        return ("<h3>Monitoring evidence</h3>"
                + empty_state("No difference recorded",
                              "Every measurement so far agreed with the "
                              "authoritative hierarchy, so there is no "
                              "comparison to show."))
    anomaly = rows[0]
    checks = _evidence(anomaly["checks"])
    stage1 = checks.get("stage1") or {}
    stage2 = checks.get("stage2_authoritative") or {}
    unpublished = set(stage1.get("unpublished") or [])
    trusted = list(stage2.get("records") or [])

    event = next((r for r in storage.search_events(
        limit=1, resolver=anomaly["resolver"], domain=anomaly["domain"],
        rtype=anomaly["rtype"])), None)
    monitored = []
    if event is not None and event["returned_records"]:
        monitored = [x.strip() for x in event["returned_records"].split(",")
                     if x.strip()]

    def lines(values, mark_extra=False):
        if not values:
            return "<span class='muted'>(no records returned)</span>"
        out = ""
        for value in values:
            extra = " extra" if mark_extra and value in unpublished else ""
            out += ("<div class='" + extra.strip() + "'>" + e(value)
                    + ("  &larr; not in the trusted answer" if extra else "")
                    + "</div>")
        return out

    resolver_ip = ""
    for r in storage.list_resolvers():
        if r["name"] == anomaly["resolver"]:
            resolver_ip = r["address"]
            break

    classification = anomaly["classification"]
    result = verdict.short_of(classification)
    tone = verdict.tone_of(classification)

    return (
        "<h3>Monitoring evidence</h3>"
        "<p class='sub'>The most recent difference on record: <b>"
        + e(anomaly["domain"]) + "</b> (" + e(anomaly["rtype"]) + ") on <b>"
        + e(anomaly["resolver"]) + "</b>, " + ts(anomaly["observed_at"])
        + ".</p>"
        "<div class='paths'>"
        "<div class='pathbox untrusted'><h4>Untrusted path &mdash; the cache</h4>"
        "<code class='cmd'>dig +short @" + e(resolver_ip or "&lt;resolver&gt;")
        + " " + e(anomaly["domain"]) + " " + e(anomaly["rtype"]) + "</code>"
        "<div class='ans'>" + lines(monitored, mark_extra=True) + "</div></div>"
        "<div class='pathbox trusted'><h4>Trusted path &mdash; walked from the "
        "root</h4>"
        "<code class='cmd'>dig +trace " + e(anomaly["domain"]) + " "
        + e(anomaly["rtype"]) + "</code>"
        "<div class='ans'>" + lines(trusted) + "</div></div>"
        "</div>"
        "<div class='verdictline'>" + badge(result, tone) + "<b>"
        + e(verdict.verdict_of(classification)) + "</b>"
        "<span>" + e(anomaly["reason"] or stage1.get("reason") or "") + "</span>"
        "</div>"
        "<p class='sub' style='margin-top:10px'>Argus resolves natively rather "
        "than shelling out to dig; the commands above reproduce the same "
        "comparison with standard tools. <code>dig +trace</code> fetches "
        "out-of-bailiwick glue through the local system resolver, whereas the "
        "trusted path sub-walks from the root for it.</p>")


def _paper(storage, report, live: bool) -> str:
    """The report rendered as a sheet, the way the PDF lays it out."""
    return ("<div class='paper'>"
            "<div class='paper-head'>" + ASSET_LOGO
            + "<div class='paper-meta'><b>" + e(report.title) + "</b>"
            "Period: " + e(report.period) + "<br>"
            "Generated: " + ts(report.generated_at) + "<br>"
            "Vantage: " + e(report.vantage) + "</div></div>"
            + _preview(report, live)
            + _evidence_panel(storage, live)
            + "</div>")


def _preview_view(storage, live: bool, report, fmt: str, query: str) -> str:
    if not _has_data(storage):
        return "<div class='panel'>" + _no_data_state(live) + "</div>"
    actions = ""
    if live:
        actions = ("<a class='action primary' href='" + REPORT_DOWNLOAD + query
                   + "&amp;format=pdf'>" + ICON_REPORT + "Download PDF</a>"
                   "<a class='action' href='" + REPORT_DOWNLOAD + query
                   + "&amp;format=csv'>Download CSV</a>")
    else:
        actions = ("<span class='muted small'>Start <code>python -m argus "
                   "dashboard</code> to download this report.</span>")
    return ("<div class='builder-actions' style='margin:0 0 16px'>"
            "<a class='action' href='" + _view_link(live, "selection")
            + "'>&larr; Back to reports</a>" + actions + "</div>"
            + _paper(storage, report, live))


# -- pages 3-6: the individual report views ---------------------------------

def _report_view(storage, live: bool, report) -> str:
    """A built report shown as dashboard sections rather than as a sheet."""
    if not _has_data(storage):
        return "<div class='panel'>" + _no_data_state(live) + "</div>"
    return ("<div class='builder-actions' style='margin:0 0 16px'>"
            "<a class='action' href='" + _view_link(live, "selection")
            + "'>&larr; Back to reports</a>"
            + ("<a class='action primary' href='" + REPORT_DOWNLOAD
               + "?kind=" + report.kind + "&amp;format=pdf'>" + ICON_REPORT
               + "Download PDF</a>" if live else "")
            + "</div>" + _preview(report, live))


def _domain_view(storage, live: bool, params: dict) -> str:
    """Page 5. The table is filtered and paged here, over real rows only."""
    if not _has_data(storage):
        return "<div class='panel'>" + _no_data_state(live) + "</div>"

    get = lambda k: (params.get(k) or "").strip()          # noqa: E731
    search, category, status = get("q").lower(), get("category"), get("status")
    try:
        from ..config import load_settings
        categories = load_settings().categories
    except Exception:                                      # noqa: BLE001
        categories = {}

    rows = []
    for r in storage.rollup("domain"):
        label = categories.get(r["key"], "")
        state = ("Poisoning" if r["poisoning"]
                 else ("Under review" if r["flagged"] else "Healthy"))
        if search and search not in r["key"].lower():
            continue
        if category and label != category:
            continue
        if status and state != status:
            continue
        rows.append((r, label, state))

    options = sorted({c for c in categories.values() if c})
    form = ("<form class='filterbar' method='get' action='"
            + link("reports", live) + "'>"
            "<input type='hidden' name='view' value='domain'>"
            + _select("category", "Category", options, category)
            + _select("status", "Status",
                      ["Healthy", "Under review", "Poisoning"], status)
            + "<div class='field grow'><label for='q'>Search</label>"
            "<input id='q' name='q' value='" + e(get("q"))
            + "' placeholder='Search domain...'></div>"
            "<button type='submit'>Filter</button>"
            "<a class='btn' href='" + _view_link(live, "domain")
            + "'>Reset</a></form>")

    tones = {"Healthy": "ok", "Under review": "warn", "Poisoning": "bad"}
    body = ""
    for r, label, state in rows:
        body += ("<tr><td><b>" + e(r["key"]) + "</b></td>"
                 "<td class='small'>" + (e(label) or "<span class='muted'>"
                                         "&mdash;</span>") + "</td>"
                 "<td>" + "{:,}".format(r["checks"]) + "</td>"
                 "<td>" + ("<b>%d</b>" % r["flagged"] if r["flagged"] else "0")
                 + "</td>"
                 "<td class='small muted'>" + ts(r["last_seen"]) + "</td>"
                 "<td>" + badge(state, tones[state], True) + "</td></tr>")

    tiles = ("<div class='kpis'>"
             + kpi("info", KPI_ICONS["domains"], str(len(rows)),
                   "Domains listed")
             + kpi("ok", KPI_ICONS["resolvers"],
                   str(sum(1 for _r, _l, s in rows if s == "Healthy")),
                   "Fully corroborated")
             + kpi("warn", KPI_ICONS["anomalies"],
                   str(sum(1 for _r, _l, s in rows if s == "Under review")),
                   "Under review")
             + kpi("bad" if any(s == "Poisoning" for _r, _l, s in rows) else "ok",
                   KPI_ICONS["uptime"],
                   str(sum(1 for _r, _l, s in rows if s == "Poisoning")),
                   "With possible poisoning")
             + "</div>")

    listing = (table(["Domain", "Category", "Total checks", "Flagged",
                      "Last checked", "Status"], body, 6)
               if body else empty_state(
                   "No domain matches these filters",
                   "Clear the filters to see every monitored domain."))

    return ("<div class='builder-actions' style='margin:0 0 16px'>"
            "<a class='action' href='" + _view_link(live, "selection")
            + "'>&larr; Back to reports</a>"
            + ("<a class='action primary' href='" + REPORT_DOWNLOAD
               + "?kind=domains&amp;format=pdf'>" + ICON_REPORT
               + "Download PDF</a>" if live else "")
            + "</div>" + tiles + "<div class='panel'>" + form + listing
            + "</div>")


def _crontab_entries() -> list:
    """Argus export lines actually installed in the user's crontab.

    Read, never written. Argus has no scheduler of its own -- cron already does
    this well -- so the panel reports what is really scheduled instead of
    offering a toggle that would have nothing behind it.
    """
    import subprocess
    try:
        done = subprocess.run(["crontab", "-l"], capture_output=True, text=True,
                              timeout=5)
    except (OSError, subprocess.SubprocessError):
        return []                                  # no cron on this platform
    if done.returncode != 0:
        return []                                  # no crontab for this user
    out = []
    for line in done.stdout.splitlines():
        line = line.strip()
        if line.startswith("#") or "argus" not in line or "export" not in line:
            continue
        fields = line.split()
        if len(fields) < 6:
            continue
        schedule = " ".join(fields[:5])
        kind = ""
        rest = fields[5:]
        for i, token in enumerate(rest):
            if token == "--type" and i + 1 < len(rest):
                kind = rest[i + 1]
        out.append({"schedule": schedule,
                    "kind": reporting.REPORT_TITLES.get(kind, kind or "Report"),
                    "command": line})
    return out


_CRON_HINT = ("0 6 * * 1 cd %s &amp;&amp; .venv/bin/python -m argus export "
              "--type summary --format pdf --days 7 --no-open")


def _schedule_panel(live: bool) -> str:
    entries = _crontab_entries()
    if entries:
        rows = ""
        for item in entries:
            rows += ("<tr><td><b>" + e(item["kind"]) + "</b></td>"
                     "<td class='mono small'>" + e(item["schedule"]) + "</td>"
                     "<td>" + badge("installed", "ok", True) + "</td></tr>")
        body = table(["Report", "Cron schedule", "Status"], rows, 3)
        body += ("<p class='sub' style='margin:10px 0 0'>Read from "
                 "<code>crontab -l</code>. Edit with <code>crontab -e</code>; "
                 "Argus never writes your crontab.</p>")
    else:
        from ..config import ROOT
        body = (empty_state("No scheduled reports",
                            "Argus has no scheduler of its own -- cron already "
                            "does this well, so nothing here is simulated.")
                + "<p class='sub'>Install one with <code>crontab -e</code>. "
                "This line writes a weekly summary every Monday at 06:00 into "
                "<code>reports/</code>:</p>"
                # One line, deliberately: a crontab entry cannot be continued
                # across lines, so a wrapped command would be copied and fail.
                + "<pre class='cmd'>" + (_CRON_HINT % e(str(ROOT))) + "</pre>")
    return ("<div class='panel'><h3>Scheduled reports</h3>" + body + "</div>")


def settings(storage, live: bool) -> str:
    """The configuration in force, and the file that sets each value.

    Read-only by design. The dashboard is a view of the database; letting a
    browser rewrite the files that decide what gets queried would make the
    monitoring configuration untraceable, so every row names the file to edit.
    """
    try:
        from ..config import load_settings
        cfg = load_settings()
    except Exception as exc:                           # noqa: BLE001
        return "<div class='panel'>" + empty_state(
            "Configuration could not be read", str(exc)) + "</div>"

    counts = storage.table_counts()
    schedule, query = cfg.schedule, cfg.query
    enabled = cfg.enabled_resolvers

    def row(label, value, source):
        return ("<tr><td><b>" + e(label) + "</b></td>"
                "<td class='mono'>" + e(value) + "</td>"
                "<td class='small muted'><code>" + e(source) + "</code></td></tr>")

    general = (row("Vantage name", cfg.vantage, "config/config.yaml: vantage")
               + row("Sweep interval",
                     "%d s (%d min)" % (schedule["interval_seconds"],
                                        max(1, schedule["interval_seconds"] // 60)),
                     "config/config.yaml: schedule.interval_seconds")
               + row("Concurrency", str(schedule.get("concurrency", 1)),
                     "config/config.yaml: schedule.concurrency")
               + row("Pause between queries",
                     "%.2f s" % schedule.get("per_resolver_delay", 0.0),
                     "config/config.yaml: schedule.per_resolver_delay")
               + row("Query timeout", "%.1f s" % query["timeout_seconds"],
                     "config/config.yaml: query.timeout_seconds")
               + row("Retries per query", str(query["retries"]),
                     "config/config.yaml: query.retries")
               + row("Record types", ", ".join(query["rtypes"]),
                     "config/config.yaml: query.rtypes")
               + row("TTL inflation threshold",
                     "%.2fx" % cfg.freshness["max_ttl_ratio"],
                     "config/config.yaml: freshness.max_ttl_ratio")
               + row("DNSSEC checks",
                     "enabled" if cfg.raw.get("dnssec", {}).get("enabled", True)
                     else "disabled", "config/config.yaml: dnssec.enabled")
               + row("Database", str(cfg.db_path),
                     "config/config.yaml: storage.path")
               + row("Report output", str(reporting.reports_dir()),
                     "written by argus export"))

    verification = "".join(
        row(label, str(cfg.verification.get(key)), "config/config.yaml: verification." + key)
        for key, label in (("requery", "Re-query the resolver"),
                           ("rewalk", "Re-walk the hierarchy"),
                           ("control_crosscheck", "Cross-check resolvers"),
                           ("persistence", "Repeats required")))

    resolvers = ""
    for r in cfg.resolvers:
        resolvers += ("<tr><td><b>" + e(r.name) + "</b></td>"
                      "<td class='mono'>" + e(r.address) + "</td>"
                      "<td><span class='chip'>" + e(r.role.upper())
                      + "</span></td><td class='small'>" + e(r.isp) + "</td>"
                      "<td>" + badge("enabled" if r.enabled else "disabled",
                                     "ok" if r.enabled else "muted", True)
                      + "</td>"
                      "<td class='small muted'>"
                      + ("%.1f, %.1f" % (r.map_x, r.map_y) if r.has_location
                         else "not set") + "</td></tr>")

    body = ("<div class='kpis'>"
            + kpi("ok", KPI_ICONS["resolvers"],
                  "%d / %d" % (len(enabled), len(cfg.resolvers)),
                  "Resolvers enabled", link("resolvers", live))
            + kpi("info", KPI_ICONS["domains"], str(len(cfg.watchlist)),
                  "Domains watched", link("domains", live))
            + kpi("muted", KPI_ICONS["uptime"],
                  "%d min" % max(1, schedule["interval_seconds"] // 60),
                  "Sweep interval", "")
            + kpi("muted", KPI_ICONS["anomalies"],
                  "{:,}".format(counts.get("query_results", 0)),
                  "Measurements stored", link("queries", live))
            + "</div>")

    body += note("These values are read from the configuration files on every "
                 "request. The dashboard never writes them: edit the file "
                 "named beside each value, then run a sweep for it to take "
                 "effect.")
    body += "<h2>General</h2>"
    body += table(["Setting", "Value in force", "Set in"], general, 3)
    body += "<h2>Verification engine</h2>"
    body += table(["Stage", "Value in force", "Set in"], verification, 3)
    body += "<h2>Configured resolvers</h2>"
    body += table(["Name", "Address", "Role", "Operator", "State",
                   "Map position"], resolvers, 6)
    body += ("<p class='small muted'>Edit <code>config/resolvers.yaml</code> to "
             "add a resolver or set <code>map_x</code> / <code>map_y</code> "
             "(0-100) so it appears on the national map. Edit "
             "<code>config/watchlist.txt</code> to change the domains, keeping "
             "each under its category heading.</p>")
    return body


def reports(storage, live: bool, params: dict) -> str:
    get = lambda k: (params.get(k) or "").strip()          # noqa: E731
    view = get("view") or "selection"
    if view not in dict(REPORT_VIEWS):
        view = "selection"

    kind = get("kind") or "summary"
    if kind not in reporting.REPORT_TITLES:
        kind = "summary"
    fmt = get("format") if get("format") in reporting.FORMATS else "pdf"
    since_raw, until_raw = get("since"), get("until")
    flags = reporting.resolve_options(params.get("options_list"))

    body = _tabs(live, view)

    if view == "selection":
        return body + _selection(storage, live, kind, since_raw, until_raw,
                                 fmt, flags)
    if view == "domain":
        return body + _domain_view(storage, live, params)

    # The remaining views are a built report, rendered two ways.
    fixed = {"summary": "summary", "resolver": "health", "alerts": "alerts"}
    built_kind = fixed.get(view, kind)
    if not _has_data(storage):
        return body + "<div class='panel'>" + _no_data_state(live) + "</div>"

    report = reporting.build(
        storage, built_kind,
        since=reporting.parse_day(since_raw),
        until=reporting.parse_day(until_raw, end_of_day=True),
        vantage=_vantage(storage), options=flags)

    if view == "preview":
        query = ("?kind=" + built_kind
                 + ("&amp;since=" + e(since_raw) if since_raw else "")
                 + ("&amp;until=" + e(until_raw) if until_raw else ""))
        return body + _preview_view(storage, live, report, fmt, query)
    return body + _report_view(storage, live, report)


def _vantage(_storage) -> str:
    try:
        from ..config import load_settings
        return load_settings().vantage
    except Exception:                                      # noqa: BLE001
        return "local"


def _preview(report, live: bool) -> str:
    """Render a built report as HTML, section by section.

    Deliberately the same section list the PDF renderer walks, so what is shown
    here is what a download contains.
    """
    out = ""
    for index, section in enumerate(report.sections, start=1):
        if section.heading:
            out += "<h3>" + str(index) + ". " + e(section.heading) + "</h3>"
        if section.note:
            out += "<p class='sub'>" + e(section.note) + "</p>"

        if section.kind == "tiles":
            out += "<div class='cards'>"
            for label, value, tone in section.payload:
                out += _card(tone, e(value), label)
            out += "</div>"

        elif section.kind == "bars":
            rows = ""
            for label, value, tone in section.payload:
                rows += ("<tr><td><b>" + e(label) + "</b></td>"
                         "<td style='width:70%'>" + bar(value, tone) + "</td></tr>")
            out += table(["", ""], rows, 2)

        elif section.kind == "donut":
            out += donut(section.payload)

        elif section.kind == "trend":
            out += linechart([{"name": entry["name"],
                               "colour": SERIES_COLOURS[i % len(SERIES_COLOURS)],
                               "points": entry["points"]}
                              for i, entry in enumerate(section.payload)])

        elif section.kind == "findings":
            out += findings(section.payload)

        elif section.kind == "scorecards":
            out += "<div class='scores'>"
            for name, value, status, tone in section.payload:
                out += scorecard(name, value, status, tone)
            out += "</div>"

        elif section.kind == "stack":
            total = sum(v for _l, v, _t in section.payload) or 1
            rows = ""
            for label, value, tone in section.payload:
                rows += ("<tr><td>" + badge(label, tone, True) + "</td>"
                         "<td class='mono'>" + "{:,}".format(int(value)) + "</td>"
                         "<td style='width:60%'>"
                         + bar(value / total * 100, tone) + "</td></tr>")
            out += table(["Result", "Count", "Share"], rows, 3)

        elif section.kind == "table":
            spec = section.payload
            rows = ""
            for row in spec["rows"]:
                cells = ""
                for cell in row:
                    if isinstance(cell, tuple):
                        text, tone = cell
                        cells += "<td>" + badge(text, tone, True) + "</td>"
                    else:
                        cells += "<td>" + e(cell) + "</td>"
                rows += "<tr>" + cells + "</tr>"
            out += table([e(h) for h in spec["headers"]], rows,
                         len(spec["headers"]))

        elif section.kind == "kv":
            out += "<div class='panel'><dl class='kv'>"
            for label, value in section.payload:
                out += "<dt>" + e(label) + "</dt><dd>" + e(value) + "</dd>"
            out += "</dl></div>"

        elif section.kind == "text":
            out += note(e(str(section.payload)))
    return out


