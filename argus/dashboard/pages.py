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

from . import verdict
from .shell import (HEALTHY, NO_DATA, STATUS_SEVERITY, badge, e, link, ms, note,
                    pct, rate, records, resolver_status, sparkline, status_tone,
                    table, ts)

PAGE_SIZE = 25


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

def overview(storage, live: bool) -> str:
    rows = resolver_summaries(storage)
    counts = storage.table_counts()
    healthy = sum(1 for x in rows if x["status"] == HEALTHY)
    unhealthy = sum(1 for x in rows
                    if x["status"] not in (HEALTHY, NO_DATA))
    alerts = counts.get("alerts", 0)
    anomalies = counts.get("anomalies", 0)
    has_data = counts.get("query_results", 0) > 0

    body = _verdict_banner(alerts, anomalies, has_data)
    if not has_data:
        body += note("No monitoring data available yet. Run a sweep with "
                     "<code>argus run-once</code> (or <code>argus serve</code>), "
                     "then reload.", "warn")

    body += "<h2>System totals</h2><div class='cards'>"
    body += _card("muted", len(rows), "monitored resolvers")
    body += _card("ok", healthy, "healthy")
    body += _card("warn", unhealthy, "unhealthy / alert")
    body += _card("warn", anomalies, "anomalies")
    body += _card("bad", alerts, "possible poisoning")
    body += _card("muted", counts.get("query_results", 0), "queries recorded")
    body += "</div>"

    body += "<h2>Latest alerts</h2>"
    rowsout = ""
    for a in storage.recent_alerts(3):
        rowsout += ("<tr><td class='small muted'>" + ts(a["confirmed_at"]) + "</td>"
                    "<td><b>" + e(a["resolver"]) + "</b></td>"
                    "<td>" + e(a["domain"]) + " <span class='chip'>" + e(a["rtype"])
                    + "</span></td><td>"
                    + badge(verdict.POSSIBLE, "bad", True) + "</td></tr>")
    body += table(["When", "Resolver", "Domain", "Verdict"], rowsout, 4)
    body += ("<p class='small muted'>Full evidence for every event is on the "
             "<a href='" + link("poisoning", live) + "'>Cache Poisoning Detection</a> "
             "page.</p>")

    body += "<h2>Resolver status summary</h2>"
    rowsout = ""
    for x in rows:
        dim = " class='dim'" if x["status"] == NO_DATA else ""
        rowsout += ("<tr" + dim + "><td><b>" + e(x["name"]) + "</b></td>"
                    "<td class='mono'>" + e(x["ip"]) + "</td>"
                    "<td>" + badge(x["status"], status_tone(x["status"])) + "</td>"
                    "<td>" + pct(x["availability"]) + "</td>"
                    "<td>" + ms(x["latency"]) + "</td></tr>")
    body += table(["Resolver", "IP", "Status", "Availability", "Avg latency"], rowsout, 5)
    body += ("<p class='small muted'>Detail and per-resolver breakdown on the "
             "<a href='" + link("resolvers", live) + "'>Resolver Health</a> page.</p>")
    return body


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
                 + " trusted resolvers</dd>"
                 "<dt>Persistence</dt><dd>"
                 + str(stage5.get("reproduced", "—")) + " of "
                 + str(stage5.get("repetitions", "—")) + " repeats</dd>"
                 "<dt>Classification</dt><dd>"
                 + badge(a["status"], verdict.tone_of(a["status"])) + "</dd>"
                 "<dt>Reported verdict</dt><dd>"
                 + badge(verdict.verdict_of(a["status"]),
                         verdict.tone_of(a["status"])) + "</dd></dl></div>")

        trusted = ""
        for name, recs in sorted(answers.items()):
            trusted += ("<tr><td><b>" + e(name) + "</b></td>"
                        "<td class='mono'>" + e(", ".join(recs) or "(none)") + "</td></tr>")
        if not trusted and stage3.get("queried"):
            trusted = ("<tr><td colspan='2' class='muted small'>"
                       + e(", ".join(stage3["queried"])) +
                       " were queried; per-resolver answers were not retained for "
                       "this event.</td></tr>")
        body += ("<div class='panel'><h3>Trusted resolver answers</h3>"
                 + table(["Resolver", "Answer"], trusted, 2) +
                 "<p class='small muted'>" +
                 ("At least one trusted resolver returned the same unexpected data, "
                  "which argues against poisoning."
                  if stage3.get("corroborates_unexpected")
                  else "No trusted resolver returned the unexpected data.") +
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
                 "<li><b>Stage 3 &mdash; trusted resolvers</b>"
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
                 "absent from the authoritative servers, no trusted resolver "
                 "corroborates it, and it persists across repeated queries &mdash; "
                 "is <b>" + verdict.POSSIBLE + "</b> reported.")
    return body


# -- 6. INDEPENDENT VERIFICATION --------------------------------------------

def verification(storage, live: bool, params: dict, result=None) -> str:
    # The choices come from the configuration, not from the database. The
    # resolvers table keeps every name ever recorded, so offering those would
    # list resolvers that are no longer configured and cannot be queried.
    from ..config import load_settings
    try:
        configured = load_settings().resolvers
    except Exception:                                  # noqa: BLE001
        configured = []
    resolver_names = [r.name for r in configured] or         [r["name"] for r in storage.list_resolvers()]
    chosen = (params.get("resolver") or "").strip()
    domain = (params.get("domain") or "").strip()
    rtype = (params.get("rtype") or "A").strip().upper()

    body = note("This page performs a live check. It queries the selected resolver, "
                "the trusted public resolvers, and the authoritative servers for the "
                "zone &mdash; walking Root &rarr; TLD &rarr; authoritative itself &mdash; "
                "then compares the three.")

    body += ("<form class='filters' method='get' action='"
             + link("verification", live) + "'>"
             "<div class='field'><label for='domain'>Domain</label>"
             "<input id='domain' name='domain' value='" + e(domain)
             + "' placeholder='peoplesbank.lk' required></div>"
             + _choose("rtype", "Record type", ["A", "AAAA"], rtype or "A")
             + _choose("resolver", "Monitored resolver", resolver_names,
                       chosen or (resolver_names[0] if resolver_names else ""))
             + "<button type='submit'>Run verification</button></form>")

    if not live:
        body += note("Live verification needs the built-in server. Start it with "
                     "<code>python -m argus dashboard</code>, or run the same check "
                     "from the terminal with "
                     "<code>python scripts/demo_workflow.py &lt;domain&gt; &lt;resolver-ip&gt;</code>.",
                     "warn")
        return body

    if result is None:
        body += note("Choose a domain and a resolver, then select "
                     "<b>Run verification</b>.")
        return body
    if "error" in result:
        body += note(e(result["error"]), "warn")
        return body

    body += "<h2>Monitored result</h2>"
    body += ("<div class='panel'><dl class='kv'>"
             "<dt>Resolver</dt><dd><b>" + e(result["resolver"]) + "</b> "
             "<span class='mono'>" + e(result["resolver_ip"]) + "</span></dd>"
             "<dt>Query</dt><dd>" + e(result["domain"]) + " "
             + e(result["rtype"]) + "</dd>"
             "<dt>Answer</dt><dd class='mono'>"
             + e(", ".join(result["direct"]) or "(none)") + "</dd>"
             "<dt>Response code</dt><dd class='mono'>" + e(result["rcode"]) + "</dd>"
             "<dt>Latency</dt><dd>" + ms(result["latency"]) + "</dd>"
             "<dt>TTL</dt><dd>" + e(result["ttl"] if result["ttl"] is not None else "—")
             + "</dd></dl></div>")

    body += "<h2>Trusted resolver results</h2>"
    rowsout = ""
    for name, info in result["controls"].items():
        agree = "ok" if info["agrees"] else "warn"
        rowsout += ("<tr><td><b>" + e(name) + "</b></td>"
                    "<td class='mono'>" + e(info["ip"]) + "</td>"
                    "<td class='mono'>" + e(", ".join(info["records"]) or "(none)")
                    + "</td><td>" + badge("agrees with authoritative" if info["agrees"]
                                          else "differs", agree, True) + "</td></tr>")
    body += table(["Resolver", "IP", "Answer", "Agreement"], rowsout, 4)

    body += "<h2>Authoritative result</h2>"
    body += ("<div class='panel'><dl class='kv'>"
             "<dt>Answer</dt><dd class='mono'>"
             + e(", ".join(result["authoritative"]) or "(none)") + "</dd>"
             "<dt>Response code</dt><dd class='mono'>"
             + e(result["auth_rcode"]) + "</dd>"
             "<dt>Delegation walked</dt><dd class='mono small'>"
             + e(" | ".join(result["chain"]) or "(direct)") + "</dd>"
             "<dt>Servers asked</dt><dd class='mono small'>"
             + e(", ".join(result["auth_servers"]) or "—") + "</dd></dl></div>")

    body += "<h2>Comparison result</h2>"
    body += ("<div class='panel'><dl class='kv'>"
             "<dt>Stage 1 classification</dt><dd>"
             + badge(result["stage1"], verdict.tone_of(result["stage1"])) + "</dd>"
             "<dt>Final classification</dt><dd>"
             + badge(result["classification"],
                     verdict.tone_of(result["classification"])) + "</dd>"
             "<dt>Reason</dt><dd>" + e(result["reason"]) + "</dd></dl></div>")

    body += dig_commands(result["domain"], result["rtype"], result["resolver_ip"])

    final = result["verdict"]
    tone = verdict.verdict_tone(final)
    explain = {
        verdict.NO_POISONING: "The monitored resolver agrees with the trusted "
                              "resolvers and the authoritative servers.",
        verdict.POSSIBLE: "The monitored resolver differs from the independent "
                          "sources consistently. Possible &mdash; not proven.",
        verdict.INCONCLUSIVE: "The sources disagree in a way that cannot be "
                              "confidently classified.",
    }[final]
    body += ('<div class="verdict ' + tone + '" style="margin-top:18px">'
             '<span class="dot"></span><div><b>' + final + "</b><span>"
             + explain + "</span></div></div>")
    return body


# -- 7. REPORTS -------------------------------------------------------------

REPORT_KINDS = (
    ("daily", "Daily report", "Measurements, anomalies and alerts from the last 24 hours."),
    ("health", "Resolver health report", "Current health metrics for every resolver."),
    ("anomaly", "DNS anomaly report", "Every anomaly with its classification and state."),
    ("poisoning", "Cache-poisoning detection report",
     "Confirmed events with the evidence behind each verdict."),
)


def reports(storage, live: bool, kind: str = "") -> str:
    body = "<div class='grid2'>"
    for key, title, blurb in REPORT_KINDS:
        href = link("reports", live, "?kind=" + key)
        body += ("<div class='panel'><h3>" + e(title) + "</h3>"
                 "<p class='small muted'>" + e(blurb) + "</p>"
                 "<a class='btn' href='" + href + "'>Open</a></div>")
    body += "</div>"
    body += note("The static snapshot written by <code>python -m argus report</code> "
                 "remains unchanged and still opens without a server.")

    if not kind:
        return body

    titles = {k: t for k, t, _b in REPORT_KINDS}
    if kind not in titles:
        return body + note("Unknown report type.", "warn")
    body += "<h2>" + e(titles[kind]) + "</h2>"

    if kind == "health":
        rowsout = ""
        for x in resolver_summaries(storage):
            rowsout += ("<tr><td><b>" + e(x["name"]) + "</b></td>"
                        "<td class='mono'>" + e(x["ip"]) + "</td>"
                        "<td>" + badge(x["status"], status_tone(x["status"])) + "</td>"
                        "<td>" + pct(x["availability"]) + "</td>"
                        "<td>" + ms(x["latency"]) + "</td>"
                        "<td>" + rate(x["correctness"]) + "</td>"
                        "<td>" + e(x["freshness"] or "—") + "</td></tr>")
        body += table(["Resolver", "IP", "Status", "Availability", "Avg latency",
                       "Correctness", "Freshness"], rowsout, 7)

    elif kind == "anomaly":
        rowsout = ""
        for a in storage.recent_anomalies(200):
            cls = a["classification"]
            rowsout += ("<tr><td class='small muted'>" + ts(a["observed_at"]) + "</td>"
                        "<td>" + e(a["resolver"]) + "</td>"
                        "<td>" + e(a["domain"]) + " (" + e(a["rtype"]) + ")</td>"
                        "<td>" + badge(cls, verdict.tone_of(cls), True) + "</td>"
                        "<td>" + badge(verdict.verdict_of(cls),
                                       verdict.tone_of(cls), True) + "</td>"
                        "<td class='wrap small'>" + e(a["reason"] or "—") + "</td></tr>")
        body += table(["When", "Resolver", "Domain", "Classification", "Verdict",
                       "Reason"], rowsout, 6)

    elif kind == "poisoning":
        rowsout = ""
        for a in storage.recent_alerts(200):
            ev = _evidence(a["evidence"])
            s5 = ev.get("stage5_persistence") or {}
            rowsout += ("<tr><td class='small muted'>" + ts(a["confirmed_at"]) + "</td>"
                        "<td>" + e(a["resolver"]) + "</td>"
                        "<td>" + e(a["domain"]) + " (" + e(a["rtype"]) + ")</td>"
                        "<td>" + badge(verdict.POSSIBLE, "bad", True) + "</td>"
                        "<td>" + str(s5.get("reproduced", "—")) + "/"
                        + str(s5.get("repetitions", "—")) + "</td>"
                        "<td class='wrap small'>" + e(ev.get("decision") or "—")
                        + "</td></tr>")
        body += table(["When", "Resolver", "Domain", "Verdict", "Persistence",
                       "Decision"], rowsout, 6)

    else:  # daily
        import time as _time
        since = _time.time() - 86400
        total = storage.count_events(since=since)
        counts = verdict.summarise(
            [r["comparison_classification"]
             for r in storage.search_events(limit=5000, since=since)])
        body += "<div class='cards'>"
        body += _card("muted", total, "measurements (24 h)")
        body += _card("ok", counts[verdict.NO_POISONING], "no poisoning detected")
        body += _card("warn", counts[verdict.INCONCLUSIVE], "inconclusive")
        body += _card("bad", counts[verdict.POSSIBLE], "possible poisoning")
        body += "</div>"
        rowsout = ""
        for a in storage.recent_alerts(20):
            if a["confirmed_at"] and a["confirmed_at"] >= since:
                rowsout += ("<tr><td class='small muted'>" + ts(a["confirmed_at"])
                            + "</td><td>" + e(a["resolver"]) + "</td>"
                            "<td>" + e(a["domain"]) + "</td>"
                            "<td>" + badge(verdict.POSSIBLE, "bad", True)
                            + "</td></tr>")
        body += "<h2>Alerts in the last 24 hours</h2>"
        body += table(["When", "Resolver", "Domain", "Verdict"], rowsout, 4)
    return body
