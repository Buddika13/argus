"""REPORTING — downloadable reports, built once and rendered to PDF or CSV.

A report is assembled as a list of typed sections (tiles, tables, charts, prose)
and only then handed to a renderer. Building the content once means the PDF and
the CSV can never disagree about what was measured, and a new format is a new
renderer rather than a second set of queries.

Nothing here re-decides a classification: like the dashboard, it reads what the
detection engine stored and maps it for presentation.

    kinds     summary, health, domains, alerts, dnssec, anomalies
    formats   pdf (argus.pdfdoc, no third-party dependency), csv (stdlib)

Reports are written under `reports/` beside the database so a generated file can
be downloaded again later without regenerating it.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .dashboard import verdict
from .pdfdoc import PdfDocument
from .xlsx import Workbook

# key, title, one-line description
REPORT_TYPES = (
    ("summary", "Summary report",
     "Totals, resolver health, result distribution and findings for the period."),
    ("health", "Resolver health report",
     "Availability, latency, correctness and freshness for every resolver."),
    ("domains", "Domain analysis report",
     "Per-domain check counts, agreement rate and response time."),
    ("alerts", "Alerts report",
     "Confirmed possible-poisoning events with the evidence behind each."),
    ("dnssec", "DNSSEC report",
     "Signedness, resolver posture and authenticated-data flags per domain."),
    ("anomalies", "Anomaly report",
     "Every difference under review, with its classification and state."),
)

REPORT_TITLES = {key: title for key, title, _d in REPORT_TYPES}
# Offered on the Reports page, in this order.
FORMATS = ("pdf", "csv", "xlsx")
FORMAT_LABELS = {"pdf": "PDF", "csv": "CSV", "xlsx": "Excel"}

# Which optional sections a report may carry. The names are what the Reports
# page shows as checkboxes.
OPTIONS = (
    ("charts", "Include charts"),
    ("details", "Include detailed results"),
    ("alerts", "Include alerts"),
    ("limits", "Include limitations"),
)
DEFAULT_OPTIONS = {"charts": True, "details": True, "alerts": True, "limits": True}

_SAFE_NAME = re.compile(r"^argus-[a-z]+-\d{8}-\d{6}\.(pdf|csv|xlsx)$")


# -- section model ----------------------------------------------------------

@dataclass
class Section:
    """One block of a report. `kind` selects how a renderer draws it."""

    kind: str                       # tiles | table | bars | stack | text | kv
    heading: str = ""
    payload: object = None
    note: str = ""


@dataclass
class Report:
    kind: str
    title: str
    subtitle: str
    since: float
    until: float
    generated_at: float
    vantage: str
    sections: list = field(default_factory=list)

    @property
    def period(self) -> str:
        return "%s to %s" % (_day(self.since), _day(self.until))

    def basename(self, extension: str) -> str:
        return "argus-%s-%s.%s" % (
            self.kind, time.strftime("%Y%m%d-%H%M%S",
                                     time.localtime(self.generated_at)), extension)


# -- helpers ----------------------------------------------------------------

def _day(stamp: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(stamp)) if stamp else "the beginning"


def _stamp(stamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(stamp)) if stamp else "-"


def _pct(part: float, whole: float) -> float:
    return (part / whole * 100.0) if whole else 0.0


def _num(value, suffix: str = "") -> str:
    if not isinstance(value, (int, float)):
        return "-"
    return "{:,.0f}{}".format(value, suffix)


def parse_day(text: str, end_of_day: bool = False) -> float:
    """Parse YYYY-MM-DD (or YYYY-MM-DDTHH:MM) into an epoch, or 0.0."""
    text = (text or "").strip()
    if not text:
        return 0.0
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            parsed = time.strptime(text, fmt)
        except ValueError:
            continue
        stamp = time.mktime(parsed)
        if end_of_day and fmt == "%Y-%m-%d":
            stamp += 86399                      # inclusive of the whole day
        return stamp
    return 0.0


def resolve_options(raw) -> dict:
    """Normalise however the caller expressed the options into a flag dict."""
    if raw is None:
        return dict(DEFAULT_OPTIONS)
    if isinstance(raw, dict):
        return {key: bool(raw.get(key, DEFAULT_OPTIONS[key]))
                for key, _label in OPTIONS}
    chosen = {str(x).strip().lower() for x in raw}
    return {key: key in chosen for key, _label in OPTIONS}


def _tone_for(classification: str) -> str:
    return verdict.tone_of(classification)


# -- content builders -------------------------------------------------------

def build(storage, kind: str, since: float = 0.0, until: float = 0.0,
          vantage: str = "local", options=None) -> Report:
    """Assemble a report of the given kind over the given window."""
    if kind not in REPORT_TITLES:
        raise ValueError("unknown report type: %s" % kind)
    flags = resolve_options(options)
    now = time.time()
    report = Report(kind=kind, title=REPORT_TITLES[kind],
                    subtitle="National DNS caching-server health and "
                             "cache-poisoning monitoring",
                    since=since, until=until or now, generated_at=now,
                    vantage=vantage)

    builder = {
        "summary": _summary, "health": _health, "domains": _domains,
        "alerts": _alerts, "dnssec": _dnssec, "anomalies": _anomalies,
    }[kind]
    builder(storage, report, flags)

    if flags["limits"]:
        report.sections.append(Section(
            "text", "Limitations",
            "A verdict of POSSIBLE_CACHE_POISONING means a resolver persistently "
            "returned data that neither the authoritative servers nor any "
            "independent resolver corroborated. It is not proven poisoning: "
            "proof would require the resolver's own cache contents or capture of "
            "the injection, which a passive observer cannot obtain. Measurements "
            "come from a single vantage point, so geographically varying answers "
            "can look like a disagreement. The authoritative walk that provides "
            "ground truth is followed correctly but is not itself "
            "DNSSEC-validated."))
    return report


def _period_filters(report: Report) -> dict:
    return {"since": report.since, "until": report.until}


def _headline(storage, report, window) -> tuple:
    counts = storage.classification_counts(**window)
    total = sum(r["n"] for r in counts)
    benign = sum(r["n"] for r in counts
                 if verdict.verdict_of(r["classification"]) == verdict.NO_POISONING)
    poisoning = sum(r["n"] for r in counts
                    if r["classification"] == "POSSIBLE_CACHE_POISONING")
    resolver_rows = storage.rollup("resolver", **window)
    latencies = [r["avg_latency"] for r in resolver_rows
                 if r["avg_latency"] is not None]
    average = sum(latencies) / len(latencies) if latencies else None
    return counts, total, benign, poisoning, average


def _summary(storage, report, flags) -> None:
    window = _period_filters(report)
    counts, total, benign, poisoning, average = _headline(storage, report, window)

    report.sections.append(Section("tiles", "Executive summary", [
        ("Total checks", _num(total), "info"),
        ("Corroborated answers", "%.1f%%" % _pct(benign, total), "ok"),
        ("Possible poisoning", _num(poisoning), "bad" if poisoning else "ok"),
        ("Avg response", _num(average, " ms") if average else "-", "info"),
    ]))

    resolver_rows = storage.rollup("resolver", **window)
    if flags["charts"]:
        series = _trend_series(storage)
        if series:
            report.sections.append(Section(
                "trend", "DNS query trend", series,
                note="Average response time per resolver, one point per "
                     "recorded sweep."))

        if resolver_rows:
            report.sections.append(Section(
                "bars", "Agreement with the authoritative hierarchy",
                [(r["key"], _pct(r["matched"], r["checks"]),
                  "ok" if _pct(r["matched"], r["checks"]) >= 99 else "warn")
                 for r in sorted(resolver_rows, key=lambda r: r["key"])[:8]],
                note="Share of this resolver's answers that the authoritative "
                     "walk corroborated."))

        report.sections.append(Section(
            "donut", "Result distribution",
            [(verdict.short_of(r["classification"]), r["n"],
              _tone_for(r["classification"])) for r in counts],
            note="%s measurements, by the classification stored for each."
                 % _num(total)))

    report.sections.append(Section(
        "table", "Top domains by checks", _top_domains(storage, window),
        note="The most frequently checked names in this period."))

    report.sections.append(Section(
        "findings", "Key findings", _key_findings(storage, report, window),
        note="Each line restates a measured value; none of them is advice."))

    report.sections.append(Section(
        "table", "Resolver totals",
        {"headers": ["Resolver", "Checks", "Corroborated", "Flagged",
                     "Possible poisoning", "Avg response", "Last seen"],
         "widths": [1.4, 0.8, 1.0, 0.8, 1.2, 1.0, 1.4],
         "aligns": ["l", "r", "r", "r", "r", "r", "l"],
         "rows": [[r["key"], _num(r["checks"]),
                   "%.1f%%" % _pct(r["matched"], r["checks"]),
                   _num(r["flagged"]),
                   (_num(r["poisoning"]), "bad" if r["poisoning"] else "ink"),
                   _num(r["avg_latency"], " ms"), _stamp(r["last_seen"])]
                  for r in resolver_rows]}))

    if flags["alerts"]:
        _alerts(storage, report, flags, heading="Confirmed events in this period")


def _health(storage, report, flags) -> None:
    from .dashboard.pages import resolver_summaries
    rows = resolver_summaries(storage)
    window = _period_filters(report)

    monitored = [x for x in rows if x["enabled"]]
    healthy = [x for x in monitored if x["status"] == "HEALTHY"]
    report.sections.append(Section("tiles", "Health at a glance", [
        ("Resolvers monitored", str(len(monitored)), "info"),
        ("Healthy", str(len(healthy)), "ok"),
        ("Needing attention", str(len(monitored) - len(healthy)),
         "warn" if len(healthy) < len(monitored) else "ok"),
        ("Records compared", _num(storage.count_events(**window)), "info"),
    ]))

    report.sections.append(Section(
        "scorecards", "Correctness by resolver",
        [(x["name"], (x["correctness"] * 100
                      if isinstance(x["correctness"], (int, float)) else None),
          x["status"], _status_tone(x["status"]))
         for x in monitored],
        note="Correctness is a stored metric, not a blended score: the share of "
             "judgeable answers that agreed with the authoritative hierarchy."))

    if flags["charts"] and monitored:
        report.sections.append(Section(
            "bars", "Availability by resolver",
            [(x["name"], x["availability"],
              "ok" if (x["availability"] or 0) >= 100 else "warn")
             for x in monitored if x["availability"] is not None],
            note="Share of queries that received any answer at all."))

        series = _trend_series(storage)
        if series:
            report.sections.append(Section(
                "trend", "Average response time", series,
                note="One point per resolver per recorded sweep."))

    report.sections.append(Section(
        "table", "Health dimension scores",
        {"headers": ["Resolver", "Correctness", "Freshness", "Availability",
                     "DNSSEC (AD)"],
         "widths": [1.4, 1.0, 1.0, 1.0, 1.0],
         "aligns": ["l", "r", "r", "r", "r"],
         "rows": [[x["name"],
                   _dimension(x["correctness"], scale=100),
                   _dimension(x["freshness_rate"], scale=100),
                   _dimension(x["availability"]),
                   _dimension(x["ad_rate"], scale=100)]
                  for x in monitored]},
        note="Every column is one column of the health_metrics table."))

    issues = []
    for a in storage.anomalies_between(**window)[:25]:
        issues.append([_stamp(a["observed_at"]), a["resolver"],
                       "%s (%s)" % (a["domain"], a["rtype"]),
                       (verdict.severity_of(a["classification"]) or "-",
                        verdict.severity_tone(a["classification"])),
                       a["verification_state"], a["reason"] or "-"])
    report.sections.append(Section(
        "table", "Resolver issues",
        {"headers": ["Observed", "Resolver", "Domain", "Severity", "State",
                     "Issue"],
         "widths": [1.3, 1.0, 1.4, 0.8, 1.0, 3.2],
         "aligns": ["l", "l", "l", "l", "l", "l"], "rows": issues}))

    report.sections.append(Section(
        "table", "Health metrics",
        {"headers": ["Resolver", "IP address", "Status", "Availability",
                     "Avg latency", "Correctness", "Freshness", "DNSSEC"],
         "widths": [1.1, 1.2, 1.7, 0.9, 0.9, 0.9, 0.9, 1.4],
         "aligns": ["l", "l", "l", "r", "r", "r", "l", "l"],
         "rows": [[x["name"], x["ip"],
                   (x["status"], _status_tone(x["status"])),
                   "%.0f%%" % x["availability"] if x["availability"] is not None else "-",
                   _num(x["latency"], " ms"),
                   "%.0f%%" % (x["correctness"] * 100)
                   if x["correctness"] is not None else "-",
                   x["freshness"] or "-", x["dnssec"]]
                  for x in rows]}))


def _status_tone(status: str) -> str:
    from .dashboard.shell import status_tone
    return status_tone(status)


def _dimension(value, scale: float = 1.0) -> tuple:
    """One health dimension as a percentage with a tone, or a dash if unmeasured."""
    if not isinstance(value, (int, float)):
        return ("-", "muted")
    percent = value * scale if scale != 1.0 else value
    tone = "ok" if percent >= 99 else ("warn" if percent >= 90 else "bad")
    return ("%.0f%%" % percent, tone)


def _domains(storage, report, flags) -> None:
    window = _period_filters(report)
    rows = storage.rollup("domain", **window)
    flagged = [r for r in rows if r["flagged"]]

    report.sections.append(Section("tiles", "Domain coverage", [
        ("Domains checked", str(len(rows)), "info"),
        ("Fully corroborated", str(len(rows) - len(flagged)), "ok"),
        ("With at least one flag", str(len(flagged)),
         "warn" if flagged else "ok"),
        ("Checks in period", _num(sum(r["checks"] for r in rows)), "info"),
    ]))

    if flags["charts"] and flagged:
        report.sections.append(Section(
            "bars", "Domains with the most flagged answers",
            [(r["key"], float(r["flagged"]), "bad" if r["poisoning"] else "warn")
             for r in flagged[:8]],
            note="Count of answers that were not immediately corroborated. A "
                 "flag is a question, not a finding."))

    report.sections.append(Section(
        "table", "Per-domain results",
        {"headers": ["Domain", "Checks", "Corroborated", "Flagged",
                     "Possible poisoning", "Avg response", "Last checked"],
         "widths": [2.0, 0.8, 1.0, 0.8, 1.2, 1.0, 1.3],
         "aligns": ["l", "r", "r", "r", "r", "r", "l"],
         "rows": [[r["key"], _num(r["checks"]),
                   "%.1f%%" % _pct(r["matched"], r["checks"]),
                   _num(r["flagged"]),
                   (_num(r["poisoning"]), "bad" if r["poisoning"] else "ink"),
                   _num(r["avg_latency"], " ms"), _stamp(r["last_seen"])]
                  for r in rows]}))


def _alerts(storage, report, flags, heading: str = "") -> None:
    window = _period_filters(report)
    rows = storage.alerts_between(**{"since": window["since"],
                                     "until": window["until"]})
    section_rows = []
    for a in rows:
        evidence = _evidence(a["evidence"])
        persistence = evidence.get("stage5_persistence") or {}
        section_rows.append([
            _stamp(a["confirmed_at"]), a["resolver"],
            "%s (%s)" % (a["domain"], a["rtype"]),
            (verdict.POSSIBLE, "bad"),
            "%s/%s" % (persistence.get("reproduced", "-"),
                       persistence.get("repetitions", "-")),
            evidence.get("decision") or "-",
        ])
    if not heading:
        # Severity counts, over confirmed events and everything still under
        # review, so the tiles describe the whole workload rather than only the
        # worst of it.
        anomalies = storage.anomalies_between(**window)
        by_severity = {"High": 0, "Medium": 0, "Low": 0}
        for a in anomalies:
            level = verdict.severity_of(a["classification"])
            if level:
                by_severity[level] += 1
        report.sections.append(Section("tiles", "Alerts in this period", [
            ("Total findings", str(len(anomalies)), "info"),
            ("High severity", str(by_severity["High"]),
             "bad" if by_severity["High"] else "ok"),
            ("Medium severity", str(by_severity["Medium"]),
             "warn" if by_severity["Medium"] else "ok"),
            ("Low severity", str(by_severity["Low"]), "muted"),
        ]))
        report.sections.append(Section(
            "table", "All findings by severity",
            {"headers": ["Time", "Severity", "Domain", "Resolver",
                         "Classification", "State"],
             "widths": [1.3, 0.8, 1.5, 1.0, 1.8, 1.0],
             "aligns": ["l", "l", "l", "l", "l", "l"],
             "rows": [[_stamp(a["observed_at"]),
                       (verdict.severity_of(a["classification"]) or "-",
                        verdict.severity_tone(a["classification"])),
                       "%s (%s)" % (a["domain"], a["rtype"]), a["resolver"],
                       (a["classification"], _tone_for(a["classification"])),
                       a["verification_state"]]
                      for a in anomalies]},
            note="Severity is a display ranking of the stored classification: "
                 "possible poisoning is High, a persistent irregularity is "
                 "Medium, a transient or unmeasurable one is Low."))

    report.sections.append(Section(
        "table", heading or "Confirmed possible-poisoning events",
        {"headers": ["Confirmed", "Resolver", "Domain", "Verdict",
                     "Persistence", "Decision"],
         "widths": [1.3, 1.0, 1.5, 1.7, 0.8, 3.2],
         "aligns": ["l", "l", "l", "l", "r", "l"],
         "rows": section_rows},
        note="Persistence is how many of the repeated queries reproduced the "
             "answer." if section_rows else ""))

    if flags["details"] and rows:
        detail = []
        for a in rows:
            evidence = _evidence(a["evidence"])
            controls = (evidence.get("stage3_controls") or {}).get("answers") or {}
            for name, answer in sorted(controls.items()):
                detail.append([_stamp(a["confirmed_at"]), a["domain"], name,
                               ", ".join(answer) or "(none)"])
        report.sections.append(Section(
            "table", "Cross-check resolver answers at the time",
            {"headers": ["Event", "Domain", "Cross-check resolver", "Answer"],
             "widths": [1.3, 1.6, 1.4, 3.0],
             "aligns": ["l", "l", "l", "l"], "rows": detail},
            note="These independent recursives were asked whether they saw the "
                 "same data. They corroborate; they never define ground truth."))


def _dnssec(storage, report, flags) -> None:
    window = _period_filters(report)
    rows = storage.dnssec_rollup(**window)
    signed = [r for r in rows if r["signed"]]
    authenticated = [r for r in rows if r["ad_flag"]]

    report.sections.append(Section("tiles", "DNSSEC posture", [
        ("Observations", str(len(rows)), "info"),
        ("On signed zones", str(len(signed)), "info"),
        ("Authenticated (AD)", str(len(authenticated)),
         "ok" if authenticated else "warn"),
        ("AD rate", "%.1f%%" % _pct(len(authenticated), len(rows)), "info"),
    ]))
    report.sections.append(Section(
        "table", "Latest observation per domain and resolver",
        {"headers": ["Domain", "Resolver", "Zone signed", "Resolver posture",
                     "Security", "AD flag", "Observed"],
         "widths": [1.8, 1.1, 0.9, 1.3, 1.4, 0.7, 1.3],
         "aligns": ["l", "l", "l", "l", "l", "l", "l"],
         "rows": [[r["domain"], r["resolver"],
                   "yes" if r["signed"] else ("no" if r["signed"] == 0 else "-"),
                   r["posture"] or "-", r["security"] or "-",
                   "yes" if r["ad_flag"] else "no", _stamp(r["observed_at"])]
                  for r in rows]},
        note="DNSSEC is supporting evidence in this system, never proof on its "
             "own: a signed zone makes unpublished data more suspicious."))


def _anomalies(storage, report, flags) -> None:
    window = _period_filters(report)
    rows = storage.anomalies_between(**window)
    by_class: dict[str, int] = {}
    for a in rows:
        by_class[a["classification"]] = by_class.get(a["classification"], 0) + 1

    confirmed = sum(1 for a in rows if a["verification_state"] == "CONFIRMED")
    report.sections.append(Section("tiles", "Anomalies in this period", [
        ("Recorded", str(len(rows)), "info"),
        ("Confirmed", str(confirmed), "warn" if confirmed else "ok"),
        ("Cleared as legitimate",
         str(sum(1 for a in rows if a["verification_state"] == "CLEARED")), "ok"),
        ("Still pending",
         str(sum(1 for a in rows if a["verification_state"] == "PENDING")),
         "warn"),
    ]))

    if flags["charts"] and by_class:
        report.sections.append(Section(
            "stack", "By classification",
            [(verdict.short_of(k), v, _tone_for(k))
             for k, v in sorted(by_class.items(), key=lambda kv: -kv[1])],
            note="Each anomaly counted once, under the classification the "
                 "verification engine settled on."))

    report.sections.append(Section(
        "table", "Every anomaly",
        {"headers": ["Observed", "Resolver", "Domain", "Classification",
                     "Verdict", "State", "Reason"],
         "widths": [1.3, 1.0, 1.4, 1.6, 1.6, 0.9, 3.0],
         "aligns": ["l", "l", "l", "l", "l", "l", "l"],
         "rows": [[_stamp(a["observed_at"]), a["resolver"],
                   "%s (%s)" % (a["domain"], a["rtype"]),
                   (a["classification"], _tone_for(a["classification"])),
                   verdict.verdict_of(a["classification"]),
                   a["verification_state"], a["reason"] or "-"]
                  for a in rows]}))


def _trend_series(storage, limit: int = 24) -> list:
    """Response time per resolver over the recorded sweeps.

    Points come from health_metrics -- one per resolver per sweep -- so the
    chart plots what was measured rather than an interpolation.
    """
    from .dashboard.pages import resolver_summaries
    series = []
    for row in resolver_summaries(storage):
        if not row["enabled"]:
            continue
        history = storage.metric_history(row["name"], limit=limit)
        points = [(h["computed_at"], h["avg_latency_ms"]) for h in history
                  if h["computed_at"] and h["avg_latency_ms"] is not None]
        if points:
            series.append({"name": row["name"], "points": sorted(points)})
    return series


def _key_findings(storage, report, window) -> list:
    """Plain statements of what the numbers say, each traceable to a metric.

    Every line restates something measured. Nothing here is advice, a
    prediction, or a judgement the detection engine did not already make.
    """
    counts, total, benign, poisoning, average = _headline(storage, report, window)
    findings = []
    if not total:
        return [("No measurements were recorded in this period.", "muted")]

    agreement = _pct(benign, total)
    findings.append((
        "Resolvers agreed with the authoritative hierarchy on %.1f%% of %s "
        "checks." % (agreement, _num(total)),
        "ok" if agreement >= 99 else ("warn" if agreement >= 95 else "bad")))

    anomalies = storage.anomalies_between(**window)
    if anomalies:
        confirmed = sum(1 for a in anomalies
                        if a["verification_state"] == "CONFIRMED")
        findings.append((
            "%d difference%s went to verification; %d %s confirmed as a "
            "persistent irregularity." % (
                len(anomalies), "" if len(anomalies) == 1 else "s", confirmed,
                "was" if confirmed == 1 else "were"),
            "warn" if confirmed else "ok"))
    else:
        findings.append(("No difference required investigation in this period.",
                         "ok"))

    if poisoning:
        findings.append((
            "%s answer%s carried the unpublished-address fingerprint of cache "
            "poisoning. Possible, not proven." % (
                _num(poisoning), "" if poisoning == 1 else "s"), "bad"))
    else:
        findings.append(("No answer carried the fingerprint of cache poisoning.",
                         "ok"))

    resolver_rows = storage.rollup("resolver", **window)
    slow = [r for r in resolver_rows if (r["avg_latency"] or 0) > 0]
    if slow:
        worst = max(slow, key=lambda r: r["avg_latency"])
        findings.append((
            "%s was the slowest resolver at %s average response time; the "
            "mean across resolvers was %s." % (
                worst["key"], _num(worst["avg_latency"], " ms"),
                _num(average, " ms")),
            "warn" if worst["avg_latency"] > 1000 else "info"))

    dnssec = storage.dnssec_rollup(**window)
    if dnssec:
        authenticated = sum(1 for r in dnssec if r["ad_flag"])
        rate = _pct(authenticated, len(dnssec))
        findings.append((
            "The authenticated-data flag was set on %.1f%% of %d DNSSEC "
            "observations." % (rate, len(dnssec)),
            "ok" if rate >= 50 else "warn"))
    return findings


def _top_domains(storage, window, limit: int = 5) -> dict:
    rows = storage.rollup("domain", **window)
    busiest = sorted(rows, key=lambda r: -r["checks"])[:limit]
    return {"headers": ["#", "Domain", "Checks", "Flagged", "Agreement",
                        "Status"],
            "widths": [0.3, 2.2, 0.8, 0.7, 0.9, 1.1],
            "aligns": ["r", "l", "r", "r", "r", "l"],
            "rows": [[str(i), r["key"], _num(r["checks"]), _num(r["flagged"]),
                      "%.1f%%" % _pct(r["matched"], r["checks"]),
                      ("Clean", "ok") if not r["flagged"]
                      else (("Poisoning", "bad") if r["poisoning"]
                            else ("Under review", "warn"))]
                     for i, r in enumerate(busiest, start=1)]}


def _evidence(raw):
    try:
        return json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return {}


# -- renderers --------------------------------------------------------------

def to_pdf(report: Report) -> bytes:
    doc = PdfDocument(
        title=report.title,
        subtitle="Argus - " + report.subtitle,
        meta=["Report period : " + report.period,
              "Generated on  : " + time.strftime(
                  "%Y-%m-%d %H:%M:%S", time.localtime(report.generated_at)),
              "Vantage point : " + report.vantage,
              "Generated by  : Argus v" + __version__],
        footer="Argus v%s - %s - possible, never proven" % (__version__,
                                                            report.title))
    for index, section in enumerate(report.sections, start=1):
        if section.heading:
            doc.heading("%d. %s" % (index, section.heading))
        if section.note:
            doc.paragraph(section.note, 8.5)
        if section.kind == "tiles":
            doc.tiles(section.payload)
        elif section.kind == "bars":
            doc.barchart(section.payload)
        elif section.kind in ("stack", "donut"):
            # A donut prints as a proportion bar: on paper a labelled bar is
            # read more accurately than an arc, and it carries the same numbers.
            doc.stacked_bar(section.payload)
        elif section.kind == "trend":
            doc.linechart(section.payload, unit="Response time (ms)")
        elif section.kind == "findings":
            doc.bullets(section.payload)
        elif section.kind == "scorecards":
            doc.tiles([(name, ("%.0f%%" % value)
                        if isinstance(value, (int, float)) else "-", tone)
                       for name, value, _status, tone in section.payload])
        elif section.kind == "table":
            spec = section.payload
            doc.table(spec["headers"], spec["rows"], spec.get("widths"),
                      spec.get("aligns"))
        elif section.kind == "kv":
            doc.kv(section.payload)
        elif section.kind == "text":
            doc.paragraph(str(section.payload), 9.0)
    return doc.render()


def to_csv(report: Report) -> bytes:
    """Every section flattened into one CSV, each preceded by its heading.

    A spreadsheet cannot hold a chart, so a chart section is written as the
    numbers it was drawn from -- the reader loses the picture, not the data.
    """
    buffer = io.StringIO(newline="")
    out = csv.writer(buffer, lineterminator="\r\n")
    out.writerow(["Argus report", report.title])
    out.writerow(["Period", report.period])
    out.writerow(["Generated",
                  time.strftime("%Y-%m-%d %H:%M:%S",
                                time.localtime(report.generated_at))])
    out.writerow(["Vantage", report.vantage])
    out.writerow(["Argus version", __version__])

    def plain(cell):
        return cell[0] if isinstance(cell, tuple) else cell

    for section in report.sections:
        out.writerow([])
        if section.heading:
            out.writerow([section.heading])
        if section.note:
            out.writerow([section.note])
        if section.kind == "tiles":
            out.writerow(["Measure", "Value"])
            for label, value, _tone in section.payload:
                out.writerow([label, value])
        elif section.kind in ("bars", "stack", "donut"):
            out.writerow(["Label", "Value"])
            for label, value, _tone in section.payload:
                out.writerow([label, value])
        elif section.kind == "trend":
            out.writerow(["Resolver", "Time", "Response time (ms)"])
            for entry in section.payload:
                for stamp, value in entry["points"]:
                    out.writerow([entry["name"], _stamp(stamp), round(value, 2)])
        elif section.kind == "findings":
            out.writerow(["Finding"])
            for text, _tone in section.payload:
                out.writerow([text])
        elif section.kind == "scorecards":
            out.writerow(["Resolver", "Correctness", "Status"])
            for name, value, status, _tone in section.payload:
                out.writerow([name,
                              ("%.1f%%" % value)
                              if isinstance(value, (int, float)) else "",
                              status])
        elif section.kind == "table":
            spec = section.payload
            out.writerow(spec["headers"])
            for row in spec["rows"]:
                out.writerow([plain(cell) for cell in row])
        elif section.kind == "kv":
            for label, value in section.payload:
                out.writerow([label, value])
        elif section.kind == "text":
            out.writerow([str(section.payload)])
    return buffer.getvalue().encode("utf-8-sig")


def to_xlsx(report: Report) -> bytes:
    """One sheet per section, with real numbers left numeric.

    A chart cannot go into a plain worksheet, so a chart section is written as
    the rows it was drawn from: the reader loses the picture, never the data,
    and can rebuild the chart in Excel from the numbers.
    """
    book = Workbook(title="%s - Argus" % report.title)

    front = book.sheet("Report")
    front.row(["Argus report", report.title], header=True)
    front.row(["Period", report.period])
    front.row(["Generated", time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(report.generated_at))])
    front.row(["Vantage", report.vantage])
    front.row(["Argus version", __version__])

    def plain(cell):
        return cell[0] if isinstance(cell, tuple) else cell

    for index, section in enumerate(report.sections, start=1):
        name = section.heading or ("Section %d" % index)
        sheet = book.sheet("%d. %s" % (index, name))
        if section.note:
            sheet.row([section.note])
            sheet.blank()

        if section.kind == "tiles":
            sheet.row(["Measure", "Value"], header=True)
            for label, value, _tone in section.payload:
                sheet.row([label, value])
        elif section.kind in ("bars", "stack", "donut"):
            sheet.row(["Label", "Value"], header=True)
            for label, value, _tone in section.payload:
                sheet.row([label, value])
        elif section.kind == "trend":
            sheet.row(["Resolver", "Time", "Response time (ms)"], header=True)
            for entry in section.payload:
                for stamp, value in entry["points"]:
                    sheet.row([entry["name"], _stamp(stamp), round(value, 2)])
        elif section.kind == "findings":
            sheet.row(["Finding"], header=True)
            for text, _tone in section.payload:
                sheet.row([text])
        elif section.kind == "scorecards":
            sheet.row(["Resolver", "Correctness (%)", "Status"], header=True)
            for label, value, status, _tone in section.payload:
                sheet.row([label, round(value, 1)
                           if isinstance(value, (int, float)) else "", status])
        elif section.kind == "table":
            spec = section.payload
            sheet.row(list(spec["headers"]), header=True)
            for row in spec["rows"]:
                sheet.row([plain(cell) for cell in row])
        elif section.kind == "kv":
            sheet.row(["Item", "Value"], header=True)
            for label, value in section.payload:
                sheet.row([label, value])
        elif section.kind == "text":
            sheet.row([str(section.payload)])
    return book.render()


RENDERERS = {"pdf": to_pdf, "csv": to_csv, "xlsx": to_xlsx}
MIME = {
    "pdf": "application/pdf",
    "csv": "text/csv; charset=utf-8",
    "xlsx": ("application/vnd.openxmlformats-officedocument."
             "spreadsheetml.sheet"),
}


def render(report: Report, fmt: str) -> bytes:
    if fmt not in RENDERERS:
        raise ValueError("unknown format: %s" % fmt)
    return RENDERERS[fmt](report)


# -- the saved-reports directory -------------------------------------------

def reports_dir(base: Path | str | None = None) -> Path:
    """Where generated files are kept. Created on demand, never cleaned."""
    from .config import ROOT
    path = Path(base) if base else (ROOT / "reports")
    path.mkdir(parents=True, exist_ok=True)
    return path


def save(report: Report, fmt: str, base: Path | str | None = None) -> Path:
    """Render and write the report, returning the file that was written."""
    target = reports_dir(base) / report.basename(fmt)
    target.write_bytes(render(report, fmt))
    return target


def saved_reports(base: Path | str | None = None, limit: int = 25) -> list[dict]:
    """Previously generated files, newest first."""
    out = []
    for path in sorted(reports_dir(base).glob("argus-*.*"),
                       key=lambda p: p.stat().st_mtime, reverse=True):
        if not _SAFE_NAME.match(path.name):
            continue
        stat = path.stat()
        parts = path.stem.split("-")
        out.append({
            "name": path.name,
            "kind": REPORT_TITLES.get(parts[1], parts[1] if len(parts) > 1 else "-"),
            "format": path.suffix.lstrip(".").upper(),
            "size": stat.st_size,
            "modified": stat.st_mtime,
        })
        if len(out) >= limit:
            break
    return out


def saved_path(name: str, base: Path | str | None = None) -> Path | None:
    """Resolve a saved report by name, refusing anything outside the directory.

    The name arrives from a URL, so it is matched against the exact pattern the
    generator produces rather than merely stripped of separators.
    """
    if not _SAFE_NAME.match(name or ""):
        return None
    path = reports_dir(base) / name
    return path if path.is_file() else None
