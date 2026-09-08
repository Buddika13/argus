"""LIVE — the built-in web server and the on-demand verification check.

The server routes one URL per dashboard page and re-reads the database on every
request, so the pages always reflect what the backend has written. Filtering,
paging and resolver selection are handled here as ordinary query parameters,
which keeps every page free of JavaScript.

The verification check reuses the existing pipeline modules unchanged —
`ResolverProbe`, `AuthoritativeVerifier`, `compare` and `AnomalyVerifier`. It
does not implement any DNS logic of its own.
"""

from __future__ import annotations

import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from .. import reporting
from ..comparison import compare
from ..models import MonitoredResolver
from ..probe import ResolverProbe
from ..storage import Storage
from ..verification import AnomalyVerifier
from ..verifier import AuthoritativeVerifier
from . import pages, verdict
from .shell import PAGES, page

log = logging.getLogger("argus.dashboard")

_ROUTES = {p[2]: p[0] for p in PAGES}          # "/resolvers" -> "resolvers"

# Routes that return a file instead of a page.
DOWNLOAD_PATH = "/reports/download"
FILE_PATH = "/reports/file"


def _params(query: str) -> dict:
    """Query parameters, one value each, plus every repeated `options` value.

    Checkboxes submit the same name once per ticked box, so the multi-valued
    list is kept alongside the collapsed single values the pages expect.
    """
    parsed = parse_qs(query, keep_blank_values=True)
    params = {k: v[0] for k, v in parsed.items()}
    # An unticked checkbox submits nothing, so "no options" and "the form was
    # never submitted" look identical in a query string. The builder sends a
    # hidden marker, which is what tells the two apart: with the marker, an
    # absent option means the reader unticked it; without it, the request came
    # from somewhere else and the defaults apply.
    params["options_list"] = (parsed.get("options", [])
                              if "opts" in parsed else None)
    return params


def build_report(storage, params: dict, vantage: str):
    """Build the report the Reports form is asking for, and its format."""
    kind = (params.get("kind") or "summary").strip()
    if kind not in reporting.REPORT_TITLES:
        raise ValueError("Unknown report type: %s" % kind)
    fmt = (params.get("format") or "pdf").strip().lower()
    if fmt not in reporting.FORMATS:
        raise ValueError("Unknown format: %s" % fmt)
    report = reporting.build(
        storage, kind,
        since=reporting.parse_day(params.get("since", "")),
        until=reporting.parse_day(params.get("until", ""), end_of_day=True),
        vantage=vantage,
        options=reporting.resolve_options(params.get("options_list")))
    return report, fmt


def run_verification(domain: str, rtype: str, resolver_name: str) -> dict:
    """Query one resolver, the controls and the hierarchy; classify the result.

    Reuses the monitoring pipeline rather than duplicating it, so the dashboard
    cannot disagree with what a sweep would have recorded.
    """
    from ..config import load_settings

    domain = (domain or "").strip().rstrip(".")
    rtype = (rtype or "A").strip().upper()
    if not domain:
        return {"error": "Enter a domain to verify."}
    if rtype not in ("A", "AAAA"):
        return {"error": "Record type must be A or AAAA."}

    settings = load_settings()
    target = next((r for r in settings.resolvers if r.name == resolver_name), None)
    if target is None:
        known = ", ".join(r.name for r in settings.resolvers)
        if not resolver_name:
            return {"error": "Choose a monitored resolver, then select Run "
                             "verification. Configured resolvers: " + known}
        return {"error": "No resolver named '%s' is configured. This can happen "
                         "if it was removed from config/resolvers.yaml after "
                         "measurements were recorded. Configured resolvers: %s"
                         % (resolver_name, known)}

    probe = ResolverProbe(timeout=settings.query["timeout_seconds"],
                          retries=settings.query["retries"])
    walk_timeout = settings.raw.get("trusted_walk", {}).get("timeout_seconds", 5.0)
    walker = AuthoritativeVerifier(timeout=walk_timeout)
    controls = [r for r in settings.resolvers if r.role == "control"]

    direct = probe.query(target, domain, rtype)
    truth = walker.resolve(domain, rtype)
    result = compare(direct, truth,
                     max_ttl_ratio=settings.freshness["max_ttl_ratio"])

    classification = result.classification
    reason = result.reason
    if result.classification.needs_review:
        outcome = AnomalyVerifier(probe, walker, controls=controls,
                                  repetitions=2).verify(target, direct, truth, result)
        classification = outcome.classification
        reason = outcome.reason

    control_results = {}
    for control in controls:
        if control.address == target.address and control.port == target.port:
            continue
        answer = probe.query(control, domain, rtype)
        control_results[control.name] = {
            "ip": control.address,
            "records": sorted(answer.records),
            "agrees": bool(answer.records) and answer.records == truth.records,
        }

    return {
        "resolver": target.name, "resolver_ip": target.address,
        "domain": domain, "rtype": rtype,
        "direct": sorted(direct.records), "rcode": direct.rcode,
        "latency": direct.latency_ms, "ttl": direct.min_ttl,
        "authoritative": sorted(truth.records), "auth_rcode": truth.rcode,
        "chain": list(truth.chain), "auth_servers": list(truth.authoritative_servers),
        "controls": control_results,
        "stage1": result.classification.value,
        "classification": classification.value,
        "reason": reason,
        "verdict": verdict.verdict_of(classification.value),
    }


def _scope() -> str:
    """A one-line summary of what is monitored, for the page header."""
    try:
        from ..config import load_settings
        settings = load_settings()
    except Exception:                                  # noqa: BLE001
        return ""
    resolvers = len(settings.enabled_resolvers)
    domains = len(settings.watchlist)
    tlds = len({d.rsplit(".", 1)[-1] for d in settings.watchlist})
    minutes = max(1, int(settings.schedule["interval_seconds"]) // 60)
    # Plain text: the caller escapes this, so HTML entities would be shown
    # literally rather than rendered.
    return ("%d resolvers · %d domains across %d TLDs · every %d min"
            % (resolvers, domains, tlds, minutes))


def render_page(storage: Storage, key: str, vantage: str, params: dict,
                live: bool = True, refresh_seconds: int = 0) -> str:
    """Render one dashboard page by key."""
    if key == "overview":
        body = pages.overview(storage, live)
    elif key == "resolvers":
        body = pages.resolvers(storage, live, (params.get("resolver") or "").strip())
    elif key == "poisoning":
        body = pages.poisoning(storage, live)
    elif key == "queries":
        body = pages.queries(storage, live, params)
    elif key == "anomalies":
        body = pages.anomalies(storage, live, (params.get("id") or "").strip())
    elif key == "verification":
        result = None
        if live and (params.get("domain") or "").strip():
            try:
                result = run_verification(params.get("domain", ""),
                                          params.get("rtype", "A"),
                                          params.get("resolver", ""))
            except Exception as exc:                       # noqa: BLE001
                log.exception("live verification failed")
                result = {"error": "The verification check could not be "
                                   "completed: %s" % exc}
        body = pages.verification(storage, live, params, result)
    elif key == "domains":
        body = pages.domains(storage, live, params)
    elif key == "settings":
        body = pages.settings(storage, live)
    elif key == "help":
        body = pages.help_page(storage, live)
    elif key == "reports":
        body = pages.reports(storage, live, params)
    else:
        raise KeyError(key)
    # Auto-refresh would discard a submitted verification, so it is not applied there.
    refresh = 0 if key == "verification" else refresh_seconds
    # The confirmed-event count rides on the navigation, so it is visible from
    # every page rather than only from the Overview.
    try:
        alerts = storage.table_counts().get("alerts", 0)
    except Exception:                                  # noqa: BLE001
        alerts = 0
    return page(key, vantage, body, live=live, refresh_seconds=refresh,
                scope=_scope(), alerts=alerts, head=pages.head(key, live))


def build_server(db_path, vantage: str = "local", host: str = "127.0.0.1",
                 port: int = 8080, refresh: int = 15):
    """An HTTPServer that re-renders the requested page from the database."""

    class Handler(BaseHTTPRequestHandler):
        def _send_file(self, data: bytes, filename: str, mime: str,
                       inline: bool = False) -> None:
            # `inline` is what lets the Reports page embed the very PDF the
            # download button produces, so the preview cannot drift from the
            # file: same bytes, same route, only the disposition differs.
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Disposition",
                             '%s; filename="%s"'
                             % ("inline" if inline else "attachment", filename))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _download(self, params: dict) -> None:
            """Generate a report, keep a copy, and hand it to the browser."""
            storage = Storage(db_path)
            try:
                report, fmt = build_report(storage, params, vantage)
            except ValueError as exc:
                self.send_error(400, str(exc))
                return
            except Exception:                           # noqa: BLE001
                log.exception("report generation failed")
                self.send_error(500, "The report could not be generated")
                return
            finally:
                storage.close()
            inline = params.get("inline") == "1"
            if inline:
                # The embedded preview refreshes with the page. Keeping a copy
                # of each of those would fill reports/ with a file every few
                # seconds, so a preview renders without saving; only a real
                # download is kept.
                data, name = reporting.render(report, fmt), report.basename(fmt)
            else:
                try:
                    # Saved as well as sent, so it appears under Saved reports
                    # and can be fetched again without rebuilding it.
                    saved = reporting.save(report, fmt)
                    data, name = saved.read_bytes(), saved.name
                except OSError:
                    # A read-only checkout must still be able to download.
                    log.warning("could not write to the reports directory",
                                exc_info=True)
                    data, name = reporting.render(report, fmt), report.basename(fmt)
            self._send_file(data, name, reporting.MIME[fmt], inline=inline)

        def _saved_file(self, params: dict) -> None:
            path = reporting.saved_path(params.get("name", ""))
            if path is None:
                self.send_error(404, "No such report")
                return
            fmt = path.suffix.lstrip(".")
            self._send_file(path.read_bytes(), path.name,
                            reporting.MIME.get(fmt, "application/octet-stream"))

        def do_GET(self):                                   # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == DOWNLOAD_PATH:
                self._download(_params(parsed.query))
                return
            if parsed.path == FILE_PATH:
                self._saved_file(_params(parsed.query))
                return
            key = _ROUTES.get(parsed.path or "/")
            if key is None and parsed.path in ("/index.html", ""):
                key = "overview"
            if key is None:
                self.send_error(404, "No such page")
                return

            params = _params(parsed.query)
            storage = Storage(db_path)
            try:
                body = render_page(storage, key, vantage, params,
                                   live=True, refresh_seconds=refresh
                                   ).encode("utf-8")
            except Exception:                               # noqa: BLE001
                log.exception("failed to render %s", key)
                self.send_error(500, "Page could not be rendered")
                return
            finally:
                storage.close()

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            pass                                            # keep the console quiet

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
