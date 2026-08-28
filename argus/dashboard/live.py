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
        return {"error": "No resolver named '%s' is configured." % resolver_name}

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
    elif key == "reports":
        body = pages.reports(storage, live, (params.get("kind") or "").strip())
    else:
        raise KeyError(key)
    # Auto-refresh would discard a submitted verification, so it is not applied there.
    refresh = 0 if key == "verification" else refresh_seconds
    return page(key, vantage, body, live=live, refresh_seconds=refresh)


def build_server(db_path, vantage: str = "local", host: str = "127.0.0.1",
                 port: int = 8080, refresh: int = 15):
    """An HTTPServer that re-renders the requested page from the database."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):                                   # noqa: N802
            parsed = urlparse(self.path)
            key = _ROUTES.get(parsed.path or "/")
            if key is None and parsed.path in ("/index.html", ""):
                key = "overview"
            if key is None:
                self.send_error(404, "No such page")
                return

            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
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
