"""Argus command-line interface.

    python -m argus status      configuration, database and module readiness
    python -m argus run-once    one monitoring sweep of every monitored resolver
    python -m argus serve       continuous monitoring at the configured interval
    python -m argus simulate    feed a known-incorrect answer to the comparison
                                engine (no resolver queried, nothing stored)
    python -m argus report      write the dashboard as static pages
    python -m argus dashboard   serve the dashboard live

Terminology used throughout the codebase and the documentation:

    Public caching DNS resolver   a publicly reachable recursive resolver that
                                  caches answers for its users
    Monitored resolver            the caching resolver currently under test
    Trusted resolution path       resolution performed independently by walking
                                  Root -> TLD -> authoritative ourselves
    Authoritative DNS server      the server authoritative for the queried zone
    Root DNS server               root-level infrastructure; it returns TLD
                                  delegation, never the final address
    TLD name server               the server responsible for delegating within
                                  a top-level domain
    Trusted reference resolver    a public recursive resolver (Google,
                                  Cloudflare, Quad9, OpenDNS, Verisign) used as
                                  a corroborating cross-check. These are
                                  recursive resolvers, NOT authoritative servers
    Possible DNS cache poisoning  a mismatch that survived every independent
                                  check; never a claim of proven poisoning
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import __version__
from .config import load_settings
from .storage import Storage


def cmd_status(_args: argparse.Namespace) -> int:
    settings = load_settings()
    storage = Storage(settings.db_path)
    counts = storage.table_counts()
    storage.close()

    enabled = settings.enabled_resolvers
    print(f"Argus v{__version__}")
    print("=" * 52)
    print(f"vantage            : {settings.vantage}")
    print(f"monitored resolvers: {len(enabled)} enabled / {len(settings.resolvers)} total")
    for r in enabled:
        print(f"    - {r.name:<14} {r.address:<16} [{r.role}] {r.isp}")
    print(f"watch-list domains : {len(settings.watchlist)}")
    for d in settings.watchlist:
        print(f"    - {d}")
    print(f"sweep interval     : {settings.schedule['interval_seconds']}s")
    print(f"record types       : {', '.join(settings.query['rtypes'])}")
    print(f"verification checks : requery={settings.verification['requery']} "
          f"rewalk={settings.verification['rewalk']} "
          f"crosscheck={settings.verification['control_crosscheck']} "
          f"persistence={settings.verification['persistence']}")
    print(f"database           : {settings.db_path}")
    print(f"    tables         : {counts}")
    print(f"dashboard output   : {settings.dashboard_path}")
    print("=" * 52)
    print("Ready. Run `argus run-once` for a sweep, or `argus dashboard` for the live view.")
    return 0


def _setup_logging(level: str = "INFO") -> None:
    import logging
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


class _SweepLock:
    """Prevent two sweeps running against the same database at once.

    Overlapping sweeps contend for the SQLite write lock and query the same
    resolvers simultaneously. Measured cost of one accidental overlap: a sweep
    that normally takes 99s took 2323s. They also corrupt the timing data the
    evaluation depends on, since latency then reflects our own contention.

    A stale lock (left by a crash) is detected by age and taken over.
    """

    STALE_AFTER = 3600.0

    def __init__(self, db_path) -> None:
        self.path = Path(str(db_path) + ".sweep.lock")
        self.acquired = False

    def __enter__(self) -> "_SweepLock":
        try:
            if self.path.exists() and \
                    (time.time() - self.path.stat().st_mtime) > self.STALE_AFTER:
                self.path.unlink()          # left behind by a crashed sweep
            handle = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(handle, str(os.getpid()).encode())
            os.close(handle)
            self.acquired = True
        except FileExistsError:
            self.acquired = False
        except OSError:
            self.acquired = True            # never block monitoring on the lock itself
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.acquired:
            try:
                self.path.unlink()
            except OSError:
                pass


def cmd_run_once(args: argparse.Namespace) -> int:
    from .scheduler import Scheduler
    settings = load_settings()
    _setup_logging(settings.raw["logging"]["level"])

    with _SweepLock(settings.db_path) as lock:
        if not lock.acquired and not getattr(args, "force", False):
            print("Another sweep is already running against this database.")
            print("Overlapping sweeps contend for the SQLite write lock and skew")
            print("every latency measurement. Wait for it to finish, or pass")
            print("--force if you are certain no other sweep is active.")
            return 1
        storage = Storage(settings.db_path)
        try:
            summary = Scheduler(settings, storage).run_once()
        finally:
            storage.close()
    print("Sweep summary:", summary)
    return 0


def cmd_serve(_args: argparse.Namespace) -> int:
    from .scheduler import Scheduler
    settings = load_settings()
    _setup_logging(settings.raw["logging"]["level"])
    with _SweepLock(settings.db_path) as lock:
        if not lock.acquired:
            print("Another sweep or serve process is already running against this")
            print("database. Stop it first, or the two will contend for the write")
            print("lock and distort every latency measurement.")
            return 1
        storage = Storage(settings.db_path)
        print(f"Monitoring every {settings.schedule['interval_seconds']}s. "
              "Press Ctrl+C to stop.")
        try:
            Scheduler(settings, storage).run_forever()
        finally:
            storage.close()
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    """Feed a known-incorrect answer to the comparison engine and show the result.

    Ground truth is resolved for real through the DNS hierarchy; only the
    resolver's side is fabricated. That makes the detection path reproducible
    without touching any real resolver, and without an attacker.

    Nothing is written to the database: the research data must contain only real
    measurements, so a simulated event would contaminate the evaluation.
    """
    from .comparison import compare
    from .models import DirectAnswer, MonitoredResolver
    from .probe import ResolverProbe
    from .verification import AnomalyVerifier
    from .verifier import AuthoritativeVerifier

    settings = load_settings()
    domain, rtype = args.domain.rstrip("."), args.rtype.upper()

    walker = AuthoritativeVerifier(timeout=5.0)
    truth = walker.resolve(domain, rtype)

    fake = frozenset(a.strip() for a in args.fake_ip.split(",") if a.strip())
    injected = DirectAnswer(
        resolver="simulated-resolver", domain=domain, rtype=rtype,
        resolver_ip=args.resolver_ip, records=fake, min_ttl=args.ttl,
        rcode="NOERROR", latency_ms=1.0, authenticated=False)

    print("=" * 74)
    print("ARGUS SIMULATION - a known-incorrect answer through the real engine")
    print("=" * 74)
    print("  domain              : %s %s" % (domain, rtype))
    print("  simulated cached IPs: %s" % ", ".join(sorted(fake)))
    print("  trusted answer      : %s" % (", ".join(sorted(truth.records)) or "(none)"))
    print("  delegation walked   : %s" % (" | ".join(truth.chain) or "(direct)"))
    print("  authoritative server: %s" % (", ".join(truth.authoritative_servers) or "?"))
    print()

    result = compare(injected, truth, max_ttl_ratio=settings.freshness["max_ttl_ratio"])
    print("  stage 1 comparison  : %s" % result.classification.value)
    print("  reason              : %s" % result.reason)
    print("  unpublished by zone : %s"
          % (", ".join(sorted(result.unpublished)) or "(none)"))

    final = result.classification
    if result.classification.needs_review and args.verify:
        controls = [r for r in settings.resolvers if r.role == "control"]
        target = MonitoredResolver("simulated-resolver",
                                   args.resolver_ip, role="isp")
        outcome = AnomalyVerifier(ResolverProbe(timeout=5.0, retries=1), walker,
                                  controls=controls, repetitions=1)
        # The simulated resolver cannot be re-queried, so persistence is asserted
        # from the injected answer rather than measured. Stated, not hidden.
        verified = outcome.verify(target, injected, truth, result)
        final = verified.classification
        print("  final classification: %s" % final.value)
        print("  reason              : %s" % verified.reason)
        print()
        print("  NOTE: the simulated resolver does not exist on the network, so"
              " stages 3\n        and 5 could not query it. Treat this as a check"
              " of the comparison\n        engine, not of the full pipeline. Use"
              " scripts/demo_hijack.py for\n        an end-to-end test against a"
              " real (loopback) resolver.")

    print()
    print("  RESULT              : %s" % (
        "POSSIBLE_CACHE_POISONING"
        if final.value == "POSSIBLE_CACHE_POISONING" else final.value))
    print("  stored              : no - simulated events are never written to the"
          " database")
    print("=" * 74)
    return 0


def cmd_all(args: argparse.Namespace) -> int:
    """Run the whole system end to end and print one consolidated result.

    One command instead of five, for a demonstration or a routine check:
    configuration, a real monitoring sweep, both detection outcomes, the
    dashboard, and a summary of what was found and where the evidence lives.
    """
    from . import dashboard
    from .dashboard import shell, verdict
    from .dashboard.pages import resolver_summaries
    from .scheduler import Scheduler

    settings = load_settings()
    _setup_logging(settings.raw["logging"]["level"])
    step = "[%d/4] "

    print("=" * 74)
    print("ARGUS - full run")
    print("=" * 74)

    # 1. configuration -----------------------------------------------------
    enabled = settings.enabled_resolvers
    tlds = sorted({d.rsplit(".", 1)[-1] for d in settings.watchlist})
    print(step % 1 + "Configuration")
    print("  monitored resolvers : %d  (%s)"
          % (len(enabled), ", ".join(r.name for r in enabled)))
    print("  watch-list domains  : %d across %d TLDs (%s)"
          % (len(settings.watchlist), len(tlds), ", ".join(tlds)))
    print("  sweep interval      : %ds" % settings.schedule["interval_seconds"])

    # 2. a real sweep ------------------------------------------------------
    print()
    print(step % 2 + "Monitoring sweep (this queries every resolver; please wait)")
    with _SweepLock(settings.db_path) as lock:
        if not lock.acquired:
            print("  another sweep is already running - skipping this step")
            summary = None
        else:
            storage = Storage(settings.db_path)
            try:
                started = time.time()
                summary = Scheduler(settings, storage).run_once()
                elapsed = time.time() - started
            finally:
                storage.close()
            print("  %d queries in %.1fs - %d anomalies, %d alerts, %d failures"
                  % (summary["queries"], elapsed, summary["anomalies"],
                     summary["alerts"], summary["failures"]))
            if elapsed > settings.schedule["interval_seconds"]:
                print("  NOTE: the sweep took longer than the configured interval,"
                      " so monitoring\n        cannot actually run that often.")

    # 3. detection check ---------------------------------------------------
    print()
    print(step % 3 + "Detection check (comparison engine, nothing stored)")
    if not args.skip_checks:
        probe_domain = settings.watchlist[0] if settings.watchlist else "example.com"
        for label, fake in (("a forged answer   ", "192.0.2.123"),
                            ("the real answer   ", None)):
            sim = argparse.Namespace(domain=probe_domain, rtype="A", ttl=300,
                                     resolver_ip="192.0.2.1", verify=False,
                                     fake_ip=fake or "")
            if fake is None:
                from .verifier import AuthoritativeVerifier
                truth = AuthoritativeVerifier(timeout=5.0).resolve(probe_domain, "A")
                if not truth.records:
                    print("  %s could not establish ground truth - skipped" % label)
                    continue
                sim.fake_ip = ",".join(sorted(truth.records))
            import io
            import contextlib
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                cmd_simulate(sim)
            result = [ln.split(":", 1)[1].strip() for ln in
                      buffer.getvalue().splitlines() if ln.strip().startswith("RESULT")]
            print("  %s -> %s" % (label, result[0] if result else "?"))
    else:
        print("  skipped (--skip-checks)")

    # 4. dashboard ---------------------------------------------------------
    print()
    print(step % 4 + "Dashboard")
    storage = Storage(settings.db_path)
    try:
        out = dashboard.generate(storage, settings.dashboard_path, settings.vantage)
        rows = resolver_summaries(storage)
        counts = storage.table_counts()
    finally:
        storage.close()
    print("  written to %s" % out)
    if not args.no_open:
        import webbrowser
        webbrowser.open(out.as_uri())
        print("  opened in your browser")

    # final summary --------------------------------------------------------
    print()
    print("=" * 74)
    print("RESULT")
    print("=" * 74)
    for row in rows:
        # Only currently enabled resolvers. Disabled ones keep their last health
        # row in the database, and showing that would imply they are monitored.
        if row["status"] == shell.NO_DATA or not row["enabled"]:
            continue
        print("  %-12s %-16s %-28s availability %s   latency %s"
              % (row["name"], row["ip"], row["status"],
                 ("%.0f%%" % row["availability"]) if row["availability"] is not None
                 else "-",
                 ("%.0f ms" % row["latency"]) if row["latency"] is not None else "-"))
    print()
    print("  possible cache-poisoning events : %d" % counts.get("alerts", 0))
    print("  anomalies recorded              : %d" % counts.get("anomalies", 0))
    print("  measurements stored             : %d" % counts.get("query_results", 0))
    print()
    print("  verdicts reported: %s, %s, %s"
          % (verdict.NO_POISONING, verdict.POSSIBLE, verdict.INCONCLUSIVE))
    print("  evidence          : python scripts/show_evidence.py")
    print("  live dashboard    : python -m argus dashboard")
    print("=" * 74)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    import webbrowser
    from . import dashboard
    settings = load_settings()
    storage = Storage(settings.db_path)
    try:
        out = dashboard.generate(storage, settings.dashboard_path, settings.vantage)
    finally:
        storage.close()
    print(f"Dashboard written to {out}")
    print("Pages:", ", ".join(f[1] for f in dashboard.PAGES))
    if not args.no_open:
        webbrowser.open(out.as_uri())
        print("Opened in your browser.")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    from . import dashboard
    settings = load_settings()
    url = f"http://{args.host}:{args.port}"
    print(f"Live dashboard at {url} (auto-refresh {args.refresh}s). Press Ctrl+C to stop.")
    print("It reads the database on every request, so it shows real-time monitoring data.")
    dashboard.serve(settings.db_path, settings.vantage, args.host, args.port, args.refresh)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argus",
                                     description="DNS resolver health & cache-poisoning monitor.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="show configuration and readiness")
    p_status.set_defaults(func=cmd_status)

    p_once = sub.add_parser("run-once", help="run a single monitoring sweep")
    p_once.add_argument("--force", action="store_true",
                        help="sweep even if another appears to be running")
    p_once.set_defaults(func=cmd_run_once)
    sub.add_parser("serve", help="run continuous monitoring").set_defaults(func=cmd_serve)
    p_all = sub.add_parser(
        "all", help="run everything: sweep, detection check, dashboard, summary")
    p_all.add_argument("--no-open", action="store_true",
                       help="write the dashboard but do not open a browser")
    p_all.add_argument("--skip-checks", action="store_true",
                       help="skip the detection check step")
    p_all.set_defaults(func=cmd_all)

    p_sim = sub.add_parser(
        "simulate",
        help="feed a known-incorrect answer to the comparison engine (no network "
             "resolver involved, nothing stored)")
    p_sim.add_argument("--domain", default="example.com",
                       help="domain whose real authoritative answer is fetched")
    p_sim.add_argument("--fake-ip", default="192.0.2.123",
                       help="the incorrect address(es) to inject, comma separated "
                            "(default: 192.0.2.123, RFC 5737 documentation space)")
    p_sim.add_argument("--rtype", default="A", choices=["A", "AAAA"])
    p_sim.add_argument("--ttl", type=int, default=300,
                       help="TTL the simulated resolver claims")
    p_sim.add_argument("--resolver-ip", default="192.0.2.1",
                       help="address the simulated resolver is labelled with")
    p_sim.add_argument("--verify", action="store_true",
                       help="also run the multi-stage engine. Stages 3 and 5 need a"
                            " real resolver to query, so a simulated one is normally"
                            " downgraded to TEMPORARY_ANOMALY; use"
                            " scripts/demo_hijack.py for an end-to-end test")
    p_sim.set_defaults(func=cmd_simulate)

    p_report = sub.add_parser("report", help="write a one-off static HTML dashboard")
    p_report.add_argument("--no-open", action="store_true", help="write file but do not open browser")
    p_report.set_defaults(func=cmd_report)

    p_dash = sub.add_parser("dashboard", help="serve a live auto-refreshing dashboard")
    p_dash.add_argument("--host", default="127.0.0.1")
    p_dash.add_argument("--port", type=int, default=8080)
    p_dash.add_argument("--refresh", type=int, default=15, help="auto-refresh seconds")
    p_dash.set_defaults(func=cmd_dashboard)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
