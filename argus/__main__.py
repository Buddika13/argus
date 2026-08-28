"""Argus command-line interface.

    python -m argus status      show configuration + database + module readiness
    python -m argus run-once    run one sweep            (implemented in a later step)
    python -m argus serve       run continuously         (implemented in a later step)
    python -m argus report      build the HTML dashboard (implemented in a later step)

Only `status` is functional in the foundation; the others confirm the wiring is
in place and report that their pipeline module is not yet implemented.
"""

from __future__ import annotations

import argparse
import sys

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


def cmd_run_once(_args: argparse.Namespace) -> int:
    from .scheduler import Scheduler
    settings = load_settings()
    _setup_logging(settings.raw["logging"]["level"])
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
    storage = Storage(settings.db_path)
    print(f"Monitoring every {settings.schedule['interval_seconds']}s. Press Ctrl+C to stop.")
    try:
        Scheduler(settings, storage).run_forever()
    finally:
        storage.close()
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

    sub.add_parser("run-once", help="run a single monitoring sweep").set_defaults(func=cmd_run_once)
    sub.add_parser("serve", help="run continuous monitoring").set_defaults(func=cmd_serve)
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
