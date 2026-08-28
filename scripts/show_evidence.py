#!/usr/bin/env python3
"""Print what the system recorded: measurements, and the evidence behind alerts.

    python scripts/show_evidence.py              # recent measurements + all alerts
    python scripts/show_evidence.py --limit 40   # more measurement rows
    python scripts/show_evidence.py --alerts     # only the alert evidence chains

Reads the database read-only and writes nothing. Use it to answer, for a
supervisor or an examiner, the two questions that matter: what did the system
observe, and on what evidence did it reach its verdict.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.config import load_settings

STAGE_MEANING = {
    "stage1": "set comparison: what the resolver said vs what the zone publishes",
    "stage2_authoritative": "independent re-walk: rules out a glitch in our ground truth",
    "stage3_controls": "control resolvers: rules out a legitimate change we had not seen",
    "stage4_dnssec": "DNSSEC: rules out forgery on a signed zone",
    "stage5_persistence": "repetition: rules out a transient race or stale cache",
}


def when(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


def show_measurements(conn: sqlite3.Connection, limit: int) -> None:
    print("=" * 78)
    print("RECENT MEASUREMENTS  (resolver answer vs authoritative answer)")
    print("=" * 78)
    rows = conn.execute(
        "SELECT timestamp, resolver, domain, query_type, returned_records, "
        "       authoritative_records, comparison_classification "
        "FROM monitoring_events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    if not rows:
        print("  No measurements yet. Run:  python -m argus run-once")
        return
    for row in rows:
        stamp = when(row["timestamp"]) if isinstance(row["timestamp"], (int, float)) \
            else str(row["timestamp"])
        print("  {0}  {1:<12} {2:<16} {3:<5} {4}".format(
            stamp, row["resolver"], row["domain"], row["query_type"],
            row["comparison_classification"]))
        print("      resolver      : {0}".format(row["returned_records"] or "(none)"))
        print("      authoritative : {0}".format(row["authoritative_records"] or "(none)"))
    print()


def show_alerts(conn: sqlite3.Connection) -> None:
    print("=" * 78)
    print("ALERTS AND THEIR EVIDENCE CHAINS")
    print("=" * 78)
    rows = conn.execute(
        "SELECT confirmed_at, resolver, domain, rtype, status, persisted_count, "
        "       evidence FROM alerts ORDER BY id DESC").fetchall()
    if not rows:
        print("  No alerts recorded. Every measurement so far was NORMAL or a")
        print("  benign difference. To demonstrate detection working, run:")
        print("      python scripts/demo_hijack.py")
        print()
        return

    for row in rows:
        print("-" * 78)
        print("  {0}   {1}  {2}/{3}".format(
            when(row["confirmed_at"]), row["resolver"], row["domain"], row["rtype"]))
        print("  status            : {0}".format(row["status"]))
        print("  persisted across  : {0} repeated queries".format(row["persisted_count"]))
        try:
            evidence = json.loads(row["evidence"])
        except (TypeError, ValueError):
            print("  evidence          : (unreadable)")
            continue

        for stage, meaning in STAGE_MEANING.items():
            if stage not in evidence:
                continue
            print("  {0:<20}: {1}".format(stage, meaning))
            detail = evidence[stage]
            if isinstance(detail, dict):
                for key, value in detail.items():
                    print("      {0:<24} {1}".format(key + ":", value))
            else:
                print("      {0}".format(detail))
        if "decision" in evidence:
            print("  DECISION            : {0}".format(evidence["decision"]))
        print()

    print("  Note: surviving all five stages means the answer is uncorroborated -")
    print("  the shape of poisoning. It is not proof. From a single vantage point a")
    print("  forged record and legitimate CDN geo-variance look identical, which is")
    print("  why the strongest label is POSSIBLE_CACHE_POISONING.")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Show recorded measurements and alert evidence.")
    parser.add_argument("--limit", type=int, default=20,
                        help="how many recent measurements to show (default: 20)")
    parser.add_argument("--alerts", action="store_true",
                        help="show only the alert evidence chains")
    args = parser.parse_args()

    db_path = load_settings().db_path
    if not os.path.exists(db_path):
        print("No database at {0}. Run:  python -m argus run-once".format(db_path))
        return 1

    conn = sqlite3.connect("file:{0}?mode=ro".format(db_path), uri=True)
    conn.row_factory = sqlite3.Row
    try:
        if not args.alerts:
            show_measurements(conn, args.limit)
        show_alerts(conn)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
