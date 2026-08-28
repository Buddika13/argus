#!/usr/bin/env python3
"""Collect a clean, coherent evaluation dataset with the current code.

Runs N monitoring sweeps into a FRESH database (data/eval.sqlite3) at a fixed
interval, so the stored measurements form one consistent experiment (no sample
data, no pre-fix rows). Everything recorded is a real Argus measurement.

    python scripts/collect_eval.py --sweeps 6 --interval 10
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.config import load_settings
from argus.scheduler import Scheduler
from argus.storage import Storage


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweeps", type=int, default=6)
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--db", default="data/eval.sqlite3")
    args = ap.parse_args()

    logging.basicConfig(level=logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    settings = load_settings()
    settings.raw["storage"]["path"] = args.db
    db_file = settings.db_path
    if db_file.exists():
        db_file.unlink()                      # fresh eval db (not the main store)

    storage = Storage(db_file)
    scheduler = Scheduler(settings, storage)
    print(f"Collecting {args.sweeps} sweeps -> {db_file}")
    for i in range(args.sweeps):
        t0 = time.time()
        summary = scheduler.run_once()
        print(f"  sweep {i+1}/{args.sweeps}: {summary}  ({time.time()-t0:.1f}s)", flush=True)
        if i < args.sweeps - 1:
            time.sleep(args.interval)
    storage.close()
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
