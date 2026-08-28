#!/usr/bin/env python3
"""Initialize the Argus database.

    python scripts/init_db.py                      # create schema, seed resolvers+domains from config
    python scripts/init_db.py --with-sample-data   # also load sample monitoring events
    python scripts/init_db.py --db data/test.sqlite3

Idempotent and non-destructive: it only CREATEs tables IF NOT EXISTS and upserts
reference rows. It never drops or deletes existing data.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus import sampledata
from argus.config import load_settings
from argus.storage import Storage


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize the Argus SQLite database.")
    parser.add_argument("--db", default=None, help="database path (default: from config)")
    parser.add_argument("--with-sample-data", action="store_true",
                        help="load sample monitoring events for testing")
    args = parser.parse_args()

    settings = load_settings()
    db_path = args.db or settings.db_path
    storage = Storage(db_path)
    print(f"Schema ready at: {db_path}")

    # Seed reference tables from config (upsert — never deletes).
    for resolver in settings.resolvers:
        storage.upsert_resolver(resolver)
    for domain in settings.watchlist:
        storage.upsert_domain(domain)
    print(f"Seeded {len(settings.resolvers)} resolvers and {len(settings.watchlist)} domains from config.")

    if args.with_sample_data:
        sampledata.load(storage)
        print("Loaded sample monitoring events.")

    print("Table counts:", storage.table_counts())
    storage.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
