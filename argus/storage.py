"""DATABASE LAYER — SQLite persistence for historical analysis.

A single local database file (no server, no Docker). Eight tables plus a
convenience view, mirroring the Argus pipeline and the three-tier integrity
model. Relationships are declared with REFERENCES for documentation and join
clarity; foreign-key *enforcement* is left off (SQLite default) so the dev
prototype never fails an insert on ordering — appropriate for a research build.

Tables
------
    resolvers               monitored resolvers (+ controls)
    domains                 the watch-list
    query_results           #3 what a monitored resolver answered   (direct path)
    authoritative_results   #4 what the hierarchy independently returned
    comparisons             #5 classification of one query vs authoritative
    health_metrics          #6 aggregated per-resolver raw metrics
    anomalies               #7 Tier-1 suspicious findings + verification state
    alerts                  #8 Tier-2 verified possible-poisoning events

View
----
    monitoring_events       one row per query joined to its comparison and the
                            authoritative result — the flat historical record
                            (timestamp, resolver, domain, query type, records,
                            TTL, RCODE, response time, verification result,
                            comparison classification, anomaly status).

Safety: init_schema() uses CREATE ... IF NOT EXISTS only — it never drops or
deletes. Normal application execution only ever inserts.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from .models import (Alert, Anomaly, AuthoritativeAnswer, ComparisonResult,
                     DirectAnswer, DnssecStatus, MonitoredResolver, ResolverMetrics)

SCHEMA = """
CREATE TABLE IF NOT EXISTS resolvers (
    name    TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    role    TEXT,
    isp     TEXT,
    country TEXT,
    enabled INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS domains (
    name     TEXT PRIMARY KEY,
    category TEXT,
    enabled  INTEGER DEFAULT 1,
    added_at REAL
);

CREATE TABLE IF NOT EXISTS query_results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at      REAL NOT NULL,
    resolver         TEXT NOT NULL REFERENCES resolvers(name),
    resolver_ip      TEXT,
    domain           TEXT NOT NULL REFERENCES domains(name),
    rtype            TEXT NOT NULL,
    records          TEXT,
    ttl              INTEGER,
    rcode            TEXT,
    response_time_ms REAL,
    authenticated    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_qr_time     ON query_results (observed_at);
CREATE INDEX IF NOT EXISTS idx_qr_resolver ON query_results (resolver);
CREATE INDEX IF NOT EXISTS idx_qr_lookup   ON query_results (domain, rtype);

CREATE TABLE IF NOT EXISTS authoritative_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at REAL NOT NULL,
    domain      TEXT NOT NULL REFERENCES domains(name),
    rtype       TEXT NOT NULL,
    records     TEXT,
    ttl         INTEGER,
    rcode       TEXT,
    chain       TEXT
);
CREATE INDEX IF NOT EXISTS idx_ar_lookup ON authoritative_results (domain, rtype);

CREATE TABLE IF NOT EXISTS comparisons (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at            REAL NOT NULL,
    query_result_id        INTEGER REFERENCES query_results(id),
    authoritative_result_id INTEGER REFERENCES authoritative_results(id),
    resolver               TEXT NOT NULL,
    domain                 TEXT NOT NULL,
    rtype                  TEXT NOT NULL,
    classification         TEXT NOT NULL,
    matched                TEXT,
    unpublished            TEXT,
    missing                TEXT,
    ttl_ratio              REAL,
    ttl_inflated           INTEGER,
    is_anomaly             INTEGER,
    reason                 TEXT
);
CREATE INDEX IF NOT EXISTS idx_cmp_time  ON comparisons (observed_at);
CREATE INDEX IF NOT EXISTS idx_cmp_class ON comparisons (classification);

CREATE TABLE IF NOT EXISTS health_metrics (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    computed_at             REAL NOT NULL,
    resolver                TEXT NOT NULL REFERENCES resolvers(name),
    window_start            REAL,
    window_end              REAL,
    total_queries           INTEGER,
    availability_pct        REAL,
    avg_latency_ms          REAL,
    timeout_rate            REAL,
    servfail_rate           REAL,
    error_rate              REAL,
    correctness_rate        REAL,
    anomaly_rate            REAL,
    possible_poisoning_rate REAL,
    freshness_ok_rate       REAL,
    freshness_status        TEXT,
    ad_rate                 REAL,
    dnssec_posture          TEXT
);
CREATE INDEX IF NOT EXISTS idx_hm_resolver ON health_metrics (resolver, computed_at);

CREATE TABLE IF NOT EXISTS anomalies (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at        REAL NOT NULL,
    comparison_id      INTEGER REFERENCES comparisons(id),
    resolver           TEXT NOT NULL,
    domain             TEXT NOT NULL,
    rtype              TEXT NOT NULL,
    classification     TEXT NOT NULL,
    verification_state TEXT NOT NULL,
    reason             TEXT,
    checks             TEXT
);
CREATE INDEX IF NOT EXISTS idx_an_state ON anomalies (verification_state);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    confirmed_at    REAL NOT NULL,
    anomaly_id      INTEGER REFERENCES anomalies(id),
    resolver        TEXT NOT NULL,
    domain          TEXT NOT NULL,
    rtype           TEXT NOT NULL,
    status          TEXT NOT NULL,
    targeted        INTEGER,
    persisted_count INTEGER,
    evidence        TEXT
);
CREATE INDEX IF NOT EXISTS idx_al_time ON alerts (confirmed_at);

CREATE TABLE IF NOT EXISTS dnssec_status (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at      REAL NOT NULL,
    resolver         TEXT NOT NULL,
    domain           TEXT NOT NULL,
    signed           INTEGER,          -- 1 signed, 0 unsigned, NULL undetermined
    posture          TEXT,
    security         TEXT,
    ad_flag          INTEGER,
    supports_anomaly INTEGER,
    detail           TEXT
);
CREATE INDEX IF NOT EXISTS idx_ds_lookup ON dnssec_status (resolver, domain);

CREATE VIEW IF NOT EXISTS monitoring_events AS
    SELECT
        q.observed_at              AS timestamp,
        q.resolver                 AS resolver,
        q.domain                   AS domain,
        q.rtype                    AS query_type,
        q.records                  AS returned_records,
        q.ttl                      AS ttl,
        q.rcode                    AS rcode,
        q.response_time_ms         AS response_time_ms,
        a.rcode                    AS authoritative_rcode,
        a.records                  AS authoritative_records,
        c.classification           AS comparison_classification,
        c.reason                   AS verification_result,
        c.is_anomaly               AS anomaly_status
    FROM query_results q
    LEFT JOIN comparisons c           ON c.query_result_id = q.id
    LEFT JOIN authoritative_results a ON a.id = c.authoritative_result_id;
"""

# Tables surfaced by the `status` command / table_counts().
_TABLES = ("resolvers", "domains", "query_results", "authoritative_results",
           "comparisons", "health_metrics", "anomalies", "alerts", "dnssec_status")


def _join(records) -> str:
    return ",".join(sorted(records)) if records else ""


class Storage:
    """Owns the SQLite connection, schema and inserts. Never deletes."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self) -> None:
        """Create tables/indexes/view if absent. Idempotent; never destructive."""
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # -- reference data ---------------------------------------------------
    def upsert_resolver(self, r: MonitoredResolver) -> None:
        self._conn.execute(
            "INSERT INTO resolvers (name, address, role, isp, country, enabled) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET address=excluded.address, role=excluded.role, "
            "isp=excluded.isp, country=excluded.country, enabled=excluded.enabled",
            (r.name, r.address, r.role, r.isp, r.country, int(r.enabled)),
        )
        self._conn.commit()

    def upsert_domain(self, name: str, category: str = "", added_at: float = 0.0) -> None:
        self._conn.execute(
            "INSERT INTO domains (name, category, enabled, added_at) VALUES (?,?,1,?) "
            "ON CONFLICT(name) DO UPDATE SET category=excluded.category",
            (name, category, added_at),
        )
        self._conn.commit()

    # -- monitoring events ------------------------------------------------
    def insert_query_result(self, d: DirectAnswer) -> int:
        cur = self._conn.execute(
            "INSERT INTO query_results (observed_at, resolver, resolver_ip, domain, rtype, "
            "records, ttl, rcode, response_time_ms, authenticated) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (d.observed_at, d.resolver, d.resolver_ip, d.domain, d.rtype,
             _join(d.records), d.min_ttl, d.rcode, d.latency_ms, int(d.authenticated)),
        )
        self._conn.commit()
        return cur.lastrowid

    def insert_authoritative_result(self, a: AuthoritativeAnswer) -> int:
        cur = self._conn.execute(
            "INSERT INTO authoritative_results (observed_at, domain, rtype, records, ttl, rcode, chain) "
            "VALUES (?,?,?,?,?,?,?)",
            (a.observed_at, a.domain, a.rtype, _join(a.records), a.ttl, a.rcode,
             " | ".join(a.chain)),
        )
        self._conn.commit()
        return cur.lastrowid

    def insert_comparison(self, c: ComparisonResult, resolver: str, domain: str,
                          query_result_id: Optional[int] = None,
                          authoritative_result_id: Optional[int] = None,
                          observed_at: float = 0.0) -> int:
        cur = self._conn.execute(
            "INSERT INTO comparisons (observed_at, query_result_id, authoritative_result_id, "
            "resolver, domain, rtype, classification, matched, unpublished, missing, "
            "ttl_ratio, ttl_inflated, is_anomaly, reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (observed_at, query_result_id, authoritative_result_id, resolver, domain, c.rtype,
             c.classification.value, _join(c.matched), _join(c.unpublished), _join(c.missing),
             c.ttl_ratio, int(c.ttl_inflated), int(c.classification.needs_review), c.reason),
        )
        self._conn.commit()
        return cur.lastrowid

    def insert_health_metrics(self, m: ResolverMetrics, computed_at: float) -> int:
        cur = self._conn.execute(
            "INSERT INTO health_metrics (computed_at, resolver, window_start, window_end, "
            "total_queries, availability_pct, avg_latency_ms, timeout_rate, servfail_rate, "
            "error_rate, correctness_rate, anomaly_rate, possible_poisoning_rate, "
            "freshness_ok_rate, freshness_status, ad_rate, dnssec_posture) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (computed_at, m.resolver, m.window_start, m.window_end, m.total_queries,
             m.availability_pct, m.avg_latency_ms, m.timeout_rate, m.servfail_rate,
             m.error_rate, m.correctness_rate, m.anomaly_rate, m.possible_poisoning_rate,
             m.freshness_ok_rate, m.freshness_status, m.ad_rate, m.dnssec_posture),
        )
        self._conn.commit()
        return cur.lastrowid

    def insert_anomaly(self, a: Anomaly, comparison_id: Optional[int] = None) -> int:
        rec = a.record
        cur = self._conn.execute(
            "INSERT INTO anomalies (observed_at, comparison_id, resolver, domain, rtype, "
            "classification, verification_state, reason, checks) VALUES (?,?,?,?,?,?,?,?,?)",
            (a.observed_at, comparison_id, rec.resolver, rec.domain, rec.rtype,
             a.classification.value, a.state.value, a.reason, json.dumps(a.checks)),
        )
        self._conn.commit()
        return cur.lastrowid

    def insert_alert(self, alert: Alert, anomaly_id: Optional[int] = None) -> int:
        rec = alert.anomaly.record
        cur = self._conn.execute(
            "INSERT INTO alerts (confirmed_at, anomaly_id, resolver, domain, rtype, status, "
            "targeted, persisted_count, evidence) VALUES (?,?,?,?,?,?,?,?,?)",
            (alert.confirmed_at, anomaly_id, rec.resolver, rec.domain, rec.rtype,
             "POSSIBLE_CACHE_POISONING", int(alert.targeted), alert.persisted_count,
             json.dumps(alert.evidence)),
        )
        self._conn.commit()
        return cur.lastrowid

    def insert_dnssec_status(self, s: DnssecStatus) -> int:
        signed = None if s.signed is None else int(s.signed)
        cur = self._conn.execute(
            "INSERT INTO dnssec_status (observed_at, resolver, domain, signed, posture, "
            "security, ad_flag, supports_anomaly, detail) VALUES (?,?,?,?,?,?,?,?,?)",
            (s.observed_at, s.resolver, s.domain, signed, s.posture.value,
             s.security.value, int(s.ad_flag), int(s.supports_anomaly), s.detail),
        )
        self._conn.commit()
        return cur.lastrowid

    # -- historical queries ----------------------------------------------
    def recent_dnssec(self, limit: int = 50) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM dnssec_status ORDER BY observed_at DESC LIMIT ?", (limit,)
        ).fetchall()

    def recent_events(self, limit: int = 50) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM monitoring_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()

    def recent_anomalies(self, limit: int = 50) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM anomalies ORDER BY observed_at DESC LIMIT ?", (limit,)
        ).fetchall()

    def recent_alerts(self, limit: int = 50) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM alerts ORDER BY confirmed_at DESC LIMIT ?", (limit,)
        ).fetchall()

    def metric_history(self, resolver: str, limit: int = 100) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM health_metrics WHERE resolver=? ORDER BY computed_at DESC LIMIT ?",
            (resolver, limit),
        ).fetchall()

    def list_resolvers(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM resolvers ORDER BY role DESC, name").fetchall()

    def latest_health(self, resolver: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM health_metrics WHERE resolver=? ORDER BY computed_at DESC LIMIT 1",
            (resolver,)).fetchone()

    def latest_dnssec(self, resolver: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM dnssec_status WHERE resolver=? ORDER BY observed_at DESC LIMIT 1",
            (resolver,)).fetchone()

    # -- filtered / paginated reads (used by the dashboard pages) ---------
    @staticmethod
    def _event_filters(resolver: str = "", domain: str = "", rtype: str = "",
                       classification: str = "", since: float = 0.0,
                       search: str = "") -> tuple[str, list]:
        """Build a WHERE clause over monitoring_events. Empty filters are ignored."""
        clauses, params = [], []
        if resolver:
            clauses.append("resolver = ?")
            params.append(resolver)
        if domain:
            clauses.append("domain = ?")
            params.append(domain)
        if rtype:
            clauses.append("query_type = ?")
            params.append(rtype)
        if classification:
            clauses.append("comparison_classification = ?")
            params.append(classification)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if search:
            clauses.append("(domain LIKE ? OR resolver LIKE ? OR returned_records LIKE ?)")
            like = "%" + search + "%"
            params.extend([like, like, like])
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def search_events(self, limit: int = 25, offset: int = 0,
                      **filters) -> list[sqlite3.Row]:
        """A page of monitoring events, newest first, matching the filters."""
        where, params = self._event_filters(**filters)
        return self._conn.execute(
            "SELECT * FROM monitoring_events" + where +
            " ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset]).fetchall()

    def count_events(self, **filters) -> int:
        """How many monitoring events match the filters (for pagination)."""
        where, params = self._event_filters(**filters)
        return self._conn.execute(
            "SELECT count(*) FROM monitoring_events" + where, params).fetchone()[0]

    def distinct_events_column(self, column: str) -> list[str]:
        """Distinct values of one monitoring_events column, for filter menus."""
        allowed = {"resolver", "domain", "query_type", "comparison_classification"}
        if column not in allowed:
            raise ValueError("column not allowed: " + column)
        rows = self._conn.execute(
            "SELECT DISTINCT " + column + " FROM monitoring_events"
            " WHERE " + column + " IS NOT NULL AND " + column + " <> ''"
            " ORDER BY " + column).fetchall()
        return [r[0] for r in rows]

    def anomaly_by_id(self, anomaly_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM anomalies WHERE id = ?", (anomaly_id,)).fetchone()

    def alert_by_id(self, alert_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()

    def events_for_resolver(self, resolver: str, limit: int = 20) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM monitoring_events WHERE resolver = ?"
            " ORDER BY timestamp DESC LIMIT ?", (resolver, limit)).fetchall()

    def table_counts(self) -> dict[str, int]:
        return {t: self._conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                for t in _TABLES}

    def close(self) -> None:
        self._conn.close()
