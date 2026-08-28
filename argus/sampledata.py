"""Sample data for testing the database layer.

Populates every table with a small, representative set of monitoring events by
running real answers through the real comparison and health modules — so the
sample data is internally consistent, not hand-faked. Additive by design:
reference rows (resolvers, domains) are upserted; event rows are appended.

Loaded only when explicitly requested (see scripts/init_db.py --with-sample-data);
never during normal application execution.
"""

from __future__ import annotations

import time

from .comparison import compare
from .integrity import build_record, compute_metrics
from .models import (Alert, Anomaly, AuthoritativeAnswer, Classification,
                     DirectAnswer, DnssecPosture, DnssecStatus, MonitoredResolver,
                     SecurityStatus, VerificationState)
from .storage import Storage

RESOLVERS = [
    MonitoredResolver("google", "8.8.8.8", "control", "Google", "ANY"),
    MonitoredResolver("cloudflare", "1.1.1.1", "control", "Cloudflare", "ANY"),
    MonitoredResolver("quad9", "9.9.9.9", "control", "Quad9", "ANY"),
    MonitoredResolver("isp-demo", "203.0.113.53", "isp", "DemoISP", "LK"),
]

DOMAINS = [("example.com", "global"), ("bank.lk", "finance"), ("ghost.lk", "test")]

# resolver, domain, rtype, direct records/rcode/ttl, authoritative records/rcode/ttl
SCENARIOS = [
    ("google",     "example.com", "A", ["93.184.216.34"], "NOERROR", 300,
     ["93.184.216.34"], "NOERROR", 300),                              # NORMAL
    ("cloudflare", "example.com", "A", ["93.184.216.34"], "NOERROR", 300,
     ["93.184.216.34", "93.184.216.35"], "NOERROR", 300),             # BENIGN subset
    ("google",     "example.com", "A", ["93.184.216.34"], "NOERROR", 86400,
     ["93.184.216.34"], "NOERROR", 300),                              # ANOMALY (TTL inflated)
    ("quad9",      "bank.lk", "A", ["203.94.1.10"], "NOERROR", 300,
     ["203.94.1.10"], "NOERROR", 300),                                # NORMAL
    ("isp-demo",   "bank.lk", "A", ["203.94.1.10", "6.6.6.6"], "NOERROR", 300,
     ["203.94.1.10"], "NOERROR", 300),                                # POSSIBLE (partial)
    ("isp-demo",   "ghost.lk", "A", ["6.6.6.6"], "NOERROR", 300,
     [], "NXDOMAIN", None),                                           # POSSIBLE (phantom)
]


def load(storage: Storage, base_time: float | None = None) -> None:
    now = base_time or time.time()
    by_name = {r.name: r for r in RESOLVERS}

    for r in RESOLVERS:
        storage.upsert_resolver(r)
    for name, category in DOMAINS:
        storage.upsert_domain(name, category, now)

    records_by_resolver: dict[str, list] = {}

    for i, (rname, domain, rtype, d_recs, d_rc, d_ttl, a_recs, a_rc, a_ttl) in enumerate(SCENARIOS):
        resolver = by_name[rname]
        ts = now + i
        direct = DirectAnswer(
            resolver=resolver.name, domain=domain, rtype=rtype,
            resolver_ip=resolver.address, records=frozenset(d_recs),
            min_ttl=d_ttl, rcode=d_rc, latency_ms=10.0 + i * 4,
            authenticated=resolver.is_control, observed_at=ts,
        )
        chain = (". -> lk. -> " + domain + ".",) if domain.endswith(".lk") \
            else (". -> com. -> " + domain + ".",)
        auth = AuthoritativeAnswer(
            domain=domain, rtype=rtype, records=frozenset(a_recs),
            ttl=a_ttl, rcode=a_rc, chain=chain, observed_at=ts,
        )
        result = compare(direct, auth)

        qid = storage.insert_query_result(direct)
        aid = storage.insert_authoritative_result(auth)
        cid = storage.insert_comparison(result, resolver.name, domain, qid, aid, ts)

        record = build_record(resolver, direct, result)
        records_by_resolver.setdefault(resolver.name, []).append(record)

        if result.classification.needs_review:
            anomaly = Anomaly(record=record, classification=result.classification,
                              state=VerificationState.PENDING, reason=result.reason,
                              observed_at=ts)
            anomaly_id = storage.insert_anomaly(anomaly, cid)

            # Escalate one representative partial-injection case to a confirmed alert.
            if (result.classification is Classification.POSSIBLE_CACHE_POISONING
                    and result.matched):
                confirmed = Anomaly(record=record, classification=result.classification,
                                    state=VerificationState.CONFIRMED, reason=result.reason,
                                    observed_at=ts)
                alert = Alert(anomaly=confirmed, targeted=True, persisted_count=2,
                              evidence={"unpublished": sorted(result.unpublished)},
                              confirmed_at=ts)
                storage.insert_alert(alert, anomaly_id)

    computed_at = now + len(SCENARIOS)
    for name, records in records_by_resolver.items():
        storage.insert_health_metrics(compute_metrics(name, records), computed_at)

    # DNSSEC status samples (constructed directly — no network in sample data).
    storage.insert_dnssec_status(DnssecStatus(
        domain="cloudflare.com", resolver="google", signed=True,
        posture=DnssecPosture.VALIDATING, security=SecurityStatus.SECURE,
        ad_flag=True, supports_anomaly=True,
        detail="signed zone, answer authenticated (AD set)", observed_at=computed_at))
    storage.insert_dnssec_status(DnssecStatus(
        domain="ghost.lk", resolver="isp-demo", signed=None,
        posture=DnssecPosture.UNKNOWN, security=SecurityStatus.INDETERMINATE,
        ad_flag=False, supports_anomaly=False,
        detail="could not determine whether the zone is signed", observed_at=computed_at))
