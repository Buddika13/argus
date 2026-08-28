"""HEALTH MONITORING — raw resolver metrics.

Two responsibilities:
  1. build_record()   -> turn one measurement into a HealthRecord
  2. compute_metrics() -> aggregate many HealthRecords into ResolverMetrics

Every metric is a transparent rate or average with an explicit formula (below).
There is deliberately NO single opaque "health score" — the four dimensions
(correctness, freshness, availability/latency, DNSSEC) are reported separately.

Formulas
--------
Let N          = total queries for the resolver in the window.
Let responded  = queries that received a DNS response (rcode not a transport
                 failure; a SERVFAIL or NXDOMAIN still counts as "responded").
Let evaluable  = queries whose comparison is not VERIFICATION_FAILED, i.e. those
                 we could actually judge against authoritative ground truth.

    availability_pct        = responded / N * 100
    avg_latency_ms          = mean(response_time_ms) over timed responses
    timeout_rate            = timeouts / N
    servfail_rate           = servfails / N
    error_rate              = transport/malformed errors / N
    correctness_rate        = (NORMAL + BENIGN_DIFFERENCE) / evaluable
    anomaly_rate            = (ANOMALY + POSSIBLE_CACHE_POISONING) / evaluable
    possible_poisoning_rate = POSSIBLE_CACHE_POISONING / evaluable
    freshness_ok_rate       = (ttl_records - inflated) / ttl_records
    ad_rate                 = answers with AD flag / responded answers

Note: correctness_rate + anomaly_rate == 1 over the evaluable set, because those
two groups partition every judgeable answer. Rates are None when their
denominator is zero (nothing to measure), never a misleading 0.
"""

from __future__ import annotations

from statistics import mean

from .models import (Classification, ComparisonResult, DirectAnswer,
                     HealthRecord, MonitoredResolver, ResolverMetrics)

TRANSPORT_ERRORS = {"ERROR", "MALFORMED"}


def build_record(resolver: MonitoredResolver, direct: DirectAnswer,
                 comparison: ComparisonResult,
                 final_classification: Classification | None = None) -> HealthRecord:
    """Assemble one HealthRecord from a probe answer and its comparison.

    `final_classification` overrides the Stage-1 comparison class with the
    verified one when the anomaly-detection engine has run, so health metrics
    reflect the verified result (e.g. a GeoDNS difference cleared to benign).
    """
    cls = final_classification or comparison.classification
    return HealthRecord(
        resolver=resolver.name,
        resolver_ip=direct.resolver_ip or resolver.address,
        domain=direct.domain,
        rtype=direct.rtype,
        observed_at=direct.observed_at,
        response_time_ms=direct.latency_ms,
        rcode=direct.rcode,
        records=direct.records,
        ttl=direct.min_ttl,
        classification=cls,
        responded=direct.ok,                         # a DNS response came back
        is_anomaly=cls.needs_review,
        ttl_inflated=comparison.ttl_inflated,
        authenticated=direct.authenticated,
    )


def compute_metrics(resolver: str, records: list[HealthRecord]) -> ResolverMetrics:
    """Aggregate a resolver's HealthRecords into raw ResolverMetrics."""
    total = len(records)
    if total == 0:
        return ResolverMetrics(
            resolver=resolver, total_queries=0, responses=0, availability_pct=0.0,
            avg_latency_ms=None, timeout_rate=0.0, servfail_rate=0.0, error_rate=0.0,
            evaluable_queries=0, correctness_rate=None, anomaly_rate=None,
            possible_poisoning_rate=None, inflated_ttl_count=0,
            freshness_ok_rate=None, freshness_status="UNKNOWN", ad_rate=None,
        )

    responded = [r for r in records if r.responded]
    timeouts = sum(1 for r in records if r.is_timeout)
    servfails = sum(1 for r in records if r.is_servfail)
    errors = sum(1 for r in records if r.rcode in TRANSPORT_ERRORS)
    latencies = [r.response_time_ms for r in records if r.response_time_ms is not None]

    # correctness / anomaly are measured only over judgeable answers
    evaluable = [r for r in records if r.evaluable]
    n_eval = len(evaluable)
    correct = sum(1 for r in evaluable if r.classification.is_benign)
    anomalies = sum(1 for r in evaluable if r.classification.needs_review)
    possible = sum(1 for r in evaluable
                   if r.classification is Classification.POSSIBLE_CACHE_POISONING)

    # freshness measured only over answers that carried a TTL to compare
    ttl_records = [r for r in records if r.ttl is not None]
    inflated = sum(1 for r in ttl_records if r.ttl_inflated)
    if ttl_records:
        freshness_ok_rate = (len(ttl_records) - inflated) / len(ttl_records)
        freshness_status = "OK" if inflated == 0 else "DEGRADED"
    else:
        freshness_ok_rate, freshness_status = None, "UNKNOWN"

    ad_hits = sum(1 for r in responded if r.authenticated)

    return ResolverMetrics(
        resolver=resolver,
        total_queries=total,
        responses=len(responded),
        availability_pct=len(responded) / total * 100.0,
        avg_latency_ms=mean(latencies) if latencies else None,
        timeout_rate=timeouts / total,
        servfail_rate=servfails / total,
        error_rate=errors / total,
        evaluable_queries=n_eval,
        correctness_rate=(correct / n_eval) if n_eval else None,
        anomaly_rate=(anomalies / n_eval) if n_eval else None,
        possible_poisoning_rate=(possible / n_eval) if n_eval else None,
        inflated_ttl_count=inflated,
        freshness_ok_rate=freshness_ok_rate,
        freshness_status=freshness_status,
        ad_rate=(ad_hits / len(responded)) if responded else None,
        window_start=min(r.observed_at for r in records),
        window_end=max(r.observed_at for r in records),
    )


def aggregate(records: list[HealthRecord]) -> dict[str, ResolverMetrics]:
    """Group records by resolver and compute metrics for each."""
    by_resolver: dict[str, list[HealthRecord]] = {}
    for r in records:
        by_resolver.setdefault(r.resolver, []).append(r)
    return {name: compute_metrics(name, recs) for name, recs in by_resolver.items()}
