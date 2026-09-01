"""SCHEDULER — the periodic monitoring loop.

One sweep, in this order (ground truth first, once, so every resolver is judged
against the same authoritative snapshot):

    1. resolve every (domain, record type) via the authoritative walk
    2. for each enabled resolver x domain x record type:
         query the resolver -> compare -> build a health record -> store
         if the comparison needs review: record an anomaly
    3. per resolver: aggregate raw health metrics -> store

Resilience (requirement 10): every individual probe is wrapped, so one failing
resolver, domain or query never stops the sweep. A failed sweep in run_forever
is logged and the loop continues.

The probe and verifier are injectable, which keeps the sweep unit-testable
offline (tests pass fakes; production uses the real ones).
"""

from __future__ import annotations

import logging
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from .comparison import compare
from .config import Settings
from .dnssec import DnssecInspector
from .integrity import build_record, compute_metrics
from .models import Alert, Anomaly, Classification, DnssecStatus
from .probe import ResolverProbe
from .storage import Storage
from .verification import AnomalyVerifier
from .verifier import AuthoritativeVerifier

log = logging.getLogger("argus.scheduler")


class Scheduler:
    def __init__(self, settings: Settings, storage: Storage,
                 probe: ResolverProbe | None = None,
                 verifier: AuthoritativeVerifier | None = None,
                 dnssec: DnssecInspector | None = None) -> None:
        self.settings = settings
        self.storage = storage
        self.probe = probe or ResolverProbe(
            timeout=settings.query["timeout_seconds"], retries=settings.query["retries"])
        self.verifier = verifier or AuthoritativeVerifier(
            timeout=settings.query["timeout_seconds"])
        # DNSSEC inspection is optional and injectable (tests pass None / disable).
        dnssec_on = settings.raw.get("dnssec", {}).get("enabled", True)
        self.dnssec = dnssec or (DnssecInspector(
            timeout=settings.query["timeout_seconds"]) if dnssec_on else None)
        # The multi-stage anomaly-detection engine. Controls are the public
        # resolvers used to cross-check whether an "unexpected" answer is
        # actually legitimate (GeoDNS/CDN) rather than poisoning.
        self.anomaly_verifier = AnomalyVerifier(
            self.probe, self.verifier,
            controls=[r for r in settings.resolvers if r.role == "control"],
            repetitions=max(2, settings.verification.get("persistence", 2)),
        )
        self._stop = threading.Event()

    # -- one sweep --------------------------------------------------------
    def run_once(self) -> dict:
        resolvers = self.settings.enabled_resolvers
        domains = self.settings.watchlist
        rtypes = self.settings.query["rtypes"]
        max_ratio = self.settings.freshness["max_ttl_ratio"]
        summary = {"queries": 0, "anomalies": 0, "alerts": 0, "failures": 0,
                   "resolvers": len(resolvers)}

        if not resolvers or not domains:
            log.warning("nothing to do: %d resolvers, %d domains", len(resolvers), len(domains))
            return summary

        # Seed reference tables (upsert; never deletes).
        for resolver in resolvers:
            self.storage.upsert_resolver(resolver)
        for domain in domains:
            self.storage.upsert_domain(domain)

        # 1. ground truth once per (domain, rtype), shared across all resolvers.
        #
        # The walks are independent of one another and touch no database, so they
        # run concurrently at the configured width. Every walk still queries the
        # root and TLD servers exactly as before; only the waiting overlaps.
        # Results are collected first and written on this thread afterwards,
        # because the SQLite connection belongs to it.
        wanted = [(domain, rtype) for domain in domains for rtype in rtypes]
        width = max(1, int(self.settings.schedule.get("concurrency", 1) or 1))

        truth, auth_ids = {}, {}
        if width > 1 and len(wanted) > 1:
            with ThreadPoolExecutor(max_workers=min(width, len(wanted))) as pool:
                futures = {pool.submit(self.verifier.resolve, domain, rtype):
                           (domain, rtype) for domain, rtype in wanted}
                for future in as_completed(futures):
                    key = futures[future]
                    try:
                        truth[key] = future.result()
                    except Exception:  # noqa: BLE001 - one bad walk must not stop the sweep
                        log.exception("ground-truth walk failed: %s/%s", *key)
        else:
            for domain, rtype in wanted:
                truth[(domain, rtype)] = self.verifier.resolve(domain, rtype)

        for key in wanted:
            answer = truth.get(key)
            if answer is None:                     # walk raised; nothing to compare against
                continue
            auth_ids[key] = self.storage.insert_authoritative_result(answer)
            if answer.error:
                log.warning("verification failed for %s/%s: %s", key[0], key[1],
                            answer.error)

        # 2. probe every resolver.
        started = time.time()
        signed_cache: dict[str, bool | None] = {}   # domain -> is signed (per sweep)
        for resolver in resolvers:
            records = []
            # DNSSEC posture is per resolver; compute once per sweep (2 queries).
            posture = self.dnssec.resolver_posture(resolver.address, resolver.port) \
                if self.dnssec else None
            for domain in domains:
                for rtype in rtypes:
                    if (domain, rtype) not in truth:
                        continue          # ground-truth walk failed; nothing to compare
                    try:
                        self._pace()
                        direct = self.probe.query(resolver, domain, rtype)
                        result = compare(direct, truth[(domain, rtype)], max_ratio)
                        qid = self.storage.insert_query_result(direct)
                        cid = self.storage.insert_comparison(
                            result, resolver.name, domain, qid,
                            auth_ids[(domain, rtype)], direct.observed_at)
                        summary["queries"] += 1

                        # A Stage-1 mismatch is only a starting point: run the
                        # multi-stage verification engine before deciding. This
                        # is what stops GeoDNS/CDN differences being reported as
                        # poisoning.
                        final_class = result.classification
                        outcome = None
                        if result.classification.needs_review:
                            outcome = self.anomaly_verifier.verify(
                                resolver, direct, truth[(domain, rtype)], result)
                            final_class = outcome.classification

                        record = build_record(resolver, direct, result, final_class)
                        records.append(record)

                        # DNSSEC status (reuses this response's AD flag; one
                        # row per (resolver, domain), recorded on the A query).
                        if self.dnssec and rtype == "A":
                            if domain not in signed_cache:
                                signed_cache[domain] = self.dnssec.is_signed(domain)
                            signed = signed_cache[domain]
                            security, supports, detail = self.dnssec.assess(
                                domain, signed, posture, direct.authenticated, direct.rcode)
                            self.storage.insert_dnssec_status(DnssecStatus(
                                domain=domain, resolver=resolver.name, signed=signed,
                                posture=posture, security=security, ad_flag=direct.authenticated,
                                supports_anomaly=supports, detail=detail,
                                observed_at=direct.observed_at))

                        if outcome is not None and final_class.needs_review:
                            anomaly = Anomaly(record=record, classification=final_class,
                                              state=outcome.state, reason=outcome.reason,
                                              checks=outcome.evidence, observed_at=direct.observed_at)
                            anomaly_id = self.storage.insert_anomaly(anomaly, cid)
                            summary["anomalies"] += 1
                            log.info("anomaly: %s %s/%s -> %s", resolver.name, domain, rtype,
                                     final_class.value)

                            if final_class is Classification.POSSIBLE_CACHE_POISONING:
                                persisted = outcome.evidence.get(
                                    "stage5_persistence", {}).get("successful", 1)
                                alert = Alert(anomaly=anomaly, targeted=True,
                                              persisted_count=persisted, evidence=outcome.evidence,
                                              confirmed_at=direct.observed_at)
                                self.storage.insert_alert(alert, anomaly_id)
                                summary["alerts"] += 1
                                log.warning("POSSIBLE cache poisoning: %s %s/%s",
                                            resolver.name, domain, rtype)
                    except Exception:  # noqa: BLE001 - one bad query must not stop the sweep
                        summary["failures"] += 1
                        log.exception("probe failed: %s %s/%s", resolver.name, domain, rtype)
                        continue

            # 3. per-resolver health metrics.
            if records:
                metrics = compute_metrics(resolver.name, records)
                self.storage.insert_health_metrics(metrics, time.time())

        log.info("sweep done in %.1fs — %d queries, %d anomalies, %d failures",
                 time.time() - started, summary["queries"], summary["anomalies"],
                 summary["failures"])
        return summary

    # -- continuous loop --------------------------------------------------
    def run_forever(self) -> None:
        self._install_signal_handlers()
        interval = self.settings.schedule["interval_seconds"]
        log.info("scheduler started — interval %ds, %d resolvers, %d domains",
                 interval, len(self.settings.enabled_resolvers), len(self.settings.watchlist))
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - a bad sweep must not end the loop
                log.exception("sweep failed; continuing")
            self._stop.wait(timeout=interval)      # wakes immediately on stop()
        log.info("scheduler stopped cleanly")

    def stop(self) -> None:
        """Request a graceful shutdown; the loop exits after the current wait."""
        self._stop.set()

    # -- helpers ----------------------------------------------------------
    def _pace(self) -> None:
        delay = self.settings.schedule.get("per_resolver_delay", 0.0)
        if delay > 0:
            time.sleep(delay)

    def _install_signal_handlers(self) -> None:
        def handler(signum, _frame):
            log.info("received signal %s — shutting down after current sweep", signum)
            self.stop()
        for name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, name, None)
            if sig is not None:
                try:
                    signal.signal(sig, handler)
                except (ValueError, OSError):
                    # signal only works in the main thread; ignore otherwise.
                    pass
