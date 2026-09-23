"""SCHEDULER — the periodic monitoring loop.

One sweep, in this order (ground truth first, once, so every resolver is judged
against the same authoritative snapshot):

    1. resolve every (domain, record type) via the authoritative walk
    2. for each enabled resolver x domain x record type:
         query the resolver -> compare -> run the signal modules (§7)
         -> assign a Tier 0-6 verdict through the exclusion hierarchy (§8, §9)
         -> build a health record -> store
         if the verdict is a divergence: record an anomaly, and alert on §10.4
    3. per resolver: aggregate raw health metrics -> store

Query budget (§15). Ground truth is walked once per (domain, record type) and
shared across resolvers, and the network-facing signal modules run ONLY for an
observation that actually diverges. A clean answer costs exactly one query, so
adding the modules did not change the load ARGUS places on a healthy resolver.

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

from .alerting import AlertSink
from .comparison import compare
from .config import Settings
from .dnssec import DnssecInspector
from .integrity import build_record, compute_metrics
from .models import Alert, Anomaly, Classification, DnssecStatus, ModuleResult
from .modules import (check_bailiwick, check_cache_state, check_consensus,
                      check_ecs, check_ttl)
from .probe import ResolverProbe
from .storage import Storage
from .verdict import assign_tier
from .verification import AnomalyVerifier
from .verifier import AuthoritativeVerifier

log = logging.getLogger("argus.scheduler")


class Scheduler:
    def __init__(self, settings: Settings, storage: Storage,
                 probe: ResolverProbe | None = None,
                 verifier: AuthoritativeVerifier | None = None,
                 dnssec: DnssecInspector | None = None,
                 alert_sink: AlertSink | None = None) -> None:
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
        # Signal-module configuration (§7). Network-facing modules can be
        # switched off wholesale or individually; the TTL module is free and
        # always runs.
        self.module_config = settings.raw.get("modules", {}) or {}
        self.modules_enabled = bool(self.module_config.get("enabled", True))
        # Delivers confirmed detections outside the database. Injectable so
        # tests never touch the filesystem or the network.
        self.alert_sink = alert_sink or AlertSink.from_settings(settings)
        self._stop = threading.Event()

    # -- one sweep --------------------------------------------------------
    def run_once(self) -> dict:
        resolvers = self.settings.enabled_resolvers
        domains = self.settings.watchlist
        rtypes = self.settings.query["rtypes"]
        max_ratio = self.settings.freshness["max_ttl_ratio"]
        # `tiers` is the headline the methodology asks a run to report (§8):
        # which tiers fired, and how often — not a single aggregate number.
        summary = {"queries": 0, "anomalies": 0, "alerts": 0, "failures": 0,
                   "resolvers": len(resolvers), "tiers": {}}

        if not resolvers or not domains:
            log.warning("nothing to do: %d resolvers, %d domains", len(resolvers), len(domains))
            return summary

        # Seed reference tables (upsert; never deletes).
        for resolver in resolvers:
            self.storage.upsert_resolver(resolver)
        categories = self.settings.categories
        for domain in domains:
            self.storage.upsert_domain(domain, categories.get(domain, ""))

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
                        authoritative = truth[(domain, rtype)]
                        result = compare(direct, authoritative, max_ratio)
                        qid = self.storage.insert_query_result(direct)
                        summary["queries"] += 1

                        # DNSSEC status (reuses this response's AD flag; one
                        # row per (resolver, domain), recorded on the A query).
                        # Computed BEFORE the verdict because Tier 6 — the only
                        # conclusive claim ARGUS makes — depends on it.
                        dnssec_status = None
                        if self.dnssec and rtype == "A":
                            if domain not in signed_cache:
                                signed_cache[domain] = self.dnssec.is_signed(domain)
                            signed = signed_cache[domain]
                            security, supports, detail = self.dnssec.assess(
                                domain, signed, posture, direct.authenticated, direct.rcode)
                            dnssec_status = DnssecStatus(
                                domain=domain, resolver=resolver.name, signed=signed,
                                posture=posture, security=security, ad_flag=direct.authenticated,
                                supports_anomaly=supports, detail=detail,
                                observed_at=direct.observed_at)
                            self.storage.insert_dnssec_status(dnssec_status)

                        # A Stage-1 mismatch is only a starting point: run the
                        # multi-stage verification engine before deciding. This
                        # is what stops GeoDNS/CDN differences being reported as
                        # poisoning.
                        outcome = None
                        persistent = None
                        peers: dict = {}
                        if result.classification.needs_review:
                            outcome = self.anomaly_verifier.verify(
                                resolver, direct, authoritative, result)
                            stage5 = outcome.evidence.get("stage5_persistence") or {}
                            persistent = stage5.get("persistent")
                            # Reuse the control answers the verifier already
                            # collected rather than querying them a second time.
                            stage3 = outcome.evidence.get("stage3_controls") or {}
                            peers = {name: frozenset(recs) for name, recs
                                     in (stage3.get("answers") or {}).items()}

                        # §7 signal modules, then the §8/§9 verdict.
                        modules = self._run_modules(
                            resolver, direct, authoritative, result, peers,
                            max_ratio, diverged=outcome is not None)
                        verdict = assign_tier(
                            result, modules=modules, direct=direct,
                            authoritative=authoritative, dnssec=dnssec_status,
                            persistent=persistent)
                        final_class = verdict.classification

                        cid = self.storage.insert_comparison(
                            result, resolver.name, domain, qid,
                            auth_ids[(domain, rtype)], direct.observed_at, verdict)
                        summary["tiers"][int(verdict.tier)] =                             summary["tiers"].get(int(verdict.tier), 0) + 1

                        record = build_record(resolver, direct, result, final_class)
                        records.append(record)

                        if outcome is not None and final_class.needs_review:
                            # Store the stage evidence AND the tier audit trail
                            # together: §16 asks that a finding be defensible
                            # from storage alone, without re-measuring.
                            evidence = dict(outcome.evidence)
                            evidence["verdict"] = verdict.as_evidence()
                            anomaly = Anomaly(record=record, classification=final_class,
                                              state=outcome.state, reason=verdict.reason,
                                              checks=evidence, observed_at=direct.observed_at)
                            anomaly_id = self.storage.insert_anomaly(anomaly, cid)
                            summary["anomalies"] += 1
                            log.info("anomaly: %s %s/%s -> Tier %d (%s)",
                                     resolver.name, domain, rtype,
                                     int(verdict.tier), verdict.tier.label)

                            # §10.4: emit alerts and evidence for a divergence
                            # that survived every gate. Tiers 4-5 are worded as
                            # suggestive; only Tier 6 is stated as tampering.
                            if verdict.tier.is_divergence:
                                persisted = outcome.evidence.get(
                                    "stage5_persistence", {}).get("successful", 1)
                                alert = Alert(anomaly=anomaly, targeted=True,
                                              persisted_count=persisted, evidence=evidence,
                                              confirmed_at=direct.observed_at,
                                              tier=verdict.tier)
                                self.storage.insert_alert(alert, anomaly_id)
                                summary["alerts"] += 1
                                # Deliver outside the database. Never allowed to
                                # affect the sweep: losing a notification is bad,
                                # losing the measurement is worse.
                                try:
                                    self.alert_sink.send(alert, evidence)
                                except Exception:  # noqa: BLE001
                                    log.exception("alert delivery failed")
                                log.warning(
                                    "Tier %d %s: %s %s/%s — %s",
                                    int(verdict.tier), verdict.tier.label,
                                    resolver.name, domain, rtype,
                                    "SUGGESTIVE, not proven" if verdict.suggestive
                                    else "conclusive")
                    except Exception:  # noqa: BLE001 - one bad query must not stop the sweep
                        summary["failures"] += 1
                        log.exception("probe failed: %s %s/%s", resolver.name, domain, rtype)
                        continue

            # 3. per-resolver health metrics.
            if records:
                metrics = compute_metrics(resolver.name, records)
                self.storage.insert_health_metrics(metrics, time.time())

        tiers = ", ".join("T%d=%d" % (t, n)
                          for t, n in sorted(summary["tiers"].items())) or "none"
        log.info("sweep done in %.1fs — %d queries, %d anomalies, %d failures; "
                 "tiers: %s", time.time() - started, summary["queries"],
                 summary["anomalies"], summary["failures"], tiers)
        return summary

    # -- signal modules (§7) ----------------------------------------------
    def _run_modules(self, resolver, direct, authoritative, comparison,
                     peers: dict, max_ratio: float,
                     diverged: bool) -> "dict[str, ModuleResult]":
        """Run the signal modules for one observation.

        Two tiers of cost, deliberately separated:

        * **TTL** re-reads measurements already in hand and issues no query, so
          it runs for every observation and freshness is assessed even on a
          perfectly clean answer.
        * **Everything else sends packets.** Those run only when `diverged` —
          when there is actually a difference that needs explaining. ARGUS is a
          guest on someone else's resolver (§15); probing a healthy answer five
          more ways would multiply the load and learn nothing.

        A module that fails is recorded as UNAVAILABLE by the module itself, and
        an unexpected exception is caught here: a broken signal must degrade one
        observation, never stop a sweep.
        """
        modules: dict = {"ttl": check_ttl(direct.min_ttl, authoritative.ttl,
                                          max_ratio)}

        # Consensus is free too — it scores control answers the verification
        # engine has already collected — but it is only meaningful for a
        # divergence, because there is otherwise no deviation to isolate.
        if diverged and peers:
            modules["consensus"] = check_consensus(
                direct.records, authoritative.records, peers)

        if not (diverged and self.modules_enabled):
            return modules

        timeout = self.settings.query["timeout_seconds"]
        domain, rtype = direct.domain, direct.rtype
        cfg = self.module_config

        def run(name: str, fn) -> None:
            if not (cfg.get(name, {}) or {}).get("enabled", True):
                return
            try:
                self._pace()
                modules[name] = fn()
            except Exception:  # noqa: BLE001 - a signal must never break a sweep
                log.exception("signal module %s failed: %s %s/%s",
                              name, resolver.name, domain, rtype)

        # ECS first: it is the gate most likely to explain the difference
        # outright (§9 stage 1), and a benign explanation makes the structural
        # probes unnecessary.
        subnets = (cfg.get("ecs", {}) or {}).get("subnets") or None
        run("ecs", lambda: check_ecs(
            resolver.address, domain, rtype,
            subnets=tuple((s["address"], int(s["prefix"])) for s in subnets)
            if subnets else None,
            port=resolver.port, timeout=timeout))
        run("bailiwick", lambda: check_bailiwick(
            resolver.address, domain, rtype, port=resolver.port, timeout=timeout))
        run("snoop", lambda: check_cache_state(
            resolver.address, domain, rtype, port=resolver.port, timeout=timeout))
        return modules

    # -- continuous loop --------------------------------------------------
    def run_forever(self) -> None:
        self._install_signal_handlers()
        interval = self.settings.schedule["interval_seconds"]
        log.info("scheduler started — interval %ds, %d resolvers, %d domains",
                 interval, len(self.settings.enabled_resolvers), len(self.settings.watchlist))
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - a bad sweep must not end the loop
                log.exception("sweep failed; continuing")
            # Cadence is measured start-to-start, not end-to-start: the next
            # cycle begins `interval` after this one began, so "every 60s" means
            # every 60s. Only the time left after the sweep is waited out.
            remaining = interval - (time.monotonic() - started)
            if remaining > 0:
                self._stop.wait(timeout=remaining)     # wakes immediately on stop()
            else:
                log.warning("a full cycle took %.0fs, longer than the %ds "
                            "interval; the next cycle starts immediately. To keep "
                            "up, reduce enabled resolvers or domains, or lower the "
                            "query timeout -- unreachable resolvers spend the "
                            "timeout on every query.",
                            interval - remaining, interval)
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
