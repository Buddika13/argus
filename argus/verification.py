"""DNS INTEGRITY ANOMALY DETECTION — the multi-stage verification engine.

A single mismatch between a resolver and the authoritative answer is NEVER
enough to declare poisoning. This engine takes a Stage-1 mismatch and gathers
independent corroboration before assigning a final classification. It cannot and
does not prove an attack from response comparison alone — the strongest verdict
it issues is "possible".

Stages
------
Stage 1  Compare target resolver answer vs authoritative answer (already done;
         supplied as the ComparisonResult). MATCH/benign short-circuit.
Stage 2  Re-verify ground truth with an independent authoritative walk. If the
         authoritative answer itself is unstable, a "mismatch" may just reflect
         legitimate authoritative/GeoDNS variance.
Stage 3  Query independent public recursive resolvers (controls). If they also
         return the "unexpected" addresses, those addresses are legitimate and
         our single walk was the outlier. If only the target deviates, the
         anomaly is targeted.
Stage 4  DNSSEC where supported. If a validating public resolver authenticates
         the zone (AD), the zone is signed; unpublished addresses served for a
         signed zone strengthen suspicion (evidence only, never proof).
Stage 5  Consistency: re-query the target several times. An unexpected answer
         that is not consistently reproduced is transient, not an attack.
Stage 6  Combine the evidence into a final classification.

Final classifications and WHY each is assigned
----------------------------------------------
NORMAL                    Stage 1 already matched.
BENIGN_DIFFERENCE         Independent resolvers corroborate the target's answer,
                          or authoritative/controls disagree systemically
                          (GeoDNS/CDN) — the difference is legitimate.
TEMPORARY_ANOMALY         The mismatch was not consistently reproduced across
                          repeated queries — transient (cache churn, rotation).
DNS_INTEGRITY_ANOMALY     A persistent irregularity unique to this resolver, but
                          not the unpublished-address fingerprint of poisoning
                          (e.g. missing records, response-code diff, TTL inflation).
POSSIBLE_CACHE_POISONING  The resolver consistently serves addresses that no
                          authoritative source and no independent resolver
                          corroborates — the shape of poisoning. Still "possible".
VERIFICATION_FAILED       The corroborating checks could not be run (network),
                          so no judgement is made.
"""

from __future__ import annotations

import logging

from .comparison import compare
from .models import (AuthoritativeAnswer, Classification, DirectAnswer,
                     MonitoredResolver, VerificationOutcome, VerificationState)
from .probe import ResolverProbe
from .verifier import AuthoritativeVerifier

log = logging.getLogger("argus.verification")

_STATE = {
    Classification.NORMAL: VerificationState.CLEARED,
    Classification.BENIGN_DIFFERENCE: VerificationState.CLEARED,
    Classification.TEMPORARY_ANOMALY: VerificationState.PENDING,
    Classification.DNS_INTEGRITY_ANOMALY: VerificationState.CONFIRMED,
    Classification.POSSIBLE_CACHE_POISONING: VerificationState.CONFIRMED,
    Classification.VERIFICATION_FAILED: VerificationState.PENDING,
}


class AnomalyVerifier:
    """Runs stages 2-6 over a Stage-1 mismatch and returns a final outcome."""

    def __init__(self, probe: ResolverProbe, verifier: AuthoritativeVerifier,
                 controls: list[MonitoredResolver], repetitions: int = 3) -> None:
        self.probe = probe
        self.verifier = verifier
        self.controls = controls
        self.repetitions = max(1, repetitions)

    def verify(self, target: MonitoredResolver, direct: DirectAnswer,
               authoritative: AuthoritativeAnswer, comparison) -> VerificationOutcome:
        cls = comparison.classification
        evidence: dict = {"stage1": {
            "classification": cls.value, "reason": comparison.reason,
            "unpublished": sorted(comparison.unpublished),
        }}

        # --- Stage 1 short-circuits -------------------------------------
        if cls is Classification.NORMAL:
            return self._done(Classification.NORMAL, "answers already matched authoritative", evidence)
        if cls is Classification.BENIGN_DIFFERENCE:
            return self._done(Classification.BENIGN_DIFFERENCE,
                              "difference already explained benignly at comparison", evidence)
        if cls is Classification.VERIFICATION_FAILED:
            return self._done(Classification.VERIFICATION_FAILED,
                              "a side could not be measured at comparison", evidence)

        domain, rtype = direct.domain, direct.rtype
        auth_records = authoritative.records
        target_unpublished = direct.records - auth_records

        # --- Stage 2: independent authoritative re-walk -----------------
        auth2 = self.verifier.resolve(domain, rtype)
        auth_unstable = auth2.ok and bool(auth2.records) and (auth2.records != auth_records)
        rewalk_failed = not auth2.ok
        evidence["stage2_authoritative"] = {
            "records": sorted(auth2.records), "error": auth2.error, "unstable": auth_unstable,
        }
        # widen ground truth with the second observation
        auth_union = auth_records | (auth2.records if auth2.ok else frozenset())

        # --- Stage 3: independent public recursive resolvers ------------
        control_records: dict[str, frozenset[str]] = {}
        control_ad = False
        for control in self.controls:
            if control.address == target.address:
                continue
            try:
                ans = self.probe.query(control, domain, rtype)
            except Exception as exc:  # noqa: BLE001
                log.debug("control %s failed: %s", control.name, exc)
                continue
            if ans.ok:
                control_records[control.name] = ans.records
                control_ad = control_ad or ans.authenticated
        control_unpublished_union = set().union(
            *(recs - auth_records for recs in control_records.values())) \
            if control_records else set()
        corroborated = bool(target_unpublished) and target_unpublished <= control_unpublished_union
        systemic = auth_unstable or sum(
            1 for recs in control_records.values() if recs - auth_records) >= 2
        evidence["stage3_controls"] = {
            "queried": list(control_records),
            # What each trusted resolver actually answered, so a finding can be
            # re-read later without re-running the network checks.
            "answers": {name: sorted(recs) for name, recs in control_records.items()},
            "corroborates_unexpected": corroborated,
            "systemic_disagreement": systemic,
        }

        # --- Stage 4: DNSSEC (where supported) --------------------------
        zone_signed = control_ad or direct.authenticated
        evidence["stage4_dnssec"] = {
            "zone_signed": zone_signed, "target_ad": direct.authenticated,
            "note": "signed zone → unpublished data is stronger evidence"
                    if zone_signed else "zone not DNSSEC-validated by controls; inconclusive",
        }

        # --- Stage 5: consistency / persistence -------------------------
        reproduced = successful = unpublished_seen = 0
        for _ in range(self.repetitions):
            try:
                d = self.probe.query(target, domain, rtype)
            except Exception:  # noqa: BLE001
                continue
            successful += 1
            if compare(d, authoritative).classification.needs_review:
                reproduced += 1
            if d.records - auth_union:
                unpublished_seen += 1
        persistent = successful > 0 and reproduced == successful
        unpublished_consistent = successful > 0 and unpublished_seen == successful
        evidence["stage5_persistence"] = {
            "repetitions": self.repetitions, "successful": successful,
            "reproduced": reproduced, "persistent": persistent,
            "unexpected_consistent": unpublished_consistent,
        }

        # --- Stage 6: final classification ------------------------------
        insufficient = rewalk_failed and not control_records
        return self._decide(cls, evidence, target_unpublished, auth_union,
                            corroborated, systemic, persistent, unpublished_consistent,
                            zone_signed, insufficient)

    # -- Stage 6 decision logic ------------------------------------------
    def _decide(self, stage1, evidence, target_unpublished, auth_union,
                corroborated, systemic, persistent, unpublished_consistent,
                zone_signed, insufficient) -> VerificationOutcome:
        if insufficient:
            return self._done(Classification.VERIFICATION_FAILED,
                              "corroborating checks could not be run (no re-walk, no controls)",
                              evidence)

        # The unexpected addresses are seen by independent sources, or the sources
        # disagree among themselves → legitimate (e.g. GeoDNS / CDN).
        if corroborated:
            return self._done(Classification.BENIGN_DIFFERENCE,
                              "the unexpected addresses are also returned by independent "
                              "public resolvers, so they appear legitimate", evidence)
        if systemic:
            return self._done(Classification.BENIGN_DIFFERENCE,
                              "authoritative servers and/or control resolvers disagree "
                              "systemically (GeoDNS/CDN), not a single poisoned resolver", evidence)

        # Not corroborated. Is it even reproducible?
        if not persistent:
            return self._done(Classification.TEMPORARY_ANOMALY,
                              "the mismatch was not consistently reproduced across repeated "
                              "queries — transient (cache churn / load-balancer rotation)", evidence)

        # Persistent and unique to this resolver.
        poisoning_shaped = (stage1 is Classification.POSSIBLE_CACHE_POISONING
                            and bool(target_unpublished) and unpublished_consistent)
        if poisoning_shaped:
            extra = " on a DNSSEC-signed zone" if zone_signed else ""
            return self._done(Classification.POSSIBLE_CACHE_POISONING,
                              f"this resolver consistently returns addresses{extra} that no "
                              "authoritative source and no independent resolver corroborates — "
                              "the shape of cache poisoning (not proven)", evidence)

        return self._done(Classification.DNS_INTEGRITY_ANOMALY,
                          "a persistent irregularity unique to this resolver that is not the "
                          "unpublished-address fingerprint of poisoning (e.g. missing records, "
                          "response-code difference, or TTL inflation)", evidence)

    @staticmethod
    def _done(classification: Classification, reason: str, evidence: dict) -> VerificationOutcome:
        evidence["decision"] = reason
        return VerificationOutcome(classification=classification, reason=reason,
                                   state=_STATE[classification], evidence=evidence)
