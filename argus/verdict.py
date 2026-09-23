"""VERDICT ENGINE — the Tier 0-6 ladder and the exclusion hierarchy.

Implements docs/METHODOLOGY.md §8 (the tiers) and §9 (the five gates that
control escalation between them). This module is where ARGUS decides how strong
a claim it is entitled to make, and it is deliberately the most conservative
code in the project.

Two properties matter more than detection rate:

**The ladder is monotonic.** A higher tier requires the lower conditions to be
cleared and demands strictly stronger evidence. Nothing reaches Tier 5 without
a positive structural signal, and nothing reaches Tier 6 without cryptographic
proof. There is no path that skips a rung.

**Gates cap, they never promote.** Each of the five exclusion stages can only
hold an observation *down*. A mismatch starts as a candidate and must survive
every gate to remain one; surviving is not evidence, it is only the absence of
an innocent explanation. This is the asymmetry that keeps a GeoDNS artefact from
being reported as an attack — the failure mode that produced every false
positive in the earlier ARGUS experiment.

Reporting discipline (§8, §9 stage 5): Tiers 4 and 5 are *suggestive* and are
worded that way everywhere they surface. The word "poisoning" is reserved for
Tier 6. A run that finds nothing is a valid, reportable result.

The engine consumes what has already been measured — a `ComparisonResult` and
the `ModuleResult`s from `argus/modules/` — and issues no queries of its own, so
a verdict is fully reproducible from stored evidence (§16).
"""

from __future__ import annotations

import ipaddress

from .models import (AuthoritativeAnswer, Classification, ComparisonResult,
                     DirectAnswer, DnssecStatus, ExclusionOutcome,
                     ExclusionStage, ModuleResult, ModuleStatus, SecurityStatus,
                     SetRelation, Tier, Verdict)

# Response codes that mean the resolver did not give us a usable answer, so
# correctness could not be assessed at all (§8, Tier 2).
_UNMEASURABLE_RCODES = ("TIMEOUT", "ERROR", "MALFORMED", "SERVFAIL")

# Tier -> the legacy Classification kept for storage, alerting and the existing
# dashboard. The tier is the authority; this mapping exists so the new ladder
# drops into the current pipeline without a rewrite.
_LEGACY = {
    Tier.CLEAN: Classification.NORMAL,
    Tier.BENIGN_EXPLAINED: Classification.BENIGN_DIFFERENCE,
    Tier.HEALTH_ISSUE: Classification.VERIFICATION_FAILED,
    Tier.FRESHNESS_ANOMALY: Classification.DNS_INTEGRITY_ANOMALY,
    Tier.UNEXPLAINED_DIVERGENCE: Classification.DNS_INTEGRITY_ANOMALY,
    Tier.CORROBORATED_DIVERGENCE: Classification.POSSIBLE_CACHE_POISONING,
    Tier.CONCLUSIVE_TAMPERING: Classification.POSSIBLE_CACHE_POISONING,
}


def relation_of(comparison: ComparisonResult) -> SetRelation:
    """Characterise the divergence by shape (§4, §11)."""
    if comparison.classification is Classification.VERIFICATION_FAILED:
        return SetRelation.UNDETERMINED
    extra, missing, matched = (comparison.unpublished, comparison.missing,
                               comparison.matched)
    if not extra and not missing:
        return SetRelation.MATCH
    if extra and missing:
        return SetRelation.OVERLAP if matched else SetRelation.DISJOINT
    if extra and not matched:
        return SetRelation.DISJOINT
    return SetRelation.SUPERSET if extra else SetRelation.SUBSET


def assign_tier(comparison: ComparisonResult,
                modules: "dict[str, ModuleResult] | None" = None,
                direct: "DirectAnswer | None" = None,
                authoritative: "AuthoritativeAnswer | None" = None,
                dnssec: "DnssecStatus | None" = None,
                persistent: "bool | None" = None) -> Verdict:
    """Assign one observation its tier, with the full audit trail behind it.

    `persistent` is the §7 persistence signal from the verification engine:
    True when the divergence reproduced across every repeat query, False when it
    did not, None when persistence was not tested.
    """
    modules = dict(modules or {})
    relation = relation_of(comparison)
    exclusions: list[ExclusionOutcome] = []

    def verdict(tier: Tier, reason: str) -> Verdict:
        legacy = _LEGACY[tier]
        # Tier 3 splits: a timing artefact is transient, a TTL irregularity is a
        # persistent property of the cache. Legacy consumers care about that.
        if tier is Tier.FRESHNESS_ANOMALY and persistent is False:
            legacy = Classification.TEMPORARY_ANOMALY
        return Verdict(tier=tier, reason=reason, relation=relation,
                       modules=modules, exclusions=exclusions,
                       classification=legacy)

    # === Tier 2 — could the observation be measured at all? ==============
    # Checked first: an unanswerable query has no integrity result to discuss,
    # and calling that "clean" would quietly inflate the availability story.
    if direct is not None and (not direct.ok or direct.rcode in _UNMEASURABLE_RCODES):
        return verdict(Tier.HEALTH_ISSUE,
                       f"the resolver returned {direct.rcode}"
                       + (f" ({direct.error})" if direct.error else "")
                       + " — a health problem; correctness could not be assessed")
    if authoritative is not None and not authoritative.ok:
        return verdict(Tier.HEALTH_ISSUE,
                       f"the trusted-path walk failed ({authoritative.error}), so "
                       "there is no ground truth to compare against and integrity "
                       "is unknown")
    if comparison.classification is Classification.VERIFICATION_FAILED:
        return verdict(Tier.HEALTH_ISSUE,
                       f"integrity could not be assessed: {comparison.reason}")

    ttl_module = modules.get("ttl")
    ttl_bad = bool(comparison.ttl_inflated) or (
        ttl_module is not None and ttl_module.status is ModuleStatus.SUSPICIOUS)

    # === Tiers 0 and 3 — the answer sets agree ===========================
    if relation is SetRelation.MATCH:
        if ttl_bad:
            detail = ttl_module.detail if ttl_module else (
                f"cached TTL {comparison.ttl_direct}s exceeds authoritative "
                f"{comparison.ttl_authoritative}s")
            return verdict(Tier.FRESHNESS_ANOMALY,
                           f"the answer matches the trusted path, but {detail}")
        return verdict(Tier.CLEAN,
                       "the resolver's answer set is identical to the trusted "
                       "path and no anomaly was recorded")

    # === The sets differ. Run the exclusion hierarchy (§9). ==============
    # Every gate below can only cap the tier. None can raise it.

    # --- Stage 1: rule out GeoDNS ---------------------------------------
    geo = _geodns_explanation(modules, relation)
    exclusions.append(ExclusionOutcome(
        stage=ExclusionStage.GEODNS, passed=geo is None,
        detail=geo or "no geographic explanation found for the difference",
        capped_at=Tier.BENIGN_EXPLAINED if geo else None))
    if geo:
        return verdict(Tier.BENIGN_EXPLAINED, geo)

    # --- Stage 2: rule out timing artefacts ------------------------------
    timing = _timing_explanation(persistent, ttl_bad, ttl_module)
    exclusions.append(ExclusionOutcome(
        stage=ExclusionStage.TIMING, passed=timing is None,
        detail=timing or "the difference reproduced and is not a timing artefact",
        capped_at=Tier.FRESHNESS_ANOMALY if timing else None))
    if timing:
        return verdict(Tier.FRESHNESS_ANOMALY, timing)

    # --- Stage 3: rule out ISP policy interception -----------------------
    policy = _policy_explanation(comparison)
    exclusions.append(ExclusionOutcome(
        stage=ExclusionStage.ISP_POLICY, passed=policy is None,
        detail=policy or "the answer does not have the shape of policy "
                         "redirection or filtering",
        capped_at=Tier.BENIGN_EXPLAINED if policy else None))
    if policy:
        return verdict(Tier.BENIGN_EXPLAINED, policy)

    # --- Stage 4: require positive evidence ------------------------------
    # A bare set mismatch is not proof. Escalation past Tier 4 needs a
    # cryptographic or structural signal that something was actually wrong.
    crypto = _cryptographic_proof(dnssec, comparison)
    structural = sorted(name for name, m in modules.items()
                        if m.is_positive_evidence and name != "ttl")
    has_positive = bool(crypto or structural)
    exclusions.append(ExclusionOutcome(
        stage=ExclusionStage.POSITIVE_EVIDENCE, passed=has_positive,
        detail=(crypto or f"corroborated by: {', '.join(structural)}")
        if has_positive else
        "no cryptographic or structural evidence corroborates the divergence",
        capped_at=None if has_positive else Tier.UNEXPLAINED_DIVERGENCE))

    # --- Stage 5: characterise honestly ----------------------------------
    if crypto:
        exclusions.append(ExclusionOutcome(
            stage=ExclusionStage.HONEST_CHARACTERISATION, passed=True,
            detail="cryptographic proof is present, so the finding is stated "
                   "as conclusive"))
        return verdict(Tier.CONCLUSIVE_TAMPERING, crypto)

    if structural:
        exclusions.append(ExclusionOutcome(
            stage=ExclusionStage.HONEST_CHARACTERISATION, passed=True,
            detail="reported as SUGGESTIVE: structural corroboration is not "
                   "cryptographic proof"))
        details = "; ".join(modules[name].detail for name in structural)
        return verdict(Tier.CORROBORATED_DIVERGENCE,
                       f"the divergence survived every benign explanation and is "
                       f"corroborated by a structural signal ({details}) — "
                       "suggestive, not proven")

    exclusions.append(ExclusionOutcome(
        stage=ExclusionStage.HONEST_CHARACTERISATION, passed=True,
        detail="reported as SUGGESTIVE: a candidate for investigation, not a "
               "poisoning claim"))
    return verdict(Tier.UNEXPLAINED_DIVERGENCE,
                   f"the resolver's answer diverges from the trusted path "
                   f"({relation.value}) and no benign explanation applies, but no "
                   "positive evidence corroborates it — a candidate for "
                   "investigation, not a poisoning claim")


# --------------------------------------------------------------------------
# The five gates. Each returns a reason string when it EXPLAINS the difference
# (capping the tier), or None when the difference survives it.
# --------------------------------------------------------------------------
def _geodns_explanation(modules: "dict[str, ModuleResult]",
                        relation: SetRelation) -> "str | None":
    """§9 stage 1 — does geography account for the difference?"""
    ecs = modules.get("ecs")
    if ecs is not None and ecs.status is ModuleStatus.BENIGN:
        return f"ruled out as geographic variation: {ecs.detail}"

    consensus = modules.get("consensus")
    if consensus is not None and consensus.status is ModuleStatus.BENIGN:
        return f"ruled out as legitimate distributed-service variation: {consensus.detail}"

    # A resolver returning a strict subset of the published addresses is the
    # textbook signature of load balancing or a partially warm cache. It adds
    # nothing the zone did not publish, so there is nothing to have injected.
    if relation is SetRelation.SUBSET:
        return ("the resolver returned a strict subset of the published "
                "addresses, which is ordinary load balancing or a partial cache "
                "— it served nothing the zone does not publish")
    return None


def _timing_explanation(persistent: "bool | None", ttl_bad: bool,
                        ttl_module: "ModuleResult | None") -> "str | None":
    """§9 stage 2 — is this a race, an expiry, or transient cache state?"""
    if persistent is False:
        return ("the difference did not reproduce across repeated queries, so it "
                "is a timing artefact — cache churn, mid-flight TTL expiry, or "
                "load-balancer rotation — rather than a stable wrong answer")
    if ttl_bad and persistent is None:
        detail = ttl_module.detail if ttl_module else "TTL irregularity observed"
        return (f"a TTL irregularity is present and persistence was not tested, "
                f"so the difference cannot be separated from a timing artefact "
                f"({detail})")
    return None


def _policy_explanation(comparison: ComparisonResult) -> "str | None":
    """§9 stage 3 — is this lawful/administrative redirection rather than attack?

    Filtering and walled gardens announce themselves by *where they point*: a
    public name answered with a private, loopback, or unspecified address is a
    block page or a sinkhole, not a covert injection. An attacker wants traffic
    to reach infrastructure they control, which a non-routable address cannot do.

    Characterising this honestly as policy is a requirement, not a convenience
    (§14): interception can resemble poisoning, and conflating the two would
    misrepresent an ISP's ordinary filtering as an attack.
    """
    if not comparison.unpublished:
        return None

    special: list[str] = []
    for record in comparison.unpublished:
        try:
            address = ipaddress.ip_address(record)
        except ValueError:
            continue           # a name, not an address (CNAME comparison)
        if (address.is_private or address.is_loopback or address.is_unspecified
                or address.is_link_local or address.is_reserved):
            special.append(record)

    if special and len(special) == len(comparison.unpublished):
        return ("every address the resolver added is non-routable "
                f"({', '.join(sorted(special))}), which is the shape of policy "
                "filtering, a walled garden, or a sinkhole — characterised as "
                "ISP policy, not as an attack")
    return None


def _cryptographic_proof(dnssec: "DnssecStatus | None",
                         comparison: ComparisonResult) -> "str | None":
    """§9 stage 4 / §8 Tier 6 — is there cryptographic proof of tampering?

    The only route to Tier 6. It requires all three of: a DNSSEC-signed zone,
    a validation failure on it, and unpublished data actually served. Anything
    less is suggestive and stays at Tier 5, because DNSSEC is otherwise used as
    *supporting* evidence only.
    """
    if dnssec is None or not comparison.unpublished:
        return None
    if not dnssec.signed:
        return None
    if dnssec.security is not SecurityStatus.BOGUS:
        return None
    return ("the zone is DNSSEC-signed and the answer failed validation (BOGUS) "
            f"while the resolver served {sorted(comparison.unpublished)}, which "
            "the zone never published — cryptographic proof that the data was "
            "not what the zone signed")
