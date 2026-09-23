"""Cross-resolver consensus — docs/METHODOLOGY.md §7.

If a resolver disagrees with the trusted path *and* every one of its peers
disagrees with it too, the deviation is **isolated to that one box**. That is a
meaningfully different observation from every resolver returning the same
"wrong" answer, which instead says the trusted-path walk saw a different slice
of a distributed service — the CDN case again, not a compromised cache.

Isolation is what makes this module useful to §9 stage 4: an isolated
disagreement is a positive *structural* signal, so it can corroborate a Tier-4
divergence up to Tier 5. Systemic disagreement points the other way and caps the
observation at Tier 1.

The function is deliberately **pure**. The control resolvers are already queried
once per anomaly by `argus/verification.py`, and DNS measurement should not
issue queries twice for the same fact — so this module scores answers that have
already been collected rather than gathering its own. Everything it concludes is
reproducible from the stored evidence, which §16 requires.

Important framing (§3): peers are *untrusted*. A public resolver agreeing with
the target proves nothing about correctness — reputation is never ground truth.
Peer agreement is used only to decide whether a deviation is isolated or shared.
"""

from __future__ import annotations

from ..models import ModuleResult, ModuleStatus

# How many peers must also diverge before a disagreement counts as systemic
# rather than isolated. Two is the smallest number that distinguishes "one other
# resolver happened to agree" from a pattern.
SYSTEMIC_THRESHOLD = 2


def check_consensus(target_records: frozenset[str],
                    trusted_records: frozenset[str],
                    peer_records: "dict[str, frozenset[str]]") -> ModuleResult:
    """Score one resolver's answer against its peers and the trusted path.

    `peer_records` maps a peer resolver's name to the answer set it returned for
    the same (domain, record type). The target itself must not appear in it.
    """
    data: dict = {
        "target": sorted(target_records),
        "trusted": sorted(trusted_records),
        "peers": {name: sorted(records) for name, records in peer_records.items()},
    }

    if not peer_records:
        return ModuleResult("consensus", ModuleStatus.UNAVAILABLE,
                            "no peer resolver answered, so the deviation could "
                            "not be isolated to this resolver", data)

    target_extra = target_records - trusted_records
    data["target_unpublished"] = sorted(target_extra)

    if target_records == trusted_records:
        return ModuleResult("consensus", ModuleStatus.CLEAN,
                            "the resolver agrees with the trusted path; there is "
                            "no deviation to isolate", data)

    agree_with_target = sorted(name for name, recs in peer_records.items()
                               if recs == target_records)
    agree_with_trusted = sorted(name for name, recs in peer_records.items()
                                if recs == trusted_records)
    # Peers that returned at least one of the same records the target added.
    corroborating = sorted(name for name, recs in peer_records.items()
                           if target_extra and (recs & target_extra))
    # Peers that diverge from the trusted path in any way at all.
    divergent = sorted(name for name, recs in peer_records.items()
                       if recs != trusted_records)

    data.update({
        "agree_with_target": agree_with_target,
        "agree_with_trusted": agree_with_trusted,
        "corroborating_unpublished": corroborating,
        "divergent_peers": divergent,
    })

    if corroborating:
        return ModuleResult(
            "consensus", ModuleStatus.BENIGN,
            f"{len(corroborating)} independent resolver(s) also return "
            f"{sorted(target_extra)} ({', '.join(corroborating)}), so those "
            "addresses appear legitimate rather than injected",
            data)

    if len(divergent) >= SYSTEMIC_THRESHOLD:
        return ModuleResult(
            "consensus", ModuleStatus.BENIGN,
            f"{len(divergent)} of {len(peer_records)} peers also diverge from "
            "the trusted path — a systemic pattern (GeoDNS/CDN), not one "
            "misbehaving cache",
            data)

    if agree_with_trusted and not agree_with_target:
        return ModuleResult(
            "consensus", ModuleStatus.SUSPICIOUS,
            f"every peer that answered ({', '.join(agree_with_trusted)}) matches "
            "the trusted path while this resolver alone deviates — the "
            "disagreement is isolated to this resolver",
            data)

    return ModuleResult(
        "consensus", ModuleStatus.CLEAN,
        "peer answers neither corroborate the deviation nor cleanly isolate it; "
        "consensus is inconclusive for this observation", data)
