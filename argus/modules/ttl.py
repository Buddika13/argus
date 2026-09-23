"""TTL / freshness sanity — docs/METHODOLOGY.md §7.

Two distinct questions, deliberately kept apart because they fail differently:

**Plausibility.** Is the TTL a sane number at all? A cached TTL must not exceed
the TTL the zone actually publishes — a cache entry counts *down*, so a larger
value means the entry was not obtained by honest caching. An absurdly long TTL
is the signature of an entry pinned in place, which is exactly what an attacker
wants after an injection: the forged record survives long after the legitimate
one would have expired.

**Countdown.** Does the TTL actually decrease between two hits on the same
cached entry? A healthy resolver serves a decrementing TTL from cache and resets
it to the zone's value on re-fetch. A TTL that never moves across repeated
queries is the sign of a static, pinned answer rather than a live cache.

Neither signal is conclusive on its own. Under §8 a TTL problem on an otherwise
matching answer is a **Tier 3** freshness anomaly, which is explicitly "low-grade
— likely benign, worth logging". It never escalates a divergence by itself; it
only ever caps one (§9 stage 2, timing).
"""

from __future__ import annotations

from ..models import ModuleResult, ModuleStatus

# A TTL above this is implausible for a cached entry. One week is already far
# beyond normal practice; anything larger is either misconfiguration or a
# deliberately pinned record.
MAX_PLAUSIBLE_TTL = 604_800        # 7 days, in seconds


def check_ttl(observed_ttl: int | None, authoritative_ttl: int | None,
              max_ratio: float = 1.05,
              repeated_ttls: list[int] | None = None) -> ModuleResult:
    """Assess one observation's TTL behaviour.

    `observed_ttl` is what the monitored resolver served, `authoritative_ttl`
    what the zone publishes. `repeated_ttls` are TTLs from consecutive queries
    to the same resolver for the same name, oldest first, used for the countdown
    check; pass None to skip it (it costs extra queries).
    """
    data: dict = {
        "observed_ttl": observed_ttl,
        "authoritative_ttl": authoritative_ttl,
        "max_ratio": max_ratio,
    }

    if observed_ttl is None:
        return ModuleResult("ttl", ModuleStatus.UNAVAILABLE,
                            "no TTL observed (the resolver returned no timed answer)",
                            data)

    # --- implausible on its face ----------------------------------------
    if observed_ttl < 0:
        return ModuleResult("ttl", ModuleStatus.SUSPICIOUS,
                            f"negative TTL {observed_ttl}s is not a valid cache value",
                            data)
    if observed_ttl > MAX_PLAUSIBLE_TTL:
        return ModuleResult(
            "ttl", ModuleStatus.SUSPICIOUS,
            f"TTL {observed_ttl}s exceeds the plausible maximum "
            f"{MAX_PLAUSIBLE_TTL}s — an entry pinned far beyond normal practice",
            data)

    # --- countdown behaviour --------------------------------------------
    # Checked before the ratio test: a frozen TTL is a stronger and more
    # specific signal than a merely large one.
    if repeated_ttls:
        series = [t for t in repeated_ttls if t is not None]
        data["repeated_ttls"] = series
        if len(series) >= 2:
            if len(set(series)) == 1:
                return ModuleResult(
                    "ttl", ModuleStatus.SUSPICIOUS,
                    f"TTL did not move across {len(series)} consecutive queries "
                    f"(stayed at {series[0]}s) — a static answer, not a live cache",
                    data)
            # A rise is normal on re-fetch (the entry expired and was renewed),
            # but only up to the zone's published value.
            ceiling = authoritative_ttl or MAX_PLAUSIBLE_TTL
            if any(b > a and b > ceiling for a, b in zip(series, series[1:])):
                return ModuleResult(
                    "ttl", ModuleStatus.SUSPICIOUS,
                    f"TTL rose above the authoritative value {ceiling}s during "
                    f"the observation series {series} — not an honest re-fetch",
                    data)

    # --- ratio against published truth ----------------------------------
    if not authoritative_ttl:
        return ModuleResult("ttl", ModuleStatus.CLEAN,
                            f"TTL {observed_ttl}s is plausible; no authoritative "
                            "TTL available to compare against", data)

    ratio = observed_ttl / authoritative_ttl
    data["ratio"] = round(ratio, 4)
    if ratio > max_ratio:
        return ModuleResult(
            "ttl", ModuleStatus.SUSPICIOUS,
            f"cached TTL {observed_ttl}s exceeds authoritative TTL "
            f"{authoritative_ttl}s (ratio {ratio:.2f} > {max_ratio}) — a cache "
            "entry should count down, never up",
            data)

    return ModuleResult("ttl", ModuleStatus.CLEAN,
                        f"TTL {observed_ttl}s is consistent with the authoritative "
                        f"{authoritative_ttl}s (ratio {ratio:.2f})", data)
