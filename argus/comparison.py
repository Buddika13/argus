"""COMPARISON ENGINE — resolver answer vs authoritative answer.

Compares the monitored resolver's answer against the independently verified
authoritative answer and returns a ComparisonResult carrying a Classification
plus the evidence behind it.

Core principles:
  * Records are compared as SETS, so order is irrelevant and multiple A / AAAA
    addresses are handled correctly.
  * The comparison is DIRECTIONAL. The dangerous quantity is `unpublished`
    (records the resolver returned that the zone never published); `missing`
    (records the zone has but the resolver did not return) is usually benign
    load balancing.
  * CNAME chains are handled by the query layers: for A/AAAA queries both sides
    have already resolved the chain down to final addresses, so we compare those
    addresses; for CNAME queries we compare the target names as a set.
  * A difference is NEVER assumed to be poisoning. Only shapes that cannot be
    explained benignly are classified POSSIBLE_CACHE_POISONING, and a failed
    measurement on either side is VERIFICATION_FAILED, never an alert.

Classification rules (first matching rule wins)
------------------------------------------------
VERIFICATION_FAILED
    - the authoritative walk failed (no ground truth), OR
    - the resolver query failed at transport level (timeout/connection/malformed).
      Note: SERVFAIL and NXDOMAIN are valid *answers*, not failures.

POSSIBLE_CACHE_POISONING   (resolver served data the zone never published)
    - authoritative says NXDOMAIN but the resolver returned addresses, OR
    - authoritative publishes no records of this type but the resolver returned
      some, OR
    - the resolver's set contains addresses absent from the authoritative set
      (whether overlapping = partial injection, or disjoint = full replacement).

ANOMALY                    (odd, but not poisoning-shaped)
    - authoritative has records but the resolver returned none
      (missing records / a response-code difference such as NXDOMAIN or SERVFAIL
      for a name that exists), OR
    - the sets agree but the cached TTL exceeds the authoritative TTL
      (possible TTL inflation / stale cache).

BENIGN_DIFFERENCE          (a difference with a legitimate explanation)
    - the resolver returned a strict SUBSET of the authoritative addresses
      (load balancing / partial cache), OR
    - neither side has records but the response codes differ.

NORMAL                     (expected agreement)
    - identical answer sets with a healthy TTL, OR
    - both sides report NXDOMAIN / both empty with matching response code.
"""

from __future__ import annotations

from .models import (AuthoritativeAnswer, Classification, ComparisonResult,
                     DirectAnswer)


def compare(direct: DirectAnswer, authoritative: AuthoritativeAnswer,
            max_ttl_ratio: float = 1.05) -> ComparisonResult:
    """Compare one resolver answer against the authoritative answer."""
    rtype = direct.rtype
    rcode_d, rcode_a = direct.rcode, authoritative.rcode

    d = _normalise(direct.records)
    t = _normalise(authoritative.records)
    unpublished = d - t
    missing = t - d
    matched = d & t
    ttl_ratio, ttl_inflated = _ttl_health(direct.min_ttl, authoritative.ttl, max_ttl_ratio)

    def result(classification: Classification, reason: str) -> ComparisonResult:
        return ComparisonResult(
            rtype=rtype, classification=classification, reason=reason,
            matched=frozenset(matched), unpublished=frozenset(unpublished),
            missing=frozenset(missing), rcode_direct=rcode_d, rcode_authoritative=rcode_a,
            ttl_direct=direct.min_ttl, ttl_authoritative=authoritative.ttl,
            ttl_ratio=ttl_ratio, ttl_inflated=ttl_inflated,
        )

    # --- 0. Could we measure both sides at all? --------------------------
    if not authoritative.ok:
        return result(Classification.VERIFICATION_FAILED,
                      f"authoritative verification failed: {authoritative.error}")
    if not direct.ok:
        return result(Classification.VERIFICATION_FAILED,
                      f"resolver query failed: {direct.error}")

    # --- 1. Authoritative says the name does not exist -------------------
    if authoritative.nxdomain:
        if d:
            return result(Classification.POSSIBLE_CACHE_POISONING,
                          f"authoritative NXDOMAIN but resolver returned {sorted(d)}")
        if rcode_d == "NXDOMAIN":
            return result(Classification.NORMAL,
                          "both authoritative and resolver report NXDOMAIN")
        return result(Classification.BENIGN_DIFFERENCE,
                      f"authoritative NXDOMAIN; resolver returned no records (rcode {rcode_d})")

    # --- 2. Authoritative NODATA (name exists, no records of this type) --
    if not t:
        if d:
            return result(Classification.POSSIBLE_CACHE_POISONING,
                          f"resolver returned {sorted(d)} for a type the zone does not publish")
        classification = Classification.NORMAL if rcode_d == rcode_a \
            else Classification.BENIGN_DIFFERENCE
        return result(classification, "no records on either side")

    # --- 3. Authoritative HAS records ------------------------------------
    if not d:
        return result(Classification.ANOMALY,
                      f"resolver returned no records (rcode {rcode_d}) though "
                      f"authoritative publishes {sorted(t)}")

    if d == t:
        if ttl_inflated:
            return result(Classification.ANOMALY,
                          f"records match but cached TTL {direct.min_ttl}s exceeds "
                          f"authoritative TTL {authoritative.ttl}s (possible inflation)")
        return result(Classification.NORMAL, "resolver answer set matches authoritative")

    if not unpublished:                       # resolver set is a strict subset of truth
        if ttl_inflated:
            return result(Classification.ANOMALY,
                          "resolver returned a valid subset but with an inflated TTL")
        return result(Classification.BENIGN_DIFFERENCE,
                      f"resolver returned a subset {sorted(d)} of authoritative "
                      f"{sorted(t)} (load balancing / partial cache)")

    if matched:                               # some valid, some unpublished
        return result(Classification.POSSIBLE_CACHE_POISONING,
                      f"resolver returned unpublished addresses {sorted(unpublished)} "
                      f"alongside valid ones {sorted(matched)}")

    return result(Classification.POSSIBLE_CACHE_POISONING,   # disjoint sets
                  f"resolver answer {sorted(d)} has no overlap with authoritative {sorted(t)}")


def classify(direct: DirectAnswer, authoritative: AuthoritativeAnswer,
             max_ttl_ratio: float = 1.05) -> Classification:
    """Convenience: just the Classification for one comparison."""
    return compare(direct, authoritative, max_ttl_ratio).classification


# --------------------------------------------------------------------------
def _normalise(records: frozenset[str]) -> frozenset[str]:
    """Case-fold records so representation differences never cause a mismatch.

    dnspython already canonicalises IPv6 and appends the trailing dot to names,
    so lower-casing is sufficient to make both sides directly comparable.
    """
    return frozenset(r.lower() for r in records)


def _ttl_health(direct_ttl: int | None, auth_ttl: int | None,
                max_ratio: float) -> tuple[float | None, bool]:
    """A cached TTL counts down, so it should not exceed the authoritative TTL."""
    if direct_ttl is None or not auth_ttl:
        return None, False
    ratio = direct_ttl / auth_ttl
    return ratio, ratio > max_ratio
