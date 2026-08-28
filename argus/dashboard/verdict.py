"""RESEARCH VERDICTS — the three labels the dashboard reports.

The detection engine assigns seven internal classifications (see
`models.Classification`). For reporting, those collapse into the three verdicts
the research question actually asks about:

    NO_POISONING_DETECTED     the resolver's answer is corroborated
    POSSIBLE_CACHE_POISONING  uncorroborated, persistent, targeted
    INCONCLUSIVE              the evidence does not support either conclusion

This module only *maps* — it never re-decides. The classification stored in the
database remains the authority; nothing here changes what was measured.

Why INCONCLUSIVE exists
-----------------------
A transient mismatch, a persistent irregularity that is not the
unpublished-address fingerprint, and a check that could not be run are all
states where the honest answer is "we do not know". Reporting any of them as
poisoning would overstate the evidence; reporting them as clean would hide a
real observation. They are their own verdict.

Note that POSSIBLE_CACHE_POISONING is never PROVEN poisoning. It states that a
resolver persistently served data no authoritative source and no independent
resolver corroborates. Proof would require evidence a passive observer cannot
obtain — the resolver's own cache contents, or capture of the injection itself.
"""

from __future__ import annotations

NO_POISONING = "NO_POISONING_DETECTED"
POSSIBLE = "POSSIBLE_CACHE_POISONING"
INCONCLUSIVE = "INCONCLUSIVE"

# internal classification -> (verdict, tone, why this mapping)
_MAP = {
    "NORMAL": (NO_POISONING, "ok",
               "the resolver's answer set matched the authoritative answer"),
    "BENIGN_DIFFERENCE": (NO_POISONING, "ok",
                          "the difference has a legitimate explanation "
                          "(CDN/GeoDNS, load balancing, or a partial cache)"),
    "TEMPORARY_ANOMALY": (INCONCLUSIVE, "warn",
                          "the mismatch was not reproduced consistently, so it "
                          "looks transient rather than injected"),
    "DNS_INTEGRITY_ANOMALY": (INCONCLUSIVE, "warn",
                              "a persistent irregularity unique to this resolver, "
                              "but not the unpublished-address fingerprint of poisoning"),
    "ANOMALY": (INCONCLUSIVE, "warn",
                "a stage-1 observation that the verification engine had not yet refined"),
    "POSSIBLE_CACHE_POISONING": (POSSIBLE, "bad",
                                 "persistently served addresses that neither the "
                                 "authoritative servers nor any independent resolver "
                                 "corroborates"),
    "VERIFICATION_FAILED": (INCONCLUSIVE, "muted",
                            "one side of the comparison could not be measured, so no "
                            "judgement is made"),
}

# Legitimate reasons a resolver's answer may differ without any attack. Shown on
# the investigation page so a difference is read as a question, not a finding.
BENIGN_EXPLANATIONS = (
    ("CDN edge selection",
     "Content networks answer with the edge nearest the asker, so two resolvers "
     "in different places receive different, equally genuine addresses."),
    ("Geographic DNS",
     "A zone may publish different records per region; a single vantage point "
     "sees only one of them."),
    ("Load balancing",
     "A rotating pool may return a subset, or a different slice, on each query."),
    ("IPv4 / IPv6 differences",
     "A and AAAA are published and cached independently; one may exist without "
     "the other."),
    ("DNS propagation",
     "After a legitimate record change, caches and authoritative servers "
     "disagree until the old TTL expires."),
    ("Cache timing",
     "A resolver may still be serving a correct but superseded answer."),
    ("Differing authoritative servers",
     "Nameservers for one zone can be briefly out of sync with each other."),
)


def verdict_of(classification: str) -> str:
    """The reported verdict for a stored classification."""
    return _MAP.get((classification or "").upper(), (INCONCLUSIVE, "muted", ""))[0]


def tone_of(classification: str) -> str:
    """Colour tone: ok (green), warn (amber), bad (red), muted (grey)."""
    return _MAP.get((classification or "").upper(), (INCONCLUSIVE, "muted", ""))[1]


def rationale_of(classification: str) -> str:
    """One sentence explaining why this classification maps to its verdict."""
    return _MAP.get((classification or "").upper(),
                    (INCONCLUSIVE, "muted",
                     "this classification is not recognised, so no conclusion is drawn"))[2]


def verdict_tone(verdict: str) -> str:
    return {NO_POISONING: "ok", POSSIBLE: "bad"}.get(verdict, "warn")


def summarise(classifications) -> dict[str, int]:
    """Count verdicts across a set of stored classifications."""
    counts = {NO_POISONING: 0, POSSIBLE: 0, INCONCLUSIVE: 0}
    for c in classifications:
        counts[verdict_of(c)] = counts.get(verdict_of(c), 0) + 1
    return counts
