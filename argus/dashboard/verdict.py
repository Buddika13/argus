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


# A one-or-two word label for the same stored classification, for tables where
# the full name will not fit. Display shorthand only: it never re-decides, and
# every entry names the classification it abbreviates.
_SHORT = {
    "NORMAL": "Match",
    "BENIGN_DIFFERENCE": "Explained",
    "TEMPORARY_ANOMALY": "Transient",
    "DNS_INTEGRITY_ANOMALY": "Irregular",
    "ANOMALY": "Under review",
    "POSSIBLE_CACHE_POISONING": "Mismatch",
    "VERIFICATION_FAILED": "Not measured",
}


def short_of(classification: str) -> str:
    """A compact label for a stored classification, for narrow table cells."""
    return _SHORT.get((classification or "").upper(), "Unclassified")


# Severity, for report tables that rank findings by how much attention they
# need. This is a DISPLAY mapping over the stored classification, exactly like
# the verdict mapping above -- the engine never decides a severity, and nothing
# here can promote a finding the engine did not already make.
HIGH, MEDIUM, LOW = "High", "Medium", "Low"

_SEVERITY = {
    "POSSIBLE_CACHE_POISONING": (HIGH, "bad"),
    "DNS_INTEGRITY_ANOMALY": (MEDIUM, "warn"),
    "ANOMALY": (MEDIUM, "warn"),
    "TEMPORARY_ANOMALY": (LOW, "muted"),
    "VERIFICATION_FAILED": (LOW, "muted"),
}


def severity_of(classification: str) -> str:
    """How much attention a stored classification warrants. "" when none."""
    return _SEVERITY.get((classification or "").upper(), ("", "muted"))[0]


def severity_tone(classification: str) -> str:
    return _SEVERITY.get((classification or "").upper(), ("", "muted"))[1]


def classifications_for_severity(level: str) -> list:
    """Which stored classifications a severity covers.

    Severity is a label over the classification, not a column, so filtering by
    it has to become a filter over the classifications it stands for --
    otherwise the count and the page disagree.
    """
    level = (level or "").strip().title()
    return sorted(k for k, (name, _tone) in _SEVERITY.items() if name == level)


# The four outcomes the Results page reports. Derived from what the comparison
# engine stored -- the record sets it computed and whether it could measure at
# all -- never from the response code alone. NOERROR only says the exchange
# completed; it says nothing about whether the answer was right.
MATCH, PARTIAL, MISMATCH, ERROR = "MATCH", "PARTIAL", "MISMATCH", "ERROR"

_OUTCOME_TONE = {MATCH: "ok", PARTIAL: "warn", MISMATCH: "bad", ERROR: "muted"}

# A query that never produced a comparable answer. A timeout is an ERROR, not
# a MISMATCH: nothing was returned to disagree with.
_UNMEASURED = {"VERIFICATION_FAILED"}
_FAILED_RCODES = {"TIMEOUT", "SERVFAIL", "REFUSED", "ERROR", "CONNECTION_ERROR",
                  "NO_ANSWER"}


def outcome_of(classification: str, unpublished: str = "", missing: str = "",
               rcode: str = "", returned: str = "") -> str:
    """MATCH / PARTIAL / MISMATCH / ERROR for one stored measurement.

    Uses the sets the engine already computed, so this agrees with the live
    Monitoring page by construction rather than by coincidence.
    """
    classification = (classification or "").upper()
    if classification in _UNMEASURED or (rcode or "").upper() in _FAILED_RCODES:
        return ERROR
    if not classification:
        return ERROR
    if (unpublished or "").strip():
        return MISMATCH
    if (missing or "").strip():
        return PARTIAL
    if classification == "POSSIBLE_CACHE_POISONING":
        # Recorded before the view carried the sets; the classification alone
        # is enough to know an unpublished address was seen.
        return MISMATCH
    return MATCH


def outcome_tone(outcome: str) -> str:
    return _OUTCOME_TONE.get(outcome, "muted")


def outcome_row(row) -> str:
    """The outcome for a monitoring_events row, tolerating older rows."""
    def field(name):
        try:
            return row[name] or ""
        except (IndexError, KeyError):
            return ""
    return outcome_of(field("comparison_classification"),
                      field("unpublished_records"), field("missing_records"),
                      field("rcode"), field("returned_records"))


# What kind of finding this is, in words. Read out of the reason the engine
# itself wrote, so the label always describes what was actually detected; the
# classification is the fallback when the reason says nothing specific. No new
# detection happens here -- this only names what is already stored.
_TYPE_HINTS = (
    ("inflation", "TTL inflation"),
    ("exceeds authoritative ttl", "TTL inflation"),
    ("returned no records", "Missing records"),
    ("no records", "Missing records"),
    ("does not publish", "Unexpected IP detected"),
    ("unpublished", "Unexpected IP detected"),
    ("nxdomain", "Answer for a name the zone denies"),
    ("response-code", "Response code difference"),
    ("rcode", "Response code difference"),
    ("could not be measured", "Verification incomplete"),
    ("could not be run", "Verification incomplete"),
    ("not consistently reproduced", "Transient difference"),
    ("cache churn", "Transient difference"),
)

_TYPE_BY_CLASS = {
    "POSSIBLE_CACHE_POISONING": "Unexpected IP detected",
    "DNS_INTEGRITY_ANOMALY": "Persistent irregularity",
    "TEMPORARY_ANOMALY": "Transient difference",
    "VERIFICATION_FAILED": "Verification incomplete",
    "BENIGN_DIFFERENCE": "Explained difference",
    "ANOMALY": "Difference under review",
    "NORMAL": "No difference",
}


def alert_type_of(classification: str, reason: str = "") -> str:
    """A short name for what was detected, taken from the stored evidence."""
    text = (reason or "").lower()
    for hint, label in _TYPE_HINTS:
        if hint in text:
            return label
    return _TYPE_BY_CLASS.get((classification or "").upper(),
                              "Difference under review")


# How far a finding has got through verification. These are the engine's own
# states; they are not renamed here, because a report and the database must
# use the same words.
_STATE_TONE = {"CONFIRMED": "bad", "PENDING": "warn", "CLEARED": "ok"}


def state_tone(state: str) -> str:
    return _STATE_TONE.get((state or "").upper(), "muted")


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
