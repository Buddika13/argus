"""The shared data model — the vocabulary every Argus module speaks.

Nothing here does network I/O or makes policy decisions; these are the plain
data structures that flow through the pipeline:

    MonitoredResolver + domain
        -> DirectAnswer          (what the monitored resolver said)
        -> AuthoritativeAnswer   (what the hierarchy independently returned)
        -> Sample                (classification + health, one measurement)
        -> Anomaly               (Tier-1: suspicious, pending verification)
        -> Alert                 (Tier-2: possible poisoning, verified)

The three-tier model is deliberate: a mismatch never becomes an alert directly.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------
class Classification(str, Enum):
    """The outcome of comparing a resolver's answer to the authoritative answer.

    Deliberately conservative: a difference is not poisoning. Only shapes that
    cannot be explained benignly reach POSSIBLE_CACHE_POISONING, and even that
    word is "possible" — final confirmation is the verification stage's job.

        NORMAL                    exact, expected agreement
        BENIGN_DIFFERENCE         a difference with a legitimate explanation
                                  (subset / load balancing, rcode representation)
        ANOMALY                   Stage-1 preliminary: odd, needs verification.
                                  Verification refines it into one of the two below.
        TEMPORARY_ANOMALY         verified transient — not consistently reproduced
        DNS_INTEGRITY_ANOMALY     verified persistent irregularity, but not the
                                  fingerprint of poisoning
        POSSIBLE_CACHE_POISONING  resolver consistently served data no authoritative
                                  source or independent resolver corroborates
        VERIFICATION_FAILED       a side could not be measured; no judgement made

    "ANOMALY" is only ever a Stage-1 label; the anomaly-detection engine always
    replaces it with a final class. None of these assert proof — the strongest,
    POSSIBLE_CACHE_POISONING, remains "possible".
    """

    NORMAL = "NORMAL"
    BENIGN_DIFFERENCE = "BENIGN_DIFFERENCE"
    ANOMALY = "ANOMALY"
    TEMPORARY_ANOMALY = "TEMPORARY_ANOMALY"
    DNS_INTEGRITY_ANOMALY = "DNS_INTEGRITY_ANOMALY"
    POSSIBLE_CACHE_POISONING = "POSSIBLE_CACHE_POISONING"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"

    @property
    def is_benign(self) -> bool:
        return self in (Classification.NORMAL, Classification.BENIGN_DIFFERENCE)

    @property
    def needs_review(self) -> bool:
        """True for the classes a human/verification stage should look at."""
        return self in (Classification.ANOMALY,
                        Classification.TEMPORARY_ANOMALY,
                        Classification.DNS_INTEGRITY_ANOMALY,
                        Classification.POSSIBLE_CACHE_POISONING)


class IntegrityTier(str, Enum):
    """The three-tier severity model that keeps mismatch != poisoning."""

    OK = "OK"                    # Tier 0: benign / healthy
    ANOMALY = "ANOMALY"          # Tier 1: suspicious, awaiting verification
    CONFIRMED = "CONFIRMED"      # Tier 2: possible cache poisoning (verified)


class VerificationState(str, Enum):
    """Where an anomaly sits in the Stage-2 verification process."""

    PENDING = "PENDING"          # not yet re-verified
    CONFIRMED = "CONFIRMED"      # re-checks upheld the anomaly (targeted, persistent)
    CLEARED = "CLEARED"          # re-checks explained it away (transient / GeoDNS)


class DnssecPosture(str, Enum):
    """How a resolver behaves toward DNSSEC (signed + broken-zone probes)."""

    VALIDATING = "VALIDATING"          # AD on signed, SERVFAIL on broken
    PERMISSIVE = "PERMISSIVE"          # resolves the broken zone (not validating)
    AD_ONLY = "AD_ONLY"                # claims AD but still serves the broken zone
    NON_VALIDATING = "NON_VALIDATING"  # no AD, but correctly refuses broken zone
    UNKNOWN = "UNKNOWN"                # probe failed


class SecurityStatus(str, Enum):
    """DNSSEC validation state of a single response, where determinable.

    Mirrors RFC 4035 states. We can only reach SECURE/BOGUS reliably through a
    validating resolver; otherwise the status is INDETERMINATE by design.
    """

    SECURE = "SECURE"                # signed zone, answer authenticated (AD)
    INSECURE = "INSECURE"            # zone is not signed; no DNSSEC protection
    BOGUS = "BOGUS"                  # signed zone that failed validation (SERVFAIL)
    INDETERMINATE = "INDETERMINATE"  # cannot be reliably determined


# --------------------------------------------------------------------------
# Entities and measurements
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class MonitoredResolver:
    """A DNS caching/recursive resolver under observation. Never trusted."""

    name: str
    address: str
    role: str = "isp"            # "isp" or "control"
    isp: str = "unknown"
    country: str = "unknown"
    port: int = 53
    enabled: bool = True

    @property
    def is_control(self) -> bool:
        return self.role == "control"


@dataclass
class DirectAnswer:
    """What the monitored resolver returned (the direct path)."""

    resolver: str                      # resolver identifier (name, or IP if unnamed)
    domain: str
    rtype: str
    resolver_ip: Optional[str] = None  # the IP actually queried
    records: frozenset[str] = frozenset()
    min_ttl: Optional[int] = None
    rcode: str = "NOERROR"
    latency_ms: Optional[float] = None
    authenticated: bool = False        # AD flag set by the resolver
    error: Optional[str] = None
    observed_at: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def nxdomain(self) -> bool:
        return self.rcode == "NXDOMAIN"


@dataclass
class AuthoritativeAnswer:
    """Independent ground truth from the hierarchy (the verification path).

    `chain` records the delegation actually walked, e.g.
    (". -> lk.", "lk. -> example.lk."), so the ground truth can be audited.
    """

    domain: str
    rtype: str
    records: frozenset[str] = frozenset()
    ttl: Optional[int] = None
    rcode: str = "NOERROR"
    authoritative_servers: tuple[str, ...] = ()
    chain: tuple[str, ...] = ()
    error: Optional[str] = None
    observed_at: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def nxdomain(self) -> bool:
        return self.rcode == "NXDOMAIN"


@dataclass
class ComparisonResult:
    """The output of the comparison engine for one (domain, record type).

    Carries the classification *and* the evidence behind it, so later stages
    and the dashboard can explain a finding rather than just assert it.
    """

    rtype: str
    classification: Classification
    reason: str
    matched: frozenset[str] = frozenset()        # records present on both sides
    unpublished: frozenset[str] = frozenset()    # resolver had, authoritative did NOT
    missing: frozenset[str] = frozenset()        # authoritative had, resolver did not
    rcode_direct: str = "NOERROR"
    rcode_authoritative: str = "NOERROR"
    ttl_direct: Optional[int] = None
    ttl_authoritative: Optional[int] = None
    ttl_ratio: Optional[float] = None
    ttl_inflated: bool = False


@dataclass
class HealthRecord:
    """One monitoring measurement — the atomic unit of health data.

    A and AAAA are independent queries, so each produces its own record with its
    own response time, response code and TTL. The fields below are exactly the
    per-query facts we persist and later aggregate into resolver-level metrics.
    """

    resolver: str
    resolver_ip: str
    domain: str
    rtype: str                         # A / AAAA / CNAME
    observed_at: float                 # timestamp
    response_time_ms: Optional[float]  # None if no timed response
    rcode: str                         # NOERROR / NXDOMAIN / SERVFAIL / TIMEOUT / ERROR / MALFORMED
    records: frozenset[str]            # the answer set for this record type
    ttl: Optional[int]
    classification: Classification     # the comparison result
    responded: bool                    # a DNS response was received (not a timeout/transport error)
    is_anomaly: bool                   # classification.needs_review
    ttl_inflated: bool = False         # cached TTL exceeded authoritative TTL
    authenticated: bool = False        # AD flag (a DNSSEC signal)

    @property
    def is_timeout(self) -> bool:
        return self.rcode == "TIMEOUT"

    @property
    def is_servfail(self) -> bool:
        return self.rcode == "SERVFAIL"

    @property
    def evaluable(self) -> bool:
        """True when the comparison could actually judge correctness."""
        return self.classification is not Classification.VERIFICATION_FAILED


@dataclass
class ResolverMetrics:
    """Raw, aggregated health metrics for one resolver over a window of records.

    Every field is a directly measured rate or average with a documented
    formula (see integrity.py). Deliberately NOT a single opaque "health score":
    the four dimensions are reported separately so each can be inspected.
    """

    resolver: str
    total_queries: int
    responses: int
    availability_pct: float                    # dimension 3: availability
    avg_latency_ms: Optional[float]            # dimension 3: latency
    timeout_rate: float
    servfail_rate: float
    error_rate: float
    evaluable_queries: int
    correctness_rate: Optional[float]          # dimension 1: correctness
    anomaly_rate: Optional[float]
    possible_poisoning_rate: Optional[float]
    inflated_ttl_count: int
    freshness_ok_rate: Optional[float]         # dimension 2: freshness
    freshness_status: str
    ad_rate: Optional[float]                   # dimension 4: DNSSEC signal (AD flag)
    dnssec_posture: str = "UNKNOWN"            # dimension 4: full posture (dedicated probe)
    window_start: Optional[float] = None
    window_end: Optional[float] = None


@dataclass
class DnssecStatus:
    """A DNSSEC assessment for one (resolver, domain), suitable for storage."""

    domain: str
    resolver: str
    signed: Optional[bool]          # is the zone DNSSEC-signed? (None = undetermined)
    posture: "DnssecPosture"        # does the resolver validate?
    security: "SecurityStatus"      # this response's status where determinable
    ad_flag: bool                   # AD set on the domain response
    supports_anomaly: bool          # does DNSSEC corroborate an integrity anomaly?
    detail: str = ""
    observed_at: float = field(default_factory=time.time)


@dataclass
class VerificationOutcome:
    """The result of the multi-stage anomaly-detection engine.

    `evidence` is a per-stage record of what each check found, stored alongside
    the classification so any finding can be justified after the fact. `reason`
    is a one-line human explanation of WHY this class was assigned.
    """

    classification: Classification
    reason: str
    state: "VerificationState"
    evidence: dict = field(default_factory=dict)


@dataclass
class Anomaly:
    """Tier-1: a suspicious measurement awaiting Stage-2 verification."""

    record: HealthRecord
    classification: Classification
    state: VerificationState = VerificationState.PENDING
    reason: str = ""
    checks: dict = field(default_factory=dict)   # which re-checks ran + results
    observed_at: float = field(default_factory=time.time)


@dataclass
class Alert:
    """Tier-2: a verified possible cache-poisoning event (never 'confirmed poisoning')."""

    anomaly: Anomaly
    targeted: bool = False           # peers matched authoritative; only this resolver deviated
    persisted_count: int = 1         # consecutive sweeps the anomaly held
    evidence: dict = field(default_factory=dict)
    confirmed_at: float = field(default_factory=time.time)
