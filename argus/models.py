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


class Tier(int, Enum):
    """The verdict ladder of docs/METHODOLOGY.md §8 — one tier per observation.

    The ladder is MONOTONIC: a higher tier requires the lower conditions to be
    cleared and demands progressively stronger evidence. Escalation past a bare
    mismatch is gated by the exclusion hierarchy (§9), which is what makes an
    ARGUS claim defensible. Reporting discipline (§8): favour under-claiming —
    Tiers 4-5 are *suggestive*; the word "poisoning" is reserved for Tier 6.
    """

    CLEAN = 0                     # untrusted set == trusted set; no anomalies
    BENIGN_EXPLAINED = 1          # differs, but fully explained (GeoDNS/CDN/ECS)
    HEALTH_ISSUE = 2              # unreachable/SERVFAIL/timeout; integrity unknown
    FRESHNESS_ANOMALY = 3         # answer matches but TTL/timing is implausible
    UNEXPLAINED_DIVERGENCE = 4    # survived exclusions; no positive evidence yet
    CORROBORATED_DIVERGENCE = 5   # Tier 4 + a supporting structural signal
    CONCLUSIVE_TAMPERING = 6      # positive cryptographic proof

    @property
    def label(self) -> str:
        return {
            0: "Consistent / clean",
            1: "Benign variation explained",
            2: "Health issue (integrity unknown)",
            3: "Freshness / timing anomaly",
            4: "Unexplained divergence (candidate)",
            5: "Corroborated divergence",
            6: "Conclusive tampering",
        }[int(self)]

    @property
    def interpretation(self) -> str:
        return {
            0: "Healthy, faithful resolver — the expected state.",
            1: "Reconciled; not suspicious.",
            2: "A health problem; correctness could not be assessed.",
            3: "Low-grade signal; likely benign, worth logging.",
            4: "Anomaly worth investigating — not a poisoning claim.",
            5: "Strong suggestion; still not cryptographically proven.",
            6: "Defensible poisoning / integrity-violation claim.",
        }[int(self)]

    @property
    def is_divergence(self) -> bool:
        """Tiers that describe an unexplained integrity divergence (§8)."""
        return int(self) >= 4

    @property
    def suggestive_only(self) -> bool:
        """True where §8 requires the finding be reported as *suggestive*."""
        return int(self) in (4, 5)

    @property
    def needs_alert(self) -> bool:
        """§10.4 — emit alerts/evidence for Tier 2 or Tier >= 4."""
        return int(self) == 2 or int(self) >= 4


class SetRelation(str, Enum):
    """How the untrusted answer set relates to the trusted one (§4, §11).

    Recorded per observation so a divergence can be characterised by shape, not
    just flagged. DISJOINT is the strongest divergence.
    """

    MATCH = "MATCH"            # identical sets
    SUBSET = "SUBSET"          # resolver returned fewer (load balancing)
    SUPERSET = "SUPERSET"      # resolver returned everything, plus extras
    OVERLAP = "OVERLAP"        # partial overlap, each side has records the other lacks
    DISJOINT = "DISJOINT"      # no overlap at all
    UNDETERMINED = "UNDETERMINED"   # a side could not be measured


class ModuleStatus(str, Enum):
    """What a signal module (§7) concluded for one observation."""

    CLEAN = "CLEAN"                # ran; nothing notable
    BENIGN = "BENIGN"              # ran; explains a difference benignly
    SUSPICIOUS = "SUSPICIOUS"      # ran; a positive signal worth corroborating
    UNAVAILABLE = "UNAVAILABLE"    # could not run (network, unsupported)
    SKIPPED = "SKIPPED"            # not applicable to this observation


class ExclusionStage(int, Enum):
    """The five gates of docs/METHODOLOGY.md §9, in order."""

    GEODNS = 1              # rule out geographic variation
    TIMING = 2              # rule out races / mid-flight TTL expiry
    ISP_POLICY = 3          # rule out lawful/administrative interception
    POSITIVE_EVIDENCE = 4   # require cryptographic or structural evidence
    HONEST_CHARACTERISATION = 5   # report survivors as suggestive, not proven

    @property
    def label(self) -> str:
        return {
            1: "Rule out GeoDNS",
            2: "Rule out timing artefacts",
            3: "Rule out ISP policy interception",
            4: "Require positive evidence",
            5: "Characterise honestly",
        }[int(self)]


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
    # Whether this resolver's address has been locally verified from the
    # monitoring vantage (a real dig against it succeeded), as opposed to being
    # a candidate taken from a third-party public directory. Kept honest in the
    # research: a candidate is monitored but labelled unverified until confirmed.
    verified: bool = False
    # Optional position on the national map, as percentages of the outline's
    # bounding box. Left unset unless the operator supplies a real location:
    # the dashboard draws no marker rather than inventing one.
    map_x: float | None = None
    map_y: float | None = None

    @property
    def has_location(self) -> bool:
        return self.map_x is not None and self.map_y is not None

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
class ModuleResult:
    """What one signal module (docs/METHODOLOGY.md §7) found for an observation.

    Modules never assign a tier and never decide anything on their own; each
    records a structured result that the verdict engine (§8) weighs. That
    separation is deliberate — it keeps every escalation traceable to a named
    module output rather than to logic buried in a probe.
    """

    module: str                      # "ttl" | "bailiwick" | "consensus" | ...
    status: ModuleStatus
    detail: str = ""
    data: dict = field(default_factory=dict)

    @property
    def is_positive_evidence(self) -> bool:
        """§9 stage 4 — does this count as positive structural/crypto evidence?"""
        return self.status is ModuleStatus.SUSPICIOUS


@dataclass
class ExclusionOutcome:
    """The result of one gate in the five-stage exclusion hierarchy (§9).

    `passed` means the divergence SURVIVED this gate and may continue up the
    ladder. A gate that does not pass caps the tier at `capped_at` and records
    why, so a downgrade is as auditable as an escalation.
    """

    stage: ExclusionStage
    passed: bool
    detail: str = ""
    capped_at: Optional["Tier"] = None

    @property
    def label(self) -> str:
        return self.stage.label


@dataclass
class Verdict:
    """One observation's tier, plus everything that produced it (§8, §9, §11).

    This is the unit the dissertation reports: a tier, the set relation that
    shaped it, the module outputs that fed it, and the exclusion gates it did or
    did not survive. `classification` carries the legacy Classification so the
    existing storage, dashboard and alerting keep working unchanged.
    """

    tier: Tier
    reason: str
    relation: SetRelation = SetRelation.UNDETERMINED
    modules: dict[str, ModuleResult] = field(default_factory=dict)
    exclusions: list[ExclusionOutcome] = field(default_factory=list)
    classification: Classification = Classification.NORMAL

    @property
    def suggestive(self) -> bool:
        return self.tier.suggestive_only

    @property
    def positive_evidence(self) -> list[str]:
        """Names of the modules that supplied positive evidence (§9 stage 4)."""
        return sorted(name for name, m in self.modules.items()
                      if m.is_positive_evidence)

    def gate(self, stage: ExclusionStage) -> Optional[ExclusionOutcome]:
        """The recorded outcome for one gate, or None if it did not run."""
        for outcome in self.exclusions:
            if outcome.stage is stage:
                return outcome
        return None

    def as_evidence(self) -> dict:
        """A JSON-safe summary for storage and the dashboard's evidence panel."""
        return {
            "tier": int(self.tier),
            "tier_label": self.tier.label,
            "interpretation": self.tier.interpretation,
            "reason": self.reason,
            "relation": self.relation.value,
            "suggestive": self.suggestive,
            "positive_evidence": self.positive_evidence,
            "modules": {
                name: {"status": m.status.value, "detail": m.detail, "data": m.data}
                for name, m in self.modules.items()
            },
            "exclusions": [
                {"stage": int(o.stage), "name": o.label, "passed": o.passed,
                 "detail": o.detail,
                 "capped_at": int(o.capped_at) if o.capped_at is not None else None}
                for o in self.exclusions
            ],
        }


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
    # The methodology §8 tier this alert was raised at. Optional so an Alert
    # built by older code still constructs; the delivery layer falls back to the
    # classification when it is absent.
    tier: Optional["Tier"] = None

    # The identifying facts live on the measurement this alert was raised from.
    # Exposing them here keeps the delivery layer (alerting.py) and the report
    # writers from reaching three objects deep for a resolver name.
    @property
    def resolver(self) -> str:
        return self.anomaly.record.resolver

    @property
    def domain(self) -> str:
        return self.anomaly.record.domain

    @property
    def rtype(self) -> str:
        return self.anomaly.record.rtype

    @property
    def status(self) -> str:
        """The headline label a reader sees first.

        The tier is the authority when one was assigned, because it carries the
        strength of the claim (§8); the classification is the fallback.
        """
        if self.tier is not None:
            return f"TIER_{int(self.tier)}_{self.tier.name}"
        return self.anomaly.classification.value
