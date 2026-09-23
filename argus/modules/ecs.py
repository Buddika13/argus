"""EDNS Client Subnet — docs/METHODOLOGY.md §7, and the engine behind §9 stage 1.

    dig @<resolver_ip> <domain> +subnet=203.0.113.0/24

This is the module that separates the single largest source of false positives
from a real finding. A content-delivery network answers the *same* question with
*different* addresses depending on where the client appears to be, so a resolver
in Colombo and an authoritative walk from elsewhere legitimately disagree — and
a naive set comparison calls that poisoning. It is precisely the failure mode
the earlier ARGUS experiment recorded on `google.com` and `microsoft.com`.

EDNS Client Subnet lets us ask the question directly instead of inferring it.
By varying the client-subnet hint and watching whether the answer moves with it,
we learn whether the name is geographically sensitive at all:

* **The answer tracks the subnet** → the name is GeoDNS-served. A difference is
  explained by geography, so §9 stage 1 caps the observation at **Tier 1**.
* **The answer is identical for every subnet** → geography does not explain it.
  The divergence survives stage 1 and may continue up the ladder.

The second case is the valuable one, and it is why this module reports
`CLEAN` rather than `SUSPICIOUS` when nothing varies: it has not found evidence
of tampering, it has *removed an innocent explanation*. Only the verdict engine
draws conclusions from that.

**On the prefixes used.** ECS discrimination is only as good as the client
subnets supplied: they must plausibly geolocate to different regions or the
authoritative side has no reason to answer differently. The built-in defaults
are deliberately conservative and configurable — an operator measuring Sri
Lankan resolvers should supply real prefixes for the regions they care about.
Nothing here attacks or spoofs: an ECS hint is an ordinary, standardised EDNS
option (RFC 7871) that a client is entitled to send.
"""

from __future__ import annotations

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype

from ..models import ModuleResult, ModuleStatus

# Client subnets used to probe for geographic sensitivity. Public, widely
# geolocated prefixes spanning distinct regions, plus one RFC 5737
# documentation prefix as a neutral control that maps nowhere in particular.
# Override via config: `modules.ecs.subnets`.
DEFAULT_SUBNETS: tuple[tuple[str, int], ...] = (
    ("203.0.113.0", 24),     # RFC 5737 documentation range — neutral control
    ("8.8.8.0", 24),         # North America
    ("1.1.1.0", 24),         # global anycast
)


def check_ecs(resolver_ip: str, domain: str, rtype: str = "A",
              subnets: "tuple[tuple[str, int], ...] | None" = None,
              port: int = 53, timeout: float = 5.0,
              observed: "dict[str, frozenset[str]] | None" = None) -> ModuleResult:
    """Probe whether `domain` is answered differently per client subnet.

    Pass `observed` (subnet label -> answer set) to evaluate already-collected
    data without touching the network; this is what the tests do.
    """
    subnets = subnets or DEFAULT_SUBNETS
    data: dict = {"resolver": resolver_ip, "domain": domain, "rtype": rtype}

    if observed is None:
        observed, errors = _probe(resolver_ip, domain, rtype, subnets, port, timeout)
        data["errors"] = errors
        if not observed:
            return ModuleResult(
                "ecs", ModuleStatus.UNAVAILABLE,
                "no ECS probe succeeded, so geographic variation could not be "
                "ruled in or out: " + "; ".join(errors[:2]),
                data)

    data["answers"] = {label: sorted(records) for label, records in observed.items()}

    # A single successful probe cannot show variation, so it cannot support a
    # conclusion either way. Saying so is more useful than a false CLEAN.
    if len(observed) < 2:
        return ModuleResult(
            "ecs", ModuleStatus.UNAVAILABLE,
            f"only {len(observed)} client subnet answered; at least two are "
            "needed to tell geographic variation from tampering", data)

    distinct = {frozenset(records) for records in observed.values()}
    data["distinct_answer_sets"] = len(distinct)

    if len(distinct) > 1:
        return ModuleResult(
            "ecs", ModuleStatus.BENIGN,
            f"the answer tracks the client subnet ({len(distinct)} distinct sets "
            f"across {len(observed)} subnets) — {domain} is GeoDNS-served, so a "
            "difference is explained by geography",
            data)

    return ModuleResult(
        "ecs", ModuleStatus.CLEAN,
        f"the answer is identical across {len(observed)} client subnets — "
        "geography does not explain a difference for this name",
        data)


def _probe(resolver_ip: str, domain: str, rtype: str,
           subnets: "tuple[tuple[str, int], ...]", port: int,
           timeout: float) -> "tuple[dict[str, frozenset[str]], list[str]]":
    """Query the resolver once per client subnet. Never raises."""
    try:
        qtype = dns.rdatatype.from_text(rtype.upper())
    except dns.rdatatype.UnknownRdatatype:
        return {}, [f"unsupported record type {rtype}"]

    answers: dict[str, frozenset[str]] = {}
    errors: list[str] = []

    for address, prefix in subnets:
        label = f"{address}/{prefix}"
        try:
            option = dns.edns.ECSOption(address, prefix)
            request = dns.message.make_query(domain, qtype, use_edns=0,
                                             options=[option])
            request.flags |= dns.flags.RD
            response, _tcp = dns.query.udp_with_fallback(
                request, resolver_ip, port=port, timeout=timeout)
        except (dns.exception.DNSException, OSError, ValueError) as exc:
            errors.append(f"{label}: {exc}")
            continue

        records = {rd.to_text().lower()
                   for rrset in response.answer if rrset.rdtype == qtype
                   for rd in rrset}
        # An empty answer is not a data point about geography — it says the name
        # did not resolve for that hint, which would make identical-empty sets
        # look like reassuring agreement. Drop it rather than let it mislead.
        if records:
            answers[label] = frozenset(records)
        else:
            errors.append(f"{label}: no {rtype} records returned")

    return answers, errors
