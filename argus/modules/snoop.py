"""Cache snooping (RD=0) — docs/METHODOLOGY.md §7.

    dig @<resolver_ip> <domain> +norecurse

With recursion desired cleared, a resolver answers only from what it already
holds. That makes this the one way to observe **cache state** without creating
it: an ordinary RD=1 query changes the very thing we are trying to measure,
because it populates the cache as a side-effect of asking.

Two things it gives the study:

* **Freshness ground truth.** The TTL returned for an already-cached entry is a
  live countdown, so it is the honest input to the TTL module's countdown check
  (§7) rather than a value freshly reset by our own query.
* **Provenance of a divergence.** A divergent answer that is *already cached*
  was served to real users before ARGUS arrived. One that appears only on a
  recursive query is something the resolver fetched for us just now.

This module is **observational** and reports `CLEAN` even for a hit: a cached
entry is completely normal and is not evidence of anything. It only reports
`UNAVAILABLE` when it genuinely could not look — including when a resolver
declines RD=0 queries, which many correctly do as an anti-snooping measure, and
which is a legitimate policy rather than a fault.

Ethics (§15): RD=0 is strictly *less* intrusive than the ordinary queries ARGUS
already sends. It asks the resolver to do no work and to contact nobody.
"""

from __future__ import annotations

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from ..models import ModuleResult, ModuleStatus


def check_cache_state(resolver_ip: str, domain: str, rtype: str = "A",
                      port: int = 53, timeout: float = 5.0,
                      response: "dns.message.Message | None" = None) -> ModuleResult:
    """Report whether `domain`/`rtype` is already in the resolver's cache.

    Pass `response` to evaluate a captured RD=0 message without touching the
    network; otherwise the module sends the probe itself.
    """
    data: dict = {"resolver": resolver_ip, "domain": domain, "rtype": rtype}

    try:
        qtype = dns.rdatatype.from_text(rtype.upper())
    except dns.rdatatype.UnknownRdatatype:
        return ModuleResult("snoop", ModuleStatus.SKIPPED,
                            f"unsupported record type {rtype}", data)

    if response is None:
        request = dns.message.make_query(domain, qtype)
        request.flags &= ~dns.flags.RD          # +norecurse
        try:
            response, _tcp = dns.query.udp_with_fallback(
                request, resolver_ip, port=port, timeout=timeout)
        except (dns.exception.DNSException, OSError) as exc:
            return ModuleResult("snoop", ModuleStatus.UNAVAILABLE,
                                f"RD=0 probe failed: {exc}", data)

    rcode = dns.rcode.to_text(response.rcode())
    data["rcode"] = rcode

    # A resolver may refuse RD=0 queries outright. That is a deliberate,
    # reasonable configuration, not a finding.
    if rcode in ("REFUSED", "NOTIMP"):
        return ModuleResult("snoop", ModuleStatus.UNAVAILABLE,
                            f"the resolver declines RD=0 queries ({rcode}); "
                            "cache state cannot be observed", data)

    records: set[str] = set()
    ttls: list[int] = []
    for rrset in response.answer:
        if rrset.rdtype == qtype:
            records.update(rd.to_text().lower() for rd in rrset)
            ttls.append(rrset.ttl)

    cached = bool(records)
    data.update({
        "cached": cached,
        "records": sorted(records),
        "ttl": min(ttls) if ttls else None,
        "recursion_available": bool(response.flags & dns.flags.RA),
    })

    if cached:
        return ModuleResult(
            "snoop", ModuleStatus.CLEAN,
            f"{domain}/{rtype} is already cached (TTL {data['ttl']}s, "
            f"{len(records)} record(s)) — this answer was being served to users "
            "before ARGUS queried", data)

    return ModuleResult("snoop", ModuleStatus.CLEAN,
                        f"{domain}/{rtype} is not in the cache; any answer the "
                        "resolver gave us was fetched on demand", data)
