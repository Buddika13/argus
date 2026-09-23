"""Bailiwick checking — docs/METHODOLOGY.md §7.

A server's **bailiwick** is the zone it is authoritative for. Records that fall
outside that zone have no business appearing in its response. This is the oldest
and most structural tell of an injection attempt: the classic Kaminsky-style
attack answers a query for one name while smuggling records for an *unrelated*
name into the Additional section, so that the forged data is cached as a
side-effect of a query the attacker chose.

    dig @<resolver_ip> <domain> +norecurse +additional

RD=0 is used deliberately. It asks the resolver for what it already holds rather
than making it fetch anything, so the check observes **cache state** instead of
creating it — which keeps the module within the passive-measurement constraint
of §15.

Why this matters to the verdict engine: §9 stage 4 refuses to escalate a bare
set mismatch, and demands a *positive* signal — cryptographic (DNSSEC) or
**structural**. This module is the structural half. On its own it is explicitly
"positive but suggestive" (§7), so it corroborates a Tier-4 divergence up to
Tier 5; it never reaches Tier 6 alone, because only cryptographic proof does.
"""

from __future__ import annotations

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype

from ..models import ModuleResult, ModuleStatus

# Record types that carry addresses. An injected A/AAAA for an unrelated name is
# the payload that actually redirects traffic, so these are what we care about.
_ADDRESS_TYPES = (dns.rdatatype.A, dns.rdatatype.AAAA)


def check_bailiwick(resolver_ip: str, domain: str, rtype: str = "A",
                    port: int = 53, timeout: float = 5.0,
                    response: "dns.message.Message | None" = None) -> ModuleResult:
    """Inspect a resolver's Additional/Authority sections for foreign records.

    Pass `response` to analyse an already-captured message (this is what the
    tests do); otherwise the module sends its own RD=0 query.
    """
    data: dict = {"resolver": resolver_ip, "domain": domain, "rtype": rtype}

    if response is None:
        try:
            qtype = dns.rdatatype.from_text(rtype.upper())
        except dns.rdatatype.UnknownRdatatype:
            return ModuleResult("bailiwick", ModuleStatus.SKIPPED,
                                f"unsupported record type {rtype}", data)
        request = dns.message.make_query(domain, qtype)
        request.flags &= ~dns.flags.RD          # +norecurse
        try:
            response, _tcp = dns.query.udp_with_fallback(
                request, resolver_ip, port=port, timeout=timeout)
        except (dns.exception.DNSException, OSError) as exc:
            return ModuleResult("bailiwick", ModuleStatus.UNAVAILABLE,
                                f"RD=0 probe failed: {exc}", data)

    try:
        zone = dns.name.from_text(domain)
    except dns.exception.DNSException as exc:
        return ModuleResult("bailiwick", ModuleStatus.SKIPPED,
                            f"could not parse domain {domain}: {exc}", data)

    allowed = _bailiwick_of(zone, response)
    data["bailiwick"] = sorted(str(n) for n in allowed)

    foreign: list[str] = []
    for section, rrsets in (("additional", response.additional),
                            ("authority", response.authority)):
        for rrset in rrsets:
            if rrset.rdtype not in _ADDRESS_TYPES:
                continue
            if not _within(rrset.name, allowed):
                foreign.append(
                    f"{rrset.name.to_text()} "
                    f"{dns.rdatatype.to_text(rrset.rdtype)} "
                    f"[{section}] -> {', '.join(sorted(rd.to_text() for rd in rrset))}")

    data["out_of_bailiwick"] = foreign

    if foreign:
        return ModuleResult(
            "bailiwick", ModuleStatus.SUSPICIOUS,
            f"{len(foreign)} address record(s) outside the bailiwick of {domain}: "
            + "; ".join(foreign[:3])
            + (" …" if len(foreign) > 3 else ""),
            data)

    return ModuleResult("bailiwick", ModuleStatus.CLEAN,
                        f"no out-of-bailiwick address records for {domain}", data)


def _bailiwick_of(zone: "dns.name.Name",
                  response: "dns.message.Message") -> list["dns.name.Name"]:
    """The names a record may legitimately sit under for this response.

    Three sources, all of them conservative — the aim is to avoid crying foul at
    ordinary glue, because a module with a bad false-positive rate is worse than
    no module at all (§7):

    1. The queried name and its ancestors, stopping **above** the public suffix.
       Glue for `ns1.example.com` is legitimate in a response about
       `www.example.com`. Ancestors are cut off before reaching a bare TLD so
       that `.com` itself never becomes a bailiwick — otherwise every record
       ever sent would qualify and the check would be vacuous.
    2. Zones actually cited in the Authority section, which is the delegation
       the resolver is telling us about.
    3. The targets of NS records in that section: glue for a delegated
       nameserver's own name is expected.
    """
    allowed: list[dns.name.Name] = []

    # 1. the queried name and its ancestors, down to two labels above the root
    #    (e.g. www.example.com -> {www.example.com, example.com}, never {com}).
    current = zone
    while len(current.labels) > 2:              # labels includes the empty root
        allowed.append(current)
        current = current.parent()

    # 2 and 3. delegation context declared by the response itself.
    for rrset in response.authority:
        if rrset.name not in allowed:
            allowed.append(rrset.name)
        if rrset.rdtype == dns.rdatatype.NS:
            for rd in rrset:
                target = getattr(rd, "target", None)
                if target is not None and target not in allowed:
                    allowed.append(target)

    return allowed


def _within(name: "dns.name.Name", allowed: list["dns.name.Name"]) -> bool:
    """True when `name` sits inside any permitted zone."""
    return any(name == zone or name.is_subdomain(zone) for zone in allowed)
