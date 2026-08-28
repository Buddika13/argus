"""VERIFICATION PATH — independent authoritative resolution.

Resolves a name by walking the hierarchy ourselves, Root -> TLD -> Authoritative,
with recursion disabled (RD=0) so each server hands back a referral we follow.
We never ask a recursive resolver, because that would only trust another cache.

Design rules that keep this trustworthy ground truth:
  * The 13 root server addresses are built in (fetching them would reintroduce
    the trust we are removing).
  * We follow referrals ourselves, choosing servers at random to spread load.
  * CNAMEs are followed by restarting the walk for the target (its records may
    live in another zone).
  * Only nameserver *addresses* are briefly cached; final answers are never
    cached, since a stale answer would become a false accusation.

resolve() never raises: any failure is reported in AuthoritativeAnswer.error so a
broken walk degrades one measurement instead of stopping a sweep.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from .models import AuthoritativeAnswer

log = logging.getLogger("argus.verifier")

ROOT_HINTS: tuple[str, ...] = (
    "198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33",
)


class WalkError(Exception):
    """The hierarchy walk could not be completed."""


@dataclass
class _CacheEntry:
    addresses: tuple[str, ...]
    expires_at: float


class AuthoritativeVerifier:
    """Iterative resolver used as the reference for every comparison."""

    def __init__(self, timeout: float = 5.0, max_depth: int = 12,
                 referral_cache_seconds: int = 3600) -> None:
        self.timeout = timeout
        self.max_depth = max_depth
        self.referral_cache_seconds = referral_cache_seconds
        self._referrals: dict[str, _CacheEntry] = {}

    def resolve(self, domain: str, rtype: str = "A") -> AuthoritativeAnswer:
        try:
            return self._resolve(domain, rtype)
        except Exception as exc:  # noqa: BLE001 - deliberately total
            log.debug("authoritative walk failed for %s/%s: %s", domain, rtype, exc)
            return AuthoritativeAnswer(domain=domain, rtype=rtype,
                                       error=f"{type(exc).__name__}: {exc}")

    # -- internals -------------------------------------------------------
    def _resolve(self, domain: str, rtype: str, cname_hops: int = 0,
                 glue_depth: int = 0) -> AuthoritativeAnswer:
        qname = dns.name.from_text(domain)
        qtype = dns.rdatatype.from_text(rtype)
        nameservers = list(ROOT_HINTS)
        chain: list[str] = []
        zone = dns.name.root

        for _ in range(self.max_depth):
            response = self._query_any(nameservers, qname, qtype)
            if response is None:
                raise WalkError(f"no nameserver in {zone} answered for {domain}")
            rcode = dns.rcode.to_text(response.rcode())

            answer = self._extract(response.answer, qname, qtype)
            if answer:
                records, ttl = answer
                return AuthoritativeAnswer(
                    domain=domain, rtype=rtype, records=frozenset(records), ttl=ttl,
                    rcode=rcode, authoritative_servers=tuple(nameservers), chain=tuple(chain))

            cname = self._extract_cname(response.answer, qname)
            if cname is not None:
                if cname_hops >= 6:
                    raise WalkError(f"CNAME chain too long for {domain}")
                chain.append(f"{qname.to_text()} CNAME {cname}")
                followed = self._resolve(cname, rtype, cname_hops + 1, glue_depth)
                return AuthoritativeAnswer(
                    domain=domain, rtype=rtype, records=followed.records, ttl=followed.ttl,
                    rcode=followed.rcode, authoritative_servers=followed.authoritative_servers,
                    chain=tuple(chain) + followed.chain, error=followed.error)

            if response.rcode() == dns.rcode.NXDOMAIN:
                return AuthoritativeAnswer(
                    domain=domain, rtype=rtype, rcode="NXDOMAIN",
                    authoritative_servers=tuple(nameservers), chain=tuple(chain))

            referral = self._extract_referral(response, zone, glue_depth)
            if referral is None:
                # Authoritative but no record of this type: legitimate NODATA.
                return AuthoritativeAnswer(
                    domain=domain, rtype=rtype, records=frozenset(), rcode=rcode,
                    authoritative_servers=tuple(nameservers), chain=tuple(chain))

            child_zone, addresses = referral
            chain.append(f"{zone.to_text()} -> {child_zone.to_text()}")
            zone, nameservers = child_zone, addresses

        raise WalkError(f"delegation depth exceeded for {domain}")

    def _query_any(self, nameservers, qname, qtype):
        request = dns.message.make_query(qname, qtype)
        request.flags &= ~dns.flags.RD          # iterative: we follow referrals
        for address in random.sample(nameservers, k=len(nameservers)):
            try:
                response, _ = dns.query.udp_with_fallback(request, address, timeout=self.timeout)
                return response
            except Exception as exc:  # noqa: BLE001 - try the next server
                log.debug("nameserver %s did not answer: %s", address, exc)
        return None

    @staticmethod
    def _extract(section, qname, qtype):
        for rrset in section:
            if rrset.rdtype == qtype and rrset.name == qname:
                return {rd.to_text() for rd in rrset}, rrset.ttl
        return None

    @staticmethod
    def _extract_cname(section, qname):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.CNAME and rrset.name == qname:
                return rrset[0].target.to_text()
        return None

    def _extract_referral(self, response, current_zone, glue_depth=0):
        ns_rrset = next((rr for rr in response.authority if rr.rdtype == dns.rdatatype.NS), None)
        if ns_rrset is None:
            return None
        child_zone = ns_rrset.name
        if child_zone == current_zone or not child_zone.is_subdomain(current_zone):
            return None
        ns_names = [rd.target.to_text() for rd in ns_rrset]

        # Prefer in-bailiwick glue from the additional section (A and AAAA).
        glue: list[str] = []
        for rrset in response.additional:
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                glue.extend(rd.to_text() for rd in rrset)
        if not glue:
            glue = self._resolve_ns_addresses(ns_names, glue_depth)
        return (child_zone, glue) if glue else None

    def _resolve_ns_addresses(self, ns_names, glue_depth=0):
        """Resolve out-of-bailiwick nameserver names by our OWN iterative walk.

        Using a recursive resolver here would reintroduce the very cache trust
        the walk exists to remove, so instead we sub-walk from the root for each
        nameserver name. Bounded by `glue_depth` to prevent unbounded recursion
        (a nameserver whose own resolution needs more glue).
        """
        if glue_depth >= 3:
            log.debug("glue depth limit reached; giving up on %s", ns_names)
            return []
        now = time.time()
        addresses: list[str] = []
        for name in ns_names:
            cached = self._referrals.get(name)
            if cached and cached.expires_at > now:
                addresses.extend(cached.addresses)
                continue
            answer = self._resolve(name, "A", glue_depth=glue_depth + 1)
            resolved = tuple(answer.records) if (answer.ok and answer.records) else ()
            if not resolved:
                continue
            self._referrals[name] = _CacheEntry(resolved, now + self.referral_cache_seconds)
            addresses.extend(resolved)
            if addresses:
                break
        return addresses
