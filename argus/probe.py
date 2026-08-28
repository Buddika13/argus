"""DIRECT PATH — query a monitored DNS resolver.

Sends an ordinary recursive query (RD=1) to the resolver under test, exactly as
a real user's device would, and records what came back. This module only
*measures*; it does not compare answers or judge integrity — that happens in
later stages.

Captured per query (requirement set):
    - answer records (all of them — multiple A/AAAA fully supported)
    - TTL (the minimum TTL across the answer, i.e. what expires first)
    - response code (NOERROR / NXDOMAIN / SERVFAIL / TIMEOUT / ...)
    - query time (milliseconds)
    - resolver IP, domain, record type

Supported record types: A, AAAA, CNAME.

Failure handling is total — a query never raises. Instead the failure mode is
recorded so one bad probe degrades a single measurement rather than stopping a
sweep:
    - timeout            -> rcode "TIMEOUT",  error set   (retried first)
    - SERVFAIL/NXDOMAIN  -> rcode as returned, no error   (a valid DNS response)
    - connection error   -> rcode "ERROR",    error set   (retried first)
    - malformed response -> rcode "MALFORMED", error set
"""

from __future__ import annotations

import time
from typing import Union

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from .models import DirectAnswer, MonitoredResolver

SUPPORTED_TYPES = ("A", "AAAA", "CNAME")

# A resolver may be given as a MonitoredResolver or a bare IP string.
ResolverArg = Union[MonitoredResolver, str]


class ResolverProbe:
    """Queries a DNS resolver and times the response."""

    def __init__(self, timeout: float = 5.0, retries: int = 2,
                 default_port: int = 53) -> None:
        self.timeout = timeout
        self.retries = retries
        self.default_port = default_port

    def query(self, resolver: ResolverArg, domain: str,
              rtype: str = "A") -> DirectAnswer:
        """Query one resolver for `domain`/`rtype`, retrying transient failures."""
        name, ip, port = self._normalise(resolver)
        rtype = rtype.upper()

        try:
            qtype = dns.rdatatype.from_text(rtype)
        except dns.rdatatype.UnknownRdatatype:
            return _failure(name, ip, domain, rtype, "ERROR",
                            f"unsupported record type: {rtype}")

        request = dns.message.make_query(domain, qtype, want_dnssec=True)
        request.flags |= dns.flags.RD

        last_error = "no attempt made"
        for attempt in range(self.retries + 1):
            started = time.perf_counter()
            try:
                response, _used_tcp = dns.query.udp_with_fallback(
                    request, ip, port=port, timeout=self.timeout
                )
            except dns.exception.Timeout:
                last_error = "timeout"
                continue                      # transient — retry
            except (ConnectionError, OSError) as exc:
                last_error = f"connection error: {exc}"
                continue                      # transient — retry
            except dns.exception.FormError as exc:
                return _failure(name, ip, domain, rtype, "MALFORMED",
                                f"malformed response: {exc}")
            except dns.exception.DNSException as exc:
                last_error = f"dns error: {exc}"
                continue

            latency_ms = (time.perf_counter() - started) * 1000.0
            return build_answer(response, name, ip, domain, rtype, latency_ms)

        # All attempts exhausted (timeout / connection / other transient error).
        rcode = "TIMEOUT" if last_error == "timeout" else "ERROR"
        return _failure(name, ip, domain, rtype, rcode, last_error)

    def _normalise(self, resolver: ResolverArg) -> tuple[str, str, int]:
        if isinstance(resolver, MonitoredResolver):
            return resolver.name, resolver.address, resolver.port
        return str(resolver), str(resolver), self.default_port


def build_answer(response: dns.message.Message, name: str, ip: str,
                 domain: str, rtype: str, latency_ms: float) -> DirectAnswer:
    """Extract a DirectAnswer from a DNS response message.

    Collects every rrset of the requested type anywhere in the answer section,
    so a CNAME chain leading to several A/AAAA records is fully captured — this
    is what makes multiple-record support correct.
    """
    qtype = dns.rdatatype.from_text(rtype)
    records: set[str] = set()
    ttls: list[int] = []

    for rrset in response.answer:
        if rrset.rdtype == qtype:
            records.update(rd.to_text() for rd in rrset)
            ttls.append(rrset.ttl)

    return DirectAnswer(
        resolver=name,
        domain=domain,
        rtype=rtype,
        resolver_ip=ip,
        records=frozenset(records),
        min_ttl=min(ttls) if ttls else None,
        rcode=dns.rcode.to_text(response.rcode()),
        latency_ms=latency_ms,
        authenticated=bool(response.flags & dns.flags.AD),
    )


def _failure(name: str, ip: str, domain: str, rtype: str,
             rcode: str, error: str) -> DirectAnswer:
    return DirectAnswer(
        resolver=name, domain=domain, rtype=rtype, resolver_ip=ip,
        records=frozenset(), rcode=rcode, error=error,
    )
