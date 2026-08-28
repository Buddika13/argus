"""DNSSEC SUPPORT — an additional verification/security module.

Standalone: it does not change the monitoring pipeline. It answers four
questions, using only ordinary DNS queries (no attack of any kind):

    1. is_signed(domain)          -> is the domain DNSSEC-signed?
    2. resolver_posture(ip)       -> does the resolver validate DNSSEC?
    3. response_security(...)      -> secure / insecure / bogus (where reliable)
    4. evidence_for_anomaly(...)   -> does DNSSEC corroborate an integrity anomaly?

`inspect()` combines all four into a storable DnssecStatus.

Safe, well-known DNSSEC test domains are used for the posture probe:
    * dnssec-tools.org  — correctly signed  (a validating resolver sets AD)
    * dnssec-failed.org — deliberately bogus (a validating resolver SERVFAILs)
"""

from __future__ import annotations

import logging

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from .models import (DnssecPosture, DnssecStatus, MonitoredResolver,
                     SecurityStatus)

log = logging.getLogger("argus.dnssec")

SIGNED_TEST = "dnssec-tools.org"     # correctly signed
BOGUS_TEST = "dnssec-failed.org"     # deliberately broken signatures


class DnssecInspector:
    def __init__(self, timeout: float = 5.0, reference: str = "8.8.8.8") -> None:
        self.timeout = timeout
        self.reference = reference     # a validating public resolver used as a reference

    # -- 1. is the zone signed? ------------------------------------------
    def is_signed(self, domain: str) -> bool | None:
        """True if the zone publishes a DNSKEY, False if not, None if unknown."""
        resp = self._query(self.reference, domain, "DNSKEY")
        if resp is None:
            return None
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                return True
        return False

    # -- 2. does the resolver validate? ----------------------------------
    def resolver_posture(self, resolver_ip: str, port: int = 53) -> DnssecPosture:
        """Probe a signed and a bogus zone to classify the resolver."""
        signed = self._query(resolver_ip, SIGNED_TEST, "A", port)
        bogus = self._query(resolver_ip, BOGUS_TEST, "A", port)
        if signed is None or bogus is None:
            return DnssecPosture.UNKNOWN

        signed_ad = bool(signed.flags & dns.flags.AD)
        # A validating resolver cannot produce a usable answer for a zone whose
        # signatures do not verify, so it returns SERVFAIL.
        bogus_refused = bogus.rcode() == dns.rcode.SERVFAIL

        if signed_ad and bogus_refused:
            return DnssecPosture.VALIDATING
        if signed_ad and not bogus_refused:
            return DnssecPosture.AD_ONLY        # claims AD yet serves the bogus zone
        if bogus_refused:
            return DnssecPosture.NON_VALIDATING
        return DnssecPosture.PERMISSIVE

    # -- 3. response security status --------------------------------------
    def response_security(self, resolver_ip: str, domain: str, rtype: str = "A",
                          signed: bool | None = None,
                          posture: DnssecPosture | None = None,
                          port: int = 53) -> tuple[SecurityStatus, bool, str]:
        """Classify this resolver's response for the domain as secure/insecure/bogus."""
        if signed is None:
            signed = self.is_signed(domain)
        if posture is None:
            posture = self.resolver_posture(resolver_ip, port)

        resp = self._query(resolver_ip, domain, rtype, port)
        if resp is None:
            return SecurityStatus.INDETERMINATE, False, "response query failed"
        ad = bool(resp.flags & dns.flags.AD)
        rcode = resp.rcode()

        if signed is False:
            return SecurityStatus.INSECURE, ad, "zone is not DNSSEC-signed; no DNSSEC protection"
        if signed is None:
            return SecurityStatus.INDETERMINATE, ad, "could not determine whether the zone is signed"

        validating = posture is DnssecPosture.VALIDATING
        if rcode == dns.rcode.SERVFAIL and validating:
            return SecurityStatus.BOGUS, ad, "signed zone failed validation at a validating resolver"
        if ad:
            return SecurityStatus.SECURE, ad, "signed zone, answer authenticated (AD set)"
        if not validating:
            return (SecurityStatus.INDETERMINATE, ad,
                    "signed zone but resolver does not validate; security cannot be confirmed")
        return SecurityStatus.INDETERMINATE, ad, "signed zone, validating resolver, but AD not set"

    # -- 4. supporting evidence for an anomaly ---------------------------
    def evidence_for_anomaly(self, domain: str, security: SecurityStatus,
                             signed: bool | None = None) -> tuple[bool, str]:
        """Does DNSSEC corroborate a DNS integrity anomaly? (support, never proof)"""
        if security is SecurityStatus.BOGUS:
            return True, "response failed DNSSEC validation (BOGUS) — strong supporting evidence"
        if signed is None:
            signed = self.is_signed(domain)
        if signed:
            return (True, "zone is DNSSEC-signed, so a validating resolver should reject forged "
                          "data — supporting evidence")
        return (False, "zone is not signed / undetermined — DNSSEC cannot corroborate")

    # -- pure assessment from already-observed values (no extra query) ----
    def assess(self, domain: str, signed: bool | None, posture: DnssecPosture,
               ad: bool, rcode: str) -> tuple[SecurityStatus, bool, str]:
        """Classify security from values already gathered by the sweep.

        Lets the scheduler reuse the probe's AD flag and rcode instead of
        issuing another query per (resolver, domain).
        """
        if signed is False:
            security = SecurityStatus.INSECURE
            detail = "zone is not DNSSEC-signed; no DNSSEC protection"
        elif signed is None:
            security = SecurityStatus.INDETERMINATE
            detail = "could not determine whether the zone is signed"
        else:
            validating = posture is DnssecPosture.VALIDATING
            if rcode == "SERVFAIL" and validating:
                security = SecurityStatus.BOGUS
                detail = "signed zone failed validation at a validating resolver"
            elif ad:
                security = SecurityStatus.SECURE
                detail = "signed zone, answer authenticated (AD set)"
            else:
                security = SecurityStatus.INDETERMINATE
                detail = ("signed zone but resolver does not validate; security cannot be confirmed"
                          if not validating else "signed zone, validating resolver, but AD not set")
        supports, support_detail = self.evidence_for_anomaly(domain, security, signed)
        return security, supports, f"{detail}; {support_detail}"

    # -- combined --------------------------------------------------------
    def inspect(self, resolver: MonitoredResolver, domain: str, rtype: str = "A") -> DnssecStatus:
        signed = self.is_signed(domain)
        posture = self.resolver_posture(resolver.address, resolver.port)
        security, ad, detail = self.response_security(
            resolver.address, domain, rtype, signed, posture, resolver.port)
        supports, support_detail = self.evidence_for_anomaly(domain, security, signed)
        return DnssecStatus(
            domain=domain, resolver=resolver.name, signed=signed, posture=posture,
            security=security, ad_flag=ad, supports_anomaly=supports,
            detail=f"{detail}; {support_detail}",
        )

    # -- low-level query --------------------------------------------------
    def _query(self, ip: str, name: str, rtype: str, port: int = 53):
        request = dns.message.make_query(name, rtype, want_dnssec=True)
        request.flags |= dns.flags.RD
        try:
            response, _ = dns.query.udp_with_fallback(request, ip, port=port, timeout=self.timeout)
            return response
        except Exception as exc:  # noqa: BLE001
            log.debug("dnssec query %s %s @ %s failed: %s", name, rtype, ip, exc)
            return None
