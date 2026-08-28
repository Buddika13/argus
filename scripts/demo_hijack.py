#!/usr/bin/env python3
"""Side-by-side demonstration: an honest resolver versus a hijacked one.

    python scripts/demo_hijack.py                      # cloudflare.com, honest = 1.1.1.1
    python scripts/demo_hijack.py --domain nsbm.ac.lk
    python scripts/demo_hijack.py --honest 8.8.8.8 --forged 203.0.113.66
    python scripts/demo_hijack.py --ttl 86400          # also demonstrate TTL inflation

What this does
--------------
Starts a small DNS server on **loopback only** (127.0.0.1:5354) that behaves like
an ordinary caching resolver -- it forwards every query upstream -- except for one
name, for which it returns an address the authoritative servers never published.
That is a cache-poisoned resolver, reproduced under our own control.

Argus's full pipeline is then run twice against the same domain:

    A. an honest public resolver   -> expected NORMAL
    B. our lying local resolver    -> expected POSSIBLE_CACHE_POISONING

and the two verdicts are printed side by side, with the evidence that separates
them. This is the true-positive counterpart to the live experiment, in which no
real poisoning was observed.

Ethics
------
The lying server binds to 127.0.0.1 and answers only this process's own queries.
No third-party resolver is poisoned, flooded, or altered in any way; the honest
resolver receives ordinary queries only. The forged address defaults to
203.0.113.66, inside the RFC 5737 documentation range, which routes nowhere.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from argus.comparison import compare
from argus.models import MonitoredResolver
from argus.probe import ResolverProbe
from argus.verification import AnomalyVerifier
from argus.verifier import AuthoritativeVerifier

FORGED_DEFAULT = "203.0.113.66"     # RFC 5737 TEST-NET-3: documentation only
LAB_HOST = "127.0.0.1"
LAB_PORT = 5354                     # unprivileged: no sudo required


class PoisonedResolver:
    """A loopback caching resolver that lies about exactly one name.

    Every query is forwarded to `upstream` unchanged, except `domain`/A, which is
    answered with `forged_ip`. This reproduces the observable behaviour of a
    poisoned cache entry without touching any real resolver.
    """

    def __init__(self, domain: str, forged_ip: str, upstream: str,
                 ttl: int = 300, host: str = LAB_HOST, port: int = LAB_PORT) -> None:
        self.domain = domain.rstrip(".").lower()
        self.forged_ip = forged_ip
        self.upstream = upstream
        self.ttl = ttl
        self.host = host
        self.port = port
        self.lies_told = 0
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._sock is not None:
            self._sock.close()

    def __enter__(self) -> "PoisonedResolver":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # -- serving -----------------------------------------------------------

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, client = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                reply = self._respond(data)
            except Exception:               # a lab server must never die mid-demo
                continue
            if reply:
                try:
                    self._sock.sendto(reply, client)
                except OSError:
                    break

    def _respond(self, data: bytes) -> bytes | None:
        request = dns.message.from_wire(data)
        if not request.question:
            return None
        question = request.question[0]
        name = question.name.to_text().rstrip(".").lower()

        if name == self.domain and question.rdtype == dns.rdatatype.A:
            self.lies_told += 1
            response = dns.message.make_response(request)
            response.flags |= dns.flags.RA          # claim to be a normal cache
            response.set_rcode(dns.rcode.NOERROR)
            response.answer.append(dns.rrset.from_text(
                question.name, self.ttl, dns.rdataclass.IN, dns.rdatatype.A,
                self.forged_ip))
            return response.to_wire()

        # Everything else: behave like an ordinary forwarding cache.
        upstream = dns.query.udp(request, self.upstream, timeout=5.0)
        return upstream.to_wire()


# ------------------------------------------------------------------ report --

def assess(resolver: MonitoredResolver, domain: str, probe: ResolverProbe,
           verifier: AuthoritativeVerifier, anomaly: AnomalyVerifier) -> dict:
    """Run one resolver through the real Argus pipeline for domain/A."""
    direct = probe.query(resolver, domain, "A")
    truth = verifier.resolve(domain, "A")
    result = compare(direct, truth)

    verdict = result.classification
    reason = result.reason
    stage1 = result.classification.value
    if result.classification.needs_review:
        outcome = anomaly.verify(resolver, direct, truth, result)
        verdict = outcome.classification
        reason = outcome.reason

    return {
        "resolver": resolver,
        "returned": sorted(direct.records),
        "authoritative": sorted(truth.records),
        "ttl": direct.min_ttl,
        "auth_ttl": truth.ttl,
        "latency_ms": direct.latency_ms,
        "rcode": direct.rcode,
        "stage1": stage1,
        "verdict": verdict.value,
        "reason": reason,
        "chain": truth.chain,
    }


def _cell(value: object, width: int = 25) -> str:
    """Fit a value into the summary table; the full values are printed above."""
    if isinstance(value, list):
        text = ", ".join(str(item) for item in value) or "(none)"
    else:
        text = str(value)
    return text if len(text) <= width else text[:width - 3] + "..."


def show(title: str, report: dict) -> None:
    print("-" * 74)
    print(title)
    print("-" * 74)
    resolver = report["resolver"]
    where = resolver.address
    if resolver.port != 53:
        where += ":" + str(resolver.port)
    print("  resolver queried    : {0}  ({1})".format(where, resolver.name))
    print("  resolver returned   : {0}".format(report["returned"] or "(none)"))
    print("  authoritative truth : {0}".format(report["authoritative"] or "(none)"))
    print("  delegation walked   : {0}".format(" | ".join(report["chain"]) or "(direct)"))
    latency = report["latency_ms"]
    print("  TTL / auth TTL      : {0} / {1}".format(report["ttl"], report["auth_ttl"]))
    print("  response            : {0}   {1}".format(
        report["rcode"], "{0:.1f} ms".format(latency) if latency else ""))
    print("  stage 1 comparison  : {0}".format(report["stage1"]))
    print("  FINAL VERDICT       : {0}".format(report["verdict"]))
    print("  reason              : {0}".format(report["reason"]))
    print()


def serve_only(args: argparse.Namespace) -> int:
    """Run the poisoned resolver until interrupted, for a live dashboard demo."""
    print("=" * 74)
    print("ARGUS LAB - poisoned resolver running")
    print("=" * 74)
    print("  listening on   : {0}:{1}  (loopback only)".format(LAB_HOST, args.port))
    print("  lying about    : {0}  A  ->  {1}".format(args.domain, args.forged))
    print("  everything else: forwarded honestly to {0}".format(args.honest))
    print()
    print("  In config/resolvers.yaml set  lab-poisoned  to  enabled: true,")
    print("  then in another terminal run:")
    print("      python -m argus run-once      # the sweep will flag it")
    print("      python -m argus dashboard     # see it beside the healthy resolvers")
    print()
    print("  Press Ctrl+C to stop. Remember to set enabled: false afterwards.")
    print("=" * 74)
    sys.stdout.flush()          # visible immediately even when piped to a log

    try:
        with PoisonedResolver(args.domain, args.forged, args.honest,
                              ttl=args.ttl, port=args.port) as server:
            while True:
                threading.Event().wait(1.0)
                if server.lies_told:
                    print("\r  lies told: {0}".format(server.lies_told), end="", flush=True)
    except KeyboardInterrupt:
        print("\n  stopped.")
    except OSError as exc:
        print("Could not bind {0}:{1} - {2}".format(LAB_HOST, args.port, exc))
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Demonstrate an honest resolver against a hijacked one.")
    parser.add_argument("--domain", default="cloudflare.com",
                        help="domain to poison in the lab (default: cloudflare.com)")
    parser.add_argument("--honest", default="1.1.1.1",
                        help="honest resolver for the clean case (default: 1.1.1.1)")
    parser.add_argument("--forged", default=FORGED_DEFAULT,
                        help="address the lab resolver falsely returns")
    parser.add_argument("--ttl", type=int, default=300,
                        help="TTL the lab resolver claims; raise it to also "
                             "demonstrate the TTL-inflation (freshness) check")
    parser.add_argument("--port", type=int, default=LAB_PORT,
                        help="loopback port for the lab resolver (default: 5354)")
    parser.add_argument("--serve", action="store_true",
                        help="just run the poisoned resolver until Ctrl+C, so a "
                             "normal sweep and the live dashboard can monitor it")
    args = parser.parse_args()

    if args.serve:
        return serve_only(args)

    probe = ResolverProbe(timeout=5.0, retries=2)
    verifier = AuthoritativeVerifier(timeout=5.0)
    controls = [
        MonitoredResolver("google", "8.8.8.8", role="control"),
        MonitoredResolver("cloudflare", "1.1.1.1", role="control"),
        MonitoredResolver("quad9", "9.9.9.9", role="control"),
    ]
    anomaly = AnomalyVerifier(probe, verifier, controls=controls, repetitions=2)

    print("=" * 74)
    print("ARGUS - HIJACKED vs NOT HIJACKED")
    print("=" * 74)
    print("  domain under test   : {0}".format(args.domain))
    print("  honest resolver     : {0}".format(args.honest))
    print("  lab resolver        : {0}:{1}  (loopback, under our control)".format(
        LAB_HOST, args.port))
    print("  forged address      : {0}  (RFC 5737 documentation range)".format(args.forged))
    print("  ethics              : the lab resolver answers only this process; no")
    print("                        third-party resolver is poisoned or altered.")
    print("=" * 74)
    print()

    honest = MonitoredResolver("honest-resolver", args.honest, role="isp")
    clean = assess(honest, args.domain, probe, verifier, anomaly)
    show("CASE A - NOT HIJACKED (honest resolver)", clean)

    lab = MonitoredResolver("lab-poisoned", LAB_HOST, role="isp", port=args.port)
    try:
        with PoisonedResolver(args.domain, args.forged, args.honest,
                              ttl=args.ttl, port=args.port) as server:
            poisoned = assess(lab, args.domain, probe, verifier, anomaly)
            lies = server.lies_told
    except OSError as exc:
        print("Could not start the lab resolver on {0}:{1} - {2}".format(
            LAB_HOST, args.port, exc))
        print("Another process may hold that port; retry with --port 5355.")
        return 1

    show("CASE B - HIJACKED (cache-poisoned resolver)", poisoned)

    print("=" * 74)
    print("DIFFERENCE")
    print("=" * 74)
    def row(label: str, left: object, right: object) -> None:
        print("  {0:<20} {1:<26} {2}".format(label, _cell(left), _cell(right)))

    row("", "NOT HIJACKED", "HIJACKED")
    row("returned address", clean["returned"], poisoned["returned"])
    row("matches authority", "yes", "no - never published")
    row("stage 1", clean["stage1"], poisoned["stage1"])
    row("final verdict", clean["verdict"], poisoned["verdict"])
    print()
    print("  The lab resolver told {0} lie(s) during this run.".format(lies))
    print("  Argus reached its verdict only from evidence: the resolver returned an")
    print("  address absent from the authoritative answer, the independent re-walk")
    print("  and the control resolvers disagreed with it, and the result persisted")
    print("  across repeated queries.")
    print()
    print("  Note the wording: the strongest label Argus assigns is POSSIBLE cache")
    print("  poisoning. Even here, where we know the answer was forged because we")
    print("  forged it, the system claims an anomaly - never a proven attack.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
