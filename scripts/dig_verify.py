#!/usr/bin/env python3
"""Trusted vs untrusted answer, obtained with dig, side by side.

    python scripts/dig_verify.py peoplesbank.lk
    python scripts/dig_verify.py peoplesbank.lk 1.1.1.1
    python scripts/dig_verify.py cloudflare.com 127.0.0.1 --port 5354 --repeat 3
    python scripts/dig_verify.py gov.lk 8.8.8.8 --type AAAA

Two commands, one comparison:

    UNTRUSTED   dig +short @<resolver> <domain> <type>      what the cache says
    TRUSTED     dig +trace <domain> <type>                  walked from the root

Both commands are printed before they run, so anyone watching can copy them and
reproduce the result independently. That is the point of this script: it makes
the mechanism visible and checkable with a standard tool.

Scope
-----
This is a demonstration and cross-checking tool. The monitoring engine does NOT
use dig -- it resolves directly with dnspython, which is what lets it compare
answer sets programmatically and keep the trusted path free of any cache. Note
that `dig +trace` asks your own system resolver for nameserver addresses when
glue is missing, so its ground truth is very slightly weaker than the engine's
own walk. Where the two disagree, the engine is the authority; --no-engine turns
the comparison off.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

NO_POISONING = "NO_POISONING_DETECTED"
POSSIBLE = "POSSIBLE_CACHE_POISONING"
INCONCLUSIVE = "INCONCLUSIVE"

_RECORD = re.compile(r"^(\S+)\s+\d+\s+IN\s+(A|AAAA)\s+(\S+)\s*$")
_NS = re.compile(r"^(\S+)\s+\d+\s+IN\s+NS\s+\S+\s*$")
_FROM = re.compile(r"^;;\s+Received\s+\d+\s+bytes\s+from\s+(\S+?)#\d+\((\S+?)\)")


# -- parsing (pure functions, unit-tested in tests/test_dig_verify.py) -------

def parse_short(output: str) -> set:
    """Addresses from `dig +short`. CNAME lines and blanks are skipped."""
    found = set()
    for line in output.splitlines():
        line = line.strip()
        if not line or line.endswith("."):        # a CNAME target, not an address
            continue
        if re.match(r"^[0-9a-fA-F:.]+$", line):
            found.add(line)
    return found


def parse_trace(output: str, domain: str, rtype: str) -> dict:
    """Final answer, delegation chain and servers asked, from `dig +trace`."""
    want = domain.rstrip(".").lower() + "."
    answers, zones, servers = set(), [], []

    for line in output.splitlines():
        record = _RECORD.match(line)
        if record and record.group(1).lower() == want \
                and record.group(2) == rtype.upper():
            answers.add(record.group(3))
            continue
        ns = _NS.match(line)
        if ns:
            zone = ns.group(1).lower()
            if zone not in zones:
                zones.append(zone)
            continue
        origin = _FROM.match(line)
        if origin:
            servers.append(origin.group(2).rstrip("."))

    chain = []
    for i in range(len(zones) - 1):
        chain.append(zones[i] + " -> " + zones[i + 1])
    return {"answers": answers, "zones": zones, "chain": chain, "servers": servers}


def classify(monitored: set, trusted: set, monitored_ok: bool, trusted_ok: bool,
             repeats_total: int = 1, repeats_suspicious: int = 1) -> tuple:
    """The three research verdicts, from the evidence actually gathered."""
    if not monitored_ok or not trusted_ok:
        return INCONCLUSIVE, ("one side could not be measured, so no judgement "
                              "is made")
    if not trusted:
        return INCONCLUSIVE, ("the authoritative walk returned no records of this "
                              "type, so there is nothing to compare against")
    if monitored == trusted:
        return NO_POISONING, "the resolver's answer set matches the authoritative set"

    unpublished = monitored - trusted
    if not unpublished:
        return NO_POISONING, ("the resolver returned a subset of the authoritative "
                              "addresses, which is ordinary load balancing")
    if repeats_total > 1 and repeats_suspicious < repeats_total:
        return INCONCLUSIVE, ("the unexpected answer appeared in only %d of %d "
                              "checks, so it looks transient rather than injected"
                              % (repeats_suspicious, repeats_total))
    return POSSIBLE, ("the resolver returned %s, which the authoritative servers "
                      "never published" % ", ".join(sorted(unpublished)))


# -- running dig ------------------------------------------------------------

def run(cmd: list) -> tuple:
    """Run a command, returning (ok, output). Never raises."""
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return False, "dig is not installed. Install it with: sudo apt install -y dnsutils"
    except subprocess.SubprocessError as exc:
        return False, "dig failed: %s" % exc
    if done.returncode != 0:
        return False, (done.stderr or done.stdout or "dig exited with an error").strip()
    return True, done.stdout


def show(cmd: list) -> None:
    print("  $ " + " ".join(cmd))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare the untrusted (cache) and trusted (root walk) "
                    "answers using dig.")
    parser.add_argument("domain", help="domain to look up, e.g. peoplesbank.lk")
    parser.add_argument("resolver", nargs="?", default="1.1.1.1",
                        help="resolver to test (default: 1.1.1.1)")
    parser.add_argument("--type", default="A", choices=["A", "AAAA"],
                        help="record type (default: A)")
    parser.add_argument("--port", type=int, default=53,
                        help="resolver port, e.g. 5354 for the lab resolver")
    parser.add_argument("--repeat", type=int, default=1,
                        help="query the resolver this many times to test persistence")
    parser.add_argument("--no-engine", action="store_true",
                        help="skip the cross-check against the Argus engine")
    args = parser.parse_args()

    if shutil.which("dig") is None:
        print("dig is not installed. Install it with:")
        print("    sudo apt install -y dnsutils")
        return 1

    domain, rtype = args.domain.rstrip("."), args.type.upper()
    port = ["-p", str(args.port)] if args.port != 53 else []

    print("=" * 74)
    print("TRUSTED vs UNTRUSTED  --  %s %s" % (domain, rtype))
    print("=" * 74)

    # 1. Untrusted path -----------------------------------------------------
    print("\nUNTRUSTED PATH  (what the caching resolver says)")
    cmd = ["dig", "+short", "@" + args.resolver] + port + [domain, rtype]
    show(cmd)
    ok_direct, out = run(cmd)
    monitored = parse_short(out) if ok_direct else set()
    if ok_direct:
        for address in sorted(monitored) or ["(no records)"]:
            print("  " + address)
    else:
        print("  FAILED: " + out.strip()[:200])

    # 2. Trusted path -------------------------------------------------------
    print("\nTRUSTED PATH  (walked from the root servers)")
    trace_cmd = ["dig", "+trace", domain, rtype]
    show(trace_cmd)
    ok_trace, trace_out = run(trace_cmd)
    trusted, chain, servers = set(), [], []
    if ok_trace:
        parsed = parse_trace(trace_out, domain, rtype)
        trusted, chain, servers = parsed["answers"], parsed["chain"], parsed["servers"]
        print("  delegation : " + (" | ".join(chain) or "(direct)"))
        print("  answered by: " + (", ".join(servers[-1:]) or "?"))
        for address in sorted(trusted) or ["(no records)"]:
            print("  " + address)
    else:
        print("  FAILED: " + trace_out.strip()[:200])

    # 3. Persistence --------------------------------------------------------
    suspicious = 1 if (monitored - trusted) else 0
    total = 1
    if args.repeat > 1 and ok_direct:
        print("\nREPEATED CHECKS  (does the answer persist?)")
        show(["dig", "+short", "@" + args.resolver] + port + [domain, rtype])
        print("  run %d times" % args.repeat)
        suspicious, total = 0, args.repeat
        for i in range(args.repeat):
            ok_i, out_i = run(["dig", "+short", "@" + args.resolver] + port
                              + [domain, rtype])
            answer = parse_short(out_i) if ok_i else set()
            odd = bool(answer - trusted)
            suspicious += 1 if odd else 0
            print("    %d) %-46s %s" % (i + 1, ", ".join(sorted(answer)) or "(none)",
                                        "unexpected" if odd else "as published"))
        print("  %d of %d checks returned the unexpected answer" % (suspicious, total))

    # 4. Comparison and verdict --------------------------------------------
    print("\nCOMPARISON")
    print("  monitored     : " + (", ".join(sorted(monitored)) or "(none)"))
    print("  authoritative : " + (", ".join(sorted(trusted)) or "(none)"))
    print("  matched       : " + (", ".join(sorted(monitored & trusted)) or "(none)"))
    print("  unpublished   : " + (", ".join(sorted(monitored - trusted)) or "(none)"))
    print("  missing       : " + (", ".join(sorted(trusted - monitored)) or "(none)"))

    result, reason = classify(monitored, trusted, ok_direct, ok_trace, total, suspicious)
    print("\nVERDICT : " + result)
    print("REASON  : " + reason)
    if result == POSSIBLE:
        print("\n  'Possible' is the strongest claim available here. Proving poisoning")
        print("  would need the resolver's own cache contents or capture of the")
        print("  injection, which an outside observer cannot obtain.")

    # 5. Cross-check against the engine ------------------------------------
    if not args.no_engine:
        print("\nCROSS-CHECK  (the Argus engine, resolving with dnspython)")
        try:
            from argus.comparison import compare
            from argus.models import MonitoredResolver
            from argus.probe import ResolverProbe
            from argus.verifier import AuthoritativeVerifier

            target = MonitoredResolver("under-test", args.resolver, port=args.port)
            direct = ResolverProbe(timeout=5.0, retries=1).query(target, domain, rtype)
            truth = AuthoritativeVerifier(timeout=5.0).resolve(domain, rtype)
            engine = compare(direct, truth)
            print("  engine answer set : " + (", ".join(sorted(direct.records)) or "(none)"))
            print("  engine ground truth: " + (", ".join(sorted(truth.records)) or "(none)"))
            print("  engine stage-1     : " + engine.classification.value)
            agrees = (direct.records == monitored) and (truth.records == trusted)
            print("  agrees with dig    : " + ("yes" if agrees else
                                               "no - see the note below"))
            if not agrees:
                print("    dig and the engine measured different sets. This is usually")
                print("    CDN rotation between the two runs, or +trace resolving glue")
                print("    through your system resolver. The engine is the authority.")
        except Exception as exc:                       # noqa: BLE001
            print("  cross-check unavailable: %s" % exc)

    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
