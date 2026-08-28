#!/usr/bin/env python3
"""Discover and verify the caching resolvers actually reachable from this vantage.

    python scripts/discover_resolvers.py                      # what this machine is using
    python scripts/discover_resolvers.py --isp SLT            # label the findings
    python scripts/discover_resolvers.py 203.115.0.1 1.1.1.1  # also test given addresses
    python scripts/discover_resolvers.py --isp SLT --write    # append the working ones to config

Why this exists
---------------
ISP caching resolvers (SLT, Dialog, Mobitel, Hutch, ...) are not published as a
public list: they are handed to customers over DHCP/PPPoE and usually answer
only from inside that ISP's own network. The honest way to obtain them for a
single-vantage study is therefore to read what this machine was given, probe it,
and record what actually responded -- never to copy an address from a web page.

Every candidate is tested with one ordinary recursive query for a stable domain.
A resolver that answers a name it is not authoritative for is, by definition,
recursing for us -- that is the evidence we record. Nothing here modifies,
floods, or attacks any resolver.

The script is read-only unless --write is given, and --write only APPENDS new
entries (after a .bak backup) -- it never edits or removes an existing one.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from argus.config import load_settings
from argus.probe import ResolverProbe

# A stable, widely-hosted name no resolver is authoritative for. Answering it
# proves recursion; its address set is not used as ground truth here.
TEST_DOMAIN = "cloudflare.com"

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "resolvers.yaml")


# ---------------------------------------------------------------- discovery --

def _run(cmd: list[str]) -> str:
    """Run a helper command, returning '' if it is missing or fails."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return ""
    return out.stdout or ""


def _addresses_in(text: str) -> list[str]:
    """Plausible resolver addresses in a block of command output.

    Discards what these commands print alongside the servers -- link-local
    addresses, subnet masks (which parse as reserved 240.0.0.0/4), multicast
    and unspecified addresses -- so only dialable candidates are probed.
    """
    found = []
    for token in re.findall(r"[0-9a-fA-F:.]{7,}", text):
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            continue
        if (address.is_link_local or address.is_reserved
                or address.is_multicast or address.is_unspecified):
            continue
        found.append(token)
    return found


def system_resolvers() -> list[tuple[str, str]]:
    """Addresses this machine was configured to use, as (address, source)."""
    found: list[tuple[str, str]] = []

    # systemd-resolved knows the real upstreams; /etc/resolv.conf often only
    # shows the 127.0.0.53 stub, so ask resolvectl first.
    text = _run(["resolvectl", "status"]) or _run(["systemd-resolve", "--status"])
    for block in re.findall(r"(?:Current DNS Server|DNS Servers):(.*)", text):
        for addr in _addresses_in(block):
            found.append((addr, "resolvectl"))

    text = _run(["nmcli", "-t", "-f", "IP4.DNS,IP6.DNS", "device", "show"])
    for addr in _addresses_in(text):
        found.append((addr, "nmcli"))

    try:
        with open("/etc/resolv.conf", encoding="utf-8") as handle:
            for line in handle:
                if line.strip().startswith("nameserver"):
                    for addr in _addresses_in(line):
                        found.append((addr, "/etc/resolv.conf"))
    except OSError:
        pass

    if os.name == "nt":                       # developing on Windows
        for addr in _addresses_in(_run(["ipconfig", "/all"])):
            found.append((addr, "ipconfig"))

    # De-duplicate, keeping the first (most authoritative) source per address.
    seen: dict[str, str] = {}
    for addr, source in found:
        seen.setdefault(addr, source)
    return list(seen.items())


# ----------------------------------------------------------------- probing --

def probe(address: str, timeout: float, retries: int) -> dict:
    """One ordinary recursive query. Returns a verdict dict; never raises."""
    answer = ResolverProbe(timeout=timeout, retries=retries).query(address, TEST_DOMAIN, "A")
    usable = answer.ok and answer.rcode == "NOERROR" and bool(answer.records)
    return {
        "address": address,
        "usable": usable,
        "rcode": answer.rcode,
        "latency_ms": answer.latency_ms,
        "records": sorted(answer.records),
        "ad_flag": answer.authenticated,
        "error": answer.error,
    }


def is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


# ------------------------------------------------------------------ output --

def yaml_block(results: list[dict], isp: str, country: str, taken: set[str]) -> str:
    """Render verified resolvers as a resolvers.yaml fragment."""
    base = re.sub(r"[^a-z0-9]+", "-", isp.lower()).strip("-") or "isp"
    lines: list[str] = []
    index = 0
    for result in results:
        index += 1
        name = base if index == 1 else base + "-" + str(index)
        while name in taken:
            index += 1
            name = base + "-" + str(index)
        taken.add(name)
        latency = result["latency_ms"] or 0.0
        lines.append("  - name: " + name)
        lines.append("    address: " + result["address"])
        lines.append("    role: isp")
        lines.append("    isp: " + isp)
        lines.append("    country: " + country)
        lines.append("    enabled: true")
        lines.append("    # verified: {0:.0f} ms, {1}, AD={2}, source={3}".format(
            latency, result["rcode"], result["ad_flag"], result["source"]))
    return "\n".join(lines)


def append_to_config(block: str, path: str) -> str:
    """Append the fragment to resolvers.yaml, after taking a .bak backup."""
    shutil.copyfile(path, path + ".bak")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n  # --- discovered by scripts/discover_resolvers.py ---\n")
        handle.write(block + "\n")
    return path + ".bak"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Discover and verify caching resolvers reachable from this vantage.")
    parser.add_argument("addresses", nargs="*",
                        help="extra resolver addresses to test as well")
    parser.add_argument("--isp", default="unknown",
                        help="label for the discovered resolvers, e.g. SLT")
    parser.add_argument("--country", default="LK", help="country label (default: LK)")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--write", action="store_true",
                        help="append the working resolvers to config/resolvers.yaml")
    args = parser.parse_args()

    settings = load_settings()
    taken = {r.name for r in settings.resolvers}
    configured = {r.address for r in settings.resolvers}

    candidates: list[tuple[str, str]] = [(a, "command line") for a in args.addresses]
    given = {a for a, _ in candidates}
    for address, source in system_resolvers():
        if address not in given:
            candidates.append((address, source))

    if not candidates:
        print("No resolver addresses found. Pass some explicitly, e.g.:")
        print("    python scripts/discover_resolvers.py 8.8.8.8")
        return 1

    print("Testing {0} candidate resolver(s) with one {1} A query each.\n".format(
        len(candidates), TEST_DOMAIN))
    results = []
    for address, source in candidates:
        result = probe(address, args.timeout, args.retries)
        result["source"] = source
        results.append(result)

        if result["usable"]:
            note = "already in config" if address in configured else ""
            print("  [ OK ] {0:<20} {1:>7.1f} ms  {2:<9} AD={3:<5} (from {4}) {5}".format(
                address, result["latency_ms"] or 0.0, result["rcode"],
                str(result["ad_flag"]), source, note))
        else:
            print("  [FAIL] {0:<20} {1:>7}     {2} (from {3})".format(
                address, "", result["error"] or result["rcode"], source))

        if is_loopback(address):
            print("         ^ loopback: a local stub (systemd-resolved), not your "
                  "ISP's resolver.")
            print("           Run 'resolvectl status' and read 'Current DNS Server'.")

    working = [r for r in results if r["usable"] and r["address"] not in configured]
    if not working:
        print("\nNothing new to add: no candidate answered, or all are already in config.")
        return 0

    block = yaml_block(working, args.isp, args.country, taken)
    print("\nAdd this to the `resolvers:` list in config/resolvers.yaml:\n")
    print(block)

    if args.write:
        backup = append_to_config(block, os.path.normpath(CONFIG_PATH))
        print("\nAppended to config/resolvers.yaml (backup: {0}).".format(backup))
        print("Now run 'python -m argus status', then 'python -m argus run-once'.")
    else:
        print("\n(Re-run with --write to append these automatically.)")

    if args.isp == "unknown":
        print("\nTip: pass --isp SLT (or Dialog/Mobitel/Hutch) so the entries are "
              "labelled correctly in your evaluation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
