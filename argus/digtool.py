"""DIG CAPTURE — the two resolution paths as `dig` prints them.

Argus resolves with dnspython, and that stays the authority: every
classification on every page comes from `probe`, `verifier`, `comparison` and
`verification`, not from anything here. This module runs `dig` alongside them
purely to capture the human-readable evidence a reader can paste into their own
terminal and reproduce, which is what a research write-up needs.

So there are two layers, deliberately:

    verdict     dnspython, unchanged -- what Argus decides
    evidence    dig stdout, captured here -- what a reader can re-run

If `dig` is not installed the evidence is simply absent and says so. Nothing
degrades: the verdict never depended on it.

Safety. The browser never executes anything; this is the only place a DNS
command is built, and it is built from validated parts:

    * the domain must match a conservative hostname grammar
    * the resolver must parse as an IP address (`ipaddress`)
    * the record type must be one of a fixed set
    * no value may begin with "-" or "+", so nothing can become a dig option
    * arguments are passed as a list -- there is no shell, so no quoting,
      globbing, substitution or chaining is possible
    * every run is bounded by a timeout
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import time

# A conservative hostname: letters, digits, hyphens, dots; labels 1-63 long;
# 253 characters overall. Deliberately narrower than the RFC, because this
# string becomes a command argument.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME = re.compile(r"^%s(\.%s)*\.?$" % (_LABEL, _LABEL))

RECORD_TYPES = ("A", "AAAA")
DEFAULT_TIMEOUT = 12.0


class DigUnavailable(RuntimeError):
    """`dig` is not installed on this host."""


class InvalidQuery(ValueError):
    """A domain, resolver or record type that will not be passed to dig."""


def available() -> bool:
    """Whether a dig binary can be found on PATH."""
    return shutil.which("dig") is not None


def clean_domain(domain: str) -> str:
    """Validate a domain, or refuse it."""
    domain = (domain or "").strip().rstrip(".").lower()
    if not domain:
        raise InvalidQuery("No domain was given.")
    if len(domain) > 253:
        raise InvalidQuery("That domain name is too long to be valid.")
    if domain.startswith("-") or domain.startswith("+"):
        raise InvalidQuery("A domain cannot begin with '-' or '+'.")
    if not _HOSTNAME.match(domain):
        raise InvalidQuery(
            "%r is not a valid domain name. Use letters, digits, hyphens and "
            "dots only." % domain[:64])
    return domain


def clean_resolver(address: str) -> str:
    """Validate a resolver address, or refuse it."""
    address = (address or "").strip()
    if not address:
        raise InvalidQuery("No resolver address was given.")
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        raise InvalidQuery(
            "%r is not a valid IP address. Resolvers are addressed by IP, not "
            "by name, so the query cannot be misdirected." % address[:64])


def clean_rtype(rtype: str) -> str:
    rtype = (rtype or "").strip().upper()
    if rtype not in RECORD_TYPES:
        raise InvalidQuery("Record type must be one of: %s."
                           % ", ".join(RECORD_TYPES))
    return rtype


def _run(args: list, timeout: float) -> dict:
    """Run dig with a fixed argument list and capture what it printed.

    The binary is resolved once, and the resolved path is what is executed:
    passing a bare name would let PATH be re-searched between the availability
    check and the run, and would fail outright for a wrapper script.
    """
    binary = shutil.which("dig")
    if binary is None:
        raise DigUnavailable(
            "dig is not installed. On Ubuntu: sudo apt install dnsutils")
    started = time.time()
    try:
        done = subprocess.run([binary] + args, capture_output=True, text=True,
                              timeout=timeout, shell=False)
    except FileNotFoundError:
        raise DigUnavailable(
            "dig is not installed. On Ubuntu: sudo apt install dnsutils")
    except subprocess.TimeoutExpired:
        return {"command": "dig " + " ".join(args), "stdout": "",
                "stderr": "dig did not finish within %.0f seconds." % timeout,
                "returncode": None, "elapsed_ms": timeout * 1000.0,
                "ok": False, "timed_out": True}
    return {
        "command": "dig " + " ".join(args),
        "stdout": done.stdout.strip(),
        "stderr": done.stderr.strip(),
        "returncode": done.returncode,
        "elapsed_ms": (time.time() - started) * 1000.0,
        "ok": done.returncode == 0 and bool(done.stdout.strip()),
        "timed_out": False,
    }


def untrusted(domain: str, resolver_ip: str, rtype: str = "A",
              timeout: float = DEFAULT_TIMEOUT) -> dict:
    """`dig @<resolver> <domain> <type>` -- the monitored cache's own answer."""
    domain = clean_domain(domain)
    resolver_ip = clean_resolver(resolver_ip)
    rtype = clean_rtype(rtype)
    return _run(["@" + resolver_ip, domain, rtype, "+noall", "+answer",
                 "+comments", "+stats"], timeout)


def trusted(domain: str, rtype: str = "A",
            timeout: float = DEFAULT_TIMEOUT) -> dict:
    """`dig +trace <domain> <type>` -- the hierarchy walked from the root."""
    domain = clean_domain(domain)
    rtype = clean_rtype(rtype)
    # +trace is slower than an ordinary query: it asks the root, a TLD server
    # and the zone's own nameservers in turn.
    return _run(["+trace", domain, rtype], max(timeout, 20.0))


# -- parsing ----------------------------------------------------------------

_ANSWER = re.compile(
    r"^(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+(?P<type>A|AAAA)\s+(?P<value>\S+)\s*$",
    re.MULTILINE)
_STATUS = re.compile(r"status:\s*([A-Z]+)")
_QUERY_TIME = re.compile(r"Query time:\s*(\d+)\s*msec")


def parse(output: str, rtype: str = "A") -> dict:
    """Pull the answer records, TTL and status out of dig's output.

    Used to show what was extracted beside the raw text, and to check the
    captured evidence against what dnspython measured. It never replaces the
    engine's own parsing.
    """
    records, ttls = [], []
    for match in _ANSWER.finditer(output or ""):
        if match.group("type") != rtype:
            continue
        value = match.group("value")
        if value not in records:
            records.append(value)
        ttls.append(int(match.group("ttl")))
    status = _STATUS.search(output or "")
    query_time = _QUERY_TIME.search(output or "")
    return {
        "records": records,
        "ttl": min(ttls) if ttls else None,
        "status": status.group(1) if status else "",
        "query_time_ms": int(query_time.group(1)) if query_time else None,
    }


def capture(domain: str, resolver_ip: str, rtype: str = "A",
            timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Both paths, with their parsed answers. Never raises for a DNS failure.

    A refused query (bad domain, bad address) raises; a query that ran and
    failed is reported, because "SERVFAIL" and "the resolver timed out" are
    results a reader needs to see rather than errors to swallow.
    """
    if not available():
        return {"available": False,
                "reason": "dig is not installed on this host. On Ubuntu: "
                          "sudo apt install dnsutils"}
    left = untrusted(domain, resolver_ip, rtype, timeout)
    right = trusted(domain, rtype, timeout)
    left["parsed"] = parse(left["stdout"], rtype)
    right["parsed"] = parse(right["stdout"], rtype)
    return {"available": True, "untrusted": left, "trusted": right}
