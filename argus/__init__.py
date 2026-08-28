"""Argus — a National DNS Caching-Server Health and Cache-Poisoning Monitoring System.

Argus continuously monitors selected DNS caching/recursive resolvers. For each
monitored resolver it (1) records the resolver's answer, and (2) independently
verifies that answer by walking the DNS hierarchy (Root -> TLD -> Authoritative).
It compares the two, monitors resolver health, and — crucially — treats a
mismatch as a *DNS integrity anomaly* that must be independently re-verified
before any *possible cache-poisoning* alert is raised.

One module per component: config, models, probe, verifier, comparison,
integrity, verification, dnssec, scheduler, storage, dashboard.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
