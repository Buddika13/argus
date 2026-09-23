"""SIGNAL MODULES — docs/METHODOLOGY.md §7.

Each module probes one narrow property of a resolver's behaviour and returns a
`ModuleResult`. Modules are chosen for their *false-positive properties*: the
point of this package is not to detect more, it is to explain more, so that the
verdict engine can tell a geographic difference from a structural one.

Three rules hold for every module in here:

1. **A module never assigns a tier and never decides anything.** It reports what
   it observed. Weighing those observations is `argus/verdict.py`'s job (§8),
   which keeps every escalation traceable to a named module output.
2. **A module never raises.** Network failure is a legitimate observation and is
   reported as `ModuleStatus.UNAVAILABLE`, so one unreachable resolver degrades
   a single signal rather than stopping a sweep.
3. **A module only issues ordinary DNS queries** (§15). Nothing here attacks,
   floods, or attempts to alter any resolver.

The modules, and what each is good for:

    ttl         TTL plausibility and countdown behaviour  (freshness, §6)
    bailiwick   out-of-bailiwick records in the resolver's Additional section
                — a *positive structural* signal (§9 stage 4)
    consensus   cross-resolver agreement; isolates a deviation to one resolver
    ecs         EDNS Client Subnet — separates GeoDNS from tampering (§9 stage 1)
    snoop       RD=0 cache inspection; observes cache state without forcing
                recursion
"""

from __future__ import annotations

from .bailiwick import check_bailiwick
from .consensus import check_consensus
from .ecs import check_ecs
from .snoop import check_cache_state
from .ttl import check_ttl

__all__ = [
    "check_bailiwick",
    "check_consensus",
    "check_ecs",
    "check_cache_state",
    "check_ttl",
]
