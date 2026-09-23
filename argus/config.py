"""Configuration loader.

Reads three files from the project's `config/` directory:

    config.yaml      runtime parameters (intervals, timeouts, thresholds)
    resolvers.yaml   the monitored resolvers + controls
    watchlist.txt    the domains to monitor

Sensible defaults live here, so Argus runs even if config.yaml is absent.
No Docker, no external services — just local files.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import MonitoredResolver

# Project root = the directory that contains this package and the config/ folder.
ROOT = Path(__file__).resolve().parent.parent

DEFAULTS: dict[str, Any] = {
    "vantage": "local",
    "schedule": {"interval_seconds": 900, "per_resolver_delay": 0.25},
    "query": {"timeout_seconds": 5.0, "retries": 2, "rtypes": ["A", "AAAA"]},
    "verification": {
        "requery": True,          # re-query the resolver
        "rewalk": True,           # re-walk the hierarchy
        "control_crosscheck": True,  # compare against control resolvers
        "persistence": 2,         # sweeps an anomaly must persist to confirm
    },
    "freshness": {"max_ttl_ratio": 1.05},
    "dnssec": {"enabled": True},
    # Signal modules (docs/METHODOLOGY.md §7). The TTL module is always on: it
    # re-reads measurements already taken and costs no queries. The rest send
    # their own probes, so they run ONLY when a divergence needs explaining —
    # we are a guest on someone else's resolver (§15), and a module that fires
    # on every clean answer would multiply the query load for nothing.
    "modules": {
        "enabled": True,
        "ecs": {"enabled": True, "subnets": []},
        "bailiwick": {"enabled": True},
        "snoop": {"enabled": True},
    },
    # Where a confirmed detection is delivered, beyond the database.
    "alerting": {"enabled": True, "log_file": "data/alerts.log",
                 "webhook_url": ""},   # inspect DNSSEC posture/signedness during sweeps
    "storage": {"path": "data/argus.sqlite3"},
    "dashboard": {"path": "report.html"},
    "logging": {"level": "INFO"},
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


@dataclass
class Settings:
    """Fully resolved runtime configuration."""

    raw: dict[str, Any]
    resolvers: list[MonitoredResolver] = field(default_factory=list)
    watchlist: list[str] = field(default_factory=list)
    # domain -> the watch-list section it was listed under.
    categories: dict[str, str] = field(default_factory=dict)
    # The stable, comparable core (methodology §5.2). Empty when the watch-list
    # came from the legacy flat file, which has no way to express it.
    core_domains: set[str] = field(default_factory=set)
    # domain -> "signed" | "unsigned" | "unknown". A watch-list DESIGN hint
    # only, recording that the list deliberately spans both DNSSEC postures.
    # Never an input to a verdict: argus/dnssec.py measures signedness at run
    # time and the measured value is what is stored and reported.
    dnssec_expected: dict[str, str] = field(default_factory=dict)

    @property
    def vantage(self) -> str:
        return os.environ.get("ARGUS_VANTAGE") or self.raw["vantage"]

    @property
    def schedule(self) -> dict:
        return self.raw["schedule"]

    @property
    def query(self) -> dict:
        return self.raw["query"]

    @property
    def verification(self) -> dict:
        return self.raw["verification"]

    @property
    def freshness(self) -> dict:
        return self.raw["freshness"]

    @property
    def enabled_resolvers(self) -> list[MonitoredResolver]:
        return [r for r in self.resolvers if r.enabled]

    @property
    def db_path(self) -> Path:
        return _resolve(self.raw["storage"]["path"])

    @property
    def dashboard_path(self) -> Path:
        return _resolve(self.raw["dashboard"]["path"])


def _resolve(value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else ROOT / p


def load_settings(config_dir: Path | None = None) -> Settings:
    """Load config.yaml, resolvers.yaml and watchlist.txt into a Settings."""
    cfg = config_dir or (ROOT / "config")

    raw = DEFAULTS
    config_file = cfg / "config.yaml"
    if config_file.exists():
        loaded = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
        raw = _deep_merge(DEFAULTS, loaded)

    # The watch-list. config/domains.yaml (methodology §5.2, tagged by category
    # and marking the comparable core) is preferred; the older flat
    # config/watchlist.txt remains a fallback so an existing checkout without
    # the YAML file keeps working unchanged.
    domains_file = cfg / "domains.yaml"
    core: set[str] = set()
    expected: dict[str, str] = {}
    if domains_file.exists():
        watchlist, core, expected = load_domains(domains_file)
    else:
        watchlist = load_watchlist_with_categories(cfg / "watchlist.txt")
    # The monitoring interval can be overridden from the environment without
    # editing any file: ARGUS_INTERVAL_SECONDS (or MONITOR_INTERVAL_SECONDS) in
    # seconds, floored at 10 so a typo cannot melt the resolvers.
    env_interval = (os.environ.get("ARGUS_INTERVAL_SECONDS")
                    or os.environ.get("MONITOR_INTERVAL_SECONDS"))
    if env_interval:
        try:
            raw["schedule"]["interval_seconds"] = max(10, int(env_interval))
        except (TypeError, ValueError):
            pass

    return Settings(
        raw=raw,
        resolvers=load_resolvers(cfg / "resolvers.yaml"),
        watchlist=[name for name, _category in watchlist],
        categories={name: category for name, category in watchlist if category},
        core_domains=core,
        dnssec_expected=expected,
    )


def _coord(value):
    """A map coordinate as a percentage, or None if absent or out of range."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if 0.0 <= number <= 100.0 else None


def load_resolvers(path: Path) -> list[MonitoredResolver]:
    if not path.exists():
        return []
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = []
    for entry in doc.get("resolvers", []):
        out.append(MonitoredResolver(
            name=entry["name"],
            address=entry["address"],
            role=entry.get("role", "isp"),
            isp=entry.get("isp", "unknown"),
            country=entry.get("country", "unknown"),
            port=int(entry.get("port", 53)),
            enabled=bool(entry.get("enabled", True)),
            verified=bool(entry.get("verified", False)),
            map_x=_coord(entry.get("map_x")),
            map_y=_coord(entry.get("map_y")),
        ))
    return out


def load_domains(path: Path) -> tuple[list[tuple[str, str]], set[str], dict[str, str]]:
    """Read config/domains.yaml (methodology §5.2).

    Returns `(pairs, core, expected)` where `pairs` is the watch-list as
    (domain, category) tuples in file order, `core` is the set of domains tagged
    `core: true` -- the small, stable, comparable spine the methodology asks for
    -- and `expected` maps each domain to its `dnssec_expected` hint.

    The `excluded:` section is deliberately NOT returned. It is documentation of
    what was removed and why (methodology §9 and §16); ARGUS never measures it.
    """
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    seen: set[str] = set()
    pairs: list[tuple[str, str]] = []
    core: set[str] = set()
    expected: dict[str, str] = {}

    for entry in doc.get("domains") or []:
        # Accept a bare string as well as a mapping, so a hand-edited list of
        # plain names still loads.
        if isinstance(entry, str):
            entry = {"name": entry}
        name = str(entry.get("name", "")).strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        pairs.append((name, _category_of(str(entry.get("category", "")))))
        if entry.get("core"):
            core.add(name)
        expected[name] = str(entry.get("dnssec_expected", "unknown")).strip().lower()

    return pairs, core, expected


# "# --- Sri Lanka: banking and financial ----" -> "Banking and financial"
_SECTION = re.compile(r"^#\s*-{2,}\s*(.+?)\s*-{2,}\s*$")


def _category_of(header: str) -> str:
    """Turn a watch-list section header into a category label."""
    label = header.split(":", 1)[-1].strip() if ":" in header else header.strip()
    return label[:1].upper() + label[1:] if label else ""


def load_watchlist_with_categories(path: Path) -> list[tuple[str, str]]:
    """The watch-list as (domain, category) pairs.

    The file already groups domains under commented section headers -- banking,
    government, utilities, telecommunications, education, TLD breadth -- so the
    category is read from the file the operator already maintains rather than
    stored separately and left to drift.
    """
    if not path.exists():
        return []
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    category = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        header = _SECTION.match(stripped)
        if header:
            category = _category_of(header.group(1))
            continue
        entry = line.split("#", 1)[0].strip().lower()
        if entry and entry not in seen:
            seen.add(entry)
            out.append((entry, category))
    return out


def load_watchlist(path: Path) -> list[str]:
    return [name for name, _category in load_watchlist_with_categories(path)]
