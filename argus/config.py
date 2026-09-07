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

    watchlist = load_watchlist_with_categories(cfg / "watchlist.txt")
    return Settings(
        raw=raw,
        resolvers=load_resolvers(cfg / "resolvers.yaml"),
        watchlist=[name for name, _category in watchlist],
        categories={name: category for name, category in watchlist if category},
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
            map_x=_coord(entry.get("map_x")),
            map_y=_coord(entry.get("map_y")),
        ))
    return out


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
