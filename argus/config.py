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

    return Settings(
        raw=raw,
        resolvers=load_resolvers(cfg / "resolvers.yaml"),
        watchlist=load_watchlist(cfg / "watchlist.txt"),
    )


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
        ))
    return out


def load_watchlist(path: Path) -> list[str]:
    if not path.exists():
        return []
    seen: set[str] = set()
    domains: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.split("#", 1)[0].strip().lower()
        if entry and entry not in seen:
            seen.add(entry)
            domains.append(entry)
    return domains
