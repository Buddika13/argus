"""ALERTING — deliver a confirmed detection somewhere a person will see it.

A monitoring system that runs unattended is only useful if a finding reaches
someone. Storing an alert in the database and colouring the dashboard covers the
case where a researcher is already looking; this module covers the case where
nobody is.

Two sinks, both optional and both configured in `config/config.yaml`:

    alerting:
      enabled: true
      log_file: data/alerts.log        # append one line per confirmed event
      webhook_url: ""                  # optional: POST the evidence as JSON

The log file is the default because it needs no credentials, no network and no
account, so it works during a demonstration on a laptop with the network down.
The webhook exists so the integration point is real rather than hypothetical.

Delivery never affects monitoring. Every sink is wrapped: a full disk, a
read-only path, a dead webhook or a DNS failure resolving the webhook host is
logged and then ignored. A sweep must not fail because an alert could not be
delivered -- losing the notification is bad, losing the measurement is worse.

Only confirmed POSSIBLE_CACHE_POISONING events are delivered. Benign
differences and inconclusive anomalies stay in the database; alerting on them
would train the reader to ignore alerts.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger("argus.alerting")

WEBHOOK_TIMEOUT = 5.0


class AlertSink:
    """Delivers confirmed detections to a log file and/or a webhook."""

    def __init__(self, log_file: str | Path | None = None,
                 webhook_url: str = "", enabled: bool = True) -> None:
        self.log_file = Path(log_file) if log_file else None
        self.webhook_url = (webhook_url or "").strip()
        self.enabled = enabled
        self.delivered = 0
        self.failures = 0

    @classmethod
    def from_settings(cls, settings) -> "AlertSink":
        raw = settings.raw.get("alerting", {}) or {}
        path = raw.get("log_file") or ""
        resolved = None
        if path:
            candidate = Path(path)
            resolved = candidate if candidate.is_absolute() else \
                Path(settings.db_path).parent.parent / candidate
        return cls(log_file=resolved,
                   webhook_url=raw.get("webhook_url", ""),
                   enabled=bool(raw.get("enabled", True)))

    # -- formatting --------------------------------------------------------

    @staticmethod
    def summarise(alert, evidence: dict) -> dict:
        """The fields a reader needs to act, drawn from the stored evidence."""
        stage1 = evidence.get("stage1") or {}
        stage2 = evidence.get("stage2_authoritative") or {}
        stage3 = evidence.get("stage3_controls") or {}
        stage5 = evidence.get("stage5_persistence") or {}
        return {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S",
                                  time.localtime(alert.confirmed_at)),
            "status": alert.status,
            "resolver": alert.resolver,
            "domain": alert.domain,
            "rtype": alert.rtype,
            "unpublished": stage1.get("unpublished") or [],
            "authoritative": stage2.get("records") or [],
            "trusted_resolvers_queried": stage3.get("queried") or [],
            "corroborated": bool(stage3.get("corroborates_unexpected")),
            "reproduced": stage5.get("reproduced"),
            "repetitions": stage5.get("repetitions"),
            "reason": evidence.get("decision") or "",
        }

    @staticmethod
    def format_line(summary: dict) -> str:
        return (
            "%s  %s  resolver=%s  domain=%s/%s  returned=%s  authoritative=%s"
            "  trusted_disagreed=%d  persisted=%s/%s  reason=%s" % (
                summary["time"], summary["status"], summary["resolver"],
                summary["domain"], summary["rtype"],
                ",".join(summary["unpublished"]) or "-",
                ",".join(summary["authoritative"]) or "-",
                0 if summary["corroborated"]
                else len(summary["trusted_resolvers_queried"]),
                summary["reproduced"], summary["repetitions"],
                summary["reason"] or "-"))

    # -- delivery ----------------------------------------------------------

    def send(self, alert, evidence: dict) -> bool:
        """Deliver one confirmed detection. Returns True if any sink accepted it."""
        if not self.enabled:
            return False
        summary = self.summarise(alert, evidence)
        delivered = False
        if self._write_log(summary):
            delivered = True
        if self._post_webhook(summary):
            delivered = True
        if delivered:
            self.delivered += 1
        return delivered

    def _write_log(self, summary: dict) -> bool:
        if not self.log_file:
            return False
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_file, "a", encoding="utf-8") as handle:
                handle.write(self.format_line(summary) + "\n")
            return True
        except OSError as exc:                       # full disk, read-only path
            self.failures += 1
            log.warning("could not append to the alert log %s: %s",
                        self.log_file, exc)
            return False

    def _post_webhook(self, summary: dict) -> bool:
        if not self.webhook_url:
            return False
        try:
            # Request() itself raises on a malformed URL, so it is built inside
            # the guard: a typo in webhook_url must not escape this method.
            request = urllib.request.Request(
                self.webhook_url, data=json.dumps(summary).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json",
                         "User-Agent": "argus-dns-monitor"})
            with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT) as response:
                ok = 200 <= response.status < 300
                if not ok:
                    self.failures += 1
                    log.warning("alert webhook returned HTTP %s", response.status)
                return ok
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.failures += 1
            log.warning("alert webhook delivery failed: %s", exc)
            return False
