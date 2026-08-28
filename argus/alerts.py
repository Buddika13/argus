"""ALERT MANAGER — two-level reporting.

Level 1  integrity anomaly       (Tier-1) -> recorded for the dashboard
Level 2  possible cache poisoning (Tier-2) -> emitted to console/log/file,
         carrying the evidence bundle that justified escalation.

Deliberately simple and dependency-free: default sinks are the console log and
the database. The interface allows a future email/webhook sink without Docker or
external services. Argus only observes and reports — it never blocks or responds.

Foundation stub: interface defined; implementation added in a later step.
"""

from __future__ import annotations

from .models import Alert, Anomaly


class AlertManager:
    def record_anomaly(self, anomaly: Anomaly) -> None:
        """Record a Tier-1 integrity anomaly (no poisoning claim)."""
        raise NotImplementedError("AlertManager.record_anomaly is implemented later")

    def raise_alert(self, alert: Alert) -> None:
        """Emit a Tier-2 possible cache-poisoning alert with its evidence."""
        raise NotImplementedError("AlertManager.raise_alert is implemented later")
