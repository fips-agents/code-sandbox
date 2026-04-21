"""OCSF-compatible structured audit logging for security decisions.

Each security layer emits structured JSON events when making access control
decisions.  Events follow the OCSF Security Finding schema (class_uid=2001)
for OpenShift log collection and SIEM integration.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger("sandbox.audit")


class Severity(IntEnum):
    """OCSF severity levels."""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class SecurityEvent:
    """OCSF Security Finding (class_uid=2001)."""

    layer: str  # "ast_scan", "blocklist_audit", "runtime", "landlock", "memory", "timeout"
    action: str  # "violation", "blocked_import", "applied", "timeout_kill", etc.
    message: str  # Human-readable description
    severity: Severity
    mode: str = "enforce"  # "enforce" or "observe"
    details: dict = field(default_factory=dict)

    def to_ocsf(self) -> dict:
        """Serialize to OCSF Security Finding format."""
        return {
            "class_uid": 2001,
            "category_uid": 2,
            "activity_id": 1,
            "severity_id": self.severity.value,
            "status_id": 1 if self.mode == "enforce" else 2,
            "status": "blocked" if self.mode == "enforce" else "observed",
            "time": int(time.time() * 1000),
            "message": self.message,
            "finding_info": {
                "title": f"{self.layer}/{self.action}",
                "desc": self.message,
            },
            "metadata": {
                "product": {"name": "code-sandbox", "vendor_name": "redhat-ai"},
                "version": "1.0.0",
            },
            "unmapped": {
                "sandbox_layer": self.layer,
                "sandbox_action": self.action,
                "sandbox_mode": self.mode,
                **self.details,
            },
        }


def emit(event: SecurityEvent) -> None:
    """Emit a structured audit event as JSON to the audit logger."""
    logger.info(json.dumps(event.to_ocsf(), separators=(",", ":")))
