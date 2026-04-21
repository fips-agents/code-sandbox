"""Tests for sandbox.audit -- structured audit logging."""

import json

from sandbox.audit import SecurityEvent, Severity, emit


class TestSecurityEvent:
    def test_to_ocsf_class_uid(self):
        event = SecurityEvent(
            layer="ast_scan",
            action="violation",
            message="blocked import os",
            severity=Severity.HIGH,
        )
        ocsf = event.to_ocsf()
        assert ocsf["class_uid"] == 2001
        assert ocsf["category_uid"] == 2

    def test_enforce_status(self):
        event = SecurityEvent(
            layer="ast_scan",
            action="violation",
            message="test",
            severity=Severity.HIGH,
            mode="enforce",
        )
        ocsf = event.to_ocsf()
        assert ocsf["status_id"] == 1
        assert ocsf["status"] == "blocked"

    def test_observe_status(self):
        event = SecurityEvent(
            layer="ast_scan",
            action="violation",
            message="test",
            severity=Severity.HIGH,
            mode="observe",
        )
        ocsf = event.to_ocsf()
        assert ocsf["status_id"] == 2
        assert ocsf["status"] == "observed"

    def test_finding_info_title(self):
        event = SecurityEvent(
            layer="runtime",
            action="blocked_import",
            message="blocked os",
            severity=Severity.CRITICAL,
        )
        ocsf = event.to_ocsf()
        assert ocsf["finding_info"]["title"] == "runtime/blocked_import"

    def test_details_in_unmapped(self):
        event = SecurityEvent(
            layer="memory",
            action="oom_kill",
            message="OOM",
            severity=Severity.MEDIUM,
            details={"memory_limit_mb": 200},
        )
        ocsf = event.to_ocsf()
        assert ocsf["unmapped"]["memory_limit_mb"] == 200
        assert ocsf["unmapped"]["sandbox_layer"] == "memory"

    def test_time_is_milliseconds(self):
        event = SecurityEvent(
            layer="test",
            action="test",
            message="test",
            severity=Severity.INFO,
        )
        ocsf = event.to_ocsf()
        # Timestamp should be in milliseconds (13+ digits)
        assert ocsf["time"] > 1_000_000_000_000

    def test_metadata_product(self):
        event = SecurityEvent(
            layer="test",
            action="test",
            message="test",
            severity=Severity.INFO,
        )
        ocsf = event.to_ocsf()
        assert ocsf["metadata"]["product"]["name"] == "code-sandbox"


class TestEmit:
    def test_emit_logs_json(self):
        """emit() writes valid JSON to the audit logger."""
        import io
        import logging

        audit_logger = logging.getLogger("sandbox.audit")
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(logging.Formatter("%(message)s"))
        handler.setLevel(logging.INFO)
        audit_logger.addHandler(handler)
        old_level = audit_logger.level
        audit_logger.setLevel(logging.INFO)
        try:
            emit(SecurityEvent(
                layer="test",
                action="test",
                message="hello",
                severity=Severity.INFO,
            ))
            output = buf.getvalue().strip()
            data = json.loads(output)
            assert data["class_uid"] == 2001
            assert data["message"] == "hello"
        finally:
            audit_logger.removeHandler(handler)
            audit_logger.setLevel(old_level)


class TestAuditConfig:
    def test_default_mode_is_enforce(self):
        from sandbox.profiles import AuditConfig

        config = AuditConfig()
        assert config.get_mode("ast_scan") == "enforce"
        assert config.get_mode("anything") == "enforce"

    def test_custom_mode(self):
        from sandbox.profiles import AuditConfig

        config = AuditConfig(mode={"ast_scan": "observe"})
        assert config.get_mode("ast_scan") == "observe"
        assert config.get_mode("blocklist_audit") == "enforce"
