"""Tests for sandbox.landlock — Landlock LSM filesystem restriction wrapper."""

import os
import sys
from unittest.mock import patch

import pytest

from sandbox.landlock import (
    _ACCESS_NET_BIND_TCP,
    _ACCESS_NET_CONNECT_TCP,
    _READ_ONLY,
    _READ_WRITE,
    _SCOPE_ABSTRACT_UNIX_SOCKET,
    _SCOPE_SIGNAL,
    DEFAULT_READ_ONLY_PATHS,
    DEFAULT_READ_WRITE_PATHS,
    LandlockStatus,
    _attr_size_for_abi,
    _LandlockPathBeneathAttr,
    _LandlockRulesetAttr,
    apply_sandbox_landlock,
)

# ---------------------------------------------------------------------------
# LandlockStatus
# ---------------------------------------------------------------------------


class TestLandlockStatus:
    def test_default_not_applied(self):
        status = LandlockStatus()
        assert status.applied is False
        assert status.abi_version == 0
        assert status.reason == ""
        assert status.rules_applied == []

    def test_applied_status(self):
        status = LandlockStatus(
            applied=True,
            abi_version=5,
            reason="ok",
            rules_applied=["ro:/usr", "rw:/tmp"],
        )
        assert status.applied is True
        assert status.abi_version == 5
        assert len(status.rules_applied) == 2


# ---------------------------------------------------------------------------
# ctypes structures
# ---------------------------------------------------------------------------


class TestStructures:
    def test_ruleset_attr_size(self):
        # struct landlock_ruleset_attr: u64 (fs) + u64 (net) + u64 (scoped) = 24 bytes
        import ctypes

        assert ctypes.sizeof(_LandlockRulesetAttr) == 24

    def test_path_beneath_attr_size(self):
        # struct landlock_path_beneath_attr: u64 + s32 = 12 bytes (packed)
        import ctypes

        assert ctypes.sizeof(_LandlockPathBeneathAttr) == 12

    def test_path_beneath_attr_fields(self):
        attr = _LandlockPathBeneathAttr(allowed_access=_READ_ONLY, parent_fd=3)
        assert attr.allowed_access == _READ_ONLY
        assert attr.parent_fd == 3


# ---------------------------------------------------------------------------
# Access right constants
# ---------------------------------------------------------------------------


class TestAccessConstants:
    def test_read_only_includes_execute(self):
        assert _READ_ONLY & (1 << 0)  # EXECUTE

    def test_read_only_includes_read_file(self):
        assert _READ_ONLY & (1 << 2)  # READ_FILE

    def test_read_only_includes_read_dir(self):
        assert _READ_ONLY & (1 << 3)  # READ_DIR

    def test_read_only_excludes_write(self):
        assert not (_READ_ONLY & (1 << 1))  # WRITE_FILE

    def test_read_write_includes_write(self):
        assert _READ_WRITE & (1 << 1)  # WRITE_FILE

    def test_read_write_includes_read(self):
        assert _READ_WRITE & (1 << 2)  # READ_FILE

    def test_read_write_includes_remove(self):
        assert _READ_WRITE & (1 << 4)  # REMOVE_DIR
        assert _READ_WRITE & (1 << 5)  # REMOVE_FILE

    def test_read_write_includes_create(self):
        assert _READ_WRITE & (1 << 7)  # MAKE_DIR
        assert _READ_WRITE & (1 << 8)  # MAKE_REG


# ---------------------------------------------------------------------------
# Network constants (ABI v4+)
# ---------------------------------------------------------------------------


class TestNetworkConstants:
    def test_net_bind_tcp(self):
        assert _ACCESS_NET_BIND_TCP == 1

    def test_net_connect_tcp(self):
        assert _ACCESS_NET_CONNECT_TCP == 2

    def test_net_constants_are_distinct_bits(self):
        assert _ACCESS_NET_BIND_TCP & _ACCESS_NET_CONNECT_TCP == 0


# ---------------------------------------------------------------------------
# Scope constants (ABI v5+)
# ---------------------------------------------------------------------------


class TestScopeConstants:
    def test_scope_abstract_unix(self):
        assert _SCOPE_ABSTRACT_UNIX_SOCKET == 1

    def test_scope_signal(self):
        assert _SCOPE_SIGNAL == 2

    def test_scope_constants_are_distinct_bits(self):
        assert _SCOPE_ABSTRACT_UNIX_SOCKET & _SCOPE_SIGNAL == 0


# ---------------------------------------------------------------------------
# ABI-based attr size helper
# ---------------------------------------------------------------------------


class TestAttrSizeForAbi:
    def test_abi_v1_size(self):
        assert _attr_size_for_abi(1) == 8

    def test_abi_v2_size(self):
        assert _attr_size_for_abi(2) == 8

    def test_abi_v3_size(self):
        assert _attr_size_for_abi(3) == 8

    def test_abi_v4_size(self):
        assert _attr_size_for_abi(4) == 16

    def test_abi_v5_size(self):
        assert _attr_size_for_abi(5) == 24

    def test_abi_future_size(self):
        # Future ABI versions should still return the largest known size.
        assert _attr_size_for_abi(99) == 24


# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------


class TestDefaultPaths:
    def test_read_only_includes_usr(self):
        assert "/usr" in DEFAULT_READ_ONLY_PATHS

    def test_read_only_includes_etc(self):
        assert "/etc" in DEFAULT_READ_ONLY_PATHS

    def test_read_only_includes_app_root(self):
        assert "/opt/app-root" in DEFAULT_READ_ONLY_PATHS

    def test_read_write_is_tmp_only(self):
        assert DEFAULT_READ_WRITE_PATHS == ["/tmp"]


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    def test_non_linux_returns_not_applied(self):
        """On macOS/Windows, Landlock degrades gracefully."""
        with patch("sandbox.landlock.sys") as mock_sys:
            mock_sys.platform = "darwin"
            status = apply_sandbox_landlock()
            assert status.applied is False
            assert "Not Linux" in status.reason

    def test_custom_paths_accepted(self):
        """Custom path lists are accepted (even if Landlock isn't applied)."""
        with patch("sandbox.landlock.sys") as mock_sys:
            mock_sys.platform = "darwin"
            status = apply_sandbox_landlock(
                read_only_paths=["/custom/ro"],
                read_write_paths=["/custom/rw"],
            )
            assert status.applied is False

    def test_extra_ro_paths_from_env(self):
        """SANDBOX_LANDLOCK_EXTRA_RO is parsed even when Landlock cannot apply."""
        with patch("sandbox.landlock.sys") as mock_sys:
            mock_sys.platform = "darwin"
            with patch.dict(os.environ, {"SANDBOX_LANDLOCK_EXTRA_RO": "/data:/models"}):
                status = apply_sandbox_landlock()
                # Landlock cannot apply on darwin, but the call must not raise.
                assert status.applied is False

    def test_extra_ro_empty_env_is_harmless(self):
        """An empty SANDBOX_LANDLOCK_EXTRA_RO does not alter the path list."""
        with patch("sandbox.landlock.sys") as mock_sys:
            mock_sys.platform = "darwin"
            with patch.dict(os.environ, {"SANDBOX_LANDLOCK_EXTRA_RO": ""}):
                status = apply_sandbox_landlock()
                assert status.applied is False

    @pytest.mark.skipif(
        sys.platform != "linux", reason="Landlock only available on Linux"
    )
    @pytest.mark.skipif(
        os.environ.get("SANDBOX_SKIP_LANDLOCK") == "1",
        reason="Landlock skipped — applying it in a test runner permanently "
        "restricts the process, breaking subsequent tests",
    )
    def test_returns_abi_version_on_linux(self):
        """On Linux, the ABI version is queried (may be 0 if not enabled)."""
        status = apply_sandbox_landlock()
        # Either it applied (abi >= 1) or it didn't (abi == 0 with reason)
        assert isinstance(status.abi_version, int)
        assert status.reason != ""
