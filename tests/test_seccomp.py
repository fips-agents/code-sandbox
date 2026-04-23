"""Tests for sandbox.seccomp -- subprocess seccomp BPF preamble."""

import ast

from sandbox.seccomp import (
    AUDIT_ARCH_AARCH64,
    AUDIT_ARCH_X86_64,
    BLOCKED_SYSCALLS_AARCH64,
    BLOCKED_SYSCALLS_X86_64,
    PR_SET_SECCOMP,
    SECCOMP_MODE_FILTER,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO_EPERM,
    SECCOMP_RET_KILL_PROCESS,
    build_seccomp_preamble,
)


class TestSeccompConstants:
    def test_audit_arch_x86_64(self):
        assert AUDIT_ARCH_X86_64 == 0xC000003E

    def test_audit_arch_aarch64(self):
        assert AUDIT_ARCH_AARCH64 == 0xC00000B7

    def test_blocked_syscalls_x86_64_has_socket(self):
        assert BLOCKED_SYSCALLS_X86_64["socket"] == 41

    def test_blocked_syscalls_x86_64_has_io_uring(self):
        assert BLOCKED_SYSCALLS_X86_64["io_uring_setup"] == 425

    def test_blocked_syscalls_aarch64_has_socket(self):
        assert BLOCKED_SYSCALLS_AARCH64["socket"] == 198

    def test_blocked_syscalls_aarch64_has_io_uring(self):
        assert BLOCKED_SYSCALLS_AARCH64["io_uring_setup"] == 425

    def test_prctl_constants(self):
        assert PR_SET_SECCOMP == 22
        assert SECCOMP_MODE_FILTER == 2

    def test_seccomp_ret_values(self):
        assert SECCOMP_RET_ALLOW == 0x7FFF0000
        assert SECCOMP_RET_ERRNO_EPERM == 0x00050001
        assert SECCOMP_RET_KILL_PROCESS == 0x80000000

    def test_x86_64_covers_all_socket_syscalls(self):
        """All networking syscalls must be in the blocked list."""
        expected = {
            "socket", "connect", "accept", "sendto", "recvfrom",
            "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
            "shutdown", "bind", "listen",
            "getsockname", "getpeername", "socketpair",
            "setsockopt", "getsockopt", "accept4",
        }
        assert expected.issubset(BLOCKED_SYSCALLS_X86_64.keys())

    def test_io_uring_blocked_on_both_architectures(self):
        for table in (BLOCKED_SYSCALLS_X86_64, BLOCKED_SYSCALLS_AARCH64):
            assert "io_uring_setup" in table
            assert "io_uring_enter" in table
            assert "io_uring_register" in table


class TestSeccompPreamble:
    def test_preamble_is_valid_python(self):
        preamble = build_seccomp_preamble()
        ast.parse(preamble)  # must not raise

    def test_preamble_checks_platform(self):
        preamble = build_seccomp_preamble()
        assert "'linux'" in preamble

    def test_preamble_wraps_in_function(self):
        preamble = build_seccomp_preamble()
        assert "def __seccomp_restrict__" in preamble

    def test_preamble_deletes_function(self):
        preamble = build_seccomp_preamble()
        assert "del __seccomp_restrict__" in preamble

    def test_preamble_has_graceful_degradation(self):
        preamble = build_seccomp_preamble()
        assert "except Exception" in preamble

    def test_preamble_uses_prctl(self):
        preamble = build_seccomp_preamble()
        assert "prctl" in preamble

    def test_preamble_handles_x86_64(self):
        preamble = build_seccomp_preamble()
        assert "x86_64" in preamble

    def test_preamble_handles_aarch64(self):
        preamble = build_seccomp_preamble()
        assert "aarch64" in preamble

    def test_preamble_blocks_socket_syscall_numbers(self):
        """The preamble must contain the socket syscall numbers for blocking."""
        preamble = build_seccomp_preamble()
        # x86_64 socket=41 must appear in the blocked list
        assert "41" in preamble
        # aarch64 socket=198 must appear
        assert "198" in preamble

    def test_preamble_blocks_io_uring_numbers(self):
        preamble = build_seccomp_preamble()
        assert "425" in preamble  # io_uring_setup
