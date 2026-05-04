"""Subprocess seccomp BPF preamble for kernel-level syscall filtering.

Builds a Python code string that, when executed inside the subprocess,
installs a seccomp BPF filter blocking all networking syscalls (socket,
connect, bind, sendto, etc.), io_uring, and splice.  This closes the
UDP gap that Landlock v4 does not cover, prevents io_uring-based
bypasses, and removes the splice() system call used by the Copy Fail
exploit chain (CVE-2026-31431, Red Hat Security Bulletin RHSB-2026-02).
Blocking socket() also denies AF_ALG socket creation, which is the
entry point of that exploit's algif_aead crypto interface attack.

The filter uses SECCOMP_RET_ERRNO (EPERM) for blocked syscalls so the
subprocess receives a clean error rather than being killed outright.
Wrong-architecture processes are killed immediately.

Usage::

    from sandbox.seccomp import build_seccomp_preamble

    preamble_code = build_seccomp_preamble()
    # Inject into subprocess source before the import hook.
"""

# -- Exported constants (used by tests for validation) --

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

BLOCKED_SYSCALLS_X86_64 = {
    "socket": 41,
    "connect": 42,
    "accept": 43,
    "sendto": 44,
    "recvfrom": 45,
    "sendmsg": 46,
    "recvmsg": 47,
    "shutdown": 48,
    "bind": 49,
    "listen": 50,
    "getsockname": 51,
    "getpeername": 52,
    "socketpair": 53,
    "setsockopt": 54,
    "getsockopt": 55,
    "accept4": 288,
    "sendmmsg": 307,
    "recvmmsg": 299,
    "io_uring_setup": 425,
    "io_uring_enter": 426,
    "io_uring_register": 427,
    # splice() is the kernel primitive used in Phase 3 of the Copy Fail
    # privilege-escalation chain (CVE-2026-31431) to map page-cache pages
    # into an AF_ALG crypto socket.  User code never legitimately needs
    # splice; deny it.
    "splice": 275,
}

BLOCKED_SYSCALLS_AARCH64 = {
    "socket": 198,
    "socketpair": 199,
    "bind": 200,
    "listen": 201,
    "accept": 202,
    "connect": 203,
    "getsockname": 204,
    "getpeername": 205,
    "sendto": 206,
    "recvfrom": 207,
    "setsockopt": 208,
    "getsockopt": 209,
    "shutdown": 210,
    "sendmsg": 211,
    "recvmsg": 212,
    "accept4": 242,
    "sendmmsg": 269,
    "recvmmsg": 243,
    "io_uring_setup": 425,
    "io_uring_enter": 426,
    "io_uring_register": 427,
    # See x86_64 table for rationale.  splice on aarch64 is syscall 76.
    "splice": 76,
}

PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO_EPERM = 0x00050001
SECCOMP_RET_KILL_PROCESS = 0x80000000


def build_seccomp_preamble() -> str:
    """Return Python source that installs a seccomp BPF filter in the subprocess.

    The returned code is meant to be concatenated into the subprocess
    preamble between the Landlock block and the import hook.  It wraps
    everything in a function, calls it, and deletes it -- matching the
    pattern used by ``_build_landlock_preamble()``.
    """
    # Build the syscall-number lists as Python literals for embedding.
    x86_nums = ", ".join(str(v) for v in BLOCKED_SYSCALLS_X86_64.values())
    arm_nums = ", ".join(str(v) for v in BLOCKED_SYSCALLS_AARCH64.values())

    return (
        "def __seccomp_restrict__():\n"
        "    import sys as _sys\n"
        "    if _sys.platform != 'linux':\n"
        "        return\n"
        "    try:\n"
        "        import ctypes as _ct\n"
        "        import ctypes.util as _ctu\n"
        "        import struct as _struct\n"
        "        import platform as _platform\n"
        "        _machine = _platform.machine()\n"
        "        if _machine == 'x86_64':\n"
        f"            _arch = {AUDIT_ARCH_X86_64:#x}\n"
        f"            _blocked = [{x86_nums}]\n"
        "        elif _machine == 'aarch64':\n"
        f"            _arch = {AUDIT_ARCH_AARCH64:#x}\n"
        f"            _blocked = [{arm_nums}]\n"
        "        else:\n"
        "            return\n"
        "        _N = len(_blocked)\n"
        #
        # BPF instruction helpers and program construction.
        # Layout:
        #   [0]   LD arch
        #   [1]   JEQ arch -> skip to [3]
        #   [2]   RET KILL_PROCESS (wrong arch)
        #   [3]   LD syscall nr
        #   [4..4+N-1]  JEQ each blocked nr -> jump to BLOCK
        #   [4+N]       RET ALLOW
        #   [4+N+1]     RET ERRNO|EPERM
        #
        "        def _bpf(code, jt, jf, k):\n"
        "            return _struct.pack('<HBBI', code, jt, jf, k)\n"
        "        _BPF_LD_W_ABS = 0x20\n"
        "        _BPF_JMP_JEQ_K = 0x15\n"
        "        _BPF_RET_K = 0x06\n"
        f"        _RET_KILL = {SECCOMP_RET_KILL_PROCESS:#010x}\n"
        f"        _RET_ALLOW = {SECCOMP_RET_ALLOW:#010x}\n"
        f"        _RET_ERRNO = {SECCOMP_RET_ERRNO_EPERM:#010x}\n"
        "        _insns = bytearray()\n"
        "        _insns += _bpf(_BPF_LD_W_ABS, 0, 0, 4)\n"
        "        _insns += _bpf(_BPF_JMP_JEQ_K, 1, 0, _arch)\n"
        "        _insns += _bpf(_BPF_RET_K, 0, 0, _RET_KILL)\n"
        "        _insns += _bpf(_BPF_LD_W_ABS, 0, 0, 0)\n"
        "        for _i, _nr in enumerate(_blocked):\n"
        "            _insns += _bpf(_BPF_JMP_JEQ_K, _N - _i, 0, _nr)\n"
        "        _insns += _bpf(_BPF_RET_K, 0, 0, _RET_ALLOW)\n"
        "        _insns += _bpf(_BPF_RET_K, 0, 0, _RET_ERRNO)\n"
        "        _filter_buf = (_ct.c_char * len(_insns)).from_buffer_copy(_insns)\n"
        "        class _SockFprog(_ct.Structure):\n"
        "            _fields_ = [\n"
        "                ('len', _ct.c_ushort),\n"
        "                ('filter', _ct.c_void_p),\n"
        "            ]\n"
        "        _prog = _SockFprog()\n"
        "        _prog.len = len(_insns) // 8\n"
        "        _prog.filter = _ct.addressof(_filter_buf)\n"
        "        _libc_path = _ctu.find_library('c') or 'libc.so.6'\n"
        "        _libc = _ct.CDLL(_libc_path, use_errno=True)\n"
        "        _libc.prctl.restype = _ct.c_int\n"
        "        _libc.prctl.argtypes = [\n"
        "            _ct.c_int, _ct.c_ulong, _ct.c_ulong,\n"
        "            _ct.c_ulong, _ct.c_ulong,\n"
        "        ]\n"
        "        _libc.prctl(38, 1, 0, 0, 0)\n"
        f"        _ret = _libc.prctl({PR_SET_SECCOMP}, {SECCOMP_MODE_FILTER}, "
        "_ct.addressof(_prog), 0, 0)\n"
        "        if _ret != 0:\n"
        "            _sys.stderr.write(\n"
        "                'seccomp: prctl failed, errno='\n"
        "                + str(_ct.get_errno()) + '\\n'\n"
        "            )\n"
        "    except Exception:\n"
        "        pass\n"
        "__seccomp_restrict__()\n"
        "del __seccomp_restrict__\n"
    )
