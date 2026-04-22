"""Subprocess-based Python code executor with timeout and output capping.

Executes validated Python code in an isolated subprocess using ``python3 -I``
(isolated mode: no user site-packages, PYTHON* env vars ignored).  Code is
written to a temporary file under ``/tmp`` and cleaned up unconditionally.
"""

import asyncio
import dataclasses
import os
import tempfile

from sandbox.guardrails import _DEFAULT_ALLOWED_IMPORTS

_MAX_OUTPUT_BYTES = 50 * 1024  # 50 KB per stream
_TRUNCATION_NOTE = "\n[output truncated at 50 KB]"


def _build_landlock_preamble() -> str:
    """Build a preamble that applies a tighter Landlock policy in the subprocess.

    The parent FastAPI process applies Landlock at startup with read-only
    access to /opt/app-root (application code) and /etc (config/secrets).
    Landlock is additive: child processes can restrict further but never
    relax.  This preamble drops /opt/app-root and /etc so the subprocess
    cannot read application source or mounted secrets even if all
    Python-level defenses are bypassed.

    Must run AFTER pre-imports (so heavy libraries can load from
    /opt/app-root) but BEFORE __sandbox_setup__ (which blocks ctypes/os
    imports via the import hook).

    Allowed paths (subprocess only):
      Read-only: /usr, /lib, /lib64, /proc/self
      Read-write: /tmp
    """
    return (
        "def __landlock_restrict__():\n"
        "    import sys as _sys\n"
        "    if _sys.platform != 'linux':\n"
        "        return\n"
        "    try:\n"
        "        import ctypes as _ct\n"
        "        import ctypes.util as _ctu\n"
        "        import os as _os\n"
        "    except ImportError:\n"
        "        return\n"
        "    try:\n"
        # Query ABI version
        "        _libc_path = _ctu.find_library('c') or 'libc.so.6'\n"
        "        _libc = _ct.CDLL(_libc_path, use_errno=True)\n"
        "        _SYS_CREATE = 444\n"
        "        _SYS_ADD_RULE = 445\n"
        "        _SYS_RESTRICT = 446\n"
        "        _VERSION_FLAG = 1 << 0\n"
        "        _abi = _libc.syscall(\n"
        "            _SYS_CREATE, None, _ct.c_size_t(0),\n"
        "            _ct.c_uint32(_VERSION_FLAG),\n"
        "        )\n"
        "        if _abi < 1:\n"
        "            return\n"
        # Filesystem access bits
        "        _FS_EXECUTE    = 1 << 0\n"
        "        _FS_WRITE_FILE = 1 << 1\n"
        "        _FS_READ_FILE  = 1 << 2\n"
        "        _FS_READ_DIR   = 1 << 3\n"
        "        _FS_REMOVE_DIR = 1 << 4\n"
        "        _FS_REMOVE_FILE= 1 << 5\n"
        "        _FS_MAKE_CHAR  = 1 << 6\n"
        "        _FS_MAKE_DIR   = 1 << 7\n"
        "        _FS_MAKE_REG   = 1 << 8\n"
        "        _FS_MAKE_SOCK  = 1 << 9\n"
        "        _FS_MAKE_FIFO  = 1 << 10\n"
        "        _FS_MAKE_BLOCK = 1 << 11\n"
        "        _FS_MAKE_SYM   = 1 << 12\n"
        "        _FS_REFER      = 1 << 13\n"
        "        _FS_TRUNCATE   = 1 << 14\n"
        # Composite access sets
        "        _RO = _FS_EXECUTE | _FS_READ_FILE | _FS_READ_DIR\n"
        "        _RW = (\n"
        "            _RO | _FS_WRITE_FILE | _FS_REMOVE_DIR\n"
        "            | _FS_REMOVE_FILE | _FS_MAKE_DIR | _FS_MAKE_REG\n"
        "            | _FS_MAKE_SYM\n"
        "        )\n"
        "        if _abi >= 3:\n"
        "            _RW |= _FS_TRUNCATE\n"
        # handled_access_fs based on ABI
        "        _ALL_V1 = (\n"
        "            _FS_EXECUTE | _FS_WRITE_FILE | _FS_READ_FILE\n"
        "            | _FS_READ_DIR | _FS_REMOVE_DIR | _FS_REMOVE_FILE\n"
        "            | _FS_MAKE_CHAR | _FS_MAKE_DIR | _FS_MAKE_REG\n"
        "            | _FS_MAKE_SOCK | _FS_MAKE_FIFO | _FS_MAKE_BLOCK\n"
        "            | _FS_MAKE_SYM\n"
        "        )\n"
        "        _handled_fs = _ALL_V1\n"
        "        if _abi >= 2:\n"
        "            _handled_fs |= _FS_REFER\n"
        "        if _abi >= 3:\n"
        "            _handled_fs |= _FS_TRUNCATE\n"
        # Network and scope
        "        _handled_net = 0\n"
        "        if _abi >= 4:\n"
        "            _handled_net = (1 << 0) | (1 << 1)\n"
        "        _scoped = 0\n"
        "        if _abi >= 5:\n"
        "            _scoped = (1 << 0) | (1 << 1)\n"
        # Struct size based on ABI
        "        if _abi >= 5:\n"
        "            _attr_size = 24\n"
        "        elif _abi >= 4:\n"
        "            _attr_size = 16\n"
        "        else:\n"
        "            _attr_size = 8\n"
        # Build ruleset attr struct
        "        class _RulesetAttr(_ct.Structure):\n"
        "            _fields_ = [\n"
        "                ('handled_access_fs', _ct.c_uint64),\n"
        "                ('handled_access_net', _ct.c_uint64),\n"
        "                ('scoped', _ct.c_uint64),\n"
        "            ]\n"
        "        class _PathBeneathAttr(_ct.Structure):\n"
        "            _pack_ = 1\n"
        "            _fields_ = [\n"
        "                ('allowed_access', _ct.c_uint64),\n"
        "                ('parent_fd', _ct.c_int32),\n"
        "            ]\n"
        # E2BIG fallback: RHEL backport kernels may report ABI v5 but
        # reject the v5 struct size.  Try progressively smaller sizes.
        "        _E2BIG = 7\n"
        "        _ruleset_fd = -1\n"
        "        for _try_size in [s for s in [24, 16, 8] if s <= _attr_size]:\n"
        "            _attr = _RulesetAttr(\n"
        "                handled_access_fs=_handled_fs,\n"
        "                handled_access_net=_handled_net if _try_size >= 16 else 0,\n"
        "                scoped=_scoped if _try_size >= 24 else 0,\n"
        "            )\n"
        "            _ruleset_fd = _libc.syscall(\n"
        "                _SYS_CREATE, _ct.byref(_attr),\n"
        "                _ct.c_size_t(_try_size), _ct.c_uint32(0),\n"
        "            )\n"
        "            if _ruleset_fd >= 0:\n"
        "                break\n"
        "            if _ct.get_errno() != _E2BIG:\n"
        "                return\n"
        "        if _ruleset_fd < 0:\n"
        "            return\n"
        "        try:\n"
        # Add path rules — read-only
        "            for _path in ['/usr', '/lib', '/lib64', '/proc/self']:\n"
        "                if not _os.path.exists(_path):\n"
        "                    continue\n"
        "                _fd = _os.open(_path, _os.O_PATH | _os.O_CLOEXEC)\n"
        "                try:\n"
        "                    _rule = _PathBeneathAttr(\n"
        "                        allowed_access=_RO, parent_fd=_fd,\n"
        "                    )\n"
        "                    _libc.syscall(\n"
        "                        _SYS_ADD_RULE, _ct.c_int(_ruleset_fd),\n"
        "                        _ct.c_int(1), _ct.byref(_rule),\n"
        "                        _ct.c_uint32(0),\n"
        "                    )\n"
        "                finally:\n"
        "                    _os.close(_fd)\n"
        # Add path rules — read-write
        "            for _path in ['/tmp']:\n"
        "                if not _os.path.exists(_path):\n"
        "                    continue\n"
        "                _fd = _os.open(_path, _os.O_PATH | _os.O_CLOEXEC)\n"
        "                try:\n"
        "                    _rule = _PathBeneathAttr(\n"
        "                        allowed_access=_RW, parent_fd=_fd,\n"
        "                    )\n"
        "                    _libc.syscall(\n"
        "                        _SYS_ADD_RULE, _ct.c_int(_ruleset_fd),\n"
        "                        _ct.c_int(1), _ct.byref(_rule),\n"
        "                        _ct.c_uint32(0),\n"
        "                    )\n"
        "                finally:\n"
        "                    _os.close(_fd)\n"
        # Restrict self
        "            _rr = _libc.syscall(\n"
        "                _SYS_RESTRICT, _ct.c_int(_ruleset_fd),\n"
        "                _ct.c_uint32(0),\n"
        "            )\n"
        "        finally:\n"
        "            _os.close(_ruleset_fd)\n"
        "    except Exception:\n"
        "        pass\n"
        "__landlock_restrict__()\n"
        "del __landlock_restrict__\n"
    )


def _build_memory_preamble(limit_mb: int) -> str:
    """Build a preamble that applies RLIMIT_AS to the subprocess.

    Must run before any imports so that subsequent memory allocations are
    subject to the limit.  Wrapped in try/except for graceful degradation on
    platforms where RLIMIT_AS is unavailable (e.g. macOS with strict limits).
    """
    limit_bytes = limit_mb * 1024 * 1024
    return (
        "try:\n"
        "    import resource as _res\n"
        f"    _res.setrlimit(_res.RLIMIT_AS, ({limit_bytes}, {limit_bytes}))\n"
        "    del _res\n"
        "except Exception:\n"
        "    pass\n"
    )


def _build_preamble(
    *,
    allowed_imports: frozenset[str],
    preimport: list[str] | None = None,
    landlock: bool = True,
) -> str:
    """Build a runtime preamble that restricts imports in the subprocess.

    This is defense-in-depth: even if AST guardrails are bypassed via
    dynamic string construction (chr(), bytes.decode(), etc.), the
    runtime import hook blocks any module not in the allowlist.

    Uses an allowlist (not a denylist) so that novel escape routes via
    unlisted modules (e.g. ``io.FileIO``) are blocked by default.  The
    ``caller == '__main__'`` check ensures this only applies to user code:
    stdlib internal imports (e.g. ``random`` internally importing ``os``)
    still work because they execute with ``__name__`` set to their own
    module name, not ``'__main__'``.

    Args:
        allowed_imports: Frozenset of top-level module names the user
            is permitted to import.  Comes from the active profile.
        preimport: Modules to import BEFORE applying runtime restrictions.
            Heavy libraries like pandas call ``open()`` during initialisation;
            pre-importing them here lets them load with full builtins available,
            while restrictions still apply to user-supplied code.
        landlock: If True (default), include a subprocess Landlock preamble
            that drops /opt/app-root and /etc from the filesystem access.
            Inserted after pre-imports but before the import hook.
    """
    parts: list[str] = []

    # Pre-import allowed libraries before restrictions are applied.
    # pandas (via six) calls open() and imports builtins during __init__;
    # doing this here means those calls succeed before we remove open/builtins.
    if preimport:
        for mod in preimport:
            parts.append(f"import {mod}\n")

    # Subprocess Landlock: tighter filesystem restriction that drops
    # /opt/app-root and /etc.  Must run after pre-imports (so heavy
    # libraries can load) but before the import hook (which blocks ctypes).
    if landlock:
        parts.append(_build_landlock_preamble())

    # Build the allowlist literal for the preamble.  Sorted for
    # deterministic output in tests.
    allowed_repr = ", ".join(f"'{m}'" for m in sorted(allowed_imports))

    # All stdlib imports needed by the preamble (operator, re, random) must
    # happen BEFORE the import hook is installed.  After the hook is active,
    # only modules in _allowed can be imported from __main__.
    parts.append(
        "def __sandbox_setup__():\n"
        "    import sys as _sys\n"
        "    import operator as _op\n"
        "    import re as _re\n"
        f"    _allowed = frozenset({{{allowed_repr}}})\n"
        "    # Purge the most critical module reference: random._os → os.\n"
        "    # Other references (statistics.sys, etc.) are caught by AST.\n"
        "    # Generic purge is too destructive — collections._sys breaks namedtuple.\n"
        "    try:\n"
        "        import random as _random\n"
        "        if hasattr(_random, '_os'):\n"
        "            delattr(_random, '_os')\n"
        "    except ImportError:\n"
        "        pass\n"
        "    _bi = __builtins__\n"
        "    _d = _bi if isinstance(_bi, dict) else _bi.__dict__\n"
        "    _orig = _d['__import__']\n"
        "    def _rimp(name, gl=None, lo=None, fromlist=(), level=0):\n"
        "        top = name.split('.')[0]\n"
        "        if level == 0 and top not in _allowed:\n"
        "            caller = (gl or {}).get('__name__', '__main__')\n"
        "            if caller == '__main__':\n"
        "                raise ImportError(f\"import of '{name}' blocked by sandbox\")\n"  # noqa: Q003
        "        return _orig(name, gl, lo, fromlist, level)\n"
        "    _d['__import__'] = _rimp\n"
        "    # Remove dangerous builtins so they can't be reached via any\n"
        "    # object graph traversal (defense-in-depth catch-all).\n"
        "    # exec/eval/compile must stay — import machinery uses them.\n"
        "    for _name in ('open', 'breakpoint', 'input'):\n"
        "        _d.pop(_name, None)\n"
        "    # Monkey-patch operator.attrgetter and operator.methodcaller to\n"
        "    # reject dunder attribute access at runtime.  AST guardrails can't\n"
        "    # inspect dynamically-constructed strings (chr(), bytes.decode(),\n"
        "    # etc.), so this runtime check closes the gap.\n"
        "    _dunder_re = _re.compile(r'^__\\w+__$')\n"
        "    _orig_ag = _op.attrgetter\n"
        "    _orig_mc = _op.methodcaller\n"
        "    class _safe_attrgetter:\n"
        "        __slots__ = ('_inner',)\n"
        "        def __init__(self, *attrs):\n"
        "            for a in attrs:\n"
        "                for part in str(a).split('.'):\n"
        "                    if _dunder_re.match(part):\n"
        "                        raise RuntimeError(\n"
        "                            'dunder attribute access blocked by sandbox'\n"
        "                        )\n"
        "            self._inner = _orig_ag(*attrs)\n"
        "        def __call__(self, obj):\n"
        "            return self._inner(obj)\n"
        "    class _safe_methodcaller:\n"
        "        __slots__ = ('_inner',)\n"
        "        def __init__(self, name, /, *args, **kwargs):\n"
        "            for part in str(name).split('.'):\n"
        "                if _dunder_re.match(part):\n"
        "                    raise RuntimeError(\n"
        "                        'dunder attribute access blocked by sandbox'\n"
        "                    )\n"
        "            self._inner = _orig_mc(name, *args, **kwargs)\n"
        "        def __call__(self, obj):\n"
        "            return self._inner(obj)\n"
        "    _op.attrgetter = _safe_attrgetter\n"
        "    _op.methodcaller = _safe_methodcaller\n"
        "    del _sys, _op, _re\n"
        "__sandbox_setup__()\n"
        "del __sandbox_setup__\n"
    )

    return "".join(parts)


@dataclasses.dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False


async def execute_code(
    code: str,
    timeout: float = 10.0,
    *,
    runtime_restrict: bool = True,
    memory_limit_mb: int = 200,
    preimport: list[str] | None = None,
    allowed_imports: frozenset[str] | None = None,
    subprocess_landlock: bool = True,
) -> ExecutionResult:
    """Execute *code* in an isolated Python subprocess and return the result.

    Args:
        code: Python source code to run.
        timeout: Wall-clock seconds before the process is killed.
        runtime_restrict: If True (default), a runtime preamble is prepended
            that blocks imports of modules not in *allowed_imports*.
            Defense-in-depth against AST bypasses.
        memory_limit_mb: RLIMIT_AS limit in megabytes applied inside the
            subprocess.  Set to 0 to disable.  Defaults to 200 MB.
        allowed_imports: Frozenset of top-level module names the user code
            may import at runtime.  Defaults to the minimal profile's
            allowlist when ``None``.
        subprocess_landlock: If True (default) and *runtime_restrict* is
            True, include a Landlock preamble that drops /opt/app-root and
            /etc from the subprocess's filesystem access.

    Returns:
        An :class:`ExecutionResult` with captured stdout, stderr, exit code,
        and a flag indicating whether the process was killed due to timeout.
    """
    if runtime_restrict:
        effective_allowed = (
            allowed_imports if allowed_imports is not None
            else _DEFAULT_ALLOWED_IMPORTS
        )
        code = _build_preamble(
            allowed_imports=effective_allowed,
            preimport=preimport,
            landlock=subprocess_landlock,
        ) + code
    if memory_limit_mb > 0:
        code = _build_memory_preamble(memory_limit_mb) + code

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            suffix=".py", dir="/tmp", delete=False, mode="w", encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        process = await asyncio.create_subprocess_exec(
            "python3", "-I", tmp_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            raw_stdout, raw_stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            # Drain whatever was buffered before the kill
            try:
                raw_stdout, raw_stderr = await asyncio.wait_for(
                    process.communicate(), timeout=5.0
                )
            except TimeoutError:
                raw_stdout, raw_stderr = b"", b""
            return ExecutionResult(
                stdout=_decode(raw_stdout),
                stderr=f"Execution timed out after {timeout}s",
                exit_code=process.returncode if process.returncode is not None else -1,
                timed_out=True,
            )

        return ExecutionResult(
            stdout=_decode(raw_stdout),
            stderr=_decode(raw_stderr),
            exit_code=process.returncode,
        )
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


def _decode(raw: bytes) -> str:
    # Truncate bytes before decoding to enforce a consistent size cap
    # regardless of character encoding.
    if len(raw) > _MAX_OUTPUT_BYTES:
        raw = raw[:_MAX_OUTPUT_BYTES]
        return raw.decode("utf-8", errors="replace") + _TRUNCATION_NOTE
    return raw.decode("utf-8", errors="replace")
