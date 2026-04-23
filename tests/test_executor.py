"""Tests for sandbox.executor."""

import sys

import pytest

from sandbox.executor import _build_landlock_preamble, _build_preamble, execute_code
from sandbox.guardrails import _DEFAULT_ALLOWED_IMPORTS


@pytest.mark.asyncio
async def test_happy_path():
    result = await execute_code('print("hello")')
    assert result.stdout == "hello\n", f"unexpected stdout: {result.stdout!r}"
    assert result.exit_code == 0, f"unexpected exit_code: {result.exit_code}"
    assert result.stderr == "", f"unexpected stderr: {result.stderr!r}"
    assert result.timed_out is False


@pytest.mark.asyncio
async def test_math_computation():
    result = await execute_code("import math; print(math.pi)")
    assert result.exit_code == 0, f"unexpected exit_code: {result.exit_code}"
    assert "3.14" in result.stdout, f"unexpected stdout: {result.stdout!r}"


@pytest.mark.asyncio
async def test_stderr_output():
    result = await execute_code(
        'import sys; print("err", file=sys.stderr)',
        runtime_restrict=False,
    )
    assert result.stderr == "err\n", f"unexpected stderr: {result.stderr!r}"
    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_nonzero_exit():
    result = await execute_code("import sys; sys.exit(1)", runtime_restrict=False)
    assert result.exit_code == 1, f"unexpected exit_code: {result.exit_code}"


@pytest.mark.asyncio
async def test_runtime_error():
    result = await execute_code("1/0")
    assert result.exit_code != 0, "expected non-zero exit for ZeroDivisionError"
    assert "ZeroDivisionError" in result.stderr, (
        f"expected ZeroDivisionError in stderr, got: {result.stderr!r}"
    )


@pytest.mark.asyncio
async def test_timeout():
    # time is not in the default allowlist, so disable runtime restrictions
    # here — this test validates the timeout mechanism, not import policy.
    result = await execute_code(
        "import time; time.sleep(30)", timeout=1.0, runtime_restrict=False,
    )
    assert result.timed_out is True, "expected timed_out=True"
    assert result.exit_code != 0, f"expected non-zero exit_code, got: {result.exit_code}"
    assert "timed out" in result.stderr, (
        f"expected timeout message in stderr, got: {result.stderr!r}"
    )


@pytest.mark.asyncio
async def test_empty_code():
    result = await execute_code("")
    assert result.exit_code == 0, f"unexpected exit_code: {result.exit_code}"
    assert result.stdout == ""
    assert result.timed_out is False


@pytest.mark.asyncio
async def test_multiline_code():
    result = await execute_code("x = 5\ny = 10\nprint(x + y)")
    assert result.stdout == "15\n", f"unexpected stdout: {result.stdout!r}"
    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_unicode_output():
    result = await execute_code('print("hello 世界")')
    assert "世界" in result.stdout, f"unexpected stdout: {result.stdout!r}"
    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_preimport_modules_available():
    """Pre-imported modules are accessible even after runtime restrictions apply."""
    # json is always available and has no heavy deps — good canary for the mechanism.
    result = await execute_code(
        "import json\nprint(json.dumps({'ok': True}))",
        timeout=5.0,
        preimport=["json"],
    )
    assert result.exit_code == 0, (
        f"unexpected exit_code: {result.exit_code}; stderr: {result.stderr!r}"
    )
    assert '{"ok": true}' in result.stdout, f"unexpected stdout: {result.stdout!r}"


@pytest.mark.asyncio
async def test_preimport_none_is_harmless():
    """Passing preimport=None behaves identically to the default."""
    result = await execute_code("print(1 + 1)", timeout=5.0, preimport=None)
    assert result.exit_code == 0, f"unexpected exit_code: {result.exit_code}"
    assert result.stdout == "2\n", f"unexpected stdout: {result.stdout!r}"


# -- operator.attrgetter / methodcaller runtime patch tests --


@pytest.mark.asyncio
async def test_attrgetter_legitimate_use():
    """operator.attrgetter works for normal (non-dunder) attribute access."""
    result = await execute_code(
        "import operator\nprint(operator.attrgetter('real')(1))",
    )
    assert result.exit_code == 0, (
        f"legitimate attrgetter failed; stderr: {result.stderr!r}"
    )
    assert result.stdout.strip() == "1", f"unexpected stdout: {result.stdout!r}"


@pytest.mark.asyncio
async def test_attrgetter_blocks_dunder():
    """operator.attrgetter rejects dunder attribute names at runtime."""
    result = await execute_code(
        "import operator\noperator.attrgetter('__class__')(1)",
    )
    assert result.exit_code != 0, "expected non-zero exit for dunder access"
    assert "dunder attribute access blocked by sandbox" in result.stderr, (
        f"expected RuntimeError in stderr, got: {result.stderr!r}"
    )


@pytest.mark.asyncio
async def test_attrgetter_blocks_dynamic_dunder():
    """Dynamic chr()-based dunder construction is caught at runtime."""
    code = (
        "import operator\n"
        "operator.attrgetter(chr(95)*2 + 'class' + chr(95)*2)(1)\n"
    )
    result = await execute_code(code)
    assert result.exit_code != 0, "expected non-zero exit for dynamic dunder"
    assert "dunder attribute access blocked by sandbox" in result.stderr, (
        f"expected RuntimeError in stderr, got: {result.stderr!r}"
    )


@pytest.mark.asyncio
async def test_attrgetter_blocks_dotted_dunder_path():
    """Dotted paths containing a dunder segment are blocked."""
    result = await execute_code(
        "import operator\noperator.attrgetter('__class__.__bases__')(1)",
    )
    assert result.exit_code != 0, "expected non-zero exit for dotted dunder path"
    assert "dunder attribute access blocked by sandbox" in result.stderr, (
        f"expected RuntimeError in stderr, got: {result.stderr!r}"
    )


@pytest.mark.asyncio
async def test_methodcaller_blocks_dunder():
    """operator.methodcaller rejects dunder method names at runtime."""
    result = await execute_code(
        "import operator\noperator.methodcaller('__repr__')(1)",
    )
    assert result.exit_code != 0, "expected non-zero exit for dunder methodcaller"
    assert "dunder attribute access blocked by sandbox" in result.stderr, (
        f"expected RuntimeError in stderr, got: {result.stderr!r}"
    )


@pytest.mark.asyncio
async def test_methodcaller_legitimate_use():
    """operator.methodcaller works for normal (non-dunder) method calls."""
    result = await execute_code(
        "import operator\nprint(operator.methodcaller('strip')('  hello  '))",
    )
    assert result.exit_code == 0, (
        f"legitimate methodcaller failed; stderr: {result.stderr!r}"
    )
    assert result.stdout.strip() == "hello", f"unexpected stdout: {result.stdout!r}"


@pytest.mark.asyncio
async def test_attrgetter_no_inner_leak():
    """The safe attrgetter wrapper must not expose the original via _inner."""
    result = await execute_code(
        "import operator\n"
        "ag = operator.attrgetter('real')\n"
        "print(hasattr(ag, '_inner'))\n",
    )
    assert result.exit_code == 0, f"stderr: {result.stderr!r}"
    assert result.stdout.strip() == "False", (
        f"_inner attribute should not exist on wrapper; stdout: {result.stdout!r}"
    )


# -- Runtime import allowlist tests --


@pytest.mark.asyncio
async def test_allowlist_permits_allowed_import():
    """An import explicitly in the allowlist succeeds at runtime."""
    result = await execute_code(
        "import math\nprint(math.sqrt(4))",
        allowed_imports=_DEFAULT_ALLOWED_IMPORTS,
    )
    assert result.exit_code == 0, (
        f"allowed import 'math' failed; stderr: {result.stderr!r}"
    )
    assert "2.0" in result.stdout, f"unexpected stdout: {result.stdout!r}"


@pytest.mark.asyncio
async def test_allowlist_blocks_io_module():
    """The io module is not in the allowlist and is blocked at runtime.

    This is the actual exploit vector: typing.ForwardRef._evaluate()
    calls eval() with __name__=='typing', then imports io (not in the
    old denylist).  With the allowlist, io is blocked for user code.
    """
    result = await execute_code(
        "import io\nprint(io.FileIO('/etc/passwd', 'r').read())",
        allowed_imports=_DEFAULT_ALLOWED_IMPORTS,
    )
    assert result.exit_code != 0, (
        f"expected io import to be blocked; stdout: {result.stdout!r}"
    )
    assert "blocked by sandbox" in result.stderr, (
        f"expected 'blocked by sandbox' in stderr, got: {result.stderr!r}"
    )


@pytest.mark.asyncio
async def test_allowlist_blocks_subprocess():
    """subprocess is not in the allowlist and is blocked at runtime."""
    result = await execute_code(
        "import subprocess\nsubprocess.run(['id'])",
        allowed_imports=_DEFAULT_ALLOWED_IMPORTS,
    )
    assert result.exit_code != 0, "expected subprocess import to be blocked"
    assert "blocked by sandbox" in result.stderr, (
        f"expected 'blocked by sandbox' in stderr, got: {result.stderr!r}"
    )


@pytest.mark.asyncio
async def test_allowlist_stdlib_internal_imports_work():
    """Stdlib internal imports still work despite the allowlist.

    ``random`` internally imports ``os`` and ``hashlib``.  Because those
    imports happen with ``__name__ == 'random'`` (not ``'__main__'``),
    the allowlist hook lets them through.
    """
    result = await execute_code(
        "import random\nprint(random.randint(1, 100))",
        allowed_imports=_DEFAULT_ALLOWED_IMPORTS,
    )
    assert result.exit_code == 0, (
        f"random (which internally imports os) failed; stderr: {result.stderr!r}"
    )
    # Just verify we got an integer output
    value = result.stdout.strip()
    assert value.isdigit(), f"expected integer output, got: {result.stdout!r}"


@pytest.mark.asyncio
async def test_allowlist_none_uses_default():
    """Passing allowed_imports=None falls back to _DEFAULT_ALLOWED_IMPORTS."""
    # math is in the default allowlist, os is not
    result = await execute_code(
        "import math\nprint(math.e)",
        allowed_imports=None,
    )
    assert result.exit_code == 0, (
        f"default allowlist should permit math; stderr: {result.stderr!r}"
    )

    result = await execute_code(
        "import os\nprint(os.getcwd())",
        allowed_imports=None,
    )
    assert result.exit_code != 0, "os should be blocked with default allowlist"
    assert "blocked by sandbox" in result.stderr, (
        f"expected 'blocked by sandbox' in stderr, got: {result.stderr!r}"
    )


@pytest.mark.asyncio
async def test_allowlist_custom_set():
    """A custom allowlist restricts imports to only its members."""
    custom = frozenset({"json"})
    # json should work
    result = await execute_code(
        "import json\nprint(json.dumps([1]))",
        allowed_imports=custom,
    )
    assert result.exit_code == 0, (
        f"json should be allowed in custom set; stderr: {result.stderr!r}"
    )

    # math is NOT in the custom set
    result = await execute_code(
        "import math\nprint(math.pi)",
        allowed_imports=custom,
    )
    assert result.exit_code != 0, "math should be blocked by custom allowlist"
    assert "blocked by sandbox" in result.stderr, (
        f"expected 'blocked by sandbox' in stderr, got: {result.stderr!r}"
    )


# -- Subprocess Landlock preamble tests --


def test_landlock_preamble_includes_allowed_paths():
    """The Landlock preamble grants access to /usr, /lib, /tmp but not
    /opt/app-root or /etc."""
    preamble = _build_landlock_preamble()
    assert "'/usr'" in preamble, "expected /usr in Landlock preamble"
    assert "'/lib'" in preamble, "expected /lib in Landlock preamble"
    assert "'/tmp'" in preamble, "expected /tmp in Landlock preamble"
    assert "'/opt/app-root'" not in preamble, (
        "/opt/app-root must NOT appear in subprocess Landlock preamble"
    )
    # /etc must not appear as a path rule.  The string '/etc' should not
    # appear anywhere in the preamble (it's not used even in comments).
    assert "'/etc'" not in preamble, (
        "/etc must NOT appear as a path rule in subprocess Landlock preamble"
    )


def test_landlock_preamble_excluded_when_disabled():
    """When landlock=False, the preamble omits __landlock_restrict__."""
    preamble = _build_preamble(
        allowed_imports=_DEFAULT_ALLOWED_IMPORTS, landlock=False,
    )
    assert "__landlock_restrict__" not in preamble, (
        "expected no Landlock preamble when landlock=False"
    )


def test_landlock_preamble_included_by_default():
    """When landlock=True (default), the preamble includes __landlock_restrict__."""
    preamble = _build_preamble(
        allowed_imports=_DEFAULT_ALLOWED_IMPORTS, landlock=True,
    )
    assert "__landlock_restrict__" in preamble, (
        "expected Landlock preamble when landlock=True"
    )


@pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock requires Linux",
)
@pytest.mark.asyncio
async def test_landlock_blocks_opt_app_root_read():
    """On Linux, the subprocess Landlock prevents reading /opt/app-root."""
    # Use runtime_restrict=False so we can freely use os.open, but keep
    # subprocess_landlock=True so the Landlock preamble is still applied
    # (it runs unconditionally when the flag is set via _build_preamble,
    # which is only called when runtime_restrict=True).
    # Instead, we use runtime_restrict=True with a permissive allowlist
    # that includes os, so the code can attempt the read.
    permissive = frozenset({"os", "math", "sys"})
    result = await execute_code(
        "import os\n"
        "try:\n"
        "    fd = os.open('/opt/app-root/sandbox/app.py', os.O_RDONLY)\n"
        "    os.close(fd)\n"
        "    print('ACCESS_GRANTED')\n"
        "except (PermissionError, OSError) as e:\n"
        "    print(f'ACCESS_DENIED: {e}')\n",
        timeout=5.0,
        allowed_imports=permissive,
        subprocess_landlock=True,
    )
    assert result.exit_code == 0, (
        f"unexpected exit_code: {result.exit_code}; stderr: {result.stderr!r}"
    )
    assert "ACCESS_DENIED" in result.stdout, (
        f"expected Landlock to block /opt/app-root read; stdout: {result.stdout!r}"
    )


def test_landlock_preamble_has_e2big_fallback():
    """The Landlock preamble handles E2BIG by trying smaller struct sizes."""
    preamble = _build_landlock_preamble()
    assert "_E2BIG" in preamble, "preamble should handle E2BIG fallback"
    assert "24, 16, 8" in preamble or "[24,16,8]" in preamble, (
        "preamble should try sizes 24, 16, 8"
    )


# -- Subprocess seccomp preamble tests --


def test_seccomp_preamble_included_by_default():
    """When seccomp=True (default), the preamble includes __seccomp_restrict__."""
    preamble = _build_preamble(
        allowed_imports=_DEFAULT_ALLOWED_IMPORTS, seccomp=True,
    )
    assert "__seccomp_restrict__" in preamble, (
        "expected seccomp preamble when seccomp=True"
    )


def test_seccomp_preamble_excluded_when_disabled():
    """When seccomp=False, the preamble omits __seccomp_restrict__."""
    preamble = _build_preamble(
        allowed_imports=_DEFAULT_ALLOWED_IMPORTS, seccomp=False,
    )
    assert "__seccomp_restrict__" not in preamble, (
        "expected no seccomp preamble when seccomp=False"
    )


def test_seccomp_ordering_after_landlock_before_hook():
    """Seccomp preamble must appear after Landlock and before the import hook."""
    preamble = _build_preamble(
        allowed_imports=_DEFAULT_ALLOWED_IMPORTS, landlock=True, seccomp=True,
    )
    ll_pos = preamble.index("__landlock_restrict__")
    sc_pos = preamble.index("__seccomp_restrict__")
    hook_pos = preamble.index("__sandbox_setup__")
    assert ll_pos < sc_pos < hook_pos, (
        "expected ordering: Landlock < seccomp < import hook"
    )


@pytest.mark.skipif(
    sys.platform != "linux", reason="Seccomp requires Linux",
)
@pytest.mark.asyncio
async def test_seccomp_blocks_socket_creation():
    """On Linux, seccomp BPF prevents socket() syscall in the subprocess."""
    permissive = frozenset({"ctypes", "math", "sys"})
    result = await execute_code(
        "import ctypes\n"
        "import ctypes.util\n"
        "_libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6', use_errno=True)\n"
        "fd = _libc.socket(2, 1, 0)\n"
        "if fd < 0:\n"
        "    import ctypes\n"
        "    print(f'BLOCKED: errno={ctypes.get_errno()}')\n"
        "else:\n"
        "    print(f'CREATED_SOCKET: fd={fd}')\n",
        timeout=5.0,
        allowed_imports=permissive,
        subprocess_seccomp=True,
        subprocess_landlock=True,
    )
    assert "BLOCKED" in result.stdout, (
        f"expected seccomp to block socket(); stdout: {result.stdout!r}, "
        f"stderr: {result.stderr!r}"
    )
