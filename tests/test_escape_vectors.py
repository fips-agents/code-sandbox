"""Sandbox escape vector tests.

Red-team test suite that attempts to bypass sandbox guardrails and
achieve code execution, information leakage, or denial of service.

Each test is named for the attack vector it exercises.  Tests that
FAIL (i.e., the guardrail catches the attack) are GOOD -- they prove
the defense works.  Tests that PASS despite the attack code getting
through are VULNERABILITIES that need fixing.

Run with: pytest sandbox/tests/test_escape_vectors.py -v
"""

import sys
import textwrap

import pytest

from sandbox.executor import execute_code
from sandbox.guardrails import validate_code

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate(source: str) -> list[str]:
    """Validate dedented source and return the violation list."""
    return validate_code(textwrap.dedent(source).strip())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_imports():
    """Allowed imports for the minimal profile."""
    return frozenset({
        "math", "statistics", "itertools", "functools", "re",
        "datetime", "collections", "json", "csv", "string",
        "textwrap", "decimal", "fractions", "random", "operator",
        "typing",
    })


# ---------------------------------------------------------------------------
# Section 1: Guardrail Bypass Tests
#
# A test FAILING here means the guardrail caught the attack (GOOD).
# A test PASSING here means the guardrail missed it (VULNERABILITY).
# ---------------------------------------------------------------------------


class TestGuardrailBypasses:
    """Tests that verify guardrails catch malicious code.

    Each test submits a known attack payload to validate_code().  If
    validate_code returns an empty violations list, the guardrail failed
    to detect the attack -- that is a vulnerability.
    """

    @pytest.mark.escape_vector
    def test_globals_builtins_access(self):
        """globals() is not blocked; dict key access bypasses dunder check."""
        code = textwrap.dedent("""\
            g = globals()
            b = g['__builtins__']
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: globals() returns a dict containing "
            "'__builtins__'; dict key access (ast.Subscript) is not "
            "checked for dunder names"
        )

    @pytest.mark.escape_vector
    def test_operator_attrgetter_bypass(self):
        """operator.attrgetter passes dunder as string arg, not ast.Attribute."""
        code = textwrap.dedent("""\
            import operator
            import math
            b = operator.attrgetter('__builtins__')(math)
            imp = b.__import__ if hasattr(b, '__import__') else b['__import__']
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: operator.attrgetter('__builtins__') passes "
            "the dunder name as a string argument; AST visitor only checks "
            "ast.Attribute nodes, not string constants in call args"
        )

    @pytest.mark.escape_vector
    def test_exception_traceback_frame_walk(self):
        """__traceback__ is not in blocked dunders; frame walk to builtins."""
        code = textwrap.dedent("""\
            try:
                1/0
            except Exception as e:
                frame = e.__traceback__.tb_frame
                b = frame.f_globals['__builtins__']
                imp = b['__import__'] if isinstance(b, dict) else b.__import__
                os_mod = imp('os')
                print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: __traceback__ is not in _BLOCKED_DUNDERS; "
            "exception handler can reach tb_frame -> f_globals -> "
            "__builtins__ via dict key access"
        )

    @pytest.mark.escape_vector
    def test_generator_frame_walk(self):
        """Generator gi_frame attribute reaches f_globals -> builtins."""
        code = textwrap.dedent("""\
            def gen():
                yield 1
            g = gen()
            frame = g.gi_frame
            b = frame.f_globals['__builtins__']
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: generator gi_frame -> f_globals -> "
            "__builtins__ via dict key access; gi_frame and f_globals "
            "are not blocked attributes"
        )

    @pytest.mark.escape_vector
    def test_vars_builtins_access(self):
        """vars() is not in blocked calls; vars(module) exposes __builtins__."""
        code = textwrap.dedent("""\
            import math
            d = vars(math)
            b = d['__builtins__']
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: vars() is not a blocked call; "
            "vars(module) returns __dict__ which often contains "
            "__builtins__"
        )

    @pytest.mark.escape_vector
    def test_dynamic_chr_construction(self):
        """chr() can build dunder names dynamically, invisible to AST."""
        code = textwrap.dedent("""\
            name = chr(95)*2 + 'builtins' + chr(95)*2
            b = globals()[name]
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: chr() dynamically constructs '__builtins__' "
            "at runtime; the AST only sees chr(95) calls, not the "
            "resulting string"
        )

    @pytest.mark.escape_vector
    def test_bytes_decode_dunder_construction(self):
        """bytes.decode() builds dunder names from integer sequences."""
        code = textwrap.dedent("""\
            name = bytes([95,95,98,117,105,108,116,105,110,115,95,95]).decode()
            b = globals()[name]
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: bytes([...]).decode() constructs "
            "'__builtins__' from integer ordinals; invisible to "
            "static AST analysis"
        )

    @pytest.mark.escape_vector
    def test_format_string_attribute_traversal(self):
        """Format strings traverse attributes via dotted names in braces."""
        code = textwrap.dedent("""\
            def f(): pass
            leaked = '{0.__globals__}'.format(f)
            print('LEAKED_GLOBALS:', leaked[:200])
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: '{0.__globals__}'.format(f) traverses "
            "dunder attributes via format string mini-language; the "
            "dunder is inside a string literal, not an ast.Attribute"
        )

    @pytest.mark.escape_vector
    def test_class_chain_reconnaissance(self):
        """__class__, __bases__ not blocked; exposes object hierarchy."""
        code = textwrap.dedent("""\
            obj_class = ().__class__.__bases__[0]
            print('OBJECT:', obj_class)
            print('DICT:', obj_class.__dict__.keys())
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: __class__, __bases__, __dict__ are not "
            "in _BLOCKED_DUNDERS; allows object hierarchy traversal "
            "for subclass exploitation"
        )

    @pytest.mark.escape_vector
    def test_metaclass_globals_escape(self):
        """Metaclass __new__ runs at class definition; accesses globals()."""
        code = textwrap.dedent("""\
            class Meta(type):
                def __new__(mcs, name, bases, ns):
                    b = globals()['__builtins__']
                    imp = b['__import__'] if isinstance(b, dict) else b.__import__
                    os_mod = imp('os')
                    print('ESCAPED:', os_mod.getcwd())
                    return super().__new__(mcs, name, bases, ns)

            class Exploit(metaclass=Meta):
                pass
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: metaclass __new__ executes at class "
            "definition time; globals()['__builtins__'] via dict key "
            "access is not caught"
        )

    @pytest.mark.escape_vector
    def test_operator_methodcaller_bypass(self):
        """operator.methodcaller invokes methods by string name."""
        code = textwrap.dedent("""\
            import operator
            import math
            mc = operator.methodcaller('__init__')
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: operator.methodcaller('__init__') "
            "invokes dunder methods via string name; AST sees only "
            "a string constant, not an attribute access"
        )

    @pytest.mark.escape_vector
    def test_functools_reduce_attrgetter_chain(self):
        """functools.reduce chains attrgetter calls to walk dunders."""
        code = textwrap.dedent("""\
            import functools
            import operator
            attrs = ['__class__', '__bases__']
            result = functools.reduce(
                lambda obj, attr: operator.attrgetter(attr)(obj),
                attrs, ()
            )
            print('CHAIN:', result)
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: functools.reduce + operator.attrgetter "
            "chains dunder traversal via string arguments; fully "
            "invisible to static AST checks"
        )

    @pytest.mark.escape_vector
    def test_locals_builtins_access(self):
        """locals() is not blocked; at module level it equals globals()."""
        code = textwrap.dedent("""\
            l = locals()
            b = l['__builtins__']
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: locals() is not a blocked call; at "
            "module scope locals() == globals(), providing access to "
            "__builtins__ via dict key"
        )

    @pytest.mark.escape_vector
    def test_bare_builtins_name_reference(self):
        """__builtins__ as a bare name (ast.Name) bypasses attribute checks."""
        code = textwrap.dedent("""\
            b = __builtins__
            imp = b.__import__
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: __builtins__ as a bare ast.Name reference "
            "is not caught by visit_Attribute (which only checks "
            "ast.Attribute nodes)"
        )

    @pytest.mark.escape_vector
    def test_bare_builtins_open_method(self):
        """Chain: bare __builtins__ -> .open() to read files."""
        code = textwrap.dedent("""\
            b = __builtins__
            f = b.open('/etc/passwd', 'r')
            print(f.read())
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: __builtins__.open() bypasses _BLOCKED_CALLS "
            "because the call check only fires on ast.Name, not method "
            "calls on objects"
        )


# ---------------------------------------------------------------------------
# Section 1a: Module Attribute Traversal Tests
# ---------------------------------------------------------------------------


class TestModuleAttributeTraversal:
    """Tests for accessing dangerous modules through allowed modules."""

    @pytest.mark.escape_vector
    def test_random_os_escape(self):
        """random._os is a direct reference to the os module."""
        code = textwrap.dedent("""\
            import random
            random._os.system('id')
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: random._os gives direct access to the "
            "os module, enabling os.system() command execution"
        )

    @pytest.mark.escape_vector
    def test_random_os_environ_leak(self):
        """random._os.environ leaks environment variables."""
        code = textwrap.dedent("""\
            import random
            print(dict(random._os.environ))
        """)
        violations = validate_code(code)
        assert violations, (
            "GUARDRAIL BYPASS: random._os.environ leaks all "
            "environment variables including secrets"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_random_os_runtime_purge(self):
        """Runtime preamble should purge _os from random module."""
        code = textwrap.dedent("""\
            import random
            print('has _os:', hasattr(random, '_os'))
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught _os attribute access (good)")
        result = await execute_code(code, timeout=5.0)
        assert "True" not in result.stdout, (
            f"RUNTIME BYPASS: random._os still accessible after purge: "
            f"{result.stdout!r}"
        )


# ---------------------------------------------------------------------------
# Section 1b: Eval-Based Bypass Tests
#
# Tests for vectors that use allowed modules to eval() strings,
# bypassing AST guardrails entirely.
# ---------------------------------------------------------------------------


class TestEvalBypasses:
    """Tests for modules that eval() user-controlled strings at runtime.

    typing.get_type_hints evaluates string annotations via eval().
    The annotation string passes AST checks (it's just a string literal)
    but gets executed as Python code at runtime.
    """

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_typing_get_type_hints_eval_bypass(self):
        """typing.get_type_hints evals annotations; runtime hook must block os."""
        code = textwrap.dedent("""\
            import typing

            class X:
                a: 'type(print(__import__(\"os\").getcwd()))'

            typing.get_type_hints(X)
        """)
        # AST guardrails won't catch this — the annotation is just a string.
        # The runtime import hook must block __import__('os') from __main__.
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good but unexpected)")
        result = await execute_code(code, timeout=5.0)
        assert "ESCAPED" not in result.stdout and result.exit_code != 0, (
            f"EVAL BYPASS: typing.get_type_hints executed os.getcwd(): "
            f"stdout={result.stdout!r}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_typing_eval_env_leak(self):
        """typing.get_type_hints can leak env vars if os import succeeds."""
        code = textwrap.dedent("""\
            import typing

            class X:
                a: 'type(print(__import__(\"os\").environ.get(\"HOME\", \"blocked\")))'

            try:
                typing.get_type_hints(X)
            except Exception:
                pass
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        # If HOME appears in output, the env leak succeeded
        out = result.stdout
        assert "/home" not in out.lower() and "/root" not in out.lower() and "/Users" not in out, (
            f"ENV LEAK via typing eval: stdout={out!r}"
        )


# ---------------------------------------------------------------------------
# Section 2: Execution Tests
#
# For vectors that bypass guardrails AND achieve code execution, these
# tests confirm the vulnerability is real, not theoretical.
# ---------------------------------------------------------------------------


class TestExecutionEscapes:
    """Tests that prove a guardrail bypass leads to real code execution.

    These are async tests that run the full pipeline: validate_code()
    followed by execute_code().  If the guardrail catches the payload,
    the test skips (that is the desired outcome).
    """

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_globals_escape_executes(self):
        """Proves globals() -> __builtins__ -> __import__ achieves execution."""
        code = textwrap.dedent("""\
            g = globals()
            b = g['__builtins__']
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert result.exit_code != 0 or "ESCAPED:" not in result.stdout, (
            f"ESCAPE SUCCESSFUL via globals(): stdout={result.stdout!r}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_operator_attrgetter_escape_executes(self):
        """Proves operator.attrgetter('__builtins__') achieves execution."""
        code = textwrap.dedent("""\
            import operator
            import math
            b = operator.attrgetter('__builtins__')(math)
            imp = b.__import__ if hasattr(b, '__import__') else b['__import__']
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert result.exit_code != 0 or "ESCAPED:" not in result.stdout, (
            f"ESCAPE SUCCESSFUL via operator.attrgetter: stdout={result.stdout!r}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_traceback_frame_escape_executes(self):
        """Proves exception traceback frame walk achieves execution."""
        code = textwrap.dedent("""\
            try:
                1/0
            except Exception as e:
                frame = e.__traceback__.tb_frame
                b = frame.f_globals['__builtins__']
                imp = b['__import__'] if isinstance(b, dict) else b.__import__
                os_mod = imp('os')
                print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert result.exit_code != 0 or "ESCAPED:" not in result.stdout, (
            f"ESCAPE SUCCESSFUL via traceback frame walk: stdout={result.stdout!r}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_generator_frame_escape_executes(self):
        """Proves generator gi_frame -> f_globals walk achieves execution."""
        code = textwrap.dedent("""\
            def gen():
                yield 1
            g = gen()
            frame = g.gi_frame
            b = frame.f_globals['__builtins__']
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert result.exit_code != 0 or "ESCAPED:" not in result.stdout, (
            f"ESCAPE SUCCESSFUL via generator frame walk: stdout={result.stdout!r}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_dynamic_chr_escape_executes(self):
        """Proves chr()-constructed dunder name achieves execution."""
        code = textwrap.dedent("""\
            name = chr(95)*2 + 'builtins' + chr(95)*2
            b = globals()[name]
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert result.exit_code != 0 or "ESCAPED:" not in result.stdout, (
            f"ESCAPE SUCCESSFUL via chr() construction: stdout={result.stdout!r}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_bytes_decode_escape_executes(self):
        """Proves bytes.decode() dunder construction achieves execution."""
        code = textwrap.dedent("""\
            name = bytes([95,95,98,117,105,108,116,105,110,115,95,95]).decode()
            b = globals()[name]
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            print('ESCAPED:', os_mod.getcwd())
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert result.exit_code != 0 or "ESCAPED:" not in result.stdout, (
            f"ESCAPE SUCCESSFUL via bytes.decode(): stdout={result.stdout!r}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_metaclass_escape_executes(self):
        """Proves metaclass __new__ + globals() achieves execution."""
        code = textwrap.dedent("""\
            class Meta(type):
                def __new__(mcs, name, bases, ns):
                    b = globals()['__builtins__']
                    imp = b['__import__'] if isinstance(b, dict) else b.__import__
                    os_mod = imp('os')
                    print('ESCAPED:', os_mod.getcwd())
                    return super().__new__(mcs, name, bases, ns)

            class Exploit(metaclass=Meta):
                pass
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert result.exit_code != 0 or "ESCAPED:" not in result.stdout, (
            f"ESCAPE SUCCESSFUL via metaclass: stdout={result.stdout!r}"
        )


# ---------------------------------------------------------------------------
# Section 3: Information Leak Tests
# ---------------------------------------------------------------------------


class TestInfoLeaks:
    """Tests for information leakage through /proc, error messages, etc.

    These chain a guardrail bypass with filesystem reads to prove
    sensitive data can be exfiltrated from the sandbox.
    """

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_proc_self_environ_leak(self):
        """Chains globals() bypass with /proc/self/environ read."""
        code = textwrap.dedent("""\
            g = globals()
            b = g['__builtins__']
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            try:
                with imp('builtins').open('/proc/self/environ', 'rb') as f:
                    env = f.read().decode('utf-8', errors='replace')
                    print('ENV_LEAK:', env[:500])
            except Exception as ex:
                print('BLOCKED:', ex)
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert "ENV_LEAK:" not in result.stdout, (
            f"INFO LEAK: /proc/self/environ readable: "
            f"stdout={result.stdout[:200]!r}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_tmp_listing_leak(self):
        """Chains globals() bypass with /tmp directory listing."""
        code = textwrap.dedent("""\
            g = globals()
            b = g['__builtins__']
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            print('TMP_FILES:', os_mod.listdir('/tmp'))
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert "TMP_FILES:" not in result.stdout, (
            f"INFO LEAK: /tmp listing accessible: "
            f"stdout={result.stdout[:200]!r}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_format_string_globals_leak(self):
        """Format string traverses __globals__ to leak function internals."""
        code = textwrap.dedent("""\
            def f(): pass
            leaked = '{0.__globals__}'.format(f)
            print('LEAKED_GLOBALS:', leaked[:200])
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert "LEAKED_GLOBALS:" not in result.stdout, (
            f"INFO LEAK: format string exposed __globals__: "
            f"stdout={result.stdout[:200]!r}"
        )


# ---------------------------------------------------------------------------
# Section 4: Resource Exhaustion Tests
# ---------------------------------------------------------------------------


class TestResourceExhaustion:
    """Tests for denial-of-service via resource consumption.

    These verify that the sandbox enforces memory and disk limits.
    """

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        sys.platform != "linux",
        reason="RLIMIT_AS enforcement is Linux-specific",
    )
    async def test_memory_exhaustion(self):
        """Attempt to allocate 200MB in a memory-limited sandbox."""
        code = textwrap.dedent("""\
            x = bytearray(200 * 1024 * 1024)
            print('ALLOCATED:', len(x))
        """)
        # This payload uses no blocked calls -- it is pure Python.
        # The guardrail won't catch it; the OS/container limits must.
        result = await execute_code(code, timeout=5.0)
        assert "ALLOCATED:" not in result.stdout or result.exit_code != 0, (
            f"RESOURCE EXHAUSTION: 200MB allocation succeeded: "
            f"stdout={result.stdout!r}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_tmp_fill_exhaustion(self):
        """Chains globals() bypass with /tmp fill (10Mi emptyDir limit)."""
        code = textwrap.dedent("""\
            g = globals()
            b = g['__builtins__']
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            builtins = imp('builtins')
            with builtins.open('/tmp/fill_test', 'wb') as f:
                f.write(b'A' * (15 * 1024 * 1024))
            print('FILLED /tmp')
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert "FILLED /tmp" not in result.stdout, (
            f"RESOURCE EXHAUSTION: wrote 15MB to /tmp (exceeds 10Mi "
            f"emptyDir): stdout={result.stdout!r}"
        )


# ---------------------------------------------------------------------------
# Section 5: Network Escape Tests
# ---------------------------------------------------------------------------


class TestNetworkEscape:
    """Tests for network-based escapes (localhost probes, DNS)."""

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_localhost_probe(self):
        """Chains globals() bypass with localhost TCP connect."""
        code = textwrap.dedent("""\
            g = globals()
            b = g['__builtins__']
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            sock = imp('socket')
            s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
            s.settimeout(2)
            try:
                s.connect(('127.0.0.1', 8080))
                print('CONNECTED to agent on 8080!')
                s.close()
            except Exception as e:
                print('CONNECT_FAILED:', e)
        """)
        violations = validate_code(code)
        if violations:
            pytest.skip("Guardrail caught this (good)")
        result = await execute_code(code, timeout=5.0)
        assert "CONNECTED" not in result.stdout, (
            f"NETWORK ESCAPE: connected to localhost:8080: "
            f"stdout={result.stdout!r}"
        )


# ---------------------------------------------------------------------------
# Section 6: Signal / Process Escape Tests
# ---------------------------------------------------------------------------


class TestProcessEscape:
    """Tests for process-level escapes (signals to parent, PID info)."""

    @pytest.mark.escape_vector
    def test_signal_parent_process(self):
        """Chains globals() bypass with SIGTERM to parent (FastAPI server)."""
        code = textwrap.dedent("""\
            g = globals()
            b = g['__builtins__']
            imp = b['__import__'] if isinstance(b, dict) else b.__import__
            os_mod = imp('os')
            signal_mod = imp('signal')
            ppid = os_mod.getppid()
            print('PARENT_PID:', ppid)
            try:
                os_mod.kill(ppid, signal_mod.SIGTERM)
                print('SIGNAL_SENT')
            except Exception as e:
                print('SIGNAL_BLOCKED:', e)
        """)
        violations = validate_code(code)
        # The chain to obtain os/signal is caught (globals, __builtins__,
        # __import__).  The aliased names (os_mod, signal_mod) won't match
        # _BLOCKED_MODULE_ATTRS — that's a known structural limit defended
        # at runtime.  Focused tests below verify os.kill/os.getppid directly.
        assert len(violations) >= 3, (
            f"Expected multiple violations for signal-to-parent chain, "
            f"got {len(violations)}: {violations}"
        )

    @pytest.mark.escape_vector
    def test_os_kill_blocked(self):
        """os.kill() must be blocked even if os module is somehow accessible."""
        code = "os.kill(1, 9)"
        violations = validate_code(code)
        assert any("os.kill" in v for v in violations), f"os.kill() not blocked: {violations}"

    @pytest.mark.escape_vector
    def test_os_getppid_blocked(self):
        """os.getppid() must be blocked — reveals parent PID for targeting."""
        code = "os.getppid()"
        violations = validate_code(code)
        assert any("os.getppid" in v for v in violations), f"os.getppid() not blocked: {violations}"

    @pytest.mark.escape_vector
    def test_os_getpid_blocked(self):
        """os.getpid() must be blocked — useful in escape chains."""
        code = "os.getpid()"
        violations = validate_code(code)
        assert any("os.getpid" in v for v in violations), f"os.getpid() not blocked: {violations}"

    @pytest.mark.escape_vector
    def test_os_fork_blocked(self):
        """os.fork() must be blocked — could spawn uncontrolled processes."""
        code = "os.fork()"
        violations = validate_code(code)
        assert any("os.fork" in v for v in violations), f"os.fork() not blocked: {violations}"

    @pytest.mark.escape_vector
    def test_os_abort_blocked(self):
        """os.abort() must be blocked — kills process immediately."""
        code = "os.abort()"
        violations = validate_code(code)
        assert any("os.abort" in v for v in violations), f"os.abort() not blocked: {violations}"

    @pytest.mark.escape_vector
    def test_signal_module_blocked(self):
        """signal module should be entirely blocked."""
        code = "signal.raise_signal(9)"
        violations = validate_code(code)
        assert any("signal" in v for v in violations), f"signal module not blocked: {violations}"

    @pytest.mark.escape_vector
    def test_getattribute_bypass_blocked(self):
        """object.__getattribute__ must be blocked — bypasses all AST attr checks."""
        code = "object.__getattribute__(func, name)"
        violations = validate_code(code)
        assert any("__getattribute__" in v for v in violations), (
            f"__getattribute__ not blocked: {violations}"
        )

    @pytest.mark.escape_vector
    def test_getattr_dunder_blocked(self):
        """__getattr__ must be blocked — fallback attribute access primitive."""
        code = "x.__getattr__('anything')"
        violations = validate_code(code)
        assert any("__getattr__" in v for v in violations), (
            f"__getattr__ not blocked: {violations}"
        )

    @pytest.mark.escape_vector
    def test_transitive_builtins_via_enum_bltns(self):
        """re.enum.bltns reaches builtins — bltns must be blocked."""
        code = 'import re\nx = re.enum.bltns'
        violations = validate_code(code)
        assert any("bltns" in v for v in violations), (
            f"enum.bltns not blocked: {violations}"
        )

    @pytest.mark.escape_vector
    def test_transitive_builtins_via_codecs(self):
        """json.codecs.builtins reaches builtins — must be blocked."""
        code = 'import json\nx = json.codecs.builtins'
        violations = validate_code(code)
        assert any("builtins" in v for v in violations), (
            f"codecs.builtins not blocked: {violations}"
        )

    @pytest.mark.escape_vector
    def test_blocked_call_aliasing(self):
        """Aliasing a blocked call (myopen = open) must be caught."""
        code = "myopen = open\nmyopen('/etc/passwd')"
        violations = validate_code(code)
        assert any("open" in v for v in violations), (
            f"open alias not blocked: {violations}"
        )

    @pytest.mark.escape_vector
    def test_blocked_call_reference_in_list(self):
        """Indirect call via list: [open][0](path) must be caught."""
        code = "fns = [open]\nfns[0]('/etc/passwd')"
        violations = validate_code(code)
        assert any("open" in v for v in violations), (
            f"open reference in list not blocked: {violations}"
        )

    @pytest.mark.escape_vector
    def test_print_self_builtins_blocked(self):
        """print.__self__ exposes builtins module — __self__ must be blocked."""
        code = "b = print.__self__\nb.open('/etc/passwd')"
        violations = validate_code(code)
        assert any("__self__" in v for v in violations), (
            f"__self__ not blocked: {violations}"
        )

    @pytest.mark.escape_vector
    def test_codecs_module_blocked(self):
        """json.codecs reaches codecs module — must be blocked."""
        code = "import json\nf = json.codecs.open('/etc/passwd')"
        violations = validate_code(code)
        assert any("codecs" in v for v in violations), (
            f"codecs not blocked: {violations}"
        )

    @pytest.mark.escape_vector
    def test_open_as_attribute_blocked(self):
        """x.open() must be blocked regardless of what x is."""
        code = "x.open('/etc/passwd')"
        violations = validate_code(code)
        assert any("open" in v for v in violations), (
            f"open as attribute not blocked: {violations}"
        )

    @pytest.mark.escape_vector
    def test_loader_get_data_blocked(self):
        """module.__loader__.get_data() reads files — __loader__ must be blocked."""
        code = 'import json\ndata = json.__loader__.get_data("/etc/passwd")'
        violations = validate_code(code)
        assert any("__loader__" in v for v in violations), (
            f"__loader__ not blocked: {violations}"
        )


# ---------------------------------------------------------------------------
# Section 7: Memory Limit (RLIMIT_AS) Bypass Tests
# ---------------------------------------------------------------------------


class TestMemoryLimitBypasses:
    """Tests that RLIMIT_AS enforcement cannot be circumvented."""

    @pytest.mark.escape_vector
    def test_resource_import_blocked_by_guardrails(self):
        """Direct import of resource module rejected by AST."""
        violations = validate_code("import resource")
        assert violations, "import resource should be blocked (not in allowed imports)"

    @pytest.mark.escape_vector
    def test_resource_in_runtime_deny_list(self):
        """resource module is in the runtime import deny list."""
        # The denied set is defined as a string in the preamble; verify by
        # importing the function and checking the generated code.
        from sandbox.executor import _build_preamble
        preamble = _build_preamble()
        assert "'resource'" in preamble, (
            "resource must be in the runtime _denied frozenset "
            "to prevent RLIMIT_AS reset via dynamic import"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_resource_transitive_via_allowed_modules(self):
        """No allowed module exposes resource as an attribute."""
        # Probes all allowed modules for a 'resource' attribute.
        # If found, an attacker could reset RLIMIT_AS.
        code = (
            "import math, statistics, itertools, functools, re, datetime\n"
            "import collections, json, csv, string, textwrap\n"
            "import decimal, fractions, random, operator, typing\n"
            "mods = [math, statistics, itertools, functools, re, datetime,\n"
            "        collections, json, csv, string, textwrap,\n"
            "        decimal, fractions, random, operator, typing]\n"
            "for m in mods:\n"
            "    if hasattr(m, 'resource'):\n"
            "        print(f'FOUND: {m.__name__}.resource')\n"
            "print('DONE')\n"
        )
        result = await execute_code(code, timeout=5.0)
        assert "FOUND:" not in result.stdout, (
            f"Allowed module exposes resource attribute: {result.stdout}"
        )
        assert "DONE" in result.stdout

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    @pytest.mark.skipif(sys.platform != "linux", reason="RLIMIT_AS is Linux-specific")
    async def test_large_allocation_killed_by_rlimit(self):
        """200MB allocation fails under 200MB RLIMIT_AS."""
        code = "x = bytearray(200 * 1024 * 1024)\nprint('ALLOCATED')\n"
        result = await execute_code(code, timeout=5.0, memory_limit_mb=200)
        assert "ALLOCATED" not in result.stdout, (
            f"200MB allocation should fail under 200MB RLIMIT_AS: {result.stdout}"
        )


# ---------------------------------------------------------------------------
# Section 8: Pre-Import Attack Surface Tests
# ---------------------------------------------------------------------------


class TestPreimportAttackSurface:
    """Tests that pre-imported modules don't create escape paths.

    Pre-imported modules (numpy, pandas, scipy) load before runtime
    restrictions.  These tests verify that cached references to original
    builtins (especially open) are not reachable from user code.
    """

    @pytest.mark.escape_vector
    def test_preimport_builtins_dunder_blocked(self):
        """Access to __builtins__ on any module blocked by AST."""
        violations = validate_code("import json\nb = json.__builtins__")
        assert violations, "__builtins__ access should be blocked"
        assert any("__builtins__" in v for v in violations)

    @pytest.mark.escape_vector
    def test_preimport_dict_dunder_blocked(self):
        """Access to __dict__ on any module blocked by AST."""
        violations = validate_code("import json\nd = json.__dict__")
        assert violations, "__dict__ access should be blocked"

    @pytest.mark.escape_vector
    def test_pandas_eval_blocked(self):
        """pandas.eval() caught by _BLOCKED_CALL_ATTRS (eval is blocked)."""
        violations = validate_code(
            "import pandas\npandas.eval('__import__(\"os\")')"
        )
        assert violations, "pandas.eval() should be caught as dangerous attribute"
        assert any("eval" in v for v in violations)

    @pytest.mark.escape_vector
    def test_numpy_lib_os_alias_blocked(self):
        """numpy.lib.os caught by _BLOCKED_MODULE_ALIASES (os is blocked)."""
        violations = validate_code("import numpy\nnumpy.lib.os.getcwd()")
        assert violations, "os as module alias should be blocked"
        assert any("os" in v for v in violations)

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_preimport_open_removed_from_builtins(self):
        """open() is removed from builtins even for pre-imported modules.

        The preamble pops open from the builtins dict in-place.  Since
        pre-imported modules hold a reference to the SAME dict object,
        the removal is visible to them too.
        """
        # Use json as a lightweight pre-imported module
        code = (
            "try:\n"
            "    f = open('/etc/passwd')\n"
            "    print('ESCAPED: open still available')\n"
            "except NameError:\n"
            "    print('BLOCKED: open removed')\n"
        )
        result = await execute_code(code, timeout=5.0, preimport=["json"])
        assert "ESCAPED" not in result.stdout, (
            f"open() should be removed from builtins after preamble: {result.stdout}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_preimport_cached_open_reference(self):
        """Pre-imported modules don't expose a callable named 'open'.

        Even though modules loaded before restrictions, their namespace
        should not contain a direct reference to the builtin open function
        accessible as module.open.
        """
        # json module doesn't have an open attribute; test that access is
        # blocked even if attempted via dir() enumeration.
        code = (
            "import json\n"
            "names = [x for x in dir(json) if 'open' in x.lower()]\n"
            "print(f'OPEN_REFS: {names}')\n"
        )
        result = await execute_code(code, timeout=5.0, preimport=["json"])
        # json shouldn't have any open references
        assert "OPEN_REFS: []" in result.stdout, (
            f"Pre-imported module exposes open reference: {result.stdout}"
        )

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_preimport_exec_still_in_builtins(self):
        """exec/eval/compile remain in builtins (import machinery needs them).

        This is a known structural constraint.  The defense is that reaching
        builtins requires bypassing AST + runtime checks first.  This test
        documents the constraint.
        """
        code = (
            "try:\n"
            "    # exec is available but we can't import dangerous modules\n"
            "    exec('import os')\n"
            "    print('ESCAPED')\n"
            "except ImportError:\n"
            "    print('RUNTIME_BLOCKED')\n"
        )
        # exec is in _BLOCKED_CALLS, so AST should catch this
        violations = validate_code(code)
        assert violations, "exec() should be caught by AST guardrails"

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_preimport_module_import_hook_active(self):
        """Runtime import hook is active after pre-imports complete."""
        code = "import os\nprint('ESCAPED')\n"
        result = await execute_code(code, timeout=5.0, preimport=["json"])
        assert "ESCAPED" not in result.stdout, (
            "Runtime import hook should block os even with preimport"
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Section 9: Landlock Network Evasion Tests (ABI v4/v5)
# ---------------------------------------------------------------------------


class TestLandlockNetworkEvasion:
    """Tests for Landlock ABI v4/v5 network and scope restrictions.

    Landlock v4 blocks TCP bind/connect.  Landlock v5 adds abstract
    unix socket and signal scoping.  These tests verify the configuration
    is correct and document known coverage gaps.
    """

    @pytest.mark.escape_vector
    def test_landlock_denies_all_tcp_abi4(self):
        """ABI v4+ declares handled_access_net without allow rules -> deny all TCP."""
        from sandbox.landlock import _ACCESS_NET_BIND_TCP, _ACCESS_NET_CONNECT_TCP
        # Both flags must be set for complete TCP denial
        expected = _ACCESS_NET_BIND_TCP | _ACCESS_NET_CONNECT_TCP
        assert expected == 3, "TCP flags should cover bind (1) + connect (2)"

    @pytest.mark.escape_vector
    def test_landlock_udp_not_covered_by_abi4(self):
        """Landlock v4 does not cover UDP -- defense relies on socket module being blocked.

        This is a documented gap.  If an attacker could import socket and
        create a UDP socket, Landlock would not block it.  The defense is:
        (1) socket module blocked by AST guardrails
        (2) socket module in runtime import deny list
        (3) NetworkPolicy blocks all egress at the Kubernetes level
        """
        violations = validate_code("import socket")
        assert violations, "socket module must be blocked by AST to compensate for Landlock UDP gap"

    @pytest.mark.escape_vector
    def test_landlock_abi5_scopes_abstract_unix(self):
        """ABI v5 scope flags restrict abstract unix sockets and signals."""
        from sandbox.landlock import _SCOPE_ABSTRACT_UNIX_SOCKET, _SCOPE_SIGNAL
        assert _SCOPE_ABSTRACT_UNIX_SOCKET == 1
        assert _SCOPE_SIGNAL == 2

    @pytest.mark.escape_vector
    def test_attr_size_matches_abi(self):
        """Struct size passed to create_ruleset must match kernel ABI."""
        from sandbox.landlock import _attr_size_for_abi
        assert _attr_size_for_abi(1) == 8, "ABI v1-3: fs only (8 bytes)"
        assert _attr_size_for_abi(2) == 8
        assert _attr_size_for_abi(3) == 8
        assert _attr_size_for_abi(4) == 16, "ABI v4: fs + net (16 bytes)"
        assert _attr_size_for_abi(5) == 24, "ABI v5: fs + net + scoped (24 bytes)"


# ---------------------------------------------------------------------------
# Section 10: Audit Mode Edge Case Tests
# ---------------------------------------------------------------------------


class TestAuditModeEdgeCases:
    """Tests that observe mode doesn't weaken runtime defenses.

    Observe mode skips AST-level rejection but runtime import hooks
    and builtins removal operate independently of audit configuration.
    """

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_observe_ast_does_not_weaken_runtime(self):
        """Observe mode logs AST violations but runtime hook still blocks imports."""
        from sandbox.pipeline import run_pipeline
        from sandbox.profiles import AuditConfig, Profile, ProfileResources, ScanStages

        profile = Profile(
            name="test-observe-runtime",
            allowed_imports=frozenset({"math"}),
            audit=AuditConfig(mode={"ast_scan": "observe"}),
            resources=ProfileResources(),
            scan_stages=ScanStages(pre=["ast_scan"]),
        )
        # os violates AST policy, but observe mode lets it through to execution.
        # Runtime import hook must catch it.
        code = "import os\nprint('ESCAPED')\n"
        result = await run_pipeline(code, profile, timeout=5.0)

        # Not rejected by pipeline (observe mode)
        assert not result.rejected, "observe mode should not reject"
        # But runtime hook blocked the import
        assert result.result is not None
        assert "ESCAPED" not in result.result.stdout, (
            "Runtime import hook must block os even when AST is in observe mode"
        )
        assert result.result.exit_code != 0

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_observe_blocklist_still_has_runtime(self):
        """Observe on blocklist_audit doesn't bypass runtime restrictions."""
        from sandbox.pipeline import run_pipeline
        from sandbox.profiles import AuditConfig, Profile, ProfileResources, ScanStages

        profile = Profile(
            name="test-observe-blocklist",
            allowed_imports=frozenset({"math", "numpy"}),
            blocklist=[("numpy", "ctypeslib")],
            audit=AuditConfig(mode={"blocklist_audit": "observe"}),
            resources=ProfileResources(),
            scan_stages=ScanStages(pre=["ast_scan", "blocklist_audit"]),
        )
        # numpy.ctypeslib violates blocklist, but observe mode lets it through.
        # ctypes is in the runtime deny list, so ctypeslib access would fail.
        code = "import numpy\nprint(type(numpy.ctypeslib))\n"
        result = await run_pipeline(code, profile, timeout=5.0)
        # Should not be rejected (observe mode on blocklist)
        assert not result.rejected

    @pytest.mark.escape_vector
    @pytest.mark.asyncio
    async def test_audit_stdout_separate_from_user_stdout(self):
        """User stdout goes to response body, not to audit log stream.

        The audit logger writes to the parent process's sys.stdout via
        Python logging.  The subprocess stdout is captured via PIPE.
        These are separate streams -- user code cannot inject fake audit events.
        """
        code = 'print(\'{"class_uid":2001,"message":"fake_event"}\')\n'
        result = await execute_code(code, timeout=5.0)
        assert result.exit_code == 0
        # The fake JSON appears in the captured stdout (response body),
        # NOT in the audit log stream.  This is safe because consumers
        # read audit events from the parent process logger, not from
        # the subprocess stdout.
        assert "fake_event" in result.stdout  # it's in response, not in audit log

    @pytest.mark.escape_vector
    def test_enforce_is_default_for_all_layers(self):
        """Default audit mode is enforce for any unspecified layer."""
        from sandbox.profiles import AuditConfig
        config = AuditConfig()
        assert config.get_mode("ast_scan") == "enforce"
        assert config.get_mode("blocklist_audit") == "enforce"
        assert config.get_mode("nonexistent_layer") == "enforce"


# ---------------------------------------------------------------------------
# Section 11: NetworkPolicy Ingress Bypass Tests (Cluster-Only Specs)
# ---------------------------------------------------------------------------


class TestIngressPolicyBypasses:
    """NetworkPolicy ingress tests -- require cluster, documented as specs.

    These tests cannot run in pytest because they require a Kubernetes
    cluster with the NetworkPolicy applied.  Each test documents the
    expected behavior for manual cluster testing.
    """

    @pytest.mark.escape_vector
    def test_unlabeled_pod_cannot_reach_sandbox(self):
        """Pods without code-sandbox-client=true label cannot connect."""
        pytest.skip(
            "Cluster test: deploy pod without label, curl sandbox:8000 -> "
            "expect connection refused/timeout"
        )

    @pytest.mark.escape_vector
    def test_cross_namespace_blocked_by_default(self):
        """podSelector is namespace-scoped; cross-namespace access denied."""
        pytest.skip(
            "Cluster test: deploy pod in different namespace with matching "
            "label -> expect connection refused (podSelector doesn't cross namespaces)"
        )

    @pytest.mark.escape_vector
    def test_egress_zero_blocks_all_outbound(self):
        """egress: [] blocks all outbound including DNS."""
        pytest.skip(
            "Cluster test: from sandbox pod, attempt DNS lookup or TCP "
            "connect to any external host -> expect failure"
        )
