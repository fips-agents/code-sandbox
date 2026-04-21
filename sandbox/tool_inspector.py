"""Tool call argument inspector for LLM agent safety.

Scans tool call arguments for secrets, C2 patterns, prompt injection,
SQL injection, and path traversal before execution.  Standalone library --
not coupled to FastAPI or the code execution pipeline.

Usage::

    from sandbox.tool_inspector import ToolInspector

    inspector = ToolInspector()
    violations = inspector.scan("execute_sql", {"query": "DROP TABLE users"})
"""

from __future__ import annotations

import re
from collections.abc import Generator

from sandbox.patterns import _PATH_TRAVERSAL_RE, _SECRET_PATTERNS, _SQL_KEYWORD_RE

# -- C2 / shell-injection patterns -------------------------------------------

_SUSPICIOUS_SCHEME_RE: re.Pattern[str] = re.compile(
    r"(?:data|javascript|file|gopher|dict):", re.IGNORECASE,
)
# High-confidence shell injection indicators only.  Bare ; and | are
# too noisy in prose/URLs.  Backticks, &&, and $() are reliable.
_SHELL_METACHAR_RE: re.Pattern[str] = re.compile(
    r"\w\s*;\s*\w|\w\s*&&\s*\w|`[^`]+`|\$\(",
)
# Detects base64 blobs (64+ chars) either standalone or embedded.
_BASE64_PAYLOAD_RE: re.Pattern[str] = re.compile(
    r"[A-Za-z0-9+/]{64,}={0,2}",
)

# -- Prompt-injection heuristic -----------------------------------------------

_PROMPT_INJECTION_RE: re.Pattern[str] = re.compile(
    r"(?:ignore\s+(?:previous|above|all)\s+instructions"
    r"|you\s+are\s+now"
    r"|disregard\s+(?:previous|prior|all)"
    r"|new\s+instructions"
    r"|forget\s+(?:everything|all|your)"
    r"|override\s+(?:previous|system)"
    r"|system\s*:\s*you)",
    re.IGNORECASE,
)

# -- Interpolation markers that distinguish dynamic SQL from static SQL -------

_SQL_INTERPOLATION_RE: re.Pattern[str] = re.compile(r"%[sd]|\{|\$\{|\$\(")

# Truncation limit for matched text shown in violation messages.
_MATCH_DISPLAY_LIMIT = 40


def _truncate(text: str) -> str:
    """Truncate *text* to at most *_MATCH_DISPLAY_LIMIT* characters."""
    if len(text) <= _MATCH_DISPLAY_LIMIT:
        return text
    return text[:_MATCH_DISPLAY_LIMIT - 3] + "..."


class ToolInspector:
    """Scans tool call arguments for security violations."""

    def scan(self, tool_name: str, arguments: dict[str, object]) -> list[str]:
        """Scan tool arguments and return a list of violation strings.

        Parameters
        ----------
        tool_name:
            Name of the tool being invoked (for future per-tool policy;
            currently unused but part of the public interface).
        arguments:
            Arbitrary nested dict of argument values to inspect.

        Returns
        -------
        list[str]
            Human-readable violation descriptions.  Empty means clean.
        """
        violations: list[str] = []
        for path, value in self._walk_strings(arguments):
            violations.extend(self._check_secrets(path, value))
            violations.extend(self._check_sql_injection(path, value))
            violations.extend(self._check_path_traversal(path, value))
            violations.extend(self._check_c2_patterns(path, value))
            violations.extend(self._check_prompt_injection(path, value))
        return violations

    # -- recursive string walker ----------------------------------------------

    @staticmethod
    def _walk_strings(
        obj: object, prefix: str = "",
    ) -> Generator[tuple[str, str], None, None]:
        """Yield ``(path, value)`` for every string in a nested structure."""
        if isinstance(obj, dict):
            for key, val in obj.items():
                child_path = f"{prefix}.{key}" if prefix else str(key)
                yield from ToolInspector._walk_strings(val, child_path)
        elif isinstance(obj, (list, tuple)):
            for idx, val in enumerate(obj):
                child_path = f"{prefix}[{idx}]"
                yield from ToolInspector._walk_strings(val, child_path)
        elif isinstance(obj, str):
            yield prefix, obj

    # -- individual scan categories -------------------------------------------

    @staticmethod
    def _check_secrets(path: str, value: str) -> list[str]:
        if len(value) < 16:
            return []
        for name, pattern in _SECRET_PATTERNS:
            m = pattern.search(value)
            if m:
                return [
                    f"Argument '{path}': {name} detected "
                    f"(matched: '{_truncate(m.group())}')"
                ]
        return []

    @staticmethod
    def _check_sql_injection(path: str, value: str) -> list[str]:
        m = _SQL_KEYWORD_RE.search(value)
        if not m:
            return []
        if not _SQL_INTERPOLATION_RE.search(value):
            return []
        return [
            f"Argument '{path}': potential SQL injection "
            f"(matched: '{_truncate(m.group())}')"
        ]

    @staticmethod
    def _check_path_traversal(path: str, value: str) -> list[str]:
        m = _PATH_TRAVERSAL_RE.search(value)
        if not m:
            return []
        return [
            f"Argument '{path}': path traversal detected "
            f"(matched: '{_truncate(m.group())}')"
        ]

    @staticmethod
    def _check_c2_patterns(path: str, value: str) -> list[str]:
        violations: list[str] = []
        m = _SUSPICIOUS_SCHEME_RE.search(value)
        if m:
            violations.append(
                f"Argument '{path}': suspicious URI scheme "
                f"(matched: '{_truncate(m.group())}')"
            )
        m = _SHELL_METACHAR_RE.search(value)
        if m:
            violations.append(
                f"Argument '{path}': shell meta-character detected "
                f"(matched: '{_truncate(m.group())}')"
            )
        if _BASE64_PAYLOAD_RE.search(value):
            violations.append(
                f"Argument '{path}': long base64 payload "
                f"(matched: '{_truncate(value)}')"
            )
        return violations

    @staticmethod
    def _check_prompt_injection(path: str, value: str) -> list[str]:
        if len(value) <= 20:
            return []
        m = _PROMPT_INJECTION_RE.search(value)
        if not m:
            return []
        return [
            f"Argument '{path}': prompt injection pattern "
            f"(matched: '{_truncate(m.group())}')"
        ]
