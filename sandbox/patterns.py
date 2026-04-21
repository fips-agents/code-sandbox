"""Shared regex patterns for security scanning.

These patterns are used by both the AST guardrails (compile-time code
validation) and the ToolInspector (runtime argument scanning).  Keeping
them in one place avoids drift between the two enforcement layers.
"""

from __future__ import annotations

import re

# Compiled regexes for credential / secret detection in string literals.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "generic secret assignment",
        re.compile(
            r"(?:api[_-]?key|api[_-]?secret|token|secret[_-]?key"
            r"|password|passwd|auth[_-]?token)"
            r"""\s*[:=]\s*['"][A-Za-z0-9+/=_-]{16,}['"]"""
        ),
    ),
    (
        "PEM private key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        # Known limitation: fires on git SHAs, UUIDs without hyphens, and
        # MD5 checksums. No entropy check — purely length-based.
        "high-entropy hex string",
        re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    ),
]

# SQL keyword pattern for injection detection.
_SQL_KEYWORD_RE: re.Pattern[str] = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION)\b",
    re.IGNORECASE,
)

# Path traversal pattern — any string containing "../".
# Known limitation: does not detect URL-encoded variants (%2e%2e%2f)
# or Windows-style (..\).
_PATH_TRAVERSAL_RE: re.Pattern[str] = re.compile(r"\.\./")
