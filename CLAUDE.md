# CLAUDE.md

This is the code-sandbox project -- a standalone code execution sandbox for AI agents.

## What This Is

A FastAPI sidecar that validates and executes LLM-generated Python code under 6 layers of isolation:

1. **AST guardrails** -- import allowlist, blocked calls/dunders/attrs, subscript/name checks
2. **Runtime preamble** -- import denylist, module reference purge
3. **Subprocess isolation** -- `python3 -I`, temp file cleanup, output capping, timeout
4. **Landlock LSM** -- filesystem read-only except /tmp (Linux 5.13+, RHEL 9.6+)
5. **Seccomp profile** -- dangerous syscall blocking (via Security Profiles Operator)
6. **Container hardening** -- read-only rootfs, non-root, all caps dropped, NetworkPolicy zero egress

## Repository Structure

```
sandbox/                  # Python package
  app.py                  # FastAPI endpoints: /healthz, /profile, /execute
  guardrails.py           # AST-based code validation (single-pass visitor)
  executor.py             # Subprocess execution with runtime preamble
  pipeline.py             # Multi-stage pipeline orchestration
  landlock.py             # Linux Landlock LSM integration (ctypes)
  profiles.py             # Profile loading (minimal, data-science)
  profiles/               # YAML profile definitions + pip requirements
tests/                    # pytest test suite (8 files, ~190 tests)
docs/                     # Security research and pentest report
chart/                    # Helm chart for standalone deployment
Containerfile             # Red Hat UBI 9 Python 3.11
```

## Key Architecture Decisions

- **Profile-driven**: Import allowlists and blocklists are defined in YAML, not hardcoded
- **Defense-in-depth**: Each layer operates independently; removing one still leaves 5 others
- **Graceful degradation**: Landlock/seccomp are optional (log and continue if unavailable)
- **Immutable images**: Code, tools, profiles all baked in. Only env vars are external.

## Development

```bash
make install    # Create venv, install deps
make test       # Run tests
make lint       # Ruff check
make run        # Local dev server (port 8000)
make build      # Build container (minimal profile)
make build PROFILE=data-science  # Build with profile
```

## Testing

- `tests/test_guardrails.py` -- AST validation rules
- `tests/test_executor.py` -- Subprocess execution, timeout, output capping
- `tests/test_escape_vectors.py` -- Red-team tests (41 escape vector probes)
- `tests/test_integration.py` -- End-to-end realistic scenarios + edge cases
- `tests/test_pipeline.py` -- Multi-stage pipeline
- `tests/test_profiles.py` -- Profile loading and inheritance
- `tests/test_landlock.py` -- Landlock LSM (skipped on non-Linux)
- `tests/test_app.py` -- HTTP endpoint tests

## Common Mistakes to Avoid

- Do not add modules to the import allowlist without checking their transitive dependencies
- Do not remove builtins in the runtime preamble (breaks Python import machinery)
- Module attribute references (e.g. `random._os`) must be blocked in BOTH AST and runtime
- The `typing.get_type_hints` eval path bypasses AST -- runtime import deny is the defense
