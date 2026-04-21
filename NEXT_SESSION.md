# Next Session

## Completed this session (2026-04-20)

- **#2** — AST guardrails hardened: blocked process signals, `__getattribute__`/
  `__getattr__`/`__self__`/`__loader__`/`__func__`/`__wrapped__`, builtins/bltns/
  codecs/io/pathlib/tempfile aliases, call aliasing, `open` as universal attribute,
  runtime builtins purge. Haiku failed to escape after 5 rounds (75+ techniques).
- **#5** — SeccompProfile CRD shipped in Helm chart (v0.6.0). Deployed to both
  code-sandbox-agent and ecosystem-test namespaces. SCC updated with profile
  paths and RoleBinding for ecosystem-test.
- **#7** — ToolInspector implemented: 5 scan categories (secrets, SQL injection,
  path traversal, C2 patterns, prompt injection), shared patterns module, 26 tests.

## Medium priority

### 1. #3 — Application-level memory limit
Use `resource.setrlimit(RLIMIT_AS)` in the subprocess to limit memory below
the 256Mi cgroup threshold. Convert `test_memory_exhaustion` from xfail to
passing.

### 2. #4 — pandas/six compatibility
The runtime import hook blocks `builtins` imports, breaking pandas via its
`six` dependency. Evaluate allowing `builtins` imports from non-`__main__`
callers, or pre-importing pandas before applying the hook.

### 3. #8 — Structured audit trail + enforce/observe mode
OCSF-compatible structured logging for all security decisions. Per-layer
enforce/observe toggle. JSON to stdout for OpenShift log collection.

### 4. #6 — Landlock LSM wrapper (UNBLOCKED — OCP 4.20)
Research is complete, `sandbox/landlock.py` exists. Production-ready it with
runtime ABI detection, graceful degradation, and env var gate. Clusters are
on OCP 4.20 (RHEL 9.6+ kernel, Landlock ABI 5 enabled by default).

## Low priority

### 5. #9 — NetworkPolicy manifest in Helm chart
Already enforced on cluster. Package in the chart for portability.

## Not on the board but tracked

- #1 — CTF challenge (running April 22-29)
- #10 — Sandbox-as-wrapper pattern (security proxy for untrusted agents)

## OpenShell upstream — waiting for feedback

- NVIDIA/OpenShell#899 — Platform mode / restricted SCC support
- NVIDIA/OpenShell#900 — FIPS 140-3 compliance path
- Pending: K3s decoupling issue (file after feedback on #899/#900)
- Next step after feedback: start vouch process for PR contributions
