# Next Session

## Completed this session (2026-04-21)

- **#3** — Application-level memory limit via `resource.setrlimit(RLIMIT_AS)`
  in subprocess preamble. `subprocess_memory_mb` added to ProfileResources
  (200 MB minimal, 800 MB data-science). `test_memory_exhaustion` converted
  from xfail to passing (skipif non-Linux).
- **#4** — pandas/six compatibility via pre-import mechanism. Profile `preimport`
  list runs before runtime restrictions are applied, so pandas/numpy/scipy load
  with full builtins (including `open`). Data-science profile declares preimport.
- **#6** — Landlock LSM production-ready for OCP 4.20 (ABI v5). Added ABI v4
  network restrictions (deny all TCP), ABI v5 scope restrictions (abstract unix
  sockets, signals). `_attr_size_for_abi()` sizes the struct correctly per ABI.
  `SANDBOX_LANDLOCK_EXTRA_RO` env var for runtime path injection.
- **#8** — OCSF structured audit trail (class_uid=2001). `sandbox/audit.py`
  emits JSON security findings to stdout. Per-layer enforce/observe mode via
  profile `audit.mode` config. Pipeline emits events for violations, timeouts,
  and OOM kills. Landlock startup events in app.py.
- **#9** — NetworkPolicy Ingress added to Helm chart. Default: only pods with
  `code-sandbox-client=true` label on port 8000. Configurable via
  `networkPolicy.ingressFrom` in values.yaml. Zero-egress unchanged.

## Completed previously (2026-04-20)

- **#2** — AST guardrails hardened (blocked signals, dunders, aliases, builtins
  purge). Haiku failed to escape after 5 rounds (75+ techniques).
- **#5** — SeccompProfile CRD shipped in Helm chart (v0.6.0).
- **#7** — ToolInspector implemented (5 scan categories, 26 tests).

## Not on the board but tracked

- #1 — CTF challenge (start date TBD — hardening #13-#16 first)
- #10 — Sandbox-as-wrapper pattern (security proxy for untrusted agents)

## OpenShell upstream — waiting for feedback

- NVIDIA/OpenShell#899 — Platform mode / restricted SCC support
- NVIDIA/OpenShell#900 — FIPS 140-3 compliance path
- Pending: K3s decoupling issue (file after feedback on #899/#900)
- Next step after feedback: start vouch process for PR contributions
