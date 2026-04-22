# Next Session

## Red team results (2026-04-21)

Two AI attackers (Sonnet informed, Opus blind) both escaped and read the flag
independently. Both exploits are now documented as issues with proposed fixes.

**Informed attacker** (Sonnet, 27 attempts): `typing.ForwardRef._evaluate()`
calls `eval()` with `__name__ == 'typing'`, bypassing the `__main__` caller
check. Then imports `io` (not in runtime deny list) and uses `io.FileIO` to
read the flag. Root cause: runtime deny list is a denylist, not an allowlist.

**Blind attacker** (Opus, 32 attempts): `operator.attrgetter()` with
`chr()`-constructed dunder strings bypasses AST check entirely. Traverses
`(1).__class__.__base__.__subclasses__()` → `os._wrap_close` →
`__init__.__globals__` → `os.open()` + `os.read()`. Root cause: AST can't
inspect runtime string values.

**Key architectural insight**: Language-level Python sandboxing is not a viable
security boundary (consensus from pysandbox author, RestrictedPython CVE
history, and industry practice). Every production system — E2B, AWS Lambda,
Google Cloud Run — uses OS-level isolation. Our AST guardrails are valuable
as defense-in-depth but the real enforcement must come from Landlock/seccomp.

## Foundational

### 1. #11 — Formalize FIPS 140-3 compliance validation
CI FIPS test job on RHEL 9 FIPS node, crypto algorithm inventory, deployment
guide section. No code changes to the sandbox — testing and documentation
gap. Should run first (or in parallel with #15–#16) because FIPS compliance
is a platform property that all other work builds on. If we harden the
sandbox but break FIPS mode, we've built on sand.

## Next up

### 1. Re-run both AI red team attackers to verify fixes
All four critical fixes (#13–#16) are now implemented. Re-run the informed
(Sonnet) and blind (Opus) attackers against the hardened sandbox to verify
the escape vectors are closed before announcing the CTF.

### 2. #1 — CTF challenge (start date TBD)
Blocked on red team re-verification. Once both attackers fail to escape,
set the date and announce.

## Medium priority

### 7. #10 — Sandbox-as-wrapper pattern
Security proxy for untrusted agents. Reverse proxy that intercepts tool
calls, validates against policy, blocks dangerous operations. Separate
capability from the code execution sandbox. Design is sketched in the issue.

## Low priority

### 8. #12 — IronBank base image for STIG compliance
Parameterize BASE_IMAGE in Containerfile, validate against IronBank Python
3.11, document the swap procedure. No urgency — driven by future DoD
deployment requirements.

## Completed this session (2026-04-21, second pass)

- **#13** — Block typing.ForwardRef._evaluate + io.FileIO in AST guardrails
- **#14** — Runtime-patch operator.attrgetter/methodcaller for dunder rejection
- **#15** — Convert runtime import deny list to allowlist (structural fix)
- **#16** — Subprocess Landlock: drops /opt/app-root and /etc
- Updated test_escape_vectors resource test for allowlist model
- 22 new tests (298 total, all passing)

## Completed this session (2026-04-21, first pass)

- **#3** — Memory limit via RLIMIT_AS (200 MB minimal, 800 MB data-science)
- **#4** — pandas/six pre-import compatibility
- **#6** — Landlock production-ready (ABI v4 TCP deny, v5 scope)
- **#8** — OCSF structured audit trail + enforce/observe mode
- **#9** — NetworkPolicy ingress in Helm chart
- Added `resource` to runtime deny list (seccomp allows prlimit64)
- 24 new red team tests (Tier 1: memory, pre-import, Landlock, audit, ingress)
- 2 AI red team runner docs (Tier 2: informed + blind attacker)
- Ran both Tier 2 attackers — both escaped, findings filed as #13, #14

## Completed previously (2026-04-20)

- **#2** — AST guardrails hardened
- **#5** — SeccompProfile CRD in Helm chart
- **#7** — ToolInspector (5 scan categories, 26 tests)

## OpenShell upstream — waiting for feedback

- NVIDIA/OpenShell#899 — Platform mode / restricted SCC support
- NVIDIA/OpenShell#900 — FIPS 140-3 compliance path
- Pending: K3s decoupling issue (file after feedback on #899/#900)
