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

## Red team re-verification results (2026-04-21)

Blind attacker (Opus) found a new Python-level escape variant:
`typing.get_type_hints()` → `eval()` string annotation → `exec()` with
`__name__` spoofed to `'typing'` → import hook bypassed → any module
importable → `io.open('/opt/app-root/flag.txt')`.

**Python-level defenses bypassed, but Landlock blocked the flag read.**
`[Errno 13] Permission denied: '/opt/app-root/flag.txt'`

Three deployment issues discovered and fixed during verification:
1. Seccomp profile missing Landlock syscalls (444-446)
2. RHEL 9.6 ABI v5 struct E2BIG — fallback to size 16 needed
3. `find_library('c')` returns None in `python3 -I` — `libc.so.6` fallback

**Architectural validation**: The defense-in-depth model works. Python
sandboxing is not a reliable boundary (as predicted), but the kernel-level
Landlock restriction is. The subprocess Landlock drops `/opt/app-root` and
`/etc`, making the flag unreadable even with full Python escape.

## Next up

### 1. Re-run informed attacker (Sonnet) against correct endpoint
The informed attacker hit the wrong URL during this session. Re-run against
the direct sandbox route:
`https://code-sandbox-direct-code-sandbox-agent.apps.cluster-l78nk.l78nk.sandbox1834.opentlc.com`

### 2. Consider blocking typing.get_type_hints at AST level
The `get_type_hints` → `eval()` path is a known Python-level escape that
bypasses AST guardrails via string annotations. Adding `get_type_hints` to
`_BLOCKED_CALL_ATTRS` would close this as defense-in-depth. Not critical
(Landlock is the real boundary) but reduces the attack surface.

### 3. #1 — CTF challenge (start date TBD)
Landlock-verified. Python-level escapes exist but kernel blocks the flag.
Decide: is the CTF about escaping Python guardrails (easy) or reading the
flag (requires Landlock bypass, much harder)?

### 4. Clean up temporary route
`code-sandbox-direct` service/route was created for testing. Either keep
it for the CTF or remove it after.

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

## Completed this session (2026-04-21, third pass — deployment verification)

- Landlock seccomp syscalls added to SeccompProfile CRD
- E2BIG fallback for RHEL 9.6 kernel Landlock struct size mismatch
- `libc.so.6` fallback for `find_library('c')` in isolated mode
- Parent Landlock TCP deny moved to subprocess-only (parent needs TCP for uvicorn)
- Updated informed attacker doc for all new defenses
- Containerfile: glob `sandbox/*.py` instead of explicit file list
- Verified on fips-rhoai: Landlock ABI v5 active, flag blocked at kernel level

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
