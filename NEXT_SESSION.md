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

## Critical — fix before CTF (#13–#16)

### 2. #15 — Convert runtime import deny to allowlist
**Structural fix** that closes the entire class of "blocked by AST but not
runtime" vulnerabilities. Change `_denied` frozenset to `_allowed` frozenset
matching the AST import allowlist. The caller check already exempts non-main
callers, so stdlib internal imports still work — only the set being checked
changes. Closes the ForwardRef path and every future eval-in-different-context
path.

### 3. #14 — Runtime-patch operator.attrgetter for dunder rejection
Monkey-patch `operator.attrgetter` and `operator.methodcaller` in the
preamble to reject dunder patterns at runtime. The AST check only catches
literal string arguments; dynamic `chr()` construction is invisible to it.
Preamble wraps these functions to check for `__*__` patterns before calling
the originals.

### 4. #13 — Block typing.ForwardRef._evaluate + io.FileIO
Secondary defense-in-depth for the informed attacker's chain. Add `_evaluate`
and `FileIO` to `_BLOCKED_CALL_ATTRS`. Redundant once #15 lands but
defense-in-depth.

### 5. #16 — Tighten subprocess Landlock to exclude /opt/app-root
**Architectural improvement.** The subprocess should apply its own stricter
Landlock ruleset on top of the inherited one — no `/opt/app-root`, no `/etc`.
Even if all Python-level defenses are bypassed, the subprocess can't read
application files or mounted secrets. Landlock is additive: child processes
can restrict further but not relax. This makes the OS layer the true security
boundary, matching industry practice.

### After fixes: re-run both attackers to verify

### 6. #1 — CTF challenge (start date TBD)
Blocked on #13–#16. Once hardening is verified by re-running the AI red
team, set the date and announce.

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

## Completed this session (2026-04-21)

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
