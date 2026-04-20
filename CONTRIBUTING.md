# Contributing to code-sandbox

Thanks for your interest in contributing! This project is a code execution sandbox for AI agents with layered security isolation. Contributions range from security research (finding bypass vectors) to new features (profiles, guardrail rules, deployment targets).

## Getting started

1. Fork the repository
2. Clone your fork locally
3. Set up the development environment:
   ```bash
   cd code-sandbox
   make install    # creates .venv, installs editable + dev deps
   make test       # run the test suite
   make lint       # check code style
   ```
4. Create a branch for your change: `git checkout -b my-change`
5. Make your changes, with tests where applicable
6. Open a pull request against `main`

## Issue guidelines

Use the issue templates -- they exist to make triage faster for everyone.

**Bug reports** -- Include the exact code you submitted to `/execute`, the HTTP status and response body, the sandbox profile you were using, and what you expected to happen.

**Feature requests** -- Start with the problem, not the solution. "The sandbox blocks `numpy.ctypeslib` but my use case needs C-type interop" is more useful than "Add ctypeslib to the allowlist." We may solve the underlying problem differently than you expect.

**Escape vectors** (security findings) -- Include the exact Python payload, which defense layer was bypassed, what an attacker can do with the bypass, and a severity assessment. Minimal reproductions are strongly preferred over long exploit chains. See the dedicated section below.

Please search existing issues before opening a new one. If your issue is a duplicate, add context to the existing thread instead.

## Reporting security vulnerabilities

If you've found a way to bypass the sandbox guardrails or escape the execution environment, we want to hear about it.

### What qualifies

- **Guardrail bypass**: Code that passes AST validation but shouldn't (e.g., accessing blocked modules or builtins)
- **Sandbox escape**: Code that achieves file access, network access, or command execution outside the sandbox
- **Information leak**: Code that reveals secrets, environment variables, or sensitive internal paths
- **Denial of service**: Code that crashes the sandbox process or exhausts container resources

### How to report

For CTF-style findings and general security research: use the **Escape Vector** issue template. These are public by design -- the whole point is collaborative hardening.

For vulnerabilities that affect production deployments and should not be disclosed publicly: use [GitHub Security Advisories](https://github.com/fips-agents/code-sandbox/security/advisories/new) for private reporting.

### What makes a good security report

- **Minimal reproduction** -- the shortest possible code that demonstrates the issue
- **Clear explanation** -- which layer was bypassed and why the check missed it
- **Severity assessment** -- what can an attacker actually achieve with this bypass?
- **Suggested fix** -- optional but appreciated; even a sketch helps

## Commit messages

Use [conventional commits](https://www.conventionalcommits.org/):

- `feat: add new profile for financial computation`
- `fix: block __loader__ attribute traversal`
- `security: close typing.get_type_hints eval bypass`
- `docs: document seccomp profile deployment`
- `test: add escape vector test for format string traversal`
- `chore: update UBI base image to 9.5`

The commit body should explain the *why* behind the change, not just the *what*.

## Pull requests

- Keep PRs focused. One feature or fix per PR; split large changes into reviewable pieces.
- Include tests for new behavior. Security fixes must include an escape vector test proving the bypass is now blocked.
- Run `make test && make lint` before pushing.
- Link related issues in the PR description (`Closes #123`).
- CI must be green before merge.

## Code style

- Python, async throughout
- Line length: 100 characters (enforced by ruff)
- Follow existing patterns in the codebase -- read the file you're changing before modifying it
- Run `make lint` to check; `ruff check --fix` for auto-fixable issues

## Architecture overview

Understanding the security layers helps you contribute effectively:

1. **AST guardrails** (`guardrails.py`) -- Static analysis of Python code before execution. Import allowlist, blocked calls/dunders/attrs, subscript checks, format string checks.
2. **Runtime preamble** (`executor.py`) -- Injected before user code at execution time. Import denylist with caller check, module reference purge.
3. **Subprocess isolation** (`executor.py`) -- `python3 -I`, temp file cleanup, output capping, wall-clock timeout.
4. **Landlock LSM** (`landlock.py`) -- Kernel-level filesystem restrictions. Read-only except `/tmp`.
5. **Seccomp** (`chart/`) -- Syscall filtering via Security Profiles Operator.
6. **Container hardening** (`chart/`, `Containerfile`) -- Read-only rootfs, non-root, all caps dropped, NetworkPolicy zero egress.

When adding a guardrail rule, add it to the AST layer first (good error messages), then consider whether runtime defense-in-depth is needed.

## Adding a new profile

Profiles define which Python modules are allowed and what attribute-level restrictions apply.

1. Create `sandbox/profiles/my-profile.yaml` following the structure of `minimal.yaml`
2. If the profile needs pip packages, create `sandbox/profiles/my-profile-requirements.txt`
3. Test: `make build PROFILE=my-profile`
4. Add integration tests exercising the new module set

## Community norms

- Be kind, be direct, assume good intent.
- Technical disagreements are welcome; personal attacks are not.
- Security research is encouraged -- breaking the sandbox to make it stronger is the whole point.
- Credit others' work. If you build on someone else's finding, reference their issue.
- Don't submit issues or PRs generated entirely by AI without review. If you used AI assistance, review and understand the output before submitting.

## Questions

Open an issue with the `question` label, or reach out via the contact in [SECURITY.md](SECURITY.md) for anything sensitive.
