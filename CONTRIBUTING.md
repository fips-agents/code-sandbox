# Contributing to code-sandbox

## Reporting Security Vulnerabilities

If you've found a way to bypass the sandbox guardrails or escape the execution environment, we want to hear about it! Use the **Escape Vector** issue template to report your finding.

### What qualifies as a vulnerability?

- **Guardrail bypass**: Code that passes AST validation but shouldn't (e.g., accessing blocked modules)
- **Sandbox escape**: Code that achieves file access, network access, or command execution
- **Information leak**: Code that reveals secrets, environment variables, or sensitive paths
- **Denial of service**: Code that crashes the sandbox or exhausts resources

### How to report

1. Go to [Issues](https://github.com/fips-agents/code-sandbox/issues/new/choose)
2. Select the **Escape Vector** template
3. Include the exact Python code that demonstrates the bypass
4. Describe what defense layer was bypassed and how

### What makes a good report?

- **Minimal reproduction** -- shortest possible code that demonstrates the issue
- **Clear explanation** -- which layer was bypassed and why
- **Severity assessment** -- what can an attacker actually DO with this bypass?
- **Suggested fix** -- optional but appreciated

## Development Setup

```bash
git clone https://github.com/fips-agents/code-sandbox.git
cd code-sandbox
make install
make test
```

## Pull Requests

1. Fork the repo and create a feature branch
2. Add tests for any new guardrail rules or security fixes
3. Run `make test && make lint` before submitting
4. PRs require CI to pass and one review approval
