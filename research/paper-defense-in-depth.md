# Defense in Depth for AI Code Execution: Why Python Sandboxing Fails and Kernel Enforcement Holds

## Status

- **Stage:** Research & validation
- **Target venues:** USENIX Security, IEEE S&P (workshop), arXiv preprint
- **Shorter versions:** Conference brief (4pp), blog post
- **Next steps:** Validate claims against counterpoints, survey additional projects, run controlled experiments with more models

---

## Abstract

Large language model agents increasingly require code execution capabilities,
yet no consensus exists on how to sandbox LLM-generated code safely. Industry
practice splits into two camps: language-level restriction (AST analysis,
import allowlists, builtin removal) and OS-level isolation (microVMs, gVisor,
containers). We present evidence that these approaches are complementary, not
alternatives, and that language-level Python sandboxing alone is not a viable
security boundary regardless of implementation sophistication.

We describe a six-layer defense-in-depth architecture for Python code execution
that combines AST guardrails, runtime import hooks, operator function patching,
and builtin removal (layers 1-4) with Linux Landlock LSM filesystem
restriction and seccomp-bpf syscall filtering (layers 5-6). Critically, the
architecture employs a two-layer Landlock strategy: the parent server process
applies a broad filesystem policy, while the code execution subprocess applies
a strictly tighter policy that drops access to application code and secrets.
This leverages Landlock's kernel-enforced ruleset intersection property --
child processes can restrict further but never relax inherited restrictions.

We evaluate this architecture using AI red team methodology: four independent
attack runs using frontier LLMs (Claude Opus 4.6 and Sonnet 4.6) as both
informed and blind attackers, totaling 298 distinct escape attempts. Every run
bypassed all Python-level defenses through three independently discovered
techniques: annotation evaluation via `typing.get_type_hints()`, dynamic
attribute traversal via `string.Formatter.get_field()`, and operator function
wrapper leakage. In every case, the kernel-level Landlock restriction blocked
the final file read with EACCES. We additionally evaluate three smaller open
models (8B-20B parameters) as attackers via an automated agent framework,
finding they lack the reasoning depth for Python sandbox escape in short
sessions but can successfully interact with the defense layers.

Our findings support the architectural principle that language-level Python
sandboxing serves as defense-in-depth -- raising the bar and providing clear
error diagnostics -- but the security boundary must be the OS kernel. The
two-layer Landlock pattern, which requires no root privileges and runs under
OpenShift's restricted-v2 security context, offers a practical middle ground
between heavyweight VM isolation and insufficient container-only approaches.
To our knowledge, no existing open-source AI code execution sandbox combines
language-level AST restrictions with kernel-level Landlock enforcement, and
the two-layer Landlock architecture for server/subprocess isolation is novel
in this domain.

---

## Outline

### 1. Introduction
- The code execution capability gap: LLM agents need to run code, but generated code is untrusted
- The false dichotomy: language-level sandboxing vs. OS-level isolation
- Contribution: defense-in-depth architecture with empirical AI red team evaluation
- Scope: Python specifically (most common LLM code generation target)

### 2. Background and Related Work
#### 2.1 Language-Level Python Sandboxing
- RestrictedPython (Zope): AST transformation with guard functions; recurring CVEs (2023-37271, 2024-47532)
- pysandbox: abandoned with "BROKEN BY DESIGN" (Stinner, 2013)
- smolagents (Hugging Face): AST walking with import allowlists; no kernel enforcement
- asteval: academic sandbox escape research ("sandboxing CPython is a prayer without end")
- Common failure mode: Python's introspection (object graph, frames, format strings, annotations) creates an unbounded attack surface

#### 2.2 OS-Level Isolation for Code Execution
- Firecracker microVMs (E2B, AWS Lambda): strongest isolation, highest overhead
- gVisor (Google Cloud Run, GKE Agent Sandbox): user-space kernel, ~15% overhead
- nsjail (Google CTF): namespaces + seccomp, no Landlock
- Bubblewrap (OpenAI Codex CLI, Anthropic sandbox-runtime): namespace isolation
- Sandlock: Landlock + seccomp, no language-level checks

#### 2.3 Landlock LSM
- Kernel filesystem and network restriction without root privileges
- ABI evolution: v1 (filesystem) through v5 (scope restrictions)
- Ruleset stacking: intersection semantics, one-way ratchet
- Adoption: limited in AI sandboxing despite being purpose-built for this

#### 2.4 AI Red Teaming for Security Evaluation
- Microsoft RedCodeAgent: automated red teaming for code agents
- CTF-style evaluation: informed vs. blind attacker methodology
- Gap: most AI red teaming targets prompt injection, not sandbox escape

### 3. Architecture
#### 3.1 Threat Model
- Untrusted Python code generated by an LLM agent
- Attacker goal: read sensitive files (application source, secrets, flags)
- Attacker capability: arbitrary Python source that must pass static analysis
- Defense goal: no file read outside allowed paths, no network exfiltration

#### 3.2 Layer 1: AST Guardrails
- Single-pass AST visitor: import allowlist, blocked calls/dunders/attrs
- Module alias blocking (random._os, statistics.sys)
- Format string scanning, subscript key checking
- String literal matching against blocked attribute names

#### 3.3 Layer 2: Runtime Import Hook
- Allowlist-based __import__ replacement
- Caller identity check (__name__ == '__main__')
- Builtin removal (open, breakpoint, input)
- Module reference purging (random._os)

#### 3.4 Layer 3: Operator Function Patching
- Closure-based wrappers for attrgetter/methodcaller
- Runtime dunder pattern rejection
- Why closures, not classes (slot leakage finding)

#### 3.5 Layer 4: Subprocess Isolation
- python3 -I (isolated mode), temp file execution
- RLIMIT_AS memory cap, output capping, timeout

#### 3.6 Layer 5: Two-Layer Landlock
- Parent process: broad policy (app readable for serving)
- Subprocess preamble: tighter policy (drops /opt/app-root, /etc)
- Intersection semantics: child can never exceed parent
- Graceful degradation: E2BIG fallback, libc.so.6 fallback
- No root required: works under OpenShift restricted-v2 SCC

#### 3.7 Layer 6: Seccomp + Container Hardening
- Custom SeccompProfile CRD via Security Profiles Operator
- Read-only rootfs, all caps dropped, NetworkPolicy zero egress

### 4. Evaluation: AI Red Team
#### 4.1 Methodology
- Two attacker profiles: informed (full defense knowledge) and blind (reconnaissance-first)
- Two frontier models: Claude Opus 4.6 and Sonnet 4.6
- Structured output format: per-attempt JSON with category, technique, result, analysis
- Minimum 30 distinct techniques per run
- Safety constraints: no DoS, no fork bombs

#### 4.2 Results: Python-Level Escapes
##### 4.2.1 typing.get_type_hints annotation evaluation
- String annotations evaluated via eval() bypass AST entirely
- exec() + __name__ spoofing defeats import hook
- Discovered independently by both Opus (blind) and Sonnet (informed)

##### 4.2.2 string.Formatter.get_field object graph traversal
- getattr() with user-controlled attribute names, returns actual objects
- Dynamic dunder construction via chr() bypasses AST string checks
- Full class hierarchy traversal: __class__ -> object -> __subclasses__()
- Discovered by Opus (informed)

##### 4.2.3 Operator wrapper _inner slot leakage
- Class-based wrapper stored original attrgetter in accessible __slots__
- type(instance._inner) recovered the unpatched class
- Fixed by switching to closure-based wrappers
- Discovered by Sonnet (informed v2)

#### 4.3 Results: Landlock Holds
- Every Python-level escape achieved arbitrary module imports (os, ctypes, subprocess)
- Every file read attempt returned EACCES (errno 13)
- Tested vectors: os.open, io.open, ctypes libc.open, direct SYS_open syscall,
  O_PATH + openat, /proc/self/root traversal, compiled C binary, mmap,
  numpy.fromfile, subprocess cat, new thread, symlink creation
- All blocked by Landlock at kernel level

#### 4.4 Results: Small Model Attackers
- Granite 3.3 8B, Gemma 4 E4B, GPT-OSS 20B via automated agent framework
- All successfully used code execution tool
- None progressed past Layer 1 (AST guardrails) in short sessions
- Validates that defense-in-depth raises the bar even without kernel enforcement

### 5. Discussion
#### 5.1 Why Language-Level Sandboxing Fails
- Python's introspection surface is unbounded
- Every new CPython feature potentially introduces bypass paths
- Format strings, annotations, descriptors, class machinery: each is an attack surface
- The "whack-a-mole" pattern: patching one escape reveals another

#### 5.2 Why Kernel Enforcement Holds
- Landlock operates at syscall level — independent of Python runtime
- No amount of Python cleverness changes what the kernel allows
- Intersection semantics prevent privilege escalation
- Minimal kernel attack surface (vs. full VM escape)

#### 5.3 The Defense-in-Depth Argument
- Language-level restrictions still have value:
  - Clear error messages for legitimate mistakes
  - Audit trail of what was attempted
  - Raises the bar (8B models can't escape; frontier models need 30-150 attempts)
  - Reduces kernel attack surface by limiting what code runs
- But they must not be the security boundary

#### 5.4 Two-Layer Landlock: Design Rationale
- Why the parent needs broader access (serving, health checks, module loading)
- Why the subprocess needs tighter access (untrusted code)
- The pre-import ordering: heavy libraries load before Landlock tightens
- Deployment gotchas: seccomp must allow Landlock syscalls, E2BIG on RHEL backports, find_library failures in isolated mode

#### 5.5 Limitations
- Landlock does not restrict stat/chmod/access — metadata leakage possible
- UDP not blocked by Landlock v4 (only TCP)
- 16-ruleset stacking limit
- Kernel bugs in Landlock itself would be a full escape
- Evaluation limited to Claude and three small models; other frontier models not tested

### 6. Conclusion
- Language-level Python sandboxing is defense-in-depth, not a security boundary
- Two-layer Landlock provides practical kernel enforcement without VMs
- AI red teaming is an effective methodology for sandbox validation
- Open-source implementation available (link to repo)

### Appendices
- A: Full attacker runner documents (informed + blind)
- B: Per-attempt results from all four frontier model runs
- C: Sandbox profile YAML examples
- D: Helm chart and deployment configuration

---

## Research Notes: Validated Findings

### Industry survey (validated 2026-04-22)

**Two-layer Landlock:**
- Kernel docs explicitly support stacking up to 16 rulesets with intersection semantics
- Sandlock (multikernel.io, March 2026) confirms nesting works natively
- No production AI sandbox found using parent/child Landlock tightening
- OpenAI Codex CLI uses Landlock as fallback behind bubblewrap, single layer
- Anthropic sandbox-runtime uses bubblewrap, no Landlock
- nsjail (Google) predates Landlock, uses namespaces + seccomp
- Bubblewrap has open PRs for Landlock support (not merged)

**Combined AST + kernel sandboxing:**
- smolagents (Hugging Face): AST only, explicitly says "no local sandbox can be completely secure"
- Sandlock: kernel only, no language-level checks
- OpenAI Codex: kernel only (bubblewrap + seccomp + Landlock-fallback)
- OpenEdx/codejail: AppArmor only
- Andrew Healey: seccomp only, explicitly rejected AST approach
- dida.do: gVisor only
- **No project found combining both AST and kernel enforcement**

**AI red teaming for sandbox escape:**
- Microsoft RedCodeAgent: automated, more sophisticated but targets code agents generally
- Promptfoo/DeepTeam: focus on prompt injection, not sandbox escape
- Our informed/blind methodology with structured JSON output appears novel for sandbox-specific evaluation

### To validate in future sessions

- [ ] Check if Cisco, NVIDIA, or other large vendors have adopted two-layer Landlock (search corporate engineering blogs, patents)
- [ ] Check Google's GKE Agent Sandbox for Landlock usage (it uses gVisor, but may layer Landlock too)
- [ ] Verify Sandlock's claimed performance characteristics (sub-1ms overhead)
- [ ] Check if any academic papers cover Landlock stacking for defense-in-depth
- [ ] Survey Kata Containers and Confidential Containers for Landlock integration
- [ ] Check CNCF sandbox/incubation projects for Landlock adoption
- [ ] Review Landlock mailing list archives for discussion of two-layer patterns
- [ ] Test with additional frontier models: GPT-4o, Gemini 2.5, Llama 4, Mistral Large
- [ ] Run longer sessions (50+ iterations) with small models to see if they can escape Layer 1
- [ ] Measure performance overhead of the six layers (latency per layer)
- [ ] Compare our approach against smolagents + E2B as a baseline

### Key references

**Python sandboxing failures:**
- Victor Stinner, pysandbox "BROKEN BY DESIGN" (2013): https://github.com/vstinner/pysandbox
- CVE-2023-37271 RestrictedPython gi_frame escape: https://www.robertxiao.ca/research/cve-2023-37271/
- CVE-2024-47532 RestrictedPython AttributeError.obj leak
- CVE-2025-68668 n8n Pyodide WASM escape
- asteval escape research: https://radboudinstituteof.pwning.nl/posts/asteval_post_1/

**OS-level isolation:**
- Landlock kernel docs: https://docs.kernel.org/userspace-api/landlock.html
- Sandlock: https://multikernel.io/2026/03/14/introducing-sandlock/
- OpenAI Codex linux-sandbox: https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md
- Anthropic sandbox-runtime: https://github.com/anthropic-experimental/sandbox-runtime
- GKE Agent Sandbox: https://github.com/kubernetes-sigs/agent-sandbox

**Industry landscape:**
- E2B: https://github.com/e2b-dev/E2B
- Hugging Face smolagents: https://huggingface.co/docs/smolagents/en/tutorials/secure_code_execution
- Northflank sandbox comparison: https://northflank.com/blog/best-code-execution-sandbox-for-ai-agents
- NVIDIA code execution risks: https://developer.nvidia.com/blog/how-code-execution-drives-key-risks-in-agentic-ai-systems/
- Securing AI Agent Execution (arXiv): https://arxiv.org/pdf/2510.21236

**AI red teaming:**
- Microsoft RedCodeAgent: https://www.microsoft.com/en-us/research/blog/redcodeagent-automatic-red-teaming-agent-against-diverse-code-agents/
- HackTricks Python sandbox bypasses: https://github.com/b4rdia/HackTricks
- CTF Wiki Python sandbox escape: https://ctf-wiki.mahaloz.re/pwn/linux/sandbox/python-sandbox-escape/
