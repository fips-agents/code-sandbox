# Python Sandbox Landscape Analysis

Date: 2026-04-21
Context: Red team evaluation of code-sandbox found two independent escapes. This research
was conducted to understand how the industry handles Python sandboxing and whether
language-level restriction is architecturally viable.

## Conclusion

Language-level Python sandboxing is not a viable security boundary. Every production system
doing AI code execution uses OS-level isolation (microVMs, gVisor, nsjail). AST-based
restrictions are valuable as defense-in-depth but should not be the security boundary.

This matches our red team findings: both attackers escaped the Python-level defenses but
would have been stopped by a properly configured Landlock/seccomp layer.

## Industry Approaches

### PyPy Sandbox Mode

**Isolation**: Process-level RPC interception. A special PyPy build runs as a subprocess;
every syscall is serialized and sent to a parent controller process that decides whether
to allow it. No syscall reaches the kernel directly.

**Language restriction**: None. All Python code is allowed; the controller restricts what
the interpreter can *do*, not what the code *says*.

**Status**: Abandoned. The original sandbox was explicitly marked unmaintained. A sandbox-2
rewrite was sponsored by Anvil in 2019 but shows no evidence of active maintenance or
production adoption since then.

### RestrictedPython (Zope Foundation)

**Isolation**: Language-level. Compiles Python through a restricted AST transformer that
rewrites attribute access, subscript access, and imports into calls to guard functions
(`_getattr_`, `_getitem_`, `_getiter_`). Caller supplies the guards. Builtins replaced
with a `safe_builtins` dict.

**Language restriction**: Yes — this is the core mechanism. CPython only.

**Known bypasses**:
- CVE-2023-37271 (CVSS 9.8): Generator `gi_frame` -> `f_back` -> `f_builtins` ->
  `__import__`. Frame-walking escapes the sandbox because `gi_frame` and `f_back` don't
  start with `_` so the attribute guard didn't block them.
- CVE-2024-47532: `AttributeError.obj` leaked a reference to the underlying unrestricted
  module.
- Format string escape (2023): Format specs traverse object attributes, leaking data.

**Status**: Actively maintained (761 commits, recent CVE patches). Used in Plone/Zope for
through-the-web Python, but the Plone docs say "avoid through-the-web scripts if possible."
The security model is fundamentally fragile — same whack-a-mole pattern we're experiencing.

### Pyodide / WebAssembly

**Isolation**: WASM VM. CPython compiled to WebAssembly via Emscripten. The WASM VM
enforces memory isolation at the instruction level — modules cannot access host memory,
issue syscalls, or call host functions except through declared imports.

**Language restriction**: None. Python runs unrestricted; the sandbox boundary is the
WASM VM itself. File I/O must be supplied by the runtime. Network is unavailable or proxied.

**Known bypasses**:
- CVE-2025-68668 (CVSS 9.9): n8n ran Pyodide in a Node.js worker. A string manipulation
  exploit escaped Pyodide to reach the Node.js layer. Root cause: WASM only sandboxes
  *within* the module; if the host exposes dangerous capabilities (Node.js fs,
  child_process), those remain accessible via JS bridge calls.

**Status**: Production for client-side use cases (JupyterLite, Cloudflare Workers). For
server-side AI agent sandboxing, the host bridge bypass is a significant risk.

### gVisor (runsc)

**Isolation**: User-space application kernel. A Go process (the Sentry) intercepts all
syscalls before they reach the host kernel, implementing a Linux-like syscall interface
internally. Issues only ~53 host syscalls (no networking) or ~211 with networking. A
separate Gofer process mediates filesystem access over 9P protocol.

**Language restriction**: None. Language-agnostic. Python runs unmodified.

**Known limitations**: The Sentry is a large Go codebase; any bug in syscall emulation is
a potential escape. ~10-20% performance overhead vs native containers (improved with the
Systrap platform replacing ptrace in 2022).

**Status**: Production at Google scale. Used for Cloud Run and GKE Sandbox.

### Firecracker microVMs

**Isolation**: Hardware virtualization (KVM). Each workload runs in its own VM with a
dedicated guest kernel. The VMM is minimal (~50K lines of Rust vs ~1.4M for QEMU). The
Jailer wraps the VMM in seccomp-bpf + cgroups + chroot. Two isolation layers: VM boundary
+ Jailer.

**Language restriction**: None. Python runs unmodified inside the VM.

**Known limitations**: VM escape requires a guest kernel exploit or KVM hypervisor bug.
~125ms startup, supports 150 microVMs/second/host at <5MB overhead per VM.

**Status**: Battle-tested at massive scale by AWS Lambda and Fargate. E2B also uses
Firecracker as their sandbox backend.

### nsjail

**Isolation**: Linux kernel features composed: PID/mount/network/user/UTS/IPC namespaces,
cgroups v2, rlimits, and seccomp-bpf. Uses the Kafel BPF language for policy files. Single
binary, no daemon, ~<20ms startup.

**Language restriction**: None. Pure OS-level isolation.

**Known limitations**: Requires kernel support for unprivileged user namespaces. A
misconfigured seccomp policy reduces effective isolation.

**Status**: Production. Used by Google for CTF hosting (explicitly adversarial workloads).
The Morph LLM platform published a case study using nsjail for AI code execution in 2026.

### E2B

**Isolation**: Firecracker microVMs. Each sandbox gets its own VM with a separate kernel.
Starts in ~150ms. Custom VM images via Docker-based configuration.

**Language restriction**: None. Python runs unmodified inside the VM.

**Status**: Production. ~15 million sandbox sessions/month as of March 2025, ~50% of
Fortune 500 reportedly using it. Active commercial product (4,771 commits, 465 releases).

### OpenAI Code Interpreter

**Isolation**: Not officially disclosed. Described as "a fully sandboxed virtual machine."
Third-party analysis speculates gVisor. The Codex CLI uses platform-native sandboxing
(macOS Seatbelt, Linux bubblewrap).

**Language restriction**: Almost certainly none. Container or VM; Python runs unmodified.

**Status**: Production. Architecture undisclosed from a security research standpoint.

## Summary Table

| Approach | Isolation Layer | Language Restrictions | Production | Key Weakness |
|---|---|---|---|---|
| PyPy sandbox | Process RPC | None | No | Unmaintained since 2019 |
| RestrictedPython | Language (AST) | Yes | Limited | Recurring CVEs, fragile model |
| Pyodide/WASM | WASM VM | None | Client-side | Host bridge leakage on server |
| gVisor | User-space kernel | None | Yes (Google) | Sentry bugs, ~15% overhead |
| Firecracker | Hardware VM (KVM) | None | Yes (AWS) | Infra complexity |
| nsjail | Namespaces + seccomp | None | Yes (Google) | Config complexity |
| E2B | Firecracker + managed | None | Yes | Opaque, not self-hostable |
| OpenAI CI | Unknown (VM likely) | None | Yes | Architecture undisclosed |

## The Consensus on Language-Level Python Sandboxing

**Victor Stinner, pysandbox author (2013)**: Abandoned the project with
`WARNING: pysandbox is BROKEN BY DESIGN`. Conclusion: "Putting a sandbox in CPython is
the wrong design. There are too many ways to escape the untrusted namespace using the
various introspection features of the Python language." With 126K+ lines of C to audit, any
single bug is a full escape.

**The asteval escape research**: "Sandboxing CPython is a prayer without end" — the
language's introspection, continuous new features, and memory corruption bugs make it
architecturally resistant to language-level restriction.

**CVE patterns**: RestrictedPython has received regular CVEs since 2019 despite being one of
the most mature language-level sandboxes. Each fix closes one path, but generator frames,
exception objects, format strings, and module attributes keep yielding new ones.

**n8n's experience (2025-2026)**: After CVE-2025-68668 forced them off in-process Pyodide,
they rebuilt with an external Python process. Then CVE-2026-0863 hit the new design.
Different approach, same class of problem.

**Practical consensus**: Language-level Python sandboxing is not viable as a primary security
control. It can provide defense-in-depth — an additional layer that slows attackers and
handles unsophisticated code — but it is not a security boundary. The accepted answer is
OS-level sandboxing (seccomp, namespaces, gVisor, microVM).

## Implications for code-sandbox

Our 6-layer architecture is the right model. The correction needed is in emphasis:

1. **Layers 4-6 (Landlock, seccomp, NetworkPolicy)** should be the security boundary. A
   Python-level escape should not grant meaningful capability.

2. **Layers 1-3 (AST, runtime hooks, builtins removal)** are defense-in-depth. They provide
   clear error messages, catch accidental dangerous code, and raise the bar. But they are
   not the security guarantee.

3. **The subprocess needs its own Landlock ruleset** (#16). The current shared ruleset gives
   the subprocess read access to `/opt/app-root` (the app directory) because the FastAPI app
   needs it. Tightening the subprocess ruleset so it can only read `/usr`, `/lib`, `/tmp`
   makes Python-level escapes much less consequential.

4. **The runtime deny list should be an allowlist** (#15). This is still worth doing as
   defense-in-depth — it closes an entire class of bypass — even though the OS layer is
   the real boundary.

## References

- [PyPy Sandbox Documentation](https://doc.pypy.org/en/stable/sandbox.html)
- [PyPy Sandbox Second Life (2019)](https://pypy.org/posts/2019/08/a-second-life-for-sandbox-6848726729476245390.html)
- [RestrictedPython GitHub](https://github.com/zopefoundation/RestrictedPython)
- [CVE-2023-37271: RestrictedPython Stack Frame Escape](https://www.robertxiao.ca/research/cve-2023-37271/)
- [CVE-2024-47532 NVD Detail](https://nvd.nist.gov/vuln/detail/CVE-2024-47532)
- [asteval Sandbox Escape Research](https://radboudinstituteof.pwning.nl/posts/asteval_post_1/)
- [The Failure of pysandbox (LWN.net)](https://lwn.net/Articles/574215/)
- [pysandbox BROKEN BY DESIGN (GitHub)](https://github.com/vstinner/pysandbox)
- [Pyodide/LangChain Sandbox](https://github.com/langchain-ai/langchain-sandbox)
- [NVIDIA: Sandboxing Agentic AI with WebAssembly](https://developer.nvidia.com/blog/sandboxing-agentic-ai-workflows-with-webassembly/)
- [CVE-2025-68668: n8n Pyodide WASM Escape](https://dev.to/cverports/cve-2025-68668-n8n-sandbox-escape-when-python-breaks-the-wasm-wall-5ad3)
- [CVE-2026-0863: n8n Python Sandbox Escape](https://www.smartkeyss.com/post/cve-2026-0863-python-sandbox-escape-in-n8n-via-exception-formatting-and-implicit-code-execution)
- [gVisor Architecture Guide](https://gvisor.dev/docs/architecture_guide/intro/)
- [gVisor Security Basics](https://gvisor.dev/blog/2019/11/18/gvisor-security-basics-part-1/)
- [Firecracker microVMs](https://firecracker-microvm.github.io/)
- [How AWS Firecracker Works (Amazon Science)](https://www.amazon.science/blog/how-awss-firecracker-virtual-machines-work)
- [nsjail GitHub](https://github.com/google/nsjail)
- [nsjail for AI Code Execution (Morph)](https://www.morphllm.com/nsjail-sandbox)
- [E2B GitHub](https://github.com/e2b-dev/E2B)
- [Docker + E2B Architecture](https://www.docker.com/blog/docker-e2b-building-the-future-of-trusted-ai/)
- [OpenAI Code Interpreter API Docs](https://developers.openai.com/api/docs/guides/tools-code-interpreter)
- [OpenAI Codex Sandboxing](https://developers.openai.com/codex/concepts/sandboxing)
- [HackTricks Python Sandbox Bypasses](https://github.com/b4rdia/HackTricks/blob/master/generic-methodologies-and-resources/python/bypass-python-sandboxes/README.md)
- [CTF Wiki: Python Sandbox Escape](https://ctf-wiki.mahaloz.re/pwn/linux/sandbox/python-sandbox-escape/)
