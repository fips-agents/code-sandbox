# Separate-Pod Sandbox Deployment (ADR)

**Status**: Accepted
**Issue**: code-sandbox#18

## Context

The sandbox currently runs either standalone (its own Deployment) or as a sidecar container in the agent pod. When running as a sidecar:

- Shares the pod's network namespace — code that escapes Python defenses could reach the agent's network listeners
- Shares pod resource limits — a runaway subprocess could starve the agent
- Shares blast radius — a compromised sandbox is in the same pod as the agent
- Seccomp profiles set at pod level apply to both agent and sandbox containers

The standalone pattern is already proven (CTF eval deployment). The question was whether to formalize it as the recommended production pattern.

## Decision

**Standalone Deployment (separate pod) is the recommended production deployment.** Sidecar mode remains supported for development and simple single-agent clusters.

## Alternatives Considered

**Job-per-execution**: A Kubernetes Job for each code execution. Maximum isolation (dedicated pod, destroyed after). Rejected due to pod startup latency (1-5 seconds per execution) and operational complexity (RBAC, Job lifecycle, log retrieval). May be revisited as an Execution Ladder Tier 4 (agent-template#69).

**Enhanced sidecar**: Tighten the sidecar with container-level seccomp. Does not solve the fundamental problem: shared network namespace and blast radius. The subprocess BPF filter already provides kernel-level seccomp in the subprocess.

**Unix socket sidecar**: Replace HTTP with a Unix domain socket on a shared emptyDir. Eliminates networking syscalls from the sandbox container. Rejected as niche — Option A solves the problem more completely. Could be revisited for latency-sensitive sidecar deployments.

## Deployment Tiers

Maps to the Execution Ladder concept (agent-template#69):

| Tier | Model | Latency | Isolation | Use |
|------|-------|---------|-----------|-----|
| 2 | Sidecar | ~50ms | Landlock + seccomp BPF + import hook | Dev, demos |
| 3 | Standalone | ~51ms | Full pod isolation + NetworkPolicy | Production |
| 4 | Ephemeral Job | 1-5s | Dedicated pod, destroyed after | Aspirational |

The agent doesn't know or care whether the sandbox is a sidecar or separate pod — it calls `POST {SANDBOX_URL}/execute` either way.

## Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│   Agent Pod          │         │   Sandbox Pod        │
│                      │  HTTP   │                      │
│  ┌────────────────┐  │ ──────► │  ┌────────────────┐  │
│  │ Agent container │  │ :8000  │  │ FastAPI/uvicorn │  │
│  │                 │  │         │  │                 │  │
│  │ SANDBOX_URL=    │  │         │  │ ┌────────────┐ │  │
│  │ http://sandbox  │  │         │  │ │ python3 -I │ │  │
│  │ .ns.svc:8000   │  │         │  │ │ (preamble) │ │  │
│  └────────────────┘  │         │  │ └────────────┘ │  │
│                      │         │  └────────────────┘  │
│  Labels:             │         │                      │
│   code-sandbox-      │         │  SecurityContext:     │
│   client: "true"     │         │   non-root, ro rootfs │
│                      │         │   caps: drop ALL      │
│                      │         │   seccomp: custom SPO  │
│                      │         │                      │
│                      │         │  NetworkPolicy:       │
│                      │         │   egress: [] (zero)   │
│                      │         │   ingress: client     │
│                      │         │   label only          │
└─────────────────────┘         └─────────────────────┘
```

## NetworkPolicy

The existing chart NetworkPolicy works unchanged:

- **Ingress**: Only pods with label `code-sandbox-client: "true"` on port 8000/TCP
- **Egress**: `[]` (zero outbound)
- **Cross-namespace**: Override via `networkPolicy.ingressFrom` with `namespaceSelector`

## Agent-Template Changes (future session)

The agent-template Helm chart needs:

1. New `sandbox.external` values block:
```yaml
sandbox:
  enabled: false          # sidecar mode (existing)
  external:
    enabled: false        # standalone mode
    url: ""               # e.g., http://code-sandbox.sandbox-ns.svc:8000
```

2. Conditional `SANDBOX_URL` env var in deployment template
3. Conditional `code-sandbox-client: "true"` label on agent pod
4. Mutual exclusion: `sandbox.enabled` and `sandbox.external.enabled` cannot both be true

No code changes needed in the `code_executor` tool — it already uses `SANDBOX_URL`.

## Seccomp Tightening

The container-level seccomp profile now blocks io_uring (setup, enter, register). uvicorn on RHEL 9 uses epoll, not io_uring. This removes a known container escape vector class at the container level. The subprocess BPF filter also blocks these — defense-in-depth.

Networking syscalls remain ALLOWED at the container level (uvicorn needs them). The subprocess BPF filter blocks them at the kernel level for executed code.

## Migration Path

1. Deploy sandbox standalone: `helm install code-sandbox ./chart -f chart/values-standalone.yaml`
2. Verify health: `curl http://code-sandbox.<ns>.svc:8000/healthz`
3. Update agent values: set `sandbox.external.enabled=true`, `sandbox.external.url=...`
4. Redeploy agent — sidecar is removed, agent calls external sandbox
5. Sidecar mode remains available for dev/simple deployments

## Related Issues

- code-sandbox#18 — This ADR
- code-sandbox#10 — Sandbox-as-wrapper (security proxy for untrusted agents)
- agent-template#69 — Execution Ladder concept
- agent-template#66 — Code-as-tool pattern
- agent-template#76 — Multi-provider LLM adapter (affects sandbox URL routing)
