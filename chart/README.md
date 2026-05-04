# code-sandbox Helm Chart

Standalone chart for the code-sandbox FastAPI sidecar.  Install per-cluster
or per-namespace; pair with the workload that needs sandboxed execution.

```bash
helm install code-sandbox ./chart -f chart/values-standalone.yaml
```

See `chart/values.yaml` for the full set of tunables.

## Host Requirements

The container delivers Layers 1–3 of the sandbox (AST guardrails, runtime
preamble, subprocess isolation).  Layers 4–6 (Landlock, seccomp, container
hardening) depend on the worker node kernel and the cluster operator
configuration.  The sections below list the host-side prerequisites the
chart cannot enforce on its own.

### Linux kernel for Landlock

Landlock LSM v4 requires Linux 5.13+.  Red Hat ships Landlock backports in
RHEL 9.6+ / RHCOS 9.6+.  On older kernels the subprocess preamble logs a
warning and continues — Layers 1–3 still apply.

### CVE-2026-31431 — "Copy Fail" privilege escalation

Red Hat Security Bulletin: [RHSB-2026-02][rhsb] · CVE: [CVE-2026-31431][cve]
· CVSS 7.8 (Important) · `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
· CWE-1288.

The Linux kernel's `algif_aead` cryptographic interface contains an
incorrect in-place operation between source and destination data
mappings.  An unprivileged user can chain `AF_ALG` socket setup,
`sendmsg()` AAD writes, and `splice()` of a setuid binary's page-cache
pages to corrupt cached executables in memory and obtain root.  In a
multi-tenant cluster the shared host page cache makes pod-to-node escape
possible.

#### Red Hat product status (as of 2026-05-04)

| Product                         | Component   | State        | Errata               |
|---------------------------------|-------------|--------------|----------------------|
| Red Hat Enterprise Linux 9      | kernel      | Fixed        | RHSA-2026:13565      |
| Red Hat Enterprise Linux 9      | kernel-rt   | Affected     | none                 |
| Red Hat Enterprise Linux 8      | kernel      | Affected     | none                 |
| Red Hat Enterprise Linux 8      | kernel-rt   | Affected     | none                 |
| Red Hat Enterprise Linux 10     | kernel      | Affected     | none                 |
| Red Hat Enterprise Linux 6 / 7  | kernel      | Not affected | vulnerable code n/a  |
| OpenShift Container Platform 4  | rhcos       | Affected     | none                 |

Track [the CVE page][cve] for updates to RHCOS and the remaining kernel
streams.

#### Workload-side mitigation (this chart applies it automatically)

The subprocess seccomp BPF preamble (`sandbox/seccomp.py`) blocks
`socket()` — which denies `AF_ALG` along with every other socket family —
and `splice()`.  The container-level SeccompProfile
(`chart/templates/seccomp-profile.yaml`) also denies `splice()`.  Both
ship by default; no values override is required.  This is defense in
depth, not a replacement for the host fix.

#### Host-side mitigation (operator must apply per Red Hat guidance)

Red Hat's mitigation is a kernel boot argument set via MachineConfig.  The
`algif_aead` module is **builtin** on RHEL/RHCOS and cannot be blacklisted;
Red Hat's guidance is to disable the affected initcalls.  In order of
narrowest blast radius:

```text
initcall_blacklist=algif_aead_init
initcall_blacklist=af_alg_init
initcall_blacklist=crypto_authenc_esn_module_init
```

> Red Hat warning: "there may be performance impacts for modifying
> functionality that uses kernel cryptographic functions" (RHSB-2026-02).

For OpenShift fleets managed by Red Hat Advanced Cluster Management, an
example ACM Governance Policy is shipped in
[`chart/policies/copy-fail-mitigation-policy.yaml`](policies/copy-fail-mitigation-policy.yaml).
The policy is `remediationAction: inform` by default; switching it to
`enforce` deploys a `MachineConfig` that adds the boot argument and
**reboots all targeted nodes**.  Verbatim from Red Hat solution
[7142032][sol-acm].

#### Per-product mitigation references (Red Hat Customer Portal)

- RHEL: [solution 7141931][sol-rhel]
- OpenShift 4: [solution 7141979][sol-ocp]
- ROSA Classic / OpenShift Dedicated: [article 7141989][sol-rosa]
- Azure Red Hat OpenShift: [solution 7141990][sol-aro]
- ACM Governance Policy: [solution 7142032][sol-acm]

[rhsb]: https://access.redhat.com/security/vulnerabilities/RHSB-2026-02
[cve]: https://access.redhat.com/security/cve/cve-2026-31431
[sol-rhel]: https://access.redhat.com/solutions/7141931
[sol-ocp]: https://access.redhat.com/solutions/7141979
[sol-rosa]: https://access.redhat.com/articles/7141989
[sol-aro]: https://access.redhat.com/solutions/7141990
[sol-acm]: https://access.redhat.com/solutions/7142032
