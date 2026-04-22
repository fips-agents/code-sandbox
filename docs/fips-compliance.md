# FIPS 140-3 Compliance

**Date:** 2026-04-22
**Cluster:** fips-rhoai (RHEL 9 CoreOS, kernel `fips=1`)
**OpenSSL:** 3.5.1 (FIPS provider)
**Python:** 3.11.13 on UBI 9

## Overview

FIPS 140-3 mandates validated cryptographic modules for federal systems. When deploying code-sandbox on a FIPS-enabled OpenShift cluster, the RHEL kernel enforces FIPS mode system-wide: OpenSSL's FIPS provider activates automatically, Python's `hashlib` delegates to it, and non-approved algorithms are blocked at the library level.

The sandbox itself performs no cryptographic operations in user-facing code paths. Its FIPS surface area is limited to TLS termination (handled by OpenShift/ingress) and the `random` module's DRBG (backed by `os.urandom`, which uses the kernel's FIPS-approved CSPRNG).

## Prerequisites

1. **FIPS-enabled nodes** -- RHEL 9 or CoreOS with kernel boot parameter `fips=1`
2. **Red Hat UBI base images** -- The Containerfile already uses `registry.redhat.io/ubi9/python-311`
3. **OpenShift cluster** -- TLS termination at the route/ingress layer uses the node's FIPS-validated OpenSSL

Verify FIPS is active on cluster nodes:

```bash
oc debug node/<node-name> -- chroot /host cat /proc/sys/crypto/fips_enabled
# Expected: 1
```

## Validated Crypto Algorithms

Tested on the fips-rhoai cluster by instantiating each algorithm via `hashlib.new()` with both `usedforsecurity=True` (default) and `usedforsecurity=False`.

| Algorithm | `usedforsecurity=True` | `usedforsecurity=False` | Notes |
|-----------|----------------------|------------------------|-------|
| md5       | BLOCKED              | Available              | Non-approved; checksums only |
| sha1      | Available            | Available              | HMAC/legacy approved |
| sha256    | Available            | Available              | Primary hash |
| sha384    | Available            | Available              | |
| sha512    | Available            | Available              | |
| sha3_256  | Available            | Available              | SHA-3 family |
| blake2b   | BLOCKED              | Available              | Non-approved; checksums only |

"BLOCKED" means `hashlib.new(name)` raises `ValueError: [digital envelope routines] unsupported` under the FIPS provider. Passing `usedforsecurity=False` bypasses the FIPS check for non-security uses (e.g., cache keys, checksums).

## TLS Configuration

OpenSSL 3.5.1 in FIPS mode exposes 21 cipher suites, all AEAD (GCM or CCM):

```
TLSv1.3:
  TLS_AES_128_GCM_SHA256    TLS_AES_256_GCM_SHA384    TLS_AES_128_CCM_SHA256

TLSv1.2:
  DHE-PSK-AES128-CCM              DHE-PSK-AES128-GCM-SHA256
  DHE-PSK-AES256-CCM              DHE-PSK-AES256-GCM-SHA384
  DHE-RSA-AES128-CCM              DHE-RSA-AES128-GCM-SHA256
  DHE-RSA-AES256-CCM              DHE-RSA-AES256-GCM-SHA384
  ECDHE-ECDSA-AES128-CCM          ECDHE-ECDSA-AES128-GCM-SHA256
  ECDHE-ECDSA-AES256-CCM          ECDHE-ECDSA-AES256-GCM-SHA384
  ECDHE-RSA-AES128-GCM-SHA256     ECDHE-RSA-AES256-GCM-SHA384
  PSK-AES128-CCM                   PSK-AES128-GCM-SHA256
  PSK-AES256-CCM                   PSK-AES256-GCM-SHA384
```

Protocol enforcement:

- **Minimum:** TLS 1.2
- **Maximum:** TLS 1.3
- **Negotiated (default):** TLS_AES_128_GCM_SHA256
- **TLS 1.1:** Correctly rejected (`ssl.SSLError: [SSL: NO_PROTOCOLS_AVAILABLE]`)

The sandbox container does not terminate TLS itself. TLS is handled by the OpenShift route or ingress controller, which inherits the node's FIPS-validated OpenSSL.

## Sandbox-Specific Considerations

**hashlib is not accessible from user code.** The `hashlib` module is not on any profile's import allowlist. User-submitted code cannot import it, so FIPS hash restrictions have no effect on sandbox execution.

**`random` module uses FIPS-approved DRBG.** `random.random()`, `random.randint()`, etc. seed from `os.urandom()`, which calls `getrandom(2)` backed by the kernel's FIPS-validated DRBG. This works without modification.

**Data-science libraries are unaffected.** numpy, pandas (when available), scipy, and all stdlib modules (math, json, statistics, datetime, collections, itertools) operate normally under FIPS. These libraries do not invoke FIPS-restricted crypto paths during typical data processing.

## What's NOT Affected

The following sandbox isolation layers have no cryptographic dependencies and are unaffected by FIPS mode:

- **AST guardrails** -- Pure Python AST analysis, no crypto
- **Runtime preamble** -- Import deny/module purge, no crypto
- **Subprocess isolation** -- `python3 -I` with timeout, no crypto
- **Landlock LSM** -- Kernel filesystem restriction via `landlock_*` syscalls
- **Seccomp profile** -- Syscall filtering via BPF, no crypto
- **Container hardening** -- Read-only rootfs, dropped capabilities, no crypto

## Known Limitations

1. **md5 and blake2b** are unavailable for security purposes (`usedforsecurity=True`). This does not affect the sandbox since `hashlib` is blocked by guardrails, but it matters if you extend the service itself to use these algorithms.
2. **Performance** -- FIPS-validated crypto modules may be slightly slower than non-FIPS equivalents. This is negligible for the sandbox's use case.
3. **pandas** -- pandas works under FIPS (validated with pandas 3.0.2 on fips-rhoai). Earlier `six` compatibility issues are resolved.

## Verification Steps

To re-run FIPS validation on a cluster, use the Helm chart's FIPS test job:

```bash
# Enable and run the FIPS validation job
helm upgrade <release> chart/ --set fipsValidation.enabled=true

# Check results
oc logs job/<release>-code-sandbox-fips-test -n <namespace>

# Clean up
helm upgrade <release> chart/ --set fipsValidation.enabled=false
```

Or run checks manually from a pod on FIPS-enabled nodes:

```bash
# Verify kernel FIPS mode
cat /proc/sys/crypto/fips_enabled
# Expected: 1

# Check OpenSSL FIPS provider
python3 -c "import ssl; ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); print('Ciphers:', len(ctx.get_ciphers())); print('Min:', ctx.minimum_version); print('Max:', ctx.maximum_version)"

# Test hash availability
python3 -c "
import hashlib
for alg in ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'sha3_256', 'blake2b']:
    for sec in [True, False]:
        try:
            hashlib.new(alg, usedforsecurity=sec)
            print(f'{alg:10s} usedforsecurity={sec!s:5s} OK')
        except Exception as e:
            print(f'{alg:10s} usedforsecurity={sec!s:5s} BLOCKED')
"

# Verify TLS 1.1 rejection
python3 -c "
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
try:
    ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    print('WARNING: TLS 1.1 not rejected')
except Exception:
    print('TLS 1.1 correctly rejected')
"
```
