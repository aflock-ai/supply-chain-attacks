# supply-chain-attacks

> A catalog of real-world software supply-chain attacks reproduced as safe harnesses, each with cilock detection demonstrated by live CI.

[![ci](https://github.com/aflock-ai/supply-chain-attacks/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/aflock-ai/supply-chain-attacks/actions/workflows/ci.yml)
[![docs](https://img.shields.io/badge/docs-cilock.aflock.ai-2e6cdf)](https://cilock.aflock.ai/tutorials/defending-against-supply-chain-attacks)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![cilock](https://img.shields.io/badge/built%20on-cilock-success)](https://github.com/aflock-ai/rookery)

Every entry in this repo is **a real attack, a safe synthetic reproduction of it, the [cilock](https://github.com/aflock-ai/rookery) policy that catches it, and a CI workflow that proves the policy works on every push**. No marketing claims — green badges or red badges, both auditable.

## The 7 attacks

| Date | Attack | Vector | Affected | Detection layer | Status |
|---|---|---|---|---|---|
| **2026-05-19** | [Nx Console VS Code extension](2026-05-nx-vscode/) | IDE extension scope abuse | `nrwl/nx-console`, 2.2M+ installs | Content (secretscan) + Behavior (trace) | 📋 documented, implementation pending |
| **2026-05-19** | [`actions-cool` hijack](2026-05-actions-cool-hijack/) | Imposter commits via stolen maintainer creds, secrets scraped from `/proc/<pid>/mem` | `actions-cool/*` Actions | Prevention (source policy) + Behavior (`/proc/*/mem` access) | ✅ **live detection** |
| **2026-05-19** | [Shai-Hulud npm worm](2026-05-shai-hulud-npm-worm/) | Self-replicating malware across published npm packages | dozens of npm packages | Content (secretscan on install scripts) + Behavior (`npm install` patterns) | 📋 documented, implementation pending |
| **2026-05-18** | [Microsoft `durabletask` PyPI trojan](2026-05-microsoft-durabletask-pypi/) | Trojanized release of a Microsoft-published PyPI package | `durabletask` on PyPI | Prevention (attestation policy requires upstream attestation) + Content (secretscan on `setup.py` / `.pth`) | 📋 documented, implementation pending |
| **2026-05-18** | [GitHub internal source disclosure](2026-05-github-source-disclosure/) | Data exposure / breach, GitHub's own source code | GitHub internal repos | N/A at runtime — cilock would have provided forensic attestations from affected build pipelines | 📋 documentation-only |
| **2026-03-24** | [LiteLLM `.pth` credential stealer](2026-03-litellm-pth-stealer/) | Python `.pth` file executed on every interpreter startup, sweeping creds | `litellm==1.82.7` and `1.82.8` on PyPI | Content (secretscan with recursive base64 decode) + Behavior (`/proc/self/environ` read) | 📖 see deep-dive walkthrough |
| **2026-03-19** | [Trivy tag rewrite](2026-03-trivy-tag-rewrite/) | 75/76 version tags force-pushed in `aquasecurity/trivy-action`, creds stolen from `/proc/<pid>/mem` | every pipeline pinning the action by tag | Prevention (SHA pinning enforced by policy) + Content + Behavior | 📖 [full deep-dive in `aflock-ai/cilock-trivy-detection-test`](https://github.com/aflock-ai/cilock-trivy-detection-test) |

## What this repo is

A working answer to the question every dev asks after a supply-chain incident: **"would my tooling have caught this?"**

For each catalogued attack, this repo ships:

1. **A README** with the timeline, IOCs, attribution, and the cilock detection mechanism that catches it.
2. **A safe synthetic payload** that reproduces the attack's syscalls / output patterns without any real exfiltration. No live secrets. No network beacons. No live malware.
3. **A signed cilock policy** ([OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)) that detects the attack at one or more of cilock's three defense layers.
4. **A live CI workflow** (`.github/workflows/detect-<attack>.yml`) that runs the payload through cilock with the policy on every push and turns the badge green or red. If it goes red, the detection broke and the README is now lying.

The harness shape is identical across attacks — the same `cilock run` + `cilock verify` pair, the same policy module structure, the same job matrix. Only the payload and the policy details change. That makes it cheap to add a new attack and trivial for a reader to compare detections across attacks.

## How detection works

Cilock catches supply-chain attacks at three independent layers, so an attacker has to bypass all three to succeed:

| Layer | What it does | Example detection in this repo |
|---|---|---|
| **1. Prevention** | Signed Rego policy restricts which actions, packages, and refs are allowed to run. Enforces SHA pinning. Untrusted refs never execute. | `actions-cool-hijack/policy-source-restrict.rego` denies `actions-cool/*` refs that aren't SHA-pinned |
| **2. Content detection** | The `secretscan` attestor runs Gitleaks on stdout and **recursively decodes** base64, hex, and URL-encoded payloads through three layers. Credential patterns trigger a build fail. | LiteLLM `.pth` stealer caught: the `__pycache__`-embedded payload is base64-encoded inside the bytecode; secretscan's recursive decoder unwraps it |
| **3. Behavioral detection** | The `--trace` flag (Linux only) ptraces the wrapped process and records every file each process opens. OPA Rego policies match credential-harvesting filesystem patterns. | `actions-cool-hijack/policy-trace-behavioral.rego` denies any process that reads `/proc/<pid>/mem` or `/proc/self/environ` — both are credential-harvesting fingerprints |

**Defense in depth is the point.** A single layer can be bypassed; three independent layers raise the cost to the attacker materially. Each attack catalogued here is annotated with which layers fire, so you can see what bypasses what.

## Reproduce any detection locally

The CI workflows run as-is on GitHub-hosted runners. To run any detection locally on Linux:

```bash
# Install cilock (one of):
curl -fsSL https://cilock.aflock.ai/install.sh | bash
# or
docker pull ghcr.io/aflock-ai/cilock:latest

# Pick an attack, run its payload through cilock with the policy:
cd 2026-05-actions-cool-hijack
cilock run \
  --step detect-actions-cool \
  --attestations secretscan git environment commandrun \
  --trace \
  --attestor-secretscan-fail-on-detection \
  --signer-fulcio-url https://fulcio.sigstore.dev \
  --signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com \
  --signer-fulcio-oidc-client-id sigstore \
  --timestamp-servers https://timestamp.sigstore.dev/api/v1/timestamp \
  --enable-archivista=false \
  --outfile attestation.json \
  -- bash payload.sh

# Verify against the policies (the detection layer that catches it):
cilock verify --policy policy-source-restrict.rego attestation.json
cilock verify --policy policy-trace-behavioral.rego attestation.json
```

If the policies detect the attack (and they should), `cilock run` exits non-zero and `cilock verify` reports the matching `deny` rules. That is the detection.

## How to add an attack to this catalog

Each subdirectory is independent. To add a new attack:

```
<date>-<slug>/
├── README.md                          # Timeline, IOCs, attribution, detection layer
├── payload.sh                          # Safe synthetic reproduction. NEVER include
│                                       # real secrets or live exfil URLs. Echo synthetic
│                                       # credential patterns + touch the same syscalls
│                                       # the real attack hits.
└── policy-<layer>.rego                 # One or more Rego policies that fire on the attack

.github/workflows/detect-<attack-name>.yml     # CI for this attack. Mirror the shape
                                                # of detect-2026-05-actions-cool-hijack.yml.
                                                # Lives at the repo root because GitHub
                                                # only discovers workflows there.
```

Open a PR; the top-level CI matrix automatically picks up the new directory. README's table needs a new row.

## Ethics + safety

Every payload in this repo is a synthetic reproduction. We exercise the same syscalls and content patterns the real attack used, but:

- **No real credentials.** Payloads echo strings shaped like AWS keys, GitHub PATs, RSA private keys — but the values are not real secrets and have never been valid.
- **No live exfiltration.** Payloads do not perform any network egress. No DNS queries. No HTTP. The behavior layer fires on filesystem access patterns, not on outbound traffic.
- **No malware redistribution.** We do not host copies of the real malware. The IOCs (file paths, package names, version numbers, hashes) are documented for forensic reference; the original sources cited in each attack's README are the place to obtain real samples if you have a legitimate research reason.

This repo is a **defensive demonstration**, not an offensive toolkit.

## Related

- **Cilock itself:** [aflock-ai/rookery](https://github.com/aflock-ai/rookery)
- **CI integration:** [aflock-ai/cilock-action](https://github.com/aflock-ai/cilock-action)
- **Trivy deep-dive (single-attack):** [aflock-ai/cilock-trivy-detection-test](https://github.com/aflock-ai/cilock-trivy-detection-test)
- **Docs:** [cilock.aflock.ai](https://cilock.aflock.ai) — three-layer model, attestor catalog, threat walkthrough
- **Commercial / managed:** [TestifySec Platform](https://testifysec.com/product)

## License

Apache 2.0 — see [LICENSE](LICENSE). Built and sponsored by [TestifySec](https://testifysec.com).
