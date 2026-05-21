# LiteLLM `.pth` credential stealer (2026-03-24)

> Status: **📋 documented, implementation pending.** This catalog entry summarizes the attack and the detection mechanism. A dedicated harness for the `.pth` vector is a follow-up PR.

## Timeline

| When | What |
|---|---|
| **2026-03-24** | `litellm==1.82.7` shipped to PyPI with a credential stealer hidden in a `.pth` file. |
| **2026-03-24, hours later** | `1.82.8` followed with the same payload (and minor obfuscation tweaks). |
| **2026-03-24** | Disclosure; PyPI yanked the bad versions; the project re-published a clean release. By that point, every Python interpreter that had been started with `litellm` in `site-packages` had run the stealer at startup. |

## Vector

- **`.pth` file abuse.** Python automatically processes `.pth` files in `site-packages` at every interpreter startup. Lines beginning with `import ` are evaluated as code. Adding `import os, base64, urllib.request; exec(base64.b64decode("..."))` runs every time Python starts. No `import litellm` required by user code.
- **Multi-layer obfuscation.** The payload was base64-encoded inside the `.pth`, which expanded to more base64 inside a Python `compile()` call, which expanded again to the final stealer logic. A single-pass content scan would have missed it; the recursive decoder catches it.
- **Universal reach.** Since `.pth` runs at interpreter startup, the stealer fired in every Python execution context where litellm was installed: dev REPLs, CI test runs, production worker pods. The blast radius was wherever Python ran with that version present.

## What the stealer did

- Read `/proc/self/environ` and walked the process tree for sibling-process environment variables.
- Walked `~/.aws/credentials`, `~/.ssh/id_*`, `~/.config/gcloud/application_default_credentials.json`, `~/.kube/config`, `~/.bash_history`.
- Encrypted the harvest with AES + RSA wrapping.
- Exfiltrated to a typosquat domain via HTTPS.

## IOCs

- **Package:** `litellm` on PyPI, versions `1.82.7` and `1.82.8`.
- **Filesystem indicator on install:** a `.pth` file in `site-packages/` containing `import ` lines beyond the standard path additions.
- **Behavioral indicator on Python startup:** any `python` process reading `/proc/self/environ` or credential-path files in the first few seconds of process lifetime.

## How cilock catches it

This is the canonical motivating example for cilock's **content layer** with **recursive base64 decode** (default depth 3). The `secretscan` attestor:

1. Captures stdout from the wrapped `pip install` (or any `python` invocation).
2. Runs Gitleaks patterns across the captured content.
3. Then base64-decodes, hex-decodes, and URL-decodes any string matching those encoding patterns and re-runs Gitleaks on the decoded content. Recurses up to 3 levels by default.
4. Fails the build if any credential pattern matches at any decoding depth.

The LiteLLM stealer's three-layer encoding falls exactly inside that decoder's capability.

The **behavior layer** also catches it independently: wrap any Python startup with `cilock run --trace` and the Rego policy denies `python` reading `/proc/self/environ` or credential-path files at startup time.

## Follow-up implementation

The full harness for the `.pth` vector — a synthetic `.pth` file that triggers the recursive decoder, plus the trace policy on `python` startup credential reads, plus a CI workflow proving both — will ship in a separate PR. The catalog entry above describes the detection mechanism in enough depth for a reader to apply the same pattern to their own pipelines today.

## References

- **Blog:** [A .pth File, 34KB of Base64, and Every Secret You Have](https://testifysec.com/blog/cilock-litellm-supply-chain-attack) — Cole Kennedy, March 2026
- **Secretscan attestor docs:** [cilock.aflock.ai → concepts/attestors#secretscan-attestor](https://cilock.aflock.ai/concepts/attestors#secretscan-attestor)
- **Related:** [Microsoft `durabletask` PyPI trojan (2026-05)](../2026-05-microsoft-durabletask-pypi/) — same `.pth` vector, two months later, different package.
