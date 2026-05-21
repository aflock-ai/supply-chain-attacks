# Microsoft `durabletask` PyPI trojan (2026-05-18)

> Status: **📋 documented, implementation pending.** Detection harness lands in a follow-up PR.

## Timeline

| When | What |
|---|---|
| **2026-05-18** | A trojanized release of the Microsoft-published `durabletask` package appeared on PyPI. |
| **2026-05-18** | The trojanized version added a `.pth` file (same pattern as the March 2026 LiteLLM stealer) that ran at every Python interpreter startup, with or without `import durabletask`. |
| **2026-05-18** | Disclosure; PyPI yanked the bad version. Microsoft re-published a clean version with a fresh signing identity. Customer exposure still under investigation. |

## Vector

- **PyPI publish-credential compromise.** The attacker pushed a malicious release using credentials with publish rights to the Microsoft-owned `durabletask` project.
- **`.pth` file execution.** Python automatically processes `.pth` files at startup and treats lines starting with `import ` as code to execute. Adding `import os, urllib.request; ...` to a `.pth` file runs every time Python starts — no user `import` of the package required.
- **Hidden in plain sight.** The bytecode payload was stored in `__pycache__` and base64-encoded, with a multi-layer wrapper. A single-pass content scan would have missed it.

## IOCs

- **Package:** `durabletask` on PyPI.
- **Affected versions:** (specific versions to be added from upstream advisory).
- **Filesystem indicators on a runner with the bad version installed:**
  - A `.pth` file containing `import` statements with embedded code (legitimate `.pth` files contain only path additions).
  - A new file under the site-packages directory referenced from the `.pth` import.
  - Base64-shaped strings ≥ 200 chars inside `__pycache__` bytecode.

## Detection plan

- **Content layer:** `secretscan` with recursive base64/hex/URL decode (default depth 3) is the exact countermeasure for this attack — the same content layer that caught LiteLLM in March 2026.
- **Prevention layer:** an attestation policy requires every installed PyPI package to have a publisher attestation from the registered Microsoft publisher identity. A trojanized release published with stolen credentials would still have a different OIDC identity in the build attestation than legitimate Microsoft releases, and the policy denies the install.
- **Behavior layer:** wrap `pip install` and any subsequent Python interpreter invocation with `cilock run --trace`. The behavioral policy denies any `python` process reading `~/.aws/credentials`, `~/.ssh/id_*`, `/proc/self/environ`, or any other credential path at interpreter-startup time — the LiteLLM fingerprint.

Follow-up PR ships the harness + policies + CI.

## References

- Microsoft / PyPI advisory (link to be added).
- Related: [LiteLLM `.pth` stealer (2026-03)](../2026-03-litellm-pth-stealer/) — same `.pth` vector, different package.
- Cilock secretscan with recursive decode: [docs](https://cilock.aflock.ai/concepts/attestors#secretscan-attestor).
