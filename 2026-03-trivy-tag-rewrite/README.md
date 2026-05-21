# Trivy tag rewrite (2026-03-19)

> Status: **📖 see deep-dive.** This attack has its own full detection-validation repo with all four detection scenarios implemented and live CI proving each one. We don't duplicate it here.

## Where the deep-dive lives

**[aflock-ai/cilock-trivy-detection-test](https://github.com/aflock-ai/cilock-trivy-detection-test)**

That repo is the canonical detection demo for this attack and is referenced from the [cilock tutorial](https://cilock.aflock.ai/tutorials/defending-against-supply-chain-attacks). It ships:

- Four payload scripts reproducing the AWS key, RSA key, `procmem` patterns, and SARIF-embedded credential variants.
- Two Rego policies (`policy-source-restrict.rego`, `policy-trace-behavioral.rego`) that are the templates the rest of this catalog mirrors.
- A CI workflow (`.github/workflows/protected.yml`) with 6 detection jobs + performance benchmarks.

## Why a separate repo

The Trivy deep-dive existed before this catalog and is referenced from multiple places (the cilock-docs intro page, the attestor catalog, the tutorial). Moving it here would have broken those links. Cross-linking keeps the deep-dive discoverable while letting this catalog stay broad.

## Summary

For full context: on **2026-03-19** an attacker force-pushed 75 of 76 version tags in `aquasecurity/trivy-action`, replacing the tagged commits with a credential-stealer that scraped secrets from `/proc/<pid>/mem` and `/proc/*/environ`, encrypted them with AES-256-CBC + RSA-4096, and exfiltrated to a typosquat domain. Every pipeline that pinned the action by tag (instead of SHA) silently ran the malicious code on its next trigger.

Cilock catches this at all three layers — source policy denies non-SHA-pinned refs (prevention), secretscan catches the credential patterns in stdout (content), and trace + OPA catches the `/proc` reads (behavior).

## Read more

- **Detection demo:** [aflock-ai/cilock-trivy-detection-test](https://github.com/aflock-ai/cilock-trivy-detection-test)
- **Threat walkthrough:** [cilock.aflock.ai → Defending against supply-chain attacks](https://cilock.aflock.ai/tutorials/defending-against-supply-chain-attacks)
- **Blog:** [75 Poisoned Tags and Nobody Noticed](https://testifysec.com/blog/cilock-action-supply-chain-attacks) — Cole Kennedy, March 2026
