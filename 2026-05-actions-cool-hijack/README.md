# `actions-cool` GitHub Actions hijack (2026-05-19)

> Stolen maintainer credentials let an attacker push imposter commits to popular GitHub Actions in the `actions-cool/*` namespace. The injected code scraped CI/CD secrets from `/proc/<pid>/mem` and exfiltrated them at workflow run time.

## Timeline

| When | What |
|---|---|
| **2026-05-19** | First detections of imposter commits in `actions-cool/*` repositories. Some commits forged author metadata to look like the legitimate maintainer. |
| **2026-05-19, hours later** | Affected actions referenced by tag (e.g. `@v1`, `@main`) silently pulled the malicious version on next workflow execution. |
| **2026-05-19, late** | Disclosure; org rotated credentials; commits reverted. By then, an unknown number of downstream workflows had run with the malicious code and exposed secrets. |

## What the attacker actually did

1. Obtained credentials to push to `actions-cool/*` repos (most likely a phished or leaked PAT for an account with write access to those Actions).
2. Force-pushed imposter commits onto the default branches and rewrote a few release tags so existing consumers pinned to `@v1` / `@main` would silently pick up the malicious code.
3. The injected payload, executed at the start of any wrapped workflow run, opened `/proc/<pid>/mem` of sibling processes on the GitHub-hosted runner to scrape secrets that the runner had loaded into memory (environment variables, GHA `secrets.*`, AWS / GCP / Azure tokens injected by `aws-actions/configure-aws-credentials` and similar).
4. Encoded the scraped secrets and exfiltrated them to an attacker-controlled HTTPS endpoint.

## IOCs

- **Affected namespace:** `actions-cool/*`. Specific actions named in the disclosure (verify against upstream advisory before relying on this list).
- **Indicator on the runner:** any process opening `/proc/<other-pid>/mem` or repeatedly scanning `/proc/*/environ` is anomalous for a typical CI step.
- **Indicator at the policy layer:** a workflow referencing an `actions-cool/*` ref that is not SHA-pinned, or any reference to a tag that doesn't match the published release SHA.

## How cilock catches it

Cilock catches this attack at **two of its three layers** independently. Either is sufficient to block the release; both together make the bypass cost prohibitive.

### Layer 1: Prevention — source policy + SHA pinning

`policy-source-restrict.rego` denies workflow steps that reference any action not in the approved namespace, AND denies any reference that isn't pinned to a 40-character commit SHA. If consumers had pinned by SHA, the imposter commits would have produced a different SHA, the policy would have refused to let the workflow proceed, and the attack would not have executed.

This is the same pattern that defended against the [March 2026 Trivy tag rewrite](https://github.com/aflock-ai/cilock-trivy-detection-test). Tag pinning is broken; the policy enforces SHA pinning.

### Layer 3: Behavioral — ptrace + OPA Rego

`policy-trace-behavioral.rego` denies any wrapped process that opens `/proc/<pid>/mem` for any PID other than its own, or that reads `/proc/self/environ`, `/proc/*/environ`, or files matching `/tmp/runner_collected_*`. These are the credential-harvesting fingerprints used by every variant of the actions-cool payload observed in the wild and by the related Trivy and LiteLLM attacks of March 2026.

Cilock's `--trace` flag wraps the build process in ptrace and records every open syscall; the Rego policy matches the patterns above and emits a deny that fails the build.

## Reproduction harness (safe synthetic)

`payload.sh` reproduces the attack's syscalls and content patterns without any real secrets or network egress:

- Echoes a synthetic credential pattern shaped like an AWS access key and a GitHub PAT (Gitleaks-pattern shape, value is fake).
- Reads `/proc/self/environ` (triggers behavioral policy).
- Attempts to open `/proc/self/mem` (the actions-cool fingerprint).
- Writes a marker file to `/tmp/runner_collected_<pid>.txt`.
- **No network traffic. No exfiltration. No live secrets.**

## Run it locally

```bash
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

# Expected: cilock run exits non-zero (secretscan fired).
# Verify behavior layer fires too:
cilock verify --policy policy-trace-behavioral.rego attestation.json
# Expected: deny rules emitted for /proc/self/environ and /proc/self/mem reads.

# Source policy demo: try to wrap a hypothetical actions-cool action by tag
echo '{"actionref":"actions-cool/some-action@v1","refpinned":false}' \
  | cilock verify --policy policy-source-restrict.rego --input-json -
# Expected: deny — untrusted source + not SHA-pinned.
```

## Live CI

[`detect-2026-05-actions-cool-hijack.yml`](../.github/workflows/detect-2026-05-actions-cool-hijack.yml) runs each detection layer as a separate job on every push that touches this directory. Green = detection still works; red = detection broke, file an issue.

## References

- Upstream disclosure: see the actions-cool repository advisories on GitHub (specific links to be added as they're confirmed).
- Related attacks with the same playbook: [Trivy tag rewrite (2026-03)](https://github.com/aflock-ai/cilock-trivy-detection-test), [LiteLLM `.pth` stealer (2026-03)](../2026-03-litellm-pth-stealer/).
- Cilock three-layer defense model: [cilock.aflock.ai](https://cilock.aflock.ai).
