# GitHub internal source disclosure (2026-05-18)

> Status: **📋 documentation-only.** This attack is structurally different from the others in this catalog — it was a **data exposure** of GitHub's own internal source code, not a runtime compromise of code that downstream consumers ran. There is no synthetic payload to ship and no Rego policy that would have prevented the disclosure itself. We document the attack here because it's part of the same May 2026 wave and because cilock attestations from the affected build pipelines would have provided forensic value.

## Timeline

| When | What |
|---|---|
| **2026-05-18** | GitHub disclosed that an unauthorized party had accessed an unknown quantity of GitHub's internal source code. |
| **2026-05-18** | Initial advisory: details on the access vector and the scope of disclosed code were limited. Investigation ongoing. |

## Vector

- **Data exposure** of GitHub's own internal repositories. Distinct in kind from the other attacks in this catalog: there is no malicious code running on a downstream consumer's machine. The exposure is the leak itself.
- The disclosed source code could subsequently inform attackers about GitHub's internal APIs, attack surface, and unpublished features.

## What cilock would NOT prevent

The disclosure itself. Cilock's three-layer defense model (prevention / content / behavior) protects against malicious code executing in your build pipelines or on your machines. It does not prevent a credential leak or unauthorized read of source code at rest.

## What cilock attestations DO provide in this scenario

For an organization in GitHub's position, attestations from cilock-wrapped build pipelines provide:

- **Forensic timeline.** Every build of every affected repo, with the commit SHA, environment fingerprint, and signing identity. After a disclosure, you can answer "was the leaked snapshot built? where? by whom?" in seconds against the attestation log.
- **Tamper-evidence on releases.** Even if internal source leaked, any downstream-shipped release artifact remains attested — consumers can verify the artifact they downloaded matches a known-good build, regardless of what an attacker with source access might publish elsewhere.
- **Identity scoping for the leaked source.** If the leaked source includes build configuration, an attacker can't impersonate the legitimate build identity in subsequent publishing: the OIDC identity in the attestation is bound to the workflow path + repository, not to file contents.

## Why we list it here

The wave of attacks in May 2026 included this one. A catalog that omits it would understate the breadth of vectors that hit the SDLC in 48 hours. The honest answer is "cilock doesn't prevent source disclosure," and saying so explicitly is more useful than silence.

## References

- GitHub advisory (link to be added).
- Related GitHub Actions hijacks where cilock detection DOES apply: [`actions-cool` hijack (2026-05)](../2026-05-actions-cool-hijack/).
