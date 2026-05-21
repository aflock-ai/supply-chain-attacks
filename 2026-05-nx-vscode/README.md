# Nx Console VS Code extension compromise (2026-05-19)

> Status: **📋 documented, implementation pending.** This README is the catalog entry for the attack. The detection harness and policies will land in a follow-up PR.

## Timeline

| When | What |
|---|---|
| **2026-05-19** | A malicious update to the `nrwl/nx-console` VS Code extension was published. The extension had 2.2M+ installs at the time. |
| **2026-05-19** | The poisoned version executed on every workspace open and scraped local secrets — git credentials, SSH keys, GitHub PATs in `.env` files. |
| **2026-05-19** | Disclosure; the marketplace pulled the bad version. The full scope of exfiltrated data is still being inventoried as of writing. |

## Vector

- **Extension scope abuse.** VS Code extensions can register file watchers, run background workers, and read any file the user can read. The malicious update added an `activate()` hook that walked common credential paths.
- **Wide blast radius.** Extensions update silently in the background by default. By the time the bad version was identified, every developer who'd opened VS Code with `nx-console` installed in that window had it run.

## IOCs

- **Package:** `nrwl.angular-console` on the VS Code Marketplace (formerly known as `nx-console`).
- **Install count at compromise:** 2.2M+.
- **Filesystem indicator on a developer machine:** any process spawned by `Code Helper (Plugin)` opening `~/.aws/credentials`, `~/.ssh/id_*`, `~/.gitconfig`, `.env`, or `~/.netrc` is anomalous for a code-navigation extension.

## Detection plan

This attack runs on the developer machine, not in CI. The cilock playbook for it:

- **Content layer:** wrap the extension build / publish step with cilock so that `secretscan` runs on the bundled extension code. The trojanized version contained patterns that secretscan's recursive base64 / hex decoder catches.
- **Behavior layer:** on a developer machine, run an audit step (cilock wraps the user's first invocation after an extension update) that ptraces the extension host process and matches the credential-path-read fingerprint above.
- **Prevention layer:** an attestation policy on the marketplace publisher's release pipeline — only allow installs of extensions whose latest version is signed by a known publisher identity, with provenance attestation from the publisher's CI.

The follow-up PR will ship:

- `payload.sh` — a synthetic harness that imitates the malicious `activate()` hook (file walks + reads, no exfiltration).
- `policy-trace-behavioral.rego` — a Rego deny rule on credential-path reads from non-credential-aware processes.
- `policy-publisher-attestation.json` — a cilock policy that requires a publisher-signed attestation alongside any extension installed in CI.
- `.github/workflows/detect.yml` — the live CI proving the above.

## References

- Original disclosure (forthcoming — add link as it lands).
- Related: any prior IDE-extension scope-abuse incidents in `vsx-marketplace` (links forthcoming).
