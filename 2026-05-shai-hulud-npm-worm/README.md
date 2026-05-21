# Shai-Hulud npm worm (2026-05-19)

> Status: **📋 documented, implementation pending.** This README is the catalog entry. Detection harness lands in a follow-up PR.

## Timeline

| When | What |
|---|---|
| **2026-05-19** | First detections of the Shai-Hulud worm-pattern code in `postinstall` scripts of multiple npm packages. |
| **2026-05-19** | Self-replicating: the malicious `postinstall` scraped the user's `~/.npmrc` for a publish token and, if present, used it to push patched versions of every package the user owned with the same worm. |
| **2026-05-19** | Detection chained: within hours, dozens of packages were observed publishing patched versions with the same payload, indicating successful self-propagation. |

## Vector

- **`postinstall` script abuse + maintainer token theft.** npm runs `postinstall` scripts in package context with full filesystem access at install time. The script harvested `~/.npmrc`, found the `_authToken`, and used it to publish patched versions of every package owned by that npm user.
- **Worm dynamics.** Each newly-infected maintainer became a new propagation node. Estimated dozens of packages affected; full scope under active investigation.

## IOCs

- **Behavior on a developer machine running `npm install`:** any child process of `npm` opening `~/.npmrc`, then making outbound HTTPS to `registry.npmjs.org` with `PUT` or `POST` requests that don't correspond to the user's current invocation.
- **Behavior in CI:** the same, scoped to whichever working directory contains an `.npmrc` with credentials.
- **Filesystem indicator:** the malicious `postinstall` typically wrote a marker file to `/tmp/.shai-hulud-<random>` to track infection state. Exact prefix may vary by variant.

## Detection plan

- **Content layer:** `secretscan` over `package.json`'s `scripts.postinstall` value and any files it `require()`s. The worm's published variants contained `_authToken` reads near `.npmrc` paths — a Gitleaks-grep pattern matches.
- **Behavior layer:** wrap `npm install` with `cilock run --trace` and a Rego policy denying:
  - Any process reading `~/.npmrc` that isn't a known npm binary.
  - Any process opening `/tmp/.shai-hulud-*` or writing files matching that prefix.
  - Any HTTPS to `registry.npmjs.org` from a process other than the top-level `npm` binary.
- **Prevention layer:** an attestation policy that denies installs of packages without an upstream publish attestation matching the registered publisher identity.

Follow-up PR ships the harness + policies + CI.

## References

- Disclosure (link to be added).
- Related: prior post-install attacks like `ua-parser-js` (2021), `event-stream` (2018).
