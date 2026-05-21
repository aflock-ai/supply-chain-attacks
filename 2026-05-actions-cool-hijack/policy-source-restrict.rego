# Source-policy detection of the May 2026 actions-cool hijack.
#
# Deny rules:
#   1. Any action ref outside the approved namespace.
#   2. Any action ref that is not SHA-pinned (40-char commit SHA).
#
# Either rule firing on `actions-cool/*` would have prevented the attack:
# the imposter commits would have produced a different SHA than the published
# release, so a SHA-pinned consumer would have seen the policy reject the
# unexpected SHA. A consumer pinning to `@v1` or `@main` skipped that check
# and ran the attacker's code.

package cilock.verify

import rego.v1

# Approved Actions namespaces. Add additional trusted namespaces here.
# Note: `actions-cool/*` is INTENTIONALLY OMITTED because of the May 2026
# compromise. Even after the upstream rotation, consumers should pin to
# specific known-good SHAs rather than blanket-trusting the namespace again.
allowed_namespace := {
    "actions/",
    "chainguard-dev/",
    "aflock-ai/",
    "in-toto/",
    "sigstore/",
}

# Deny: action ref is not from a known-good namespace.
deny contains msg if {
    ref := input.actionref
    not allowed_match(ref)
    msg := sprintf("Action ref from untrusted source (not in allowed_namespace): %s", [ref])
}

# Deny: action ref is not pinned to a 40-char commit SHA.
deny contains msg if {
    not input.refpinned
    msg := sprintf("Action ref not pinned to SHA: %s (use @<40-char-sha> not @<tag>)", [input.actionref])
}

# Helper: does the action ref start with any allowed namespace prefix?
allowed_match(ref) if {
    some ns in allowed_namespace
    startswith(ref, ns)
}
