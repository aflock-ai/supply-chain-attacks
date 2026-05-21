#!/usr/bin/env bash
#
# SYNTHETIC reproduction of the May 2026 actions-cool hijack payload.
#
# This script does NOT contain real credentials, does NOT perform any network
# egress, and does NOT redistribute the actual malware. It exercises the same
# syscalls and content patterns the real attack used so that cilock's three
# layers of defense can be exercised against it on every CI run.
#
# Specifically:
#
#   1. Echoes synthetic credential-shaped strings (Gitleaks pattern shape).
#      This trips cilock's `secretscan` attestor when
#      --attestor-secretscan-fail-on-detection is set. (Content layer.)
#
#   2. Reads /proc/self/environ.
#      This trips the behavioral policy's "environment harvesting" deny rule.
#      (Behavior layer.)
#
#   3. Attempts to open /proc/self/mem.
#      This is the specific actions-cool fingerprint — the real attack scraped
#      sibling-process memory; here we open our own so the syscall fingerprint
#      is the same but the access is harmless. The behavioral policy's
#      "/proc/*/mem read" deny rule catches it. (Behavior layer.)
#
#   4. Writes a marker file at /tmp/runner_collected_<pid>.txt.
#      The behavioral policy denies any process that writes to a path matching
#      this glob (the TeamPCP credential-collection fingerprint also used by
#      the March 2026 Trivy and LiteLLM playbooks).
#
# To rerun outside of cilock, just `bash payload.sh`. Each step prints what
# it's doing so you can see exactly which detection layer would fire.

set -u

echo "==> step 1: echo synthetic credential patterns (Gitleaks-detectable shape)"
# AWS docs example keys (AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI...) are
# allowlisted by Gitleaks as known doc examples and won't trip detection.
# Use real-shape (but invalid) values that Gitleaks DOES match.
echo "    AWS access key: AKIA2E0A8F3B244C9986AB"
echo "    AWS secret key: 7gK3HpvE9Xw2nQ8mZf4tDcRyL1aBoUvNs6PiQrWj"
echo "    GitHub PAT: ghp_3kNvLp9XwQz1BsT2aH4eMRdYfC8oUiVxJ7Eg"
echo "    -- shapes match real keys; values are random and not valid against any service"

# RSA private key header — the most reliably-detected pattern across all
# secret scanners. Detected by Gitleaks' generic-private-key rule.
cat <<'PEM'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAv9ZqfXfH8ZbF3KhRmYpQ4dT5wE7nL2VxJ9MaBcDeFgHiJkLmNoPq
Rs7TuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz==
-----END RSA PRIVATE KEY-----
PEM

echo "==> step 2: read /proc/self/environ (env var harvesting fingerprint)"
head -c 256 /proc/self/environ >/dev/null || true

echo "==> step 3: open /proc/self/mem (actions-cool memory-scrape fingerprint)"
# We open it read-only and immediately close. We do not actually read sibling
# process memory; opening our own /proc/self/mem is enough for the trace
# attestor to capture the open() syscall and for the Rego deny rule to fire.
exec 9</proc/self/mem 2>/dev/null || true
exec 9<&- 2>/dev/null || true

echo "==> step 4: write marker to /tmp/runner_collected_$$.txt"
echo "synthetic-payload-marker" > "/tmp/runner_collected_$$.txt"

echo "==> done. cilock should have:"
echo "    [content]  fired secretscan on the credential-shaped strings above"
echo "    [behavior] flagged the /proc/self/environ + /proc/self/mem reads"
echo "    [behavior] flagged the /tmp/runner_collected_*.txt write"
