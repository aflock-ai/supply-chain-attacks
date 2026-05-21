# Behavioral detection of the May 2026 actions-cool hijack.
#
# Cilock's commandrun attestor with --trace records every open() syscall the
# wrapped process and its children perform. This policy denies any process
# that touches the credential-harvesting filesystem fingerprints used by
# the real attack:
#
#   - /proc/<pid>/mem  — the specific actions-cool fingerprint, used to
#     scrape sibling-process memory on shared GitHub-hosted runners
#   - /proc/self/environ + /proc/<pid>/environ — environment-variable
#     harvesting, the same fingerprint as the March 2026 LiteLLM stealer
#   - /tmp/runner_collected_*.txt — the TeamPCP credential-collection
#     pattern, also used by the Trivy tag-rewrite attack
#
# Three independent rules; any one of them firing fails the policy.

package cilock.verify

import rego.v1

# Rule 1: process opened /proc/<pid>/mem.
deny contains msg if {
    some proc in input.processes
    some file in object.keys(proc.openedfiles)
    regex.match(`^/proc/[0-9]+/mem$|^/proc/self/mem$`, file)
    msg := sprintf(
        "behavior: process %s (PID %d) opened %s — /proc/<pid>/mem read is the actions-cool credential-scrape fingerprint",
        [proc.program, proc.processid, file],
    )
}

# Rule 2: process read /proc/<pid>/environ or /proc/self/environ.
deny contains msg if {
    some proc in input.processes
    some file in object.keys(proc.openedfiles)
    regex.match(`^/proc/[0-9]+/environ$|^/proc/self/environ$`, file)
    msg := sprintf(
        "behavior: process %s (PID %d) read %s — environment-variable harvesting indicator",
        [proc.program, proc.processid, file],
    )
}

# Rule 3: process wrote to /tmp/runner_collected_*.
deny contains msg if {
    some proc in input.processes
    some file in object.keys(proc.openedfiles)
    startswith(file, "/tmp/runner_collected_")
    msg := sprintf(
        "behavior: process %s (PID %d) touched %s — TeamPCP credential-collection fingerprint",
        [proc.program, proc.processid, file],
    )
}
