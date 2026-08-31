# Submission pointer

This file identifies the exact revision the [attestation](ATTESTATION.md) covers.

| Field | Value |
|---|---|
| Repository | https://github.com/shubham7jswl/tamper-evident-audit-log-service |
| Branch | `feature/taper-evident-log-service` |
| Reviewed revision | the commit pointed to by the annotated git tag **`submission`** |
| Verify | `git fetch --tags && git rev-parse submission` — this SHA is the tree under review |

The commit history on the branch is the authentic development record (unsquashed). Notable
milestones:

- `Scaffold tamper-evident audit log service` — Scenario A + B core
- `Add test suite and fix build/runtime issues found by it`
- `Add documentation, ADRs, scenario write-ups` — architecture + decisions
- `restructured the directory structure` / `realigned the tests` — layered package layout
- `eval remediation` commits — attestation binding, credential startup gate, concurrency test,
  security test matrix (see `docs/decisions/` and `docs/eval-remediation.md`)

If you were handed a `.zip` without a `.git` directory, ask for the repository or a
history-preserving archive so the tag and history above can be checked.
