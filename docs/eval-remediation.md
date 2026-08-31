# Post-review remediation

An external review of an earlier archive (commit `c8cc098`) raised three guardrail concerns.
This document records what changed in response, on branch `feature/eval-remediation`.

## 1. Attestation not bound to a reviewable revision

The graded archive shipped without `.git` and the attestation named no repository, branch, or
commit.

- `ATTESTATION.md` now carries a submission-identity table (repository URL, branch, and the
  `submission` git tag) and a claim → evidence map.
- `SUBMISSION.md` at the repo root points at the exact revision (`git rev-parse submission`).
- The "template — complete with §0.4 wording" banner is removed; the file is signed and dated.

## 2. Default API credentials active in the main configuration

`application.yml` embedded `dev-writer-key` / `dev-admin-key` as env-var fallbacks, so
`java -jar` with no environment set came up with working admin credentials.

- `application.yml` ships **no** key values. Keys come from `AUDIT_READER_KEY` /
  `AUDIT_WRITER_KEY` / `AUDIT_ADMIN_KEY`.
- The well-known local keys moved to `application-dev.yml` (`dev` profile).
- `ApiKeyConfigValidator` fails startup if, outside the `dev`/`test` profiles, any key is
  missing, a known placeholder, or shorter than 16 characters.
- `ApiKeyAuthFilter` ignores blank keys and treats a blank `X-Api-Key` as unauthenticated.
- Tests: `ApiKeyConfigValidatorTest` (static logic) + `ApiKeyConfigValidatorContextTest`
  (`ApplicationContextRunner` — proves the context actually fails / starts).

Not changed: static keys, no rotation/expiry/revocation, no rate limiting. These remain the
documented production gaps in `architecture.md` §6.

## 3. No concurrency test for the single-writer lock

ADR-0003's correctness claim (a `chain_head` `SELECT FOR UPDATE` serializes all appends) had no
test.

- `ChainAppenderConcurrencyIT`: 8 threads × 8 concurrent `append()` calls → asserts a gap-free
  `seq` 1..64, chain head at 64, and `ChainVerifier` `intact`. Removing the lock fails it
  (duplicate `seq` → PK violation).
- Still only single-JVM contention on H2; two-instance behaviour against Postgres remains
  argued, not tested (`docs/testing.md`).

## 4. Thin security test coverage

401/403 were checked on a single endpoint.

- `SecurityMatrixIT` (23 cases): bad/blank/unknown/wrong key → 401; every protected endpoint ×
  an under-scoped key → 403 (including READ denial via a new WRITE-only test key, and ADMIN
  denial on redaction + retention); `deep=true` verify requires ADMIN; ADMIN is never blocked
  by auth.

## Not in scope of this pass

BOLA / per-resource ownership (the service is a single-trust-domain operator tool — now stated
explicitly in `docs/testing.md`), idempotency/replay defense, branch-coverage gate in the
default build, and external chain anchoring. Tracked as follow-ups.
