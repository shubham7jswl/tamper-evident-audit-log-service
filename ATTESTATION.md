# Attestation

## Submission identity and reviewed revision

| Field | Value                                                                                                                                                               |
|---|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Candidate | Shubham Jaiswal                                                                                                                                                     |
| Contact | shubham7jaiswal@gmail.com                                                                                                                                           |
| Repository | https://github.com/shubham7jswl/tamper-evident-audit-log-service                                                                                                    |
| Branch under review | `feature/taper-evident-log-service` (spelling of "taper" is a typo in the branch name only)                                                                         |
| Reviewed revision | The commit pointed to by the annotated git tag **`submission`**. Confirm with `git fetch --tags && git rev-parse submission`. See `SUBMISSION.md` at the repo root. |
| Commit history | Authentic and unsquashed. Work proceeded in reviewable increments — `git log --oneline` is the development record.                                                  |

> If you received this as an archive without a `.git` directory, request the repository (or an
> archive that includes `.git`) so the revision and history above can be verified. The commit SHA
> in `SUBMISSION.md` identifies the exact tree this attestation covers.

## Authorship and ownership

I, Shubham Jaiswal, am the author of this submission and I own its correctness, design,
maintainability, and production-readiness judgments. AI assistance (Claude Code) was used as an
accelerator within tasks I defined and reviewed; it did not autonomously drive the work.

## AI assistance disclosure

- **Tools used:** Claude Code (Claude Sonnet).
- **Where AI was used:** first drafts of implementation code and documentation; comparison of
  design alternatives; diagnosis of framework/build issues.
- **Where AI was not used / was overridden:** binding technology decisions (datastore, auth
  model, scope), the redaction scheme design direction, canonicalization correctness
  requirements, and all commit decisions. Specific accepted / modified / rejected items are
  logged in `docs/ai-usage-log.md`.
- **Review:** every AI-generated change was read, compiled, and tested before commit. The
  security-critical paths were additionally validated by tampering with the datastore directly
  and confirming detection (`scripts/tamper-demo.md`, `ChainVerifierIT`).
- **Secure usage:** no secrets, credentials, or proprietary/third-party data were shared with the
  AI. Dependencies suggested by AI were verified against the build before adoption.
- **Reuse:** no third-party or copyrighted source was copied in. Dependencies are declared in
  `pom.xml` and resolved from Maven Central; `CanonicalJson` is an original implementation
  (its divergence from RFC 8785 for exotic floats is documented in `docs/architecture.md`).

## Development process

Work proceeded in reviewable increments: scaffold → hashing core → chain → API → extensions →
tests → documentation → readability pass → post-review remediation. Each step is a separate
commit on the branch above.

## High-impact changes

The following are treated as high-impact and require explicit human sign-off (and are gated by
the `ADMIN` scope at runtime): payload redaction, retention/archival runs, and deep chain
verification.

## Claim → evidence map

| Claim | Where to verify |
|---|---|
| Append-only hash chain, tamper-evident, first-inconsistency verification | `AuditHasher`, `ChainVerifier`, `docs/architecture.md` §3, `ChainVerifierIT` |
| Single-writer append is serialized and gap-free (incl. concurrent writers) | `ChainAppender` (`chain_head` `SELECT FOR UPDATE`), `ChainAppenderConcurrencyIT`, ADR-0003 |
| Redaction does not break the chain | `RedactionService`, ADR-0004, `RedactionServiceIT` |
| Retention archives without creating a false chain gap | `RetentionService`, ADR-0005, `RetentionServiceIT` |
| Exported bundles verify offline with no Spring | `BundleExporter`, `com.sj.audit.utils.BundleVerifier`, `BundleExportIT` |
| Scoped API-key auth; high-impact ops require ADMIN | `config.security` package, `SecurityConfig`, `SecurityMatrixIT` |
| No default credentials active outside the `dev` profile | `ApiKeyConfigValidator`, `application-dev.yml`, `ApiKeyConfigValidatorTest` / `ApiKeyConfigValidatorContextTest` |
| Every AI-assisted change was compiled and tested | `./mvnw verify` (source level 21, built on JDK 26); `docs/ai-usage-log.md` |

---

Signed: **Shubham Jaiswal**  Date: 2026-08-31
