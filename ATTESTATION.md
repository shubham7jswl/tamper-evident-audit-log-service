# Attestation

> **Template — complete with the exact wording from the assignment's §0.4 before submitting.**
> The assignment text pasted into development did not include §0, so this file is scaffolded with
> the substance the attestation is expected to cover. Replace/confirm each section against the
> real §0.4.

## Authorship and ownership

I, **<your name>**, am the author of this submission and I own its correctness, design,
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
  and confirming detection.
- **Secure usage:** no secrets, credentials, or proprietary/third-party data were shared with the
  AI. Dependencies suggested by AI were verified against the build before adoption.

## Development process

The repository's commit history is the authentic development record. Work proceeded in reviewable
increments: scaffold → hashing core → chain → API → extensions → tests → documentation.

## High-impact changes

The following are treated as high-impact and require explicit human sign-off (and are gated by
the `ADMIN` scope at runtime): payload redaction, retention/archival runs, and deep chain
verification.

---

Signed: ______________________  Date: ______________
