# Plan: record the bbs-2023 decisions of 2026-11-23 in the PRD

**Status:** for approval. No PRD edit has been made.
**Date:** 2026-11-23
**Scope:** `docs/credentials-dotnet-prd.md` only (documentation). No source, no tests.
**Tracking:** epic #25; sub-issues #61, #62, #66 (with #69, #70), #67.

## Owner's intent

The owner wants full `bbs-2023` support for issuing and verifying JSON-LD credentials, driven by epic #25. The epic listed PRD points the PRD does not settle. On 2026-11-23 the owner answered four of them:

> Decisions: 1) Yes to #66. 2) Yes to #62, 3) Yes to #61. 4) Update wording

`CLAUDE.md` says the PRD is updated once a question is answered, and that a PRD edit waits for approval of a written plan. This is that plan.

## Decisions taken

| # | Owner's answer | Recorded as |
|---|---|---|
| PD-1 | Yes to #66 | The `bbs-2023` optional features (anonymous holder binding, pseudonyms) are in scope. |
| PD-2 | Yes to #62 | A revocable `bbs-2023` credential is linkable through its Bitstring Status List entry. Accepted as a stated limit. |
| PD-3 | Yes to #61 | Replay protection for a derived credential through the presentation header is in scope. |
| PD-4 | Update wording | FR-015 is reworded to cover signing through a key store. |

**My reading, to confirm.** The question behind PD-3 was how the presentation header encodes a challenge. "Yes" settles that the feature is in scope; it does not pick an encoding. This plan leaves the encoding as an open question (OQ-5 below) with the recommendation of opaque bytes supplied by the caller.

## Proposed edits

All in `docs/credentials-dotnet-prd.md`. Text in quotes is the exact proposed wording.

### E1. FR-015 (PD-4)

Replace

> **FR-015** — The Issuer MUST sign using an issuer key obtained through `net-did`'s signer abstraction; it MUST NOT handle raw private key material directly.

with

> **FR-015** — The Issuer MUST sign through a key abstraction and MUST NOT handle raw private key material directly. For single-message signatures the abstraction is the signer obtained through `net-did`. For `bbs-2023`, whose signature covers many messages and cannot be produced by a single-message signer, it is a `crypto-dotnet` key-store handle.

### E2. FR-031 (PD-2)

Append to FR-031:

> Unlinkability is a property of the derived proof value. The derived credential also carries whatever the issuer made mandatory, and a credential with a Bitstring Status List entry is linkable through that entry, which is unique to the credential. This is an accepted limit.

### E3. New requirements for replay protection (PD-3)

Add after FR-034:

> **FR-035** — The Holder MUST be able to bind a `bbs-2023` derived credential to a verifier-supplied value through the presentation header, without a holder key.

Add after FR-045:

> **FR-046** — The Verifier MUST be able to require that a `bbs-2023` derived credential is bound to an expected value, and MUST reject one that is bound to a different value or to none.

Add to §11:

> **OQ-5** — The encoding of the `bbs-2023` presentation header: opaque bytes supplied by the caller, or an encoding of challenge and domain defined by this library.

### E4. New requirements for the optional features (PD-1)

Add after FR-016:

> **FR-017** — The Issuer MUST be able to issue a `bbs-2023` base credential with each optional feature of the cryptosuite: anonymous holder binding, a per-verifier pseudonym, and both together.

Add after the new FR-035:

> **FR-036** — The Holder MUST be able to create the commitment an issuer needs for the `bbs-2023` optional features, and to derive from such a credential: proving possession of the holder secret, and presenting a pseudonym for a given verifier.

Add after the new FR-046:

> **FR-047** — The Verifier MUST verify `bbs-2023` derived proofs that use the optional features, report whether holder binding was proven, and return the verified pseudonym.

Add to §11:

> **Risk R-4** — The `bbs-2023` optional features are marked at risk in the Candidate Recommendation Draft: they are removed unless the IETF documents they rest on reach RFC on the same timeline and each has two independent implementations. If the specification drops a feature, the matching part of FR-017 / FR-036 / FR-047 is withdrawn. NFR-005 keeps the features behind a stable API.

### E5. §10, a record of the decisions

Add under the D1–D12 line:

> **PRD-level decisions (2026-11-23).** PD-1 the `bbs-2023` optional features are in scope (FR-017, FR-036, FR-047) · PD-2 a revocable `bbs-2023` credential is linkable through its status entry, an accepted limit (FR-031) · PD-3 replay protection for a `bbs-2023` derived credential through the presentation header (FR-035, FR-046) · PD-4 `bbs-2023` issuance signs through a key store (FR-015).

D1–D12 come from the concept document and are not re-opened. D3 already scopes embedded selective disclosure to `bbs-2023`; the optional features are part of that cryptosuite, so the concept document does not change.

### E6. Appendix A, traceability

- "Issuer — issue a `bbs-2023` base credential": FR-014, **FR-017**.
- "Holder — derive minimally disclosing credential": FR-031, FR-032, **FR-035, FR-036**.
- "Verifier — verify selective disclosure": FR-042, **FR-046, FR-047**.

## Not in this change

- The PRD points still open in epic #25: the mandatory-group policy, the default for proof `created`, a context-registration hook under FR-081, the pinned specification revision, whether this library attaches the base proof, the interim holder check, and where holder secrets live.
- `tests/Credentials.TestSupport/RequirementIds.cs`. The requirement-coverage gate reads that file, not the PRD, and requires a tagged test per id. The new ids are added there together with their tests, in the PRs that implement them. Until then the PRD is ahead of `RequirementIds`, which is the intended state for a target document.

## Steps

- [ ] Owner approves the wording above (E1 to E6) and the reading of PD-3.
- [ ] Branch `docs/prd-bbs-2023-decisions` off `origin/main`.
- [ ] Apply E1 to E6.
- [ ] Check: every new id is unique and referenced consistently in §6, §10, §11 and Appendix A; `dotnet test tests/Credentials.ArchitectureTests` is still green.
- [ ] `CHANGELOG.md`: one documentation line.
- [ ] Pull request that references #25, #61, #62, #66 and #67. Commit and push only on the owner's word.
- [ ] Review section added to this file.
