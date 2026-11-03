# Plan — DataProofsDotnet 1.5.0 → 2.0.0 (+ JsonSchema.Net 9.6.0), new PR

Status: **APPROVED 2026-11-02 and IMPLEMENTED on PR #21's branch** (`fix/dataproofs-1.3.0-issue-20`).
Owner decisions: **fold into the existing PR #21** (D1); **v1.2.0 stays** (D2) — "there are no existing
credentials in the wild, no backwards compatibility is necessary", so the CHANGELOG states the
incompatibilities in one line and carries no migration or inventory guidance; D3 (`KnownContexts`
follow-up issue) left open. Pre-approval evidence came from a scratch worktree of `17fbc44` with the two
pins moved; the Review section records the results on the real branch.

## Owner's intent

> "DataProofsDotnet are now 2.0.0. Update your dependencies and open PR"

Keep Credentials on the latest stack and open a PR for it. PR #21 (every dependency at latest, v1.2.0) is
still **open and unmerged**; its head is `17fbc44`, all checks green.

## Inventory

| Package | Now (#21) | Latest | Action |
|---|---|---|---|
| `DataProofsDotnet.*` (Core/Jose/Cose/Rdfc/DI) | 1.5.0 | **2.0.0** | bump; rebuild required (binary break in Rdfc constructors) |
| `JsonSchema.Net` | 9.5.0 | **9.6.0** | bump (minor) |
| NetDid 4.0.0, NetCrypto 1.7.1, NetCid 1.6.0, M.E. 10.0.14, test stack | — | same | already latest |
| `FluentAssertions` | 7.0.0 | 8.11.0 | **held** (owner decision, licence) |
| `DidComm.Core` (consumer, not pinned) | — | 1.5.0 | compiled against Jose 1.5.0; Jose's public API is unchanged in 2.0.0, so it binds |

DataProofs 2.0.0 floors: NetCrypto 1.7.1, NetCid 1.6.0 (unchanged). No new transitive packages in the
default closure.

## What 2.0.0 changes for Credentials (from its changelog and public-API diff, checked by the trial)

1. **Builds clean, no source change needed for the API.** The Rdfc suites and canonicalizer now have one
   constructor each with an optional parameter; our `new EddsaRdfc2022Cryptosuite()` etc. compile and bind.
   It is a binary break, so a rebuild + release is required (as with Jose 1.3.0).
2. **RDFC now carries `@direction`** (our issue #40, implemented upstream with `rdfDirection: i18n-datatype`,
   the representation the reference implementations sign with). **This reverses last round's scope
   decision.** Trial: a direction-bearing credential issues and verifies; flipping or removing the direction
   fails with `PROOF_VERIFICATION_ERROR`; a number or boolean with `@direction` is still refused
   (`DATA_LOSS_DETECTION_ERROR`). The 8 direction tests from #21 now fail and must be rewritten to the
   new contract. The W3C suite's four direction cases should pass again (DataProofs states this; CI confirms).
3. **Security fix inherited (GHSA-6fxh-mc39-94vc):** the proof members a verifier acts on (`proofPurpose`,
   `challenge`, `domain`, `expires`, …) are now bound to the signature; with 1.5.0, a holder could respell
   them via `@context` with no key. Affects RDFC and bbs-2023; JCS/JOSE/COSE/SD-JWT were never affected.
   Some spec-legal but unverifiable proof shapes are newly refused (listed upstream).
4. **Signed bytes change for some RDFC documents** (tied blank-node labelling and Unicode code-point
   ordering corrected to match `rdf-canonize`). Ordinary credentials with no tied blank nodes are
   unaffected; a document with two same-looking unnamed objects is. **An RDFC proof made by any earlier
   Credentials over such a document no longer verifies** (it never verified on the reference
   implementation either). Reissuance by the issuer is the only repair.
5. **bbs-2023 reworked to interoperate with the reference implementation.** **Base and derived proofs
   made by any earlier version do not verify or derive on 2.0.0.** New limitation: a derivation that
   reveals only the mandatory statements is refused ("the BBS provider needs at least one disclosed
   message", a NetCrypto 1.7.1 limit). Our `Bbs2023Deriver` maps that `ProofGenerationException` to a
   `CredentialFormatException` whose fixed message ("not a valid base credential, or the pointers are
   invalid") is wrong for this case. 4 bbs tests fail because they reveal mandatory-only.
6. **RDFC DoS hardening inherited:** hostile blank-node graphs no longer overflow the stack; a work budget
   refuses pathological inputs in ~50 ms. (Known limitation upstream: JSON-LD expansion is slow on long
   arrays; size-limit untrusted documents.)
7. **New upstream option `ProofVerificationOptions.KnownContexts`** (context allowlisting, VC-DI §4.6).
   Credentials does not expose it; unset means unchanged behaviour. Public-API addition → **follow-up**,
   not this PR.
8. Legacy suites (`Ed25519Signature2020`, …) changed too; Credentials does not use them.

Trial results: build 0 warnings / 0 errors; 431/443 tests pass, the 12 failures are items 2 and 5;
0 vulnerable packages; default closure Newtonsoft-free; ApiCompat vs 1.1.1: no breaking changes;
DidComm.Core 1.5.0 consumer harness 14/14 with DataProofs 2.0.0 loaded (note: the harness loads DidComm
but does not exercise DidComm's own signing paths).

## Changes

- [ ] `Directory.Packages.props`: DataProofs 2.0.0, JsonSchema.Net 9.6.0; rationale comments updated
  (binary break, direction now carried, bytes change, bbs incompatibility).
- [ ] **Direction tests rewritten** (`RdfcIssueVerifyTests`, theory over the four W3C positions): RDFC
  issues and verifies a direction-bearing value; flipping `ltr`→`rtl` and removing the direction after
  signing → Rejected `PROOF_VERIFICATION_ERROR` (the property last round's scope decision could not
  give); a number with `@direction` → issuance refused; JCS still secures the same document.
- [ ] **Conformance gate:** remove the four direction entries from `KnownFailures`, floor 54 → 58;
  `docs/conformance.md` → 58/59 with the direction row replaced by a "now passes" note and #40 marked
  resolved. CI's W3C job is the proof; if any direction case still fails there, that is investigated, not
  re-listed.
- [ ] **bbs-2023 deriver:** the `CredentialFormatException` message includes the substrate's cause (one
  level, as `DataIntegrityMechanism` does), and `IBbsDeriver` docs state the mandatory-only limitation.
  The 4 failing tests reveal one non-mandatory claim (their purpose is unchanged: mandatory group always
  present, issuer binding, withheld-validity residual, unknown pointer ignored); one new test pins the
  mandatory-only refusal and its message.
- [ ] `CHANGELOG.md` v1.2.0: DataProofs 2.0.0 section (items 2–7 above, with the stored-proof inventory
  guidance), the direction scope decision replaced by "supported", JsonSchema.Net 9.6.0.
- [ ] Verification: `-warnaserror` build; full suite; vulnerability audit; Newtonsoft closure; ApiCompat;
  pack + DidComm 1.5.0 consumer check from the branch's packs; **adversarial pass** on the changed
  behaviours (direction binding through Credentials, proof-member binding through our DI verify path,
  bbs derive/verify under the rework, the deriver's error mapping); push; CI incl. the W3C job.
- [ ] Follow-up issue (this repo): expose `KnownContexts` through `CredentialVerificationOptions`.

## Decisions for the owner

**D1. PR vehicle (recommended: a new PR stacked on #21).** Branch `chore/dataproofs-2.0.0` from `17fbc44`,
PR base = `fix/dataproofs-1.3.0-issue-20`, so the diff shows only this change and #21 stays reviewable
as is; GitHub retargets it to `main` when #21 merges. Alternative: fold into #21 again. Say which.

**D2. Version.** #21 is v1.2.0 by your earlier decision. 2.0.0 adds two compatibility effects for stored
artifacts: RDFC proofs over tied-blank-node documents and **all** bbs-2023 proofs issued by ≤ 1.1.1 no
longer verify. The repo's own precedent (v1.0.0) put "newly rejecting previously accepted input" in a
major. Keeping **1.2.0** is consistent with your earlier call (the undefined-terms narrowing already had
this shape); **2.0.0** is the semver-strict reading. I'll go with 1.2.0 unless you say 2.0.0.

**D3. `KnownContexts`:** file the follow-up issue now (recommended), or leave it.

## Review (results on the real branch)

- Build `-warnaserror`: 0 warnings / 0 errors. **428 tests pass** (the 443 of the trial minus the 8
  direction tests folded into 5, plus the new bbs tests).
- Gates: 0 vulnerable packages across 29 projects; default closure Newtonsoft-free; ApiCompat vs 1.1.1: no
  breaking changes for Core, DI, Rdfc.
- Direction: `Rdfc_signs_a_language_value_with_direction_in_every_suite_position` (4 positions × RDFC and
  JCS; post-signing flip and removal → `PROOF_VERIFICATION_ERROR`) and
  `Rdfc_still_refuses_a_direction_on_a_non_string_value` (→ `DATA_LOSS_DETECTION_ERROR`).
- bbs-2023: four tests reveal one non-mandatory claim; `Bbs_mandatory_only_reveal_is_refused_with_the_cause`
  and `Bbs_reveal_pointer_matching_nothing_is_refused_with_the_cause` pin the two new refusals (the second
  is a behaviour change found by the suite: 1.5.0 ignored an unmatched pointer, 2.0.0 refuses it like the
  reference implementation). `Bbs2023Deriver` carries the substrate's cause in its message.
- Conformance gate: known failures = 1 (`relatedResource` digest), floor 58; parser test updated to show the
  direction messages as *unknown*. CI's W3C job decides; result recorded in the PR thread.
- DidComm.Core 1.5.0 consumer harness and the adversarial pass: see the PR thread.

## Explicitly not changing

- No Credentials public API change. `KnownContexts` stays a follow-up.
- The conformance shim stays on `eddsa-rdfc-2022`.
