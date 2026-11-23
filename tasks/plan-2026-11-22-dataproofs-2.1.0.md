# Plan: consume DataProofsDotnet 2.1.0 (2026-11-22)

## Owner intent

> "I deployed a new version of dataproofs. Fetch the latest and use it" (2026-11-22)

DataProofsDotnet 2.1.0 (all six packages on nuget.org, tag `v2.1.0` @ `c122334`) is the upstream bundle that
epic #23 was waiting for. It closes dataproofs-dotnet #44 (bbs-2023 base proof through a key store), #45 (SD-JWT
`nbf`/`exp`), #46 (`x5c`), #47 (Type Metadata processing), #48 (positional must-not-disclose), #49 (SD-JWT VC
re-pinned -16 → -27), #50 (`System.Formats.Cbor` floor 10.0.15) and #61. Its public API only adds. It refuses
some inputs that 2.0.0 accepted (see its CHANGELOG, "Read these entries before upgrading").

## Trial result (scratch worktree, nothing committed)

Bumping the five `DataProofsDotnet.*` PackageVersions 2.0.0 → 2.1.0 and removing the Cbor pin:

- Restore and Release build clean: 0 warnings, 0 errors (`TreatWarningsAsErrors`; no `[Obsolete]` use).
- All 442 tests pass (Core 204, DI 168, Rdfc 29, SampleSmoke 14, Architecture 9, RoundTrip 9, Interop 5,
  Conformance 4 + 1 skipped locally; the W3C suite itself runs in CI).
- Without the pin, every project resolves `System.Formats.Cbor` 10.0.15 transitively.
  `dotnet list package --vulnerable --include-transitive` is clean in every project. The packed
  `Credentials.Core` nuspec no longer lists Cbor (it comes through `DataProofsDotnet.Cose` 2.1.0).
  `Cose_unprotected_header_nesting_is_bounded` still passes.
- `tools/check-no-newtonsoft-closure.sh` OK; `tools/check-api-compat.sh` finds no breaking change.
- Probe of the #51 table: `credentialSubject.<name>` disclosable for `status`, `exp`, `iss`, `nbf`, `cnf`,
  `vct` and `given_name` now issues **and verifies Accepted**. #51 is fixed by the bump alone.
- Probe of the #50 table: a past `exp` and a future `nbf` are now **Rejected**, but through the proof check
  (`proof=Failed(PROOF_VERIFICATION_ERROR)`, `validity=Passed`). `SdJwtVcMechanism.MapErrorCode` has no arm for
  `SD_JWT_EXPIRED` / `SD_JWT_NOT_YET_VALID` / `SD_JWT_*_INVALID`, so they fall through to the generic code. The
  substrate also uses its own 2-minute skew, not `CredentialVerificationOptions`' skew. A non-number `exp` now
  makes issuance throw `ArgumentException` (the substrate refuses to sign it).

## Scope (in)

1. `Directory.Packages.props`: five `DataProofsDotnet.*` 2.0.0 → 2.1.0; extend the version-history comment with
   what 2.1.0 changes for Credentials.
2. Remove the Cbor security pin (#53): the central `PackageVersion`, the `PackageReference` in
   `Credentials.Core.csproj`, both comments, and the Cbor mention in the header's hold-back list.
3. #51: a regression test for each of the seven names (issue → holder presents → verify Accepted, credential
   and presentation paths). Closes #51; the epic #23 "#51 interim guard" step is dropped.
4. 2.1.0 #45 at the credentials level: a regression test that a past `exp` / future `nbf` SD-JWT VC is
   Rejected, pinning today's reporting (proof check). #50 stays open for the reporting and skew work (D2).
5. Stale text that 2.1.0 makes false: `CredentialsRdfcBuilderExtensions` XML doc (lines 42-43, "exposes no
   key-store / signer BBS base-proof API") and the comment in `Bbs_issuance_is_gated`. Wording only; the gate
   stays until #43.
6. `CHANGELOG.md` *Unreleased*: rewrite the #52 Security entry (the Cbor floor now comes from DataProofs 2.1.0,
   no local pin); add a *Changed* entry for DataProofs 2.1.0 with the behaviour changes Credentials users see
   (SD-JWT `nbf`/`exp` enforced, nested reserved names verify, stricter SD-JWT digest / `_sd_alg` /
   `aka_vcts` rules, `vc+sd-jwt` typ refused (never emitted here), the DI JCS `@context` edge cases).
7. Adversarial pass (one subagent) on the SD-JWT verify path under 2.1.0: `nbf`/`exp` bypass through
   Disclosures, nested time claims, exception escapes from the new checks, clock-skew interplay with
   `VerificationTime`, and the closure without the pin. Findings reported in detail; real ones fixed here or
   filed.
8. Verify: Release build, full tests, vulnerable audit, nuspec check, the two gate scripts, CI on the PR
   (including the W3C Conformance job).
9. Update memory (dependency surfaces, epic #23 orchestration order).

## Out of scope (2.1.0 unblocks these; each keeps its own issue and PR)

- #50: report `nbf`/`exp` failures in the Validity check with `expired` / `not_yet_valid` and the configured skew.
- #43 (+ #44): issue `bbs-2023` through `ICapableKeyStore` (the new `CreateBaseProofAsync` overload).
- #38: re-pin this repo's SD-JWT VC docs and PRD from -16 to -27.
- #33 (`x5c`), #37 (Type Metadata processing), #27 (return the disclosed claims).

## Decisions

- **D1 (owner): where it lands.** Recommended: fold into PR #55 (`fix/issue-52-cbor-advisory`). 2.1.0 replaces
  that PR's stopgap pin with the upstream fix, #53 says to remove the pin "in the PR that takes that DataProofs
  release", and the pin then never reaches `main`. Cost: PR #55's review restarts on the wider scope.
  Alternative: merge #55 as it is, then a new PR off `main`.
- **D2 (owner): #50 in this PR?** Recommended: no. Pin the new Rejected behaviour with a test (item 4) and leave
  the Validity-check reporting to #50, the next item in epic #23 order. Alternative: map the four `SD_JWT_*`
  codes to distinct proof diagnostics now.
- Version heading stays *Unreleased*; #52 stays open until a release ships (owner's call, PR #55 round 1).

Owner answers (2026-11-22): **D1 = fold into PR #55. D2 = leave the reporting to #50.** Per the epic #23
rules, PR #55's review is the plan gate.

## Checklist

- [x] 1. DataProofs 2.0.0 → 2.1.0 and the props history comment
- [x] 2. Cbor pin removed (#53)
- [x] 3. #51 regression tests (7 names × issue, present with KB-JWT, verify)
- [x] 4. `nbf`/`exp` window tests (Rejected via proof; `VerificationTime` threaded; non-numeric refused at issuance)
- [x] 5. Stale BBS text (`UseBbs2023` XML doc, `Bbs_issuance_is_gated` comment)
- [x] 6. CHANGELOG *Unreleased*
- [x] 7. Adversarial pass
- [x] 8. Verification (below); CI on the PR pending
- [x] 9. Memory

## Review

- **Commit `e4d804d`.** Release build has 0 warnings and 0 errors. **455 passed, 1 skipped** (the W3C fact, which
  runs in CI): Core 204, DI 181 (168 + 13 new), Rdfc 29, SampleSmoke 14, Architecture 9, RoundTrip 9, Interop 5,
  Conformance 4. The vulnerable audit is clean in 29 of 29 projects. The no-Newtonsoft closure, API compat
  (no breaking change against 1.2.0) and API coverage gates all pass.
- **Mutation check.** On 2.0.0 (audit off), 10 of the 13 new tests fail. The three that pass are the
  `given_name` control and the two `VerificationTime` cases, which only mean something next to the
  rejection test. On 2.1.0 all 13 pass.
- **Every pin re-checked against nuget.org on 2026-11-23.** All are at latest except the documented hold-backs
  (FluentAssertions 7.0.0, `Microsoft.Extensions.*` on 10.0.15).
- **Adversarial pass (one agent, about 250 probes, each diffed between 2.0.0 and 2.1.0). Nothing exploitable
  comes from the bump:**
  - No expired or not-yet-valid SD-JWT VC was Accepted on any path. Paths tried: the bytes overload, the parsed
    overload, a VP child, a disclosed `exp`/`nbf`, number spellings, duplicate keys, the KB-JWT window and
    `VerificationTime` extremes.
  - Nothing escaped the verifier from the new checks. 2.1.0 also fixed a `MaxHolderBindingAge` overflow
    that surfaced as Indeterminate on 2.0.0.
  - There is no split-brain beyond the documented withheld-top-level-disclosure residual.
  - Consumer closure: a packed consumer resolves Cbor 10.0.15 with no NU1902. Pinning 10.0.8 directly fails
    restore (NU1605 + NU1902).
  - Pre-existing items, identical on 2.0.0:
    - `CheckValidity` overflows the `DateTimeOffset` range at a `0001-01-01` `validFrom` or a `9999-12-31`
      `validUntil`, or with an extreme `ClockSkew`. The check becomes Indeterminate `operation_error`, so a
      `9999` sentinel credential is Rejected by default. It fails closed. Proposed as a new public issue.
    - Diagnostics: `VC_AKA_VCTS_INVALID` maps to `PROOF_VERIFICATION_ERROR`. This goes with #50's code mapping.
    - Two more items were reported to the owner.
- **Follow-ups (each its own issue and PR):** #50 next in epic #23 order. #51 closes with this PR; its interim
  guard step is dropped. #43, #38, #33 and #37 are now unblocked.
