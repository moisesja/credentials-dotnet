# Plan — PR #21 review: RDFC `@direction` support contract, conformance gate, twin test

Status: **APPROVED 2026-10-29 (D1 yes, D2 file, D3 recommended) and IMPLEMENTED** on
`fix/dataproofs-1.3.0-issue-20` (PR #21). DataProofs issue filed:
[dataproofs-dotnet#40](https://github.com/moisesja/dataproofs-dotnet/issues/40). See Review at the end.

## Owner's intent

Address [PR #21 review comment 6513682713](https://github.com/moisesja/credentials-dotnet/pull/21#issuecomment-6513682713):

1. **Blocking.** The W3C gate fails (54 passing, baseline 57). Four failures are language value objects
   with `@direction` in `name`, `description`, `issuer.name` and `issuer.description`; RDFC issuance now
   refuses them. The reviewer's requirements, verbatim in spirit:
   - do **not** restore the unsafe behaviour (DataProofs ≤ 1.4 signed identical bytes for `ltr`/`rtl`);
   - resolve the intended support contract: a DataProofs fix adopted here, **or** an explicit scope
     decision with the exact limitation and conformance expectations documented;
   - **not** a bare lowering of the pass-count threshold, which would hide regressions;
   - focused coverage for the four affected positions;
   - update `docs/conformance.md` (still claims 57/59 and passing language-value cases) and the release notes.
2. **Non-blocking.** `JoseSubstrateRegressionTests.cs:441-452`: the KB-JWT and VP-JWT twins are only
   checked with the wrong nonce/challenge. Assert each twin succeeds with matching expectations first, then
   fails for the freshness reason, so a signature rejection can't satisfy the assertion by accident.

## Facts established (verified, not assumed)

- The suite's four cases are **issuer-side** `assert.doesNotReject(endpoints.issue(fixture))`, with
  `{"@value": "…", "@language": "en", "@direction": "ltr"}` (`tests/4.06-names-and-descriptions.js`,
  fixtures `*-language-direction-en-ok.json`). Each is the first direction assertion in its `it` block, so
  the block's later assertions (multi-language value, extra-property rejection) are **no longer reached**.
- The shim issues with `eddsa-rdfc-2022` (`Credentials.Conformance.VcApi/Program.cs:50`).
- DataProofs 1.5.0 refuses `@direction` deliberately (`JsonLdLossAudit.cs:175`, changelog #36): JSON-LD
  1.1's default JSON-LD→RDF conversion drops direction, so the old canonicalizer produced the same signed
  bytes for `ltr` and `rtl`; a holder could flip it undetected.
- **The Data Integrity specs define no lossless canonicalization of direction.** `vc-di-eddsa` and
  `vc-data-integrity` contain zero occurrences of "direction", `rdfDirection` or `i18n`. JSON-LD 1.1 offers
  `rdfDirection: "i18n-datatype"` (dotNetRDF 3.5.1 implements it: `JsonLdRdfDirection.I18NDatatype`), but
  any implementation that enables it unilaterally produces signatures other RDFC verifiers cannot check.
  So "secure RDFC direction support" is an interop decision for DataProofs and the specs, not a bug fix.
- JCS suites (`eddsa-jcs-2022`, `ecdsa-jcs-2019`) sign the JSON as written, so direction-bearing
  credentials issue and verify there (probed in this session). JOSE, COSE and SD-JWT are unaffected.
- The `type` term-resolution test, a documented gap at 57/59, now **passes** because RDFC data-loss
  detection rejects an unmapped `type`. That holds only for RDFC-secured input.

## Decisions for the owner

**D1. Scope (recommended): direction-bearing RDFC credentials are unsupported in v1.2.0.**
- `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` and `bbs-2023` refuse to issue a document containing `@direction`
  (`InvalidOperationException` naming the cause) and fail to verify one (`DATA_LOSS_DETECTION_ERROR`,
  Rejected), including third-party RDFC credentials signed by implementations that dropped the direction.
- Supported path: the JCS suites, or omit `@direction` (language-only value objects work under RDFC).
- Alternative: hold #21 until DataProofs offers an opt-in `rdfDirection` mode. Even then the output is not
  interoperable with verifiers using the JSON-LD default, so I would still make the scope decision now.

**D2. File a public DataProofs issue** (not a vulnerability): "RDFC: opt-in lossless `@direction` via
JSON-LD 1.1 `rdfDirection: i18n-datatype`", stating the interop caveat and that the DI specs are silent.
Cross-repo, so your call.

**D3. Gate design: named known failures + a count floor** (addresses "lowering hides the regression").
- `W3cVcdm2SuiteTests` parses the mocha failure section and keys each failure on the suite's own assertion
  message (stable strings such as "Failed to accept a VC using `name` with language & direction expressed.").
- Pass requires **both**: every failure is in the documented known-failure list, **and** the passing count
  is ≥ 54. A failure outside the list fails the gate with its message, however many tests pass. A listed
  failure that starts passing prints a loud notice to remove it and raise the floor (not a failure: an
  upstream suite change must not break CI by itself).
- The known-failure list has five entries: the four direction cases and `relatedResource` digest.

## Changes

- [ ] **`tests/Credentials.Conformance.Tests/W3cVcdm2SuiteTests.cs`** — D3: `KnownFailures` list, failure
  parsing, both assertions; doc comment rewritten (currently says 57/59 and names the wrong gaps).
- [ ] **`docs/conformance.md`** — 54/59; the gap table gains the direction row (the four positions, the
  reason, the security meaning, the JCS alternative, the DataProofs issue, and the note that the later
  assertions in those four `it` blocks are not reached); `relatedResource` row unchanged; `type` row moves
  to "passes, via RDFC data-loss detection, for RDFC-secured input only"; the gate description explains
  the named-failure design.
- [ ] **`tests/Credentials.Rdfc.Tests/RdfcIssueVerifyTests.cs`** — focused coverage, a `[Theory]` over the
  four positions (`name`, `description`, `issuer.name`, `issuer.description`):
  1. RDFC issuance of a direction-bearing value object throws `InvalidOperationException` whose message
     names `@direction`, with the DataProofs exception as `InnerException`.
  2. The same document issues and verifies **Accepted** under `eddsa-jcs-2022` (the supported path).
  3. A language-only value object in the same position issues and verifies under RDFC (the limitation is
     direction, not language value objects).
  4. **Security meaning:** issue under RDFC with language only, then add `@direction` after signing →
     Rejected with `DATA_LOSS_DETECTION_ERROR`. Under DataProofs ≤ 1.4 this tampering verified Accepted.
- [ ] **`src/Credentials.Core/Securing/Internal/DataIntegrityMechanism.cs`** — the wrap message appends
  the first inner exception's message, so callers (and the shim's HTTP 400 body) see "uses @direction…"
  instead of only the generic "cannot be RDFC-canonicalized without losing data". One level only;
  DataProofs states its data-loss messages name the cause without quoting the input. Test 1 pins it.
- [ ] **`CHANGELOG.md`** v1.2.0 — the RDFC strictness bullet states the exact limitation, the JCS
  alternative, and the conformance effect (57 → 54, named).
- [ ] **`tests/Credentials.Extensions.DependencyInjection.Tests/JoseSubstrateRegressionTests.cs`** — the
  KB-JWT twin: Accepted with the matching nonce, then Rejected with a stale nonce **and** the holder-binding
  diagnostic names the nonce/freshness code (not `sdjwt_key_binding_invalid` for the signature). The VP-JWT
  twin: Accepted with the matching challenge, then Rejected with `holder_binding_replay`.
- [ ] File the DataProofs issue (D2) and reference it from the doc and CHANGELOG.
- [ ] Verification: `-warnaserror` build; full suite; the W3C job on the PR (I cannot run the suite locally;
  cloning + `npm install` of external code was blocked). Then reply to the review comment point by point.

## Review (results)

- All checklist items done. Build `-warnaserror`: 0 warnings / 0 errors.
- **Gate:** `W3cVcdm2SuiteTests` now keys on five named known failures plus a floor of 54, fails closed if
  the mocha failure section cannot be parsed, and prints a notice when a known failure starts passing.
  `ParseFailures` is pinned by four unit tests against a captured mocha excerpt (they run locally; the suite
  itself only runs on CI).
- **Focused coverage:** `RdfcIssueVerifyTests` gained two theories over the four suite positions (8 cases):
  RDFC refuses `@direction` with a message naming it, JCS secures the same document, language-only secures
  under RDFC, and adding `@direction` after RDFC signing is Rejected with `DATA_LOSS_DETECTION_ERROR`.
- **Twin test:** both twins are Accepted with matching expectations before the stale case; the stale VP
  asserts `holder_binding_replay`, the stale KB-JWT asserts the key-binding code and not an issuer-signature
  code. Credentials maps every KB-JWT problem to one code, so the Accepted assertion is what excludes a
  signature failure. A distinct KB-JWT freshness code would be a small follow-up, not part of this PR.
- **Docs:** `docs/conformance.md` rewritten (54/59, the gate design, the direction row, the unreached
  assertions, the `type` case now passing for RDFC input); CHANGELOG updated.
- The W3C job's verdict on the pushed head is recorded in the PR thread.

## Explicitly not changing

- The shim stays on `eddsa-rdfc-2022`. Switching it to JCS would make the four cases pass and the `type`
  case fail again, changing what the suite measures to get a green run.
- No DataProofs guard is weakened and no `@direction` is stripped before signing.
