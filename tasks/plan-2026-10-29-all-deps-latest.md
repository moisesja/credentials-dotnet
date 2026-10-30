# Plan — update every dependency to its latest stable version (v1.2.0)

Status: **APPROVED 2026-10-29 and IMPLEMENTED** on `fix/dataproofs-1.3.0-issue-20` (folded into PR #21).
The pre-approval evidence came from a scratch trial worktree (`fa4c3e4` + these changes); the Review
section records the results on the real branch.

## Owner's intent

> "we have a mess here. I made a lot of changes upstream. Please update ALL your dependencies to their
> latest versions"

The first-party stack moved forward in a coordinated way: DataProofs 1.5.0, NetDid 4.0.0 and
DidComm.Core 1.5.0, all released 2026-10-28. Credentials still pins the older stack: DataProofs 1.3.0,
NetDid 2.3.0, Microsoft.Extensions 10.0.8. So a consumer that combines Credentials with DidComm.Core 1.5.0
resolves a graph Credentials was never built or tested against. The goal is that **every** dependency is
on its latest stable version, Credentials converges exactly with the rest of the stack, and it ships as v1.2.0.

## Decisions already taken (earlier in this session)

- Release as **v1.2.0**, a minor version.
- NetCrypto **1.7.1**, the latest, rather than the 1.4.0 floor.
- The **`v1.2.0` tag is held** until further fixes targeted at v1.2.0 land.
- Security findings go to private advisories, per `SECURITY.md`. Nothing about them appears in public commits.

**Owner decisions on this plan (2026-10-29):**
1. FluentAssertions **stays at 7.0.0** (licence).
2. **Fold** the all-latest update into PR #21.
3. **Re-enable** the Conformance workflow. Done: `gh workflow enable Conformance`.

## Inventory (current → latest stable)

| Package | Now | Target | Notes |
|---|---|---|---|
| DataProofsDotnet.Core/Jose/Cose/Rdfc/Extensions.DependencyInjection | 1.3.0 | **1.5.0** | security fixes; source-compatible; rebuild required |
| NetDid.Core/Method.Key/Extensions.DependencyInjection | 2.3.0 | **4.0.0** | no source change; `NetDidBuilder` (in our public API) changes are additive only |
| JsonSchema.Net | 7.3.2 | **9.5.0** | **API break**: one file to port (below) |
| Microsoft.Extensions.* (6 packages) | 10.0.8 | **10.0.14** | **required**: NetDid 4.0.0 floors 10.0.14, so staying is an NU1605 downgrade |
| System.Reflection.MetadataLoadContext | 10.0.8 | 10.0.14 | |
| Microsoft.CodeAnalysis.PublicApiAnalyzers | 4.14.0 | 5.6.0 | no new diagnostics |
| Microsoft.NET.Test.Sdk | 17.12.0 | 18.11.0 | |
| xunit.runner.visualstudio | 2.8.2 | 4.0.1 | xunit itself is already at its latest, 2.9.3 |
| NSubstitute | 5.3.0 | 6.2.0 | |
| coverlet.collector | 6.0.3 | 10.1.0 | |
| Xunit.SkippableFact | 1.5.61 | 1.5.85 | |
| Microsoft.DotNet.ApiCompat.Tool (dotnet tool) | 10.0.301 | 10.0.403 | |
| FluentAssertions | 7.0.0 | 8.11.0 | **decision 1**: licence |
| NetCrypto 1.7.1, NetCid 1.6.0, xunit 2.9.3, SourceLink 10.0.403 | — | — | already latest |

The resolved graph matches DidComm.Core 1.5.0's floors exactly: Jose 1.5.0, NetCrypto 1.7.1, NetDid.Core
4.0.0 and Microsoft.Extensions 10.0.14.

## Required code changes (each one found by the trial, not assumed)

1. **Port `JsonSchema2020Validator` to JsonSchema.Net 9** (`src/Credentials.Core/Schema/Internal/`).
   - Mechanical part: v9 moved the dialect to `BuildOptions.Dialect`, `Evaluate` now takes a `JsonElement`
     (so the extra `JsonNode` parse goes away), and `HasErrors` is gone.
   - **Two security regressions a compile-only port would have shipped.** I found both by probing; the
     existing tests catch neither.
     - **Global registry.** v9 registers every built schema in the *process-wide* `SchemaRegistry.Global`.
       - An attacker-supplied schema's `$id` would then resolve another credential's `$ref`. Probe: a later
         `$ref` changed from Indeterminate to **Failure** using the earlier schema.
       - Reusing a `$id` would throw `JsonSchemaException: Overwriting registered schemas is not permitted`.
       - Fix: a fresh local `SchemaRegistry` per validation.
     - **Escaping exception.** v9 throws `JsonSchemaException` for structurally invalid schemas (`{"type":5}`,
       `{"$ref":1}`, an unknown `$schema`). The current `catch` misses it, so the exception escapes a
       validator documented as never throwing. v7 returned Indeterminate for all of these. Fix: add
       `JsonSchemaException` to the `catch`.
   - With both fixes, **v9 matches v7 on every probe**:
     - external `$ref` → Indeterminate, with **no network request** (checked with a local HTTP listener);
     - no leakage across validations;
     - `$id` reuse works;
     - malformed schemas → Indeterminate;
     - the ReDoS pattern is cut off by the 5 s regex timeout → Indeterminate.
   - The only difference: an unknown `$schema` now reports `schema.unparseable` rather than
     `schema.evaluation_error`. Both are Indeterminate.
   - **New tests pin all of this**, since none existed: registry isolation, `$id` reuse, malformed schemas,
     external `$ref`, ReDoS bounded.
2. **Keep `IIssuer.IssueAsync`'s documented exception contract.**
   - DataProofs 1.4.0 changed `AddProofAsync` to throw its own `ProofGenerationException` where it used to
     throw raw `InvalidOperationException`, `JsonException` or `ArgumentException`.
   - `IIssuer` documents only `NotSupportedException` and `InvalidOperationException`, and NFR-005 keeps
     DataProofs types behind the mechanisms.
   - With 1.5.0 this becomes common: any RDFC credential with an undefined term throws it.
   - Fix: `DataIntegrityMechanism.SecureAsync` wraps `ProofGenerationException` in `InvalidOperationException`,
     with a clear message and the inner exception kept. Add a test.
3. **Message for the new problem code.** Add a `DATA_LOSS_DETECTION_ERROR` case to
   `DefaultVerifier.MapProofMessage`; today it falls back to "The proof is invalid.". Verdicts already fail
   closed: any unverified Data Integrity result maps to Failed.
4. **RDFC sample** (`samples/Credentials.Sample.DataIntegrityRdfc`): add
   `https://www.w3.org/ns/credentials/undefined-terms/v2` as the last `@context`. Its custom `degree` claims
   are undefined terms that DataProofs 1.5.0 now refuses to sign. The context is bundled in DataProofs'
   offline loader. Verified in the trial: 14/14 samples pass.
5. Version pins (`Directory.Packages.props`, with updated rationale comments) and
   `.config/dotnet-tools.json`.

**Trial result with items 1, 4 and 5 applied:** build 0 warnings / 0 errors; **396/396 tests pass**.

## Behaviour changes to document (CHANGELOG v1.2.0)

**DataProofs 1.5.0 RDFC data-loss fix** (upstream security fix, #36). Before it, anything RDFC
canonicalization silently dropped or respelled was not signed, so a holder could change it. Every custom
claim of a credentials/v2-only credential fell into this category.
- RDFC issuance now refuses such documents; verification fails them with `DATA_LOSS_DETECTION_ERROR`.
- **RDFC credentials issued earlier with undefined terms will no longer verify.** That includes ones
  Credentials issued on ≤ 1.1.1.
- Migration: define the terms in a context, or list `credentials/undefined-terms/v2` last.
- VCDM 1.1 RDFC proofs without `https://w3id.org/security/data-integrity/v2` are also refused. Their proof
  configuration was unsigned.
- bbs-2023 fixes: literal relabeling, and the `@id` re-insertion.

**DataProofs 1.4.0 strictness.** Malformed UTF-8 or a lone surrogate in a JOSE header, an SD-JWT
disclosure, or a Data Integrity document now ends **Failed** instead of Indeterminate. That closes
holder-triggerable paths to Indeterminate. Invalid-UTF-8 compact headers now fail (dataproofs#28, which we
filed, is closed).

**NetDid 3.0–4.0:**
- stricter DID syntax and DID-document validation, so more inputs resolve as errors (→ Indeterminate);
- a verification method's `controller` is now required (#121);
- relative verification-method ids are now legal and kept as written.

None of these change a did:key verdict.

**Upstream API changes:** none affect Credentials. There is no public API change, and ApiCompat runs in
verification. The default (Core + DI) closure stays Newtonsoft-free; NetDid 4.0's DI package adds only
`NetDid.Method.Ethr.dll`, which has no Nethereum dependency.

## Explicitly not in this PR

The analysis also surfaced some pre-existing hardening items in the key-resolution code. They are tracked
privately with the security work targeted at v1.2.0, per `SECURITY.md`, and are not part of this
dependency update.

## Verification

- Release build with warnings as errors (PublicAPI analyzers 5.6); full suite; sample smoke tests.
- `dotnet list --vulnerable --include-transitive` = 0; `check-no-newtonsoft-closure.sh`.
- `check-api-compat.sh` against 1.1.1, with the 10.0.403 tool.
- Pack 1.2.0 and inspect the nuspec floors.
- **DidComm consumer check against `DidComm.Core` 1.5.0**: all 14 samples, printing the loaded versions.
- **Adversarial agent pass** on the changed code: the validator (registry poisoning, `$ref`/SSRF, ReDoS,
  exception escape) and the issuance exception wrap.
- **W3C conformance:** I can't run it locally, because cloning the suite and `npm install` was blocked as
  external code. It runs on GitHub for PRs touching `src/`/`tests/`, but the workflow is
  `disabled_inactivity`, so it needs `gh workflow enable Conformance` (decision 3). The baseline is 57.
  RDFC issuance by the shim could move it if the suite sends undefined terms; any drop is investigated,
  never papered over.

## Decisions for the owner

1. **FluentAssertions 7.0.0 → 8.11.0.**
   - The technical cost is trivial: 2 compile errors (`NotContainKey` on JSON-node assertions) in one test file.
   - The catch is the licence: 8.x is under Xceed's licence, which needs a paid licence for commercial
     use. Your lessons pin 7.0.0 as the last free (Apache-2.0) version.
   - **Recommendation: keep 7.0.0** unless you hold or want a licence. Say so and I'll bump it.
2. **Release vehicle.** Recommendation: **fold this into the open PR #21.**
   - v1.2.0 is unreleased, and #21 is a dependency PR for the same release.
   - I'd retitle it "update all dependencies to latest (#20), v1.2.0" and rewrite its description and the
     CHANGELOG entry. The #20 fix still holds, now built against DataProofs 1.5.0.
   - Alternative: merge #21 as it is, then open a second PR.
3. **Re-enable the Conformance workflow** (`gh workflow enable Conformance`) so the PR runs the W3C suite.
4. **Order.** Land this first; the remaining v1.2.0 work follows. The tag waits for both.

## Checklist (after approval)

- [x] Version pins and tool manifest, with rationale comments
- [x] Port `JsonSchema2020Validator` (local registry, `JsonSchemaException` catch) + new security tests
- [x] Wrap `ProofGenerationException` at issuance + test
- [x] `DATA_LOSS_DETECTION_ERROR` message + test
- [x] RDFC sample `@context`
- [x] Gates (above) + adversarial pass + DidComm 1.5.0 consumer check
- [x] CHANGELOG v1.2.0 rewrite; task record; lessons; memory
- [ ] Push to #21 (or a new PR, per decision 2); reply on the PR; watch CI and conformance

## Review (results on the real branch)

- **Build and tests:**
  - `dotnet build -c Release -warnaserror`: 0 warnings / 0 errors (PublicApiAnalyzers 5.6.0).
  - `dotnet test --filter "Category!=Conformance"`: **418 passed**, 0 failed. That is the previous 396
    plus 20 schema-validator tests and 2 RDFC tests.
- **Package gates:**
  - Vulnerable packages: 0 across 29 projects.
  - `check-no-newtonsoft-closure.sh`: OK. NetDid 4.0's DI package adds only `NetDid.Method.Ethr.dll`.
  - `check-api-compat.sh` (tool 10.0.403): **no breaking changes** for Core, DI and Rdfc against 1.1.1.
  - Packed 1.2.0 nuspecs require DataProofs ≥ 1.5.0, NetDid ≥ 4.0.0, NetCrypto ≥ 1.7.1, JsonSchema.Net
    ≥ 9.5.0 and Microsoft.Extensions ≥ 10.0.14. Rdfc declares no AngleSharp.
- **Consumer check:** a scratch app referencing **`DidComm.Core` 1.5.0** and the packed 1.2.0 runs
  **14/14 samples**. The graph is uniform: DataProofs 1.5.0, NetCrypto 1.7.1, and NetDid.Core / Method.Key
  / Extensions.DependencyInjection all at 4.0.0.
- **Adversarial pass on the changed code**, about 160 probes, with a v7 vs v9 differential:
  - It found three regressions in the first port of the validator. All three are fixed, each pinned by a
    test, and **each fix mutation-checked**: with the fix removed, the test fails.
    1. **Dialect-registry poisoning.** JsonSchema.Net 9 records document-defined `$schema` dialects in a
       process-wide registry, first writer wins. An attacker's schema could redefine a custom dialect as
       core-only, so a later victim credential flipped from Rejected to Accepted. The same unsynchronized
       dictionary also grew without bound and corrupted under concurrency. Fix: a fresh local
       `DialectRegistry` per validation.
    2. **Exceptions escaping `Validate`.** A non-string `$schema`, or a lone surrogate in a keyword value,
       threw `InvalidOperationException` where v7 returned Indeterminate. Fix: the build step maps every
       non-cancellation exception to Indeterminate `schema.unparseable`.
    3. **Global fetch fallback.** JsonSchema.Net falls back to `SchemaRegistry.Global.Fetch`, which other
       code in the process may set. Fix: the local registry's `Fetch` refuses, so no external reference is
       fetched under any configuration.
  - Also corrected: a false code comment claiming the dialect was fixed at 2020-12; the CHANGELOG now
    describes the actual `$schema` semantics.
  - Confirmed sound:
    - schema-registry isolation;
    - no network egress across 14 network-shaped schemas;
    - no DataProofs exception type escaping issuance or presentation binding (36 hostile documents ×
      4 suites);
    - RDFC data-loss tampering → Failed `DATA_LOSS_DETECTION_ERROR`;
    - did:key edge inputs under NetDid 4.0 never Accepted.
  - The pass also surfaced findings that **pre-date** this update (they reproduce at `fa4c3e4`). Per
    `SECURITY.md` they were reported to the owner privately, outside this PR.
- **W3C conformance:** the workflow is re-enabled and runs on the PR, as I can't run it locally. Results go
  in the PR thread.
