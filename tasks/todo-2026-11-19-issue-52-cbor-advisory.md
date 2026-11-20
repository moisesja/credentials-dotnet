# Todo: issue #52, System.Formats.Cbor advisory blocks restore

Plan: `tasks/plan-2026-11-19-issue-52-cbor-advisory.md`. Branch `fix/issue-52-cbor-advisory`.

## Checklist

- [x] Reproduce on `main` (047acf3): `dotnet restore Credentials.sln` fails `NU1902` for every project.
- [x] Read the advisory: patched 10.0.15 (10.0 line) and 11.0.0; colliding map keys, fixed with seeded Marvin hashing.
- [x] Inventory every `PackageVersion` and dotnet tool against nuget.org latest stable (plan, Inventory).
- [x] Research the verify-side packages: Cbor (advisory, DataProofs reader modes), JsonSchema.Net (upstream
      compare d3b5142..c1646b3, release notes), Microsoft.Extensions 10.0.15 (servicing notes).
- [x] `Directory.Packages.props`:
  - add the `System.Formats.Cbor` 10.0.15 pin;
  - JsonSchema.Net 9.7.0; Microsoft.Extensions.* 10.0.15;
  - SourceLink 11.0.100; MetadataLoadContext 11.0.0; Test.Sdk 18.12.0; coverlet 10.1.1;
  - remove the unused Caching.Memory pin;
  - comments for each change and hold-back.
- [x] `src/Credentials.Core/Credentials.Core.csproj`: versionless `System.Formats.Cbor` reference, commented.
- [x] `.config/dotnet-tools.json`: ApiCompat 11.0.100.
- [x] `dotnet pack`: Core's nuspec declares `System.Formats.Cbor >= 10.0.15`; DI and Rdfc inherit it via Core.
- [x] Prove the consumer gate has teeth: pack Core without the pin, then the ConsumerProbe restore fails `NU1902`.
- [x] Adversarial pass (two agents, A/B old vs new through `IVerifier`), before the first commit.
- [x] Pin each uncovered verify-side change, and mutation-check it on the old versions:
  - [x] `M3EnvelopingTests.Cose_unprotected_header_nesting_is_bounded` (fails on Cbor 10.0.8).
  - [x] `SchemaValidatorTests.DynamicRef_*` and `A_v1_subschema_inside_a_2020_12_schema_*` (fail on 9.6.0,
        exactly the v1 rows).
  - [x] `SchemaValidatorTests.Hostname_*` (pins an invariant that holds on both versions; fails when the validator's
        build dialect is switched to draft 6).
- [x] CHANGELOG: `## v1.2.0 - 2026-11-03`, new `## Unreleased` above it.
- [x] Follow-ups filed: #53 (remove the pin after dataproofs-dotnet#50) and #54 (schema-stage dialect policy and gaps).
- [x] Lesson added (`tasks/lessons.md`): a patch release's advisory is not its changelog.
- [x] Clean Release build, full test suite, the CI gate scripts.
- [ ] PR opened; CI and Conformance green on the PR.
- [ ] Review loop: every finding addressed; reviewer's verdict on the current head.
- [ ] Merged; `main` pulled; issue #52 closed.

## Review / results

### Verification (local, SDK 10.0.404, after a clean of all bin/obj)

- `dotnet restore Credentials.sln`: clean (was `NU1902` on `main`).
- `dotnet build Credentials.sln -c Release`: 0 warnings, 0 errors.
- `dotnet list Credentials.sln package --vulnerable --include-transitive`: 29 of 29 projects have no vulnerable package.
- `dotnet test Credentials.sln -c Release`: 442 passed, 1 skipped (the W3C conformance fact, which needs the Node suite).
  - Before the new pins, the branch ran 428 passed, the same count recorded for the v1.2.0 head, so the
    Test.Sdk/coverlet bumps did not change test discovery.
  - Per assembly: Core.Tests 204, DI.Tests 168, Rdfc.Tests 29, RoundTrip 9, SampleSmoke 14, Interop 5,
    Architecture 9, Conformance 4 + 1 skipped.
- `tools/check-no-newtonsoft-closure.sh`: NFR-002 OK; the packed-consumer closure resolves `System.Formats.Cbor 10.0.15`.
- `tools/check-api-compat.sh` (ApiCompat 11.0.100): no breaking changes for Core / DI / Rdfc against the published 1.2.0.
- `tools/run-api-coverage.sh` (coverlet 10.1.1): 53 covered, 0 uncovered.
- SourceLink 11.0.100 generates the correct `raw.githubusercontent.com` source-link map.

### Adversarial pass

| Finding | Verified | Resolution |
|---|---|---|
| Cbor 10.0.15 adds an unannounced 64-level CBOR depth cap. A genuine COSE credential with a deeply nested unsigned unprotected header went from Accepted to `CredentialFormatException`; at the 4 MiB limit, 10.0.8 took about 0.9 s and 830 MB | In-repo test; mutation on 10.0.8 makes the 1000-level row accept | Pinned (`Cose_unprotected_header_nesting_is_bounded`) and documented (CHANGELOG Security, props comment). Fail-closed hardening, taken |
| Hash flood reachable only through the bbs-2023 proofValue label map (strict reader); COSE reads in lax mode. It needs the per-process seed; 10.0.15 closes it | DataProofs source read; agent's A/B timings | Documented (CHANGELOG, props comment) |
| JsonSchema.Net 9.7.0 reverses the v1-dialect `$dynamicRef` anchor form, reachable through a declared `$schema` at any depth. Flips only between Indeterminate and evaluated | In-repo tests; mutation on 9.6.0 fails exactly the 5 v1 tests | Pinned (`DynamicRef_*`, `A_v1_subschema_*`) and documented (CHANGELOG Changed, props comment); dialect policy filed as #54 |
| `hostname`: the draft 6 / v1 IDNA change does not reach verification (formats come from the 2020-12 build dialect) | Own probe across dialects and build dialects | Pinned (`Hostname_*`) |
| `Microsoft.Extensions.Caching.Memory` pin referenced by no project | `git grep`; added in the M0 scaffold | Removed |
| Microsoft.Extensions 10.0.15: identical IL to 10.0.14; fetcher redirect and scheme posture unchanged | Agent's IL hash and behaviour probe; `HttpFetchRedirectTests` pass | No action |
| Pre-existing: schema remark overstates root self-defined dialects; empty-keyword `schema.` code from `unevaluatedProperties`; no HTTPS-only-default test | Reproduced in a throwaway test (deleted) and by `git grep` | Filed #54 |
| Pre-existing, upstream: bbs-2023 proofValue malleability (non-canonical or duplicate key encodings, trailing bytes, unused label-map entries still verify; no forgery) | Agent's A/B (identical on both versions) | Reported to the owner; upstream (DataProofs), not filed here |

No exception other than the documented `CredentialFormatException` escaped `VerifyCredentialAsync` on either version.

### CI / review

- PR: _pending_
