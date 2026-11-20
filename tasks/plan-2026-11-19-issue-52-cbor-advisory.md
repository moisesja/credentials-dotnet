# Plan: issue #52, restore fails on `main` (System.Formats.Cbor advisory)

Branch `fix/issue-52-cbor-advisory`. Checklist: `tasks/todo-2026-11-19-issue-52-cbor-advisory.md`.

## Owner's intent

- Unblock CI. `dotnet restore Credentials.sln` on `main` (047acf3) fails with `NU1902` (warnings are errors)
  because `System.Formats.Cbor` 10.0.8, which `DataProofsDotnet.Cose` 2.0.0 brings in transitively, carries
  GHSA-vmv3-wvjp-wqpj (CVE-2026-118747). The nightly Conformance workflow fails every day for the same reason.
  This is step 0 of epic #23: every later SD-JWT PR needs green CI.
- Fix it here, in this repo only. The upstream floor bump is moisesja/dataproofs-dotnet#50 and is not part of
  this work.
- Consumers of the published packages must also resolve a patched Cbor, not only this repo's build.
- Per `tasks/lessons.md`, a dependency PR updates the whole graph to latest, and every hold-back is listed with
  its reason. FluentAssertions stays at 7.0.0 (owner hold, licence).
- Fold in the known doc fix: CHANGELOG's `## v1.2.0 - Unreleased` becomes `## v1.2.0 - 2026-11-03` (tag
  `v1.2.0` on 047acf3), with a new `## Unreleased` entry above it.
- Short but real adversarial pass: confirm no bump changed a verify-side behaviour the tests don't cover.

## Decisions

1. **Pin with a direct reference in `Credentials.Core`, not CPM transitive pinning.** A central
   `PackageVersion` plus a versionless `<PackageReference Include="System.Formats.Cbor" />` in
   `Credentials.Core.csproj`, the project that brings in Cose. This is the issue #18 (AngleSharp) precedent.
   - The floor lands in Core's nuspec (`System.Formats.Cbor >= 10.0.15`, checked with `dotnet pack`).
   - Every published package (DI, Rdfc) depends on Core, so it covers `DataProofsDotnet.Rdfc`'s 10.0.8 floor too.
   - `CentralPackageTransitivePinningEnabled` was considered and rejected. It applies to every `PackageVersion`
     in the file, would promote other transitive packages (e.g. `Microsoft.Extensions.DependencyInjection.Abstractions`)
     into the nuspecs as new direct dependencies, and is less explicit than one commented reference.
   - Removal: once DataProofs floors a patched Cbor (dataproofs-dotnet#50), the pin goes. If DataProofs floors
     above 10.0.15, the pin becomes an `NU1605` downgrade and fails loudly, which forces the removal.
2. **Stay on the 10.0 line for consumer-facing .NET platform packages.** .NET 11 shipped since the last
   dependency pass, so `Microsoft.Extensions.*` and `System.Formats.Cbor` have an 11.0.0. Those floors reach
   every consumer's graph. The library targets .NET 10 (D7, NFR-001), and the rest of the first-party stack
   (NetDid 4.0.0, DataProofs 2.0.0, DidComm) is on 10.0.x. Taking 11.0.0 would put .NET 11 packages into every
   .NET 10 app and override ASP.NET Core 10's shared-framework copies. That is a stack-wide decision for the
   owner, so they move to the latest 10.0 servicing release (10.0.15) and the 11.0 move is reported, not taken.
   Cbor 11.0.0 is also patched; 10.0.15 is the version the issue names.
3. **Dev-only and build-only packages take the latest, including 11.x.** None of them reach a consumer, and each
   was checked to run unchanged on the .NET 10 SDK: SourceLink 11.0.100 (net10.0 task assets; the generated
   source-link map is correct), the ApiCompat tool 11.0.100 (runs on net10.0; ApiCompat clean against the
   published 1.2.0), MetadataLoadContext 11.0.0 (net10.0 build; ArchitectureTests pass).
4. **Remove the `Microsoft.Extensions.Caching.Memory` pin.** It was added in the M0 scaffold and no project has
   ever referenced it, and CPM transitive pinning is off, so it did nothing. Keeping it at "latest" would claim
   control it never had.
5. **JsonSchema.Net 9.7.0 is taken, with its one reachable change pinned.** It is third-party, its v1
   `$dynamicRef` change aligns with the current JSON Schema Test Suite, and it never moves a result between
   Success and Failure (see the adversarial pass). The orchestrator's hold-back rule for verify-side changes
   applies to first-party packages, and no first-party package moves in this PR.

## Inventory (nuget.org latest stable, 2026-11-19)

| Package | Was | Latest | Now | Note |
|---|---|---|---|---|
| DataProofsDotnet.Core / .Rdfc / .Jose / .Cose / .Extensions.DependencyInjection | 2.0.0 | 2.0.0 | 2.0.0 | at latest |
| NetCrypto | 1.7.1 | 1.7.1 | 1.7.1 | at latest |
| NetDid.Core / .Method.Key / .Extensions.DependencyInjection | 4.0.0 | 4.0.0 | 4.0.0 | at latest |
| NetCid | 1.6.0 | 1.6.0 | 1.6.0 | at latest |
| System.Formats.Cbor | 10.0.8 (transitive) | 11.0.0 | **10.0.15** | new direct pin; **held** on 10.0 (decision 2) |
| JsonSchema.Net | 9.6.0 | 9.7.0 | **9.7.0** | |
| Microsoft.Extensions.DependencyInjection(.Abstractions), .Http, .Logging.Abstractions, .Options | 10.0.14 | 11.0.0 | **10.0.15** | **held** on 10.0 (decision 2) |
| Microsoft.Extensions.Caching.Memory | 10.0.14 | 11.0.0 | **removed** | unreferenced (decision 4) |
| Microsoft.SourceLink.GitHub (build-only) | 10.0.403 | 11.0.100 | **11.0.100** | |
| Microsoft.CodeAnalysis.PublicApiAnalyzers | 5.6.0 | 5.6.0 | 5.6.0 | at latest |
| System.Reflection.MetadataLoadContext (test-only) | 10.0.14 | 11.0.0 | **11.0.0** | |
| Microsoft.NET.Test.Sdk | 18.11.0 | 18.12.0 | **18.12.0** | |
| xunit | 2.9.3 | 2.9.3 | 2.9.3 | at latest (v3 is a different package id) |
| xunit.runner.visualstudio | 4.0.1 | 4.0.1 | 4.0.1 | at latest |
| FluentAssertions | 7.0.0 | 8.11.0 | 7.0.0 | **held**: owner decision, licence |
| NSubstitute | 6.2.0 | 6.2.0 | 6.2.0 | at latest |
| coverlet.collector | 10.1.0 | 10.1.1 | **10.1.1** | |
| Xunit.SkippableFact | 1.5.85 | 1.5.85 | 1.5.85 | at latest |
| dotnet tool microsoft.dotnet.apicompat.tool | 10.0.403 | 11.0.100 | **11.0.100** | |
| SDK (`global.json`) | 10.0.100, `latestFeature` | | unchanged | already floats to the latest 10.0 SDK (CI used 10.0.403, local 10.0.404) |

First-party changelog review: no first-party package changes version, so there is no first-party changelog to read.

## Upstream research (third-party, verify-side)

- **System.Formats.Cbor 10.0.8 → 10.0.15.** The advisory: colliding map keys hash-flood the uniqueness check;
  the fix seeds Marvin hashing. DataProofs Cose reads COSE_Sign1, its headers and CWT claims in `Lax` mode (no
  uniqueness check). `Bbs2023ProofValue` uses the default `Strict` mode, so only bbs-2023 reaches it.
- **JsonSchema.Net 9.6.0 → 9.7.0** (json-everything d3b5142..c1646b3): .NET 11 support, a new net10.0 build,
  `hostname` without IDNA rules for draft 6 / v1, and the v1 `$dynamicRef` anchor form. JsonPointer.Net
  7.0.4 → 7.1.0 and Json.More.Net 3.0.1 → 3.1.0 only add .NET 11 targets.
  - The validator always builds with `Dialect.Draft202012`, and the format registry comes from the build
    dialect, not the declared `$schema` (`options.FormatRegistry ?? _buildOptions.Dialect.FormatRegistry`). So
    `hostname` keeps the IDNA rules for every schema, on both versions (probed across dialects; the change shows
    only when the build dialect is draft 6).
- **Microsoft.Extensions 10.0.15**: the November 2026 servicing release. No package-specific notes.

## Test plan

- `dotnet restore` / `dotnet build -c Release` (warnings are errors) / `dotnet test Credentials.sln`: green.
- `dotnet list package --vulnerable --include-transitive`: 0 vulnerable packages across all 29 projects.
- `dotnet pack`: Core's nuspec declares `System.Formats.Cbor >= 10.0.15`.
- The CI gate scripts locally: `check-no-newtonsoft-closure.sh`, `check-api-compat.sh`, `run-api-coverage.sh`.
- **The consumer gate has teeth.** The no-Newtonsoft job restores a real consumer (ConsumerProbe) from freshly
  packed packages under the repo's warnings-as-errors. Packing Core without the pin makes that restore fail
  `NU1902` on Cbor 10.0.8; with the pin it resolves 10.0.15.
- New pins, each mutation-checked against the old package versions:
  - `M3EnvelopingTests.Cose_unprotected_header_nesting_is_bounded`: a genuine COSE credential with 10 nested
    levels in its unsigned unprotected header verifies; 1000 levels throws `CredentialFormatException`. Fails on
    Cbor 10.0.8.
  - `SchemaValidatorTests.DynamicRef_*` and `A_v1_subschema_inside_a_2020_12_schema_*`: the v1 and 2020-12
    `$dynamicRef` forms, with positive controls. Fail on JsonSchema.Net 9.6.0, exactly on the v1 rows.
  - `SchemaValidatorTests.Hostname_*`: IDNA rules under every declared dialect, plus a positive control. They pin
    an invariant that holds on both versions, and fail if the validator's build dialect changes (checked by
    switching it to draft 6).
- CI on the PR. `conformance.yml` runs on pull requests that touch `src/**` or `tests/**`, and this PR touches
  both, so the W3C suite runs on the PR without a manual dispatch.

## Risks

- **New nuspec dependency.** `Credentials.Core` gains a direct `System.Formats.Cbor` dependency. It is the same
  package consumers already got transitively, so the closure doesn't grow; the NFR-002 closure gate stays green.
- **Upstream drift.** When DataProofs ships dataproofs-dotnet#50, the pin must go. Filed as #53.
- **Published 1.2.0 consumers** still resolve 10.0.8 until the next release, so this PR says `Refs #52` and
  #52 stays open until a release carrying the pin ships (review round 1; releasing is the owner's call). The CHANGELOG tells them how to pin
  locally. This PR does not bump `CredentialsVersion`, tag or release (protocol).
- **Dev-only 11.x tools on the 10.0 SDK.** They run locally on SDK 10.0.404, and CI resolves the latest
  10.0.4xx SDK. If a CI job disagrees, the fallback is the 10.0.404 / 10.0.15 builds of the same tools.

## Adversarial pass (before the first commit)

Two agents, one per verify-side package, both A/B-testing the old and new versions through `IVerifier` with
post-sign tampering and self-consistent forgeries, each proving which assembly loaded.

- **Cbor.** The bump carries an unannounced second change: a CBOR max nesting depth of 64. A genuine COSE
  credential whose unsigned unprotected header nests 63+ levels verified on 10.0.8 and is refused as malformed
  on 10.0.15. It also removes a ~0.9 s / ~830 MB decode cost at the 4 MiB input limit. That is fail-closed
  hardening, not a regression, and no test covered it. Fixed: pinned by `Cose_unprotected_header_nesting_is_bounded`
  and documented. The hash flood is reachable in code on 10.0.8 only through the bbs-2023 label map, needs the
  per-process seed, and is closed on 10.0.15. All bbs-2023 and other COSE cases are identical on both versions.
  No exception escapes `VerifyCredentialAsync` other than the documented `CredentialFormatException`.
- **JsonSchema.Net / Microsoft.Extensions.**
  - Across 2,927 JSON-Schema-Test-Suite tests under every dialect and 118 end-to-end rows, the only
    difference is the v1 `$dynamicRef` form. A declared `$schema` can reach the v1 dialect at the root or in any
    subschema.
  - Every flip is between Indeterminate and evaluated, never between Success and Failure. No test covered it.
    Fixed: pinned and documented.
  - Hostname, 2020-12 `$dynamicRef`, 2019-09 `$recursiveRef`, registry isolation, no-fetch and the HTTP
    fetchers' redirect and scheme posture are unchanged. Microsoft.Extensions 10.0.15 has IL identical to 10.0.14.
  - Found the dead Caching.Memory pin (decision 4).
- **Pre-existing, unchanged by this PR**, identical on the old and new versions. None is fixed here.
  - Schema stage, filed as #54: which declared dialects to honour (an owner decision against D9/NFR-005); a
    validator remark that overstates self-defined root dialects; an empty-keyword diagnostic code from
    `unevaluatedProperties`; no test for the HTTP fetchers' HTTPS-only default.
  - Upstream in DataProofs `Bbs2023ProofValue`, reported to the owner and not filed here (in this repo only):
    proofValue malleability. Different bytes still verify: a duplicate label-map key in a second integer
    encoding, non-canonical key encodings, trailing bytes after the array, unused extra label-map entries. No
    forgery; never deduplicate on proofValue bytes.
