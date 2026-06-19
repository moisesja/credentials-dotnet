# Changelog

All notable changes to `credentials-dotnet` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Milestone M0 (skeleton, core model, structural validation, DI)

- Repository scaffolding: `Credentials.sln`, central package management, `Directory.Build.props/.targets`,
  `global.json` (.NET 10), Apache-2.0 license, thin-router README.
- `Credentials.Core` document-centric core model (D10 / OQ-3): `CredentialDocument` (frozen single source of
  truth with verbatim-byte fidelity and three faithful projections), `Credential`, `VerifiablePresentation`,
  `ContainedCredential`, write-through `CredentialBuilder` / `VerifiablePresentationBuilder`, and the
  `SecuringState` / `DocumentOrigin` / `VcdmVersion` enums.
- `CredentialJson.Faithful` — the faithful (not canonical) serializer, derived at init from
  `DataProofsDotnet.DataProofsJsonOptions.Default` so signed-bytes == wire-bytes (fix F1).
- `StructuralValidator` — version-aware VCDM 2.0 / 1.1 structural conformance with the conformance fixes folded
  in (A1–A3, B1, C1–C2, D1, F8, H2–H4).
- Engine crypto seams: `IDigestService` over `NetCrypto.Hash`, and an `IRandomSource` RNG seam (wraps the BCL
  RNG — `NetCrypto` exposes no RNG abstraction).
- `Credentials.Extensions.DependencyInjection`: `AddCredentials` + `CredentialsBuilder` + `CredentialsOptions`.

### Security / hardening — M0 adversarial review (2026-06-18)

- Reject duplicate JSON object keys eagerly at parse (`AllowDuplicateProperties = false`), closing an
  unhandled-`ArgumentException` DoS, a "never throws" contract break in `ValidateStructure`, and a
  signed-bytes-vs-parsed-tree discrepancy.
- Bound parsed input size (`CredentialDocument.MaxInputBytes`, 4 MiB) to cap memory amplification on
  untrusted input (NFR-006).
- Structural validation now rejects: non-string/non-object `@context` entries after index 0; empty
  objects inside a `credentialSubject` array; and blank/empty identity & type strings (`issuer.id`,
  `holder.id`, top-level `id`, `credentialStatus.type`, `credentialSchema.id`, etc.).
- 11 adversarial regression tests added (81 tests total).
