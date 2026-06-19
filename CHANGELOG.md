# Changelog

All notable changes to `credentials-dotnet` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Milestone M1 (embedded Data Integrity: issue + verify)

- **Roles:** `IIssuer` (embedded Data Integrity issuance) and `IVerifier` (end-to-end credential
  verification), registered by `AddCredentials`. Issuance signs through `NetCrypto.ISigner` and never
  handles raw keys (FR-015).
- **Cryptosuites:** EdDSA + ECDSA, both JCS (`eddsa-jcs-2022`, `ecdsa-jcs-2019`, default) and RDFC
  (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, opt-in via the new `Credentials.Rdfc` package). A new suite is
  selectable by opaque string with no public-API change (FR-053).
- **Securing seam:** internal `ISecuringMechanism` + `DataIntegrityMechanism` — the sole caller of the
  proofs layer (FR-050); roles never touch a substrate type. `SecuringForm` / `SecuringSelector` /
  `ISecuringCapabilities` expose runtime-discovered suites.
- **Verification result model:** `CredentialVerificationResult` (proof → structure → validity; status
  / schema / issuer-trust report `Skipped` until M2), with `CheckResult` / `CheckStatus` /
  `CheckDiagnostic` and fail-closed `DecisionComposer`. Side-effect free; reports failed checks rather
  than throwing (FR-045). A bad signature is `Failed`; an unresolvable verification method is
  `Indeterminate`.
- **Resolution:** `NetDidVerificationMethodResolver` bridges NetDid resolution to the proofs layer
  (FR-080); `UseNetDid()` wires `did:key`. `AddCredentials` fails fast when no DID resolver is present.

### Security / hardening — M1 adversarial review (2026-06-19)

- **Issuer binding (critical):** the verifier now binds the credential's `issuer` to the **base DID of
  the proof's verification method** (the identifier the signing key lives under), not a
  resolver-supplied `controller` field — which an attacker-influenced DID document could forge. This
  closes an issuer-spoofing forgery for non-`did:key` methods.
- **NFR-002:** the default closure is System.Text.Json-only — the RDFC suites (and their transitive
  dotNetRDF / Newtonsoft.Json) are confined to the opt-in `Credentials.Rdfc` package.
- `UseNetDid()` is idempotent (a second call no longer crashes NetDid's composite resolver); DID-URL
  query strings are stripped before resolution; issuance observes a pre-cancelled token.

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
