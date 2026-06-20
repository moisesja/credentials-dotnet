# Changelog

All notable changes to `credentials-dotnet` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Milestone M2 (credential status + schema + issuer-trust hook)

- **Status (Bitstring Status List v1.0):** `StatusListManager` produces and maintains the unsecured
  `BitstringStatusListCredential` (create / revoke / suspend / reinstate, one bitstring per purpose) for
  the issuer to sign; `BitstringStatusListEntry` + `CredentialBuilder.AddStatus(entry)` set a credential's
  status reference (FR-016, FR-020, FR-021). The codec is MSB-first, GZIP-then-multibase-base64url over
  `NetCid` with an explicit decode bound (NetCid's 4096-char default is too small for a real list), a
  decompression-bomb cap, and the 131,072-bit minimum-length floor.
- **Status verification (FR-022):** an injected `IStatusListFetcher` resolves the list; the verifier
  verifies the fetched list credential's *own* proof recursively (with the validity window enabled, so a
  stale or unsigned list is not trusted), asserts the list/subject types and that the entry's purpose is
  one the list declares, then decodes and reads the status bit. A set revocation/suspension bit is
  `Failed`; an unreachable / unverifiable / stale / malformed / out-of-range list is `Indeterminate`;
  never throws (FR-045).
- **Schema (JSON Schema 2020-12, FR-070):** an injected `ICredentialSchemaResolver` fetches the schema
  (returning raw bytes so the engine enforces any declared `digestSRI` via the `NetCrypto.Hash` seam
  before parsing); `ICredentialSchemaValidator` is keyed by `credentialSchema.type` through an immutable
  `SchemaValidatorRegistry` (no public `Register`), so a future SHACL validator is just a DI registration.
  The v1 `JsonSchema2020Validator` runs over `JsonSchema.Net` (System.Text.Json-native) with format
  assertion on; tri-state Success/Failure/Indeterminate. `JsonSchemaCredential` entries have the wrapper
  VC's proof verified recursively before the inner schema is applied.
- **Issuer trust (FR-081/082):** an injected `IIssuerTrustPolicy` is evaluated as an explicit, optional
  step over the **proof-verified** issuer (never a self-asserted one), returning a structured
  decision+reason. No trust lists ship in the library. `Untrusted` ⇒ `Failed`; a throwing policy ⇒
  `Indeterminate` (never crashes verification).
- **Verifier pipeline:** runs proof → structure → validity → status → schema → issuer-trust; each new
  stage is `Skipped` when its hook is unconfigured, the credential declares nothing to check, or the
  per-call toggle (`CheckStatus` / `CheckSchema` / `EvaluateIssuerTrust` on
  `CredentialVerificationOptions`) is off. `CheckResult` gained an optional structured `Detail`.
- **DI:** `AddCredentials` builder gains `UseStatusListFetcher` / `UseSchemaResolver` /
  `UseIssuerTrustPolicy` (typed and instance overloads) and opt-in, bounded HTTP convenience hooks
  `UseHttpStatusListFetcher` / `UseHttpSchemaResolver` (egress / SSRF posture is the caller's
  responsibility — front the named `HttpClient` with an allowlisting handler where required).
- **Dependencies / NFR-002:** referenced `NetCid` (→ SimpleBase) and `JsonSchema.Net` (→ JsonPointer.Net
  / Json.More.Net / Humanizer.Core) directly; the default closure stays System.Text.Json-only — no
  `Newtonsoft.Json` / dotNetRDF (verified by `dotnet list … --include-transitive`).

### Security / hardening — M2 adversarial review (2026-06-19)

Three adversarial agents attacked the codec/DoS, status-recursion/trust, and schema/SSRF surfaces by
compiling and running exploits. Fixes folded in (with regression tests):

- **Status-list issuer binding (high — revocation masking):** the verifier verified the fetched status
  list credential's own proof but did not bind the list to the credential's issuer. An attacker able to
  influence what `IStatusListFetcher` returns (SSRF, cache poisoning, a colluding intermediary) could
  substitute an all-clear list validly self-signed by an unrelated DID and silently mask a real
  revocation. The status stage now requires the list issuer to equal the credential issuer
  (`status.list_issuer_mismatch` ⇒ Indeterminate); cross-issuer status delegation is not supported in v1.
- **Issuer-trust context (medium):** `IssuerTrustContext` no longer carries the credential `Document`, so
  an issuer-trust decision can neither depend on nor leak subject claims (NFR-008). It exposes identity
  only (issuer, verification methods, types, mechanism, id).
- **Multi-bit revocation (low):** a `statusSize > 1` revocation/suspension slot with a nonzero value is
  now reported `Failed` (previously only single-bit slots were).
- **Codec overflow hardening (low):** `StatusBitstring.Decode` computes its multibase length bound without
  overflowing for a near-`long.MaxValue` inflate cap, and `CreateEmpty` rejects an oversized length with a
  clear error instead of overflowing the allocation.

The agents confirmed the defenses that held: SSRF is structurally impossible (JsonSchema.Net's default
registry fetch returns null — no egress); ReDoS is bounded by the BCL regex match timeout (no infinite
hang); and the status path resisted issuer-spoofed/stale/wrong-type/wrong-purpose lists, out-of-range and
malformed indices, malformed/oversized/throwing fetches, self-referential recursion, and a throwing or
proof-unauthenticated trust policy.

PR review follow-ups (also fixed, with tests):

- **`JsonSchemaCredential` wrapper issuer binding (high):** the schema stage now binds a wrapped schema
  credential to the subject credential's issuer (`schema.wrapper_issuer_mismatch` ⇒ Indeterminate) — the
  same revocation-masking class as the status-list fix, applied to schemas. Third-party schemas use the
  plain `JsonSchema` type pinned with `digestSRI`.
- **Status-list entry-count floor:** the verifier enforces Bitstring Status List validate-step 9
  (`bitLength / statusSize ≥ 131,072` entries), so a multi-bit list that meets only the raw bit floor is
  rejected (`status.list_too_short`).
- **`StatusListManager` multi-bit API:** methods take an honest `entryIndex` (the manager computes the bit
  position from `statusSize`); added `WithStatusValue` / `GetStatusValue` so callers no longer hand-compute
  bit positions. `FirstStatusListSubject` no longer falls back to an arbitrary first subject.
- **`digestSRI`:** compares raw digest bytes and accepts both standard base64 and base64url (so a correct
  base64url digest is not falsely rejected); an unparseable value is Indeterminate, not a silent pass.
- **HTTP hooks default to HTTPS-only** (`allowHttp: true` to opt into cleartext).
- **`CheckResult.GetDetail<T>()`** typed accessor over the structured `Detail`.

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
