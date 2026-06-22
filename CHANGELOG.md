# Changelog

All notable changes to `credentials-dotnet` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Milestone M5 (bbs-2023 selective disclosure)

- **Verification (FR-042):** `UseBbs2023()` registers the `bbs-2023` cryptosuite, so a **derived**
  bbs-2023 proof verifies through the existing `IVerifier` with no new verifier code — the Data Integrity
  pipeline dispatches by cryptosuite name, the existing resolver produces the issuer's BLS12-381-G2 key, and
  the M1 issuer binding applies. Mandatory disclosure is cryptographically enforced by the substrate (the
  verifier recomputes the BBS header from the revealed mandatory statements), so a holder cannot drop or
  alter a mandatory claim.
- **Holder derivation (FR-031):** `IBbsDeriver.DeriveAsync(baseCredential, BbsDisclosureRequest)` produces a
  minimally-disclosing credential — the issuer's mandatory group plus the holder's chosen
  `RevealPointers` — as a zero-knowledge BBS proof, with no issuer interaction and no private key. Each
  derivation draws a fresh CSPRNG presentation header from the engine RNG seam (`IRandomSource`, F9), so
  repeated derivations of the same base are unlinkable; the CPU-bound derivation is offloaded at the role
  boundary (F5). `IBbsDeriver` / `BbsDisclosureRequest` are draft-free (NFR-005) — the `Bbs2023Cryptosuite`
  draft type is confined to the internal `Bbs2023Deriver`.
- **Issuance (FR-014) is gated.** `DataProofsDotnet` exposes no key-store / `ISigner` BBS base-proof API —
  only `CreateBaseProofAsync(rawPrivateKey)` — and exporting a raw private key would violate FR-015/NFR-006.
  So a `bbs-2023` issuance request fails fast (`NotSupportedException`); only verify + derive ship. BBS
  issuance lands the day DataProofs adds a key-store BBS create API (an **upstream** capability gap, not a
  credentials-dotnet defect).
- **Packaging / NFR-002:** bbs-2023 lives in the opt-in `Credentials.Rdfc` package (which already carries
  `DataProofsDotnet.Rdfc` → dotNetRDF + Newtonsoft), so it adds **zero** new closure cost; the Core/DI
  default closure stays System.Text.Json-only (re-verified). **Zero Core changes** — the deriver uses only
  the public `IRandomSource` / `Credential` surface, and verify is pure suite registration. A reflection
  test confirms no `DataProofsDotnet` / dotNetRDF / Newtonsoft type on the `Credentials.Rdfc` public surface
  (NFR-005 / D3).

### Security / hardening — M5 adversarial review (2026-06-22)

Three adversarial agents attacked the disclosure-forgery, F7/DoS, and leakage/residual surfaces by
compiling and running ~50 exploits against the real `UseBbs2023()` wiring with the BBS native library
present. **No cryptographic forgery was found** — every attempt to drop or alter a mandatory claim (incl.
CBOR surgery on the derived proofValue's index sets and label map), forge `issuer=victim`, hide the issuer,
splice a proof across credentials, or inject an unsigned claim was Rejected. Mandatory-group enforcement
(the recomputed BBS header) and issuer binding both held cryptographically; F7 held (a malformed/forged
proof is `Failed`, the most lenient outcome is `Indeterminate`, never a false Accept); NFR-005 surface and
NFR-002 closure are clean. Two items were addressed:

- **`DeriveAsync` malformed-pointer leak (medium — fixed):** a malformed RFC 6901 `RevealPointers` entry
  (missing leading `/`, a `null` element) made the substrate's JSON Pointer parser throw a raw
  `ArgumentException` that escaped `DeriveAsync`, violating its documented contract and surfacing the
  internal substrate pointer type. It is now mapped to `CredentialFormatException`; a well-formed pointer to
  an absent path correctly reveals nothing extra.
- **Withheld validity/status claim (high — inherent issuer-side residual, documented):** a holder can
  withhold a verification-critical claim (`validUntil`, `credentialStatus`) that the issuer left out of the
  mandatory group, so an expired/revoked credential verifies — the verifier cannot distinguish "no expiry"
  from "expiry hidden". This is the **same inherent selective-disclosure limitation as the M4 SD-JWT
  residual**; the defence is issuer-side (the issuer must place `validUntil`/`validFrom`/`credentialStatus`/
  `issuer`/`id`/`type`/`@context` in the mandatory group, where disclosure is cryptographically enforced).
  `IBbsDeriver` / `BbsDisclosureRequest` now document the issuer's mandatory-group obligation, and a
  characterization test shows the residual and its mitigation. **This engine does not issue bbs-2023 bases**
  (issuance is gated), so the mandatory-group choice is the third-party issuer's responsibility; the engine
  will enforce it when bbs-2023 issuance ships.

Documented, non-blocking (default fail-closed posture is safe): a bad derived proof can be steered
`Failed → Indeterminate` by an unresolvable `verificationMethod` (a general Data Integrity property, not
BBS-specific — under the default `TreatIndeterminateAsFailure` it is still `Rejected`); a derived proofValue
is not bit-canonical (no forgery / no extra disclosure); a substrate (`dataproofs-dotnet`) round-trip
failure at very large message counts (fails closed); and a bare derived credential has no replay protection
until the presentation/holder milestone binds the BBS presentation header to a verifier challenge.

### Added — Milestone M4 (SD-JWT VC)

- **SD-JWT VC issuance (FR-013):** `SdJwtVcIssuanceRequest` issues a VCDM 2.0 credential as a selectively
  disclosable SD-JWT VC (`typ=dc+sd-jwt`, media `application/dc+sd-jwt`). The credential is carried as the
  SD-JWT VC claims set with the required `vct` added in the clear and an `iss` claim mirroring the issuer
  (the binding anchor); caller-chosen claims are made selectively disclosable, and an optional holder
  `cnf` key (`HolderBindingKey`) can be embedded for a later Key-Binding presentation. The signature `alg`
  is derived from the signer's key type; an out-of-scope key fails fast. `IssuedCredential` gains an
  `SdJwtVc` factory + `CompactSdJwt` accessor; the issued `Credential` retains its verbatim compact
  serialization (`Credential.CompactEnvelope`).
- **SD-JWT VC verification (FR-013):** the verifier detects an SD-JWT (`issuer-JWS~D1~…~`) from the bytes
  (`EnvelopeDetector` branches on `~` **before** the compact-JWS branch), verifies the issuer signature
  and reconstructs the disclosed payload through the substrate, and enforces the profile (`typ`/media,
  `vct` present, no reserved claim disclosed). Structure and validity run over the credential's clear
  VCDM members.
- **Draft-free public surface (FR-051 / D12):** `SdJwtVcIssuanceRequest`, `DisclosureSelector`
  (`Claim` / `ObjectProperties` / `ArrayElements`), `HolderBindingKey`, `SdHashName`, and
  `ICredentialTypeMetadataResolver` — no SD-JWT draft type (`DisclosureFrame`, `SdJwtIssuerOptions`,
  `Jwk`, `ITypeMetadataResolver`, `SdJwtVc*`) appears on the public API. The draft types are confined to
  the internal `SdJwtVcMechanism` (the sole caller of the `DataProofsDotnet.Jose` SD-JWT APIs, FR-050) and
  a `TypeMetadataResolverAdapter` (fix F3); enforced by a reflection test.
- **Issuer binding:** the credential issuer is bound to the **base DID of the issuer-JWT `kid`**
  (`BaseDid(kid) == iss`, falling back to the VCDM `issuer`) — `iss`/`vct` are reserved-non-disclosable so
  they stay in the signed clear payload. A missing `kid` fails closed. A self-enforcing guard asserts the
  issuer-JWT cleartext `iss`/`vct` equal the substrate-verified disclosed payload's (`sdjwt_payload_mismatch`).
- **F7 / report-don't-throw:** the issuer key is resolved asynchronously **before** the substrate verify, so
  a DID/IO failure is `Indeterminate` while a bad signature, a bad disclosure, an `_sd`-digest mismatch, a
  wrong `typ`, a disclosed reserved claim, or a missing `vct` is `Failed` — never conflated, never thrown
  (FR-045). A constant resolver is passed to the substrate so its negative can never mean "key not found".
- **Two-layer disclosure guard:** a `DisclosureSelector` may not target a VCDM structural member
  (`@context` / `type` / `issuer` / `id` / `credentialSubject` as a whole) or an SD-JWT reserved claim — so
  the issuer binding and structural checks always read clear members.
- **DI:** `AddCredentials` registers the SD-JWT VC mechanism unconditionally (no new dependency — `.Jose`
  was already in the closure from M3) and a `builder.UseTypeMetadataResolver(...)` hook for optional
  `vct` Type Metadata; `SecuringSelector.SdJwtVc()` and `ISecuringCapabilities` surface the new form.
  NFR-002 closure unchanged (System.Text.Json-only).
- **Scope:** M4 issues and verifies the **issuer-signed** SD-JWT VC; holder-side disclosure selection and
  Key-Binding-JWT creation/verification are deferred to the presentations milestone (M6) — an issued `cnf`
  is forward-compatible with it.

### Security / hardening — M4 adversarial review (2026-06-21)

Three adversarial agents attacked the issuer-binding/disclosure-forgery, F7-classification/detection/DoS,
and payload-fidelity/leakage surfaces by compiling and running exploits. **Three genuine defects were found
and fixed** (each with a regression test that reproduces the exploit and asserts it is now Rejected/Failed);
NFR-005 surface and NFR-002 closure were re-confirmed clean.

- **`iss`/VCDM-`issuer` split-brain (critical — issuer impersonation):** the proof bound on the SD-JWT
  `iss` claim while the consumer-visible `Credential.Issuer` and the issuer-trust stage read the VCDM
  `issuer`, with nothing requiring the two to agree. An attacker signing with their own key (`iss=attacker`,
  so binding + signature pass) but setting `issuer=victim` produced a credential Accepted and trusted as the
  victim's. The proof stage now requires `iss == issuer` (string or object `id`) when both are present
  (`sdjwt_issuer_mismatch` ⇒ Failed) — legitimate issuance always sets them equal — and issuer-trust now
  consumes the same proof-bound anchor as the binding.
- **Validity / status / schema disclosure bypass (high):** the verifier reads `validFrom`/`validUntil`/
  `issuanceDate`/`expirationDate`/`credentialStatus`/`credentialSchema` from the issuer-JWT cleartext, but
  these VCDM members were not in the non-disclosable set (only the SD-JWT `exp`/`nbf` were). Marking
  `validUntil` selectively disclosable hid it, so an **expired credential verified as valid**; a disclosable
  `credentialStatus` made the **revocation check Skipped**. Fix: those members are now rejected at issuance,
  and a verify-side guard rejects any of them that is *revealed* via a disclosure but absent from the
  cleartext the stages validate (`sdjwt_hidden_member` ⇒ Failed) — covering credentials crafted outside this
  engine. **Known residual (inherent to SD-JWT):** a holder who simply *withholds* a disclosure that a
  non-conformant third-party issuer made disclosable cannot be detected — the leftover digest is dropped as
  an indistinguishable decoy (RFC 9901 §4.2.7), the same limitation the SD-JWT VC profile carries for
  `iss`/`nbf`/`exp`/`status`. The defence is issuer-side and **this library's own issuer keeps these claims
  non-disclosable, so credentials it issues are immune**; a presentation-completeness / Type-Metadata
  disclosability policy for third-party credentials is a later (M6) concern.
- **F7 kid-fragment downgrade (medium; also hardens the M3 JOSE/COSE path):** the shared
  `NetDidEnvelopeKeyResolver` returned `null` for both "DID unresolvable" and "DID resolved but the
  verification method is absent", so an attacker could mangle a tampered/forged credential's `kid` fragment
  (leaving the base DID resolvable) to downgrade a definitive bad signature to `Indeterminate` — soft-accepted
  under a non-strict policy. The resolver now returns a tri-state result: a resolvable DID whose document
  lacks the referenced method is `verification_method_not_found` ⇒ **Failed**, and only a genuine resolution
  failure is `Indeterminate`.
- **Whitespace (low) / Type Metadata resolver (info):** ingest/verify now trim the same surrounding JSON
  whitespace the detector tolerates (a wire token with an incidental newline round-trips); a throwing Type
  Metadata resolver is treated as best-effort (no metadata) and can no longer downgrade an otherwise-valid
  credential.

### Added — Milestone M3 (enveloping VC-JOSE-COSE)

- **Enveloping issuance (FR-012):** `JoseEnvelopeIssuanceRequest` signs a credential's exact bytes into a
  compact JWS (`typ=vc+jwt`, `cty=vc`); `CoseEnvelopeIssuanceRequest` signs them into a tagged COSE_Sign1
  (`typ=application/vc+cose`, `content-type=application/vc`). The COSE algorithm and the JOSE `alg` are
  derived from the signer's key type (EdDSA / ES256 / ES384 / ES256K); an out-of-scope key (e.g. P-521)
  fails fast rather than mis-signing. Signing goes through `NetCrypto.ISigner` — never a raw key (FR-015).
  `IssuedCredential` gains `Jose` / `Cose` factories with `CompactJws` / `CoseBytes` accessors and the
  `application/vc+jwt` / `application/vc+cose` media types; the issued `Credential` retains its verbatim
  envelope (`Credential.CompactEnvelope` for JOSE) and re-verifies directly.
- **Enveloping verification (FR-012):** the verifier detects its input's securing form from the bytes
  (`EnvelopeDetector`: JSON object vs compact JWS vs COSE_Sign1) and decodes the inner credential through
  the owning mechanism, so the structure / validity / status / schema stages run over the signed inner
  document while the proof stage verifies the verbatim wire bytes. Sign-exact-bytes throughout: the
  payload is never re-serialized, and the mechanism asserts the substrate-verified payload equals the
  inner document the stages validate (`envelope_payload_mismatch`).
- **Issuer binding for enveloping forms:** the credential `issuer` is bound to the **base DID of the
  signing key's `kid`** (the JWS protected-header `kid`, or the COSE key id), reusing the M1 binding — to
  claim `issuer=victim` an attacker needs the victim's key. A missing `kid` fails closed; the unprotected
  COSE `kid` is used only to *look up* a key, never trusted for authorization.
- **F7 / report-don't-throw:** the verification key is resolved asynchronously **before** the synchronous
  substrate verify, so a DID/IO resolution failure is `Indeterminate` while a bad signature (or a
  wrong/absent `typ`/`cty`) is `Failed` — never conflated, never thrown (FR-045). JOSE's throw-based
  verify (`MalformedJoseException` / `JoseCryptoException`) is caught and mapped at the mechanism boundary;
  COSE's result-style verify maps `Verified==false` to `Failed`.
- **Securing seam:** internal `JoseEnvelopingMechanism` / `CoseEnvelopingMechanism` — each the sole caller
  of its DataProofs package (`DataProofsDotnet.Jose` / `.Cose`, FR-050); a neutral `IEnvelopeKeyResolver`
  (`NetDidEnvelopeKeyResolver`) turns one DID resolution into both a JWK (JOSE) and a raw key (COSE).
  `SecuringSelector.Jose()` / `Cose()` and `ISecuringCapabilities` surface the new forms.
- **Dependencies / NFR-002 / NFR-005:** referenced `DataProofsDotnet.Jose` and `DataProofsDotnet.Cose`
  directly; the default closure stays System.Text.Json-only — no `Newtonsoft.Json` / dotNetRDF (Cose adds
  only the BCL `System.Formats.Cbor`), verified by `dotnet list … --include-transitive`. No JOSE/COSE
  substrate type (`Jwk`, `JwsSigner`, `CoseAlgorithm`, `CoseSign1VerificationResult`, …) appears on the
  public surface — enforced by a reflection test (NFR-005 / FR-051 / D12).

### Security / hardening — M3 adversarial review (2026-06-20)

Three adversarial agents attacked the forgery/issuer-binding, F7-status-mapping/detection/DoS, and
payload-substitution/surface-leakage surfaces by compiling and running 127 exploit tests. **No exploitable
issue was found.** The agents confirmed the defenses held: every issuer-spoofing forgery is Rejected on
both forms (including the unprotected-COSE-`kid` rewrite and the self-consistent forgery signed under the
victim's `kid`); a bad signature stays `Failed` (not Indeterminate) even under a non-strict policy;
payload-substitution is impossible (ingest decode == substrate-verified payload == inner `AsUtf8`, and a
detached/nil COSE payload is rejected at ingest); the size bound precedes any decode; and the NFR-005
surface and NFR-002 closure are clean. The sign-exact-bytes invariant was additionally made self-enforcing
(`envelope_payload_mismatch`) so it no longer depends on the substrate decoding the payload identically.

PR review follow-ups (also fixed, with tests):

- **COSE negative tests (DoD gap):** added the COSE counterparts the plan promised — wrong `typ`, wrong
  `content-type`, missing-`kid` fail-closed, and the self-consistent forgery signed under the victim's
  `kid` — crafting raw COSE_Sign1 with the lower-level signer to drive the bad-header paths.
- **`SecureOutcome` accessors are symmetric:** the `Document` / `Jose` / `Cose` accessors now all throw on
  a wrong-form outcome (the COSE accessor previously returned an empty `ReadOnlyMemory` silently).
- **`IssuedCredential.Cose` rejects empty bytes**, matching the non-empty guard on the JOSE factory.
- Documented the unprotected-COSE-`kid` mitigation on `CoseEnvelopingMechanism.VerifyAsync` and the
  byte-stability assumption on `Credential.AsUtf8()` that the `envelope_payload_mismatch` guard relies on.

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
