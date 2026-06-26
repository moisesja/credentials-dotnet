# Changelog

All notable changes to `credentials-dotnet` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **VCDM 2.0 compliance hardening — W3C conformance baseline raised 43 → 57 / 59.** The structural validator
  now enforces several VCDM 2.0 rules it previously accepted. This is intentionally landed in the 1.0.0
  major (not a later 1.0.x) because it makes validation *stricter* — newly rejecting inputs the engine used
  to accept would otherwise be a semver-breaking change:
  - **Identifier members must be URLs** — an absolute URI with a scheme; DIDs/URNs/URLs pass, while
    scheme-less / whitespace / `null` / multi-valued identifiers are rejected: `id`, `issuer` (bare string
    and object `.id`), `credentialStatus.id`, `credentialSchema.id`, `credentialSubject.id`,
    `refreshService.id`, `relatedResource.id` (VCDM §4.4 / §4.7 / §4.9 / §4.11).
  - **`refreshService`** entries must carry a `type`.
  - **`relatedResource`** must be one or more objects, each with a unique URL `id` and at least one of
    `digestSRI` / `digestMultibase` (§5.3, structural; digest *hash*-verification is a deferred follow-up).
  - **`name` / `description`** language value objects (top-level and on the `issuer` object) are closed —
    only `@value`, `@language`, `@direction` are permitted (§11.1).
  - **Issuance rejects a Data Integrity proof whose `proofPurpose` is not `assertionMethod`** at the role
    boundary (VC Data Integrity 1.0 §3.2), rather than merely defaulting it.

  The W3C VCDM 2.0 suite now passes **57 / 59**; the 2 remaining are documented in
  [docs/conformance.md](docs/conformance.md) — detecting an unmapped-via-`@context` `type` (a JSON-LD
  term-resolution check, an STJ-only non-goal) and `relatedResource` digest hash-verification (deferred to
  a focused follow-up). The conformance gate baseline is raised to **57**.

### Security

- **Data Integrity verification now distinguishes "DID unresolvable" from "verification method absent" (F7).**
  The embedded Data Integrity path resolved a proof's `verificationMethod` through a 2-state (nullable)
  resolver, so a DID that *resolved* but did not publish the referenced method collapsed to the same
  `Indeterminate` outcome as a genuine resolution failure. An attacker could mangle a tampered/forged
  credential's `verificationMethod` **fragment** (over a still-resolvable base DID) to downgrade a
  definitive bad-signature **Failed** to **Indeterminate**, which a non-strict policy
  (`TreatIndeterminateAsFailure = false`) soft-accepts. The resolver is now **tri-state** (Resolved /
  DidUnresolvable / MethodNotFound), matching the enveloping (JOSE/COSE/SD-JWT) path hardened in M4: a
  method absent from a resolvable DID is a definitive `Failed` (`verification_method_not_found`), never
  Indeterminate (fail-closed across multi-proof credentials). Default deployments
  (`TreatIndeterminateAsFailure = true`, fail-closed) were not exploitable, but the diagnostic was
  dishonest and a non-strict policy was. All changes are internal (no public API change); covered by a new
  resolver unit test and an end-to-end mangled-fragment regression test (strict → Failed; non-strict →
  Rejected), with a companion proving a genuinely-unresolvable base DID still maps to Indeterminate.
- **Opt-in HTTP status/schema fetchers no longer follow redirects (SSRF / HTTPS-downgrade).**
  `UseHttpStatusListFetcher` / `UseHttpSchemaResolver` validated only the **initial** URL's scheme, while
  the named `"credentials-dotnet"` `HttpClient` followed 3xx redirects by default — so a hostile
  credential's HTTPS `credentialStatus`/`credentialSchema` URL could redirect to an internal host
  (`169.254.169.254`, `localhost`) or cleartext, silently breaking the documented "HTTPS by default"
  promise. The named client now sets `AllowAutoRedirect = false`, so the redirected request never fires (a
  status list / schema is a single canonical document with no legitimate redirect). A caller who needs
  redirects can reconfigure the named client and owns that SSRF posture. Covered by a loopback regression
  test asserting the redirect target is never reached. No public API change.

### Fixed

- **Verifiable Presentation verification for holder-less and credential-less presentations (#11).** VCDM 2.0
  makes both `holder` and `verifiableCredential` **optional**, but the verifier rejected a presentation that
  omitted either — so a standard Data-Integrity-signed VP from another implementation (e.g. the W3C suite's
  `eddsa-rdfc-2022` presentations, which carry no `holder`) failed to verify. The earlier "VP authentication
  proof reported as `NoProof`" diagnosis was incorrect; the real causes were two over-strict checks:
  - `BindHolder` failed when `holder` was absent. Now a signed presentation with no holder passes the binding
    check on **possession alone** (the binding proof verified and the challenge/domain matched; there is no
    holder identity to bind). This is an **engine-default behaviour change** — it applies to all callers under
    default options (still replay-safe: `RequireHolderBinding` defaults `true`, forcing a challenge), and is the
    intended interop fix. It is not abusable: `holder` is inside the proof's signed scope, so stripping a
    victim's `holder` invalidates the proof before the check runs (guarded by a new regression test). The scope
    of holder binding (possession + freshness, **not** that the presenter is the credential subject) is now
    documented on `PresentationVerificationOptions.RequireHolderBinding` and covered by a test.
  - The empty-presentation rule (`presentation_no_credentials`) is, by contrast, gated on the existing
    `RequireAtLeastOneCredential` option, which is **unchanged at its `true` default**; only the conformance
    shim sets it `false` (a VP may legitimately carry no credentials).
  This raises the W3C VCDM 2.0 conformance baseline **36 → 43 / 59** (the `4.13-verifiable-presentations`
  group now passes). See [docs/conformance.md](docs/conformance.md).

### Added — Milestone M8c (Conformance + interop) — the M8 finale

The last of three M8 PRs: empirical W3C VCDM 2.0 conformance + cross-implementation interop, closing
NFR-007. Test count **352 → 357** (+5 interop) plus the conformance harness; build stays 0-warning.

- **`Credentials.Conformance.VcApi`** — a minimal ASP.NET VC-API shim over `IIssuer`/`IVerifier`
  (`POST /credentials/issue`, `/credentials/verify`, `/presentations/verify`; `GET /` returns the shim's
  `did:key`). It issues with `eddsa-rdfc-2022`, validates structure before signing (so the suite's negative
  issue cases reject), and maps non-conforming input to HTTP ≥ 400. The suite injects the shim's own
  `did:key` as the credential issuer, so issuance satisfies the engine's issuer-binding with no field
  rewriting.
- **`Credentials.Conformance.Tests`** — boots the shim on loopback, writes `localConfig.cjs`, runs the
  [`w3c/vc-data-model-2.0-test-suite`](https://github.com/w3c/vc-data-model-2.0-test-suite), and asserts a
  passing **baseline of 36** (a `SkippableFact`, `Category=Conformance`, that skips visibly when the Node
  suite isn't prepared). **Current result: 36 / 59 passing** — the engine passes the structural / issue /
  verify core; the 23 not-yet-passing tests are documented known limitations (full JSON-LD term mapping,
  `relatedResource` integrity, `name`/`description` language objects, a VP authentication-proof interop
  gap) in [docs/conformance.md](docs/conformance.md), not a "fully conformant" claim. The baseline guards
  against regression.
- **`Credentials.InteropTests`** (NFR-007): SD-JWT VC disclosure digests are cross-checked against the
  spec algorithm (`base64url(SHA-256(ascii(disclosure)))` recomputed independently and matched to the
  issued `_sd`), with the tampered- and unmatched-disclosure negatives and the `dc+sd-jwt` drift sentinel;
  bbs-2023 (`IsAvailable`-gated) pins the `bbs-2023` cryptosuite + multibase `proofValue` drift sentinels,
  verifies a derived proof, and rejects a tampered mandatory value.
- **CI** — `.github/workflows/conformance.yml` (PR + nightly): clones + installs the Node suite, builds
  the shim, runs the harness. The FrCoverage gate's NFR-007 deferral is removed now that it is tagged.
- **Docs** — [docs/conformance.md](docs/conformance.md) records the honest conformance + interop status.

### Added — Milestone M8b (Samples matrix & API-coverage gate)

The second of three M8 PRs. A first-class, offline samples matrix demonstrating every role × securing
form plus status/schema/trust/1.1, and an api-coverage gate proving the samples exercise the public
surface. Test count **338 → 352** (+14 sample smoke tests); build stays 0-warning.

- **`Credentials.Samples.Shared`** — the keystone wiring (`SampleKeys` in-memory `did:key` minting,
  `SampleNarrator` FR-banner output, and `AllowlistIssuerTrustPolicy` — the one shipped trust policy,
  which per FR-082 lives in samples, not the library).
- **14 `samples/*` console projects**, each exposing `Program.RunAsync(TextWriter, IServiceProvider?)`,
  offline, narrating the FRs it demonstrates and throwing on any unexpected outcome:
  DataIntegrity (eddsa-jcs-2022, + a capabilities query over `ISecuringCapabilities`/`SecuringSelector`),
  DataIntegrityRdfc (eddsa-rdfc-2022), JoseEnvelope (vc+jwt), CoseEnvelope (vc+cose),
  SdJwtVc (selective disclosure), SdJwtPresentation (KB-JWT holder binding), Bbs2023 (bbs-2023 derive,
  `IsAvailable`-gated), PresentationDataIntegrity + PresentationJose (holder binding + presentation
  verification), StatusList (Bitstring Status List revoke/verify), Schema (JSON Schema 2020-12),
  IssuerTrust (allowlist trusted/untrusted), Vcdm11 (verify a foreign-issued 1.1 credential + the
  `AcceptVcdm11=false` opt-out gate), and FullPipeline (status + schema + trust composed).
- **`Credentials.SampleSmokeTests`** — runs every sample's `RunAsync` in-process (14 facts); doubles as
  the api-coverage driver under coverlet (scoped to Core + DI).
- **`tools/api-coverage`** (+ `tools/run-api-coverage.sh`, `tools/coverage.runsettings`) — a console
  tool that diffs the public surface (via `MetadataLoadContext`) against the samples' coverage and fails
  if any gateable public type is exercised by no sample. Type-level: **53 covered, 0 uncovered, 4
  documented exemptions** (`api-coverage-exclusions.txt` — error-path exceptions + the tuning options
  object; the tool also fails on a stale exclusion that has since become covered). Interfaces/enums and
  internal types are auto-skipped.
- **CI** — `ci.yml` gains an `api-coverage` job (`needs: build-test`).

### Added — Milestone M8a (Quality & release gates)

The first of three M8 PRs (M8 = conformance + interop + samples + gates). M8a lands the pure-.NET
quality and release gates — no external runtime — closing the package/surface/doc halves of NFR-002,
NFR-005, NFR-009 empirically and wiring CI/CD. Test count **318 → 338**; build stays 0-warning under
`TreatWarningsAsErrors`.

- **`Credentials.TestSupport`** — a shared, non-packable library holding the `[FrTag]` requirement-
  coverage attribute and `RequirementIds`, the single source of truth for the PRD §8 set (34 FR + 9 NFR).
- **`Credentials.ArchitectureTests`** — invariant gates inspected by metadata only
  (`System.Reflection.MetadataLoadContext`, so the opt-in Credentials.Rdfc is examined without loading
  its Newtonsoft into the test host):
  - `PublicSurface_ExposesNoDataProofsType` (FR-051 / NFR-005, F3) — no `DataProofsDotnet` type may
    appear in any public/protected signature of the three libraries (return/parameter/field/property/
    generic-argument/base/interface vectors all covered).
  - `DefaultLibrary_ReferenceClosure_HasNoNewtonsoft` (NFR-002, static half) — the compile-time
    reference closure of Core + DI is Newtonsoft-free. Documented scope: catches a *used* Newtonsoft
    type; the authoritative package-level guarantee is the ConsumerProbe (below).
  - `PublicSurface_EveryDocumentedMember_HasNonEmptySummary` (NFR-009) — complements CS1591-as-error
    (missing docs) by catching *empty* `<summary>` on public-surface members.
  - `RoleMethods_NamedAsync_ReturnTaskOrValueTask` (NFR-004) and `Library_TargetsNet10` (NFR-001).
  - `EveryRequirement_HasAtLeastOneTaggedTest` (the **FrCoverage gate**) — every PRD §8 requirement has
    ≥1 `[FrTag]`-tagged test (deferring NFR-007 to M8c with a logged reason); a typo'd/unknown id fails.
- **`Credentials.RoundTripTests`** (FR-003) — byte-fidelity DoD per securing family this engine issues
  end-to-end (unsecured received-bytes verbatim; embedded DI in JCS+RDFC byte-stable with exactly one
  `proof`; JOSE/SD-JWT verbatim compact + signed-payload == source bytes; COSE verbatim wire bytes;
  H1 `<>&`/non-BMP-emoji value fidelity).
- **`Credentials.ConsumerProbe`** + `tools/check-no-newtonsoft-closure.sh` (NFR-002, authoritative
  package half) — packs Core + DI, restores a real package consumer against a local feed, and asserts
  Newtonsoft is absent from the transitive closure (`dotnet list package --include-transitive`).
- **Public-API surface tracking (NFR-005 semver)** — `Microsoft.CodeAnalysis.PublicApiAnalyzers`
  (RS0016/RS0017) wired for the three shippable libraries via `Directory.Build.targets`, with the
  current surface committed to `PublicAPI.{Shipped,Unshipped}.txt` (749 / 26 / 16 entries). Any public-
  surface change now fails the build until the API file is updated — a reviewable text diff. RS0026/
  RS0027 (the "no overloads with optional parameters" opinion) are disabled for the deliberate, in-place
  ergonomic role overloads. `Microsoft.DotNet.ApiCompat.Tool` (local tool manifest) +
  `tools/check-api-compat.sh` add the package-compat check against the last published version (skip-
  logged pre-release; honest, never falsely green).
- **`[FrTag]` tagging** — a representative existing test tagged for each of the 42 currently-coverable
  requirements, plus two new tests: FR-004 (lazy projections memoized over the frozen document, proven
  via `ReferenceEquals`) and FR-021 (`StatusListManager` set→re-produce→read and clear→re-produce→read).
- **CI/CD** — `.github/workflows/ci.yml` (ubuntu+windows build/test matrix with `TreatWarningsAsErrors`
  as the XML-doc + public-API gate, plus `no-newtonsoft` and `semver` jobs) and `release.yml` (tag-
  driven pack + gate + push under a protected `nuget-release` environment).

#### Security & hardening (M8a adversarial review)

An adversarial pass attacked each gate to confirm it has teeth (not hollow). The surface, semver
(RS0016), doc (CS1591/empty-summary), and FrCoverage (missing-tag + unknown-id) gates all failed
correctly when defeat was attempted. Two real findings were fixed:

- **ConsumerProbe was hollow (stale-cache false-pass).** Re-packing the fixed version `0.1.0` with new
  dependencies served *stale* package metadata from nuget's id+version-keyed cache, so a Newtonsoft
  dependency added to Core was invisible to the closure check — it always reported the first run's
  result. Fixed by packing under a unique per-run version delivered as an environment-variable MSBuild
  property (consistent across restore/build/`dotnet list`, which does not accept `-p:`). Verified: the
  fixed gate now reports the violation when Newtonsoft is present and clean otherwise.
- **The static reference-closure check has an inherent blind spot** — the C# compiler only records
  references to *used* assemblies, so an unused-yet-declared `PackageReference` carrying Newtonsoft is
  invisible to it. Documented honestly; recursion broadened to every non-BCL assembly (so a *used*
  Newtonsoft edge hidden behind an intermediate is still caught); the package-level ConsumerProbe is the
  authoritative NFR-002 gate. The FrCoverage scan was also hardened to ignore commented-out `[FrTag]`s.

### Added — Milestone M7 (VCDM 1.1 verify)

- **VCDM 1.1 verification (FR-044 / D8):** the verifier now accepts **VCDM 1.1** credentials and
  presentations alongside 2.0, gated by `CredentialVerificationOptions.AcceptVcdm11` (default `true`).
  **Issuance is 2.0-only — now enforced at the role boundary:** `IIssuer.IssueAsync` rejects any non-2.0
  credential (`InvalidOperationException`) before signing, for every securing form. Previously the 2.0-only
  contract was only assumed from the builder (which seals 2.0), but a caller could parse a 1.1 document and
  mint it through the public issuer — that gap is now closed, so "verify 1.1, never issue it" is true of the
  public API, not just a convention. A 1.1 document is also **never upgraded** to 2.0 (its `@context`, members,
  and detected version survive a serialize→re-parse round-trip unchanged).
  Most of the version-aware machinery already existed (positive `@context[0]` detection in `VersionProjection`;
  the structural validator's 1.1 branch requiring `issuanceDate` and forbidding `validFrom`/`validUntil`; the
  validity window projected per version in `ValidityProjection`); M7 closes the two remaining gaps:
  - **Presentation-path gate (G1):** `CheckPresentationStructure` now rejects a **1.1 presentation envelope**
    with `vcdm11_not_accepted` when 1.1 is disallowed — previously only contained credentials were gated, so a
    1.1 VP itself slipped through. There is **no** new presentation-level flag: the single
    `CredentialOptions.AcceptVcdm11` governs both the VP envelope and its children (one source of truth).
  - **Version-correct validity diagnostics (G2):** a not-yet-valid / expired **1.1** credential now reports the
    member that actually exists in the document — `/issuanceDate` ÷ `/expirationDate` — instead of the 2.0
    `/validFrom` ÷ `/validUntil`. The computed window was already correct; only the diagnostic pointer/message
    were 2.0-only. The stable codes `not_yet_valid` / `expired` are unchanged.
  - Contained-credential `AcceptVcdm11` inheritance through `BuildContainedCredentialOptions` is now documented
    (the `with` copy preserves it), so a 1.1 child in a 2.0 VP is gated by the same flag.
- **Tests (+19):** 8 Core unit (`ValidityProjection` 1.1 **and** 2.0 branches each ignoring the other version's
  members — no cross-version read; 1.1 inverted window; 1.1 credential + presentation no-upgrade round-trip) and
  11 integration (DI-secured 1.1 credential and holder-bound 1.1 VP → Accepted; G1 1.1-VP rejection; G2
  `/issuanceDate`÷`/expirationDate` pointers; G3 1.1 child in a 2.0 VP rejected; Unknown-context rejection;
  `IssueAsync` rejects a 1.1 credential; the two Unknown-version diagnostic-honesty regressions). A secured 1.1
  fixture is produced the way a foreign 1.1 issuer would — a hand-built 1.1 document signed faithfully through
  the engine's internal Data Integrity mechanism (**not** the public issuer, which is 2.0-only).

#### Security & hardening (M7 adversarial review)

- **Adversarial pass: zero vulnerabilities.** Five attackers each ran throwaway exploits against the verify
  pipeline. Confirmed: (1) the `AcceptVcdm11=false` gate holds on **all** paths — credential, 1.1 VP envelope,
  1.1 child in a 2.0 VP, the **recursive** status-list / schema-credential paths (a 1.1 status list →
  `Indeterminate`/`status.list_unverified`, never Accepted), and enveloped 1.1; (2) version detection and
  validity-member selection are driven by a **single** detected version, so they can't be desynchronized;
  (3) a structurally inconsistent document (e.g. a v2 `@context` carrying 1.1 date members) is always Rejected
  — the validity check may pass over the absent members, but the structural validator independently fails it
  (`version.mismatch_dates_v2`), so an expired/not-yet-valid credential never reaches Accepted (defense in
  depth); (4) **no upgrade** holds — a received 1.1 document's verbatim bytes, `@context`, members, and proof
  survive verify/serialize/holder-binding unchanged, and 1.1 replay defence is identical to 2.0's.
- **Fixed (low — diagnostic accuracy):** `CheckValidity` lumped `Unknown`-version credentials with 2.0, so an
  Unknown document's expiry diagnostic named `/validUntil` even when the window was read (via
  `ValidityProjection`'s Unknown fallback) from `expirationDate`. Now an explicit `switch` on the version names
  the member that actually exists (Unknown mirrors the projection's prefer-2.0-then-1.1 fallback). No decision
  impact (Unknown is rejected by structure regardless); the stable codes `not_yet_valid`/`expired` are unchanged.

#### Post-review (PR #7)

- **Blocking — issuance 2.0-only contract was not enforced (fixed):** the PR review found that, although the
  docs say issuance is 2.0-only, `IIssuer.IssueAsync` only rejected *already-secured* credentials — a caller
  could `Credential.Parse` a 1.1 document and mint it through the public issuer (the M7 test helper itself did
  exactly this). Added a `credential.Version != V2_0` guard at the role boundary (before the form switch, so it
  covers DI/JOSE/COSE/SD-JWT), a negative test, and re-pointed the secured-1.1 test fixture at the engine's
  internal Data Integrity mechanism instead of the public issuer.
- **Diagnostic honesty (low):** the `Unknown`-version validity pointer now follows **parse success** (mirroring
  `ValidityProjection.Read`), not member presence — a present-but-malformed `validUntil` no longer steals the
  pointer from the `expirationDate` that actually supplied the window value.

### Added — Milestone M6 (presentations + holder binding)

- **Holder role (`IHolder`):** `Ingest` (FR-030) materializes a received credential (JSON / JOSE / SD-JWT)
  into a `HeldCredential`; `InspectSdJwt` lists an SD-JWT VC's disclosable claims + whether it supports
  holder binding; `PresentSdJwtAsync` (FR-032) reveals a chosen disclosure subset and appends a Key Binding
  JWT — the holder signs through a caller-supplied `NetCrypto.ISigner` (never raw keys), and the KB-JWT binds
  the verifier's `aud`/`nonce` and the exact disclosed set (`sd_hash`). `BuildPresentation` (FR-033)
  assembles a VP from embedded + enveloped (verbatim compact) children; `BindWithDataIntegrityAsync` /
  `BindWithJoseEnvelopeAsync` (FR-034) bind it to the holder key as a Data Integrity `authentication` proof
  (with `challenge`/`domain`) or a compact `vp+jwt`.
- **Presentation verification (FR-041):** `IVerifier.VerifyPresentationAsync` (VP-object and bytes
  overloads) verifies the **holder binding**, the VP **structure**, and **every contained credential**
  through the full credential pipeline (self-recursive). The holder binding applies the M1 look-up-then-bind
  to the **holder**: the binding key's base DID must equal the VP `holder` (a forged holder needs the
  holder's key); the DI path enforces `proofPurpose=authentication` + `challenge`/`domain`, the `vp+jwt`
  path asserts `typ=vp+jwt`. A presentation is `Accepted` only when the binding (when required), the
  structure, and every child are accepted (fail-closed). New `PresentationVerificationOptions` /
  `PresentationVerificationResult`, `CheckKinds.HolderBinding`, and `RequireHolderBinding` /
  `ExpectedAudience` / `ExpectedNonce` on `CredentialVerificationOptions` (the SD-JWT KB-JWT path).
- **Securing seam:** `SecureRequest`/`VerifyRequest` gain `Challenge`/`Domain`/`Kind`; the Data Integrity
  mechanism threads challenge/domain; the JOSE mechanism gains a `vp+jwt` path (the generic `JwsBuilder` /
  `JwsParser`, since the substrate has no VP-specific helper — `typ` asserted on verify, G1); a shared
  `EnvelopeIngest` routes ingest for both the verifier and the holder. All signing/binding paths are
  honestly async over the substrate sign (F5).
- **Scope (deferred):** BBS derivation stays in `Credentials.Rdfc` (`IBbsDeriver`) rather than absorbed into
  Core's `IHolder` (NFR-002 — Core cannot pull dotNetRDF); a BBS credential is presented as an embedded VP
  child, replay-protected by the VP binding. COSE VPs (`vp+cose`), the `EnvelopedVerifiableCredential`
  `data:`-URI wrapper, `IHolderKeyResolver`, and `InspectBbsBase` are deferred. Core/DI default closure
  unchanged (System.Text.Json-only); no substrate type on the holder/presentation public surface (NFR-005).

#### Security & hardening (M6 adversarial review)

- **vp+jwt replay (F1):** the generic compact-JWS builder has no header-claim hook, so the `vp+jwt` path
  signs the verifier's `nonce` (= `challenge`) and `aud` (= `domain`) **into** the VP payload, and the
  verifier requires them to equal its own `ExpectedChallenge`/`ExpectedDomain` (`holder_binding_replay`). A
  captured `vp+jwt` is therefore not a bearer token — it does not replay against a verifier demanding fresh
  values.
- **Fail-closed required binding (F2):** a required holder binding with **no** `ExpectedChallenge` now fails
  (`holder_binding_challenge_required`) instead of accepting any captured presentation — the substrate's
  challenge/domain check is fail-open (only enforced when an expectation is supplied), so the orchestrator
  enforces the expectation's presence itself.
- **Malformed contained credential (F4):** a structurally broken child is reported as a rejected credential
  (`contained_credential_malformed`), never thrown out of `VerifyPresentationAsync`.
- **Empty presentation (F6):** `RequireAtLeastOneCredential` (default `true`) makes an empty/absent
  `verifiableCredential` a structure failure (`presentation_no_credentials`) — an `Accepted` decision now
  implies a credential was actually presented, not merely holder-key possession.
- **Withheld-disclosure residual (F5, documented):** M6 confirmed the verifier cannot precisely detect a
  holder who *withholds* a disclosure for a validity/status member — the leftover top-level `_sd` digest is
  indistinguishable from a legitimately-disclosed non-validity claim (RFC 9901 §4.2.7), so any verifier-side
  guard over-rejects compliant credentials. The posture stays issuer-side (this engine's own SD-JWT VCs keep
  validity/status non-disclosable, so they are immune) plus documentation; a precise fix needs Type-Metadata
  disclosability (a future milestone). The holder↔subject relationship (F3) likewise remains a verifier
  policy concern, not enforced by the binding.

#### Post-review hardening (M6 PR review)

- **Contained-credential fault isolation:** `VerifyContainedAsync` now isolates *any* fault from a child
  (not only `CredentialFormatException`) — an operational fault becomes an `Indeterminate` child
  (`operation_error`) instead of escaping `VerifyPresentationAsync`; cancellation and null-argument
  programming errors still propagate. Regression tests feed JOSE-shaped and SD-JWT-shaped malformed enveloped
  children (the decode paths the F4 test did not reach) and assert a rejected child, no throw.
- **`SecureRequest` Document/Payload invariant:** documented that the enveloping forms (JOSE/COSE) sign
  `Payload` as the sole authority and ignore `Document` (so a caller's payload mutation — e.g. the holder's
  `nonce`/`aud` injection — must go into `Payload`); the JOSE and COSE mechanisms now assert `Payload` is
  non-empty, turning a future "sign `Document` by mistake" footgun into a loud failure.
- **Docs/tests:** a `<remarks>` makes the deliberate `RequireHolderBinding` default asymmetry explicit
  (VP-level `true` vs credential-level `false`); added a JOSE-leg negative test for the shared
  `holder_binding_challenge_required` guard, a credential-level test pinning the SD-JWT substrate's
  fail-closed `KB_JWT_AUDIENCE/NONCE_UNCHECKED` contract (required binding with null `aud`/`nonce` → rejected),
  and a throw test for `InspectSdJwt` on a non-SD-JWT credential. The reviewer's two "must fix" items — a
  credential-level fail-open and a `BindHolder` empty-VM-list bug — were verified against the substrate and the
  full guard and found to be non-issues (both already fail closed; the empty-VM case is guarded by an explicit
  `Count == 0` clause). 299 tests (was 294).

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
