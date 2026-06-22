# M6 — Presentations + holder binding — Implementation Plan

**Status:** For approval (precedes any source).
**Date:** 2026-06-22.
**Branch:** `feature/m6-presentations` off `main` (M5 / PR #5 merged 2026-06-22 as `5ba5eb0`; no rebase needed).
**Milestone:** M6 of `tasks/todo-2026-06-18-credentials-dotnet-implementation.md` §6 — **FR-002** (VP model), **FR-030** (holder ingest), **FR-032** (SD-JWT KB-JWT presentation + verification), **FR-033** (VP assembly), **FR-034** (holder binding: DI authentication + JOSE `vp+jwt`), **FR-041** (presentation verification). The largest milestone after M0 — the entire Holder role (deferred from M3/M4/M5) plus VP verification.
**Deps added to the default closure:** **none.** `DataProofsDotnet.Jose` (KB-JWT / `vp+jwt`) and `DataProofsDotnet.Core` (DI auth proof) are already in the Core closure; BBS stays in the opt-in `Credentials.Rdfc`.

Written after a 3-agent recon that read the real DataProofs/NetCrypto present+verify APIs, the existing engine VP/holder/verifier surface, and the master plan + everything M3/M4/M5 deferred to M6.

---

## 1. Verified substrate API (the corrected truth)

### SD-JWT Key Binding (FR-032) — `DataProofsDotnet.Jose.SdJwt`
| Member | Real signature | Notes |
|---|---|---|
| `SdJwtHolder.CreatePresentationWithKeyBindingAsync` | `static Task<string>(string issuedSdJwt, IEnumerable<string> disclosuresToReveal, JwsSigner holderSigner, string audience, string nonce, DateTimeOffset? issuedAt = null, ct)` | Selects disclosures **by exact encoded base64url string** (from `Disclosure.Encoded`), re-emits `issuerJwt~Dᵢ~…~` for the chosen subset, signs a KB-JWT over it, appends it (no trailing `~`). |
| `SdJwtHolder.CreatePresentation` | `static string(string issuedSdJwt, IEnumerable<string> disclosuresToReveal)` | KB-less subset presentation (ends in `~`). |
| `SdHashAlgorithm.ComputeSdHash` | `static string(string sdAlg, string sdJwtWithTrailingTilde)` | `sd_hash` over the literal ASCII presentation; SHA-256/384/512 only (else `MalformedJoseException`). |
| `Vc.SdJwtVcVerifier.VerifyAsync` (M4) | `…(string presentation, Func<string,Jwk?>, SdJwtVerificationOptions?, ITypeMetadataResolver?, IJoseCryptoProvider?, ct) → Task<SdJwtVcVerificationResult>` | **result-style.** With `RequireKeyBinding=true` + `ExpectedAudience`/`ExpectedNonce`, the substrate verifies the KB-JWT (typ=`kb+jwt`, sig under `cnf`, `sd_hash` constant-time, `aud`, `nonce`, `iat` freshness if `MaxKeyBindingAge` set). `result.KeyBindingVerified` reports the outcome. |
| `SdJwtVerificationOptions` | `{ bool RequireKeyBinding; string? ExpectedAudience; string? ExpectedNonce; TimeSpan? MaxKeyBindingAge; TimeSpan ClockSkew = 2min; DateTimeOffset? CurrentTime }` | When a KB-JWT is verified, `ExpectedAudience`/`ExpectedNonce` are REQUIRED (null ⇒ failure). |
| `SdJwtComponents.Parse(string).Disclosures` (M4) | `IReadOnlyList<Disclosure>` — `Disclosure.{ClaimName, Encoded, IsArrayElement}` | The holder maps requested claim names → `Encoded` to drive `disclosuresToReveal`. |

### JOSE `vp+jwt` (FR-034) — generic, **no VC-specific helper**
| Member | Real signature | Notes |
|---|---|---|
| `Signing.JwsBuilder.BuildCompactAsync` | `static Task<string>(ReadOnlyMemory<byte> payload, JwsSigner signer, string typ, bool detachedPayload = false, ct)` | Build a compact JWS with an **arbitrary `typ`** (`vp+jwt`). No profile validation (unlike `VcJose`). |
| `JwsParser.ParseCompact` | `(string envelope, Func<string,Jwk?> resolve, IJoseCryptoProvider?) → (payload, header, verified)` | Verify; the `typ` check (`== vp+jwt`) is **our** responsibility (G1). |

*(Signatures from the recon's file:line; re-verify exact params against `JwsBuilder.cs`/`JwsParser.cs` at impl, as for every milestone.)*

### Data Integrity authentication proof (FR-034) — `DataProofsDotnet.Core`
| Member | Fact |
|---|---|
| `DataIntegrityProof` | carries `ProofPurpose`, `Challenge` (`"challenge"`), `Domain` (`"domain"`), `Created`, … — null fields omitted. |
| `DataIntegrityProofPipeline.AddProofAsync(doc, proofOptions, signer, ct)` | proofOptions with `ProofPurpose="authentication"` + `Challenge` + `Domain` produces an authentication proof over the VP. |
| `DataIntegrityProofPipeline.VerifyAsync(doc, resolver, options, ct)` | `ProofVerificationOptions { ExpectedProofPurpose, ExpectedChallenge, ExpectedDomain, VerificationTime }` — mismatches fail with distinct codes (`InvalidChallengeError`/`InvalidDomainError`), **not** crypto failures. |

### Holder key
The holder signs the KB-JWT / VP binding with a **`NetCrypto.ISigner` the caller supplies** (same as the issuer supplies one in `IssuanceRequest`); `JwsSigner(ISigner, kid)` derives the alg. The holder's public key must equal the `cnf` set at SD-JWT issuance (M4 `HolderBindingKey`).

### Existing engine surface (what's already built vs. missing)
- **Built (M0):** `VerifiablePresentation` (Holder, VerifiableCredentials, Securing, Version), `ContainedCredential.Embedded(Credential)` / `Enveloped(string)`, `VerifiablePresentationBuilder`, `StructuralValidator` `VcRole.Presentation` (validates holder).
- **Missing (M6 adds):** `IHolder` + `DefaultHolder`; `IVerifier.VerifyPresentationAsync`; `PresentationOrchestrator`; `PresentationVerificationResult`/`PresentationVerificationOptions`; `Challenge`/`Domain` on `SecureRequest`/`VerifyRequest`; a `vp+jwt` path on the JOSE mechanism; the SD-JWT **present** (KB-JWT) + **verify-with-RequireKeyBinding** paths; `ExpectedAudience`/`ExpectedNonce`/`RequireHolderBinding` on `CredentialVerificationOptions`.

---

## 2. Scope decisions (the cuts that keep M6 tractable)

M6 as fully drawn (8-method `IHolder`, COSE VPs, BBS-in-Core, inspections) is enormous. Disciplined cuts, each justified:

1. **BBS derivation stays in `Credentials.Rdfc` (`IBbsDeriver`) — NOT absorbed into Core's `IHolder` (NFR-002).** `IHolder` is in Core; BBS needs `DataProofsDotnet.Rdfc` → dotNetRDF/Newtonsoft. Pulling that into Core's `IHolder` would violate the System.Text.Json-only default closure. So the M5 `IBbsDeriver` remains the BBS seam; the holder presents a BBS-derived credential as an **embedded VP child** (a derived credential is an ordinary DI credential), and the VP-level binding gives it replay protection (see §3). `IHolder.DeriveBbsDisclosureAsync` is therefore **not** added to Core — BBS derive is reached via `IBbsDeriver` (Rdfc) as today.
2. **COSE VPs (`application/vp+cose`) + binary `ContainedCredential` + the `data:`-URI wrapper are OUT of scope.** The master plan §3 keeps `ContainedCredential` = `Embedded(Credential)` | `Enveloped(string)` and explicitly does **not** add the `EnvelopedVerifiableCredential` `data:`-URI wrapper. VP children are therefore **embedded JSON** or **`Enveloped` compact strings** (JOSE `vc+jwt` / SD-JWT — both ASCII). The two VP **binding** paths in the DoD are **DI authentication** and **JOSE `vp+jwt`** — no `vp+cose`. (A binary-COSE child needs the deferred wrapper; the form is already recorded on the enveloped `Credential` for that future work.)
3. **Holder key: the caller provides the `ISigner`** in the present/bind requests (consistent with `IssuanceRequest`), **not** an `IHolderKeyResolver` seam. Simpler, matches M1–M5, and the cnf-vs-signing-key match is the caller's responsibility (the substrate enforces it cryptographically at KB-JWT verify).
4. **`InspectSdJwt` is provided (cheap); `InspectBbsBase`/`BbsDisclosureMap` are deferred.** `InspectSdJwt` returns the disclosable claims from `SdJwtComponents.Parse(...).Disclosures` (public) so the holder can select by claim name. `InspectBbsBase` still needs internal base-proof metadata (`Bbs2023ProofValue.ParseBaseProof` is internal to DataProofs) — deferred, as in M5.
5. **Per-credential challenge-bound BBS replay protection is deferred — resolved at the VP level instead.** The M5 residual (a bare derived credential is replayable) is closed by presenting it inside a **challenge-bound VP** (the VP's DI/JOSE binding carries the verifier `challenge`/`domain`, binding the whole presentation). A finer-grained "bind the BBS presentation header to the challenge" is a future refinement (and couples Rdfc to the challenge); not needed when presenting in a bound VP.
6. **SD-JWT array-element disclosures** (where `Disclosure.ClaimName` is null) are selected only when the holder passes their encoded form; M6's by-claim-name selection covers flat + object-property disclosures (the common case). Documented.

**Net M6 deliverable:** the Holder role — **ingest, inspect (SD-JWT), present an SD-JWT VC with a KB-JWT, assemble a VP, bind it (DI authentication or JOSE `vp+jwt`)** — and the Verifier — **`VerifyPresentationAsync`: per-contained-credential verification + VP holder-binding + SD-JWT KB-JWT**. Honest async throughout (F5).

---

## 3. Design

### 3.1 `IHolder` (public, `Credentials.Roles`)
```csharp
public interface IHolder
{
    HeldCredential Ingest(ReadOnlyMemory<byte> credentialWireBytes);                 // FR-030
    SdJwtInspection InspectSdJwt(HeldCredential held);                               // disclosable claims
    Task<string> PresentSdJwtAsync(HeldCredential held, SdJwtPresentationRequest request, CancellationToken ct = default); // FR-032 (KB-JWT)
    VerifiablePresentation BuildPresentation(VpAssemblyRequest request);             // FR-033
    Task<VerifiablePresentation> BindWithDataIntegrityAsync(VerifiablePresentation vp, VpBindingRequest request, CancellationToken ct = default); // FR-034
    Task<string> BindWithJoseEnvelopeAsync(VerifiablePresentation vp, VpBindingRequest request, CancellationToken ct = default);                 // FR-034 (vp+jwt)
}
```
- `HeldCredential` — a frozen wrapper over an ingested credential (the wire bytes + its detected `SecuringState` + the parsed `Credential` for inspectable forms). `Ingest` reuses the verifier's `EnvelopeDetector` + the mechanisms' `IEnvelopeIngest` (no re-implementation).
- `SdJwtPresentationRequest { IReadOnlyList<string> DiscloseClaims; ISigner HolderSigner; string VerificationMethod; string Audience; string Nonce; }` → the SD-JWT mechanism maps `DiscloseClaims` → encoded disclosures and calls `CreatePresentationWithKeyBindingAsync`. Honest async over the signing (F5).
- `VpAssemblyRequest { string? Holder; IReadOnlyList<ContainedCredential> Credentials; … }` → `BuildPresentation` assembles + `Seal()`s the VP (structurally validated, `VcRole.Presentation`).
- `VpBindingRequest { string Cryptosuite?; ISigner HolderSigner; string VerificationMethod; string? Challenge; string? Domain; }` → DI binding sets `proofPurpose=authentication` + challenge/domain; JOSE binding builds `vp+jwt`.

### 3.2 Securing-seam extensions (reuse the mechanisms; FR-050)
- `SecureRequest` += `string? Challenge`, `string? Domain`, `SecuringDocumentKind Kind = Credential` (Credential | Presentation). `VerifyRequest` += `string? ExpectedChallenge`, `string? ExpectedDomain`.
- `DataIntegrityMechanism`: pass `Challenge`/`Domain`/`ProofPurpose` through to `DataIntegrityProof`; on verify, pass `ExpectedChallenge`/`ExpectedDomain` to `ProofVerificationOptions`. (The same mechanism secures a VP doc with `proofPurpose=authentication`.)
- `JoseEnvelopingMechanism`: when `Kind == Presentation`, build/verify via the **generic** `JwsBuilder`/`JwsParser` with `typ=vp+jwt` (asserted on verify, G1) instead of `VcJose` (`vc+jwt`). Credential path unchanged.
- `SdJwtVcMechanism`: add a **present** entry (`CreatePresentationWithKeyBindingAsync`) and make verify honour `RequireHolderBinding`/`ExpectedAudience`/`ExpectedNonce` (RequireKeyBinding) from the options.

### 3.3 Holder binding model (security)
- **DI-bound VP:** the VP carries an embedded `authentication` proof with `challenge`/`domain`. The verifier binds the proof's `verificationMethod` base DID to the **VP `holder`** (the M1 look-up-then-bind, applied to the holder rather than the issuer) and checks `proofPurpose=authentication` + `ExpectedChallenge`/`ExpectedDomain`. A missing holder ⇒ binding fails closed.
- **`vp+jwt`-bound VP:** a compact JWS (`typ=vp+jwt`) over the VP JSON; the verifier resolves the JWS `kid` → key, verifies the signature, asserts `typ=vp+jwt`, binds `BaseDid(kid) == VP.holder`. Replay protection comes from a `challenge`/`nonce` claim the holder includes (verifier-supplied).
- **SD-JWT KB-JWT (contained or standalone):** `RequireKeyBinding=true` + `ExpectedAudience`/`ExpectedNonce`; the substrate binds the KB-JWT to the issuer's `cnf` and the exact disclosed set (`sd_hash`). The verifier surfaces `KeyBindingVerified`.
- **Replay:** every binding path carries a verifier-supplied `challenge`/`nonce`/`domain`; a BBS-derived credential is replay-protected by the VP wrapper's binding.

### 3.4 `IVerifier.VerifyPresentationAsync` (FR-041) + `PresentationOrchestrator`
```csharp
ValueTask<PresentationVerificationResult> VerifyPresentationAsync(VerifiablePresentation vp, PresentationVerificationOptions? options = null, CancellationToken ct = default);
ValueTask<PresentationVerificationResult> VerifyPresentationAsync(ReadOnlyMemory<byte> presentation, PresentationVerificationOptions? options = null, CancellationToken ct = default);
```
The orchestrator (internal) runs, over an immutable accumulator (mirroring the credential pipeline, fix F4):
1. **Ingest/route** — bytes overload: JSON VP object (parse + DI-bound), or `vp+jwt` compact JWS (decode payload → VP, holder JWS verified by the JOSE mechanism).
2. **Holder-binding stage** — verify the VP binding (DI authentication challenge/domain, or `vp+jwt` typ+sig), bind to `VP.holder`. `Skipped` when unbound and `RequireHolderBinding=false`; `Failed` when required-and-missing/invalid.
3. **Per-contained-credential stage** — each `ContainedCredential` runs the **existing** credential pipeline (`VerifyCredentialAsync`, self-recursive — the M2 status-recursion shape): `Embedded` → the `Credential`; `Enveloped` → the verbatim compact bytes (its own proof/issuer binding; SD-JWT children additionally KB-verified with the presentation `aud`/`nonce`). Each credential's result is carried per-credential.
4. **Compose** — `PresentationVerificationResult { Decision, Binding: CheckResult, Credentials: IReadOnlyList<CredentialVerificationResult>, … }`: `Accepted` iff the binding (when required) and every contained credential are `Accepted`; fail-closed otherwise (`DecisionComposer`).
- `PresentationVerificationOptions { CredentialVerificationOptions CredentialOptions; string? ExpectedAudience; string? ExpectedChallenge; string? ExpectedDomain; bool RequireHolderBinding (default true); VerificationPolicy Policy; }`. `CredentialVerificationOptions` += `ExpectedAudience`, `ExpectedNonce`, `RequireHolderBinding` (the SD-JWT KB path at the credential level).

### 3.5 Honest async (F5)
Every signing/derivation path returns a real `Task` over the substrate's async sign (KB-JWT, DI proof, `vp+jwt`) — never `Task.FromResult` over blocking work. `BuildPresentation`/`InspectSdJwt`/`Ingest` are sync (pure assembly/parse) — no fake async. Documented at the role boundary.

---

## 4. File-by-file (high-level; refined at impl)

### New — `src/Credentials.Core`
- `Roles/IHolder.cs`, `Roles/HeldCredential.cs`, `Roles/SdJwtPresentationRequest.cs`, `Roles/SdJwtInspection.cs` (+`DisclosableClaim`), `Roles/VpAssemblyRequest.cs`, `Roles/VpBindingRequest.cs`, `Roles/DefaultHolder.cs`.
- `Verification/PresentationVerificationResult.cs`, `Verification/PresentationVerificationOptions.cs`.
- `Roles/Internal/PresentationOrchestrator.cs` (or fold into `DefaultVerifier`).
- `Securing/Internal/SecuringDocumentKind.cs`.

### Edited — `src/Credentials.Core`
- `Securing/Internal/SecuringMessages.cs` (Challenge/Domain/Kind on Secure/VerifyRequest), `DataIntegrityMechanism.cs` (pass them), `JoseEnvelopingMechanism.cs` (`vp+jwt` path), `SdJwtVcMechanism.cs` (present + RequireKeyBinding verify), `EnvelopeDetector.cs` (route `vp+jwt` vs `vc+jwt` — both compact JWS; the typ is decided by the mechanism on decode, so detection stays form-level + the orchestrator distinguishes VC vs VP by context).
- `Roles/IVerifier.cs` + `DefaultVerifier.cs` (VerifyPresentationAsync + the holder-binding + per-credential stages; reuse `BindIssuer` shape for holder binding).
- `Verification/CredentialVerificationOptions.cs` (ExpectedAudience/ExpectedNonce/RequireHolderBinding).
- `VerifiablePresentation.cs`/`VerifiablePresentationBuilder.cs` (any accessors the binding/verify need; minimal).

### Edited — DI
- `CredentialsServiceCollectionExtensions.cs` (register `IHolder → DefaultHolder`), `CredentialsBuilder.cs` (no new required hook — caller provides signers).

### Tests
- `tests/…DependencyInjection.Tests/M6HolderPresentationTests.cs` (e2e), `tests/…Core.Tests/M6PresentationVerificationTests.cs` + extend `VerifiablePresentationTests`.

---

## 5. Security model (carried invariants)
- **Holder binding = look-up-then-bind, on the holder** (the M1 issuer-binding lesson applied to `VP.holder`): bind the binding proof's VM / `vp+jwt` `kid` base DID to `VP.holder`; a forged holder needs the holder's key. Missing holder ⇒ fail closed.
- **SD-JWT KB-JWT:** the substrate cryptographically binds the KB-JWT to the issuer-set `cnf` and the exact disclosed set (`sd_hash`, constant-time) + `aud`/`nonce`/freshness — M6 enables it (`RequireKeyBinding`) and surfaces `KeyBindingVerified`.
- **Replay:** verifier-supplied `challenge`/`nonce`/`domain` on every binding path; BBS credentials are bound via the VP wrapper.
- **FR-045 / F7:** binding/KB failures ⇒ `Failed`; resolver/IO ⇒ `Indeterminate`; only malformed input / programming errors propagate. The known general-DI `Indeterminate`-downgrade follow-up (M5) is noted, not in M6.
- **FR-050:** all proof creation/verification delegated to the mechanisms/substrate; the holder never hand-builds a proof. **NFR-002:** Core/DI closure unchanged (BBS stays Rdfc). **NFR-005:** no substrate type on the `IHolder`/options surface (reflection-tested).
- **Per-contained-credential verification** runs the full credential pipeline (proof→structure→validity→status→schema→trust) over each child — a VP is only as valid as its credentials **and** its holder binding.

---

## 6. Test plan
House conventions (xUnit + FluentAssertions 7.0.0, NSubstitute, DI + `did:key` `TestKeys`). Holder keys are minted like issuer keys; the cnf at SD-JWT issuance = the holder's signing key.
- **SD-JWT presentation (FR-032):** issue a cnf-bearing SD-JWT VC (M4) → `PresentSdJwtAsync` (disclose a subset, KB-JWT with aud/nonce) → `VerifyCredentialAsync` with `RequireHolderBinding`+aud+nonce ⇒ Accepted, `KeyBindingVerified`. Negatives: wrong aud / wrong nonce / tampered disclosure (sd_hash) / KB signed by a non-cnf key / `RequireHolderBinding` but no KB ⇒ Rejected.
- **VP assembly (FR-002/033):** build a VP with ≥1 children (embedded + a JOSE `vc+jwt` enveloped string) → structural validation passes; round-trips.
- **DI binding (FR-034):** `BindWithDataIntegrityAsync` (authentication, challenge, domain) → `VerifyPresentationAsync` (matching challenge/domain) ⇒ Accepted; wrong/absent challenge or domain ⇒ Rejected; holder-binding forgery (vm base DID ≠ holder) ⇒ Rejected.
- **JOSE `vp+jwt` binding (FR-034):** `BindWithJoseEnvelopeAsync` → verify ⇒ Accepted; wrong `typ` (≠ `vp+jwt`) ⇒ Rejected; tampered signature ⇒ Failed; holder-binding forgery ⇒ Rejected.
- **Per-contained-credential (FR-041):** a VP whose child credential is expired/tampered/revoked ⇒ VP Rejected (the child's stage fails) even with a valid holder binding; a valid VP with all children valid ⇒ Accepted.
- **F7 / F5:** binding resolver failure ⇒ Indeterminate; honest-async (no `Task.FromResult` over signing). **NFR-005** surface confinement (extend). **NFR-002** closure unchanged.

---

## 7. Build / verify / done
1. `dotnet build -c Release` clean (0 warnings). 2. `dotnet test` — all existing (275) + new M6 green. 3. NFR-002 closure check. 4. **Adversarial pass (mandatory):** holder-binding forgery (forge the holder, replay across verifiers/challenges, swap a child, mix-and-match a KB-JWT), F7/DoS (malformed VP/`vp+jwt`/KB-JWT, oversized child lists), NFR-005/002 leakage. Fix every valid finding with a regression test. 5. CHANGELOG + lessons + this review section + memory. 6. `gh pr create` (base `main`); address review.

**DoD (§9):** VP from ≥1 credentials (embedded + enveloped verbatim); DI authentication binding (challenge/domain) + JOSE `vp+jwt` binding; SD-JWT KB-JWT with aud/nonce/iat/**sd_hash** asserted; per-contained-credential verification; honest async.

---

## 8. Risks & out-of-scope
- **Large milestone.** If preferred, M6 can split into **(a) SD-JWT KB-JWT present/verify** (FR-032, standalone) and **(b) VP build/bind/verify** (FR-002/030/033/034/041) as two PRs — say so at approval. Default: one coherent PR with the §2 cuts.
- **Out of scope (deferred):** COSE VPs (`vp+cose`) + binary `ContainedCredential` + the `EnvelopedVerifiableCredential` `data:`-URI wrapper; `IHolderKeyResolver`; `InspectBbsBase`/`BbsDisclosureMap` (internal substrate metadata); BBS-in-Core (`IHolder.DeriveBbsDisclosureAsync` — BBS derive stays `IBbsDeriver` in Rdfc, NFR-002); per-credential challenge-bound BBS header; array-element SD-JWT selection by claim name; the general-DI `Indeterminate`-downgrade hardening (a cross-cutting M1 follow-up).
- **`JwsBuilder`/`JwsParser` exact signatures** are from one recon agent — re-verify at impl (as every milestone).
- **VCDM 1.1 VP** detection is already version-aware (F8); 1.1 acceptance is M7.

---

## 9. Review

**Delivered (one PR, `feature/m6-presentations`).** The full Holder role (`IHolder`: `Ingest` /
`InspectSdJwt` / `PresentSdJwtAsync` / `BuildPresentation` / `BindWithDataIntegrityAsync` /
`BindWithJoseEnvelopeAsync`) + presentation verification (`IVerifier.VerifyPresentationAsync`, VP-object and
bytes overloads) over the existing securing seam (`SecureRequest`/`VerifyRequest` gained `Challenge`/
`Domain`/`Kind`; a `vp+jwt` JOSE path via the generic `JwsBuilder`/`JwsParser`; a shared `EnvelopeIngest`).
Verification composes holder-binding + structure + every contained credential (self-recursive) fail-closed.

**Scope cuts held** (all in §2): BBS derivation stayed in `Credentials.Rdfc` (NFR-002); COSE VPs and the
`data:`-URI wrapper deferred; caller supplies the holder `ISigner` (no `IHolderKeyResolver`); `InspectSdJwt`
shipped, `InspectBbsBase` deferred; per-credential challenge-bound BBS deferred (VP-level binding gives the
replay defence).

**Adversarial pass — findings & resolutions:**
- **F1 vp+jwt replay** — *fixed.* The `vp+jwt` path had no freshness binding (the generic JWS builder has no
  header-claim hook). Now the holder signs `nonce`/`aud` into the VP payload and the verifier requires them
  to equal `ExpectedChallenge`/`ExpectedDomain` (`holder_binding_replay`). Regression:
  `Jose_vp_jwt_replay_against_a_fresh_challenge_is_rejected`.
- **F2 fail-open required binding** — *fixed.* A required binding with no `ExpectedChallenge` now fails
  (`holder_binding_challenge_required`) rather than accepting any captured VP — the substrate is fail-open,
  so the orchestrator enforces the expectation's presence. Regression:
  `Required_holder_binding_without_an_expected_challenge_is_rejected`.
- **F4 malformed child throws** — *fixed.* `VerifyContainedAsync` wraps the child pipeline; a broken child is
  a rejected credential (`contained_credential_malformed`), never thrown. Regression:
  `Presentation_with_a_malformed_contained_credential_is_rejected_not_thrown`.
- **F6 empty VP** — *fixed.* `RequireAtLeastOneCredential` (default true) makes an empty `verifiableCredential`
  a structure failure (`presentation_no_credentials`). Regression:
  `Empty_presentation_is_rejected_when_at_least_one_credential_required`.
- **F5 withheld-disclosure residual** — *documented* (the M4/M5 inherent residual; a verifier-side guard
  over-rejects compliant credentials — RFC 9901 §4.2.7). Posture stays issuer-side + docs; precise fix needs
  Type-Metadata disclosability (future). Code comment in `SdJwtVcMechanism` updated.
- **F3 holder↔subject** — *documented*: the binding proves holder-key possession, not that the holder is the
  credential subject; that's a verifier policy concern (out of M6 scope).

**Verification:** full suite green — **294 tests** (Core 135 + DI 138 + Rdfc 21), up from 290 (+4 regression
tests). NFR-002 (System.Text.Json-only default closure) and NFR-005 (no substrate type on the holder/
presentation public surface) re-checked clean.
