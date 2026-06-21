# M4 — SD-JWT VC — Implementation Plan

**Status:** For approval (precedes any source).
**Date:** 2026-06-20.
**Branch:** `feature/m4-sdjwt-vc` off `main` (PR #3 / M3 **merged** as `c316094`; no rebase needed — verified via `gh pr view 3` → `MERGED`).
**Milestone:** M4 of `tasks/todo-2026-06-18-credentials-dotnet-implementation.md` §6 — **FR-013** (issue SD-JWT VC) + **FR-051 / D12** (no draft-version type on the public surface; pin `draft-ietf-oauth-sd-jwt-vc-16`). Resolves **OQ-2** (the precise SD-JWT VC validation surface).
**Deps added to the default closure:** **none** — `DataProofsDotnet.Jose 1.0.1` is already in the closure from M3 (re-verified the SD-JWT types ship in the consumed `1.0.1` DLL; source repo at tag `v1.0.1`). M4 adds **zero** NFR-002 risk.

This plan was written **after** a first-hand recon that read the real SD-JWT VC substrate source + the cached `1.0.1` DLL + every credentials-dotnet seam. The §6 master-plan API names (`SdJwtVcIssuer`, `SdJwtHolder`, `SdJwtVcVerifier`, `DisclosureFrame`, `SdJwtIssuerOptions`, `Jwk`, `ITypeMetadataResolver`) were *claims*; the corrected, verified truth is §1 and supersedes the master plan where they disagree.

---

## 1. Verified substrate API (the corrected truth — supersedes the master plan)

All in `DataProofsDotnet.Jose` (namespaces `…SdJwt` and `…SdJwt.Vc`), signer in `…Jose.Signing`. **Confirmed present in the consumed `1.0.1` DLL** (`strings` + 143 `SdJwt` XML-doc entries; source at `v1.0.1`).

### Issuance / verification (the SD-JWT **VC profile**)
| Member | Real signature | Notes |
|---|---|---|
| `Vc.SdJwtVcIssuer.IssueAsync` | `static Task<SdJwtIssuer.Result> IssueAsync(JsonObject claims, DisclosureFrame frame, JwsSigner signer, SdJwtIssuerOptions? options = null, CancellationToken ct = default)` | Pins `typ = dc+sd-jwt` itself (delegates to base `SdJwtIssuer` with `typ: MediaType`). **Throws `MalformedJoseException`** if `vct` is missing/blank **or** the frame marks any reserved claim. `claims` not mutated. |
| `Vc.SdJwtVcVerifier.VerifyAsync` | `static Task<SdJwtVcVerificationResult> VerifyAsync(string presentation, Func<string,Jwk?> resolveIssuerPublicJwk, SdJwtVerificationOptions? options = null, Vc.ITypeMetadataResolver? typeMetadataResolver = null, IJoseCryptoProvider? cryptoProvider = null, CancellationToken ct = default)` | **async + RESULT-style** (does **not** throw on a bad signature / bad disclosure / bad typ — returns `Failure`). Gate order: parse → `typ ∈ {dc+sd-jwt, vc+sd-jwt}` → base `SdJwtVerifier.Verify` → no reserved claim disclosed → `vct` non-empty in disclosed payload → optional metadata. |
| `SdJwtIssuer.Result` (record) | `{ string Issuance; string IssuerJwt; IReadOnlyList<Disclosure> Disclosures }` | `Issuance` = the full compact SD-JWT (`issuerJwt~D1~…~Dn~`, no KB-JWT). This is what we emit + ingest + verify in M4. |
| `Vc.SdJwtVcVerificationResult` | `{ bool IsValid; IReadOnlyList<string> Errors; JsonObject? DisclosedPayload; bool KeyBindingVerified; string? Vct; JsonObject? TypeMetadata }` | Result-style. `Errors[i]` are coded prefixes (`ISSUER_SIGNATURE_INVALID:`, `DISCLOSURE_INVALID:`, `VC_MEDIA_TYPE_INVALID:`, `VC_DISALLOWED_DISCLOSURE:`, `VC_VCT_MISSING:`, `MALFORMED:`). We map **by prefix → our neutral code** (F10: never surface upstream free-text). |

### Base SD-JWT verifier (the F7-load-bearing detail)
`SdJwtVerifier.Verify(string, Func<string,Jwk?> resolveIssuerPublicJwk, SdJwtVerificationOptions?, IJoseCryptoProvider?)` is **synchronous + fully result-style** (read first-hand):
- resolver returns `null` → `Failure("ISSUER_KEY_UNRESOLVED:…")` (**not** a throw),
- bad signature → `Failure("ISSUER_SIGNATURE_INVALID:…")`,
- malformed / bad disclosure → `Failure("MALFORMED…"/"DISCLOSURE_INVALID…")`,
- **only `ArgumentException`/`ArgumentNullException`** on a null/empty `presentation` or null resolver (programming errors).
This differs from M3's JOSE path (sync **+throw**). The classify-before-crypto lesson still applies: **resolve the key out-of-band first** (null/IO → `Indeterminate`), then pass a **constant** resolver (`_ => jwk`) so any `IsValid == false` is a real crypto/profile negative → `Failed`. (`SdJwtVcVerifier.VerifyAsync` calls the base verifier **unguarded**; the only residual throw source is the optional type-metadata resolver doing I/O — we wrap it → `Indeterminate`.)

### Constants, options, frame, components
| Member | Fact |
|---|---|
| `Vc.SdJwtVcConstants.MediaType` | `"dc+sd-jwt"` — the issuer-JWT `typ` **and** the base media type. Issued media type = `application/dc+sd-jwt`. |
| `Vc.SdJwtVcConstants.TransitionalMediaType` | `"vc+sd-jwt"` — accepted on **input** only. |
| `Vc.SdJwtVcConstants.VctClaim` / `VctIntegrityClaim` / `StatusClaim` | `"vct"` / `"vct#integrity"` / `"status"`. |
| `Vc.SdJwtVcConstants.MustNotBeSelectivelyDisclosed` | `["iss","nbf","exp","cnf","vct","vct#integrity","status"]` — substrate-enforced at **both** issue and verify. |
| `SdJwtIssuerOptions` (record) | `{ string HashAlgorithm = "sha-256"; int DecoyDigestCount; Jwk? HolderConfirmationKey }` — `HolderConfirmationKey` ⇒ the `cnf` key. |
| `SdHashAlgorithm` | constants `Default/Sha256 = "sha-256"`, `Sha384 = "sha-384"`, `Sha512 = "sha-512"`; `IsSupported(string?)`. |
| `SdJwtVerificationOptions` (record) | `{ bool RequireKeyBinding; string? ExpectedAudience; string? ExpectedNonce; TimeSpan? MaxKeyBindingAge; TimeSpan ClockSkew = 2min; DateTimeOffset? CurrentTime }`. **`CurrentTime`/`ClockSkew` are used ONLY for KB-JWT `iat` freshness** — the substrate does **not** check the issuer-JWT `nbf`/`exp`. |
| `DisclosureFrame` | builder; **`.Entries` is `internal`** (we only *build* via the public fluent methods). Public: `Disclose(name)`, `DiscloseObjectProperties(name, params subClaims)`, `DiscloseObject(name, nested)`, `DiscloseRecursively(name, params subClaims)`, `DiscloseRecursiveObject(name, nested)`, `DiscloseArrayElements(name, params indices)`. |
| `SdJwtComponents.Parse(string) → { string IssuerJwt; IReadOnlyList<Disclosure> Disclosures; string? KeyBindingJwt; bool HasKeyBinding; string SdJwtWithoutKeyBinding }` | Splits on `~`; throws `MalformedJoseException` on a missing issuer JWT / missing trailing `~` / empty disclosure slot. The first segment is a plain compact JWS. |
| `JwsSigner(NetCrypto.ISigner, string? kid)` | (from M3) derives `alg` from `KeyType`; `NotSupportedException` for P-521/RSA. |
| `Jwk` + `JwkConversion.{FromMultikey,ToPublicJwk,ExtractPublicKey}` | (from M3) the kid→Jwk building blocks. **Substrate types → confine (NFR-005/D12).** |
| `Vc.ITypeMetadataResolver` | `Task<JsonObject?> ResolveAsync(string vct, CancellationToken ct = default)` — **draft type → confine; wrap (F3).** `LocalCacheTypeMetadataResolver` is an offline impl. |

### NFR-002 closure
No change: `DataProofsDotnet.Jose → DataProofsDotnet.Core` only (STJ-native). M4 imports **only** `.Jose` (already present from M3). **Gate:** re-run `dotnet list … --include-transitive`; fail the plan if Newtonsoft/dotNetRDF appears.

---

## 2. The data-model decision (the crux — resolves OQ-2)

**An SD-JWT VC in this library is a VCDM 2.0 credential carried as the SD-JWT VC claims set.** This is **forced by the architecture and is spec-permitted**:

- The only issuance entry point is `IIssuer.IssueAsync(Credential, IssuanceRequest)`, and `Credential.Build()…Seal()` runs the VCDM 2.0 `StructuralValidator` — so **the issuance input is necessarily a valid VCDM 2.0 credential**. A flat IETF-style claims object cannot be built/sealed. (A separate claims-object entry point is out of M4 scope and not in the role API.)
- `SdJwtVcIssuer.IssueAsync` accepts an **arbitrary** `JsonObject` of claims and requires only a non-empty `vct`. draft-16 §3.2.2 permits arbitrary additional claims. So the SD-JWT VC payload = the VCDM document (`@context`, `type`, `issuer`, `credentialSubject`, `validFrom`/`validUntil`, …) **+ `vct` (in the clear) + `iss` (injected, = `issuer.id`)**, with caller-chosen non-structural claims marked selectively disclosable. This is a conformant SD-JWT VC **and** a conformant VCDM 2.0 credential.
- **Verified that this reuses the whole pipeline with near-zero branching:** `StructuralValidator` is whitelist-additive (it validates only known members and ignores `vct`/`iss`/`_sd`/`_sd_alg`/`cnf`), so the ingested SD-JWT VC document passes `ValidateStructure()` **unchanged**; `Version` (`@context[0]`), `ValidFrom/Until` (`validFrom`/`validUntil`), and status/schema projections all read the **clear** structural members.

**Issuer binding anchor = the `iss` claim** (draft §3.2.2.1.1 makes `iss` the authoritative issuer identifier; we inject `iss = issuer.id`, which is also kept in the clear because `iss` is reserved-non-disclosable). The verifier binds `BaseDid(kid) == iss` — the same look-up-then-bind shape as M1/M3.

**Reserved-claim guard, two layers:** the substrate rejects disclosing `iss/nbf/exp/cnf/vct/vct#integrity/status`. We **additionally** reject a `DisclosureSelector` that targets a **VCDM structural** member (`@context`, `type`, `issuer`, `id`, `credentialSubject` *as a whole*) so the issuer/structure/validity anchors always stay in the clear (a caller can still disclose `credentialSubject` *sub-properties* and other non-structural claims).

### M4 / M6 scope split (the ambiguity the working agreement asked to resolve)
- **In M4:** *issue* an SD-JWT VC (VCDM claims + `vct` + path-selected disclosures + **optional `cnf`** holder-binding key) and *verify* the **issuer-signed** SD-JWT and its disclosures (signature, `typ`/media/`vct`/reserved-claim profile, disclosure reconstruction, issuer binding, structure, validity). Verify runs with `RequireKeyBinding = false`.
- **Deferred to M6** (consistent with M3 deferring **all** holder/VP work): `IHolder.InspectSdJwt` / `SdJwtInspection` / `DisclosableClaim` (holder-side disclosure selection), `CreatePresentationWithKeyBindingAsync` (KB-JWT creation), and **verifier-side KB-JWT verification** (holder proof-of-possession with `aud`/`nonce`/`sd_hash`/freshness). The `cnf` key issued in M4 is forward-compat for that. **Rationale:** M4's core, per the master plan, is "issue with a disclosure frame + verify the issuer-signed SD-JWT" — the holder is a separate role with its own milestone.
- **Schema for SD-JWT VC is out of the M4 test matrix.** SD-JWT VC uses `vct` Type Metadata, not `credentialSchema`; and JSON-Schema-over-selectively-disclosed subject claims has a disclosed-vs-ingested subtlety (the ingested issuer-JWT cleartext carries `_sd` digests in place of disclosable sub-claims). Full SD-JWT schema/metadata validation over the **reconstructed** payload is an M6 concern. Status (`credentialStatus`, if present and in the clear) naturally runs.

---

## 3. Design decisions

1. **`SdJwtVcMechanism : ISecuringMechanism, IEnvelopeIngest`** (`Form = SdJwtVc`, `SuiteNames = []`, `IsAvailable = true`) — the **sole** importer of the SD-JWT substrate (FR-050). Mirrors `JoseEnvelopingMechanism`. Reuses the existing `IEnvelopeKeyResolver`/`NetDidEnvelopeKeyResolver` (kid → JWK) unchanged.

2. **Issue (`SecureAsync`):**
   - `claims = credential.AsClaimsObject()` (deep clone); set `claims["vct"] = request.Vct`; if absent, set `claims["iss"] = credential.Issuer.Id` (the binding anchor + draft-required, kept in the clear).
   - Build the `DisclosureFrame` from `request.Disclosable` (our `DisclosureSelector` → the public fluent methods). **Guard** structural targets first (→ `ArgumentException`, a usage error).
   - `options = new SdJwtIssuerOptions { HashAlgorithm = Map(request.SdHash), DecoyDigestCount = request.DecoyDigestCount, HolderConfirmationKey = request.HolderBinding is {} h ? ToJwk(h) : null }`.
   - `signer = new JwsSigner(request.Signer, request.VerificationMethod)`; `result = await SdJwtVcIssuer.IssueAsync(claims, frame, signer, options, ct)`. Let `NotSupportedException` (unsupported key) and `MalformedJoseException` (programming/usage error: blank `vct`, reserved disclosed) propagate at **issue** (issuance bugs throw, per the role contract).
   - `SecureOutcome.ForSdJwt(result.Issuance)`.

3. **Ingest (`Ingest`, `IEnvelopeIngest`):** `components = SdJwtComponents.Parse(compact)` → `payload = CompactJws.DecodePayload(components.IssuerJwt)` (the issuer-JWT cleartext: VCDM members in the clear + `vct`/`iss`/`_sd`/`_sd_alg`/`cnf`) → `inner = CredentialDocument.Parse(payload)` → `Credential.FromEnvelope(inner, SecuringState.SdJwtVc, envelope)`. Wrap `MalformedJoseException` → `CredentialFormatException` (malformed input contract). The clear structural members make `Version`/`Issuer`/`ValidFrom/Until`/`ValidateStructure` work as for any VCDM credential.

4. **Verify (`VerifyAsync`), F7 classify-before-crypto:**
   - `compact = UTF8(envelope)`; `kid = CompactJws.ReadKid(SdJwtComponents.Parse(compact).IssuerJwt)`. **Missing/empty kid → `Invalid("sdjwt_kid_missing")`** (fail closed — no signer identity to bind).
   - Resolve `kid` via `_keyResolver` (throw/`null` → `Unresolvable` → **Indeterminate**); build `Jwk` (failure → `Unresolvable`). **Key resolved before any crypto.**
   - `opts = new SdJwtVerificationOptions { RequireKeyBinding = false, CurrentTime = request.VerificationTime }`.
   - `result = await SdJwtVcVerifier.VerifyAsync(compact, _ => jwk, opts, typeMetadataResolver: _metadataAdapter, cryptoProvider: null, ct)`, wrapped: `OperationCanceledException` rethrows; any **other** exception (only reachable via the optional metadata resolver doing I/O, since the key is pre-resolved and the verifier is result-style) → `Unresolvable("type_metadata_unresolvable")` → **Indeterminate**.
   - `result.IsValid == false` → `Invalid(MapCode(result.Errors))` → **Failed** (every SD-JWT negative — bad sig, bad disclosure, wrong typ, vct missing, reserved disclosed — is definitive; the pre-resolved key means it can never be a resolution failure).
   - `result.IsValid == true`: **self-enforcing consistency guard** (mirror `envelope_payload_mismatch`) — re-decode the issuer-JWT cleartext and assert its `iss`/`vct` equal `result.DisclosedPayload`'s `iss`/`vct` (both are reserved-non-disclosable, so they *must* match; this converts "safe because reserved" into "explicitly checked"). Mismatch → `Invalid("sdjwt_payload_mismatch")`. Else `Verified([kid])`.

5. **Verifier wiring (`DefaultVerifier`):**
   - `CheckProofAsync`: add `SecuringState.SdJwtVc => SecuringForm.SdJwtVc`; build the enveloping-shaped `VerifyRequest { Document = AsElement(), Envelope = EnvelopeBytes, VerificationTime }` (no `ExpectedPayload` — SD-JWT does its own iss/vct guard); map `Verified → BindIssuer`, `Invalid → Failed`, `Unresolvable → Indeterminate`, `NoProof → NoProof` (unchanged mapping).
   - `BindIssuer`: branch the anchor — `issuerId = credential.Securing == SecuringState.SdJwtVc ? IssClaim(credential) : credential.Issuer?.Id`, where `IssClaim` reads the clear `iss` string (missing → `issuer_binding_missing`). Everything else (`BaseDid(vm) == issuerId`) is unchanged. Reuses the M3 binding diagnostics (`issuer_binding`, `issuer_binding_missing`).
   - **Structure / validity / status run unchanged** (they read clear VCDM members). Schema naturally `Skipped` when no `credentialSchema` (out of M4 SD-JWT matrix; see §2).

6. **Detection (`EnvelopeDetector.Detect`):** add the SD-JWT branch **before** the compact-JWS branch — after whitespace-trim, if the first byte is base64url **and** the (trimmed) span contains `~`, return `SdJwtVc`. (A plain compact JWS has no `~`; an SD-JWT always has a trailing `~`. `~` is outside the base64url+`.` alphabet, so the existing `LooksLikeCompactJws` already returns `false` for SD-JWT input — the new branch makes routing explicit instead of falling through to `null`.) Routing hint only; the authoritative check is ingest/verify.

7. **Public draft-free request/option types** (`Credentials.Roles`, mirroring `*IssuanceRequest`):
   ```csharp
   public sealed record SdJwtVcIssuanceRequest : IssuanceRequest {
       public required string Vct { get; init; }
       public required ISigner Signer { get; init; }
       public required string VerificationMethod { get; init; }
       public IReadOnlyList<DisclosureSelector> Disclosable { get; init; } = [];
       public HolderBindingKey? HolderBinding { get; init; }
       public SdHashName SdHash { get; init; } = SdHashName.Sha256;
       public int DecoyDigestCount { get; init; }
   }
   ```
   - `DisclosureSelector` (draft-free) — factories `Claim(name)` (flat), `ObjectProperties(name, params subClaims)` (structured), `ArrayElements(name, params indices)`. Maps to `DisclosureFrame.Disclose/DiscloseObjectProperties/DiscloseArrayElements`. (Recursive frames deferred — note it; not needed for M4.)
   - `HolderBindingKey` (draft-free) — the holder's **public** cnf key as neutral `NetCrypto` material; factories `FromMultikey(string multibase)` / `FromPublicKey(KeyType, ReadOnlyMemory<byte>)`. Mechanism converts to substrate `Jwk` via `JwkConversion`. (`NetCrypto.KeyType` is already public surface via the JOSE/COSE requests — not a draft type.)
   - `SdHashName` (draft-free enum) — `Sha256 | Sha384 | Sha512` → the `SdHashAlgorithm` string constants.
   - **Naming:** master plan §4 says `SdJwtVcRequest`; we use **`SdJwtVcIssuanceRequest`** to match the established `DataIntegrity/Jose/CoseEnvelopeIssuanceRequest` convention (same kind of alignment as M3's `IIssuerJwkResolver → IEnvelopeKeyResolver`).

8. **`ICredentialTypeMetadataResolver` wrapper (F3)** in `Credentials.Schema`:
   ```csharp
   public interface ICredentialTypeMetadataResolver { Task<JsonObject?> ResolveAsync(string vct, CancellationToken ct = default); }
   ```
   - Internal `TypeMetadataResolverAdapter : DataProofsDotnet.Jose.SdJwt.Vc.ITypeMetadataResolver` wraps the public hook and is the **only** place the draft `ITypeMetadataResolver` is named (besides the mechanism). DI registers the adapter **only when** a public `ICredentialTypeMetadataResolver` is registered (optional hook, like the schema/status hooks); absent ⇒ the mechanism passes `null` (no metadata retrieval). `TypeMetadata` is informational in M4 (not gated).

9. **`IssuedCredential.SdJwtVc(Credential enveloped, string compactSdJwt)`** factory (media `application/dc+sd-jwt`) + a `string? CompactSdJwt` accessor. `Credential.CompactEnvelope` stays JOSE-only; the SD-JWT compact is exposed on `IssuedCredential` (and recoverable from `Credential.EnvelopeBytes` internally). The enveloped `Credential` carries the verbatim compact for re-verification.

10. **Registration is unconditional** (`.Jose` is a default-closure dep). No new fail-fast (reuses the M3 `IEnvelopeKeyResolver`/`IDidResolver`).

---

## 4. File-by-file changes

### New — `src/Credentials.Core`
- `Securing/Internal/SdJwtVcMechanism.cs` — `ISecuringMechanism, IEnvelopeIngest`; **sole caller** of `DataProofsDotnet.Jose.SdJwt(.Vc)`. Implements §3.2–3.4 (`SecureAsync`, `Ingest`, `VerifyAsync`) + private `DisclosureSelector → DisclosureFrame`, `HolderBindingKey → Jwk`, `SdHashName → string`, `Errors → neutral code` mappers + the `iss/vct` consistency guard.
- `Securing/Internal/TypeMetadataResolverAdapter.cs` — internal adapter over the public `ICredentialTypeMetadataResolver` (the one extra place the draft `ITypeMetadataResolver` is named).
- `Roles/SdJwtVcIssuanceRequest.cs` *(or appended to `IssuanceRequest.cs`)* — the public request record (§3.7).
- `Roles/DisclosureSelector.cs` — public draft-free selector (§3.7).
- `Roles/HolderBindingKey.cs` — public draft-free cnf key (§3.7).
- `Roles/SdHashName.cs` — public draft-free enum (§3.7).
- `Schema/ICredentialTypeMetadataResolver.cs` — public hook (F3, §3.8).

### Edited — `src/Credentials.Core`
- `Securing/Internal/SecuringMessages.cs`:
  - `SecureRequest` += SD-JWT fields (init-only, nullable; ignored by the other forms): `string? Vct`, `IReadOnlyList<DisclosureSelector>? Disclosable`, `HolderBindingKey? HolderBinding`, `SdHashName? SdHash`, `int DecoyDigestCount`.
  - `SecureOutcome` += `string SdJwt` payload + `ForSdJwt(string)` factory + `SecuringForm.SdJwtVc` arm.
- `Securing/Internal/EnvelopeDetector.cs` — the `~` → `SdJwtVc` branch (§3.6) + a `ContainsTilde` helper bounded to the trimmed span.
- `Securing/SecuringSelector.cs` — `static SecuringSelector SdJwtVc()`.
- `Roles/IssuedCredential.cs` — `SdJwtVc(Credential, string)` factory (media `application/dc+sd-jwt`) + `string? CompactSdJwt`.
- `Roles/DefaultIssuer.cs` — `SdJwtVcIssuanceRequest` case: resolve `SecuringForm.SdJwtVc`, build the SD-JWT `SecureRequest` (incl. `Document = credential.AsElement()` for the claims clone via the mechanism using `credential` — actually pass the claims via the mechanism reading `request`-carried fields + `credential.AsClaimsObject()`; the issuer hands the mechanism the `Credential` claims through `SecureRequest`), call `SecureAsync`, build the enveloped `Credential` via `Credential.FromEnvelope(credential.Document, SecuringState.SdJwtVc, UTF8(outcome.SdJwt))` + `IssuedCredential.SdJwtVc(...)`.
  - *Note:* `SecureRequest` carries `Document`/claims — the mechanism needs the **claims object**; simplest is to add `JsonObject? ClaimsObject` to `SecureRequest` (or have the mechanism rebuild from `Document`). Decision: add `JsonObject? Claims` to `SecureRequest` (SD-JWT-only), set to `credential.AsClaimsObject()` in the issuer — avoids re-parsing `Document`.
- `Roles/DefaultVerifier.cs` — `CheckProofAsync` `SdJwtVc` arm + `BindIssuer` `iss` anchor branch (§3.5).
- `Credential.cs` — no change needed (`FromEnvelope`/`EnvelopeBytes`/`AsClaimsObject` already exist; `CompactEnvelope` stays JOSE-only by design). *Optionally* extend `CompactEnvelope` to also return the SD-JWT compact for `SecuringState.SdJwtVc` — **decision: yes**, return the SD-JWT compact too (it is a compact string form), documented; keeps a single accessor for "the compact serialization."

### Edited — DI + csproj
- `src/Credentials.Extensions.DependencyInjection/CredentialsServiceCollectionExtensions.cs`:
  - `TryAddEnumerable(ServiceDescriptor.Singleton<ISecuringMechanism, SdJwtVcMechanism>(sp => new SdJwtVcMechanism(sp.GetRequiredService<IEnvelopeKeyResolver>(), sp.GetService<ICredentialTypeMetadataResolver>())))` — collected by `SecuringMechanismRegistry`.
  - (No new package reference — `DataProofsDotnet.Jose` already referenced by `Credentials.Core.csproj` from M3.)
- `src/Credentials.Extensions.DependencyInjection/CredentialsBuilder.cs` — optional `UseTypeMetadataResolver<T>()` / `UseTypeMetadataResolver(instance)` ergonomics (mirrors `UseSchemaResolver`); the hook is otherwise just a consumer registration of `ICredentialTypeMetadataResolver`.

---

## 5. Security model (carried invariants)

- **FR-050:** `SdJwtVcMechanism` is the sole importer of `DataProofsDotnet.Jose.SdJwt(.Vc)`; roles/verifier touch no substrate type. The `iss`/`vct` consistency guard and the binding live above the substrate.
- **NFR-005 / FR-051 / D12 (F3):** no `SdJwt*`/`DisclosureFrame`/`SdJwtIssuerOptions`/`Jwk`/`ITypeMetadataResolver` on the public surface — confined to the mechanism + the `TypeMetadataResolverAdapter`. Public types are the draft-free `SdJwtVcIssuanceRequest`/`DisclosureSelector`/`HolderBindingKey`/`SdHashName`/`ICredentialTypeMetadataResolver`. **Extend the NFR-005 reflection test** (rename → `SurfaceConfinementTests`) to also forbid `DataProofsDotnet.Jose.SdJwt*`.
- **FR-045 / F7:** key resolved async **before** the substrate verify → DID/IO failure ⇒ `Indeterminate`; bad signature / bad disclosure / `_sd`-digest mismatch / wrong `typ` / disclosed-reserved / missing `vct` ⇒ `Failed`. Only malformed input (`CredentialFormatException`) / programming errors (`ArgumentNullException`) propagate. The optional metadata resolver's I/O fault ⇒ `Indeterminate`, never a crypto verdict.
- **Issuer binding:** `BaseDid(kid) == iss` (look-up-then-bind; `iss` is inside the signed issuer JWT and reserved-non-disclosable, so it is authenticated and cannot be selectively hidden). Missing kid ⇒ fail closed. To forge `iss = victim` an attacker must sign under a kid whose base DID is the victim's ⇒ the resolver fetches the victim's key ⇒ the signature fails.
- **Sign/serialize fidelity:** the substrate owns the issuer-JWT serialization + `_sd` digesting (FR-050). Our self-enforcing guard ties the bound `iss`/`vct` to the substrate-verified disclosed payload (`sdjwt_payload_mismatch`), mirroring the M3 `envelope_payload_mismatch` lesson.
- **Frozen document never mutated:** issuance uses `AsClaimsObject()` (a deep clone) for the SD-JWT claims; the source `CredentialDocument` is untouched; the enveloped/ingested credential re-ingests via `CredentialDocument.Parse`.

---

## 6. Test plan

House conventions: xUnit + FluentAssertions **7.0.0**, NSubstitute `.Returns(value)`. End-to-end via `AddCredentials().UseNetDid()` + `TestKeys` in-memory `did:key`. New files: `tests/…DependencyInjection.Tests/M4SdJwtVcTests.cs` (e2e), `tests/…Core.Tests/M4SdJwtDetectionTests.cs` (detector), and extensions to `M3SurfaceConfinementTests` (→ `SurfaceConfinementTests`).

**Round-trip (per alg):** issue → verify `Accepted` for **EdDSA + ES256** (Ed25519 + P-256). Assert `IssuedCredential.Form == SdJwtVc`, `MediaType == "application/dc+sd-jwt"`, `CompactSdJwt` non-empty and ends with `~`; verify both the `Credential` object **and** the verbatim compact wire bytes (bytes overload + detection). Proof + Structure + Validity all `Passed`.
**vct / profile:** issued issuer-JWT `typ == dc+sd-jwt` (decode header); `vct` present in the clear and equals the request; the transitional `vc+sd-jwt` is accepted on input (hand-craft + verify).
**Selective disclosure round-trip:** disclose a `credentialSubject` sub-property and a top-level non-structural claim; verify reconstructs them; the issued issuer-JWT cleartext carries `_sd` (not the value).
**Reserved-claim rejection (issue):** a `DisclosureSelector.Claim("vct")` / `"iss"` / `"cnf"` ⇒ the issue throws (substrate `MalformedJoseException` surfaced); a selector targeting a **VCDM structural** member (`issuer`/`type`/`@context`/`id`) ⇒ `ArgumentException` (our guard).
**Reserved-claim rejection (verify):** a hand-crafted SD-JWT VC that selectively discloses a reserved claim ⇒ `Rejected` (proof `Failed`, code mapped).
**cnf (issue-side):** issuing with `HolderBinding` ⇒ the issuer-JWT payload carries a `cnf` JWK; without it, no `cnf`. (KB-JWT verification is M6 — assert M4 verifies fine with `RequireKeyBinding = false` whether or not `cnf` is present.)
**Issuer binding (load-bearing):**
  - *post-sign mismatch:* `iss = victim`, signed by attacker under attacker's kid ⇒ `Rejected` (`issuer_binding`).
  - *self-consistent forgery:* `iss = victim`, `kid = victim`'s VM, signed by **attacker** ⇒ `Rejected` (signature fails against the victim's resolved key).
  - *missing kid:* issuer-JWT with no `kid` ⇒ `Rejected` (fail closed), not Indeterminate.
**F7 Indeterminate vs Failed:** unresolvable kid ⇒ proof `Indeterminate` (credential `Rejected` under fail-closed default); tampered issuer-JWT signature ⇒ proof `Failed` — assert the two are **not** conflated and neither throws.
**Validity:** an expired SD-JWT VC (`validUntil` in the past) ⇒ Validity `Failed` (the validity stage reads the clear `validFrom`/`validUntil`).
**Detection:** `EnvelopeDetector.Detect` returns `SdJwtVc` for `issuerJwt~D1~…~` (with/without disclosures, with/without trailing KB segment) and is **not** misrouted to `Jose`; a plain compact JWS still returns `Jose`; undecodable SD-JWT (bad issuer-JWT payload) ⇒ `CredentialFormatException` at ingest.
**NFR-005 surface confinement:** the reflection test forbids any `DataProofsDotnet.Jose.SdJwt*` (incl. `DisclosureFrame`, `SdJwtIssuerOptions`, `ITypeMetadataResolver`, `Jwk`, `SdJwtVc*`) on any public credentials-dotnet signature.
**DI:** `AddCredentials` registers the SD-JWT mechanism; `ISecuringCapabilities.AvailableForms` contains `SdJwtVc`; `IsSupported(SecuringSelector.SdJwtVc())` is true; an `ICredentialTypeMetadataResolver` registration is honored (adapter invoked).

---

## 7. Build / verify / done

1. `dotnet build -c Release` clean (0 warnings — `TreatWarningsAsErrors`, XML-doc gate; **document every new public member**).
2. `dotnet test -c Release --no-build` — all existing (205) + new M4 tests green.
3. **NFR-002 gate:** `dotnet list src/Credentials.Core/Credentials.Core.csproj package --include-transitive` — assert no `Newtonsoft.Json`/`dotNetRDF` in the default closure (unchanged from M3).
4. **Adversarial pass (mandatory, CLAUDE.md):** 2–3 read-only general-purpose agents (a Workflow fan-out) attacking different surfaces — (a) issuer/holder-binding & disclosure forgery (forge `iss`, hide/forge a disclosure, swap a disclosure, replay), (b) F7 status mapping & detection/DoS (force a forgery onto `Indeterminate`, `~`-routing confusion, oversized/over-disclosed input), (c) fidelity/`_sd`-digest tampering & NFR-005/NFR-002 leakage (`sdjwt_payload_mismatch`, surface/closure). Confirm-by-running in `/tmp` scratch projects, **no repo edits**. Fix every valid finding with a regression test.
5. Update `CHANGELOG.md` (M4 entry), `tasks/lessons.md` (new lessons), the **Review** section below, and **memory** (dependency-surfaces project-status line + the SD-JWT API facts; `MEMORY.md` index hook).
6. `gh pr create` (base `main`, head `feature/m4-sdjwt-vc`); address valid review comments, mapping each finding → fix in a PR comment.

**DoD (§9 contributions):** FR-013 issue SD-JWT VC + verify the issuer-signed SD-JWT/disclosures; `typ=dc+sd-jwt` / media `application/dc+sd-jwt` / `vct` non-disclosable / reserved-claims-rejected asserted; FR-051/D12 no draft type on the surface (reflection test); F7 bad-sig→Failed / resolver-IO→Indeterminate; issuer binding (post-sign + self-consistent forgery + missing-kid); NFR-002 closure unchanged.

---

## 8. Risks & out-of-scope

- **Holder presentation + KB-JWT verification are M6** (disclosure selection, `CreatePresentationWithKeyBindingAsync`, `aud`/`nonce`/`sd_hash`/freshness). M4 issues a `cnf`-bearing SD-JWT VC and verifies it with `RequireKeyBinding = false`. Flagged, not built here.
- **Schema/Type-Metadata over disclosed claims is M6** — the disclosed-vs-ingested subtlety (ingested cleartext carries `_sd` digests for disclosable sub-claims) means schema validation must run over the substrate-**reconstructed** payload; deferred. M4 keeps `credentialSchema` out of the SD-JWT matrix.
- **VCDM-carried model, not flat IETF claims** (§2) — forced by the `Credential`/`Seal()` entry point and spec-permitted (arbitrary claims + `vct`). A future flat-claims issuance entry point (claims object in, no VCDM `Seal`) would be a separate, additive API — not M4.
- **draft-16 pin (D12)** — `SdJwtVcConstants` confirms `-16` is current; all draft-sensitive values stay in the substrate + our mappers, so a re-pin is localized.
- **Recursive disclosure frames deferred** — M4's `DisclosureSelector` covers flat / object-properties / array-elements (the common cases); recursive (`DiscloseRecursively`) is additive later.
- **Seam churn** — widening `SecureRequest`/`SecureOutcome` touches only internal call sites (no public API change); the DI/JOSE/COSE mechanisms ignore the new SD-JWT fields.

---

## 9. Review

*(to be completed after implementation + adversarial pass)*
