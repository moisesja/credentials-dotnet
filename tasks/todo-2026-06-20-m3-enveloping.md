# M3 — Enveloping VC-JOSE-COSE — Implementation Plan

**Status:** For approval (precedes any source).
**Date:** 2026-06-20.
**Branch:** `feature/m3-enveloping` off `main` (PR #2 / M2 merged 2026-06-20 as `a6edef5`; no rebase needed).
**Milestone:** M3 of `tasks/todo-2026-06-18-credentials-dotnet-implementation.md` §6 — **FR-012** (produce & verify enveloping VC-JOSE-COSE, both serializations). **OQ-4 resolved: JOSE first, then COSE, both in this milestone.**
**Deps added to the default closure:** `DataProofsDotnet.Jose 1.0.1`, `DataProofsDotnet.Cose 1.0.1` (already pinned in `Directory.Packages.props`).

This plan was written **after** a 5-agent recon that verified every DataProofs API against the consumed 1.0.1 packages' `PublicAPI.Unshipped.txt` + XML docs and read every credentials-dotnet seam first-hand. The §6 master plan's API names were *claims*; the corrected truth is in §1 below and supersedes the master plan where they disagree.

---

## 1. Verified substrate API (the corrected truth — supersedes the master plan)

### DataProofsDotnet.Jose 1.0.1 (namespace `DataProofsDotnet.Jose`, signer in `.Signing`)
| Member | Real signature | Notes |
|---|---|---|
| `VcJose.EnvelopeCredentialAsync` | `static Task<string> EnvelopeCredentialAsync(ReadOnlyMemory<byte> credentialJson, JwsSigner signer, CancellationToken ct = default)` | **async**, returns compact JWS. Hard-codes `typ=vc+jwt`, `cty=vc`, derives `alg`+`kid` from the signer. Throws `MalformedJoseException` if payload isn't a JSON object. |
| `VcJose.VerifyCredential` | `static byte[] VerifyCredential(string envelope, Func<string, Jwk?> resolveSignerPublicJwk, IJoseCryptoProvider? cryptoProvider = null)` | **SYNCHRONOUS, THROW-based.** Asserts `typ==vc+jwt` **and** `cty==vc` (else `MalformedJoseException`); bad signature **and** resolver-returns-`null` → `JoseCryptoException` (not distinguishable from each other). Returns inner credential bytes. Resolver is invoked with the protected-header `kid` (empty string if absent). |
| `Signing.JwsSigner` | `JwsSigner(NetCrypto.ISigner signer, string? kid = null)`; `.Algorithm`, `.Kid`, `.Signer` | Derives `alg` from `KeyType` (Ed25519→EdDSA, P-256→ES256, P-384→ES384, secp256k1→ES256K; **else `NotSupportedException`**). Auto-transcodes ECDSA DER→IEEE-P1363. **Always sign through `JwsSigner`.** |
| `Jwk` | mutable RFC-7517 class `{Kty,Crv,X,Y,D,K,Kid,Alg,Use,AdditionalData}` | **Substrate type — confine (NFR-005/D12).** |
| `JwkConversion` | `FromMultikey(string multibase, string? kid)→Jwk`; `ToPublicJwk(KeyType, byte[], string? kid)→Jwk`; `ExtractPublicKey(Jwk)→(KeyType,byte[])` | kid→Jwk building blocks for the resolver. |
| Constants | `VcJose.EnvelopeType="vc+jwt"`, `CredentialContentType="vc"`, `MediaType="application/vc+jwt"` | typ/cty pin values (asserted internally) + the issued media type. |
| Exceptions | `MalformedJoseException`, `JoseCryptoException` (both `: Exception`, sealed) | Map: malformed/wrong-typ-cty → structural Invalid; crypto → crypto Invalid. |
| **No VP path** | — | No `vp+jwt` helper exists. Enveloped VP (FR-033/034) is **M6**, not M3. |
| **No header peek** | — | `kid` reaches us only inside the resolver. M3 reads `kid` by base64url-decoding protected-header segment 0 itself. |

### DataProofsDotnet.Cose 1.0.1 (namespace `DataProofsDotnet.Cose`)
| Member | Real signature | Notes |
|---|---|---|
| `VcCose.EnvelopeCredentialAsync` | `static Task<byte[]> EnvelopeCredentialAsync(ReadOnlyMemory<byte> credentialJson, NetCrypto.ISigner signer, CoseAlgorithm algorithm, ReadOnlyMemory<byte>? keyId = null, CancellationToken ct = default)` | **async**, returns tagged COSE_Sign1 bytes. Pins (protected) `content-type=application/vc` (label 3) + `typ=application/vc+cose` (label 16). Throws `CoseException` on non-JSON-object payload or alg/key mismatch. `keyId` is **bytes**, emitted unprotected (label 4). |
| `VcCose.Verify` | `static CoseSign1VerificationResult Verify(ReadOnlyMemory<byte> envelope, NetCrypto.KeyType keyType, ReadOnlyMemory<byte> publicKey)` | **SYNCHRONOUS, RESULT-style, never throws on bad sig.** Asserts both protected headers (→ `InvalidType`/`InvalidContentType`). Key is **raw public-key bytes + KeyType** (no Jwk, no resolver). |
| `CoseSign1.Decode` | `static CoseSign1Message Decode(ReadOnlyMemory<byte> encodedMessage)` | **Public decode-without-verify.** Read `KeyId`/`Payload`/`Algorithm`/`Type`/`ContentType` before verifying. Throws `CoseException` on malformed CBOR. |
| `CoseSign1Message` | `.KeyId:ReadOnlyMemory<byte>?`, `.Payload:ReadOnlyMemory<byte>?`, `.Algorithm:CoseAlgorithm?`, `.ContentType:string?`, `.Type:string?` | The decoded message. |
| `CoseAlgorithm` | `enum { EdDsa=-8, ES256=-7, ES384=-35, ES256K=-47 }` | **No public KeyType→CoseAlgorithm helper** — M3 maps it. Note casing `EdDsa`. No ES512/P-521. |
| `CoseSign1VerificationResult` | `{ bool Verified; CoseVerificationFailure? Failure; CoseSign1Message? Message }` | Success flag is `Verified` (not `IsValid`). Inner bytes at `Message.Payload`. |
| `CoseVerificationFailure` | `{ CoseVerificationErrorCode Code; string Message }` | Map `Code` to a neutral code. |
| `CoseVerificationErrorCode` | `…InvalidSignature=8, InvalidContentType=9, InvalidType=10, MalformedMessage=0, AlgorithmKeyMismatch=5, …` | All map to Invalid (Failed). |
| `CoseException` | sealed `: Exception` | Thrown only on issue/decode paths, **not** on `Verify`. Catch on issue + the M3 decode step. |
| Constants | `VcCose.CredentialContentType="application/vc"`, `EnvelopeType="application/vc+cose"` | Per-form (note: full media types, unlike JOSE's bare `vc`/`vc+jwt`). |

### Key-resolution shape difference (the load-bearing asymmetry)
JOSE verify wants a **`Jwk`** (via `Func<string,Jwk?>`); COSE verify wants **`(NetCrypto.KeyType, raw publicKey bytes)`**. One DID resolution must yield both. The neutral resolver returns NetCrypto key material; the JOSE mechanism converts to `Jwk` via `JwkConversion.ToPublicJwk`, the COSE mechanism uses it directly.

### NFR-002 closure (manifest-level, re-verified empirically at impl)
`Jose → DataProofsDotnet.Core` only; `Cose → DataProofsDotnet.Core + System.Formats.Cbor` (BCL). No Newtonsoft/dotNetRDF in either manifest. `Microsoft.IdentityModel.Tokens` is already in the closure via NetCrypto (M1), STJ-native. **Gate:** run `dotnet list … --include-transitive` after adding the references; fail the plan if Newtonsoft appears in the default closure.

---

## 2. Design decisions (resolving the recon's open questions)

1. **Verifier proof path branches on `credential.Securing`, not on `HasEmbeddedProof`.** There is no `DataIntegrityProofStage` class to mirror; the proof check is private methods on `DefaultVerifier`. M3 turns `CheckProofAsync` into a switch over `Securing` (`DataIntegrity` → DI mechanism (unchanged); `Jose`/`Cose` → enveloping mechanisms; `Unsecured` → `NoProof`). Structure/validity/status/schema/trust stages are unchanged and run over the **inner** credential document.

2. **Enveloped input enters through the Verifier's `ReadOnlyMemory<byte>` overload** (there is no `IHolder`/`IngestCompact` — that's M6). A new internal `EnvelopeDetector` classifies the bytes (JSON object → existing `Credential.Parse`; compact JWS → JOSE; COSE_Sign1 CBOR → COSE) **before** `CredentialDocument.Parse` (which throws on non-object). Decode failure on a detected envelope → `CredentialFormatException` (the overload's existing malformed-input contract). A *decodable* envelope with a *bad signature* → a `Failed` result (never thrown).

3. **The enveloped `Credential` carries the inner document + the verbatim envelope.** New internal factory `Credential.FromEnvelope(CredentialDocument inner, SecuringState form, ReadOnlyMemory<byte> envelope)`. The inner document is `CredentialDocument.Parse(decodedPayloadBytes)` (origin `ReceivedBytes`, byte-verbatim → `AsUtf8()` == the signed payload). Projections (issuer, validFrom, …) read the inner document as today. New public `string? CompactEnvelope` (the compact JWS for JOSE; `null` otherwise — forward-compat for M6 VP embedding) + new internal `ReadOnlyMemory<byte> EnvelopeBytes` (read by the proof stage; works for both forms).

4. **Issuer binding reuses the existing `BindIssuer` unchanged.** Each enveloping mechanism returns `SecuringVerificationResult.Verified([kid])` where `kid` is the signer's verification-method DID URL (JOSE protected-header `kid`; COSE `Message.KeyId` as UTF-8). `BindIssuer` then requires `BaseDid(kid) == inner.issuer.id`. **Security:** the signature is verified against the key the resolver fetches for `kid`; to claim `issuer=victim` an attacker must sign under a `kid` whose base DID is the victim's, which requires the victim's key. The COSE `kid` being *unprotected* does not weaken this — `kid` is used only to *look up* a key, never trusted for authorization; the bind requires the resolved key's DID to equal the signed-payload issuer. **A missing/empty `kid` fails closed** (definitive `Invalid` → `Failed`: an enveloped credential we cannot bind to an issuer is rejected, not Indeterminate).

5. **F7 report-don't-throw, per form (a bad signature is ALWAYS `Failed`, never `Indeterminate`):**
   - **Resolve the key async *outside* the substrate verify call first.** Resolver returns `null`/unresolvable (DID/IO failure) → `SecuringVerificationResult.Unresolvable` → **Indeterminate**. This is the F7 fix — DID resolution failure must not be conflated with a crypto failure.
   - **JOSE:** the mechanism catches `MalformedJoseException` (wrong/absent typ/cty or structural) → `Invalid` (structural code) → **Failed**; `JoseCryptoException` (bad signature) → `Invalid` (crypto code) → **Failed**. Neither bubbles past `DefaultVerifier`'s `RunProofAsync` boundary.
   - **COSE:** result-style — `Verified==false` → map `Failure.Code` → `Invalid` → **Failed**. `CoseException` on the decode step → `Invalid` (defensive).

6. **Sign/verify over exact bytes, never re-serialize.** Issue signs `credential.AsUtf8()` (serialize-once-pinned/verbatim bytes), never `AsElement()`→reserialize. Verify hands back the verbatim compact string (JOSE) / wire bytes (COSE). The inner credential keeps its own verbatim bytes (`ReceivedBytes`). Golden-bytes test: signed payload == inner `AsUtf8()` == wire.

7. **typ/cty (G1) come for free on verify** — both packages pin the headers in the protected bucket on envelope and assert them on verify (`MalformedJoseException` for JOSE; `InvalidType`/`InvalidContentType` for COSE). M3 adds **no manual header assertion** but **tests all four wrong/absent permutations per form** as negatives (mapped to `Failed`, not Indeterminate). M3 must use `VcCose.Verify` (not the lower-level `CoseSign1.Verify`, which skips the VC header checks).

8. **The neutral resolver is renamed from the master plan's `IIssuerJwkResolver` to `IEnvelopeKeyResolver`** because COSE needs raw key + KeyType, not a `Jwk`. It returns NetCrypto key material and mirrors `NetDidVerificationMethodResolver`; the DataProofs key-decoding stays in `Credentials.Resolution`, so the two enveloping mechanisms import **only** their own `.Jose`/`.Cose` package (clean FR-050).

9. **COSE algorithm is derived from `Signer.KeyType`, not exposed.** `CoseEnvelopeIssuanceRequest` carries only `ISigner` + `VerificationMethod` (draft-free, NFR-005). The mechanism maps `KeyType→CoseAlgorithm` (Ed25519→EdDsa, P-256→ES256, P-384→ES384, secp256k1→ES256K) and **fails fast** (`NotSupportedException`) for an out-of-scope key (P-521/RSA) — mirroring `JwsSigner`'s own behaviour.

10. **Registration is unconditional** (always `IsAvailable`, like `DataIntegrityMechanism`) since `.Jose`/`.Cose` are now default-closure deps; reuses the existing `IDidResolver` fail-fast (the resolver needs it). No new fail-fast.

---

## 3. File-by-file changes

### New files — `src/Credentials.Core`
- `Securing/Internal/JoseEnvelopingMechanism.cs` — `ISecuringMechanism` (`Form=Jose`, `SuiteNames=[]`, `IsAvailable=true`). **Sole caller of `DataProofsDotnet.Jose`.**
  - `SecureAsync`: `new JwsSigner(request.Signer, request.VerificationMethod)`; `VcJose.EnvelopeCredentialAsync(request.Payload, signer, ct)` → `SecureOutcome.Jose(compact)`. Catch `MalformedJoseException`/`NotSupportedException` → surfaced as an issue error.
  - `VerifyAsync`: read `kid` from protected-header segment 0 (internal `CompactJws.ReadKid`); async-resolve via `IEnvelopeKeyResolver` (null → `Unresolvable`); `JwkConversion.ToPublicJwk(key.KeyType, key.PublicKey, kid)`; `VcJose.VerifyCredential(compact, _ => jwk, null)` inside try/catch (`MalformedJoseException`→structural `Invalid`; `JoseCryptoException`→crypto `Invalid`); success → `Verified([kid])`.
- `Securing/Internal/CoseEnvelopingMechanism.cs` — `ISecuringMechanism` (`Form=Cose`). **Sole caller of `DataProofsDotnet.Cose`.**
  - `SecureAsync`: map `Signer.KeyType→CoseAlgorithm` (fail-fast on unsupported); `VcCose.EnvelopeCredentialAsync(request.Payload, request.Signer, alg, keyId: UTF8(VerificationMethod), ct)` → `SecureOutcome.Cose(bytes)`. Catch `CoseException`.
  - `VerifyAsync`: `CoseSign1.Decode(envelope)` → `kid = UTF8(Message.KeyId)` (missing → `Invalid` fail-closed); async-resolve (null → `Unresolvable`); `VcCose.Verify(envelope, key.KeyType, key.PublicKey)`; `Verified` → `Verified([kid])`; else map `Failure.Code` → `Invalid`. Catch `CoseException` → `Invalid`.
- `Securing/Internal/EnvelopeDetector.cs` — internal `static SecuringForm? Detect(ReadOnlySpan<byte>)` + `static bool TryReadKid(...)` helpers; size-bounded (`CredentialDocument.MaxInputBytes`), overflow-safe. JSON-object → `null` (caller uses `Credential.Parse`); compact-JWS (ASCII, exactly two `.`, base64url segments) → `Jose`; CBOR tag-18 (`0xD2`) / 4-elem array (`0x84`) / tag prefix → `Cose`.
- `Securing/Internal/CompactJws.cs` — internal helper: split a compact JWS, base64url-decode a segment, read a header string member (`kid`/`typ`). No DataProofs dependency (pure base64url + STJ). Defensive/bounded parse.
- `Resolution/IEnvelopeKeyResolver.cs` — internal `interface IEnvelopeKeyResolver { Task<EnvelopeKey?> ResolveAsync(string kid, CancellationToken ct); }` + `internal readonly record struct EnvelopeKey(NetCrypto.KeyType KeyType, ReadOnlyMemory<byte> PublicKey)`.
- `Resolution/NetDidEnvelopeKeyResolver.cs` — internal impl; delegates to the injected `DataProofsDotnet.DataIntegrity.IVerificationMethodResolver` (reuse the DID-URL→VM→key logic already in `NetDidVerificationMethodResolver`) and maps `ResolvedVerificationMethod.PublicKey.{KeyType,KeyBytes}` → `EnvelopeKey`; resolution failure/`null` → `null`.

### Edited files — `src/Credentials.Core`
- `Securing/Internal/SecuringMessages.cs`:
  - `SecureRequest` += `ReadOnlyMemory<byte> Payload` (exact bytes; enveloping signs these). Relax `Cryptosuite`/`ProofPurpose`/`Created` to DI-only (nullable; DI sets them, enveloping leaves null). `Document` stays (DI uses it; enveloping ignores).
  - Replace `record SecureOutcome(JsonElement SecuredDocument)` with a small **discriminated** `SecureOutcome` carrying exactly one of `{JsonElement Document | string Jose | ReadOnlyMemory<byte> Cose}` + `SecuringForm Form`; factories `Document(...)`, `Jose(...)`, `Cose(...)`. (DI call site updated to `SecureOutcome.Document(...)`.)
  - `VerifyRequest` += `ReadOnlyMemory<byte>? Envelope` (the secured wire bytes; enveloping uses it, DI uses `Document`).
- `Credential.cs`: add internal `ReadOnlyMemory<byte> _envelope` + `SecuringForm`-derived state via `Securing`; new `internal static Credential FromEnvelope(CredentialDocument inner, SecuringState form, ReadOnlyMemory<byte> envelope)`; new `public string? CompactEnvelope` (JOSE compact string, else null) + `internal ReadOnlyMemory<byte> EnvelopeBytes`. `Securing` set to `Jose`/`Cose`. `HasEmbeddedProof` stays inner-doc-based (false for enveloped — intentional; proof dispatch now keys on `Securing`).
- `Roles/IssuanceRequest.cs`: add `public sealed record JoseEnvelopeIssuanceRequest : IssuanceRequest { required ISigner Signer; required string VerificationMethod; }` and `public sealed record CoseEnvelopeIssuanceRequest : IssuanceRequest { required ISigner Signer; required string VerificationMethod; }`.
- `Roles/IssuedCredential.cs`: add `string? CompactJws` + `ReadOnlyMemory<byte>? CoseBytes` accessors and `Jose(Credential enveloped, string compact)` / `Cose(Credential enveloped, ReadOnlyMemory<byte> bytes)` factories (media `application/vc+jwt` / `application/vc+cose`). `Credential` stays populated for all forms (the enveloped `Credential` for JOSE/COSE) — uniform + re-verifiable.
- `Roles/DefaultIssuer.cs`: add `JoseEnvelopeIssuanceRequest`/`CoseEnvelopeIssuanceRequest` cases — resolve mechanism by `SecuringForm.Jose`/`Cose`, build `SecureRequest{ Payload = credential.AsUtf8(), Signer, VerificationMethod }`, call `SecureAsync`, build the enveloped `Credential` via `Credential.FromEnvelope(credential.Document, …, outcome.Jose/Cose)` and the matching `IssuedCredential` factory.
- `Roles/DefaultVerifier.cs`:
  - `VerifyCredentialAsync(ReadOnlyMemory<byte>)`: size-bound; `EnvelopeDetector.Detect` → JSON → `Credential.Parse` (unchanged); JOSE → decode payload (base64url segment 1) → inner `CredentialDocument.Parse` → `Credential.FromEnvelope(…, Jose, bytes)`; COSE → `CoseSign1.Decode`… **no** — keep DataProofs out of `DefaultVerifier`: detection routes to an internal `EnvelopedCredentialFactory` that, for COSE, uses `CoseSign1.Decode` **inside the COSE mechanism's assembly area**. *(Refinement: the inner-payload extraction for ingest lives in the mechanisms' assembly via a small internal `IEnvelopeIngest` per form so `DefaultVerifier` imports no DataProofs type. JOSE ingest is pure base64url (no DataProofs); COSE ingest needs `CoseSign1.Decode`, so it lives beside `CoseEnvelopingMechanism`.)* Decode failure → `CredentialFormatException`.
  - `CheckProofAsync`: switch on `credential.Securing` — `DataIntegrity` → current DI path; `Jose`/`Cose` → `_registry.GetMechanism(SecuringForm.Jose/Cose)` with `VerifyRequest{ Envelope = credential.EnvelopeBytes, VerificationTime }`, map `Verified`→`BindIssuer`, `Invalid`→`Failed`, `Unresolvable`→`Indeterminate`, `NoProof`→`NoProof`; `Unsecured` → `NoProof`. `BindIssuer` unchanged.

### Edited files — `src/Credentials.Core/*.csproj` + DI
- `Credentials.Core.csproj`: add `<PackageReference Include="DataProofsDotnet.Jose" />` + `<PackageReference Include="DataProofsDotnet.Cose" />`.
- `src/Credentials.Extensions.DependencyInjection/CredentialsServiceCollectionExtensions.cs`: register `IEnvelopeKeyResolver → NetDidEnvelopeKeyResolver` (`TryAddSingleton`, over `IVerificationMethodResolver`); `TryAddEnumerable(ISecuringMechanism → JoseEnvelopingMechanism)` and `→ CoseEnvelopingMechanism` (over the resolver) — collected by `SecuringMechanismRegistry` automatically.
- `Securing/SecuringSelector.cs` (optional ergonomics): add `static SecuringSelector Jose()` / `Cose()` factories (draft-free).

---

## 4. Test plan (`tests/Credentials.Core.Tests` + `…DependencyInjection.Tests`)

House conventions: xUnit + FluentAssertions **7.0.0**, NSubstitute `.Returns(value)`. End-to-end issue→verify tests use the DI project's `TestKeys`/in-memory `did:key`.

**Round-trip (per form × per alg):** issue → verify `Accepted` for JOSE **EdDSA + ES256** and COSE **EdDsa + ES256** (Ed25519 + P-256 keys). Add ES384 if `TestKeys` provides a P-384 key; otherwise note the gap.
**Golden bytes / sign-exact:** signed payload == inner `AsUtf8()` == wire bytes; verify accepts the verbatim wire bytes; `<>&` + non-BMP-emoji credential round-trips and verifies (relaxed-escaping, H1).
**Detection/ingest:** verifier bytes overload routes JSON-object / compact-JWS / COSE correctly; undecodable envelope → `CredentialFormatException`; size bound enforced; truncated/garbage compact and CBOR → `CredentialFormatException` (ingest) or `Failed` (decodable-but-bad).
**Negative — signature:** post-sign tamper of the JWS signature segment / a COSE byte → `Rejected` (proof `Failed`), **not** Indeterminate (F7). COSE bad-sig is a `Verified==false` result; JOSE bad-sig is a caught `JoseCryptoException`.
**Negative — typ/cty (G1, all four permutations per form):** wrong/absent `typ`; wrong/absent `cty`/content-type → `Failed` (structural). Built by hand-crafting an envelope with the wrong header (via the generic `JwsBuilder`/`CoseSign1.SignAsync` with mismatched headers, behind the test, or by byte-editing).
**Negative — issuer binding (the load-bearing security test, both forms):**
  - *post-sign mismatch:* a validly enveloped credential whose `kid` base DID ≠ inner `issuer` → `Rejected` (`issuer_binding`).
  - *self-consistent forgery:* attacker signs a credential with `issuer = victimDID` using the **attacker's** key + `kid = attacker's VM` → `Rejected` (binding mismatch), and using `kid = victim's VM` → `Rejected` (signature fails / resolver returns victim's key). Covers the CLAUDE.md "self-consistent forged document" requirement.
  - *missing kid:* enveloped credential with no `kid` → `Rejected` (fail-closed), not Indeterminate.
**Indeterminate vs Failed (F7):** DID resolution failure (resolver throws / returns null) → proof `Indeterminate` (so the credential is Indeterminate under strict policy), while a bad signature → `Failed`. Asserts the two are not conflated.
**Unsupported alg fail-fast:** issuing JOSE/COSE with a P-521/unsupported `ISigner` → `NotSupportedException` at issue (not a silent mis-sign).
**NFR-005 surface confinement:** a reflection test asserting no `DataProofsDotnet.Jose.*` / `DataProofsDotnet.Cose.*` type (`Jwk`, `JwsSigner`, `CoseAlgorithm`, `CoseSign1VerificationResult`, `IJoseCryptoProvider`, `VcJose`, `VcCose`) appears on any public credentials-dotnet signature (extends/adds the F3 `PublicSurface_ExposesNoDataProofsDraftType`).
**DI:** `AddCredentials` registers Jose+Cose mechanisms; `ISecuringCapabilities.AvailableForms` contains `Jose`+`Cose`; `IsSupported(SecuringSelector.Jose()/Cose())` is true.

---

## 5. Build / verify / done

1. `dotnet build -c Release` clean (0 warnings — `TreatWarningsAsErrors`, XML-doc gate).
2. `dotnet test` — all existing (168) + new M3 tests green.
3. **NFR-002 gate:** `dotnet list src/Credentials.Core/Credentials.Core.csproj package --include-transitive` — assert no `Newtonsoft.Json` / `dotNetRDF` in the default closure after adding `.Jose`/`.Cose`.
4. **Adversarial pass (mandatory, CLAUDE.md):** 2–3 read-only general-purpose agents (a Workflow fan-out) attacking different surfaces — (a) issuer-binding/forgery on both enveloping forms, (b) F7/Indeterminate-vs-Failed + envelope-detection/decode confusion + size/overflow, (c) NFR-002/NFR-005 leakage + sign-exact-bytes/round-trip fidelity. Confirm-by-running, no repo edits. Fix every valid finding with a regression test.
5. Update `CHANGELOG.md` (M3 entry) and `tasks/lessons.md` (any new lesson). Append an M3 review section to this file.
6. `gh pr create` (base `main`, head `feature/m3-enveloping`), then address valid review comments, mapping each finding → fix in a PR comment.

**DoD (§9 contributions):** FR-012 both serializations issue→verify; G1 typ/cty pinned+asserted (all four permutations tested); F7 bad-sig→Failed / resolver-IO→Indeterminate; sign-exact-bytes round-trip (golden bytes); issuer binding for enveloping (post-sign + self-consistent-forgery); NFR-002 closure clean; NFR-005 no draft type on the surface.

---

## 6. Risks & out-of-scope

- **Enveloped VP / `EnvelopedVerifiableCredential` (data: URI wrapper) is M6, not M3.** `ContainedCredential.Enveloped(string)` is string-only and cannot carry binary COSE; M6 must add a form discriminator + the `data:application/vc+jwt,…` / `data:application/vc+cose;base64,…` representation. M3 records the form on the enveloped `Credential` (`Securing` + `CompactEnvelope`/`EnvelopeBytes`) so M6 can build it. Flagged, not fixed here.
- **No `vp+jwt` helper in DataProofs** — VP enveloping (FR-034) would use the generic `JwsBuilder.BuildCompactAsync(typ:vp+jwt)`; deferred to M6.
- **COSE `kid` is unprotected & advisory.** Mitigated by the lookup-then-bind model (§2.4) — never trusted for authorization. Covered by the issuer-binding tests.
- **`CoseException` extends `System.Exception` directly** (not yet a DataProofs base type). Catch by concrete type; pin to 1.0.1 behavior.
- **Seam churn:** widening `SecureRequest`/`SecureOutcome`/`VerifyRequest` touches `DataIntegrityMechanism`'s call sites (internal only; no public API change). The DI mechanism keeps using `Document`/`Cryptosuite`.

---

## 7. Review (2026-06-20)

**Status: complete and green.** Clean Release build (0 warnings, `TreatWarningsAsErrors`), **201 tests
pass** (120 `Credentials.Core.Tests` + 77 `Credentials.Extensions.DependencyInjection.Tests` + 4
`Credentials.Rdfc.Tests`); 22 new M3 tests.

**Delivered (as planned, §3):** `Jose`/`CoseEnvelopingMechanism` (each the sole caller of its DataProofs
package); `IEnvelopeKeyResolver` + `NetDidEnvelopeKeyResolver`; `EnvelopeDetector` + `CompactJws`; the seam
extension (`SecureRequest.Payload`, discriminated `SecureOutcome`, `VerifyRequest.Envelope`/`ExpectedPayload`);
`Credential.FromEnvelope`/`CompactEnvelope`/`EnvelopeBytes`; `IssuedCredential.Jose`/`Cose`;
`Jose`/`CoseEnvelopeIssuanceRequest`; `SecuringSelector.Jose()`/`Cose()`; verifier proof-path branch on
`Securing` + envelope ingest on the bytes overload; DI registration. FR-012 satisfied for both
serializations; G1 (typ/cty) pinned+asserted by the substrate + tested; F7 mapping per form; sign-exact-bytes
round-trip; issuer binding reused from M1.

**Deviations from the plan (deliberate, documented):**
1. **`IIssuerJwkResolver` → `IEnvelopeKeyResolver`** (neutral NetCrypto key material, not a `Jwk`): COSE
   verify needs a raw key + `KeyType`, JOSE needs a `Jwk`; one DID resolution serves both. The JOSE path
   builds the `Jwk` via `JwkConversion.FromMultikey` (the substrate handles EC point encoding) rather than
   from raw bytes.
2. **No `*ProofStage` classes** (none existed to mirror): the proof check branches inside
   `DefaultVerifier.CheckProofAsync` on `credential.Securing`.
3. **Envelope ingest lives behind the mechanisms** (`IEnvelopeIngest`), not a Holder (`IngestCompact` is
   M6): `DefaultVerifier` imports no JOSE/COSE type.
4. **Added a payload-integrity guard** (`ExpectedPayload` on `VerifyRequest` → `envelope_payload_mismatch`)
   beyond the plan, from the adversarial review (see below).

**Corrections to the plan's recon (verified against `PublicAPI.Unshipped.txt`):** all folded into §1 —
`VcJose.VerifyCredential` is synchronous + throw-based with a 3rd `IJoseCryptoProvider?` arg and a *nullable*
`Jwk` resolver; `VcCose.Verify` takes a raw key + `KeyType` (no resolver) and is result-style;
`CoseSign1.Decode` is public (used to read the COSE `kid` before verify); `CoseAlgorithm.EdDsa` casing; no
public `KeyType→CoseAlgorithm` helper; no VP `vp+jwt` path (correctly M6).

**Adversarial review (2026-06-20).** Three agents attacked forgery/binding, F7/detection/DoS, and
payload-substitution/surface-leakage by compiling and running 127 exploit tests. **Zero exploitable
findings.** Every forgery (incl. the unprotected-COSE-`kid` rewrite and the self-consistent forgery under the
victim's `kid`) is Rejected; bad-sig stays `Failed` under a non-strict policy; payload-substitution is
impossible (ingest decode == substrate-verified payload == inner `AsUtf8`); the size bound precedes any
decode; NFR-005 surface and NFR-002 closure are clean. **Hardening folded in:** the sign-exact-bytes
invariant is now self-enforcing (`envelope_payload_mismatch`) instead of emergent from substrate-decoder
behaviour, with JOSE+COSE regression tests.

**Out of scope (M6 follow-ups, flagged):** enveloped VP (`vp+jwt`) and the `EnvelopedVerifiableCredential`
`data:`-URI wrapper (`ContainedCredential.Enveloped` is string-only — cannot carry binary COSE); the
form is recorded on the enveloped `Credential` so M6 can build it.
