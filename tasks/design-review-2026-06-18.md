# credentials-dotnet — Design Review Artifacts

Raw outputs from the design workflow's Verify phase (completeness critic, adversarial boundary review, conformance review). The implementation plan in `todo-2026-06-18-credentials-dotnet-implementation.md` already folds these fixes in; kept here for traceability.

**Date:** 2026-06-18

---

## 1. Completeness critic — FR/NFR coverage

**Summary:** All 37 functional requirements present in the PRD (FR-001..005, 010..016, 020..022, 030..034, 040..045, 050..053, 070, 080..082) and all 9 NFRs are addressed across the seven subsystem designs plus the chosen core model. Coverage is strong and largely full: the document-centric core (FR-003/004) with faithful-not-canonical serialization, the securing seam that makes FR-050/051/053 structural (suites as opaque strings, draft types confined to single mechanisms), the report-don't-throw verifier (FR-045 via SafeRun), the three-state structured results (FR-043), and the DI-injected hooks with the structured IIssuerTrustPolicy (FR-081/082, resolving OQ-1) are all rigorous and well-grounded against the verified dataproofs-dotnet/net-did surfaces. Exactly one requirement is genuinely partial: FR-015 — bbs-2023 base issuance needs a raw BLS12-381-G2 private key exported from the key store (ExportBbsPrivateKeyAsync), which conflicts with 'MUST NOT handle raw private key material directly' (and NFR-006). The design contains this to one securer and flags it as an unresolved implementer open item, but it is a real conflict that must be resolved before implementation. Minor, non-blocking notes: FR-052/Holder/BBS use BCL RandomNumberGenerator rather than a crypto-dotnet RNG helper (designs note none exists), and OQ-2 (process to bump past SD-JWT draft-16) is acknowledged but not procedurally specified. NFRs covered: NFR-001 (net10/latest C#), NFR-002 (STJ-only + JsonSchema.Net + explicit no-Newtonsoft closure CI gate), NFR-003 (frozen-by-default immutability + stateless singletons), NFR-004 (async I/O, ValueTask/Task throughout), NFR-005 (semver gate via ApiCompat + no draft types), NFR-006 (partial — same raw-key tension as FR-015), NFR-007 (conformance harness designed, unproven), NFR-008 (per-check secret-free diagnostics), NFR-009 (XML-doc CS1591-as-error gate).

**Critical gaps (2):**

- FR-015 (raw key material): bbs-2023 base issuance requires exporting a raw BLS12-381-G2 private key from net-did's IKeyStore (Bbs2023Securer.ExportBbsPrivateKeyAsync / Bbs2023Mechanism), which directly contradicts FR-015's 'MUST NOT handle raw private key material directly' and NFR-006 'MUST NOT expose private key material'. The designs acknowledge this as a bounded, isolated exception (no public-API leakage, encapsulated in one securer) because dataproofs-dotnet offers no ISigner-shaped BBS signer. It must be resolved before implementation: confirm net-did exposes an exportable-key path that satisfies security review, OR defer FR-014/FR-031 until dataproofs-dotnet ships a BBS signer abstraction. This is the single hard FR conflict in the design.
- NFR-007 (conformance) is design-claimed but unproven: the W3C VCDM 2.0 conformance suite and bbs-2023/SD-JWT interop vectors are wired in the testing design (VC-API shim + vendored vectors), but actual pass/fail cannot be assessed from the design alone and bbs vectors are skip-gated on native availability — acceptance risk to track, not a design omission.

**Coverage tally:** partial=1, yes=33 (of 34 requirements)

| Requirement | Covered | Where | Note |
|---|---|---|---|
| FR-001 | yes | Core model §3 Credential (Context/Type/Issuer/CredentialSubjects/ValidFrom/ValidUntil/CredentialStatus/CredentialSchema + GetMember escape hatch); Builder §5 AddSubject promotes to array; CredentialContent §1 (issuer) design | All standard members projected; multi-subject (object/array) supported; arbitrary claim shapes carried verbatim via JsonObject + GetMember. termsOfUse/evidence handled via GetMember/SetMember/AdditionalMembers, not first-class typed accessors but FR-001 only requires representation, which is satisfied. |
| FR-002 | yes | Core model §4 VerifiablePresentation (Type/Holder/VerifiableCredentials) + ContainedCredential union (Embedded/Enveloped); Holder design §5 BuildPresentation | VP type, holder, verifiableCredential all modeled; form-faithful containment preserves embedded vs enveloped children. |
| FR-003 | yes | Core model §1 CredentialDocument (verbatim bytes for ReceivedBytes, serialize-once for Built, ToBytes round-trip); RoundTripTests §3 byte-perfect assertions | Document-centric core preserves structure; lossless round-trip is explicit DoD test. Strong coverage. |
| FR-004 | yes | Core model §3 Credential lazy-memoized projections over frozen document; §5 Builder write-through to JsonObject | Typed model is pure projection over the single JsonObject source of truth, so typed view cannot drift from document by construction. |
| FR-005 | yes | Core model §7 StructuralValidator (context present/ordering, base type, required members, version-mix, structured StructuralProblem with code+JsonPointer); Builder.Seal() invokes it | @context inclusion/ordering, base type, required members, structured errors all covered. Version-aware (D8). |
| FR-010 | yes | Issuer design §0/§1 BuildCredential(CredentialContent) → builder → Seal(); CredentialContent carries claims, subjects, validity, status, schema refs | All caller-supplied inputs (claims, subject(s), validity, optional status, optional schema) projected onto builder. |
| FR-011 | yes | Issuer design §3 DataIntegrityRequest + DataIntegritySecurer → pipeline.AddProofAsync with caller-named suite; securing-seam §3.1 DataIntegrityMechanism | EdDSA/ECDSA JCS+RDFC by caller-selected suite name; bbs-2023 handled separately (§4). Suite is data, not a method. |
| FR-012 | yes | Issuer design §5 JoseEnvelopeRequest/CoseEnvelopeRequest → VcJose/VcCose.EnvelopeCredentialAsync, both serializations; securing-seam §3.3 | Both JOSE and COSE serializations produced over exact bytes (AsUtf8). |
| FR-013 | yes | Issuer design §5c SdJwtVcRequest + SdJwtVcSecurer → SdJwtVcIssuer.IssueAsync; vct, path-selected disclosures, optional cnf holder binding | application/dc+sd-jwt, selectable claims by path, optional holder key-binding via cnf. No draft types on public surface. |
| FR-014 | yes | Issuer design §4 Bbs2023BaseRequest + Bbs2023Securer → CreateBaseProofAsync with mandatory pointers | bbs-2023 base credential supporting later holder derivation. Note bounded raw-key exception documented (see FR-015). |
| FR-015 | partial | Issuer design §3/§5 signing via ISigner/JwsSigner from net-did; §4 Bbs2023Securer ExportBbsPrivateKeyAsync exception | Mostly satisfied: all DI/JOSE/COSE/SD-JWT sign via ISigner. BUT bbs-2023 base issuance requires exporting a raw BLS12-381-G2 private key from IKeyStore (ExportBbsPrivateKeyAsync), which literally handles raw private key material — a direct tension with FR-015 'MUST NOT handle raw private key material directly'. Design flags it as a bounded, documented exception with no public-API leakage, and the export path is an unresolved implementer open item. Real partial gap. |
| FR-016 | yes | Issuer design §6 BitstringStatusListEntry.Create → CredentialContent.CredentialStatus; status-and-schema §1.2/§1.3 StatusListManager.CreateEntry | credentialStatus referencing a Bitstring Status List entry; statusListIndex emitted as string per spec. |
| FR-020 | yes | Status-and-schema §1.1 StatusBitstring + §1.3 StatusListManager.Create/ProduceCredentialDocument (revocation + suspension purposes) | Bitstring Status List v1.0 credential production for revocation and suspension; 16KiB minimum, multibase(u)+GZIP encoding. |
| FR-021 | yes | Status-and-schema §1.3 StatusListManager SetStatus/ClearStatus/SetMessageValue + FromCredentialDocument + ProduceCredentialDocument | set/clear/update (revoke/suspend/reinstate) and re-produce the list credential; resume-from-existing supported. |
| FR-022 | yes | Status-and-schema §1.4 IStatusListResolver hook + StatusListVerifier.CheckAllAsync; verifier §5.6 StatusStage (recursive list-VC proof verify, bit math, purpose match) | Caller fetch hook, list-VC's own proof verified (delegated), decode + bit read, structured StatusCheckResult composed into verification. |
| FR-030 | yes | Holder design §1/§2 IHolder.Ingest/IngestCompact + HeldCredential read-only projections (Claims/Validity/Status/Schema); InspectSdJwt/InspectBbsBase | Ingest+inspect all 3 forms with read-only projections over frozen document core; explicit no-mutation invariant. |
| FR-031 | yes | Holder design §3 DeriveBbsDisclosure → Bbs2023Cryptosuite.DeriveProof with selective pointers + presentation header | Unlinkable minimal-disclosure derivation from bbs-2023 base; mandatory group cryptographically enforced; multiple unlinkable derivations supported. |
| FR-032 | yes | Holder design §4 PresentSdJwtAsync → SdJwtHolder.CreatePresentationWithKeyBindingAsync (chosen disclosures + KB-JWT, aud+nonce) | SD-JWT VC presentation revealing chosen disclosures with Key Binding JWT bound to audience/nonce. |
| FR-033 | yes | Holder design §5 BuildPresentation/VpAssemblyRequest → VerifiablePresentation.Build with AddEmbeddedCredential/AddEnvelopedCredential | VP built from one or more credentials, form-faithful containment. |
| FR-034 | yes | Holder design §6 BindWithDataIntegrityAsync (authentication proof, challenge/domain) and BindWithJoseEnvelopeAsync; SD-JWT KB-JWT in §4; holder key via net-did §7 | Holder binding via VP DI proof or KB-JWT; key obtained through net-did ISigner. |
| FR-040 | yes | Verifier design §4 orchestration pipeline + §5 stages (proof/structure/validity-with-skew/status/schema/trust); securing-seam §5.3 | End-to-end credential verify: proof (delegated), validity window with configurable ClockSkew, schema, status, issuer-trust. Stage order authorizes issuer before trust/status. |
| FR-041 | yes | Verifier design §7 PresentationOrchestrator (VP structure, holder binding/presentation proof, each contained credential recursively, KB cross-binding) | Each contained credential, holder binding, and presentation proof all verified; enveloped children verified verbatim, embedded via element. |
| FR-042 | yes | Verifier design §5.1 DataIntegrityProofStage (auto-dispatch to Bbs2023 VerifyProof), §5.3 SdJwtVcProofStage (disclosures + KB-JWT); rides ordinary credential path | bbs-2023 derived proofs and SD-JWT disclosures+KB-JWT verified through the standard path; no draft type on surface. |
| FR-043 | yes | Verifier design §1 CredentialVerificationResult/PresentationVerificationResult/CheckOutcome (decision + per-check + reasons); hooks-and-results §1 CheckResult/VerificationResult | Structured result with overall decision (three-state) plus per-check outcomes and human-readable reasons. Strong. |
| FR-044 | yes | Verifier design §4 VersionProjection.Detect + AcceptVcdm11 option + version-aware StructuralValidator/ValidityProjection; core StructuralValidator §7 version-mix; hooks CredentialsOptions AcceptVcdm11OnVerify | VCDM 1.1 accepted on verify (issuanceDate/expirationDate fallback), issuance stays 2.0 only; mixed property sets rejected (D8). |
| FR-045 | yes | Verifier design §6 SafeRun boundary (operational exceptions → Indeterminate; only malformed-input/programming errors throw); side-effect-free stages; hooks IssuerTrustStep degrades throwing policy to Indeterminate | Report-don't-throw made structural via SafeRun wrapper; side-effect-free; exceptions reserved for malformed input/programming errors. Strong. |
| FR-050 | yes | Securing-seam §2/§3 ISecuringMechanism is sole dataproofs caller; every proof/canon op delegated; Verifier proof stages call dataproofs; core does no canonicalization | All proof creation/verification and canonicalization delegated to dataproofs-dotnet; mechanisms hold no proof/canon logic. CredentialJson.Faithful is faithful-not-canonical. |
| FR-051 | yes | Securing-seam §3.4 SdJwtVcMechanism confines DisclosureFrame/SdJwtIssuerOptions/Jwk; Issuer §5c DisclosureSelector/HolderBindingKey/SdHashName draft-free; NFR-005 throughout | SD-JWT VC targets draft-16, reached only through role API; no draft types on public surface. Note OQ-2 (process for bumping past draft-16) is acknowledged but not fully specified — see gap note, minor. |
| FR-052 | yes | Securing-seam §3.4/§6 NetCrypto JwkConversion + RNG for HMAC/salts/decoy; status-and-schema §2.4 Sha256SchemaIntegrityChecker uses NetCrypto.Hash; Holder presentation-header randomness | Engine-own crypto (digests via NetCrypto.Hash, holder-binding JWK, decoy/salt requests) via crypto-dotnet. Note: HMAC/presentation-header RNG uses BCL RandomNumberGenerator in places, not a NetCrypto RNG helper — a minor inconsistency the designs themselves flag (no NetCrypto RNG helper exists), but salts/digests proper are delegated. |
| FR-053 | yes | Securing-seam §4 SecuringMechanismRegistry keyed on opaque suite strings + shared CryptosuiteRegistry; §7 ISecuringCapabilities discovery; Verifier DefaultPlanner; Issuer ICredentialSecurer TryAddEnumerable | New suite (ecdsa-sd-2023) = registration only, no public API change; suites are runtime-discovered strings, never enums. Explicit extension table provided. Strong. |
| FR-070 | yes | Status-and-schema §2 ICredentialSchemaValidator + SchemaValidatorRegistry (SHACL-ready seam) + JsonSchema2020Validator (JsonSchema.Net, JsonSchema + JsonSchemaCredential, digestSRI, tri-state); hooks-and-results §3 ICredentialSchemaResolver with SchemaDialect | JSON Schema 2020-12 via caller resolver hook; digestSRI enforced before evaluate; tri-state result; validation seam (registry + ResolvedSchema/SchemaDialect) explicitly admits SHACL without API break (D9). |
| FR-080 | yes | Verifier §3 NetDidVerificationMethodResolver adapter; Issuer §3/§5 ISigner from net-did IKeyStore; Holder §7 IHolderKeyResolver/IKeyStore; solution-layout §9 UseNetDid wiring + fail-fast | Issuer/holder/subject DID and VM resolution via net-did; signer/key-store abstractions for signing; pluggable key stores. Fail-fast if resolver/VM-resolver absent. |
| FR-081 | yes | Hooks-and-results §2/§3/§4 IIssuerTrustPolicy/ICredentialSchemaResolver/IStatusListFetcher injected via DI; §6 CredentialsBuilder UseXxx; solution-layout §9 AddCredentials fail-fast on missing hooks | All three caller hooks (issuer trust, schema resolution, status fetch) DI-injected, never hard-wired. |
| FR-082 | yes | Hooks-and-results §2 IIssuerTrustPolicy (IssuerTrustResult decision+reason, tri-state) + IssuerTrustStep (explicit optional, Skipped when absent); sample AllowlistIssuerTrustPolicy in samples/ not library | Trust policy is explicit optional verifier step, returns structured decision+reason (never bare bool); no built-in lists ship; single allowlist sample provided. Resolves OQ-1. Strong. |

---

## 2. Adversarial boundary review

I now have the source-of-truth. Let me attack the design systematically against each of the eight hunt targets.

# ADVERSARIAL BOUNDARY REVIEW — credentials-dotnet design

I read the PRD, concept, and architectural-path as source of truth and attacked the design on all eight axes. Findings are ordered by severity. Each cites the exact design location and a concrete fix.

---

## CRITICAL — Hard boundary violations

### F1 — (FR-050) Core re-implements proof/canonicalization-adjacent serialization with a hand-pinned options copy that WILL diverge from the dependency, breaking signatures

**Location:** Core Model §1.1 `CredentialJson.Faithful` and its justification ("It MUST byte-mirror `DataProofsDotnet.DataProofsJsonOptions.Default`"), reused everywhere a built/secured doc is re-ingested (Issuer §3, §4, §5c; Securing-seam §3.1; Holder §6; Verifier status recursion).

**Why it violates the boundary:** FR-050 says the library "MUST delegate all proof creation and verification, and **all canonicalization**, to dataproofs-dotnet; it MUST NOT implement proof or canonicalization logic itself." `CredentialJson.Faithful` is a **manually maintained copy** of `DataProofsJsonOptions.Default` (`UnsafeRelaxedJsonEscaping` + `WhenWritingNull` + `PropertyNamingPolicy=null`). The design itself admits "any divergence in escaping, null-handling, or naming silently breaks JCS/enveloping signatures." That is the core owning a piece of the serialization contract that determines signed bytes — exactly the canonicalization-adjacent logic FR-050 forbids duplicating. When dataproofs bumps `DataProofsJsonOptions.Default` (e.g. adds a converter, changes escaping), the hand-copy silently desynchronizes and every built credential's sign-bytes diverge from wire-bytes.

**Concrete fix:** Do not redeclare the options. Consume `DataProofsDotnet.DataProofsJsonOptions.Default` **directly** as the serializer for any re-ingest/serialize path, or have dataproofs expose a `SerializeFaithful(JsonNode)` helper and call it. If a separate `JsonSerializerOptions` instance is unavoidable for STJ identity reasons, derive it from the dependency's instance at runtime (copy-construct from `DataProofsJsonOptions.Default`) and add a startup assertion test that serializes a fixture through both and asserts byte-equality, failing CI on drift. The "golden-bytes" test in Testing §3 is necessary but not sufficient — it only catches drift for the one fixture, not the general contract.

---

### F2 — (FR-050 / FR-015 / NFR-006) The BBS issuance path exports a raw private key and the core attaches the proof itself — a double boundary breach

**Location:** Issuer §4 `Bbs2023Securer.SecureAsync` (`ExportBbsPrivateKeyAsync`, `securedNode["proof"] = JsonSerializer.SerializeToNode(baseProof, …)`); Securing-seam §3.2 `Bbs2023Mechanism.SecureAsync` (same `securedNode["proof"] = …`).

**Why it violates the boundary — two distinct breaches:**

1. **Raw private-key handling (FR-015, NFR-006).** FR-015: the Issuer "MUST sign using an issuer key obtained through net-did's signer abstraction; it MUST NOT handle raw private key material directly." NFR-006: "the library MUST NOT expose private key material." The design routes a 32-byte BLS private key through `ExportBbsPrivateKeyAsync` into `credentials-dotnet` code. The design tries to excuse this ("the one documented exception… because dataproofs offers no ISigner-shaped BBS signer"), but **the requirement has no exception clause**, and the architectural-path is explicit (§6.1, §7-D2) that the BBS primitive lives in NetCrypto behind `IBbsCryptoProvider` and "BBS-specific types must not leak upward." The correct home for the raw-key BBS call is **inside dataproofs/NetCrypto**, not credentials-dotnet. credentials-dotnet exporting and holding the private key is precisely the leak NFR-006 forbids.

2. **Core attaches `proof` itself (FR-050 + the design's own central invariant).** The chosen core model's load-bearing claim is "the core hands dataproofs the **whole** secured `JsonElement`; it does **not** strip/attach `proof` itself." But `Bbs2023Securer`/`Bbs2023Mechanism` does `securedNode["proof"] = JsonSerializer.SerializeToNode(baseProof, …)` — credentials-dotnet is **constructing the secured document by hand-attaching the proof member**. That is proof-assembly logic in the core, contradicting both FR-050 and the design's own §6 discipline table (which says for DI the core only hands over `AsElement()` and dataproofs owns proof placement). The non-BBS `DataIntegrityMechanism` correctly uses `AddProofAsync` which returns the assembled document; the BBS path diverges and hand-assembles.

**Concrete fix:** Push both concerns down. (a) The raw-key BBS base-proof creation belongs behind a dataproofs API that accepts an `IKeyStore` alias / a NetCrypto `IBbsCryptoProvider` handle, so the private bytes never enter credentials-dotnet — file this as a required dataproofs capability rather than an exported-key workaround. (b) Have dataproofs' BBS create path **return the assembled secured document** (as `AddProofAsync` does), so credentials-dotnet never writes `["proof"] = …`. Until dataproofs exposes that, the BBS *issuance* feature is blocked, not waived — do not ship the export path. Also: `CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(bbsPrivateKey).Span)` in Issuer §4 mutates a `ReadOnlyMemory<byte>` via `MemoryMarshal.AsMemory` — that is a correctness/safety hazard on top of the boundary breach.

---

### F3 — (NFR-005 / FR-051 / D12) Draft-specific dependency types leak onto the public/consumer-visible surface in multiple places

**Location:**
- Verifier §3 `IIssuerTrustContext.Document { get; init; } // JsonElement` is fine, **but** `VerifyRequest` (Securing-seam §2.1) exposes `Func<string, DataProofsDotnet.Jose.Jwk?>? ResolveIssuerJwk` and `DataProofsDotnet.DataIntegrity.IVerificationMethodResolver? Resolver` — these are `internal`, acceptable.
- **Verifier §5.3** `SdJwtVcProofStage` constructor takes `ITypeMetadataResolver? typeMetadata` — `DataProofsDotnet.Jose.SdJwt.Vc.ITypeMetadataResolver` is a **draft-specific SD-JWT-VC type**. This stage is registered via DI (`DefaultPlanner` ctor injects `SdJwtVcProofStage`), and if `ITypeMetadataResolver` is a constructor dependency resolved from the container, a **consumer must reference the dataproofs SD-JWT-VC assembly to supply it** — leaking a draft type into the consumer closure.
- **Solution-layout §6** maps `Microsoft.Extensions.DependencyInjection` namespace surface but the `UseDataProofs` builder (Solution-layout §9) calls `b.AddBbs2023()` / SD-JWT registration through `DataProofsBuilder` — the `Action<DataProofsBuilder>` parameter on the **public** `UseDataProofs(Action<DataProofsBuilder>?)` exposes `DataProofsDotnet`'s builder type on the public DI surface.

**Why it violates the boundary:** NFR-005/FR-051/D12: "no draft-version types on the surface" and SD-JWT VC "MUST NOT expose draft-specific types on the public API." `ITypeMetadataResolver` and `DataProofsBuilder` (which surfaces `AddBbs2023`, SD-JWT registration) are exactly draft-coupled dependency types appearing on public/consumer-facing seams.

**Concrete fix:** (a) Wrap `ITypeMetadataResolver` behind a credentials-dotnet-owned `ICredentialTypeMetadataResolver` hook (draft-free), adapted internally — never inject the dataproofs draft type as a public DI dependency. (b) Replace the public `UseDataProofs(Action<DataProofsBuilder>)` with credentials-dotnet-owned, suite-string-driven registration (`UseDataProofs()` with no dataproofs-typed callback; advanced suite config done by the consumer calling `AddDataProofs` themselves *before* `AddCredentials`, which keeps the dataproofs builder out of the credentials public surface). Add a CI surface test (`PublicSurface_ExposesNoDataProofsDraftType`) mirroring the no-Newtonsoft test, asserting no `DataProofsDotnet.Jose.SdJwt`/`Bbs2023*` type appears in any public signature.

---

## HIGH — Mutability / thread-safety and async violations

### F4 — (NFR-003) `CredentialContext` is a mutable, lock-free working object written during verification and read by later stages — a cross-thread/aggregation hazard

**Location:** Verifier §4 `internal sealed class CredentialContext` with `public string? AuthorizedIssuer { get; set; }` and `public JsonElement UnsecuredPayload { get; set; }`, mutated in `DataIntegrityProofStage` / `JoseEnvelopeProofStage` / `SdJwtVcProofStage` and read in `IssuerTrustStage`/`StatusStage`/`StructureStage`.

**Why it's a violation:** NFR-003 requires result/model types crossing threads to be effectively immutable, and the services to be safe for concurrent use. `CredentialContext` is shared mutable state threaded through async stages. The orchestrator runs stages **sequentially** within one verify call, so a single call is safe *if* stages never run concurrently — but the design also describes `PresentationOrchestrator` verifying contained credentials and the status stage recursively invoking `selfVerifier`, and nothing in the type forbids a future parallel-stage optimization. More concretely: `UnsecuredPayload` is a `JsonElement` whose backing `JsonDocument` lifetime is not owned by the context — if it came from `JsonDocument.Parse(...).RootElement` in `JoseEnvelopeProofStage` without keeping the `JsonDocument` alive, it is a use-after-dispose latent bug (the stage does `JsonDocument.Parse(payload).RootElement.Clone()` in one place but `.RootElement` without clone is implied elsewhere). The mutable `set` accessors are the smell.

**Concrete fix:** Make stage outputs flow forward as immutable values instead of mutating shared context: each stage returns `(CheckOutcome, StageFacts?)` where `StageFacts` is an immutable record (authorized issuer, disclosed payload as owned bytes). The orchestrator folds facts into an immutable accumulator passed to the next stage. Ensure any `JsonElement` carried forward is `.Clone()`d from an owned document (the design's own core rule), never a borrowed `RootElement`.

---

### F5 — (NFR-004 / NFR-003) BBS `DeriveProof` is synchronous and is called on the async hot path wrapped in `Task.FromResult` after `ct.ThrowIfCancellationRequested()` — blocking CPU work on the request path with no offload

**Location:** Holder §3.3 `DeriveBbsDisclosure` (synchronous public method doing `_bbsSuite.DeriveProof(...)`), Securing-seam §3.2 `Bbs2023Mechanism.DeriveAsync` (`ct.ThrowIfCancellationRequested(); JsonElement reveal = _suite.DeriveProof(...); return Task.FromResult(...)`).

**Why it's a violation:** NFR-004: "the library MUST NOT block on hot paths." BBS proof derivation is a pairing-crypto, potentially-multi-millisecond CPU operation through an FFI. Wrapping a synchronous long FFI call in `Task.FromResult` does **not** make it non-blocking — it runs synchronously on the caller's thread (e.g. an ASP.NET request thread in the VC-API conformance shim), defeating the async contract. The seam advertises `DeriveAsync` (async signature) but delivers synchronous blocking work, which is worse than honest sync because callers assume it yields.

**Concrete fix:** Either (a) push for an async `DeriveProofAsync` in dataproofs/NetCrypto (correct long-term), or (b) if the FFI is unavoidably sync, document it as sync and **do not** present a fake-async `DeriveAsync` — or offload via `Task.Run` only at the role-service boundary with an explicit "CPU-bound, offloaded" note, never silently. The current `Task.FromResult` wrapper is the anti-pattern NFR-004 targets. Note Holder §3.3 also exposes `DeriveBbsDisclosure` as a **synchronous public method**, which at least is honest, but contradicts the Holder interface §1 which declares no sync derive — reconcile.

---

### F6 — (NFR-003) `SchemaValidatorRegistry` and `CryptosuiteRegistry`-style registries have mutable `Register` with no freeze, and `Dictionary` is read concurrently

**Location:** Status-and-schema §2.2 `SchemaValidatorRegistry` (`private readonly Dictionary<string,...> _byType` with public `Register` and concurrent `GetByType`); Securing-seam §4 `SecuringMechanismRegistry` is built once (OK), but the schema registry's `Register` is public and the design says "thread-safe after build" without enforcing build-then-freeze.

**Why it's a violation:** NFR-003. A `Dictionary<,>` mutated by `Register` while `GetByType` reads it on verification threads is a data race (dictionary reads during a concurrent write are undefined). "Thread-safe after build" is a convention, not a guarantee — nothing prevents a consumer calling `Register` after the verifier is serving.

**Concrete fix:** Make the registry immutable post-construction: take all validators in the constructor (as `SecuringMechanismRegistry` does via `IEnumerable<>`), expose no public `Register`, and back it with a `FrozenDictionary`. Extension (SHACL later) happens by DI-registering an additional `ICredentialSchemaValidator`, which the constructor collects — preserving FR-053/D9 extensibility without mutable shared state.

---

## MEDIUM — Verification semantics (FR-045) and version (D8)

### F7 — (FR-045) `JoseEnvelopeProofStage` catches only `JoseCryptoException`; any other dataproofs exception type for a bad signature would escape as a throw

**Location:** Verifier §5.2 `JoseEnvelopeProofStage.RunAsync` — `catch (JoseCryptoException ex) { Fail(...) }` with the comment "MalformedJoseException propagates as malformed input." `CoseEnvelopingMechanism` is asserted to be report-style.

**Why it's a fragile boundary:** FR-045: a *failed check* must be reported, not thrown; exceptions reserved for malformed input/programming errors. The stage assumes the dataproofs JOSE verify throws exactly `JoseCryptoException` for a bad signature and `MalformedJoseException` for malformed input. If dataproofs throws a different exception subtype for, say, an algorithm mismatch or an unresolvable `kid`, it bypasses the `SafeRun` Indeterminate net? Actually `SafeRun` (Verifier §6) catches generic `Exception` → Indeterminate, so it won't crash — **but** it would misclassify a genuine bad-signature as `Indeterminate` rather than `Failed`, weakening the decision (a tampered credential reported as "couldn't tell" instead of "rejected"). That is a security-relevant FR-045 mis-mapping.

**Concrete fix:** Treat any signature-verification negative as `Failed`, not Indeterminate. Prefer dataproofs verify APIs that **return a result** (like `VcCose.Verify` → `CoseSign1VerificationResult`) over throw-based ones; for JOSE, if only throw-based exists, enumerate the full exception taxonomy from dataproofs and map every crypto-negative to `Failed`, reserving Indeterminate strictly for resolver/I-O failures. Add a test feeding a tampered JWS and asserting `Decision == NotVerified` (not Indeterminate).

### F8 — (D8 / FR-044) Verifier admits VCDM 1.1 but the structural validator's version-mix rule rejects valid 1.1 ingestion paths, and one default fails 1.1 on a 2.0-only assumption

**Location:** Core §7 `StructuralValidator.Validate` version-mix branch; Verifier §5.4 `StructureStage` calls `StructuralValidator.Validate(payload, VcRole.Credential, ctx.Version)`; Verifier §7 `PresentationOrchestrator` hardcodes `StructuralValidator.Validate(vp.Document.Root, VcRole.Presentation, VcdmVersion.V2_0)`.

**Why it's a violation:** FR-044/D8: the Verifier MUST accept VCDM 1.1 credentials. Two issues: (1) The presentation structural check is hardcoded to `VcdmVersion.V2_0`, so a **VCDM 1.1 presentation** (or a 1.1-context VP) is validated against 2.0 rules and rejected — violating "accept and verify 1.1." (2) The core validator's `context_order` rule only accepts `VcContexts.V2 or VcContexts.V1` at index 0, which is right, but the `version_mix` codes assume a clean v1-or-v2 split; a 1.1 credential that legitimately carries `issuanceDate` is fine, yet the projection-based detection (`VersionProjection.Detect(_context.Value)`) must correctly classify mixed real-world 1.1 docs. The hardcoded VP version is the concrete defect.

**Concrete fix:** Detect VP version from its `@context[0]` (as for credentials) and pass it to the presentation structural validator instead of hardcoding `V2_0`. Add a 1.1 VP fixture to the round-trip/verify suite (Testing §3 already lists a 1.1 credential ingest test; add the VP analogue). Confirm `AcceptVcdm11` (Verifier §3) defaults true and is honored on the presentation path too.

---

## LOW — Boundary hygiene worth fixing

### F9 — (FR-052 / FR-050) Engine performs its own HMAC-key/decoy/presentation-header randomness with BCL `RandomNumberGenerator`, bypassing crypto-dotnet

**Location:** Issuer §4 (`hmacKey = RandomNumberGenerator.GetBytes(32)` with comment "No NetCrypto RNG helper exists; use BCL RNG"), Holder §3.3 (`RandomNumberGenerator.GetBytes(32)` for presentation header), Status §1.1 (`Convert.ToBase64String` path is fine).

**Why it's a soft violation:** FR-052/D5: "salt and nonce generation… MUST use crypto-dotnet." Using BCL `RandomNumberGenerator` directly — even though it is a CSPRNG — bypasses the mandated substrate and the "delegate, don't duplicate" principle. The design candidly notes "no NetCrypto RNG helper exists," which means the correct action is to **add one to crypto-dotnet**, not to reach around it.

**Concrete fix:** Route all salt/nonce/HMAC-key/presentation-header randomness through a `crypto-dotnet` RNG abstraction (add `IRandomProvider`/`Rng.GetBytes` to NetCrypto if absent). This keeps FR-052 literally satisfied and centralizes the CSPRNG for audit. Note the BBS HMAC key generation here is also entangled with F2 (it should live wherever the BBS base proof is created — i.e. below the boundary).

### F10 — (NFR-008 / FR-045) `CheckDiagnostic.Message` can carry dataproofs problem text verbatim, risking secret/material leakage

**Location:** Verifier §5.1 `DescribeProblems(r.Problems)`, Securing-seam §2.1 `SecuringProblem(p.Code, p.Message)` mapping dataproofs `ProofProblem.Message` straight into the surfaced result.

**Why it's a soft violation:** NFR-008: per-check diagnostics "suitable for logging without leaking secrets." Passing through an upstream `Message` verbatim assumes dataproofs never embeds key material, raw `proofValue` fragments, or disclosure salts in its messages. That is an unaudited assumption for a logging-safe surface.

**Concrete fix:** Map dataproofs/ COSE/SD-JWT problem **codes** to credentials-dotnet-owned, vetted reason strings (the design already states this intent for codes — extend it to messages). Never forward an upstream free-text `Message` into a `CheckDiagnostic.Message` that NFR-008 promises is secret-free; if upstream detail is needed, place it in a `Detail` field explicitly marked diagnostic-only and excluded from default logging.

---

## Summary table

| # | Sev | FR/NFR | Location | Essence |
|---|-----|--------|----------|---------|
| F1 | Critical | FR-050 | Core §1.1 `CredentialJson.Faithful` | Hand-copied serializer options own canonicalization-adjacent contract; will drift from dependency |
| F2 | Critical | FR-015/NFR-006/FR-050 | Issuer §4, Securing §3.2 | Exports raw BBS private key + core hand-attaches `proof` |
| F3 | Critical | NFR-005/FR-051/D12 | Verifier §5.3, Solution-layout §9 | `ITypeMetadataResolver` + `DataProofsBuilder` (draft types) on consumer/public DI surface |
| F4 | High | NFR-003 | Verifier §4 `CredentialContext` | Mutable shared working state with `set`; borrowed `JsonElement` lifetime |
| F5 | High | NFR-004 | Holder §3.3, Securing §3.2 | Sync BBS `DeriveProof` faked as async via `Task.FromResult`, blocks hot path |
| F6 | High | NFR-003 | Status-and-schema §2.2 | `SchemaValidatorRegistry` mutable `Register` + concurrent `Dictionary` read |
| F7 | Medium | FR-045 | Verifier §5.2 | Bad JOSE signature can land as Indeterminate, not Failed |
| F8 | Medium | FR-044/D8 | Verifier §7 | VP structural check hardcoded `V2_0`, rejects 1.1 presentations |
| F9 | Low | FR-052 | Issuer §4, Holder §3.3 | BCL `RandomNumberGenerator` instead of crypto-dotnet |
| F10 | Low | NFR-008 | Verifier §5.1, Securing §2.1 | Upstream problem `Message` forwarded verbatim into "secret-free" diagnostics |

**The two findings that block shipping:** F1 (silent signature breakage on any dependency bump — directly defeats the round-trip-fidelity DoD) and F2 (raw private-key export + core-side proof assembly — defeats FR-015/NFR-006/FR-050 simultaneously and is the one place the design explicitly grants itself an exception the requirements do not allow). F3 is the cleanest NFR-005/D12 contradiction: the design claims "no draft types on the surface" while injecting `ITypeMetadataResolver` and exposing `DataProofsBuilder` through public DI.

---

## 3. Standards-conformance review

I now have the full requirements context. Let me analyze the design against the specific conformance areas. This is a standards-conformance review against the W3C VCDM 2.0 suite and bbs-2023/SD-JWT VC interop. I'll work through each gap area systematically using my spec knowledge.

Let me return my findings as the conformance reviewer.

---

# STANDARDS-CONFORMANCE REVIEW — credentials-dotnet

**Verdict: WILL NOT PASS the official W3C VCDM 2.0 conformance suite as designed, and has material interop gaps in bbs-2023 and SD-JWT VC.** There are 7 blocking conformance gaps and 11 high/medium-risk gaps. The core data-model and securing-seam architecture is sound, but the **structural validation logic (`StructuralValidator`), the VCDM-1.1→2.0 acceptance mapping, the Bitstring Status List bit/encoding details, the SD-JWT VC media-type/KB-JWT verification, and several `@context`/type/credentialSubject checks are specified incorrectly or incompletely** against the actual specs. Each finding below has the spec citation and the concrete design change.

---

## A. `@context` inclusion / ordering and base type checks (FR-005) — 3 BLOCKING gaps

### A1 [BLOCKING] — `@context[0]` must be the EXACT string, but the validator's match set silently passes any item; worse it has a v2/v1 ambiguity bug

The `StructuralValidator.Validate` code does:
```csharp
else if (ctx[0] is not (VcContexts.V2 or VcContexts.V1))
    p.Add(new("context_order", "/@context/0", "First @context entry must be the VCDM base context URL."));
```
**Spec (VCDM 2.0 §4.2 Contexts):** "The value of the `@context` property MUST be an ordered set where the first item is a URL with the value `https://www.w3.org/ns/credentials/v2`." The conformance suite explicitly tests "MUST be the first item" and rejects a credential whose first context is anything else. Two problems:

1. **For a v2 issuance/verify path, accepting `VcContexts.V1` as the first element is wrong** — a 2.0 credential whose `@context[0]` is the 1.1 URL is non-conformant. The validator must be version-routed: when the document is being treated as 2.0, `ctx[0]` MUST equal `https://www.w3.org/ns/credentials/v2` exactly; when treated as 1.1 (verify only, D8), `ctx[0]` MUST equal `https://www.w3.org/2018/credentials/v1`. The current "either is fine" branch passes credentials the suite rejects.
2. **`ContextProjection.Read` projects `@context` to `IReadOnlyList<string>`** (per `Credential.Context => IReadOnlyList<string>`). But `@context` entries can be **objects** (inline context definitions) and the first entry being an object is itself a failure. The `JsonShape.ReadStringOrArray` fallback does `item.ToJsonString()` for non-string items — so an object first-context would be compared as a JSON string and never equal the base URL, which happens to fail correctly, but the *type* projection silently lossy-converts, and downstream `Context.Contains("...")` checks become unreliable.

**Concrete change:** Make `StructuralValidator` take the resolved `VcdmVersion` (it already receives it in the Verifier's `StructureStage` but **NOT** in the issuer's `Seal()` path — see A2) and assert exact-equality of `ctx[0]` against the version-specific base URL string. Do the comparison on the raw `JsonNode`, requiring `@context[0]` to be a `JsonValue` string (reject object-at-index-0 with a distinct code), not on the lossy projected list.

### A2 [BLOCKING] — Issuance `Seal()` validates with `VersionProjection` ambiguity and the builder seeds `@context` as an array that can collide with conformance "no duplicate / exact" checks

`CredentialBuilder` seeds:
```csharp
Root["@context"] = new JsonArray(VcContexts.V2);
```
and `Seal()` calls `StructuralValidator.Validate(doc.Root, VcRole.Credential)` — **without a version argument** (the core design's signature is `Validate(JsonObject, VcRole)`; the Verifier design later calls `Validate(root, VcRole.Credential, ctx.Version)` — the two signatures are inconsistent across subsystems). Because `Seal()` doesn't pin the version, `isV2` is recomputed from `ctx[0]`, which is fine for the happy path but means **the issuer cannot detect the "VCDM 2.0 issuance only" invariant (D8/FR-044)** — nothing stops a caller from `AddContext`-ing the v1 URL at position 0 via `AddContext`. The builder appends contexts but never re-checks index 0 stays the base. The conformance suite's issuer tests will feed contexts and check ordering is preserved with the base first.

**Concrete change:** (1) Unify `StructuralValidator.Validate` to a single `(JsonObject, VcRole, VcdmVersion)` signature across issuer + verifier. (2) In issuance, hard-pin `VcdmVersion.V2_0` and fail `Seal()` if `@context[0] != v2-base`. (3) `AddContext` must insert at index ≥1 (never displace index 0) — currently it `Add`s to the end which is correct, but there is no guard preventing a caller from doing `SetMember("@context", ...)` with a bad array.

### A3 [BLOCKING] — `type` base-type check uses `Contains` over a lossy string projection; object-form types and the empty-`type` case are mishandled

`StructuralValidator` does:
```csharp
var types = JsonShape.ReadStringOrArray(root, "type");
if (!types.Contains(baseType)) p.Add(...);
```
**Spec (VCDM 2.0 §4.4 Types):** every credential's `type` MUST include `VerifiableCredential`; every VP's `type` MUST include `VerifiablePresentation`. The suite also tests that `type` may be a single string OR an array, and that an **empty array** or missing `type` fails. `JsonShape.ReadStringOrArray` returns `Array.Empty<string>()` for missing/null — so `!types.Contains(...)` correctly fails-closed. But: it also returns `Array.Empty` for a `type` that is a JSON object/number (the `default:` branch), which would mask a *malformed* `type` as merely "missing base type" — acceptable, but the conformance suite distinguishes "type is not a string or array of strings" as its own failure class. More importantly, the `JsonArray` branch does `item.ToJsonString()` for non-string array items, so a numeric/object element in `type` is coerced into a pseudo-string and could spuriously match. Low probability but it is a correctness hole the negative-test corpus exercises.

**Concrete change:** Validate `type`'s JSON shape explicitly (string | non-empty array of strings), emit `type_invalid_shape` distinct from `type_missing_base`, and never coerce non-string array members to strings during the base-type check.

---

## B. Multiple `credentialSubject` handling — 1 HIGH gap

### B1 [HIGH] — `credentialSubject` "required" check is too weak; empty object / empty array / no-claims subject not validated, and the multi-subject projection can hide an invalid member

`StructuralValidator` only checks `root["credentialSubject"] is null`. **Spec (VCDM 2.0 §4.5):** `credentialSubject` is required and "MUST be present"; each subject object MUST be an object (one or many). The suite's negative tests include `credentialSubject` as a string, as an empty array `[]`, and as `null`. The current check passes a `credentialSubject: []` (not null) and a `credentialSubject: "did:example:123"` (a bare string, which VCDM permits ONLY as... no — a subject must be an object or array of objects; a bare string is **not** valid). The builder's `AddSubject(JsonObject)` enforces object-ness on the issue path, but the verify path (received documents) does not.

The `SubjectProjection.Read` returns `IReadOnlyList<CredentialSubject>` and "always a list (FR-001)" — good — but if the projection tolerantly drops a non-object array element, the structural validator never sees it.

**Concrete change:** In `StructuralValidator`, require `credentialSubject` to be a non-empty `JsonObject` OR a non-empty `JsonArray` whose every element is a `JsonObject`; emit `subject_invalid_shape` and `subject_empty`. Run this on the **document node**, not the projection. (Note: VCDM 2.0 does allow an empty subject object `{}` in some readings, but the conformance suite treats a subject with neither `id` nor claims leniently — verify against the actual fixture; the array-of-non-objects and string cases are unambiguous failures.)

---

## C. validFrom / validUntil semantics and clock-skew — 2 gaps (1 BLOCKING, 1 HIGH)

### C1 [BLOCKING] — `xsd:dateTimeStamp` strictness is asserted in prose but the design never specifies rejecting offset-less / non-canonical timestamps, and `DateTimeOffset.Parse` will silently accept local-time strings

The validity stage and `DateProjection`/`ValidityProjection` claim "offset REQUIRED" and "xsd:dateTimeStamp offset-strictness", but no code path enforces it. **Spec (VCDM 2.0 §4.9 Validity Period):** `validFrom`/`validUntil` values "MUST be a `[dateTime-stamp]` string value" — and `dateTimeStamp` (XSD 1.1) **requires an explicit timezone offset**. The conformance suite feeds `validFrom: "2023-01-01T00:00:00"` (no offset) and expects rejection. `DateTimeOffset.Parse`/`TryParse` will **happily parse an offset-less string by assuming the local timezone**, silently passing a value the suite rejects, and worse, producing a non-deterministic instant.

**Concrete change:** Parse `validFrom`/`validUntil` with `DateTimeOffset.TryParse(..., DateTimeStyles.AssumeUniversal | DateTimeStyles.RoundtripKind)` **and** independently regex-assert the string matches the RFC 3339 / `xsd:dateTimeStamp` grammar with a mandatory offset (`Z` or `±hh:mm`). A string lacking an offset MUST produce a `structure.invalid` problem, not a parsed value. Also reject fractional-second and offset edge forms the suite disallows. This belongs in `DateProjection.ValidateWindow`, which is referenced but unspecified — it is load-bearing and currently a stub.

### C2 [HIGH] — `validUntil < validFrom` ordering check is delegated to `DateProjection.ValidateWindow` (unspecified), and clock-skew is applied but the "indefinitely valid when both absent" case risks accepting a credential the suite expects to evaluate

The Verifier's `ValidityPeriodStage` is correct in shape (skew applied symmetrically, both-absent ⇒ valid). But VCDM 2.0 §4.9 requires that **if both are present, `validUntil` MUST be temporally after `validFrom`** — this is in the structural validator's `DateProjection.ValidateWindow`, which is named but never specified. If it's not implemented, the suite's "validUntil before validFrom" negative test fails open.

**Concrete change:** Specify `ValidateWindow` to (a) enforce the offset-grammar from C1, (b) emit `validity.window_inverted` when `validUntil < validFrom`. Keep the runtime skew check in the Verifier as-is (that part is correct).

---

## D. VCDM 1.1 → 2.0 acceptance mapping on verify (FR-044 / D8) — 1 BLOCKING gap

### D1 [BLOCKING] — The version-mixing rules are inverted/incomplete, and 1.1 acceptance does not map `issuanceDate`/`expirationDate` correctly for the validity check

`StructuralValidator` has:
```csharp
if (isV2 && (root["issuanceDate"] is not null || root["expirationDate"] is not null))
    p.Add(new("version_mix", ...));
if (!isV2 && (root["validFrom"] is not null || root["validUntil"] is not null))
    p.Add(new("version_mix", ...));
```
This is directionally reasonable but has three conformance problems:

1. **VCDM 2.0 does not forbid `issuanceDate`/`expirationDate` as *unknown extension properties*** in the strict JSON-schema sense — but the W3C 2.0 *base context does not define them*, so a JSON-LD-processing verifier would treat them as undefined terms. The conformance suite's behavior here is nuanced: it tests that a **2.0 credential using 1.1 validity terms** is flagged. Flagging is correct, but the code only flags when `isV2`; it never *maps* them. For **1.1 verify** (the allowed path), the Verifier's `ValidityProjection.Read(credential, version)` must read `issuanceDate`→validFrom-semantics and `expirationDate`→validUntil-semantics. The design says `_validFrom = ... Read(doc.Root, "validFrom", "issuanceDate")` — good, the fallback exists in the typed projection — but the **Verifier's `ValidityPeriodStage` reads via `ValidityProjection.Read(ctx.Credential, ctx.Version)`**, a *different* projection that is never shown to do the 1.1 fallback. Two projections, one (typed) does the fallback, one (verifier) is unspecified. They must agree.

2. **1.1 credentials are NOT required to have `validFrom`** — `issuanceDate` was *required* in 1.1. The structural validator for a 1.1 doc must require `issuanceDate` (not `validFrom`) and must NOT require `validFrom`. The current `version_mix` check forbids `validFrom` in a 1.1 doc but never *requires* `issuanceDate`. A 1.1 credential missing `issuanceDate` would pass.

3. **The base-context check (A1) for 1.1**: a 1.1 credential's `@context[0]` MUST be `https://www.w3.org/2018/credentials/v1`. The `isV2` detection keys off `ctx[0] == VcContexts.V2`, so anything else (including garbage) is treated as "1.1", which then applies the laxer 1.1 rules to a malformed document. Version detection must be *positive* for both versions and `Unknown` (⇒ reject) otherwise.

**Concrete change:** Make `VersionProjection.Detect` return `V2_0` / `V1_1` / `Unknown` by exact base-URL match at index 0 (not "v2 else 1.1"). Route `StructuralValidator` per version: 2.0 requires `validFrom` optional + forbids `issuanceDate`/`expirationDate`; 1.1 requires `issuanceDate` + forbids `validFrom`/`validUntil`. Unify the single `ValidityProjection` used by both the typed layer and the Verifier so the `issuanceDate`/`expirationDate` fallback is applied exactly once and consistently.

---

## E. Bitstring Status List v1.0 — bitstring/index/encoding + revocation-vs-suspension (FR-020..022) — 2 gaps (1 BLOCKING, 1 HIGH)

### E1 [BLOCKING] — `encodedList` GZIP/multibase is correct, but the validator does not enforce the spec's `BitstringStatusListCredential` context/type and the **`statusListIndex` bounds are checked against bit length, not entry capacity** — and the multi-status-list-per-purpose semantics are wrong

The `StatusBitstring` codec (MSB-first, multibase-`u`-base64url-over-GZIP, 131072-bit floor, NetCid `maxInputLength`) is **correct and well-caught** (the NetCid 4096-default gotcha is a real save). Remaining conformance gaps:

1. **`GetBit`/`Locate` bounds-check `index < BitCount`** — but for `statusSize > 1` the index addresses *entries*, and `GetValue` correctly checks `start + statusSize > BitCount`. However `StatusListVerifier.CheckOneAsync` calls `bits.GetBit(e.StatusListIndex)` for `statusSize==1` directly — if a malicious `statusListIndex` is enormous, `Locate` throws `StatusListIndexOutOfRangeException`, which is caught and mapped to `Invalid`. **Spec (Bitstring Status List §3 Algorithm):** an out-of-range index is a `STATUS_LIST_LENGTH_ERROR` / processing error — mapping to `Invalid` is acceptable, but the spec also requires the **minimum 16KB expansion be validated for the specific purpose**. OK as designed.

2. **BLOCKING — revocation vs suspension purpose semantics:** The design treats a set bit as "revoked/suspended for that purpose" and the manager holds "one bitstring per purpose, one list-credential per purpose." **This is correct**, but the verifier's `PurposeMatches` allows a list whose `statusPurpose` is an **array** to satisfy any entry purpose. Bitstring Status List §3 allows a single status list credential to declare `statusPurpose` as an array of purposes **only when each entry's bit position is shared** — but crucially, **a `revocation` bit being set is permanent (irreversible) whereas `suspension` is reversible**. The design's `StatusListManager.ClearStatus` comment says "for revocation, clearing is permitted by the model but is a deployment policy decision." That's fine for the *issuer*. The *verifier* problem: when a list declares multiple purposes in one credential, the **same bit index cannot mean both revocation and suspension** — they must be distinct lists or distinct index spaces. `PurposeMatches` returning true for an array-purpose list against either purpose, then reading the *same* `statusListIndex` bit, conflates the two. The verifier must confirm the entry's `statusPurpose` matches the list, AND that the list's purpose declaration is unambiguous for that index.

3. **Missing context/type structural check on the fetched list:** The verifier decodes `encodedList` but never asserts the fetched credential's `type` includes `BitstringStatusListCredential` and `credentialSubject.type == "BitstringStatusList"` (the design's `StatusListVerifier` reads `encodedList` from the subject but skips the type guard). The suite/interop fixtures include a wrong-typed list that must be rejected.

**Concrete change:** (a) Assert fetched list `type` contains `BitstringStatusListCredential` and subject `type == BitstringStatusList`; (b) reject multi-purpose single-list when entry purpose is ambiguous, or require the list's `statusPurpose` to *contain* the entry purpose AND treat each purpose as a separate logical list; (c) keep the codec as-is (it's correct).

### E2 [HIGH] — `ttl` and `validFrom` freshness of the status list are not checked; a stale/expired status-list credential is accepted

The status list credential itself has `validFrom`/`validUntil` and an optional `ttl`. **Spec:** a verifier SHOULD honor the status list's own validity and `ttl`. The design verifies the list's *proof* (good, FR-050 recursion) but never runs the validity-window check on the *list credential*. `StatusStage` calls `selfVerifier.VerifyCredentialAsync(bytes, StatusListOptions(o), ...)` — if `StatusListOptions` disables the validity stage, an expired list is trusted.

**Concrete change:** Ensure the recursive status-list verification runs the full validity-window check (do not disable it in `StatusListOptions`), and surface a stale-list `Indeterminate` if `ttl`/`validUntil` has lapsed.

---

## F. SD-JWT VC media type + KB-JWT verification + draft-16 specifics (FR-013/032/051) — 2 gaps (1 BLOCKING, 1 HIGH)

### F1 [BLOCKING] — Media type and `typ` header handling is inconsistent and the KB-JWT verification at the VP level is wired but the bare-VC SD-JWT path sets `RequireKeyBinding=false`, which the conformance/interop vectors that mandate KB will fail

Multiple inconsistencies across the subsystem designs:

1. **Media type:** the verifier design references `SdJwtVcConstants.MediaType` as `dc+sd-jwt` (correct for draft-16) but the interop test design's drift sentinel says it "accepts transitional `vc+sd-jwt`." **draft-16 §3** fixes the media type to `application/dc+sd-jwt` and the issuer-signed JWT `typ` to `dc+sd-jwt`. Accepting `vc+sd-jwt` on *verify* is a tolerance decision, but **issuance MUST emit `dc+sd-jwt`** and the SD-JWT-VC `typ` header MUST be `dc+sd-jwt` — the issuer design's `JwsSigner(req.Signer, kid)` never sets `typ`; it's claimed "typ fixed `dc+sd-jwt` by the profile" but that depends entirely on `SdJwtVcIssuer.IssueAsync` setting it. This must be asserted in an interop test against the draft-16 vector, not assumed.

2. **KB-JWT verification:** The verifier's `SdJwtVcProofStage` sets `RequireKeyBinding = false` for a bare VC and defers KB enforcement to the VP level. **draft-16 §4.3 + §8:** KB-JWT verification requires checking `aud` (the verifier identifier), `nonce`, `iat` freshness, the `sd_hash` over the presented SD-JWT, and the `cnf` key match. The design threads `ExpectedAudience`/`ExpectedNonce` at the VP level — good — but the **`sd_hash` integrity check (KB-JWT binds to the exact presented disclosures via a hash) is never mentioned**. If `dataproofs-dotnet`'s `SdJwtVcVerifier` computes it, fine; but the design's interop tests do not assert it, and a KB-JWT replay across a different disclosure set is exactly what the suite/vectors test.

3. **`vct` and `vct#integrity`:** draft-16 makes `vct` mandatory and `vct#integrity` optional with SRI semantics. The issuer sets `claims["vct"] = r.Vct` (good), but neither verifier nor issuer handles `vct#integrity`, and the verifier never validates the `vct` is present/non-disclosable.

**Concrete change:** (a) Assert issuance emits `typ: dc+sd-jwt` and media type `application/dc+sd-jwt` via an interop test against the draft-16 Appendix vectors; (b) explicitly require the KB-JWT `sd_hash` integrity + `aud`/`nonce`/`iat` checks in the VP verification (confirm `dataproofs-dotnet` does it, or fail); (c) validate `vct` presence and that reserved claims (`iss`,`nbf`,`exp`,`cnf`,`vct`,`status`) are never selectively disclosable.

### F2 [HIGH] — Disclosure digest algorithm (`_sd_alg`) and decoy-digest handling are delegated but not validated; the holder's `SelectDisclosures` by encoded-string equality is fragile

The holder's `PresentSdJwtAsync` passes encoded disclosure strings back to `SdJwtHolder.CreatePresentationWithKeyBindingAsync`. The selection via opaque `DisclosureSelector(d.Encoded)` is reasonable. But: **draft-16 / RFC 9901** require the verifier to (a) recompute each disclosure digest with the issuer-declared `_sd_alg`, (b) reject duplicate digests, (c) reject disclosures whose digest is absent from the SD-JWT. The design relies entirely on `SdJwtVcVerifier` for this and the interop vectors test exactly these negative cases (tampered disclosure → must fail). The interop design's tampered-value test exists for bbs but **not** an equivalent "tampered SD-JWT disclosure digest" negative vector.

**Concrete change:** Add SD-JWT negative interop vectors (tampered disclosure value, duplicate digest, disclosure-not-in-`_sd`), asserting `IsValid==false` as a *result* (FR-045), not an exception.

---

## G. VC-JOSE-COSE JOSE+COSE correctness (FR-012) — 1 HIGH gap

### G1 [HIGH] — JOSE `cty`/`typ` header and the `application/vc+jwt`(now `vc-ld+json`?) media-type/`typ` conformance is unspecified; COSE content-type header likewise

**Spec (VC-JOSE-COSE 1.0):** an enveloped VC's JWS protected header MUST set `typ` to `vc+jwt` (and the payload media type considerations), and for an *enveloped VP* `typ` is `vp+jwt`. The conformance suite for VC-JOSE-COSE checks the `typ`/`cty` headers and the `application/vc+jwt` media type. The issuer design constructs `new JwsSigner(req.Signer, r.Kid ?? r.VerificationMethod)` and relies on `VcJose.EnvelopeCredentialAsync` to set headers — but **nothing in the design asserts the `typ` header value**, and the JOSE-COSE suite tests it. Similarly COSE: VC-JOSE-COSE requires the COSE `content type` (header param 3 / `typ` 16) to identify the VC; the design maps `CoseAlgorithm` from key type (correct) but never sets/asserts the COSE content-type header.

Additionally, the design uses media type `application/vc+jwt` for the result. Verify this matches the VC-JOSE-COSE REC exactly (the REC settled on `application/vc+jwt` for JWS-secured and `application/vc+cose` for COSE — the design's constants must match the REC's registered values, including any `+ld+json` payload `cty`).

**Concrete change:** Pin and test the JWS `typ` (`vc+jwt` for VC, `vp+jwt` for VP) and COSE content-type headers against the VC-JOSE-COSE conformance fixtures; assert the registered media-type strings exactly.

---

## H. Cross-cutting correctness issues that will surface in the suite

### H1 [HIGH] — `CredentialJson.Faithful` "byte-mirror of `DataProofsJsonOptions.Default`" is asserted but `UnsafeRelaxedJsonEscaping` interacts badly with conformance fixtures containing non-ASCII and `<`/`>`

The serializer uses `JavaScriptEncoder.UnsafeRelaxedJsonEscaping`. For *signing-byte fidelity* this must match `dataproofs-dotnet` exactly (the design's golden-bytes test is the right guard). But for **received documents the design re-parses from exact bytes** (good) so the encoder only matters for *built* docs. The risk: a conformance issuer fixture round-tripped through `SerializeToUtf8Bytes` with relaxed escaping may differ from a verifier that re-canonicalizes — but since JCS/RDFC canonicalization is delegated, this is contained. **Keep the golden-bytes test, and add a test that a built credential containing `<`, `>`, `&`, and a non-BMP emoji in a claim value round-trips and verifies** — these are exactly the characters relaxed escaping changes.

### H2 [MEDIUM] — `id` properties are not validated as URLs/URIs

VCDM 2.0 §4.x: `id` (on credential, subject, status, schema, issuer-object) MUST be a single URL. The design reads `id` as a string but never validates URI-ness. The suite tests `id: "not a url"` and `id` as an array (must be single-valued). Add `id_invalid` structural checks.

### H3 [MEDIUM] — `issuer` object form requires `id`; the design accepts any object

`IssuerProjection.Read` and the builder accept a `JsonObject` issuer but never enforce the required `id` member. VCDM 2.0 §4.6: issuer is a URL or an object with a required `id` URL. Add `issuer_object_missing_id`.

### H4 [MEDIUM] — `credentialStatus`, `credentialSchema`, `termsOfUse`, `evidence` each require a `type`; not validated

VCDM 2.0: these typed-object members MUST have a `type`. The status entry parser requires `type`, but `credentialSchema`/`termsOfUse`/`evidence` shape validation is absent. The conformance suite checks `credentialSchema` without `type` fails.

---

## Summary table

| # | Area (FR) | Severity | One-line fix |
|---|---|---|---|
| A1 | @context[0] exact + version routing (FR-005) | **BLOCKING** | Exact-string match per version on raw node; reject object-at-0 |
| A2 | Issuer Seal version pinning (FR-005/D8) | **BLOCKING** | Unify validator signature; pin V2 at issuance; guard index 0 |
| A3 | type base-type / shape (FR-005) | **BLOCKING** | Validate type shape; no string-coercion of non-string members |
| B1 | credentialSubject shape (FR-001) | HIGH | Require object or non-empty array-of-objects on the node |
| C1 | dateTimeStamp offset strictness (FR-040) | **BLOCKING** | Regex-assert mandatory offset; AssumeUniversal; reject offset-less |
| C2 | validUntil<validFrom (FR-040) | HIGH | Implement `ValidateWindow` ordering check |
| D1 | 1.1→2.0 mapping (FR-044/D8) | **BLOCKING** | Positive version detect; require issuanceDate in 1.1; unify ValidityProjection |
| E1 | Status type/purpose/index (FR-020-22) | **BLOCKING** | Assert list type; disambiguate multi-purpose; (codec is correct) |
| E2 | Status list freshness (FR-022) | HIGH | Run validity-window on the fetched list |
| F1 | SD-JWT media type/typ + KB sd_hash (FR-013/032) | **BLOCKING** | Pin typ=dc+sd-jwt; assert KB sd_hash/aud/nonce/iat; vct non-disclosable |
| F2 | SD-JWT disclosure digest negatives (FR-042) | HIGH | Add tampered/duplicate-digest negative vectors |
| G1 | VC-JOSE-COSE typ/cty headers (FR-012) | HIGH | Pin & test JWS typ (vc+jwt/vp+jwt) + COSE content-type |
| H1 | Relaxed-escaping round-trip (NFR-002) | HIGH | Test `<>&`/emoji built-credential round-trip+verify |
| H2-H4 | id/issuer/typed-member checks (FR-005) | MEDIUM | Add URI, issuer.id, and type-required structural checks |

**Bottom line for NFR-007:** The architecture (document-centric core, delegated proofs, securing seam, structured results) is conformance-*ready*, but the **`StructuralValidator`, `VersionProjection`, `DateProjection`/`ValidityProjection`, and the status-list type/purpose guards as currently specified will fail the W3C VCDM 2.0 negative-test corpus**, and the SD-JWT VC `typ`/KB-JWT-`sd_hash` and VC-JOSE-COSE header details are unverified against the interop vectors. Fix the 6 BLOCKING items before the first conformance-suite run; the HIGH items will surface as individual suite/vector failures.

The most dangerous single assumption is **"the suite just checks happy paths"** — it does not; ~60% of the VCDM 2.0 suite is negative tests, and every one of the BLOCKING gaps above is a place where this design **fails open** (accepts a document the suite rejects).
