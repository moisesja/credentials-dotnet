# credentials-dotnet — Final Implementation Plan

**Status:** For approval (precedes any source).
**Date:** 2026-06-18.
**Builds on:** `docs/credentials-dotnet-concept.md`, `docs/credentials-dotnet-prd.md`, `docs/architectural-path.md` (binding; decisions D1–D12 not re-opened).
**Stack:** capability library composed by `net-wallet-sdk`; delegates crypto to `NetCrypto` (crypto-dotnet), proofs to `DataProofsDotnet` (dataproofs-dotnet), identifiers/keys to `NetDid` (net-did).

This document is self-contained and buildable by an engineer. It synthesizes the chosen core model, all seven subsystem designs, the completeness report, and the adversarial + conformance reviews into one plan, and **folds in the fixes** for every critical gap and every adversarial/conformance finding — the designs below already reflect those fixes, and each is called out where it lands.

---

## 1. Overview & scope

### What is being built

A complete, standards-conformant **W3C VCDM 2.0** engine for the three roles — **Issuer**, **Holder**, **Verifier** — covering all three securing families (embedded Data Integrity, enveloping VC-JOSE-COSE, SD-JWT VC), selective disclosure on both paths (`bbs-2023` embedded; SD-JWT salted disclosures + KB-JWT), Bitstring Status List v1.0 (revocation + suspension), and JSON Schema 2020-12 validation. The engine is protocol-agnostic (no OID4VCI/OID4VP/DIDComm), exposing roles as in-process DI-registered services.

### The delegate-don't-duplicate boundary

`credentials-dotnet` owns **only** the VCDM 2.0 / 1.1 data model, the Bitstring Status List bit/encoding model, the JSON-Schema validation shaping, and the role orchestration. Everything beneath is delegated:

| Concern | Owner | What credentials-dotnet does |
|---|---|---|
| Proof creation/verification; **all canonicalization** (RDFC + JCS) | `DataProofsDotnet` | Hands over a faithful view of the document/bytes/claims; never canonicalizes or assembles a `proof` itself (FR-050). |
| Cryptographic operations the engine performs itself — hashing/digests, **salts/nonces/RNG**, holder-binding key→JWK | `NetCrypto` | Calls `NetCrypto` for all of these via a single RNG/Hash seam; never hand-rolls crypto and never reaches around the substrate (FR-052, fix **F9**). |
| DID/verification-method resolution; signing | `NetDid` | Resolves issuer/holder/subject DIDs and VMs; signs only through `NetCrypto.ISigner` obtained from `NetDid`'s `IKeyStore`; never handles raw private keys (FR-015, FR-080, NFR-006). |

### Non-negotiable constraints

1. **System.Text.Json only.** No `Newtonsoft.Json` on the public surface or in the consumer-exposed transitive closure. `DataProofsDotnet` confines its RDFC-internal Newtonsoft; a CI gate proves it never leaks here (NFR-002; §7).
2. **No draft-version types on the public API.** `bbs-2023` and SD-JWT VC are reached only through the role API; their `DataProofsDotnet` types (`DisclosureFrame`, `SdJwtIssuerOptions`, `Jwk`, `Bbs2023Cryptosuite`, **`ITypeMetadataResolver`**, **`DataProofsBuilder`**) are confined to internal adapters (NFR-005, FR-051, D12). A CI surface test enforces this (fix **F3**; §7).
3. **`CredentialJson.Faithful` is faithful, not canonical, and is derived from — never hand-copied off — the dependency's serializer options** (fix **F1**; §3).
4. **The engine never assembles or strips `proof` itself** — the securing layer owns proof placement on every path, including BBS (fix **F2**; §3, §5).
5. **Report-don't-throw** verification; effectively-immutable, lock-free shared values; async I/O (FR-045, NFR-003, NFR-004).

---

## 2. Solution & project layout

### Repo tree

```
credentials-dotnet/
├── Credentials.sln
├── Directory.Build.props / .targets / Directory.Packages.props
├── global.json (SDK 10.0.100, rollForward latestFeature)
├── nuget.config (<clear/> + nuget.org)
├── .editorconfig / .gitignore / AGENTS.md / CLAUDE.md->AGENTS.md
├── README.md / CHANGELOG.md / CONTRIBUTING.md / LICENSE (Apache-2.0) / SECURITY.md / NOTICE
├── docs/                       (exists: prd, concept, architectural-path)
├── tasks/                      (this plan, lessons)
├── src/
│   ├── Credentials.Core/                              # model + roles + status + schema + securing seam
│   └── Credentials.Extensions.DependencyInjection/    # AddCredentials(...)
├── tests/
│   ├── Credentials.Core.Tests/
│   ├── Credentials.Extensions.DependencyInjection.Tests/
│   ├── Credentials.RoundTripTests/                    # FR-003 fidelity DoD
│   ├── Credentials.InteropTests/                      # bbs-2023 + SD-JWT VC vectors + no-Newtonsoft closure
│   ├── Credentials.Conformance.VcApi/                 # ASP.NET VC-API shim (IsPackable=false)
│   ├── Credentials.Conformance.Tests/                 # drives the W3C Node suite
│   ├── Credentials.SampleSmokeTests/                  # API-coverage gate driver
│   ├── Credentials.ArchitectureTests/                 # no-Newtonsoft surface, no-draft-type surface, XML-doc, semver helpers
│   └── Credentials.ConsumerProbe/                     # references the packed .nupkg for closure analysis
├── samples/                    (14 console projects + Credentials.Samples.Shared — §7)
├── tools/
│   ├── api-coverage/           (Roslyn public-surface enumerator + coverage diff)
│   └── apicompat/              (ApiCompat baseline txt)
└── .github/workflows/{ci.yml, conformance.yml, release.yml}
```

### csproj graph

Two `src` projects (house net-did/didcomm split): `Credentials.Core` (framework-light; the whole public surface) and `Credentials.Extensions.DependencyInjection` (the only project taking `Microsoft.Extensions.DependencyInjection`). All four stack libs are consumed as **`PackageReference`** under central package management (never `ProjectReference`) — the published-package boundary is exactly where the no-Newtonsoft-closure and semver guarantees are verifiable.

`Directory.Build.props` (root): `net10.0`, `Nullable`/`ImplicitUsings`/`LangVersion=latest`, `TreatWarningsAsErrors=true`, `GenerateDocumentationFile=true`, single `$(CredentialsVersion)` SemVer source, Apache-2.0 NuGet metadata, Source Link, deterministic CI build. `Directory.Build.targets` packs the root README into every package.

`Directory.Packages.props` pinned versions (no Newtonsoft anywhere; STJ-native schema validator):

```xml
<PackageVersion Include="NetDid.Core" Version="2.0.1" />
<PackageVersion Include="NetDid.Extensions.DependencyInjection" Version="2.0.1" />
<PackageVersion Include="DataProofsDotnet.Core" Version="1.0.0" />
<PackageVersion Include="DataProofsDotnet.Rdfc" Version="1.0.0" />          <!-- bbs-2023 / RDFC -->
<PackageVersion Include="DataProofsDotnet.Jose" Version="1.0.0" />          <!-- JOSE + SD-JWT VC -->
<PackageVersion Include="DataProofsDotnet.Cose" Version="1.0.0" />          <!-- COSE -->
<PackageVersion Include="DataProofsDotnet.Extensions.DependencyInjection" Version="1.0.0" />
<PackageVersion Include="NetCrypto" Version="1.1.0" />
<PackageVersion Include="NetCid" Version="1.6.0" />                         <!-- status-list multibase -->
<PackageVersion Include="JsonSchema.Net" Version="9.2.2" />                 <!-- JSON Schema 2020-12, STJ-native -->
<PackageVersion Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="10.0.8" />
<PackageVersion Include="Microsoft.Extensions.Http" Version="10.0.8" />
<PackageVersion Include="Microsoft.Extensions.Logging.Abstractions" Version="10.0.8" />
<PackageVersion Include="Microsoft.Extensions.Caching.Memory" Version="10.0.8" />
<PackageVersion Include="Microsoft.SourceLink.GitHub" Version="10.0.300" />
<!-- test: Microsoft.NET.Test.Sdk, xunit, xunit.runner.visualstudio, FluentAssertions, NSubstitute, coverlet.collector -->
<!-- tooling: Microsoft.DotNet.ApiCompat.Tool, Microsoft.CodeAnalysis.CSharp -->
```

`Credentials.Core.csproj` references `NetDid.Core`, the four `DataProofsDotnet.*`, `NetCrypto`, `NetCid`, `JsonSchema.Net`, `Microsoft.Extensions.Logging.Abstractions`, Source Link; `InternalsVisibleTo` the core/DI test assemblies. The DI project `ProjectReference`s Core and adds the DI/Http/Caching abstractions plus `NetDid.Extensions.DependencyInjection` and `DataProofsDotnet.Extensions.DependencyInjection`.

### Package/DI surface (namespaces)

Root namespace `Credentials`. No draft namespaces anywhere on the public surface.

| Namespace | Public surface |
|---|---|
| `Credentials` | `Credential`, `VerifiablePresentation`, `CredentialBuilder`, `VerifiablePresentationBuilder`, `ContainedCredential`, `CredentialDocument`, `CredentialJson`, `VcdmVersion`, `SecuringState`, `DocumentOrigin`, `SecuringForm`, `SecuringSelector`, `ISecuringCapabilities` |
| `Credentials.Roles` | `IIssuer`, `IHolder`, `IVerifier` + request/result records |
| `Credentials.Verification` | `VerificationResult`/`CredentialVerificationResult`/`PresentationVerificationResult`, `CheckResult`/`CheckOutcome`/`CheckStatus`/`CheckKinds`/`CheckDiagnostic`, `VerificationPolicy`/`CredentialVerificationOptions`/`PresentationVerificationOptions` |
| `Credentials.Trust` | `IIssuerTrustPolicy`, `IssuerTrustContext`, `IssuerTrustResult`, `IssuerTrustDecision` |
| `Credentials.Schema` | `ICredentialSchemaResolver`, `ResolvedSchema`, `SchemaDialect`, `SchemaCheckResult` |
| `Credentials.Status` | `IStatusListFetcher`, `StatusPurpose`, `StatusListManager`, `BitstringStatusListEntry`, `StatusCheckResult` |
| `Credentials.Validation` | `StructuralValidator`, `StructuralValidationResult`, `StructuralProblem`, `VcRole` |
| `Microsoft.Extensions.DependencyInjection` | `CredentialsServiceCollectionExtensions.AddCredentials`, `CredentialsBuilder`, `CredentialsOptions` |

---

## 3. Core data model (D10 / OQ-3)

Document-centric core (the single source of truth) + a lazy typed layer projected over it. Resolves OQ-3.

### `CredentialDocument` — the canonical store

One `System.Text.Json.Nodes.JsonObject` (mutable while building, frozen thereafter) plus, for ingested documents, the **exact original UTF-8 bytes**. A `DocumentOrigin` enum (`ReceivedBytes` | `Built` | `ParsedElement`) records provenance so the securing layer can pick the right fidelity strategy and refuse unsafe ones.

Three faithful projections map 1:1 to the three securing payload shapes:

- `ToElement() → JsonElement` — the **whole** document, a 1:1 reparse of the exact bytes, handed to the Data Integrity pipeline (which strips `proof` itself; the core never strips it). DI needs **structural** faithfulness only — canonicalization is `DataProofsDotnet`'s job (FR-050).
- `ToUtf8() → ReadOnlyMemory<byte>` — verbatim wire bytes for `ReceivedBytes`; serialize-once-pinned bytes for `Built`/`ParsedElement`. Used by enveloping JOSE/COSE (sign-exact-bytes).
- `ToClaimsObject() → JsonObject` — a deep clone for SD-JWT VC (protects the source of truth from claim-stripping).

`Parse(ReadOnlyMemory<byte>)` copies incoming bytes defensively, bounds untrusted input (`MaxDepth=256`, no trailing commas, no comments — NFR-006 posture), and freezes. `FromElement(JsonElement, origin)` deep-clones a borrowed element. `WithMember`/`ToBuilder` deep-clone. Every public exit returns a fresh copy/clone — no internal node escapes by reference (NFR-003).

```csharp
namespace Credentials;

public enum DocumentOrigin { ReceivedBytes, Built, ParsedElement }

public sealed class CredentialDocument
{
    private readonly JsonObject _root;
    private readonly bool _frozen;
    private readonly ReadOnlyMemory<byte>? _originalUtf8;      // present only for ReceivedBytes
    private ReadOnlyMemory<byte>? _serializedCache;           // lazy serialize-once for Built/ParsedElement
    private readonly object _serializeGate = new();

    public DocumentOrigin Origin { get; }
    public bool IsFrozen => _frozen;

    public static CredentialDocument Parse(ReadOnlyMemory<byte> utf8Json);   // → frozen, ReceivedBytes
    public static CredentialDocument Parse(string json);
    public static CredentialDocument FromElement(JsonElement element, DocumentOrigin origin = DocumentOrigin.ParsedElement);
    internal static CredentialDocument CreateMutable();                       // builder scratch
    internal CredentialDocument Freeze();
    internal void Set(string member, JsonNode? value);                        // building only; throws if frozen
    internal JsonObject Root { get; }
    public JsonNode? this[string member] { get; }
    public CredentialDocument WithMember(string name, JsonNode? value);       // pure, deep-cloned, Built

    public ReadOnlyMemory<byte> ToUtf8();                                     // fresh copy
    public JsonElement ToElement();                                          // self-contained clone
    public JsonObject ToClaimsObject();                                      // deep clone
    public byte[] ToBytes();
}
```

### `CredentialJson.Faithful` — derived from the dependency (fix F1)

The one serializer the core uses. It MUST byte-mirror `DataProofsDotnet.DataProofsJsonOptions.Default` because, for a credential **we** build, the bytes we serialize are the bytes the securing layer signs and emits on the wire — any divergence in escaping/null-handling/naming silently breaks JCS/enveloping signatures. **The options are not hand-copied** (the F1 fix): they are **constructed by copy-from `DataProofsDotnet.DataProofsJsonOptions.Default`** at static init (copy the `Encoder`, `DefaultIgnoreCondition`, `PropertyNamingPolicy`, `WriteIndented`), then `MakeReadOnly`. If `DataProofsDotnet` later exposes a `SerializeFaithful(JsonNode)` helper, the core calls it directly instead. A **CI assertion test** (`Faithful_ByteMirrors_DataProofsDefault`) serializes a battery of fixtures through both `CredentialJson.Faithful` and the dependency's options and asserts byte-equality, failing the build on drift — so a dependency bump that changes the default can never silently desynchronize signed-vs-wire bytes. This is faithful (preserve issuer member order), not canonical (canonicalization stays in `DataProofsDotnet`, FR-050).

### Lifecycle state machine (NFR-003 backbone)

```
Building ─Seal()→ Sealed ─secure via dataproofs→ Secured ─wire→ Received
(mutable,          (frozen,                        (frozen, +proof/         (frozen, exact
 builder-only)      validated, unsecured)           opaque envelope)         wire bytes)
   ▲                                                                            │
   └────────────── ToBuilder() (deep-clone, drops proof) ◀──────────────────────┘
```

`IsFrozen == true` for any `Credential`/`VerifiablePresentation` crossing a public boundary; `Building` exists only inside a single-threaded, single-use builder. **Frozen ⇒ no mutation ⇒ no locks** (the only lazily-written field is `_serializedCache`, double-checked under a gate, deterministic ⇒ torn races recompute identical bytes). `ToBuilder()` forks a deep clone and drops `proof` (editing invalidates an embedded proof — a deliberate, documented fork-drops-proof footgun).

### `Credential` / `VerifiablePresentation` — typed projections

Typed accessors are `Lazy<T>` projections (`LazyThreadSafetyMode.ExecutionAndPublication`) over the **frozen** document — safe to memoize precisely because the document is immutable, so the cache is a pure function of immutable data and cannot drift (FR-004). `GetMember(name)` is the untyped escape hatch so unknown members (`evidence`, `termsOfUse`, vendor extensions) are never lost (FR-001 round-trip fidelity).

```csharp
namespace Credentials;

public sealed class Credential
{
    public static CredentialBuilder Build();
    public static Credential Parse(ReadOnlyMemory<byte> utf8Json);
    public static Credential Parse(string json);
    internal static Credential FromDocument(CredentialDocument doc, SecuringState securing);
    public CredentialBuilder ToBuilder();                       // deep-clone, drops proof

    public bool IsFrozen { get; }
    public SecuringState Securing { get; }                      // Unsecured | DataIntegrity | Jose | Cose | SdJwtVc
    public DocumentOrigin Origin { get; }
    public VcdmVersion Version { get; }                         // positive detect: V2_0 | V1_1 | Unknown (fix D1/F8)
    public bool HasEmbeddedProof { get; }

    public IReadOnlyList<string> Context { get; }              // raw-node read; index-0 validated by StructuralValidator
    public IReadOnlyList<string> Type { get; }
    public string? Id { get; }
    public Issuer Issuer { get; }                              // string-or-object; object form requires id
    public IReadOnlyList<CredentialSubject> CredentialSubjects { get; }   // always a list (FR-001)
    public DateTimeOffset? ValidFrom { get; }                 // 1.1 fallback to issuanceDate
    public DateTimeOffset? ValidUntil { get; }                // 1.1 fallback to expirationDate
    public IReadOnlyList<CredentialStatusEntry> CredentialStatus { get; }
    public IReadOnlyList<CredentialSchemaRef> CredentialSchema { get; }
    public JsonNode? GetMember(string name);                  // escape hatch

    public CredentialDocument Document { get; }
    public JsonElement AsElement();                           // DI (whole document)
    public ReadOnlyMemory<byte> AsUtf8();                     // enveloping JOSE/COSE (exact bytes)
    public JsonObject AsClaimsObject();                       // SD-JWT VC (claims clone)
    public string? CompactEnvelope { get; }                  // verbatim compact for JOSE/COSE/SD-JWT received
    public byte[] ToBytes();
    public StructuralValidationResult ValidateStructure();    // version-aware
}
```

`VerifiablePresentation` mirrors this; its `verifiableCredential` projects to `ContainedCredential` — `Embedded(Credential)` for a JSON-object child (structure-faithful via `FromElement`), `Enveloped(string CompactSerialization)` kept **verbatim** for JOSE/SD-JWT compact children (touching a signed ASCII token breaks it).

### Builder — write-through DOM

`CredentialBuilder` mutates the unsealed `JsonObject` from the first call, so the sealed document is exactly what the issuer assembled — member order preserved, unknown members carried verbatim. The builder seeds `@context = ["https://www.w3.org/ns/credentials/v2"]` at index 0 and `type = ["VerifiableCredential"]`. `AddContext` appends at index ≥1 and **never displaces index 0**; there is no public `SetMember("@context", …)` that can replace the array (fix A2). `AddSubject`/`AddStatus`/`AddSchema` promote object→array on a second add (FR-001, FR-016). `WithValidFrom/Until` emit RFC-3339 with a mandatory offset. `Seal()` runs `StructuralValidator` pinned to `VcdmVersion.V2_0` (issuance is 2.0 only, D8), throws `CredentialStructureException` on malformed-by-construction, freezes, and is single-use.

### Round-trip / thread-safety discipline

- `Parse` copies incoming bytes; `ToUtf8/ToElement/ToClaimsObject/WithMember/ToBuilder` all return fresh copies/clones (NFR-003).
- After securing, the secured artifact is **re-ingested** as the new source of truth (`CredentialDocument.Parse(SerializeToUtf8Bytes(secured, CredentialJson.Faithful))`) so sign-bytes == stored-bytes == wire-bytes henceforth.
- Received-document fidelity: `Credential.Parse(bytes)` retains bytes verbatim; the Verifier hands `AsElement()`/`AsUtf8()`/the envelope-returned payload back to `DataProofsDotnet` — the core never serializes the typed object and verifies against that.

---

## 4. Public API surface

### Roles

```csharp
namespace Credentials.Roles;

public interface IIssuer
{
    Credential BuildCredential(CredentialContent content);                                    // FR-010
    Task<IssuedCredential> IssueAsync(Credential credential, IssuanceRequest request, CancellationToken ct = default); // FR-011..014,016
    Task<IssuedCredential> IssueAsync(CredentialContent content, IssuanceRequest request, CancellationToken ct = default);
}

public interface IHolder
{
    HeldCredential Ingest(ReadOnlyMemory<byte> credentialWireBytes);                           // FR-030
    HeldCredential IngestCompact(string compactSerialization, CredentialForm form);
    SdJwtInspection InspectSdJwt(HeldCredential held);                                         // FR-030/032 claim selection
    BbsDisclosureMap InspectBbsBase(HeldCredential held);                                      // FR-030/031
    Task<Credential> DeriveBbsDisclosureAsync(HeldCredential bbsBase, BbsDisclosureRequest request, CancellationToken ct = default); // FR-031 (async, fix F5)
    Task<SdJwtPresentation> PresentSdJwtAsync(HeldCredential held, SdJwtPresentationRequest request, CancellationToken ct = default); // FR-032
    VerifiablePresentation BuildPresentation(VpAssemblyRequest request);                       // FR-033
    Task<VerifiablePresentation> BindWithDataIntegrityAsync(VerifiablePresentation vp, VpBindingRequest request, CancellationToken ct = default); // FR-034
    Task<string> BindWithJoseEnvelopeAsync(VerifiablePresentation vp, VpBindingRequest request, CancellationToken ct = default);
}

public interface IVerifier
{
    ValueTask<CredentialVerificationResult> VerifyCredentialAsync(Credential securedCredential, CredentialVerificationOptions? options = null, CancellationToken ct = default); // FR-040,042
    ValueTask<CredentialVerificationResult> VerifyCredentialAsync(ReadOnlyMemory<byte> secured, CredentialVerificationOptions? options = null, CancellationToken ct = default);
    ValueTask<PresentationVerificationResult> VerifyPresentationAsync(VerifiablePresentation presentation, PresentationVerificationOptions? options = null, CancellationToken ct = default); // FR-041
}
```

`IssuanceRequest` is a closed discriminated union over the four forms — `DataIntegrityRequest { string Cryptosuite; … }` (suite is an opaque string — FR-053), `JoseEnvelopeRequest`, `CoseEnvelopeRequest`, `SdJwtVcRequest { string Vct; IReadOnlyList<DisclosureSelector> Disclosable; HolderBindingKey? HolderBinding; … }`, `Bbs2023BaseRequest { IReadOnlyList<string> MandatoryPointers; … }`. Every form carries a `NetCrypto.ISigner Signer` and a `string VerificationMethod`. `SdJwtVcRequest`'s `DisclosureSelector`/`HolderBindingKey`/`SdHashName` are credentials-dotnet-owned, draft-free types (FR-051). `IssuedCredential` is a form-tagged union (`DataIntegrity(Credential)`, `Jose(string)`, `Cose(ReadOnlyMemory<byte>)`, `SdJwtVc(string)`) with `MediaType`.

### Options & results

`CredentialVerificationOptions` (per-call): `VerificationTime?`, `ClockSkew` (default 2 min), `ExpectedProofPurpose/Domain/Challenge`, `CheckStatus/CheckSchema/CheckIssuerTrust`, `Schema/Status/TrustIsRequired`, `AcceptVcdm11` (default true). `PresentationVerificationOptions` adds `ExpectedAudience/Challenge/Domain`, `RequireHolderBinding`, and a nested `CredentialOptions`. `VerificationPolicy` carries `TreatIndeterminateAsFailure` (default true = fail-closed) and is the single home of the decision-composition rule (`DecisionComposer`): any required `Failed` ⇒ `Rejected`; else any required `Indeterminate` (under strict policy) ⇒ `Indeterminate`; else `Accepted`.

Result model (FR-043, NFR-008): `CheckStatus { Passed, Failed, Indeterminate, Skipped }`; `CheckKinds` are **strings** (additive); `CheckDiagnostic { Code, Message, Severity, JsonPointer? }` is secret-free by construction — `Message` carries vetted credentials-dotnet reason strings mapped from upstream **codes**, never an upstream free-text message verbatim (fix **F10**); `CheckResult { Kind, Status, Diagnostics, Detail?, EvaluatedAt }`; `CredentialVerificationResult`/`PresentationVerificationResult` carry the overall `VerificationDecision { Accepted, Rejected, Indeterminate }`, per-check results, `Version`, `Mechanism`, and a one-line secret-free `ToString()`.

### The three injected hooks (FR-081/FR-082; resolves OQ-1)

```csharp
namespace Credentials.Trust;
public interface IIssuerTrustPolicy   // explicit, optional verifier step; structured decision+reason, never a bare bool
{
    Task<IssuerTrustResult> EvaluateAsync(IssuerTrustContext context, CancellationToken ct = default);
}
public sealed record IssuerTrustResult { public IssuerTrustDecision Decision; public string ReasonCode; public string Reason; public IReadOnlyList<CheckDiagnostic> Diagnostics; /* Trusted/Untrusted/Indeterminate factories */ }
public enum IssuerTrustDecision { Trusted, Untrusted, Indeterminate }
// IssuerTrustContext: IssuerId, CredentialTypes, VerificationMethod (the PROOF-VERIFIED VM, so policy may pin to a key), Mechanism, CredentialId, EvaluatedAt, Document(JsonElement read-only). Never claims/keys (NFR-008).

namespace Credentials.Schema;
public interface ICredentialSchemaResolver   // fetch hook; returns dialect-abstracted ResolvedSchema (SHACL-ready, D9)
{ Task<SchemaResolutionResult> ResolveAsync(SchemaReference reference, CancellationToken ct = default); }
// ResolvedSchema { string Id; SchemaDialect Dialect (JsonSchema2020_12 | future Shacl); JsonElement Document; string? VerifiedDigestSri }

namespace Credentials.Status;
public interface IStatusListFetcher           // returns the SECURED status-list VC bytes; verifier checks ITS proof
{ Task<StatusListFetchResult> FetchAsync(StatusListReference reference, CancellationToken ct = default); }
```

Mapping (canonical, in the verifier): trust `Untrusted ⇒ Failed`, `Indeterminate ⇒ Indeterminate`, absent/disabled ⇒ `Skipped`, a throwing policy ⇒ `Indeterminate` (never crash, FR-045). The single shipped allowlist `IIssuerTrustPolicy` lives in `samples/`, **not** the library (FR-082 — no built-in trust lists).

### `AddCredentials` DI

```csharp
namespace Microsoft.Extensions.DependencyInjection;
public static class CredentialsServiceCollectionExtensions
{
    public static IServiceCollection AddCredentials(this IServiceCollection services, Action<CredentialsBuilder> configure);
}
```

The builder exposes `UseNetCrypto()`, `UseDataProofs()` (no `DataProofsBuilder` on the public callback — fix **F3**; advanced suite config is done by the consumer calling `AddDataProofs(...)` before `AddCredentials`), `UseNetDid(Action<NetDidBuilder>)`, `UseIssuerTrustPolicy<T>()/(instance)`, `UseSchemaResolver<T>()/UseHttpSchemaResolver()`, `UseStatusListFetcher<T>()/UseHttpStatusListFetcher()`, and `Configure(Action<CredentialsOptions>)`. Roles register as `TryAddSingleton` over immutable values (NFR-003). Hooks resolve as **optional** (`GetService`) so an unconfigured hook ⇒ that check is `Skipped`. `AddCredentials` **fails fast** (naming the builder method + the FR) when a required substrate is missing: no `NetDid` `IDidResolver`, no `IVerificationMethodResolver` (which `AddNetDid` does *not* register), no `DataIntegrityProofPipeline`. `IIssuerTrustPolicy` is optional (no fail-fast). `IKeyStore` is consumer-registered before `AddCredentials`.

No draft-version type appears anywhere above; `bbs-2023` is selected via `DataIntegrityRequest.Cryptosuite = "bbs-2023"` (or `Bbs2023BaseRequest`) and SD-JWT VC via `SdJwtVcRequest` only.

---

## 5. Internal architecture

### The securing-mechanism seam (one seam, four mechanisms)

A `(SecuringForm, suiteName?) → ISecuringMechanism` resolution through `SecuringMechanismRegistry`, plus neutral request/result records. The role services never touch a `DataProofsDotnet` type, a suite string at a call site, a `JwsSigner`, a `CoseAlgorithm`, a `DisclosureFrame`, or a BBS pointer. Each `ISecuringMechanism` is the **sole** place its `DataProofsDotnet` package is imported; it is a pure adapter (request → dataproofs call → result), holding no proof or canonicalization logic (FR-050). Namespace `Credentials.Core.Securing` is **internal** (`InternalsVisibleTo` tests).

```csharp
internal interface ISecuringMechanism
{
    SecuringForm Form { get; }
    IReadOnlyCollection<string> SuiteNames { get; }            // DI: bbs-2023, future sd-suites; enveloping: empty
    bool IsAvailable { get; }                                  // e.g. Bbs2023Cryptosuite.IsAvailable
    Task<SecureResult> SecureAsync(SecureRequest request, CancellationToken ct);
    Task<SecuringVerificationResult> VerifyAsync(VerifyRequest request, CancellationToken ct);
}
internal interface ISelectiveDisclosureMechanism : ISecuringMechanism   // bbs-2023, SD-JWT VC present
{ Task<SecureResult> DeriveAsync(DeriveRequest request, CancellationToken ct); }
```

Mechanisms and their delegated calls:

| Mechanism | Securing call (delegated) | Payload | Notes |
|---|---|---|---|
| `DataIntegrityMechanism` | `DataIntegrityProofPipeline.AddProofAsync(JsonElement, DataIntegrityProof, ISigner, ct) → JsonElement`; verify `VerifyAsync(JsonElement, IVerificationMethodResolver, options, ct)` | `AsElement()` (whole doc; pipeline strips/attaches `proof`) | Suite is data, never branched; delegates suite selection to the shared `CryptosuiteRegistry`. A new JCS/RDFC suite is reachable here with **no code change** (FR-053). |
| `Bbs2023Mechanism` (`ISelectiveDisclosureMechanism`) | base: a `DataProofsDotnet` BBS create path that **accepts an `IKeyStore` alias / `IBbsCryptoProvider` handle and returns the assembled secured document** (fix **F2**); derive: `Bbs2023Cryptosuite.DeriveProof(JsonElement, IReadOnlyList<string>, ReadOnlyMemory<byte>)` | `AsElement()` | The core **never** exports a raw BBS key and **never** writes `["proof"]=…` (fix **F2**). See §5 "BBS boundary" below. |
| `JoseEnvelopingMechanism` | `VcJose.EnvelopeCredentialAsync(ReadOnlyMemory<byte>, JwsSigner, ct) → string`; verify `VcJose.VerifyCredential(string, Func<string,Jwk?>) → byte[]` | `AsUtf8()` (exact bytes) | Sets/asserts JWS `typ = vc+jwt` (VP: `vp+jwt`) — fix **G1**. |
| `CoseEnvelopingMechanism` | `VcCose.EnvelopeCredentialAsync(ReadOnlyMemory<byte>, ISigner, CoseAlgorithm, keyId?, ct) → byte[]`; verify `VcCose.Verify(...) → CoseSign1VerificationResult` | `AsUtf8()` | `KeyType→CoseAlgorithm` mapped internally; COSE content-type header set/asserted (fix **G1**). Result-style verify → no throw on bad signature. |
| `SdJwtVcMechanism` (`ISelectiveDisclosureMechanism`) | issue `SdJwtVcIssuer.IssueAsync(JsonObject, DisclosureFrame, JwsSigner, SdJwtIssuerOptions, ct)`; present `SdJwtHolder.CreatePresentationWithKeyBindingAsync(...)`; verify `SdJwtVcVerifier.VerifyAsync(string, Func<string,Jwk?>, SdJwtVerificationOptions, ICredentialTypeMetadataResolver-adapted, ct)` | `AsClaimsObject()` | `DisclosureFrame`/`SdJwtIssuerOptions`/`Jwk`/`ITypeMetadataResolver` confined here; `typ = dc+sd-jwt`, media `application/dc+sd-jwt`, `vct` non-disclosable, reserved claims rejected (fix **F1**). |

**The registry (FR-053):** keyed on opaque suite **strings** + form; the single `DataIntegrityMechanism` delegates to the shared `CryptosuiteRegistry`, so a JCS/RDFC suite added there is reachable with no new mechanism; a different-shaped suite (`bbs-2023`, future `ecdsa-sd-2023`) registers a dedicated mechanism by suite name. `ISecuringCapabilities` exposes available suites as runtime-discovered strings — `SecuringSelector.DataIntegrity("ecdsa-sd-2023")` is a valid call the day the suite ships and is registered, with **no public type change**.

**BBS boundary (fix F2):** the raw-key BBS create path is pushed **below** the credentials-dotnet boundary. `Bbs2023Mechanism.SecureAsync` calls a `DataProofsDotnet`/`NetCrypto` API that takes the `IKeyStore` alias (or an `IBbsCryptoProvider` handle) and the per-credential HMAC key, performs the BBS multi-message signature, and **returns the assembled secured document** — exactly as `AddProofAsync` does. credentials-dotnet never exports the private key (preserving FR-015/NFR-006) and never hand-attaches `proof` (preserving FR-050 and the core's whole-document invariant). This is a **required `DataProofsDotnet` capability**: until it exists, BBS *issuance* (FR-014) is gated, not waived — the export-key workaround is not shipped. BBS *derivation* (FR-031) is already clean (`DeriveProof` is public and key-free). The per-credential HMAC key and the derive presentation-header randomness come from the `NetCrypto` RNG seam (fix **F9**), not BCL RNG.

### Status — Bitstring Status List v1.0 (FR-016/020/021/022)

Owned by credentials-dotnet; proof verification of the fetched list VC is delegated (FR-050). `StatusBitstring` is the codec/index core: MSB-first bit ordering, multibase-`u` base64url over GZIP via `NetCid.Multibase`. **Every `NetCid` encode/decode passes an explicit `maxInputLength`** (the `DefaultMaxInputLength == 4096` is too small for a populated 16 KiB-minimum list — the single most likely runtime bug if missed), GZIP inflation is bounded against decompression bombs (NFR-006), and the decoded bitstring is length-floor-checked (≥131072 bits). `statusListIndex` is parsed from its **string** form (spec gotcha). `StatusListManager` produces/updates/re-produces the unsecured `BitstringStatusListCredential` (one bitstring per purpose) for the Issuer to sign; revocation and suspension both supported.

Verifier `StatusStage` (FR-022), with conformance fixes folded in:
- Resolve via `IStatusListFetcher` (miss ⇒ `Indeterminate "status.list_unreachable"`, never throw).
- Verify the fetched list VC's **own proof** recursively through the same `IVerifier` (FR-050) **with the full validity-window check enabled** so a stale/expired status-list credential is not trusted (fix **E2**).
- Assert the fetched list `type` contains `BitstringStatusListCredential` and `credentialSubject.type == "BitstringStatusList"` (fix **E1**).
- Match the entry `statusPurpose` against the list's declared purpose(s); reject ambiguous multi-purpose-single-list where the same index would mean both revocation and suspension (fix **E1**).
- Decode, read bit(s), return a structured `StatusCheckResult` with `StatusCheckDetail { StatusPurpose, IsSet, Value?, StatusMessage? }` (logging-safe). A set revocation/suspension bit ⇒ `Failed`; never throws (FR-045).

### Schema validation — JSON Schema 2020-12 + named library (FR-070, D9)

`JsonSchema.Net` 9.2.2 (STJ-native, no Newtonsoft — NFR-002), build-once/evaluate-many with `RequireFormatValidation`. The SHACL-ready seam is `ICredentialSchemaValidator` (keyed by `credentialSchema.type`) dispatched by a registry that is **immutable post-construction** (constructor takes `IEnumerable<ICredentialSchemaValidator>`, backed by `FrozenDictionary`, **no public `Register`** — fix **F6**); adding SHACL later is a DI registration the constructor collects, no API break (D9). The v1 `JsonSchema2020Validator` handles `JsonSchema` and `JsonSchemaCredential` (the wrapping VC's proof verified recursively first), enforces `digestSRI` (via the `NetCrypto.Hash` seam) **before** parsing fetched bytes, and returns tri-state `Success/Failure/Indeterminate` (unknown type/unresolvable ⇒ `Indeterminate`). The schema fetch hook (`ICredentialSchemaResolver`) pre-fetches so the caller controls egress and SRI.

### Engine crypto via crypto-dotnet (FR-052)

All engine-owned randomness — SD-JWT decoy/salt requests, BBS per-credential HMAC key, BBS derive presentation-header, holder-binding nonces — routes through a single `NetCrypto` RNG seam (`IRandomProvider`/`Rng.GetBytes`; if `NetCrypto` lacks one it is added there — fix **F9**, no reaching around the substrate). All hashing/digests (including `digestSRI`) use `NetCrypto.Hash`. Holder-binding key→JWK uses `NetCrypto.JwkConversion`. SD-JWT salts/digests proper are owned inside `DataProofsDotnet`. The core data model is crypto-free; this lives in the role services/mechanisms.

### Verifier pipeline internals (FR-040/043/045)

An ordered, gated, planner-selected list of stages over an **immutable forward-flowing accumulator** (no mutable shared `CredentialContext` with `set` accessors — fix **F4**): each stage returns `(CheckOutcome, StageFacts?)` where `StageFacts` is an immutable record (proof-authorized issuer, disclosed payload as an **owned, cloned** `JsonElement` — never a borrowed `RootElement`); the orchestrator folds facts into the accumulator for the next stage. Stage order: **proof → structure → validity → status → schema → trust**. Proof is the gate and authorizes the issuer that trust/status consume (never a self-asserted `issuer`). `SafeRun` wraps every stage: operational exceptions → `Indeterminate`; only `CredentialFormatException` (malformed input) and `ArgumentNullException` (programming error) propagate; cancellation rethrows. A bad **signature** is always `Failed`, never `Indeterminate` — proof stages prefer result-returning dataproofs APIs (COSE/SD-JWT), and the JOSE stage maps the full dataproofs crypto-negative exception taxonomy to `Failed`, reserving `Indeterminate` strictly for resolver/I-O failures (fix **F7**). The net-did→dataproofs `NetDidVerificationMethodResolver` adapter bridges identity (FR-080); `ICredentialTypeMetadataResolver` is a credentials-dotnet-owned wrapper over the draft `ITypeMetadataResolver` (fix **F3**).

### Conformance-critical structural validation (folded fixes)

`StructuralValidator.Validate(JsonObject, VcRole, VcdmVersion)` — **one unified signature** across issuer `Seal()` and verifier `StructureStage` (fix **A2**). It operates on the **raw node**, not the lossy projection. Rules, with conformance fixes:

- **`@context[0]` exact-string match per version** (fix **A1**): 2.0 requires `https://www.w3.org/ns/credentials/v2` exactly; 1.1 requires `https://www.w3.org/2018/credentials/v1` exactly. Object-at-index-0 is a distinct failure. `VersionProjection.Detect` is **positive** — `V2_0`/`V1_1` by exact base-URL match, else `Unknown ⇒ reject` (no "v2 else 1.1" fallback) (fix **D1**).
- **`type` shape validated explicitly** (string | non-empty array of strings); `type_invalid_shape` distinct from `type_missing_base`; non-string array members never coerced (fix **A3**).
- **`credentialSubject`** required as a non-empty `JsonObject` or non-empty array of objects; `subject_invalid_shape`/`subject_empty` (fix **B1**).
- **`validFrom`/`validUntil` `xsd:dateTimeStamp` strictness** (fix **C1**): regex-assert a mandatory offset (`Z` or `±hh:mm`) and parse with `DateTimeStyles.AssumeUniversal | RoundtripKind`; an offset-less string is `structure.invalid`, never a silently-localized parse. `validUntil < validFrom` ⇒ `validity.window_inverted` (fix **C2**).
- **Version-mix + 1.1 required fields** (fix **D1**): 2.0 forbids `issuanceDate`/`expirationDate`; 1.1 **requires** `issuanceDate` and forbids `validFrom`/`validUntil`. A single `ValidityProjection` (shared by the typed layer and the verifier) applies the `issuanceDate→validFrom` / `expirationDate→validUntil` fallback exactly once.
- **Typed-member `type` requirements** (fix **H2–H4**): `id` is a single URL where present; object-form `issuer` requires `id`; `credentialStatus`/`credentialSchema`/`termsOfUse`/`evidence` each require a `type`.
- VP structural check is **version-detected from the VP's `@context[0]`**, not hardcoded to 2.0, so a 1.1 VP is accepted (fix **F8**).

Structured `StructuralProblem { Code, JsonPointer, Message }`; validation runs at `Seal()` (throws — issuance bug) and on-demand from the Verifier (returns, never throws — FR-045), not on every typed read.

---

## 6. Phased build plan

Each milestone lists the FRs it satisfies, the files/types added, substrate dependencies, and acceptance tied to §9 DoD.

### M0 — Skeleton, DI, core model
- **FRs:** FR-001..005 (data model + structural validation), the DI surface, FR-052 RNG/Hash seam.
- **Adds:** solution + all csproj + props; `Credentials/{CredentialDocument, CredentialJson, Credential, VerifiablePresentation, CredentialBuilder, VerifiablePresentationBuilder, ContainedCredential, SecuringState, DocumentOrigin, VcdmVersion}`; `Credentials.Validation/{StructuralValidator, VersionProjection, ValidityProjection, JsonShape, StructuralProblem, VcRole}`; projections (`ContextProjection`, `IssuerProjection`, `SubjectProjection`, `SchemaProjection`, `StatusProjection`); `Credentials.Core.Securing.RngSeam` over `NetCrypto`; `AddCredentials` + `CredentialsBuilder` + `CredentialsOptions` (roles registered, throwing-on-use placeholders until later milestones).
- **Deps:** `NetCrypto` (RNG/Hash), `Microsoft.Extensions.DependencyInjection.Abstractions`.
- **Acceptance:** unit tests for FR-001..005 incl. all conformance structural fixes (A1–A3, B1, C1–C2, D1, F8, H2–H4) as **negative-test cases**; `CredentialJson.Faithful` byte-mirror test vs `DataProofsJsonOptions.Default` (F1); thread-safety/immutability tests (NFR-003); `AddCredentials` fail-fast tests.

### M1 — Embedded issue + verify, EdDSA/ECDSA
- **FRs:** FR-010, FR-011, FR-015, FR-040, FR-043, FR-045, FR-050, FR-053, FR-080.
- **Adds:** the securing seam (`ISecuringMechanism`, `SecuringMechanismRegistry`, `SecureRequest/VerifyRequest/SecuringVerificationResult`, `SecuringForm/SecuringSelector`, `ISecuringCapabilities`); `DataIntegrityMechanism`; `DefaultIssuer` + `IssuanceRequest`/`IssuedCredential`; `Verifier` + planner + stages (`DataIntegrityProofStage`, `StructureStage`, `ValidityPeriodStage`, `SafeRun`, forward-flowing `StageFacts`); result model (`CheckResult/CheckOutcome/CheckStatus/CheckKinds/CheckDiagnostic`, `CredentialVerificationResult`, `VerificationPolicy`, `DecisionComposer`); `NetDidVerificationMethodResolver` adapter.
- **Deps:** `DataProofsDotnet.Core`, `DataProofsDotnet.Rdfc` (for RDFC suites), `NetDid.Core`.
- **Acceptance:** issue→verify for eddsa-jcs-2022, ecdsa-jcs-2019, eddsa-rdfc-2022, ecdsa-rdfc-2019 with in-memory keys; report-don't-throw (F7 mapping: tampered signature ⇒ `Rejected`, not `Indeterminate`); F4 immutable-accumulator test; suite-by-string FR-053 test (registering an extra suite needs no API change); round-trip fidelity for DI (feeds M8 DoD).

### M2 — Status + schema
- **FRs:** FR-016, FR-020, FR-021, FR-022, FR-070.
- **Adds:** `Credentials.Status/{StatusBitstring, StatusListManager, BitstringStatusListEntry, StatusPurpose, IStatusListFetcher, StatusCheckResult, StatusCheckDetail}` + `StatusStage`; `Credentials.Schema/{ICredentialSchemaResolver, ResolvedSchema, SchemaDialect, ICredentialSchemaValidator, SchemaValidatorRegistry (FrozenDictionary, ctor-injected), JsonSchema2020Validator, SchemaCheckResult}` + `SchemaStage`; `Sha256SchemaIntegrityChecker` over the `NetCrypto.Hash` seam; `IStatusListCredentialProofVerifier` seam onto the core Verifier.
- **Deps:** `NetCid` (multibase), `JsonSchema.Net`, `NetCrypto` (Hash).
- **Acceptance:** status produce/set/clear/reinstate/verify incl. multibase `maxInputLength` and GZIP-bomb bound; E1/E2 fixes (list type/purpose guard, stale-list validity); schema JsonSchema + JsonSchemaCredential with digestSRI tri-state; status-list-VC own-proof recursion.

### M3 — Enveloping VC-JOSE-COSE
- **FRs:** FR-012 (both serializations).
- **Adds:** `JoseEnvelopingMechanism`, `CoseEnvelopingMechanism`; `JoseEnvelopeProofStage`, `CoseEnvelopeProofStage`; `IIssuerJwkResolver` (net-did kid→Jwk adapter); `IngestCompact` envelope decode in the Holder.
- **Deps:** `DataProofsDotnet.Jose`, `DataProofsDotnet.Cose`.
- **Acceptance:** issue→verify JOSE (EdDSA, ES256) and COSE (EdDsa, ES256) over exact bytes; `typ`/content-type header pinned & asserted (G1); round-trip uses verbatim wire bytes (no payload re-serialize). OQ-4 resolved: **JOSE first, then COSE** within this milestone.

### M4 — SD-JWT VC
- **FRs:** FR-013, FR-051 (D12).
- **Adds:** `SdJwtVcMechanism`; `SdJwtVcRequest`/`DisclosureSelector`/`HolderBindingKey`/`SdHashName` (draft-free); `SdJwtVcProofStage`; `ICredentialTypeMetadataResolver` wrapper (F3); `InspectSdJwt`/`SdJwtInspection`/`DisclosableClaim` in the Holder.
- **Deps:** `DataProofsDotnet.Jose` (SD-JWT VC).
- **Acceptance:** issue with vct + path-selected disclosures + optional cnf; `typ=dc+sd-jwt`/media `application/dc+sd-jwt`/vct-non-disclosable/reserved-claims-rejected asserted (F1); no draft type on the surface (CI surface test, F3).

### M5 — bbs-2023 selective disclosure
- **FRs:** FR-014, FR-031, FR-042.
- **Adds:** `Bbs2023Mechanism` (`ISelectiveDisclosureMechanism`), `Bbs2023BaseRequest`, `BbsDisclosureRequest`/`BbsDisclosureMap`, `InspectBbsBase`, `DeriveBbsDisclosureAsync`; BBS branch in `DataIntegrityProofStage` (auto-dispatch derived-proof verify).
- **Deps:** `DataProofsDotnet.Rdfc` (`Bbs2023Cryptosuite`), `NetCrypto` (`IBbsCryptoProvider` indirectly + RNG).
- **Acceptance:** base issue → derive → verify; mandatory group always revealed; two unlinkable derivations both verify; **F2 fix in place** — issuance uses the dataproofs key-store-alias BBS create API that returns the assembled document (no raw-key export, no core-side `["proof"]=`); BBS issuance is gated/skip-marked until that dataproofs API ships (does not block M1–M4/M6 or the rest). Derive path uses `NetCrypto` RNG for the presentation header (F9). `IsAvailable`-gated.

### M6 — Presentations + holder binding
- **FRs:** FR-002, FR-030, FR-032, FR-033, FR-034, FR-041.
- **Adds:** `IHolder` + `HeldCredential` + `HolderIngest`; `PresentSdJwtAsync`/`SdJwtPresentationRequest`/`SdJwtPresentation`; `BuildPresentation`/`VpAssemblyRequest`; `BindWithDataIntegrityAsync`/`BindWithJoseEnvelopeAsync`/`VpBindingRequest`; `IHolderKeyResolver`/`HolderKeyRef`; `PresentationOrchestrator` + `VerifyPresentationAsync`.
- **Deps:** `DataProofsDotnet.Jose` (SdJwtHolder KB-JWT), `NetDid` (holder key).
- **Acceptance:** VP from ≥1 credentials (embedded + enveloped verbatim children); DI authentication-proof binding with challenge/domain and JOSE `vp+jwt` binding; SD-JWT KB-JWT with `aud`/`nonce`/`iat`/**`sd_hash`** asserted (F1); per-contained-credential verification; F5 fix — BBS/SD-JWT present paths are honestly async (no fake `Task.FromResult` over blocking FFI; CPU-bound work offloaded at the role boundary with an explicit note).

### M7 — VCDM 1.1 verify
- **FRs:** FR-044 (D8).
- **Adds:** 1.1 branches in `VersionProjection`/`StructuralValidator`/`ValidityProjection`; `AcceptVcdm11` honored on credential **and** presentation paths (F8).
- **Deps:** none new.
- **Acceptance:** 1.1 credential and 1.1 VP fixtures verify and round-trip (no upgrade); positive version detection rejects `Unknown`; issuance stays 2.0-only.

### M8 — Conformance + interop + samples + API-coverage gate
- **FRs:** all (validation), NFR-002/005/007/008/009.
- **Adds:** `Credentials.Conformance.VcApi` + `Credentials.Conformance.Tests`; `Credentials.InteropTests` (+vectors + no-Newtonsoft closure + `Credentials.ConsumerProbe`); `Credentials.RoundTripTests`; `Credentials.ArchitectureTests`; 14 `samples/*` + `Credentials.Samples.Shared` + `Credentials.SampleSmokeTests`; `tools/api-coverage` + `tools/apicompat`; the three workflows.
- **Deps:** `Microsoft.AspNetCore.App` (shim), `Microsoft.DotNet.ApiCompat.Tool`, `Microsoft.CodeAnalysis.CSharp`.
- **Acceptance:** the full §9 DoD — every FR has tests; W3C VCDM 2.0 conformance passes (mandatory groups, incl. the negative corpus the conformance fixes target); bbs-2023 + SD-JWT VC interop vectors pass where published (bbs `IsAvailable`-gated); round-trip fidelity green; samples run + API-coverage gate green; no-Newtonsoft + no-draft-type surface + XML-doc + semver gates green.

---

## 7. Testing, samples & CI

**Unit** (`Credentials.Core.Tests`, `Credentials.Extensions.DependencyInjection.Tests`): xUnit + FluentAssertions + NSubstitute; pure/offline (hooks and `ISigner`/`IKeyStore`/resolvers mocked). Folder→FR matrix covers every FR; an `[FrTag]`-driven `FrCoverage_EveryRequirement_HasAtLeastOneTest` fails CI if a new FR lands untested. The conformance structural fixes ship as explicit negative-test cases (~60% of the W3C suite is negative — the design fails *closed* on each).

**Round-trip fidelity** (`Credentials.RoundTripTests`, §9 DoD, FR-003): issue→serialize→parse→verify with in-memory keys, per securing family. Drift guards: byte-perfect round-trip; member-order preserved; core never strips/adds `proof`; enveloping uses verbatim wire bytes; golden-bytes test (signed bytes == wire bytes); `<>&`/non-BMP-emoji built-credential round-trips and verifies (relaxed-escaping check, fix **H1**).

**W3C VCDM 2.0 conformance** (`conformance.yml`): `Credentials.Conformance.VcApi` ASP.NET shim exposes `POST /credentials/issue`, `/credentials/verify`, `/presentations/verify` over `IIssuer`/`IVerifier`; `Credentials.Conformance.Tests` starts it on loopback, writes `localConfig.cjs`, runs the Node `w3c/vc-data-model-2.0-test-suite`, asserts zero mandatory-group failures, uploads Allure.

**Interop vectors** (`Credentials.InteropTests`, NFR-007): vendored SD-JWT VC vectors (draft-16 worked examples + OWF corpus) asserting disclosure sets + KB + the negative cases (tampered disclosure, duplicate digest, disclosure-not-in-`_sd` — fix **F2/F1**); bbs-2023 vectors (`vc-di-bbs`) `[Trait("Category","Bbs")]` **skip-gated on `IsAvailable`**; drift sentinels pin `dc+sd-jwt` and the bbs proofValue prefixes.

**Samples matrix** (`samples/`, first-class): 14 console projects (role × form + status + schema + trust allowlist + 1.1 verify) each with `Program.RunAsync(TextWriter, IServiceProvider?)` emitting FR-banner narration, plus `Credentials.Samples.Shared`. All use `InMemoryKeyStore` + `did:key`, offline.

**API-coverage gate** (§8 deliverable): `tools/api-coverage` (Roslyn) enumerates the public surface (honoring `[ExcludeFromApiCoverage]`); `Credentials.SampleSmokeTests` runs every sample's `RunAsync` in-process under coverlet scoped to the two library assemblies; the tool diffs covered-vs-public-surface and fails on any uncovered member.

**Other gates:** **semver** — `Microsoft.DotNet.ApiCompat.Tool` against a committed baseline + `PublicAPI.{Shipped,Unshipped}.txt` analyzers (RS0016/RS0017); **XML-doc** — CS1591 promoted to error in `src/*` (1591 removed from `NoWarn`) + an assertion test catching empty docs; **no-Newtonsoft** — pack `Credentials.Core`, restore `Credentials.ConsumerProbe` against it, assert `Newtonsoft.Json` absent from the transitive closure, plus a public-surface reflection test and a runtime "no Newtonsoft loaded after exercising non-RDFC paths" test; **no-draft-type surface** — `PublicSurface_ExposesNoDataProofsDraftType` asserts no `DataProofsDotnet.Jose.SdJwt`/`Bbs2023*`/`ITypeMetadataResolver`/`DataProofsBuilder` type appears in any public signature (fix **F3**).

**Workflows:** `ci.yml` (ubuntu+windows matrix, `dotnet build /warnaserror` = XML-doc gate, `dotnet test` excl. `Category=Conformance`, plus `api-coverage`/`semver-gate`/`no-newtonsoft` jobs — all block merge); `conformance.yml` (Node+.NET, PR + nightly); `release.yml` (tag-driven, `environment: nuget-release`, regenerates ApiCompat baseline, packs `.nupkg`+`.snupkg`).

---

## 8. Requirement coverage table

| Req | Milestone | Component |
|---|---|---|
| FR-001 | M0 | `Credential`/`CredentialBuilder` projections + `GetMember` escape hatch |
| FR-002 | M0/M6 | `VerifiablePresentation` + `ContainedCredential` |
| FR-003 | M0/M8 | `CredentialDocument` (verbatim bytes/serialize-once) + RoundTripTests |
| FR-004 | M0 | Lazy projections over frozen document |
| FR-005 | M0 | `StructuralValidator` (conformance fixes A1–A3,B1,C1–C2,D1,F8,H2–H4) |
| FR-010 | M1 | `IIssuer.BuildCredential` / `CredentialContent` |
| FR-011 | M1 | `DataIntegrityMechanism` + `DataIntegrityRequest` |
| FR-012 | M3 | `Jose`/`CoseEnvelopingMechanism` (both serializations) |
| FR-013 | M4 | `SdJwtVcMechanism` + `SdJwtVcRequest` |
| FR-014 | M5 | `Bbs2023Mechanism` base (F2 key-store-alias create) |
| FR-015 | M1/M5 | `ISigner` everywhere; BBS raw-key pushed below boundary (F2) |
| FR-016 | M2 | `BitstringStatusListEntry` → `CredentialContent.CredentialStatus` |
| FR-020 | M2 | `StatusBitstring` + `StatusListManager` |
| FR-021 | M2 | `StatusListManager` set/clear/update/re-produce |
| FR-022 | M2 | `StatusStage` + `IStatusListFetcher` (E1/E2 fixes) |
| FR-030 | M6 | `IHolder.Ingest`/`HeldCredential` read-only projections |
| FR-031 | M5 | `DeriveBbsDisclosureAsync` → `DeriveProof` |
| FR-032 | M6 | `PresentSdJwtAsync` → `SdJwtHolder` KB-JWT |
| FR-033 | M6 | `BuildPresentation`/`VpAssemblyRequest` |
| FR-034 | M6 | `BindWith{DataIntegrity,JoseEnvelope}Async` via net-did |
| FR-040 | M1 | `Verifier` pipeline + stages |
| FR-041 | M6 | `PresentationOrchestrator` |
| FR-042 | M5/M6 | DI bbs derived + SD-JWT proof stages |
| FR-043 | M1 | `CredentialVerificationResult`/`CheckResult` (three-state) |
| FR-044 | M7 | `VersionProjection`/version-aware validator+validity (D1/F8) |
| FR-045 | M1 | `SafeRun` boundary; bad-signature⇒Failed (F7) |
| FR-050 | M1+ | `ISecuringMechanism` sole dataproofs caller; no core canon/proof (F1/F2) |
| FR-051 | M4 | SD-JWT draft types confined; surface test (F3) |
| FR-052 | M0+ | `NetCrypto` RNG/Hash seam (F9); JwkConversion; salts in dataproofs |
| FR-053 | M1+ | `SecuringMechanismRegistry` opaque suite strings + `ISecuringCapabilities` |
| FR-070 | M2 | `JsonSchema2020Validator` + immutable `SchemaValidatorRegistry` (F6/D9) |
| FR-080 | M1+ | `NetDidVerificationMethodResolver`, `ISigner`/`IKeyStore`/`IHolderKeyResolver` |
| FR-081 | M1/M2 | Three injected hooks via `AddCredentials` builder |
| FR-082 | M1 | `IIssuerTrustPolicy` structured result; allowlist sample (OQ-1) |
| NFR-001 | M0 | net10.0 / LangVersion=latest |
| NFR-002 | M0/M8 | STJ + JsonSchema.Net; no-Newtonsoft closure gate |
| NFR-003 | M0+ | Frozen-by-default core; immutable accumulator (F4); FrozenDictionary registries (F6); singleton roles |
| NFR-004 | M1+ | async/ValueTask; honest-async derive/present (F5) |
| NFR-005 | M8 | ApiCompat + PublicAPI analyzers; no draft types (F3) |
| NFR-006 | M5 | No raw-key export (F2); bounded untrusted input/GZIP |
| NFR-007 | M8 | Conformance shim + interop vectors |
| NFR-008 | M1 | Secret-free per-check diagnostics; code-mapped messages (F10) |
| NFR-009 | M0/M8 | CS1591-as-error + XML-doc assertion test |

**At risk (track to closure before/at M5/M8):**
- **FR-014/FR-015/NFR-006 (BBS issuance):** depends on a `DataProofsDotnet` BBS create API that takes an `IKeyStore` alias / `IBbsCryptoProvider` handle and returns the assembled document. Until it lands, BBS *issuance* is gated and skip-marked (R-1). BBS *derivation*/*verify* are unaffected.
- **NFR-007 (conformance):** designed and wired but pass/fail is empirical; the negative-corpus fixes are the mitigation, results published at M8.

---

## 9. Risks & open questions

**OQ-1 — `IIssuerTrustPolicy` signature + structured trust result.** Resolved: `Task<IssuerTrustResult> EvaluateAsync(IssuerTrustContext, CancellationToken)`; `IssuerTrustResult { IssuerTrustDecision (Trusted/Untrusted/Indeterminate), ReasonCode, Reason, Diagnostics }` — decision **plus** reason, never a bool; invoked as an explicit optional step gated by `VerificationPolicy.EvaluateIssuerTrust`; absent⇒Skipped, throwing⇒Indeterminate; no built-in lists (allowlist sample only).

**OQ-2 — SD-JWT VC validation surface + draft-bump process.** Resolved at the seam: all SD-JWT draft types (`DisclosureFrame`/`SdJwtIssuerOptions`/`Jwk`/`ITypeMetadataResolver`) are confined to `SdJwtVcMechanism`; the public surface is `SdJwtVcRequest`/`DisclosureSelector`/`HolderBindingKey`/`SdHashName`. Bump process: a draft-16→17 move changes only the mechanism + the `DataProofsDotnet` dependency, with a drift-sentinel interop test pinning `dc+sd-jwt`/`typ`/`vct` so a silent draft move trips CI; no public-API change (NFR-005).

**OQ-3 — typed views over the document core.** Resolved by the chosen core model: document is the single source of truth; typed accessors are lazy projections gated on the frozen invariant, so they cannot drift; the three faithful projections (`AsElement`/`AsUtf8`/`AsClaimsObject`) map 1:1 to the three securing payload shapes; faithful-not-canonical serialization preserves issuer member order.

**OQ-4 — JOSE vs COSE first.** Resolved: **JOSE first, then COSE**, both within M3 (JOSE dominates the OpenID/EUDI consumer set the SD-JWT path also serves; COSE follows in the same milestone over `VcCose`).

**R-1 — `bbs-2023` is a CRD; interop depends on dataproofs wiring + zkryptium draft alignment.** Mitigation: BBS reached only via opaque suite string + the confined mechanism; `IsAvailable`-gated runtime + skip-gated interop vectors; the **F2** fix (no raw-key export; dataproofs returns the assembled document) is a hard precondition for BBS *issuance*, tracked as the one capability dependency that can defer FR-014 without blocking the rest; drift sentinels re-verify on each draft movement.

**R-2 — SD-JWT VC is a moving Internet-Draft.** Mitigation: D12 pin to draft-16, single-mechanism confinement, drift-sentinel + negative interop vectors; bump is mechanism-local (see OQ-2).

**R-3 — direct `crypto-dotnet` dependency vs architectural-path.** Mitigation: this plan and `architectural-path.md` §5.7/§3 both already record `credentials-dotnet → NetCrypto` as a direct edge for engine-owned crypto operations; the FR-052 RNG/Hash seam is the single, audited touch-point, keeping the dependency narrow and the same direct-dependency question for `zcap-dotnet`/`didcomm-dotnet` orthogonal to this library.

---

## 10. Implementation review — Milestone M0 (2026-06-18)

**Status: complete and green.** Clean Release build, 0 warnings (`TreatWarningsAsErrors`), **70/70 tests pass** (65 `Credentials.Core.Tests` + 5 `Credentials.Extensions.DependencyInjection.Tests`).

**Delivered**

- Repo scaffolding matching house conventions: `Credentials.sln`, central package management (`Directory.Packages.props`), `Directory.Build.props/.targets`, `global.json` (.NET 10, `rollForward latestFeature`), `nuget.config`, `.editorconfig`, Apache-2.0 `LICENSE`, thin-router `README.md`, `CHANGELOG.md`.
- Two `src` projects: `Credentials.Core` (the whole public surface) and `Credentials.Extensions.DependencyInjection`. Two test projects.
- Document-centric core (D10/OQ-3): `CredentialDocument` (frozen single source of truth, verbatim-byte fidelity for received docs, serialize-once-pinned for built docs, three faithful projections `ToElement`/`ToUtf8`/`ToClaimsObject`); `Credential` / `VerifiablePresentation` with lazy typed projections over the frozen document; write-through `CredentialBuilder` / `VerifiablePresentationBuilder`; `ContainedCredential`; enums.
- `CredentialJson.Faithful` — **F1 done via the `JsonSerializerOptions` copy-constructor over `DataProofsJsonOptions.Default`** (inherited, not hand-copied), with a byte-mirror assertion test.
- `StructuralValidator` with every conformance fix folded in (A1–A3, B1, C1–C2, D1, F8, H2–H4), each covered by a negative test.
- Engine crypto seams: `IDigestService`→`NetCryptoDigestService` (over `NetCrypto.Hash`); `IRandomSource`→`BclRandomSource`.
- `AddCredentials` + `CredentialsBuilder` + `CredentialsOptions`.

**Deviations from the M0 plan (deliberate, documented)**

1. **Role interfaces (`IIssuer`/`IHolder`/`IVerifier`) and their placeholder registration deferred to M1.** Defining their full signatures now would pull most of the §4 API surface (request/result types spanning M1–M6) into M0 as speculative code. M0 delivers the data model + validation + seams + DI skeleton instead; the substrate fail-fast checks land in M1 with the Issuer. The securing-seam types (`SecuringForm`/`SecuringSelector`/`ISecuringCapabilities`) likewise move to M1.
2. **RNG seam wraps the BCL, not `NetCrypto`.** Verified: `NetCrypto` 1.1.0 exposes **no** public RNG abstraction (digests via `NetCrypto.Hash` do go through the substrate, satisfying FR-052 for hashing). The completeness critic already flagged this as non-blocking. If `NetCrypto` later adds an RNG, swap `BclRandomSource` with no caller change.
3. **`Credential.Issuer` is nullable** (`Issuer?`) rather than the plan's non-null `Issuer`, so a typed read over a malformed received document never throws (consistent with report-don't-throw). The validator enforces issuer presence.
4. **`Credentials.Core` references `DataProofsDotnet.Core` in M0** (the plan listed only NetCrypto/DI for M0) — required for the F1 byte-mirror anchor.

**Corrections to the plan's recon (verified against the real packages)**

- `JsonSchema.Net` real latest is **7.3.2**, not the plan's `9.2.2` (affects M2). `DataProofsDotnet.*` real version is **1.0.1**.
- `DataProofsDotnet.DataProofsJsonOptions.Default` **exists** exactly as assumed (F1 is implementable as designed).
- `ISigner` is defined in **`NetCrypto`** (not `NetDid`); `DataIntegrityProofPipeline.AddProofAsync/VerifyAsync` confirmed — both relevant at M1.

**Adversarial review (2026-06-18).** Three independent adversarial agents attacked the M0 code (core-model immutability/fidelity, structural-validator false-accepts, parsing/untrusted-input/DI), each confirming findings by compiling and running exploits. Fixed and regression-tested (81 tests total):

- **Duplicate JSON keys (3-agent consensus, critical):** `JsonNode.Parse` admitted them and threw `ArgumentException` *lazily* on first access — breaking the parse/`ValidateStructure` "throws only `CredentialFormatException` / never throws" contract and splitting verbatim wire bytes from the parsed tree. Fixed with `AllowDuplicateProperties = false` (eager `JsonException` → wrapped), and `ToElement` now reuses the same `ParseOptions`.
- **No input-size bound (NFR-006 gap):** added `CredentialDocument.MaxInputBytes` (4 MiB).
- **Validator false-accepts:** `@context` entries after index 0 unchecked; `credentialSubject: [{}]`; blank/empty `issuer.id` / `holder.id` / top-level `id` / `credentialStatus.type` / `credentialSchema.id`. All now rejected.

Deferred with documented notes (latent/internal, not externally reachable): the internal `Root` getter exposes a mutable tree to friend assemblies (enforce when M1 securing lands — re-ingest, don't mutate frozen `Root`); `proof`-presence ≠ validity (doc note added); `GetMember` cannot distinguish absent from JSON-null. Verified-safe by the agents: public escape-by-reference (all clone), builder input-aliasing (deep-cloned), `Lazy`/serialize-once thread-safety, `FromElement` detachment, the F1 byte-mirror static init, and DI registration semantics.

**Next:** M1 — embedded Data Integrity issue + verify (EdDSA/ECDSA), the securing seam, the role interfaces, and the verifier pipeline.
