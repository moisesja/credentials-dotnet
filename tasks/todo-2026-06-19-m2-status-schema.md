# Milestone M2 — Status + Schema (+ issuer-trust hook)

**Status:** For approval (precedes any source).
**Date:** 2026-06-19.
**Branch:** `feature/m2-status-schema` off `main` (PR #1 / M1 merged at 3f4cb0d — verified).
**FRs:** FR-016, FR-020, FR-021, FR-022, FR-070, FR-081, FR-082. Turns the verifier's currently-`Skipped`
status / schema / issuer-trust checks into real checks, each gated on whether its hook is configured.
**Builds on:** the M1 verifier pipeline (`DefaultVerifier`), result model (`CheckResult`/`CheckStatus`/
`DecisionComposer`), securing seam, and typed projections.

---

## 0. Ground-truth recon (verified 2026-06-19 — supersedes the plan's earlier recon)

Captured to memory; the load-bearing facts:

**Bitstring Status List v1.0** (`https://www.w3.org/TR/vc-bitstring-status-list/`):
- `BitstringStatusListCredential`: `type` ⊇ `["VerifiableCredential","BitstringStatusListCredential"]`;
  `credentialSubject.type == "BitstringStatusList"` (no suffix); `credentialSubject.statusPurpose`;
  `credentialSubject.encodedList`. Optional `ttl`, `statusSize`, `statusMessage`, `statusReference`.
- `BitstringStatusListEntry` (the `credentialStatus`): `type == "BitstringStatusListEntry"`,
  `statusPurpose`, **`statusListIndex` is a STRING** (base-10, arbitrary size), `statusListCredential`
  (URL). Optional `statusSize`, `statusMessage`.
- Codec: bitstring **min 16 KiB = 131,072 bits**; **MSB-first** (index 0 = leftmost bit of byte 0 ⇒
  `byte = pos/8`, `mask = 0x80 >> (pos%8)`); `pos = statusListIndex * statusSize`. **GZIP (RFC 1952)
  FIRST, then multibase base64url** (`u`, unpadded). Decode = multibase-decode → GZIP-inflate.
- `statusSize` default 1; bit 1 = set (revoked/suspended), 0 = valid. `statusSize>1` ⇒ `statusMessage`
  of 2^N entries (`{status:"0x..",message}`); purpose `message`.
- Validate algorithm: dereference `statusListCredential`, **verify its proofs**, match purpose, expand
  bitstring, length-check `(bits/statusSize) ≥ 131,072` else `STATUS_LIST_LENGTH_ERROR`, range-check
  index else `RANGE_ERROR`, read bit. Temporal validity of the list VC is general VCDM 2.0 verification
  (so E2 = recurse through `IVerifier` with the validity window enabled). No normative gzip-bomb cap —
  **we impose our own**.

**NetCid 1.6.0** (`NetCid.Multibase`, runtime-verified): `Encode(ReadOnlySpan<byte>, MultibaseEncoding,
bool includePrefix = true)` (prefixes `u` by default); `Decode(string, out MultibaseEncoding, int
maxInputLength)` / `TryDecode(string, out byte[], out MultibaseEncoding, int maxInputLength)`.
`MultibaseEncoding.Base64Url` (prefix `u`), uses `System.Buffers.Text.Base64Url`, **unpadded**.
`DefaultMaxInputLength = 4096` bounds the **encoded text length on decode only** — too small for a real
list, so **always pass an explicit `maxInputLength`**. Decode throws `NetCid.CidFormatException`;
`maxInputLength<1` throws `ArgumentOutOfRangeException`. **NetCid does NO GZIP** — we GZIP ourselves.
Closure: NetCid → SimpleBase (zero deps). **No Newtonsoft** (NFR-002 ✔). NetCid is currently
*transitive* in `Credentials.Core` — must add an explicit `<PackageReference>`.

**JsonSchema.Net 7.3.2** (`Json.Schema`, from the package XML doc): `JsonSchema.FromText(string)` /
`FromText(string, JsonSerializerOptions)`; `schema.Evaluate(System.Text.Json.Nodes.JsonNode,
EvaluationOptions) → EvaluationResults`. `EvaluationOptions { EvaluateAs = SpecVersion.Draft202012,
RequireFormatValidation (format assertion), OutputFormat (Flag/List/Hierarchical), SchemaRegistry,
OnlyKnownFormats, ValidateAgainstMetaSchema }`. `EvaluationResults { IsValid, Details, Errors
(IReadOnlyDictionary<string,string>), HasErrors, InstanceLocation, EvaluationPath }`. STJ-native
(instance is a `JsonNode`). Parsed `JsonSchema` is reusable (build-once/evaluate-many). Closure:
JsonSchema.Net → JsonPointer.Net 5.3.1 → {Humanizer.Core 2.14.1, Json.More.Net 2.1.1 → System.Text.Json}.
**No Newtonsoft** (NFR-002 ✔); Humanizer.Core is a new benign STJ-clean transitive — note it. TFMs are
net8.0/net9.0/netstandard2.0 (net9.0 asset binds fine on net10.0).

**House conventions:** no existing status/multibase/gzip/schema helper anywhere to reuse — we own it.
Bounded-decompression idiom (didcomm `ReadCappedAsync`, net-did `ReadAtMostAsync`): cap on bytes
**produced**, 8 KiB buffer, running total, throw past cap. NSubstitute async hooks: `.Returns(value)`
(auto-wraps `Task<T>`), not `Task.FromResult`. DI optional hook = `sp.GetService<T>()` (null if absent);
required = `IsRegistered<T>` + throw. FluentAssertions pinned **7.0.0** (no 8.x API).

---

## 1. Invariants preserved (do not regress)

- **FR-050:** `DataIntegrityMechanism` stays the *sole* caller of the DataProofs pipeline. M2 adds no new
  DataProofs caller: status-list-VC proof verification recurses through `IVerifier` (which uses the
  mechanism); the codec uses NetCid + `System.IO.Compression`; the schema validator uses JsonSchema.Net;
  digestSRI uses the existing `IDigestService` (NetCrypto.Hash). ✔
- **NFR-002:** default closure stays System.Text.Json-only. New deps NetCid + JsonSchema.Net pull no
  Newtonsoft/dotNetRDF (verified). CI gate: `dotnet list ... --include-transitive` asserts no Newtonsoft.
- **NFR-005 / D12:** no draft/substrate types on the public API. The three hooks and their request/result
  records are credentials-dotnet-owned, draft-free.
- **FR-045:** report-don't-throw. Every new stage runs under the existing `SafeRun`/`SafeRunAsync`; a set
  revocation/suspension bit ⇒ `Failed`; operational faults (unreachable list, unresolvable schema,
  unverifiable list proof, stale list) ⇒ `Indeterminate`; only malformed input / programming errors
  propagate. `DecisionComposer` stays fail-closed.
- **Issuer binding / proof-as-gate:** issuer-trust consumes the **proof-verified** issuer (the base DID
  bound by the proof stage), never the self-asserted `issuer`. Trust runs only when the proof passed.
- **Frozen `CredentialDocument`:** status-list construction/update produces *new* unsecured credentials
  via `CredentialDocument.FromElement(...)` / builder — never mutates a frozen `Root`.

---

## 2. Dependencies

- Add to `src/Credentials.Core/Credentials.Core.csproj`: `<PackageReference Include="NetCid" />`,
  `<PackageReference Include="JsonSchema.Net" />` (both already pinned in `Directory.Packages.props`).
- Add to `src/Credentials.Extensions.DependencyInjection/...csproj`:
  `<PackageReference Include="Microsoft.Extensions.Http" />` (for the opt-in HTTP convenience resolvers).
- No version bumps. No new package added to `Directory.Packages.props` (all pre-pinned).

---

## 3. New public surface (all draft-free; XML-doc'd — NFR-009)

### `Credentials.Status`
- `static class StatusPurpose` — consts `Revocation`/`Suspension`/`Message`/`Refresh` (open string set).
- `sealed class BitstringStatusListEntry` — typed **builder** helper for FR-016: `Id?`, `StatusPurpose`,
  `StatusListIndex` (string), `StatusListCredential` (URL), `StatusSize?`; `JsonObject ToJsonObject()`.
- `sealed class StatusListManager` — issuer-side (FR-020/021): `CreateList(StatusListCreateOptions)` →
  unsecured `Credential` (all-zeros, ≥131,072 bits, `credentialSubject.{type,statusPurpose,encodedList}`);
  `WithStatus(Credential list, long index, bool set)` → new unsecured `Credential` (re-encoded);
  `Revoke`/`Suspend` (set) / `Reinstate` (clear) convenience; `bool GetStatus(Credential list, long index)`.
  One bitstring per purpose. Stateless; operates on the credential as source of truth.
- `interface IStatusListFetcher` (hook): `Task<StatusListFetchResult> FetchAsync(StatusListReference, CancellationToken)`.
  - `StatusListReference { StatusListCredential, StatusPurpose, StatusListIndex, StatusSize, JsonObject Raw }`.
  - `StatusListFetchResult` — `Found(ReadOnlyMemory<byte> securedListVc)` / `NotFound(reasonCode)`; returns
    the **secured** list VC so the verifier checks its proof.
- `sealed record StatusCheckResult { StatusCheckDetail[] Details }`; `StatusCheckDetail { StatusPurpose,
  IsSet, Value?, StatusMessage? }` — secret-free, logging-safe.

### `Credentials.Schema`
- `interface ICredentialSchemaResolver` (hook): `Task<SchemaResolutionResult> ResolveAsync(SchemaReference, CancellationToken)`.
  - `SchemaReference { Id, Type, ExpectedDigestSri?, JsonObject Raw }` (from the `credentialSchema` entry).
  - `SchemaResolutionResult` — `Found(ResolvedSchema)` / `NotFound(reasonCode)`.
  - `ResolvedSchema { Id, SchemaDialect Dialect, ReadOnlyMemory<byte> Content }` — dialect-abstracted,
    **raw bytes** so the engine enforces `digestSRI` itself (NFR-006/FR-052), SHACL-ready (D9).
- `enum SchemaDialect { JsonSchema2020_12 }` (future `Shacl`).
- `interface ICredentialSchemaValidator { string SchemaType { get; } SchemaCheckResult Validate(ResolvedSchema, JsonElement credential); }`
  — the SHACL-ready seam, keyed by `credentialSchema.type`.
- `sealed record SchemaCheckResult` — tri-state `Success`/`Failure`/`Indeterminate` + diagnostics.

### `Credentials.Trust`
- `interface IIssuerTrustPolicy` (hook): `Task<IssuerTrustResult> EvaluateAsync(IssuerTrustContext, CancellationToken)`.
- `sealed class IssuerTrustContext { IssuerId (proof-verified base DID), CredentialTypes, VerificationMethods
  (proof-verified), Mechanism, CredentialId?, EvaluatedAt, JsonElement Document }` — never claims/keys (NFR-008).
- `sealed record IssuerTrustResult { IssuerTrustDecision Decision; ReasonCode; Reason; CheckDiagnostic[] Diagnostics }`
  + `Trusted/Untrusted/Indeterminate` factories. `enum IssuerTrustDecision { Trusted, Untrusted, Indeterminate }`.
- **No built-in trust list ships** (FR-082); a single allowlist example lives in tests (samples/ is M8).

### `Credentials.Verification` (additions)
- `CredentialVerificationOptions` gains `bool CheckStatus = true`, `bool CheckSchema = true`,
  `bool EvaluateIssuerTrust = true` (enable toggles; an unconfigured hook ⇒ `Skipped` regardless).
  *Per-check `*IsRequired` flags from the master plan §4 are deferred* — fail-closed default already
  rejects a configured-but-`Indeterminate` check; documented as a follow-on.

### Builder (FR-016)
- `CredentialBuilder.AddStatus(BitstringStatusListEntry)` convenience overload over the existing
  `AddStatus(JsonObject)`.

---

## 4. Internal components

### `Credentials.Status` (internal)
- `static class StatusBitstring` — the codec:
  - `string Encode(ReadOnlySpan<byte> bitstring)` — GZIP → `Multibase.Encode(gz, Base64Url)` (`u`, unpadded).
  - `byte[] Decode(string encodedList, int maxEncodedChars, long maxInflatedBytes)` —
    `Multibase.TryDecode(..., maxEncodedChars)` + guard `encoding == Base64Url`, then **bounded** GZIP
    inflate (cap on bytes produced — zip-bomb defense), then **floor-check** `length ≥ 16,384 bytes`.
  - `bool GetBit(byte[] bits, long pos)` / `void SetBit(byte[] bits, long pos, bool)` — MSB-first,
    range-checked (`pos<0 || pos≥len*8` ⇒ throws → mapped to Indeterminate/RANGE).
  - consts `MinimumBits = 131_072`, `MinimumBytes = 16_384`, `DefaultMaxInflatedBytes` (generous cap,
    e.g. 16 MiB ⇒ ~134M entries), `maxEncodedChars` derived from the inflate cap.
- `sealed class StatusStage` — verifier stage; holds `IStatusListFetcher?` + a `ILogger`. Signature
  `Task<CheckResult> EvaluateAsync(Credential, CredentialVerificationOptions, IVerifier verifier, CancellationToken)`
  (the `verifier` is passed by `DefaultVerifier` as `this` → recursion with **no DI cycle**). Per entry:
  1. parse entry (`type=="BitstringStatusListEntry"`, purpose, index-from-string, list URL, statusSize);
  2. fetch (miss ⇒ `Indeterminate status.list_unreachable`);
  3. parse + **recurse** `verifier.VerifyCredentialAsync(listVc, {CheckStatus=false, CheckSchema=false,
     EvaluateIssuerTrust=false, AcceptVcdm11=outer})` — not `Accepted` ⇒ `Indeterminate
     status.list_proof_unverified` (covers bad proof **and** stale/expired list — fix **E2**);
  4. assert list `type` ⊇ `BitstringStatusListCredential` & subject `type=="BitstringStatusList"` (fix **E1**);
  5. match entry purpose ∈ list purposes (fix **E1**; mismatch ⇒ `Indeterminate status.purpose_mismatch`);
  6. decode (bounded) + length-floor + range-check (failures ⇒ `Indeterminate`);
  7. read bit ⇒ set+revocation ⇒ `Failed status.revoked`; set+suspension ⇒ `Failed status.suspended`;
     `message` ⇒ `Passed` + detail; clear ⇒ `Passed`.
  - Multiple entries: evaluate all, aggregate worst (Failed > Indeterminate > Passed).
  - **Gating ⇒ `Skipped`:** no `credentialStatus` member / `CheckStatus==false` / no fetcher registered.
  - Recursion guarded: inner verify disables status (no infinite recursion on a self-referential list).

### `Credentials.Schema` (internal)
- `sealed class SchemaValidatorRegistry` — ctor `(IEnumerable<ICredentialSchemaValidator>)`, backed by
  `FrozenDictionary<string, ICredentialSchemaValidator>` keyed on `SchemaType`, **no public Register**
  (fix **F6**); `TryGet(type)`.
- `sealed class JsonSchema2020Validator : ICredentialSchemaValidator` — `SchemaType = "JsonSchema"`.
  `JsonSchema.FromText(content)` → `Evaluate(credentialNode, new EvaluationOptions { EvaluateAs =
  SpecVersion.Draft202012, RequireFormatValidation = true, OutputFormat = OutputFormat.List })`; read
  `IsValid` + flatten `Details`/`Errors` to secret-free diagnostics. Tri-state: malformed/garbage schema
  or evaluation fault ⇒ `Indeterminate`.
- `sealed class SchemaStage` — holds `ICredentialSchemaResolver?`, `SchemaValidatorRegistry`,
  `IDigestService`. Per `credentialSchema` entry: read type/id/`digestSRI`; resolve (miss ⇒
  `Indeterminate schema.unresolvable`); **enforce `digestSRI` over the fetched bytes via `IDigestService`
  before parsing** (mismatch ⇒ `Failed schema.digest_mismatch`); dispatch to the registry validator
  (unknown type ⇒ `Indeterminate schema.unknown_type`); map Success⇒Passed / Failure⇒Failed /
  Indeterminate⇒Indeterminate. **Gating ⇒ Skipped:** no `credentialSchema` / `CheckSchema==false` /
  no resolver registered.
  - **`JsonSchemaCredential`** (the schema wrapped in a VC): detected by entry `type`; the wrapper VC's
    proof is verified by recursion through `IVerifier` (same machinery as status), then the inner
    `credentialSubject.jsonSchema` feeds `JsonSchema2020Validator`. *Scope note: `JsonSchema` is the
    primary deliverable; `JsonSchemaCredential` is included reusing the status recursion — if it proves
    larger than estimated it ships in a fast-follow, `JsonSchema` is the M2 commitment.*

### `Credentials.Verification` (internal)
- `DefaultVerifier` constructor gains `StatusStage`, `SchemaStage`, `IIssuerTrustPolicy?`. The three
  `Skipped` placeholders (lines 43–45) become real, gated calls. A single forward-flowed fact — the
  **proof-verified issuer id** (= `credential.Issuer?.Id` *iff* the proof check Passed, else null) — is
  captured after the proof stage and handed to the issuer-trust step (trust `Skipped` with
  `issuer_not_authenticated` when null). Trust mapping: `Untrusted⇒Failed`, `Indeterminate⇒Indeterminate`,
  absent policy / disabled ⇒ `Skipped`, throwing policy ⇒ `Indeterminate` (via `SafeRun`).
- `CheckKinds` already has `Status`/`Schema`/`IssuerTrust` — reused, no change.

### DI (`Credentials.Extensions.DependencyInjection`)
- `CredentialsBuilder`: `UseStatusListFetcher<T>()/(instance)`, `UseSchemaResolver<T>()/(instance)`,
  `UseIssuerTrustPolicy<T>()/(instance)`, plus opt-in `UseHttpStatusListFetcher()` /
  `UseHttpSchemaResolver()` (bounded-read `HttpClient` impls via `IHttpClientFactory`; **documented as
  caller-egress-controlled — SSRF is the caller's responsibility**, no auto-egress by default).
- `AddCredentials`: `TryAddEnumerable(ICredentialSchemaValidator ← JsonSchema2020Validator)`;
  `TryAddSingleton(SchemaValidatorRegistry ← collected validators)`; `TryAddSingleton(StatusStage ←
  GetService<IStatusListFetcher>())`; `TryAddSingleton(SchemaStage ← GetService<ICredentialSchemaResolver>(),
  SchemaValidatorRegistry, IDigestService)`; `TryAddSingleton<StatusListManager>()`; update the
  `DefaultVerifier` registration to inject the two stages + `GetService<IIssuerTrustPolicy>()`. All hooks
  optional (no new fail-fast).

---

## 5. File plan

**Add — `src/Credentials.Core/`:**
- `Status/StatusPurpose.cs`, `Status/BitstringStatusListEntry.cs`, `Status/StatusBitstring.cs`,
  `Status/StatusListManager.cs`, `Status/IStatusListFetcher.cs`, `Status/StatusMessages.cs`
  (`StatusListReference`, `StatusListFetchResult`, `StatusCheckResult`, `StatusCheckDetail`),
  `Status/Internal/StatusStage.cs`.
- `Schema/ICredentialSchemaResolver.cs`, `Schema/SchemaModels.cs` (`SchemaReference`,
  `SchemaResolutionResult`, `ResolvedSchema`, `SchemaDialect`, `SchemaCheckResult`),
  `Schema/ICredentialSchemaValidator.cs`, `Schema/Internal/SchemaValidatorRegistry.cs`,
  `Schema/Internal/JsonSchema2020Validator.cs`, `Schema/Internal/SchemaStage.cs`.
- `Trust/IIssuerTrustPolicy.cs`, `Trust/TrustModels.cs` (`IssuerTrustContext`, `IssuerTrustResult`,
  `IssuerTrustDecision`).
- `Status/Internal/BoundedGzip.cs` (cap-on-produced-bytes inflate helper).

**Edit — `src/Credentials.Core/`:** `Roles/DefaultVerifier.cs` (wire stages + trust), `CredentialBuilder.cs`
(`AddStatus(BitstringStatusListEntry)`), `Verification/CredentialVerificationOptions.cs` (3 toggles),
`Credentials.Core.csproj` (NetCid + JsonSchema.Net), `Credentials.Core.csproj` `InternalsVisibleTo` already
covers the test assemblies.

**Edit — `src/Credentials.Extensions.DependencyInjection/`:** `CredentialsBuilder.cs` (6+2 builder
methods), `CredentialsServiceCollectionExtensions.cs` (registrations), `...csproj` (Http); add
`Http/HttpStatusListFetcher.cs`, `Http/HttpSchemaResolver.cs`.

**Tests — `tests/Credentials.Core.Tests/`:** `StatusBitstringTests.cs`, `StatusListManagerTests.cs`,
`SchemaValidatorTests.cs`, `SchemaValidatorRegistryTests.cs`.
**Tests — `tests/Credentials.Extensions.DependencyInjection.Tests/`:** `M2StatusVerifyTests.cs`,
`M2SchemaVerifyTests.cs`, `M2IssuerTrustTests.cs` (+ a small `AllowlistIssuerTrustPolicy` test fixture).

---

## 6. Tests (acceptance — every FR gets automated coverage)

**Codec (FR-020):** encode→decode round-trip; **MSB-first** (set index 0 ⇒ first byte `0x80`); set/clear/read
across byte boundaries; min-length floor (a <16 KiB list ⇒ rejected); **GZIP-bomb bound** (a tiny blob that
would inflate past the cap ⇒ rejected, not OOM); **multibase `maxInputLength`** (a >4096-char `encodedList`
decodes with the explicit bound; the default-bound path is shown to reject — guards the #1 runtime bug);
`statusListIndex` parsed from string; unpadded `u` prefix; `CidFormatException` on tampered prefix/padding.

**Status manager (FR-021):** create (all-zeros, min length) → revoke (bit set) → reinstate (bit clear);
suspend on a separate-purpose list; re-produce (encodedList changes, round-trips).

**Status verify (FR-022, E1/E2)** — `IStatusListFetcher` substitute returning an issued (signed) list VC:
clear⇒`Passed`/Accepted; revoked⇒`Failed`/Rejected; suspended⇒`Failed`; reinstated⇒`Passed`; unreachable⇒
`Indeterminate`⇒Rejected (fail-closed); **tampered list VC proof⇒`Indeterminate`** (E2); **expired list VC⇒
`Indeterminate`** (E2 validity); **purpose mismatch⇒`Indeterminate`** (E1); **wrong list/subject type⇒
`Indeterminate`** (E1); no fetcher⇒`Skipped`; `CheckStatus=false`⇒`Skipped`; self-referential list does not
recurse infinitely.

**Schema (FR-070):** conforming⇒`Passed`; non-conforming⇒`Failed`/Rejected (with JSON-pointer diagnostics);
`RequireFormatValidation` catches a bad `format`; `digestSRI` match⇒`Passed`, mismatch⇒`Failed`; resolver
miss⇒`Indeterminate`; unknown schema type⇒`Indeterminate`; garbage schema⇒`Indeterminate`; no resolver⇒
`Skipped`; `CheckSchema=false`⇒`Skipped`; registry immutable / keyed-by-type; `JsonSchemaCredential` wrapper
proof verified then inner schema applied.

**Issuer trust (FR-081/082, OQ-1):** allowlist Trusted⇒`Passed`; Untrusted⇒`Failed`/Rejected; Indeterminate⇒
`Indeterminate`; no policy⇒`Skipped`; throwing policy⇒`Indeterminate` (never crash); **context carries the
proof-verified issuer** (assert `IssuerId` == bound base DID); proof-failed credential⇒trust `Skipped`
(`issuer_not_authenticated`).

**FR-016:** `BitstringStatusListEntry` → builder → issued credential carries the `credentialStatus` entry,
round-trips, and is read back by the verifier.

**NFR-002:** `dotnet list src/Credentials.Core package --include-transitive` shows no Newtonsoft/dotNetRDF
(Humanizer.Core noted as the one new benign transitive).

---

## 7. Adversarial pass (mandatory, post-implementation, before PR)

Spawn 3 read-only general-purpose agents (confirm-by-running), each attacking a surface; fix every valid
finding + regression test:
1. **Codec/DoS:** bit-order confusion, gzip bomb, multibase oversize, negative/overflow index, BigInteger
   index → `long` overflow, padding/prefix tampering, decompression DoS, allocation bombs.
2. **Status recursion/trust:** self-referential status list (infinite recursion), status-list-VC issuer
   spoofing, purpose confusion, off-by-one bit read, trusting an unverified/stale list, fetcher returning
   a non-status VC, trust evaluated on a self-asserted (proof-failed) issuer.
3. **Schema/closure:** `digestSRI` bypass, malicious meta-schema, ReDoS via `pattern`/`format`, **SSRF via
   JsonSchema.Net `SchemaRegistry` `$ref`** to internal URLs, unknown-type confusion, and an
   `assembly`-level confirmation that **no Newtonsoft** is pulled into the default closure.

---

## 8. Definition of done

- `dotnet build -c Release` clean (0 warnings; `TreatWarningsAsErrors`); all suites green.
- Every M2 FR has automated tests; E1/E2/F6 fixes are explicit negative cases.
- NFR-002 transitive-closure check green.
- Adversarial findings fixed + regression-tested.
- `CHANGELOG.md` M2 section; `tasks/lessons.md` updated with any new lessons; this file's review section
  filled in.
- PR opened via `gh` (body ends with the Claude Code generated line); PR review comments addressed.

---

## 9. Review (2026-06-19)

**Status: complete and green.** Clean Release build (0 warnings, `TreatWarningsAsErrors` + XML-doc gate);
**161 tests pass** (108 `Credentials.Core.Tests` + 49 `Credentials.Extensions.DependencyInjection.Tests`
+ 4 `Credentials.Rdfc.Tests`). NFR-002 verified: no `Newtonsoft.Json` / dotNetRDF in the Core or DI
closures (new transitives: NetCid→SimpleBase; JsonSchema.Net→JsonPointer.Net/Json.More.Net/Humanizer.Core).

**Delivered** exactly as planned — status codec + manager + stage, schema resolver/validator/registry +
stage, issuer-trust hook, verifier wiring (proof→structure→validity→status→schema→trust), the three
per-call toggles, DI builder hooks (typed/instance + opt-in bounded HTTP), and FR-016 builder support.
`JsonSchemaCredential` is implemented (wrapper proof verified recursively, then inner schema applied).
`CheckResult` gained an optional structured `Detail` to surface `StatusCheckResult`.

**Adversarial pass (3 agents, confirmed-by-running).** Fixes folded in with regression tests:
- **HIGH** — status-list issuer binding (revocation masking): bind `list.issuer == credential.issuer`
  (`status.list_issuer_mismatch` ⇒ Indeterminate).
- **MEDIUM** — removed `IssuerTrustContext.Document` (claims leak; NFR-008).
- **LOW** — multi-bit `statusSize>1` revocation/suspension nonzero ⇒ Failed.
- **LOW/latent** — overflow-safe `Decode` length bound + bounded `CreateEmpty`.
- Confirmed safe (no fix): SSRF structurally impossible (JsonSchema.Net default fetch returns null);
  ReDoS bounded by the BCL regex timeout (documented residual); 27+ status/trust attacks resisted.

**Deviations from the plan (deliberate):**
1. Removed `IssuerTrustContext.Document` (the plan §4 listed it) — the adversarial review showed it
   leaks subject claims into a trust decision, contradicting NFR-008; least-privilege wins.
2. Per-check `*IsRequired` flags remain deferred (as planned) — the fail-closed default already rejects a
   configured-but-Indeterminate check.

**Carried into M8:** ReDoS amplification on untrusted schemas is bounded but not eliminated (mitigated by
the trusted-resolver + `digestSRI` boundary); a samples-side allowlist `IIssuerTrustPolicy` (FR-082) and
the API-coverage gate land with the M8 samples (the allowlist currently exists as a test fixture).
