namespace Credentials.TestSupport;

/// <summary>
/// The canonical set of engineering requirements (the PRD §8 coverage table) the
/// <c>FrCoverage_EveryRequirement_HasAtLeastOneTest</c> gate enforces. This is the single source of
/// truth: the §8 table defines exactly these 34 functional requirements and 9 non-functional
/// requirements — the FR numbering is sparse (there is no FR-006..009, FR-017..019, FR-023..029,
/// FR-035..039, FR-046..049, FR-054..069, FR-071..079), so the gate enumerates this list, not a dense
/// range. Adding a new requirement here forces a new tagged test before CI goes green.
/// </summary>
public static class RequirementIds
{
    /// <summary>The 34 functional requirements, id → one-line description (PRD §8).</summary>
    public static readonly IReadOnlyDictionary<string, string> FunctionalRequirements = new Dictionary<string, string>
    {
        ["FR-001"] = "Credential/CredentialBuilder projections + GetMember escape hatch (round-trip fidelity)",
        ["FR-002"] = "VerifiablePresentation + ContainedCredential",
        ["FR-003"] = "CredentialDocument verbatim bytes / serialize-once + round-trip fidelity",
        ["FR-004"] = "Lazy typed projections over the frozen document",
        ["FR-005"] = "StructuralValidator (conformance fixes A1-A3,B1,C1-C2,D1,F8,H2-H4)",
        ["FR-010"] = "IIssuer credential assembly / CredentialContent",
        ["FR-011"] = "DataIntegrityMechanism + DataIntegrityIssuanceRequest (embedded issue)",
        ["FR-012"] = "Jose/Cose enveloping (both serializations)",
        ["FR-013"] = "SdJwtVcMechanism + SdJwtVcIssuanceRequest",
        ["FR-014"] = "Bbs2023Mechanism base issuance (gated on upstream key-store BBS API)",
        ["FR-015"] = "ISigner everywhere; raw keys never handled by the engine",
        ["FR-016"] = "BitstringStatusListEntry on credential content",
        ["FR-020"] = "StatusBitstring + StatusListManager codec",
        ["FR-021"] = "StatusListManager set/clear/update/re-produce",
        ["FR-022"] = "StatusStage + IStatusListFetcher (E1/E2 fixes)",
        ["FR-030"] = "IHolder.Ingest / HeldCredential read-only projections",
        ["FR-031"] = "Bbs derive disclosure (DeriveProof)",
        ["FR-032"] = "SD-JWT present (KB-JWT)",
        ["FR-033"] = "BuildPresentation / VpAssemblyRequest",
        ["FR-034"] = "BindWith{DataIntegrity,JoseEnvelope} via net-did",
        ["FR-040"] = "Verifier pipeline + stages",
        ["FR-041"] = "PresentationOrchestrator / VerifyPresentationAsync",
        ["FR-042"] = "DI bbs-derived + SD-JWT proof stages",
        ["FR-043"] = "Three-state CredentialVerificationResult / CheckResult",
        ["FR-044"] = "Version-aware validator + validity (VCDM 1.1 verify, D1/F8)",
        ["FR-045"] = "SafeRun boundary; bad-signature => Failed (F7)",
        ["FR-050"] = "ISecuringMechanism is the sole DataProofs caller; no core canon/proof",
        ["FR-051"] = "SD-JWT draft types confined; no-draft-type surface (F3)",
        ["FR-052"] = "NetCrypto RNG/Hash seam (F9); JwkConversion",
        ["FR-053"] = "SecuringMechanismRegistry opaque suite strings + ISecuringCapabilities",
        ["FR-070"] = "JsonSchema2020 validator + immutable SchemaValidatorRegistry (F6/D9)",
        ["FR-080"] = "NetDidVerificationMethodResolver; ISigner/IKeyStore identity",
        ["FR-081"] = "Three injected hooks via AddCredentials builder",
        ["FR-082"] = "IIssuerTrustPolicy structured result; allowlist sample (no built-in trust lists)",
    };

    /// <summary>The 9 non-functional requirements, id → one-line description (PRD §8).</summary>
    public static readonly IReadOnlyDictionary<string, string> NonFunctionalRequirements = new Dictionary<string, string>
    {
        ["NFR-001"] = "net10.0 / LangVersion=latest",
        ["NFR-002"] = "System.Text.Json only; no Newtonsoft in the default consumer closure",
        ["NFR-003"] = "Frozen-by-default core; immutable accumulator; singleton roles",
        ["NFR-004"] = "async/ValueTask; honest-async derive/present",
        ["NFR-005"] = "ApiCompat + PublicAPI analyzers; no draft types on the surface",
        ["NFR-006"] = "No raw-key export; bounded untrusted input / GZIP",
        ["NFR-007"] = "Conformance shim + interop vectors",
        ["NFR-008"] = "Secret-free per-check diagnostics; code-mapped messages",
        ["NFR-009"] = "CS1591-as-error + XML-doc assertion test",
    };

    /// <summary>Every requirement id the coverage gate enforces (43 = 34 FR + 9 NFR).</summary>
    public static IReadOnlyList<string> All { get; } =
        [.. FunctionalRequirements.Keys, .. NonFunctionalRequirements.Keys];

    /// <summary>Looks up the one-line description for a requirement id, or <see langword="null"/> if unknown.</summary>
    /// <param name="requirementId">The requirement id.</param>
    public static string? Describe(string requirementId) =>
        FunctionalRequirements.TryGetValue(requirementId, out var fr) ? fr
        : NonFunctionalRequirements.TryGetValue(requirementId, out var nfr) ? nfr
        : null;
}
