using Credentials.Schema;
using Credentials.Securing;
using Credentials.Status;
using Credentials.Trust;
using Credentials.Verification;

namespace Credentials.Roles;

/// <summary>
/// The default <see cref="IVerifier"/>. Runs the full check set — proof → structure → validity → status →
/// schema → issuer-trust — each wrapped so that operational faults become
/// <see cref="CheckStatus.Indeterminate"/> while a definitive negative (e.g. a bad signature, a revoked
/// status, a schema violation) is <see cref="CheckStatus.Failed"/>; malformed input and programming errors
/// propagate (FR-045). Status / schema / issuer-trust report <see cref="CheckStatus.Skipped"/> when their
/// hook is not configured or the credential declares nothing to check. Issuer-trust consumes the
/// proof-verified issuer, never the self-asserted one.
/// </summary>
internal sealed class DefaultVerifier : IVerifier
{
    private readonly SecuringMechanismRegistry _registry;
    private readonly StatusStage _statusStage;
    private readonly SchemaStage _schemaStage;
    private readonly IIssuerTrustPolicy? _trustPolicy;

    public DefaultVerifier(
        SecuringMechanismRegistry registry,
        StatusStage statusStage,
        SchemaStage schemaStage,
        IIssuerTrustPolicy? trustPolicy = null)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _statusStage = statusStage ?? throw new ArgumentNullException(nameof(statusStage));
        _schemaStage = schemaStage ?? throw new ArgumentNullException(nameof(schemaStage));
        _trustPolicy = trustPolicy;
    }

    public ValueTask<CredentialVerificationResult> VerifyCredentialAsync(
        ReadOnlyMemory<byte> credential,
        CredentialVerificationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        // Parsing/decoding malformed input throws CredentialFormatException — that is the contract.
        var parsed = Ingest(credential);
        return VerifyCredentialAsync(parsed, options, cancellationToken);
    }

    /// <summary>
    /// Materializes a <see cref="Credential"/> from raw verifier input, routing by securing form: a
    /// JSON-object credential is parsed directly; a compact JWS / COSE_Sign1 envelope is decoded by its
    /// mechanism (the sole importer of that substrate, FR-050) so the inner credential is available to the
    /// downstream stages and the verbatim envelope to the proof stage. Decode failure on a detected
    /// envelope, or any non-credential input, throws <see cref="CredentialFormatException"/>; a decodable
    /// envelope with a bad signature is a Failed result, not an exception.
    /// </summary>
    private Credential Ingest(ReadOnlyMemory<byte> credential)
    {
        if (credential.Length > CredentialDocument.MaxInputBytes)
        {
            throw new CredentialFormatException(
                $"The credential input is {credential.Length} bytes, exceeding the maximum of {CredentialDocument.MaxInputBytes} bytes.");
        }

        var form = EnvelopeDetector.Detect(credential.Span);
        if (form is not { } envelopeForm)
        {
            return Credential.Parse(credential);
        }

        if (_registry.GetMechanism(envelopeForm) is not IEnvelopeIngest ingest)
        {
            throw new CredentialFormatException(
                $"The input is an enveloped credential ({envelopeForm}) but no securing mechanism is registered to decode it.");
        }

        return ingest.Ingest(credential);
    }

    public async ValueTask<CredentialVerificationResult> VerifyCredentialAsync(
        Credential credential,
        CredentialVerificationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        options ??= new CredentialVerificationOptions();

        var proof = await RunProofAsync(credential, options, cancellationToken).ConfigureAwait(false);

        var checks = new List<CheckResult>
        {
            proof.Result,
            SafeRun(CheckKinds.Structure, () => CheckStructure(credential, options)),
            SafeRun(CheckKinds.Validity, () => CheckValidity(credential, options)),
            await SafeRunAsync(CheckKinds.Status, () => _statusStage.EvaluateAsync(credential, options, this, cancellationToken)).ConfigureAwait(false),
            await SafeRunAsync(CheckKinds.Schema, () => _schemaStage.EvaluateAsync(credential, options, this, cancellationToken)).ConfigureAwait(false),
            await SafeRunAsync(CheckKinds.IssuerTrust, () => CheckIssuerTrustAsync(credential, proof, options, cancellationToken)).ConfigureAwait(false),
        };

        var decision = DecisionComposer.Compose(checks, options.Policy);
        return new CredentialVerificationResult(decision, checks, credential.Version, credential.Securing);
    }

    private async Task<ProofOutcome> RunProofAsync(Credential credential, CredentialVerificationOptions options, CancellationToken ct)
    {
        try
        {
            return await CheckProofAsync(credential, options, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not CredentialFormatException and not ArgumentNullException)
        {
            return new ProofOutcome(
                CheckResult.Indeterminate(CheckKinds.Proof, "operation_error", "An operational error prevented this check from completing."),
                []);
        }
    }

    private async Task<ProofOutcome> CheckProofAsync(Credential credential, CredentialVerificationOptions options, CancellationToken ct)
    {
        var securingForm = credential.Securing switch
        {
            SecuringState.DataIntegrity => SecuringForm.DataIntegrity,
            SecuringState.Jose => SecuringForm.Jose,
            SecuringState.Cose => SecuringForm.Cose,
            _ => (SecuringForm?)null,
        };

        // Unsecured (or a form this verifier does not handle) — there is no proof to check.
        if (securingForm is not { } form)
        {
            return new ProofOutcome(NoProof(), []);
        }

        var mechanism = _registry.GetMechanism(form);
        if (mechanism is null)
        {
            return new ProofOutcome(
                CheckResult.Indeterminate(CheckKinds.Proof, "mechanism_unavailable", $"No securing mechanism is available for the {form} form."),
                []);
        }

        var request = form == SecuringForm.DataIntegrity
            ? new VerifyRequest
            {
                Document = credential.AsElement(),
                ExpectedProofPurpose = options.ExpectedProofPurpose ?? ProofPurpose.AssertionMethod,
                VerificationTime = options.VerificationTime,
            }
            : new VerifyRequest
            {
                // The enveloping forms verify the verbatim wire bytes; the inner element is unused there.
                Document = credential.AsElement(),
                Envelope = credential.EnvelopeBytes,
                VerificationTime = options.VerificationTime,
            };

        var result = await mechanism.VerifyAsync(request, ct).ConfigureAwait(false);
        return result.Status switch
        {
            SecuringVerificationStatus.Verified => new ProofOutcome(BindIssuer(credential, result), result.VerificationMethods),
            SecuringVerificationStatus.Invalid => new ProofOutcome(CheckResult.Failed(CheckKinds.Proof, MapProofProblems(result.Problems)), []),
            SecuringVerificationStatus.Unresolvable => new ProofOutcome(CheckResult.Indeterminate(CheckKinds.Proof,
                "verification_method_unresolvable", "The proof's verification method could not be resolved."), []),
            SecuringVerificationStatus.NoProof => new ProofOutcome(NoProof(), []),
            _ => new ProofOutcome(CheckResult.Indeterminate(CheckKinds.Proof, "unknown", "The proof verification status is unknown."), []),
        };
    }

    private static CheckResult NoProof() =>
        CheckResult.Failed(CheckKinds.Proof, "no_proof", "The credential has no embedded proof.");

    // Issuer binding: a cryptographically valid proof is only meaningful if its verification method
    // belongs to the credential's issuer. We bind on the BASE DID of each proof's verificationMethod
    // identifier (the DID where the signing key lives) — not on a resolver-supplied controller field,
    // which an attacker-influenced DID document (e.g. did:web) can forge. To claim issuer = victim, an
    // attacker would have to sign under a verificationMethod whose base DID is the victim's, which
    // requires the victim's key (the signature would otherwise fail). Without this, anyone could sign a
    // credential claiming any issuer with their own key and have it verify.
    private static CheckResult BindIssuer(Credential credential, SecuringVerificationResult result)
    {
        var issuerId = credential.Issuer?.Id;
        if (string.IsNullOrEmpty(issuerId))
        {
            return CheckResult.Failed(CheckKinds.Proof, "issuer_binding_missing",
                "The credential has no issuer to bind the proof to.", "/issuer");
        }

        if (result.VerificationMethods.Count == 0
            || result.VerificationMethods.Any(vm => !string.Equals(BaseDid(vm), issuerId, StringComparison.Ordinal)))
        {
            return CheckResult.Failed(CheckKinds.Proof, "issuer_binding",
                "The proof's verification method is not controlled by the credential issuer.", "/proof/verificationMethod");
        }

        return CheckResult.Passed(CheckKinds.Proof);
    }

    // Issuer trust (FR-082): an explicit, optional step over the PROOF-VERIFIED issuer. Skipped when
    // disabled, when no policy is configured, or when the proof did not authenticate the issuer (we never
    // evaluate trust on a self-asserted issuer). A throwing policy is mapped to Indeterminate by SafeRunAsync.
    private async Task<CheckResult> CheckIssuerTrustAsync(
        Credential credential, ProofOutcome proof, CredentialVerificationOptions options, CancellationToken ct)
    {
        if (!options.EvaluateIssuerTrust)
        {
            return CheckResult.Skipped(CheckKinds.IssuerTrust, "Issuer-trust evaluation is disabled for this verification.");
        }

        if (_trustPolicy is null)
        {
            return CheckResult.Skipped(CheckKinds.IssuerTrust, "No issuer-trust policy is configured.");
        }

        var issuerId = credential.Issuer?.Id;
        if (proof.Result.Status != CheckStatus.Passed || string.IsNullOrEmpty(issuerId))
        {
            return CheckResult.Skipped(CheckKinds.IssuerTrust, "The proof did not authenticate the issuer; trust is not evaluated.");
        }

        var context = new IssuerTrustContext(
            issuerId,
            credential.Type,
            proof.VerificationMethods,
            credential.Securing,
            credential.Id,
            options.VerificationTime ?? DateTimeOffset.UtcNow);

        var result = await _trustPolicy.EvaluateAsync(context, ct).ConfigureAwait(false);
        return result.Decision switch
        {
            IssuerTrustDecision.Trusted => CheckResult.Passed(CheckKinds.IssuerTrust),
            IssuerTrustDecision.Untrusted => CheckResult.Failed(CheckKinds.IssuerTrust, result.ReasonCode, result.Reason),
            _ => CheckResult.Indeterminate(CheckKinds.IssuerTrust, result.ReasonCode, result.Reason),
        };
    }

    private readonly record struct ProofOutcome(CheckResult Result, IReadOnlyList<string> VerificationMethods);

    // The DID portion of a DID URL: everything before the first '?' (query) or '#' (fragment).
    private static string BaseDid(string didUrl)
    {
        var cut = didUrl.Length;
        var query = didUrl.IndexOf('?');
        if (query >= 0)
        {
            cut = query;
        }

        var fragment = didUrl.IndexOf('#');
        if (fragment >= 0 && fragment < cut)
        {
            cut = fragment;
        }

        return didUrl[..cut];
    }

    private static CheckResult CheckStructure(Credential credential, CredentialVerificationOptions options)
    {
        var diagnostics = new List<CheckDiagnostic>();
        if (credential.Version == VcdmVersion.V1_1 && !options.AcceptVcdm11)
        {
            diagnostics.Add(new CheckDiagnostic("vcdm11_not_accepted",
                "VCDM 1.1 credentials are not accepted by this verifier configuration.", DiagnosticSeverity.Error));
        }

        var result = credential.ValidateStructure();
        foreach (var problem in result.Problems)
        {
            diagnostics.Add(new CheckDiagnostic(problem.Code, problem.Message, DiagnosticSeverity.Error, problem.JsonPointer));
        }

        return diagnostics.Count == 0
            ? CheckResult.Passed(CheckKinds.Structure)
            : CheckResult.Failed(CheckKinds.Structure, diagnostics);
    }

    private static CheckResult CheckValidity(Credential credential, CredentialVerificationOptions options)
    {
        var now = options.VerificationTime ?? DateTimeOffset.UtcNow;
        var skew = options.ClockSkew;
        var diagnostics = new List<CheckDiagnostic>();

        if (credential.ValidFrom is { } from && now < from - skew)
        {
            diagnostics.Add(new CheckDiagnostic("not_yet_valid",
                "The credential is not yet valid (validFrom is in the future).", DiagnosticSeverity.Error, "/validFrom"));
        }

        if (credential.ValidUntil is { } until && now > until + skew)
        {
            diagnostics.Add(new CheckDiagnostic("expired",
                "The credential has expired (validUntil is in the past).", DiagnosticSeverity.Error, "/validUntil"));
        }

        return diagnostics.Count == 0
            ? CheckResult.Passed(CheckKinds.Validity)
            : CheckResult.Failed(CheckKinds.Validity, diagnostics);
    }

    private static IReadOnlyList<CheckDiagnostic> MapProofProblems(IReadOnlyList<SecuringProblem> problems) =>
        problems.Select(p => new CheckDiagnostic(p.Code, MapProofMessage(p.Code), DiagnosticSeverity.Error)).ToList();

    private static string MapProofMessage(string code) => code switch
    {
        "PROOF_VERIFICATION_ERROR" => "The proof signature did not verify.",
        "PROOF_TRANSFORMATION_ERROR" => "The credential could not be canonicalized for verification.",
        "INVALID_VERIFICATION_METHOD" => "The proof's verification method is not authorized for its purpose.",
        "INVALID_CHALLENGE_ERROR" => "The proof challenge did not match.",
        "INVALID_DOMAIN_ERROR" => "The proof domain did not match.",
        "envelope_malformed" => "The enveloping proof is malformed (wrong media type, header, or structure).",
        "envelope_kid_missing" => "The enveloping proof carries no key identifier to bind the issuer to.",
        _ => "The proof is invalid.",
    };

    private static CheckResult SafeRun(string kind, Func<CheckResult> check)
    {
        try
        {
            return check();
        }
        catch (Exception ex) when (ex is not CredentialFormatException and not ArgumentNullException)
        {
            return CheckResult.Indeterminate(kind, "operation_error", "An operational error prevented this check from completing.");
        }
    }

    private static async Task<CheckResult> SafeRunAsync(string kind, Func<Task<CheckResult>> check)
    {
        try
        {
            return await check().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not CredentialFormatException and not ArgumentNullException)
        {
            return CheckResult.Indeterminate(kind, "operation_error", "An operational error prevented this check from completing.");
        }
    }
}
