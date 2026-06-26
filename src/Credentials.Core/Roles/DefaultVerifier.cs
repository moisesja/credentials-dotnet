using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials.Json;
using Credentials.Schema;
using Credentials.Securing;
using Credentials.Status;
using Credentials.Trust;
using Credentials.Validation;
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
    private Credential Ingest(ReadOnlyMemory<byte> credential) => EnvelopeIngest.Ingest(credential, _registry);

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

    // ---- Presentations (FR-041) -------------------------------------------------------------------

    private enum PresentationBinding
    {
        /// <summary>A JSON-object VP whose binding (if any) is an embedded Data Integrity authentication proof.</summary>
        Embedded,

        /// <summary>A compact vp+jwt whose binding is the holder JWS over the VP payload.</summary>
        Jose,
    }

    public ValueTask<PresentationVerificationResult> VerifyPresentationAsync(
        VerifiablePresentation presentation, PresentationVerificationOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        // A parsed VP carries its binding (if any) as an embedded Data Integrity proof; a vp+jwt binding is
        // only reachable through the bytes overload (the compact, not the parsed VP, carries the JWS).
        return VerifyPresentationCoreAsync(
            presentation, PresentationBinding.Embedded, default, options ?? new PresentationVerificationOptions(), cancellationToken);
    }

    public ValueTask<PresentationVerificationResult> VerifyPresentationAsync(
        ReadOnlyMemory<byte> presentation, PresentationVerificationOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new PresentationVerificationOptions();
        if (presentation.Length > CredentialDocument.MaxInputBytes)
        {
            throw new CredentialFormatException(
                $"The presentation input is {presentation.Length} bytes, exceeding the maximum of {CredentialDocument.MaxInputBytes} bytes.");
        }

        var form = EnvelopeDetector.Detect(presentation.Span);
        switch (form)
        {
            case SecuringForm.Jose:
            {
                // vp+jwt: the VP is the JWS payload; the holder JWS is the binding.
                var compact = Encoding.UTF8.GetString(presentation.Span);
                var payload = CompactJws.DecodePayload(compact);
                var vp = VerifiablePresentation.Parse(payload);
                return VerifyPresentationCoreAsync(vp, PresentationBinding.Jose, presentation, options, cancellationToken);
            }

            case null:
            {
                // A JSON-object presentation (embedded Data Integrity authentication proof, or unbound).
                var vp = VerifiablePresentation.Parse(presentation);
                return VerifyPresentationCoreAsync(vp, PresentationBinding.Embedded, default, options, cancellationToken);
            }

            default:
                throw new CredentialFormatException($"The input is not a recognizable presentation ({form}).");
        }
    }

    private async ValueTask<PresentationVerificationResult> VerifyPresentationCoreAsync(
        VerifiablePresentation vp, PresentationBinding binding, ReadOnlyMemory<byte> envelope,
        PresentationVerificationOptions options, CancellationToken ct)
    {
        var holderBinding = await RunHolderBindingAsync(vp, binding, envelope, options, ct).ConfigureAwait(false);
        var structure = SafeRun(CheckKinds.Structure, () => CheckPresentationStructure(vp, options));

        var credentialOptions = BuildContainedCredentialOptions(options);
        var credentialResults = new List<CredentialVerificationResult>(vp.VerifiableCredentials.Count);
        foreach (var contained in vp.VerifiableCredentials)
        {
            credentialResults.Add(await VerifyContainedAsync(contained, credentialOptions, ct).ConfigureAwait(false));
        }

        var presentationChecks = new[] { holderBinding, structure };
        var decision = ComposePresentationDecision(presentationChecks, credentialResults, options.Policy);
        var mechanism = binding == PresentationBinding.Jose ? SecuringState.Jose : vp.Securing;
        return new PresentationVerificationResult(decision, presentationChecks, credentialResults, vp.Version, mechanism);
    }

    private async Task<CheckResult> RunHolderBindingAsync(
        VerifiablePresentation vp, PresentationBinding binding, ReadOnlyMemory<byte> envelope,
        PresentationVerificationOptions options, CancellationToken ct)
    {
        try
        {
            var isBound = binding == PresentationBinding.Jose || vp.Securing == SecuringState.DataIntegrity;
            if (!isBound)
            {
                return options.RequireHolderBinding
                    ? CheckResult.Failed(CheckKinds.HolderBinding, "holder_binding_missing",
                        "The presentation is not bound to a holder key.")
                    : CheckResult.Skipped(CheckKinds.HolderBinding, "The presentation carries no holder binding.");
            }

            // Replay defence is mandatory for a REQUIRED binding: the verifier must supply a challenge to bind
            // against, else a captured presentation replays. (Both binding paths; fail closed, never fail open.)
            if (options.RequireHolderBinding && string.IsNullOrEmpty(options.ExpectedChallenge))
            {
                return CheckResult.Failed(CheckKinds.HolderBinding, "holder_binding_challenge_required",
                    "Holder binding is required but no expected challenge was supplied to bind the presentation against (replay defence).");
            }

            if (binding == PresentationBinding.Jose)
            {
                // The JOSE mechanism verifies typ=vp+jwt + the holder signature over the VP (which carries the
                // signed nonce/aud); the freshness comparison against the verifier's expectations is here.
                var joseResult = await CheckHolderBindingViaMechanismAsync(vp, SecuringForm.Jose, new VerifyRequest
                {
                    Document = vp.ToElement(),
                    Envelope = envelope,
                    ExpectedPayload = vp.ToUtf8(),
                    Kind = SecuringDocumentKind.Presentation,
                    VerificationTime = options.VerificationTime,
                }, ct).ConfigureAwait(false);
                return joseResult.Status == CheckStatus.Passed ? CheckPresentationFreshness(vp, options) : joseResult;
            }

            // Data Integrity authentication proof — the substrate enforces the challenge/domain match.
            return await CheckHolderBindingViaMechanismAsync(vp, SecuringForm.DataIntegrity, new VerifyRequest
            {
                Document = vp.ToElement(),
                ExpectedProofPurpose = ProofPurpose.Authentication,
                ExpectedChallenge = options.ExpectedChallenge,
                ExpectedDomain = options.ExpectedDomain,
                VerificationTime = options.VerificationTime,
            }, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not CredentialFormatException and not ArgumentNullException)
        {
            return CheckResult.Indeterminate(CheckKinds.HolderBinding, "operation_error",
                "An operational error prevented the holder-binding check from completing.");
        }
    }

    private async Task<CheckResult> CheckHolderBindingViaMechanismAsync(
        VerifiablePresentation vp, SecuringForm form, VerifyRequest request, CancellationToken ct)
    {
        var mechanism = _registry.GetMechanism(form);
        if (mechanism is null)
        {
            return CheckResult.Indeterminate(CheckKinds.HolderBinding, "mechanism_unavailable",
                $"No securing mechanism is available for the {form} form.");
        }

        var result = await mechanism.VerifyAsync(request, ct).ConfigureAwait(false);
        return result.Status switch
        {
            SecuringVerificationStatus.Verified => BindHolder(vp, result),
            SecuringVerificationStatus.Invalid => CheckResult.Failed(CheckKinds.HolderBinding, MapProofProblems(result.Problems)),
            SecuringVerificationStatus.Unresolvable => CheckResult.Indeterminate(CheckKinds.HolderBinding,
                "verification_method_unresolvable", "The holder binding's verification method could not be resolved."),
            SecuringVerificationStatus.NoProof => CheckResult.Failed(CheckKinds.HolderBinding, "holder_binding_missing",
                "The presentation carries no holder-binding proof."),
            _ => CheckResult.Indeterminate(CheckKinds.HolderBinding, "unknown", "The holder-binding status is unknown."),
        };
    }

    // vp+jwt replay defence: the holder signed `nonce` (= challenge) and `aud` (= domain) into the VP, so the
    // JWS already proved they are the holder's; here the verifier requires them to equal its own
    // expectations, so a captured vp+jwt does not replay against a verifier demanding fresh values.
    private static CheckResult CheckPresentationFreshness(VerifiablePresentation vp, PresentationVerificationOptions options)
    {
        if (options.ExpectedChallenge is { } expectedChallenge
            && !string.Equals(ReadStringMember(vp, "nonce"), expectedChallenge, StringComparison.Ordinal))
        {
            return CheckResult.Failed(CheckKinds.HolderBinding, "holder_binding_replay",
                "The presentation's nonce does not match the expected challenge.");
        }

        if (options.ExpectedDomain is { } expectedDomain
            && !string.Equals(ReadStringMember(vp, "aud"), expectedDomain, StringComparison.Ordinal))
        {
            return CheckResult.Failed(CheckKinds.HolderBinding, "holder_binding_replay",
                "The presentation's audience does not match the expected domain.");
        }

        return CheckResult.Passed(CheckKinds.HolderBinding);
    }

    private static string? ReadStringMember(VerifiablePresentation vp, string member) =>
        vp.GetMember(member) is JsonValue value && value.GetValueKind() == JsonValueKind.String
            ? value.GetValue<string>()
            : null;

    // Bind the holder-binding proof to the presentation's holder: the binding key's base DID must equal the
    // presentation's `holder` — to bind a presentation as a victim holder an attacker needs the victim's key.
    private static CheckResult BindHolder(VerifiablePresentation vp, SecuringVerificationResult result)
    {
        // Defence in depth: the holder-less Passed path below is sound only because the binding proof has
        // already verified. Today BindHolder is reachable only from the Verified switch arm; this runtime
        // guard (a real backstop — unlike a Debug.Assert, which compiles out of Release) keeps a future call
        // path that passed a non-verified result from reaching the holder-less shortcut. It fails closed.
        if (result.Status != SecuringVerificationStatus.Verified)
        {
            return CheckResult.Indeterminate(CheckKinds.HolderBinding, "binding_not_verified",
                "The holder binding could not be confirmed.");
        }

        var holderId = vp.Holder;
        if (string.IsNullOrEmpty(holderId))
        {
            // VCDM 2.0: `holder` is OPTIONAL. A signed presentation with no holder still proves possession
            // of the binding key and freshness (the binding proof verified and the challenge/domain
            // matched); there is simply no holder identity to bind it to. This cannot be abused to strip a
            // victim's `holder`: `holder` is inside the proof's signed scope, so removing it invalidates the
            // proof before this check runs (the mechanism returns Invalid, not Verified). So a holder-less
            // signed presentation is bound on possession alone.
            return CheckResult.Passed(CheckKinds.HolderBinding);
        }

        if (result.VerificationMethods.Count == 0
            || result.VerificationMethods.Any(vm => !string.Equals(BaseDid(vm), holderId, StringComparison.Ordinal)))
        {
            return CheckResult.Failed(CheckKinds.HolderBinding, "holder_binding",
                "The holder-binding proof's verification method is not controlled by the holder.", "/proof/verificationMethod");
        }

        return CheckResult.Passed(CheckKinds.HolderBinding);
    }

    private async Task<CredentialVerificationResult> VerifyContainedAsync(
        ContainedCredential contained, CredentialVerificationOptions options, CancellationToken ct)
    {
        try
        {
            return contained.IsEmbedded
                ? await VerifyCredentialAsync(contained.AsEmbedded!, options, ct).ConfigureAwait(false)
                : await VerifyCredentialAsync(Encoding.UTF8.GetBytes(contained.AsEnvelopedCompact!), options, ct).ConfigureAwait(false);
        }
        catch (CredentialFormatException)
        {
            // A malformed contained credential (e.g. a non-decodable enveloped token) is that child's
            // failure, not a fault of the whole presentation: synthesize a Rejected result so the VP still
            // composes to Rejected and every other child is evaluated (FR-045 graceful per-child handling),
            // instead of letting the exception escape the whole VerifyPresentationAsync call.
            var proof = CheckResult.Failed(CheckKinds.Proof, "contained_credential_malformed",
                "The contained credential could not be decoded.");
            return new CredentialVerificationResult(VerificationDecision.Rejected, [proof], VcdmVersion.Unknown, SecuringState.Unsecured);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not ArgumentNullException)
        {
            // Defence in depth: every reachable ingest path converts malformed input to
            // CredentialFormatException today, but a contained-credential fault must never escape the whole
            // VerifyPresentationAsync regardless of which substrate exception type surfaces (the same
            // fault-isolation guard RunHolderBindingAsync/RunProofAsync use). An operational fault is
            // non-deterministic, so report it as Indeterminate (not a definitive child rejection); real
            // programming errors (null args) and cancellation still propagate.
            var proof = CheckResult.Indeterminate(CheckKinds.Proof, "operation_error",
                "An operational error prevented the contained credential from being evaluated.");
            return new CredentialVerificationResult(VerificationDecision.Indeterminate, [proof], VcdmVersion.Unknown, SecuringState.Unsecured);
        }
    }

    // Each contained credential is verified with the presentation's verification time and, for SD-JWT VC
    // children, the presentation's audience/nonce so a contained SD-JWT VC's Key Binding JWT is checked.
    // The `c with { … }` record copy preserves every field not named here — notably AcceptVcdm11 (D8), so a
    // 1.1 child is gated by the same flag that gates the VP envelope; only the fields below are overridden.
    private static CredentialVerificationOptions BuildContainedCredentialOptions(PresentationVerificationOptions options)
    {
        var c = options.CredentialOptions;
        return c with
        {
            VerificationTime = options.VerificationTime ?? c.VerificationTime,
            RequireHolderBinding = c.RequireHolderBinding || options.ExpectedAudience is not null,
            ExpectedAudience = options.ExpectedAudience ?? c.ExpectedAudience,
            ExpectedNonce = options.ExpectedNonce ?? c.ExpectedNonce,
        };
    }

    private static CheckResult CheckPresentationStructure(VerifiablePresentation vp, PresentationVerificationOptions options)
    {
        var result = vp.ValidateStructure();
        var diagnostics = result.Problems
            .Select(p => new CheckDiagnostic(p.Code, p.Message, DiagnosticSeverity.Error, p.JsonPointer))
            .ToList();

        // FR-044/D8: honor AcceptVcdm11 on the presentation path too (not only the credential path) — a 1.1
        // presentation envelope is rejected when the verifier disallows 1.1. There is no presentation-level
        // flag by design; the single AcceptVcdm11 on CredentialOptions governs both the VP and its children.
        if (vp.Version == VcdmVersion.V1_1 && !options.CredentialOptions.AcceptVcdm11)
        {
            diagnostics.Add(new CheckDiagnostic("vcdm11_not_accepted",
                "VCDM 1.1 presentations are not accepted by this verifier configuration.", DiagnosticSeverity.Error));
        }

        // FR-033: a presentation is built from one or more credentials. An empty/absent verifiableCredential
        // would otherwise compose to Accepted (no child to reject), proving only holder-key possession.
        if (options.RequireAtLeastOneCredential && vp.VerifiableCredentials.Count == 0)
        {
            diagnostics.Add(new CheckDiagnostic("presentation_no_credentials",
                "The presentation contains no credentials.", DiagnosticSeverity.Error, "/verifiableCredential"));
        }

        return diagnostics.Count == 0
            ? CheckResult.Passed(CheckKinds.Structure)
            : CheckResult.Failed(CheckKinds.Structure, diagnostics);
    }

    // A presentation is Accepted only when every presentation-level check and every contained credential is
    // accepted; any Failed (or Rejected credential) ⇒ Rejected; else any Indeterminate ⇒ Indeterminate
    // (Rejected under the fail-closed default).
    private static VerificationDecision ComposePresentationDecision(
        IReadOnlyList<CheckResult> presentationChecks, IReadOnlyList<CredentialVerificationResult> credentials, VerificationPolicy policy)
    {
        if (presentationChecks.Any(c => c.Status == CheckStatus.Failed)
            || credentials.Any(c => c.Decision == VerificationDecision.Rejected))
        {
            return VerificationDecision.Rejected;
        }

        if (presentationChecks.Any(c => c.Status == CheckStatus.Indeterminate)
            || credentials.Any(c => c.Decision == VerificationDecision.Indeterminate))
        {
            return policy.TreatIndeterminateAsFailure ? VerificationDecision.Rejected : VerificationDecision.Indeterminate;
        }

        return VerificationDecision.Accepted;
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
            SecuringState.SdJwtVc => SecuringForm.SdJwtVc,
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
                Document = credential.ToElement(),
                ExpectedProofPurpose = options.ExpectedProofPurpose ?? ProofPurpose.AssertionMethod,
                VerificationTime = options.VerificationTime,
            }
            : new VerifyRequest
            {
                // The enveloping forms verify the verbatim wire bytes; the inner element is unused there.
                // ExpectedPayload binds the verified payload to the inner document the stages validate.
                Document = credential.ToElement(),
                Envelope = credential.EnvelopeBytes,
                ExpectedPayload = credential.ToUtf8(),
                VerificationTime = options.VerificationTime,
                // Holder binding (SD-JWT VC KB-JWT); ignored by the JOSE/COSE mechanisms.
                RequireHolderBinding = options.RequireHolderBinding,
                ExpectedAudience = options.ExpectedAudience,
                ExpectedNonce = options.ExpectedNonce,
                MaxHolderBindingAge = options.MaxHolderBindingAge,
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
        var issuerId = ResolveIssuerId(credential);
        if (string.IsNullOrEmpty(issuerId))
        {
            return CheckResult.Failed(CheckKinds.Proof, "issuer_binding_missing",
                "The credential has no issuer to bind the proof to.",
                credential.Securing == SecuringState.SdJwtVc ? "/iss" : "/issuer");
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

        // Use the SAME anchor the proof bound (ResolveIssuerId) so the trust policy evaluates the
        // proof-authenticated issuer — for SD-JWT VC that is the `iss` claim, which the proof stage's
        // sdjwt_issuer_mismatch guard has already required to equal the VCDM issuer.
        var issuerId = ResolveIssuerId(credential);
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

    // The issuer-binding anchor: for SD-JWT VC it is the (clear, reserved, signature-covered) 'iss' claim
    // per draft-ietf-oauth-sd-jwt-vc-16 §3.2.2.1.1, falling back to the VCDM issuer when absent; for every
    // other form it is the VCDM issuer. The anchor is part of the signed payload, so binding it to the
    // resolved signing-key DID is the look-up-then-bind shape (an attacker cannot claim a victim issuer
    // without the victim's key).
    private static string? ResolveIssuerId(Credential credential)
    {
        if (credential.Securing == SecuringState.SdJwtVc
            && credential.GetMember("iss") is JsonValue iss
            && iss.GetValueKind() == JsonValueKind.String)
        {
            return iss.GetValue<string>();
        }

        return credential.Issuer?.Id;
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

        // The window itself is already projected per version (ValidityProjection: 1.1 reads issuanceDate/
        // expirationDate, 2.0 reads validFrom/validUntil). Only the diagnostic must name the member that
        // actually exists in THIS document — a 1.1 credential has no /validFrom, so point at /issuanceDate.
        // Unknown is handled explicitly (not lumped with 2.0): an Unknown doc is rejected by structure
        // regardless, but its validity diagnostic must still be honest. ValidityProjection's Unknown fallback
        // selects the window value by PARSE SUCCESS (validFrom ?? issuanceDate), not member presence, so name
        // the member the same way — `Parses` mirrors ValidityProjection.Read so the pointer names the member
        // whose value was actually used (a present-but-malformed validFrom must not steal the name).
        static bool Parses(JsonNode? node) => Rfc3339.TryParse(JsonShape.AsString(node), out _);
        var (notBeforeMember, notAfterMember) = credential.Version switch
        {
            VcdmVersion.V1_1 => ("issuanceDate", "expirationDate"),
            VcdmVersion.V2_0 => ("validFrom", "validUntil"),
            _ => (Parses(credential.GetMember("validFrom")) ? "validFrom" : "issuanceDate",
                  Parses(credential.GetMember("validUntil")) ? "validUntil" : "expirationDate"),
        };

        if (credential.ValidFrom is { } from && now < from - skew)
        {
            diagnostics.Add(new CheckDiagnostic("not_yet_valid",
                $"The credential is not yet valid ({notBeforeMember} is in the future).",
                DiagnosticSeverity.Error, "/" + notBeforeMember));
        }

        if (credential.ValidUntil is { } until && now > until + skew)
        {
            diagnostics.Add(new CheckDiagnostic("expired",
                $"The credential has expired ({notAfterMember} is in the past).",
                DiagnosticSeverity.Error, "/" + notAfterMember));
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
        "envelope_payload_mismatch" => "The signed payload does not match the credential being verified.",
        "verification_method_not_found" => "The signer's DID resolved but does not publish the proof's verification method.",
        "sdjwt_malformed" => "The SD-JWT VC is malformed (wrong media type, structure, or disclosure).",
        "sdjwt_kid_missing" => "The SD-JWT VC carries no key identifier to bind the issuer to.",
        "sdjwt_disclosure_invalid" => "An SD-JWT VC disclosure did not reconstruct against the signed digests.",
        "sdjwt_disallowed_disclosure" => "The SD-JWT VC selectively disclosed a claim that must stay in the clear.",
        "sdjwt_vct_missing" => "The SD-JWT VC has no 'vct' type claim.",
        "sdjwt_key_binding_invalid" => "The SD-JWT VC Key Binding JWT did not verify.",
        "sdjwt_payload_mismatch" => "The disclosed payload does not match the SD-JWT VC being verified.",
        "sdjwt_issuer_mismatch" => "The SD-JWT VC 'iss' claim does not match the credential issuer.",
        "sdjwt_hidden_member" => "A credential member required for verification was hidden in a disclosure.",
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
