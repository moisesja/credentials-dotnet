using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials.Resolution;
using Credentials.Roles;
using Credentials.Schema;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Signing;

namespace Credentials.Securing;

/// <summary>
/// The SD-JWT VC securing mechanism (FR-013) — the single bridge to the <c>DataProofsDotnet.Jose</c>
/// SD-JWT(.Vc) APIs (FR-050). It issues a VCDM 2.0 credential as a selectively disclosable SD-JWT VC
/// (<c>typ=dc+sd-jwt</c>, the <c>vct</c> in the clear, caller-chosen claims disclosable, an optional
/// holder <c>cnf</c> key), and verifies an issuer-signed SD-JWT VC and its disclosures. No draft-version
/// type (<see cref="DisclosureFrame"/>, <see cref="SdJwtIssuerOptions"/>, <see cref="Jwk"/>,
/// <see cref="ITypeMetadataResolver"/>, …) escapes this class (NFR-005/FR-051/D12).
///
/// <para>F7/FR-045: the issuer key is resolved asynchronously <em>before</em> the substrate verify, so a
/// DID/IO failure is <see cref="SecuringVerificationStatus.Unresolvable"/> (→ Indeterminate) while a bad
/// signature, a bad disclosure, an <c>_sd</c>-digest mismatch, a wrong <c>typ</c>, a disclosed reserved
/// claim, or a missing <c>vct</c> is a definitive <see cref="SecuringVerificationStatus.Invalid"/>
/// (→ Failed). A constant resolver is passed to the substrate so its result can never mean
/// "key not found".</para>
/// </summary>
internal sealed class SdJwtVcMechanism : ISecuringMechanism, IEnvelopeIngest, ISdJwtPresenter
{
    // VCDM members that must stay in the clear because a verifier stage reads them from the
    // (selective-disclosure-stripped) issuer-JWT cleartext — never selectively disclosable. Hiding any
    // of these in a disclosure would silently disable the corresponding check (an expired/revoked
    // credential would verify) or break the issuer binding / structural / version checks. The SD-JWT
    // substrate additionally forbids the reserved JWT claims (iss/nbf/exp/cnf/vct/vct#integrity/status);
    // these are the VCDM equivalents the substrate treats as ordinary (and would otherwise allow).
    private static readonly HashSet<string> NonDisclosableMembers = new(StringComparer.Ordinal)
    {
        "@context", "type", "id", "issuer",
        "validFrom", "validUntil", "issuanceDate", "expirationDate",
        "credentialStatus", "credentialSchema",
    };

    private readonly IEnvelopeKeyResolver _keyResolver;
    private readonly ICredentialTypeMetadataResolver? _metadataResolver;

    public SdJwtVcMechanism(IEnvelopeKeyResolver keyResolver, ICredentialTypeMetadataResolver? metadataResolver = null)
    {
        _keyResolver = keyResolver ?? throw new ArgumentNullException(nameof(keyResolver));
        _metadataResolver = metadataResolver;
    }

    public SecuringForm Form => SecuringForm.SdJwtVc;

    public IReadOnlyCollection<string> SuiteNames => [];

    public bool IsAvailable => true;

    public async Task<SecureOutcome> SecureAsync(SecureRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Claims is not { } claims)
        {
            throw new ArgumentException("An SD-JWT VC securing request requires the claims object.", nameof(request));
        }

        if (string.IsNullOrEmpty(request.Vct))
        {
            throw new ArgumentException("An SD-JWT VC securing request requires a non-empty 'vct'.", nameof(request));
        }

        // The VCDM document becomes the SD-JWT VC claims set: add the required 'vct' (in the clear) and an
        // 'iss' claim mirroring the credential issuer (the binding anchor; reserved/non-disclosable). The
        // claims object is the issuer's deep clone — safe to mutate.
        claims["vct"] = request.Vct;
        if (claims["iss"] is null && ReadIssuerId(claims) is { } issuerId)
        {
            claims["iss"] = issuerId;
        }

        var frame = BuildFrame(request.Disclosable ?? []);

        var options = new SdJwtIssuerOptions
        {
            HashAlgorithm = MapHash(request.SdHash ?? SdHashName.Sha256),
            DecoyDigestCount = request.DecoyDigestCount,
            HolderConfirmationKey = request.HolderBinding is { } holder ? ToJwk(holder) : null,
        };

        // JwsSigner derives the JOSE alg from the signer's key type and throws NotSupportedException for an
        // unsupported key (P-521/RSA) — fail fast at issuance rather than mis-sign.
        var signer = new JwsSigner(request.Signer, request.VerificationMethod);

        SdJwtIssuer.Result result;
        try
        {
            result = await SdJwtVcIssuer.IssueAsync(claims, frame, signer, options, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (MalformedJoseException ex)
        {
            // A profile violation the substrate caught that our guards did not (blank vct / a reserved
            // claim marked disclosable): a usage error — surface it without leaking the substrate type.
            throw new ArgumentException($"The SD-JWT VC issuance request is invalid: {ex.Message}", nameof(request));
        }

        return SecureOutcome.ForSdJwt(result.Issuance);
    }

    // The leading/trailing JSON whitespace the EnvelopeDetector tolerates when routing (a wire token may
    // carry an incidental newline) — trimmed here so ingest/verify see the same token the detector classified.
    private static readonly char[] JsonWhitespace = [' ', '\t', '\n', '\r'];

    public Credential Ingest(ReadOnlyMemory<byte> envelope)
    {
        var compact = Encoding.UTF8.GetString(envelope.Span).Trim(JsonWhitespace);

        byte[] issuerPayload;
        try
        {
            var components = SdJwtComponents.Parse(compact);
            // The issuer-JWT cleartext carries the VCDM members in the clear plus vct/iss/_sd/_sd_alg/cnf.
            issuerPayload = CompactJws.DecodePayload(components.IssuerJwt);
        }
        catch (MalformedJoseException ex)
        {
            throw new CredentialFormatException("The value is not a well-formed SD-JWT VC.", ex);
        }

        var inner = CredentialDocument.Parse(issuerPayload);
        return Credential.FromEnvelope(inner, SecuringState.SdJwtVc, envelope);
    }

    public async Task<string> PresentAsync(SdJwtPresentRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        SdJwtComponents components;
        try
        {
            components = SdJwtComponents.Parse(request.IssuedCompact);
        }
        catch (MalformedJoseException ex)
        {
            throw new CredentialFormatException("The value is not a well-formed SD-JWT VC.", ex);
        }

        // Map the requested claim names to the encoded disclosure strings the substrate selects by.
        // Disclosures with no claim name (array elements) are not selectable by name in this milestone.
        var requested = new HashSet<string>(request.DiscloseClaims, StringComparer.Ordinal);
        var reveal = components.Disclosures
            .Where(d => d.ClaimName is { } name && requested.Contains(name))
            .Select(d => d.Encoded)
            .ToList();

        // The holder signs the KB-JWT (typ=kb+jwt) over the selected presentation; sd_hash binds the exact
        // disclosed set, aud/nonce bind the verifier + freshness. Honestly async over the signing (F5).
        var holderSigner = new JwsSigner(request.HolderSigner, request.VerificationMethod);
        return await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
                request.IssuedCompact, reveal, holderSigner, request.Audience, request.Nonce, issuedAt: null, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>The claim names that an issued SD-JWT VC carries as selectively disclosable (for holder selection).</summary>
    public static IReadOnlyList<string> DisclosableClaimNames(string issuedCompact)
    {
        SdJwtComponents components;
        try
        {
            components = SdJwtComponents.Parse(issuedCompact);
        }
        catch (MalformedJoseException ex)
        {
            throw new CredentialFormatException("The value is not a well-formed SD-JWT VC.", ex);
        }

        return components.Disclosures
            .Where(d => d.ClaimName is not null)
            .Select(d => d.ClaimName!)
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    public async Task<SecuringVerificationResult> VerifyAsync(VerifyRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Envelope is not { } envelopeBytes)
        {
            return SecuringVerificationResult.NoProof;
        }

        var compact = Encoding.UTF8.GetString(envelopeBytes.Span).Trim(JsonWhitespace);

        string issuerJwt;
        JsonObject clearPayload;
        try
        {
            var components = SdJwtComponents.Parse(compact);
            issuerJwt = components.IssuerJwt;
            clearPayload = ParsePayloadObject(CompactJws.DecodePayload(issuerJwt));
        }
        catch (Exception ex) when (ex is MalformedJoseException or CredentialFormatException)
        {
            return SecuringVerificationResult.Invalid("sdjwt_malformed");
        }

        var kid = CompactJws.ReadKid(issuerJwt);
        if (string.IsNullOrEmpty(kid))
        {
            // No signer identity ⇒ nothing to bind the issuer to — reject (fail closed).
            return SecuringVerificationResult.Invalid("sdjwt_kid_missing");
        }

        EnvelopeKeyResolution resolution;
        try
        {
            resolution = await _keyResolver.ResolveAsync(kid, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return SecuringVerificationResult.Unresolvable("verification_method_unresolvable");
        }

        switch (resolution.Status)
        {
            case EnvelopeKeyResolutionStatus.DidUnresolvable:
                return SecuringVerificationResult.Unresolvable("verification_method_unresolvable");
            case EnvelopeKeyResolutionStatus.MethodNotFound:
                // The DID resolved but does not publish this kid (e.g. an attacker-mangled kid fragment
                // over a still-resolvable base DID) — a definitive negative, not Indeterminate (F7).
                return SecuringVerificationResult.Invalid("verification_method_not_found");
        }

        var resolved = resolution.Key;
        Jwk jwk;
        try
        {
            jwk = resolved.Multibase is { } multibase
                ? JwkConversion.FromMultikey(multibase, kid)
                : JwkConversion.ToPublicJwk(resolved.KeyType, resolved.PublicKey.ToArray(), kid);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return SecuringVerificationResult.Unresolvable("verification_method_unresolvable");
        }

        // Holder Key-Binding-JWT verification (M6): when a KB-JWT is present the substrate always verifies
        // it (signature under the issuer-set cnf, sd_hash over the exact disclosed set, aud, nonce, iat
        // freshness); RequireKeyBinding additionally makes its ABSENCE a failure. The constant resolver
        // means a substrate negative is always a real crypto/profile/binding failure, never a key-resolution
        // failure (F7). The aud/nonce are threaded from the (presentation) verification options.
        var options = new SdJwtVerificationOptions
        {
            RequireKeyBinding = request.RequireHolderBinding,
            ExpectedAudience = request.ExpectedAudience,
            ExpectedNonce = request.ExpectedNonce,
            MaxKeyBindingAge = request.MaxHolderBindingAge,
            CurrentTime = request.VerificationTime,
        };
        var metadataAdapter = _metadataResolver is null ? null : new TypeMetadataResolverAdapter(_metadataResolver);

        SdJwtVcVerificationResult result;
        try
        {
            result = await SdJwtVcVerifier
                .VerifyAsync(compact, _ => jwk, options, metadataAdapter, cryptoProvider: null, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // The only residual throw source is the optional Type Metadata resolver doing I/O (the key is
            // pre-resolved and the SD-JWT verifier is result-style) — an operational fault, not a verdict.
            return SecuringVerificationResult.Unresolvable("type_metadata_unresolvable");
        }

        if (!result.IsValid)
        {
            return SecuringVerificationResult.Invalid(MapErrorCode(result.Errors));
        }

        // Self-enforcing consistency guard (mirrors the M3 envelope_payload_mismatch lesson): the
        // fields the verifier binds and validates on must equal those in the substrate-verified disclosed
        // payload, so the credential whose claims the stages check is provably the one the signature
        // covers — independent of selective disclosure.
        if (result.DisclosedPayload is not { } disclosed
            || !StringClaimEquals(clearPayload, disclosed, "iss")
            || !StringClaimEquals(clearPayload, disclosed, "vct"))
        {
            return SecuringVerificationResult.Invalid("sdjwt_payload_mismatch");
        }

        // The binding anchor (iss) and the VCDM issuer are both signed and in the clear — they must agree.
        // A "split-brain" credential (iss = attacker so the proof binds, issuer = victim so the
        // consumer/trust path reports the victim) is a definitive forgery. Legitimate issuance always sets
        // iss = issuer, so this rejects only the forgery.
        if (ReadStringClaim(clearPayload, "iss") is { } issClaim
            && ReadIssuerId(clearPayload) is { } vcdmIssuer
            && !string.Equals(issClaim, vcdmIssuer, StringComparison.Ordinal))
        {
            return SecuringVerificationResult.Invalid("sdjwt_issuer_mismatch");
        }

        // No VCDM member a verifier stage reads may be REVEALED via a disclosure: if it is present in the
        // reconstructed payload but absent from the cleartext the stages validate, the corresponding check
        // (validity window, status, schema, structure, binding) would run over the wrong document. Issuance
        // forbids disclosing these (GuardSelectableClaim), but a credential crafted outside this engine
        // could still try — this catches that. NOTE the residual, inherent to SD-JWT: a holder who simply
        // WITHHOLDS a disclosure (so the member is absent from BOTH the cleartext and the reconstructed
        // payload) cannot be detected here — the leftover `_sd` digest is dropped as an indistinguishable
        // decoy (RFC 9901 §4.2.7). The defence against that is keeping these claims non-disclosable at
        // issuance (this engine's own SD-JWT VCs always do, so they are immune; the same posture the
        // SD-JWT VC profile assumes for iss/nbf/exp/status). M6 (presentations) evaluated a verifier-side
        // guard and confirmed it cannot be made precise: a top-level `_sd` digest is indistinguishable
        // between a hidden validity/status member and a legitimately-disclosed non-validity claim (e.g.
        // `name`), so any verifier-side check over-rejects compliant credentials. The principled fix is
        // Type-Metadata-driven disclosability (a future milestone); until then the posture is issuer-side
        // (our issuance is immune) + documentation that a third-party SD-JWT VC with disclosable
        // validity/status members is not safely verifiable for expiry/revocation.
        foreach (var member in NonDisclosableMembers)
        {
            if (disclosed.ContainsKey(member) && !clearPayload.ContainsKey(member))
            {
                return SecuringVerificationResult.Invalid("sdjwt_hidden_member");
            }
        }

        return SecuringVerificationResult.Verified([kid]);
    }

    private static DisclosureFrame BuildFrame(IReadOnlyList<DisclosureSelector> selectors)
    {
        var frame = new DisclosureFrame();
        foreach (var selector in selectors)
        {
            GuardSelectableClaim(selector);
            switch (selector.Kind)
            {
                case DisclosureSelectorKind.Claim:
                    frame.Disclose(selector.ClaimName);
                    break;
                case DisclosureSelectorKind.ObjectProperties:
                    frame.DiscloseObjectProperties(selector.ClaimName, [.. selector.Properties]);
                    break;
                case DisclosureSelectorKind.ArrayElements:
                    frame.DiscloseArrayElements(selector.ClaimName, [.. selector.Indices]);
                    break;
                default:
                    throw new ArgumentException($"Unknown disclosure selector kind '{selector.Kind}'.", nameof(selectors));
            }
        }

        return frame;
    }

    private static void GuardSelectableClaim(DisclosureSelector selector)
    {
        // Disclosing a VCDM member a verifier stage reads (structure / binding / validity / status /
        // schema) would silently disable that check or break the binding. credentialSubject is handled
        // specially (and is deliberately NOT in NonDisclosableMembers): its sub-properties / array elements
        // ARE legitimately disclosable, so only the whole-object form is blocked here. Unlike the
        // validity/status members, a non-conformant credential hiding the whole credentialSubject is caught
        // by the structural validator (a missing/empty credentialSubject is a structure failure in both the
        // revealed and withheld cases), so it does not need a verify-side no-hidden-member entry.
        if (NonDisclosableMembers.Contains(selector.ClaimName)
            || (selector.ClaimName == "credentialSubject" && selector.Kind == DisclosureSelectorKind.Claim))
        {
            throw new ArgumentException(
                $"The VCDM member '{selector.ClaimName}' must stay in the clear and cannot be selectively disclosed; "
                + "disclose credentialSubject sub-properties instead.", nameof(selector));
        }

        // The SD-JWT reserved claims (the substrate also rejects these) — fail early with a clear error.
        if (SdJwtVcConstants.MustNotBeSelectivelyDisclosed.Contains(selector.ClaimName, StringComparer.Ordinal))
        {
            throw new ArgumentException(
                $"The reserved SD-JWT VC claim '{selector.ClaimName}' must not be selectively disclosed.", nameof(selector));
        }
    }

    private static string MapHash(SdHashName hash) => hash switch
    {
        SdHashName.Sha256 => SdHashAlgorithm.Sha256,
        SdHashName.Sha384 => SdHashAlgorithm.Sha384,
        SdHashName.Sha512 => SdHashAlgorithm.Sha512,
        _ => throw new ArgumentOutOfRangeException(nameof(hash), hash, "Unsupported SD-JWT hash algorithm."),
    };

    private static Jwk ToJwk(HolderBindingKey holder) =>
        holder.Multibase is { } multibase
            ? JwkConversion.FromMultikey(multibase, kid: null)
            : JwkConversion.ToPublicJwk(holder.KeyType, holder.PublicKey.ToArray(), kid: null);

    private static string? ReadIssuerId(JsonObject claims) => claims["issuer"] switch
    {
        JsonValue value when value.GetValueKind() == JsonValueKind.String => value.GetValue<string>(),
        JsonObject obj when obj["id"] is JsonValue id && id.GetValueKind() == JsonValueKind.String => id.GetValue<string>(),
        _ => null,
    };

    private static JsonObject ParsePayloadObject(byte[] payload)
    {
        try
        {
            return JsonNode.Parse(payload) as JsonObject
                ?? throw new CredentialFormatException("The SD-JWT issuer-JWT payload is not a JSON object.");
        }
        catch (JsonException ex)
        {
            throw new CredentialFormatException("The SD-JWT issuer-JWT payload is not valid JSON.", ex);
        }
    }

    private static bool StringClaimEquals(JsonObject a, JsonObject b, string name) =>
        string.Equals(ReadStringClaim(a, name), ReadStringClaim(b, name), StringComparison.Ordinal);

    private static string? ReadStringClaim(JsonObject obj, string name) =>
        obj[name] is JsonValue value && value.GetValueKind() == JsonValueKind.String ? value.GetValue<string>() : null;

    // Map the substrate's coded error prefixes to neutral, secret-free credentials-dotnet codes (F10) —
    // never the upstream free-text message. Every case is a definitive negative (→ Failed), so an
    // unrecognized prefix (e.g. if the substrate ever renames one) degrades safely to a generic
    // PROOF_VERIFICATION_ERROR and can never weaken the verdict — this is a maintenance, not a
    // correctness, coupling. Prefer substrate-exposed constant aliases here once they exist upstream.
    private static string MapErrorCode(IReadOnlyList<string> errors)
    {
        var first = errors.Count > 0 ? errors[0] : string.Empty;
        if (first.StartsWith("ISSUER_SIGNATURE_INVALID", StringComparison.Ordinal)
            || first.StartsWith("ISSUER_KEY_INVALID", StringComparison.Ordinal))
        {
            return "PROOF_VERIFICATION_ERROR";
        }

        if (first.StartsWith("VC_MEDIA_TYPE_INVALID", StringComparison.Ordinal)
            || first.StartsWith("MALFORMED", StringComparison.Ordinal))
        {
            return "sdjwt_malformed";
        }

        if (first.StartsWith("DISCLOSURE_INVALID", StringComparison.Ordinal))
        {
            return "sdjwt_disclosure_invalid";
        }

        if (first.StartsWith("VC_DISALLOWED_DISCLOSURE", StringComparison.Ordinal))
        {
            return "sdjwt_disallowed_disclosure";
        }

        if (first.StartsWith("VC_VCT_MISSING", StringComparison.Ordinal))
        {
            return "sdjwt_vct_missing";
        }

        if (first.StartsWith("KB_JWT", StringComparison.Ordinal))
        {
            return "sdjwt_key_binding_invalid";
        }

        return "PROOF_VERIFICATION_ERROR";
    }
}
