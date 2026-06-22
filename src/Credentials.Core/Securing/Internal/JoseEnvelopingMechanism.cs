using System.Text;
using Credentials.Resolution;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Signing;

namespace Credentials.Securing;

/// <summary>
/// The enveloping VC-JOSE securing mechanism — the single bridge to <see cref="VcJose"/> (FR-050). It
/// signs the credential's exact UTF-8 bytes into a compact JWS (<c>typ=vc+jwt</c>, <c>cty=vc</c> are
/// pinned by the substrate), and verifies a compact JWS by resolving the protected-header <c>kid</c> to
/// the issuer's key and mapping the substrate's throw-based result to the neutral seam.
///
/// <para>F7/FR-045 mapping: the key is resolved asynchronously <em>before</em> the synchronous substrate
/// verify so a DID/IO failure is <see cref="SecuringVerificationStatus.Unresolvable"/> (→ Indeterminate),
/// while a bad signature (<see cref="JoseCryptoException"/>) or a wrong/absent <c>typ</c>/<c>cty</c>
/// (<see cref="MalformedJoseException"/>) is a definitive <see cref="SecuringVerificationStatus.Invalid"/>
/// (→ Failed). Neither exception is allowed to escape this method.</para>
/// </summary>
internal sealed class JoseEnvelopingMechanism : ISecuringMechanism, IEnvelopeIngest
{
    // The W3C VC-JOSE-COSE presentation media type / JWS typ for an enveloped Verifiable Presentation.
    private const string VpJwtType = "vp+jwt";

    private readonly IEnvelopeKeyResolver _keyResolver;

    public JoseEnvelopingMechanism(IEnvelopeKeyResolver keyResolver) =>
        _keyResolver = keyResolver ?? throw new ArgumentNullException(nameof(keyResolver));

    public SecuringForm Form => SecuringForm.Jose;

    public IReadOnlyCollection<string> SuiteNames => [];

    public bool IsAvailable => true;

    public async Task<SecureOutcome> SecureAsync(SecureRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // The enveloping forms sign Payload, never Document (SecureRequest invariant) — fail loudly if a
        // caller forgot to set it rather than silently signing empty bytes (or the wrong, unmutated Document).
        if (request.Payload.IsEmpty)
        {
            throw new InvalidOperationException(
                "JOSE enveloping signs SecureRequest.Payload (Document is ignored); Payload must be non-empty.");
        }

        // JwsSigner derives the JOSE alg from the signer's key type and throws NotSupportedException for
        // an unsupported key (P-521/RSA) — fail fast at issuance rather than mis-sign.
        var signer = new JwsSigner(request.Signer, request.VerificationMethod);

        // A presentation is bound as a generic compact JWS with typ=vp+jwt (no vp helper in the substrate,
        // G1); a credential uses VcJose (typ=vc+jwt, cty=vc). Both sign the exact payload bytes.
        var compact = request.Kind == SecuringDocumentKind.Presentation
            ? await JwsBuilder.BuildCompactAsync(request.Payload, signer, typ: VpJwtType, cancellationToken: cancellationToken)
                .ConfigureAwait(false)
            : await VcJose.EnvelopeCredentialAsync(request.Payload, signer, cancellationToken).ConfigureAwait(false);
        return SecureOutcome.ForJose(compact);
    }

    public Credential Ingest(ReadOnlyMemory<byte> envelope)
    {
        var compact = Encoding.UTF8.GetString(envelope.Span);
        var payload = CompactJws.DecodePayload(compact);

        // The inner document is byte-faithful (ReceivedBytes), so it equals the bytes the signature
        // covers; the proof stage then verifies the same envelope. No re-serialization (sign-exact-bytes).
        var inner = CredentialDocument.Parse(payload);
        return Credential.FromEnvelope(inner, SecuringState.Jose, envelope);
    }

    public async Task<SecuringVerificationResult> VerifyAsync(VerifyRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Envelope is not { } envelopeBytes)
        {
            return SecuringVerificationResult.NoProof;
        }

        var compact = Encoding.UTF8.GetString(envelopeBytes.Span);

        var kid = CompactJws.ReadKid(compact);
        if (string.IsNullOrEmpty(kid))
        {
            // With no signer identity there is nothing to bind the issuer to — reject (fail closed).
            return SecuringVerificationResult.Invalid("envelope_kid_missing");
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
                // The DID resolved but does not publish this kid — a definitive negative, not Indeterminate.
                return SecuringVerificationResult.Invalid("verification_method_not_found");
        }

        var resolved = resolution.Key;
        Jwk jwk;
        try
        {
            // Build the JWK from the multibase multikey (the substrate handles EC point encoding);
            // fall back to the raw bytes if no multibase was resolved.
            jwk = resolved.Multibase is { } multibase
                ? JwkConversion.FromMultikey(multibase, kid)
                : JwkConversion.ToPublicJwk(resolved.KeyType, resolved.PublicKey.ToArray(), kid);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The resolved key cannot be expressed as a JWK (e.g. an unusable curve) — unknown validity.
            return SecuringVerificationResult.Unresolvable("verification_method_unresolvable");
        }

        byte[] verifiedPayload;
        if (request.Kind == SecuringDocumentKind.Presentation)
        {
            // Presentation binding: assert typ=vp+jwt (the substrate's generic parser does not), then
            // verify the holder signature over the verbatim token.
            if (!string.Equals(CompactJws.ReadTyp(compact), VpJwtType, StringComparison.Ordinal))
            {
                return SecuringVerificationResult.Invalid("envelope_malformed");
            }

            try
            {
                verifiedPayload = JwsParser.ParseCompact(compact, _ => jwk, new JoseCryptoProvider()).PayloadBytes;
            }
            catch (MalformedJoseException)
            {
                return SecuringVerificationResult.Invalid("envelope_malformed");
            }
            catch (JoseCryptoException)
            {
                return SecuringVerificationResult.Invalid("PROOF_VERIFICATION_ERROR");
            }
        }
        else
        {
            try
            {
                // The resolver already fetched the published key for this kid; the callback ignores its arg.
                verifiedPayload = VcJose.VerifyCredential(compact, _ => jwk, cryptoProvider: null);
            }
            catch (MalformedJoseException)
            {
                // Wrong/absent typ/cty or a structurally invalid token — a definitive negative.
                return SecuringVerificationResult.Invalid("envelope_malformed");
            }
            catch (JoseCryptoException)
            {
                // The signature did not verify against the resolved key — a definitive negative.
                return SecuringVerificationResult.Invalid("PROOF_VERIFICATION_ERROR");
            }
        }

        // The bytes the downstream stages validate (the ingested inner document) must be exactly the
        // bytes the signature covered — do not depend on the substrate decoding the payload as we did.
        if (request.ExpectedPayload is { } expected && !verifiedPayload.AsSpan().SequenceEqual(expected.Span))
        {
            return SecuringVerificationResult.Invalid("envelope_payload_mismatch");
        }

        return SecuringVerificationResult.Verified([kid]);
    }
}
