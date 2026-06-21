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
    private readonly IEnvelopeKeyResolver _keyResolver;

    public JoseEnvelopingMechanism(IEnvelopeKeyResolver keyResolver) =>
        _keyResolver = keyResolver ?? throw new ArgumentNullException(nameof(keyResolver));

    public SecuringForm Form => SecuringForm.Jose;

    public IReadOnlyCollection<string> SuiteNames => [];

    public bool IsAvailable => true;

    public async Task<SecureOutcome> SecureAsync(SecureRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // JwsSigner derives the JOSE alg from the signer's key type and throws NotSupportedException for
        // an unsupported key (P-521/RSA) — fail fast at issuance rather than mis-sign.
        var signer = new JwsSigner(request.Signer, request.VerificationMethod);
        var compact = await VcJose.EnvelopeCredentialAsync(request.Payload, signer, cancellationToken)
            .ConfigureAwait(false);
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

        EnvelopeKey? key;
        try
        {
            key = await _keyResolver.ResolveAsync(kid, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return SecuringVerificationResult.Unresolvable("verification_method_unresolvable");
        }

        if (key is not { } resolved)
        {
            return SecuringVerificationResult.Unresolvable("verification_method_unresolvable");
        }

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

        // The bytes the downstream stages validate (the ingested inner document) must be exactly the
        // bytes the signature covered — do not depend on the substrate decoding the payload as we did.
        if (request.ExpectedPayload is { } expected && !verifiedPayload.AsSpan().SequenceEqual(expected.Span))
        {
            return SecuringVerificationResult.Invalid("envelope_payload_mismatch");
        }

        return SecuringVerificationResult.Verified([kid]);
    }
}
