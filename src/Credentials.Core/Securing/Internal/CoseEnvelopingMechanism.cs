using System.Text;
using Credentials.Resolution;
using DataProofsDotnet.Cose;
using NetCrypto;

namespace Credentials.Securing;

/// <summary>
/// The enveloping VC-COSE securing mechanism — the single bridge to <see cref="VcCose"/> (FR-050). It
/// signs the credential's exact UTF-8 bytes into a tagged COSE_Sign1 message (<c>content-type</c> and
/// <c>typ</c> pinned by the substrate in the protected header), and verifies one by decoding the
/// unprotected <c>kid</c>, resolving the issuer's key, and mapping the substrate's result-style outcome
/// to the neutral seam.
///
/// <para>F7/FR-045 mapping: the key is resolved before the verify so a DID/IO failure is
/// <see cref="SecuringVerificationStatus.Unresolvable"/> (→ Indeterminate); a bad signature (or a
/// wrong/absent pinned header) is a <see cref="CoseSign1VerificationResult.Verified"/><c>==false</c>
/// outcome mapped to <see cref="SecuringVerificationStatus.Invalid"/> (→ Failed). The result-style
/// verify never throws on a bad signature.</para>
/// </summary>
internal sealed class CoseEnvelopingMechanism : ISecuringMechanism, IEnvelopeIngest
{
    private readonly IEnvelopeKeyResolver _keyResolver;

    public CoseEnvelopingMechanism(IEnvelopeKeyResolver keyResolver) =>
        _keyResolver = keyResolver ?? throw new ArgumentNullException(nameof(keyResolver));

    public SecuringForm Form => SecuringForm.Cose;

    public IReadOnlyCollection<string> SuiteNames => [];

    public bool IsAvailable => true;

    public async Task<SecureOutcome> SecureAsync(SecureRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var algorithm = ToCoseAlgorithm(request.Signer.KeyType);   // fail fast on an unsupported key
        var keyId = Encoding.UTF8.GetBytes(request.VerificationMethod);
        var bytes = await VcCose.EnvelopeCredentialAsync(request.Payload, request.Signer, algorithm, keyId, cancellationToken)
            .ConfigureAwait(false);
        return SecureOutcome.ForCose(bytes);
    }

    public Credential Ingest(ReadOnlyMemory<byte> envelope)
    {
        CoseSign1Message message;
        try
        {
            message = CoseSign1.Decode(envelope);
        }
        catch (CoseException ex)
        {
            throw new CredentialFormatException("The COSE envelope could not be decoded.", ex);
        }

        if (message.Payload is not { } payload)
        {
            throw new CredentialFormatException("The COSE envelope has no embedded credential payload.");
        }

        // Byte-faithful inner document (the payload the signature covers); the proof stage verifies the
        // same envelope. No re-serialization (sign-exact-bytes).
        var inner = CredentialDocument.Parse(payload);
        return Credential.FromEnvelope(inner, SecuringState.Cose, envelope);
    }

    public async Task<SecuringVerificationResult> VerifyAsync(VerifyRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Envelope is not { } envelope)
        {
            return SecuringVerificationResult.NoProof;
        }

        string? kid;
        try
        {
            var message = CoseSign1.Decode(envelope);
            kid = message.KeyId is { } id ? Encoding.UTF8.GetString(id.Span) : null;
        }
        catch (CoseException)
        {
            return SecuringVerificationResult.Invalid("envelope_malformed");
        }

        if (string.IsNullOrEmpty(kid))
        {
            // The kid is the only signer identity to bind the issuer to — reject (fail closed).
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

        CoseSign1VerificationResult result;
        try
        {
            result = VcCose.Verify(envelope, resolved.KeyType, resolved.PublicKey);
        }
        catch (CoseException)
        {
            return SecuringVerificationResult.Invalid("envelope_malformed");
        }

        if (result.Verified)
        {
            return SecuringVerificationResult.Verified([kid]);
        }

        var code = result.Failure?.Code switch
        {
            CoseVerificationErrorCode.InvalidSignature => "PROOF_VERIFICATION_ERROR",
            CoseVerificationErrorCode.InvalidType or CoseVerificationErrorCode.InvalidContentType => "envelope_malformed",
            _ => "proof_invalid",
        };
        return SecuringVerificationResult.Invalid(code);
    }

    // COSE v1 supports EdDSA / ES256 / ES384 / ES256K. An out-of-scope key (P-521, X25519, BLS, …)
    // fails fast rather than silently mis-signing — mirroring JwsSigner's NotSupportedException for JOSE.
    private static CoseAlgorithm ToCoseAlgorithm(KeyType keyType) => keyType switch
    {
        KeyType.Ed25519 => CoseAlgorithm.EdDsa,
        KeyType.P256 => CoseAlgorithm.ES256,
        KeyType.P384 => CoseAlgorithm.ES384,
        KeyType.Secp256k1 => CoseAlgorithm.ES256K,
        _ => throw new NotSupportedException($"COSE enveloping does not support key type '{keyType}'."),
    };
}
