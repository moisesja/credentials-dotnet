using System.Text.Json;
using Credentials;
using Credentials.Cryptography;
using DataProofsDotnet;
using DataProofsDotnet.Rdfc.DataIntegrity;
using NetCrypto;

namespace Credentials.Rdfc;

/// <summary>
/// The default <see cref="IBbsDeriver"/> — the single bridge to <see cref="Bbs2023Cryptosuite.DeriveProof"/>
/// (FR-050). It draws the BBS presentation header from the engine RNG seam (FR-052/F9, so repeated
/// derivations are unlinkable), delegates the zero-knowledge derivation to the substrate (which returns the
/// assembled reveal document — the engine never hand-builds or strips a <c>proof</c>), and re-ingests the
/// result as an ordinary embedded Data Integrity credential. The draft <see cref="Bbs2023Cryptosuite"/> is
/// confined here and never escapes onto the public surface (NFR-005).
/// </summary>
internal sealed class Bbs2023Deriver : IBbsDeriver
{
    // 32 bytes of CSPRNG: a presentation header / nonce that binds the derived proof and makes repeated
    // derivations of the same base unlinkable (BBS Cryptosuites v1.0; FR-031).
    private const int PresentationHeaderBytes = 32;

    private readonly IRandomSource _random;
    private readonly Bbs2023Cryptosuite _suite = new();

    public Bbs2023Deriver(IRandomSource random) =>
        _random = random ?? throw new ArgumentNullException(nameof(random));

    public Task<Credential> DeriveAsync(
        Credential baseCredential, BbsDisclosureRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(baseCredential);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        if (!_suite.IsAvailable)
        {
            throw new NotSupportedException(
                "bbs-2023 selective disclosure requires the BBS native library, which is not available on this host.");
        }

        // BBS proof derivation is CPU-bound; offload it off the caller's thread so the role boundary is
        // honestly async rather than a synchronous call wrapped in a completed Task (F5).
        return Task.Run(() => Derive(baseCredential, request), cancellationToken);
    }

    private Credential Derive(Credential baseCredential, BbsDisclosureRequest request)
    {
        var presentationHeader = _random.GetBytes(PresentationHeaderBytes);

        JsonElement reveal;
        try
        {
            reveal = _suite.DeriveProof(baseCredential.AsElement(), request.RevealPointers, presentationHeader);
        }
        catch (BbsUnavailableException ex)
        {
            throw new NotSupportedException(
                "bbs-2023 selective disclosure requires the BBS native library, which is not available on this host.", ex);
        }
        catch (ProofGenerationException ex)
        {
            throw new CredentialFormatException(
                "The credential is not a valid bbs-2023 base credential, or the disclosure pointers are invalid.", ex);
        }

        // Re-ingest the substrate-assembled reveal document as the derived credential: an embedded
        // Data Integrity credential carrying the derived proof, verifiable through the standard pipeline.
        return Credential.Parse(JsonSerializer.SerializeToUtf8Bytes(reveal));
    }
}
