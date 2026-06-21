using System.Text.Json.Nodes;
using Credentials.Schema;
using DataProofsDotnet.Jose.SdJwt.Vc;

namespace Credentials.Securing;

/// <summary>
/// Adapts the credentials-dotnet-owned <see cref="ICredentialTypeMetadataResolver"/> hook to the SD-JWT
/// substrate's draft <see cref="ITypeMetadataResolver"/> (fix F3): it is the only place — besides
/// <see cref="SdJwtVcMechanism"/> — that the draft resolver type is named, keeping every draft-version
/// type off the public surface (NFR-005/FR-051/D12).
/// </summary>
internal sealed class TypeMetadataResolverAdapter : ITypeMetadataResolver
{
    private readonly ICredentialTypeMetadataResolver _inner;

    public TypeMetadataResolverAdapter(ICredentialTypeMetadataResolver inner) =>
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    public async Task<JsonObject?> ResolveAsync(string vct, CancellationToken cancellationToken = default)
    {
        // Type Metadata is informational and non-gating in this milestone — a misbehaving resolver must
        // not be able to downgrade an otherwise cryptographically valid credential. A fault is treated as
        // "no metadata available" (best-effort), never a verification verdict. Cancellation still propagates.
        try
        {
            return await _inner.ResolveAsync(vct, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }
}
