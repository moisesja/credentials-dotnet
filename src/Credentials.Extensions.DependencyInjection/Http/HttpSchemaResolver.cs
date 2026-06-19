using System.Net.Http;
using Credentials.Schema;

namespace Credentials.Extensions.DependencyInjection.Http;

/// <summary>
/// An opt-in <see cref="ICredentialSchemaResolver"/> that fetches <c>credentialSchema</c> documents over
/// HTTP(S) with a bounded response size. <strong>Egress is the caller's responsibility</strong> (SSRF): it
/// GETs whatever URL the credential names, so front it with an allowlisting handler / proxy on the
/// <c>"credentials-dotnet"</c> named client where needed. The engine still enforces any declared
/// <c>digestSRI</c> over the returned bytes. Enable with <c>builder.UseHttpSchemaResolver()</c>.
/// </summary>
internal sealed class HttpSchemaResolver : ICredentialSchemaResolver
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly long _maxBytes;

    public HttpSchemaResolver(IHttpClientFactory httpClientFactory, long maxBytes)
    {
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _maxBytes = maxBytes;
    }

    public async Task<SchemaResolutionResult> ResolveAsync(SchemaReference reference, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reference);
        var client = _httpClientFactory.CreateClient(HttpFetch.ClientName);
        var bytes = await HttpFetch.TryGetAsync(client, reference.Id, _maxBytes, cancellationToken).ConfigureAwait(false);
        return bytes is null
            ? SchemaResolutionResult.NotFound("http_fetch_failed")
            : SchemaResolutionResult.Found(new ResolvedSchema(reference.Id, SchemaDialect.JsonSchema2020_12, bytes));
    }
}
