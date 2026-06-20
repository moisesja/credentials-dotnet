using System.Net.Http;
using Credentials.Status;

namespace Credentials.Extensions.DependencyInjection.Http;

/// <summary>
/// An opt-in <see cref="IStatusListFetcher"/> that dereferences <c>statusListCredential</c> over HTTP(S)
/// with a bounded response size. <strong>Egress is the caller's responsibility</strong>: this issues a GET
/// to whatever URL the credential names, so deployments that need SSRF protection must front it with an
/// allowlisting <see cref="HttpClient"/> handler / proxy (registered against the
/// <c>"credentials-dotnet"</c> named client). Enable with <c>builder.UseHttpStatusListFetcher()</c>.
/// </summary>
internal sealed class HttpStatusListFetcher : IStatusListFetcher
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly long _maxBytes;
    private readonly bool _allowHttp;

    public HttpStatusListFetcher(IHttpClientFactory httpClientFactory, long maxBytes, bool allowHttp)
    {
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _maxBytes = maxBytes;
        _allowHttp = allowHttp;
    }

    public async Task<StatusListFetchResult> FetchAsync(StatusListReference reference, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reference);
        var client = _httpClientFactory.CreateClient(HttpFetch.ClientName);
        var bytes = await HttpFetch.TryGetAsync(client, reference.StatusListCredential, _maxBytes, _allowHttp, cancellationToken).ConfigureAwait(false);
        return bytes is null
            ? StatusListFetchResult.NotFound("http_fetch_failed")
            : StatusListFetchResult.Found(bytes);
    }
}
