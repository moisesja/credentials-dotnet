using System.Net.Http;

namespace Credentials.Extensions.DependencyInjection.Http;

/// <summary>Shared bounded HTTP-GET helper for the opt-in status/schema fetchers.</summary>
internal static class HttpFetch
{
    /// <summary>The named <see cref="HttpClient"/> the opt-in fetchers resolve.</summary>
    public const string ClientName = "credentials-dotnet";

    /// <summary>
    /// GETs <paramref name="url"/> and reads at most <paramref name="maxBytes"/> bytes of body. Returns the
    /// bytes on a 2xx response within the cap, or <see langword="null"/> on any non-success / oversize /
    /// transport failure / disallowed-scheme URL (the caller maps null to an Indeterminate check, never a
    /// throw). HTTPS is required unless <paramref name="allowHttp"/> is set — a cleartext fetch of a status
    /// list or schema can be MitM'd to substitute a cleared list or a permissive schema. User cancellation
    /// propagates; an HttpClient timeout does not.
    /// </summary>
    public static async Task<byte[]?> TryGetAsync(HttpClient client, string url, long maxBytes, bool allowHttp, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var schemeOk = uri.Scheme == Uri.UriSchemeHttps || (allowHttp && uri.Scheme == Uri.UriSchemeHttp);
        if (!schemeOk)
        {
            return null;
        }

        try
        {
            using var response = await client
                .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            // Reject obviously-oversized bodies up front when the server declares a length.
            if (response.Content.Headers.ContentLength is { } declared && declared > maxBytes)
            {
                return null;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            return await ReadCappedAsync(stream, maxBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Timeouts, DNS failures, oversize, TLS errors — all become "not found" (Indeterminate upstream).
            return null;
        }
    }

    private static async Task<byte[]?> ReadCappedAsync(Stream body, long maxBytes, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        long total = 0;
        int read;
        while ((read = await body.ReadAsync(chunk.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > maxBytes)
            {
                return null; // do not trust a declared Content-Length; cap on bytes actually read
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }
}
