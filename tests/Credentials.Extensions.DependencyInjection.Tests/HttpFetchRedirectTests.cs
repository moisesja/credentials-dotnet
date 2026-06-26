using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using Credentials.Extensions.DependencyInjection.Http;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>
/// S2 (SSRF / HTTPS-downgrade): the opt-in HTTP fetch client must NOT follow 3xx redirects. Validating
/// only the initial URL's scheme is bypassable if the client follows a redirect from a trusted HTTPS URL
/// to an internal / cleartext location (169.254.169.254, localhost, http://…) — so the named client
/// disables auto-redirect and the redirected GET never fires. Exercised over loopback HTTP (the defence
/// is scheme/host-independent, so no TLS is needed to prove it).
/// </summary>
public sealed class HttpFetchRedirectTests
{
    [Fact]
    public async Task Named_client_does_not_follow_redirects()
    {
        var (listener, baseUrl) = StartLoopbackListener();
        var redirectUrl = baseUrl + "a";
        var targetUrl = baseUrl + "b";
        var targetHits = 0;

        using var cts = new CancellationTokenSource();
        var serving = ServeAsync(listener, targetUrl, () => Interlocked.Increment(ref targetHits), cts.Token);

        try
        {
            using var provider = new ServiceCollection()
                .AddCredentials(b => b.UseNetDid().UseHttpStatusListFetcher(allowHttp: true))
                .BuildServiceProvider();
            var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpFetch.ClientName);

            // The redirect (302 → /b) must NOT be followed: a 302 is not a success status, so the fetch
            // returns null, and the redirect target is never requested.
            var redirected = await HttpFetch.TryGetAsync(client, redirectUrl, 1_000_000, allowHttp: true, default);
            redirected.Should().BeNull();
            Volatile.Read(ref targetHits).Should().Be(0, "the redirect target must never be requested");

            // Control: a direct fetch of the same target succeeds (proving the listener and fetch path work).
            var direct = await HttpFetch.TryGetAsync(client, targetUrl, 1_000_000, allowHttp: true, default);
            direct.Should().NotBeNull();
            Volatile.Read(ref targetHits).Should().Be(1);
        }
        finally
        {
            cts.Cancel();
            listener.Close();
        }
    }

    // Bind an HttpListener to a free loopback port, retrying on the rare TOCTOU race between probing for a
    // free port and HttpListener binding it (another process can grab the port in between).
    private static (HttpListener Listener, string BaseUrl) StartLoopbackListener()
    {
        for (var attempt = 0; ; attempt++)
        {
            var baseUrl = $"http://127.0.0.1:{GetFreePort()}/";
            var listener = new HttpListener();
            listener.Prefixes.Add(baseUrl);
            try
            {
                listener.Start();
                return (listener, baseUrl);
            }
            catch (HttpListenerException) when (attempt < 5)
            {
                listener.Close();
            }
        }
    }

    private static async Task ServeAsync(HttpListener listener, string targetUrl, Action onTargetHit, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await listener.GetContextAsync().ConfigureAwait(false);
            }
            catch
            {
                return; // listener stopped
            }

            var path = context.Request.Url!.AbsolutePath;
            if (path.EndsWith("/a", StringComparison.Ordinal))
            {
                context.Response.StatusCode = 302;
                context.Response.RedirectLocation = targetUrl;
            }
            else
            {
                onTargetHit();
                context.Response.StatusCode = 200;
                var body = Encoding.UTF8.GetBytes("{}");
                context.Response.OutputStream.Write(body, 0, body.Length);
            }

            context.Response.Close();
        }
    }

    private static int GetFreePort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }
}
