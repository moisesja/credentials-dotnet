using System.Net.Http;
using Credentials.Cryptography;
using Credentials.Extensions.DependencyInjection.Http;
using Credentials.Schema;
using Credentials.Status;
using Credentials.Trust;
using NetDid.Extensions.DependencyInjection;
using NetDid.Method.Key;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Configures credentials-dotnet services on an <see cref="IServiceCollection"/>. Returned by
/// <see cref="CredentialsServiceCollectionExtensions.AddCredentials"/>; each method registers a piece
/// of the engine and returns <c>this</c> so calls can chain. Later milestones extend this builder
/// with the substrate wiring (NetDid resolution, DataProofs securing) and the policy hooks.
/// </summary>
public sealed class CredentialsBuilder
{
    internal CredentialsBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    /// <summary>The underlying service collection — exposed so consumers can register supporting services in-line.</summary>
    public IServiceCollection Services { get; }

    /// <summary>
    /// Registers NetDid resolution (with <c>did:key</c> enabled by default) so the verifier can resolve
    /// issuer/holder verification methods (FR-080). Extend the <paramref name="configure"/> callback to
    /// add more DID methods or enable caching.
    /// </summary>
    public CredentialsBuilder UseNetDid(Action<NetDidBuilder>? configure = null)
    {
        // Idempotent: a second UseNetDid would register did:key twice, and NetDid's composite resolver
        // throws on a duplicate method. Register a marker so re-entry is a safe no-op.
        if (Services.Any(d => d.ServiceType == typeof(NetDidRegistrationMarker)))
        {
            return this;
        }

        Services.AddSingleton<NetDidRegistrationMarker>();
        Services.AddNetDid(builder =>
        {
            builder.AddDidKey();
            configure?.Invoke(builder);
        });
        return this;
    }

    private sealed class NetDidRegistrationMarker;

    /// <summary>Tweaks engine-wide <see cref="CredentialsOptions"/>.</summary>
    public CredentialsBuilder Configure(Action<CredentialsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.AddOptions<CredentialsOptions>().Configure(configure);
        return this;
    }

    /// <summary>Overrides the engine's randomness seam (default: <see cref="BclRandomSource"/>).</summary>
    public CredentialsBuilder UseRandomSource<T>() where T : class, IRandomSource
    {
        Services.AddSingleton<IRandomSource, T>();
        return this;
    }

    /// <summary>Overrides the engine's randomness seam with a specific instance.</summary>
    public CredentialsBuilder UseRandomSource(IRandomSource instance)
    {
        ArgumentNullException.ThrowIfNull(instance);
        Services.AddSingleton(instance);
        return this;
    }

    /// <summary>Overrides the engine's hashing seam (default: <see cref="NetCryptoDigestService"/>).</summary>
    public CredentialsBuilder UseDigestService<T>() where T : class, IDigestService
    {
        Services.AddSingleton<IDigestService, T>();
        return this;
    }

    /// <summary>Overrides the engine's hashing seam with a specific instance.</summary>
    public CredentialsBuilder UseDigestService(IDigestService instance)
    {
        ArgumentNullException.ThrowIfNull(instance);
        Services.AddSingleton(instance);
        return this;
    }

    /// <summary>Default cap on a fetched status-list credential body (bytes), for the HTTP fetcher.</summary>
    private const long DefaultStatusListMaxBytes = 4L * 1024 * 1024;

    /// <summary>Default cap on a fetched schema document body (bytes), for the HTTP resolver.</summary>
    private const long DefaultSchemaMaxBytes = 1L * 1024 * 1024;

    /// <summary>
    /// Registers the shared <c>"credentials-dotnet"</c> named <see cref="HttpClient"/> the opt-in fetchers
    /// resolve, with HTTP redirect following disabled. A status list / schema is a single canonical
    /// document, so there is no legitimate redirect to follow; disabling it means an attacker cannot use a
    /// 3xx redirect from a trusted HTTPS URL to reach an internal / cleartext location (SSRF / downgrade) —
    /// the redirected request never fires. A caller who genuinely needs redirects (and accepts that SSRF
    /// posture) can reconfigure the named client's primary handler.
    /// </summary>
    private bool _fetchHttpClientConfigured;

    private void ConfigureFetchHttpClient()
    {
        // Idempotent: chaining UseHttpStatusListFetcher().UseHttpSchemaResolver() must not grow the named
        // client's handler-builder action list with duplicate (identical) registrations.
        if (_fetchHttpClientConfigured)
        {
            return;
        }

        _fetchHttpClientConfigured = true;
        Services.AddHttpClient(HttpFetch.ClientName)
            .ConfigurePrimaryHttpMessageHandler(static () => new HttpClientHandler { AllowAutoRedirect = false });
    }

    // ── Status (FR-022/FR-081): the status-list fetch hook. Unset ⇒ the status check is Skipped. ──

    /// <summary>Registers a caller-supplied <see cref="IStatusListFetcher"/> (FR-081).</summary>
    public CredentialsBuilder UseStatusListFetcher<T>() where T : class, IStatusListFetcher
    {
        Services.AddSingleton<IStatusListFetcher, T>();
        return this;
    }

    /// <summary>Registers a specific <see cref="IStatusListFetcher"/> instance.</summary>
    public CredentialsBuilder UseStatusListFetcher(IStatusListFetcher instance)
    {
        ArgumentNullException.ThrowIfNull(instance);
        Services.AddSingleton(instance);
        return this;
    }

    /// <summary>
    /// Registers an opt-in HTTP(S) <see cref="IStatusListFetcher"/> with a bounded response size. HTTPS is
    /// required by default (pass <paramref name="allowHttp"/> to permit cleartext, which a network attacker
    /// can MitM to substitute a cleared status list). By default the named client does <strong>not</strong>
    /// follow HTTP redirects, so an attacker-named HTTPS URL cannot reach a cleartext / internal location via
    /// a 3xx redirect. Egress is otherwise the caller's responsibility (SSRF): front the
    /// <c>"credentials-dotnet"</c> named <c>HttpClient</c> with an allowlisting handler / proxy where required
    /// (a caller that replaces its primary handler owns the redirect posture).
    /// </summary>
    public CredentialsBuilder UseHttpStatusListFetcher(long maxResponseBytes = DefaultStatusListMaxBytes, bool allowHttp = false)
    {
        ConfigureFetchHttpClient();
        Services.AddSingleton<IStatusListFetcher>(sp =>
            new HttpStatusListFetcher(sp.GetRequiredService<IHttpClientFactory>(), maxResponseBytes, allowHttp));
        return this;
    }

    // ── Schema (FR-070/FR-081): the schema fetch hook. Unset ⇒ the schema check is Skipped. ──

    /// <summary>Registers a caller-supplied <see cref="ICredentialSchemaResolver"/> (FR-081).</summary>
    public CredentialsBuilder UseSchemaResolver<T>() where T : class, ICredentialSchemaResolver
    {
        Services.AddSingleton<ICredentialSchemaResolver, T>();
        return this;
    }

    /// <summary>Registers a specific <see cref="ICredentialSchemaResolver"/> instance.</summary>
    public CredentialsBuilder UseSchemaResolver(ICredentialSchemaResolver instance)
    {
        ArgumentNullException.ThrowIfNull(instance);
        Services.AddSingleton(instance);
        return this;
    }

    /// <summary>
    /// Registers an opt-in HTTP(S) <see cref="ICredentialSchemaResolver"/> with a bounded response size.
    /// HTTPS is required by default (pass <paramref name="allowHttp"/> to permit cleartext, which a network
    /// attacker can MitM to substitute a permissive schema). By default the named client does
    /// <strong>not</strong> follow HTTP redirects, so an attacker-named HTTPS URL cannot reach a cleartext /
    /// internal location via a 3xx redirect. Egress is otherwise the caller's responsibility (SSRF), as for
    /// the status fetcher (a caller that replaces its primary handler owns the redirect posture); the engine
    /// still enforces any declared <c>digestSRI</c> over the fetched bytes.
    /// </summary>
    public CredentialsBuilder UseHttpSchemaResolver(long maxResponseBytes = DefaultSchemaMaxBytes, bool allowHttp = false)
    {
        ConfigureFetchHttpClient();
        Services.AddSingleton<ICredentialSchemaResolver>(sp =>
            new HttpSchemaResolver(sp.GetRequiredService<IHttpClientFactory>(), maxResponseBytes, allowHttp));
        return this;
    }

    // ── SD-JWT VC Type Metadata (FR-013/FR-017): the vct metadata hook. Unset ⇒ no metadata retrieval. ──

    /// <summary>Registers a caller-supplied <see cref="ICredentialTypeMetadataResolver"/> (SD-JWT VC <c>vct</c> Type Metadata).</summary>
    public CredentialsBuilder UseTypeMetadataResolver<T>() where T : class, ICredentialTypeMetadataResolver
    {
        Services.AddSingleton<ICredentialTypeMetadataResolver, T>();
        return this;
    }

    /// <summary>Registers a specific <see cref="ICredentialTypeMetadataResolver"/> instance.</summary>
    public CredentialsBuilder UseTypeMetadataResolver(ICredentialTypeMetadataResolver instance)
    {
        ArgumentNullException.ThrowIfNull(instance);
        Services.AddSingleton(instance);
        return this;
    }

    // ── Issuer trust (FR-082): the explicit, optional trust step. Unset ⇒ issuer-trust is Skipped. ──

    /// <summary>Registers a caller-supplied <see cref="IIssuerTrustPolicy"/> (FR-082). No trust lists ship in the library.</summary>
    public CredentialsBuilder UseIssuerTrustPolicy<T>() where T : class, IIssuerTrustPolicy
    {
        Services.AddSingleton<IIssuerTrustPolicy, T>();
        return this;
    }

    /// <summary>Registers a specific <see cref="IIssuerTrustPolicy"/> instance.</summary>
    public CredentialsBuilder UseIssuerTrustPolicy(IIssuerTrustPolicy instance)
    {
        ArgumentNullException.ThrowIfNull(instance);
        Services.AddSingleton(instance);
        return this;
    }
}
