using Credentials.Cryptography;
using Microsoft.Extensions.DependencyInjection.Extensions;

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
}
