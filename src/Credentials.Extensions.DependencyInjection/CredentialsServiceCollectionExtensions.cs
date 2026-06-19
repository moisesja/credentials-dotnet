using Credentials.Cryptography;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The public dependency-injection entry point: <c>services.AddCredentials(b =&gt; …)</c>.
/// </summary>
public static class CredentialsServiceCollectionExtensions
{
    /// <summary>
    /// Registers credentials-dotnet services. Wires the engine's crypto seams (<see cref="IRandomSource"/>,
    /// <see cref="IDigestService"/>) with their defaults — overridable through the
    /// <see cref="CredentialsBuilder"/> — and binds <see cref="CredentialsOptions"/>. Later milestones
    /// add the Issuer/Holder/Verifier roles and the substrate wiring; an unconfigured optional seam
    /// always resolves to its default.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Builder callback for configuring the engine.</param>
    /// <returns>The same <paramref name="services"/> for chaining.</returns>
    public static IServiceCollection AddCredentials(this IServiceCollection services, Action<CredentialsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new CredentialsBuilder(services);
        configure(builder);

        services.AddOptions<CredentialsOptions>();

        // Engine crypto seams (FR-052). Registered with TryAdd so a builder override wins.
        services.TryAddSingleton<IRandomSource, BclRandomSource>();
        services.TryAddSingleton<IDigestService, NetCryptoDigestService>();

        return services;
    }
}
