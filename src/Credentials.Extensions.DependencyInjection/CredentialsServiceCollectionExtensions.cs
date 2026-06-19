using Credentials;
using Credentials.Cryptography;
using Credentials.Resolution;
using Credentials.Roles;
using Credentials.Securing;
using DataProofsDotnet.DataIntegrity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NetDid.Core;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The public dependency-injection entry point: <c>services.AddCredentials(b =&gt; …)</c>.
/// </summary>
public static class CredentialsServiceCollectionExtensions
{
    /// <summary>
    /// Registers credentials-dotnet services: the engine crypto seams, the Data Integrity securing
    /// mechanism (over the proofs layer), the NetDid verification-method resolver, and the
    /// <see cref="IIssuer"/> / <see cref="IVerifier"/> roles. Fails fast (naming the fix) when a
    /// required substrate is missing.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Builder callback — call <c>UseNetDid()</c> to register DID resolution (FR-080).</param>
    /// <returns>The same <paramref name="services"/> for chaining.</returns>
    /// <exception cref="InvalidOperationException">A required substrate (NetDid resolution) was not registered.</exception>
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

        // Data Integrity securing substrate (FR-011/FR-050/FR-053). The default suites are the
        // System.Text.Json-native JCS suites — keeping the default closure free of the RDFC stack
        // (dotNetRDF / Newtonsoft, NFR-002). The RDFC suites are contributed by the opt-in
        // Credentials.Rdfc package, which registers more ICryptosuite services that the registry
        // collects below. A new suite is added with no public-API change (FR-053).
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ICryptosuite, EddsaJcs2022Cryptosuite>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ICryptosuite, EcdsaJcs2019Cryptosuite>());
        services.TryAddSingleton(sp =>
        {
            var registry = new CryptosuiteRegistry();
            foreach (var suite in sp.GetServices<ICryptosuite>())
            {
                registry.Register(suite);
            }

            return registry;
        });
        services.TryAddSingleton(sp => new DataIntegrityProofPipeline(sp.GetRequiredService<CryptosuiteRegistry>()));

        // NetDid -> proofs verification-method resolver (FR-080).
        services.TryAddSingleton<IVerificationMethodResolver>(sp =>
            new NetDidVerificationMethodResolver(sp.GetRequiredService<IDidResolver>()));

        // The securing mechanisms + their registry, and the role services.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISecuringMechanism, DataIntegrityMechanism>(sp =>
            new DataIntegrityMechanism(
                sp.GetRequiredService<DataIntegrityProofPipeline>(),
                sp.GetRequiredService<IVerificationMethodResolver>())));
        services.TryAddSingleton(sp => new SecuringMechanismRegistry(sp.GetServices<ISecuringMechanism>()));
        services.TryAddSingleton<ISecuringCapabilities>(sp => sp.GetRequiredService<SecuringMechanismRegistry>());
        services.TryAddSingleton<IIssuer>(sp => new DefaultIssuer(sp.GetRequiredService<SecuringMechanismRegistry>()));
        services.TryAddSingleton<IVerifier>(sp => new DefaultVerifier(sp.GetRequiredService<SecuringMechanismRegistry>()));

        // Fail fast (FR-080): the verifier needs a DID resolver to resolve verification methods.
        if (!IsRegistered<IDidResolver>(services))
        {
            throw new InvalidOperationException(
                "AddCredentials: no NetDid IDidResolver is registered. Call builder.UseNetDid(...) (or register "
                + "an IDidResolver) so the verifier can resolve proof verification methods (FR-080).");
        }

        return services;
    }

    private static bool IsRegistered<T>(IServiceCollection services)
    {
        foreach (var descriptor in services)
        {
            if (descriptor.ServiceType == typeof(T))
            {
                return true;
            }
        }

        return false;
    }
}
