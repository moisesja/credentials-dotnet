using Credentials;
using Credentials.Cryptography;
using Credentials.Resolution;
using Credentials.Roles;
using Credentials.Schema;
using Credentials.Securing;
using Credentials.Status;
using Credentials.Trust;
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

        // NetDid -> enveloping key resolver (M3, FR-012/FR-080): resolves a JWS/COSE kid (a DID URL) to
        // neutral NetCrypto key material the JOSE mechanism converts to a JWK and the COSE mechanism uses
        // as a raw key.
        services.TryAddSingleton<IEnvelopeKeyResolver>(sp =>
            new NetDidEnvelopeKeyResolver(sp.GetRequiredService<IDidResolver>()));

        // The securing mechanisms + their registry, and the role services.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISecuringMechanism, DataIntegrityMechanism>(sp =>
            new DataIntegrityMechanism(
                sp.GetRequiredService<DataIntegrityProofPipeline>(),
                sp.GetRequiredService<IVerificationMethodResolver>())));

        // Enveloping VC-JOSE-COSE securing mechanisms (M3, FR-012). Registered unconditionally (always
        // available, like Data Integrity); the registry collects them by form. Each is the sole importer
        // of its DataProofs package (FR-050).
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISecuringMechanism, JoseEnvelopingMechanism>(sp =>
            new JoseEnvelopingMechanism(sp.GetRequiredService<IEnvelopeKeyResolver>())));
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISecuringMechanism, CoseEnvelopingMechanism>(sp =>
            new CoseEnvelopingMechanism(sp.GetRequiredService<IEnvelopeKeyResolver>())));

        // SD-JWT VC securing mechanism (M4, FR-013). The sole importer of the DataProofs SD-JWT(.Vc) APIs
        // (FR-050); reuses the enveloping key resolver (kid → JWK) and the optional, consumer-registered
        // ICredentialTypeMetadataResolver (absent ⇒ no Type Metadata retrieval).
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISecuringMechanism, SdJwtVcMechanism>(sp =>
            new SdJwtVcMechanism(
                sp.GetRequiredService<IEnvelopeKeyResolver>(),
                sp.GetService<ICredentialTypeMetadataResolver>())));

        services.TryAddSingleton(sp => new SecuringMechanismRegistry(sp.GetServices<ISecuringMechanism>()));
        services.TryAddSingleton<ISecuringCapabilities>(sp => sp.GetRequiredService<SecuringMechanismRegistry>());

        // Status (M2, FR-020/022): the issuer-side manager and the verifier's status stage (which holds the
        // optional status-list fetcher; an unconfigured fetcher ⇒ the status check is Skipped).
        services.TryAddSingleton<StatusListManager>();
        services.TryAddSingleton(sp => new StatusStage(sp.GetService<IStatusListFetcher>()));

        // Schema (M2, FR-070): the JSON Schema 2020-12 validator (collected into the immutable registry, so
        // a future SHACL validator is just another registration), and the verifier's schema stage (which
        // holds the optional schema resolver; an unconfigured resolver ⇒ the schema check is Skipped).
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ICredentialSchemaValidator, JsonSchema2020Validator>());
        services.TryAddSingleton(sp => new SchemaValidatorRegistry(sp.GetServices<ICredentialSchemaValidator>()));
        services.TryAddSingleton(sp => new SchemaStage(
            sp.GetService<ICredentialSchemaResolver>(),
            sp.GetRequiredService<SchemaValidatorRegistry>(),
            sp.GetRequiredService<IDigestService>()));

        services.TryAddSingleton<IIssuer>(sp => new DefaultIssuer(sp.GetRequiredService<SecuringMechanismRegistry>()));
        services.TryAddSingleton<IVerifier>(sp => new DefaultVerifier(
            sp.GetRequiredService<SecuringMechanismRegistry>(),
            sp.GetRequiredService<StatusStage>(),
            sp.GetRequiredService<SchemaStage>(),
            sp.GetService<IIssuerTrustPolicy>())); // optional (FR-082); absent ⇒ issuer-trust Skipped

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
