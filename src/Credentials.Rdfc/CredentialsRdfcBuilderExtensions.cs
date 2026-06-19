using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Opt-in registration of the RDFC-1.0 Data Integrity cryptosuites. Referencing this package brings in
/// dotNetRDF (and its transitive <c>Newtonsoft.Json</c>); the System.Text.Json-only default avoids it
/// (NFR-002), so the RDFC suites live here behind <see cref="UseRdfcSuites"/>.
/// </summary>
public static class CredentialsRdfcBuilderExtensions
{
    /// <summary>
    /// Adds the RDFC-1.0 cryptosuites (<c>eddsa-rdfc-2022</c>, <c>ecdsa-rdfc-2019</c>) to the Data
    /// Integrity registry, using the proofs layer's default offline JSON-LD document loader (which
    /// bundles the VCDM 2.0 context). Idempotent. Call inside <c>AddCredentials(b =&gt; b.UseNetDid().UseRdfcSuites())</c>.
    /// </summary>
    public static CredentialsBuilder UseRdfcSuites(this CredentialsBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (builder.Services.Any(d => d.ServiceType == typeof(RdfcSuitesMarker)))
        {
            return builder;
        }

        builder.Services.AddSingleton<RdfcSuitesMarker>();
        builder.Services.AddSingleton<ICryptosuite>(_ => new EddsaRdfc2022Cryptosuite());
        builder.Services.AddSingleton<ICryptosuite>(_ => new EcdsaRdfc2019Cryptosuite());
        return builder;
    }

    private sealed class RdfcSuitesMarker;
}
