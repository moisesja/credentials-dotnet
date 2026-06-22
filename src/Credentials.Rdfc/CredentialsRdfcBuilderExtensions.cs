using Credentials.Cryptography;
using Credentials.Rdfc;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Opt-in registration of the RDFC-1.0 Data Integrity cryptosuites and <c>bbs-2023</c> selective
/// disclosure. Referencing this package brings in dotNetRDF (and its transitive <c>Newtonsoft.Json</c>);
/// the System.Text.Json-only default avoids it (NFR-002), so these RDF-canonicalization features live
/// here behind <see cref="UseRdfcSuites"/> / <see cref="UseBbs2023"/>.
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

    /// <summary>
    /// Adds the <c>bbs-2023</c> selective-disclosure cryptosuite (verification of derived proofs) and the
    /// holder <see cref="IBbsDeriver"/> (FR-031/FR-042). A derived <c>bbs-2023</c> proof then verifies
    /// through the standard <see cref="Credentials.Roles.IVerifier"/> path (FR-053, suite by string).
    /// Idempotent. Call inside <c>AddCredentials(b =&gt; b.UseNetDid().UseBbs2023())</c>.
    ///
    /// <para><b>Issuance is gated</b> (FR-014): <c>DataProofsDotnet</c> exposes no key-store / signer BBS
    /// base-proof API — the only path takes a raw private key, which this engine never handles (FR-015) —
    /// so a <c>bbs-2023</c> issuance request fails fast. Only verification of, and holder derivation from,
    /// <c>bbs-2023</c> credentials are supported until that capability ships. Requires the BBS native
    /// library at runtime (<see cref="IBbsDeriver"/> reports unavailability).</para>
    /// </summary>
    public static CredentialsBuilder UseBbs2023(this CredentialsBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (builder.Services.Any(d => d.ServiceType == typeof(Bbs2023Marker)))
        {
            return builder;
        }

        builder.Services.AddSingleton<Bbs2023Marker>();
        // Registers the suite so a derived bbs-2023 proof verifies through the shared registry (no new
        // verifier code); construction always succeeds even when the BBS native library is absent.
        builder.Services.AddSingleton<ICryptosuite>(_ => new Bbs2023Cryptosuite());
        builder.Services.AddSingleton<IBbsDeriver>(sp => new Bbs2023Deriver(sp.GetRequiredService<IRandomSource>()));
        return builder;
    }

    private sealed class RdfcSuitesMarker;

    private sealed class Bbs2023Marker;
}
