namespace Credentials.Roles;

/// <summary>
/// A holder's request to assemble a <see cref="VerifiablePresentation"/> (FR-033) from one or more held
/// credentials. Embedded children are carried structure-faithfully; enveloped children (JOSE / SD-JWT
/// compact tokens) are carried verbatim. The assembled presentation is unsecured until bound to a holder
/// key (see <see cref="IHolder.BindWithDataIntegrityAsync"/> / <see cref="IHolder.BindWithJoseEnvelopeAsync"/>).
/// </summary>
public sealed record VpAssemblyRequest
{
    /// <summary>The <c>holder</c> identifier (the holder's DID). Bound by the verifier to the binding key.</summary>
    public string? Holder { get; init; }

    /// <summary>The presentation <c>id</c>, if any.</summary>
    public string? Id { get; init; }

    /// <summary>The credentials to include (at least one).</summary>
    public IReadOnlyList<ContainedCredential> Credentials { get; init; } = [];
}
