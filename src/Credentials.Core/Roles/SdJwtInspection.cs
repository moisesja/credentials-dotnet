namespace Credentials.Roles;

/// <summary>
/// What a holder can see about an issued SD-JWT VC before presenting it: its type, the claim names it
/// carries as selectively disclosable (so the holder can choose which to reveal in
/// <see cref="SdJwtPresentationRequest.DiscloseClaims"/>), and whether the issuer bound it to a holder
/// key (a <c>cnf</c> confirmation key, enabling a Key Binding JWT). Returned by <see cref="IHolder.InspectSdJwt"/>.
/// </summary>
public sealed record SdJwtInspection
{
    /// <summary>The SD-JWT VC type claim (<c>vct</c>), or <see langword="null"/> if absent.</summary>
    public required string? Vct { get; init; }

    /// <summary>The claim names the holder may selectively reveal.</summary>
    public required IReadOnlyList<string> DisclosableClaims { get; init; }

    /// <summary>True when the credential carries a holder confirmation key (<c>cnf</c>) — a Key Binding JWT can be produced.</summary>
    public required bool SupportsHolderBinding { get; init; }
}
