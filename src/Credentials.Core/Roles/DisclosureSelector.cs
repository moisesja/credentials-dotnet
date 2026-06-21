namespace Credentials.Roles;

/// <summary>
/// The kind of selective disclosure a <see cref="DisclosureSelector"/> requests.
/// </summary>
public enum DisclosureSelectorKind
{
    /// <summary>The whole value of a top-level claim is one disclosure (SD-JWT "flat" style).</summary>
    Claim,

    /// <summary>Named sub-properties of an object claim are individually disclosable ("structured" style).</summary>
    ObjectProperties,

    /// <summary>Selected elements of an array claim are individually disclosable.</summary>
    ArrayElements,
}

/// <summary>
/// A draft-free description of which credential claim(s) an SD-JWT VC issuance should make selectively
/// disclosable (FR-013/FR-051). It mirrors the SD-JWT structuring styles without exposing any substrate
/// type: the engine translates a selector into the substrate's disclosure frame internally.
///
/// <para>Use the factory methods: <see cref="Claim"/> for a whole top-level claim,
/// <see cref="ObjectProperties"/> for chosen sub-properties of an object claim, and
/// <see cref="ArrayElements"/> for chosen elements of an array claim. A selector may not target a VCDM
/// structural member (<c>@context</c>, <c>type</c>, <c>issuer</c>, <c>id</c>, or <c>credentialSubject</c>
/// as a whole) — those must stay in the clear so the issuer binding and structural checks remain valid;
/// disclose <c>credentialSubject</c> <em>sub-properties</em> with <see cref="ObjectProperties"/> instead.</para>
/// </summary>
public sealed class DisclosureSelector
{
    private DisclosureSelector(DisclosureSelectorKind kind, string claimName, IReadOnlyList<string> properties, IReadOnlyList<int> indices)
    {
        Kind = kind;
        ClaimName = claimName;
        Properties = properties;
        Indices = indices;
    }

    /// <summary>The disclosure style this selector requests.</summary>
    public DisclosureSelectorKind Kind { get; }

    /// <summary>The top-level claim name the selector applies to.</summary>
    public string ClaimName { get; }

    /// <summary>The object sub-property names (for <see cref="DisclosureSelectorKind.ObjectProperties"/>); empty otherwise.</summary>
    public IReadOnlyList<string> Properties { get; }

    /// <summary>The array element indices (for <see cref="DisclosureSelectorKind.ArrayElements"/>); empty otherwise.</summary>
    public IReadOnlyList<int> Indices { get; }

    /// <summary>Marks the whole value of a top-level claim as selectively disclosable.</summary>
    /// <param name="claimName">The top-level claim name.</param>
    public static DisclosureSelector Claim(string claimName)
    {
        ArgumentException.ThrowIfNullOrEmpty(claimName);
        return new DisclosureSelector(DisclosureSelectorKind.Claim, claimName, [], []);
    }

    /// <summary>
    /// Marks named sub-properties of an object claim as individually disclosable; the object itself
    /// stays in the clear. Use <c>ObjectProperties("credentialSubject", "given_name", "address")</c> to
    /// selectively disclose subject properties.
    /// </summary>
    /// <param name="claimName">The object claim name (stays in the clear).</param>
    /// <param name="properties">The sub-property names to make disclosable (at least one).</param>
    public static DisclosureSelector ObjectProperties(string claimName, params string[] properties)
    {
        ArgumentException.ThrowIfNullOrEmpty(claimName);
        ArgumentNullException.ThrowIfNull(properties);
        if (properties.Length == 0)
        {
            throw new ArgumentException("At least one sub-property must be specified.", nameof(properties));
        }

        foreach (var p in properties)
        {
            if (string.IsNullOrEmpty(p))
            {
                throw new ArgumentException("Sub-property names must be non-empty.", nameof(properties));
            }
        }

        return new DisclosureSelector(DisclosureSelectorKind.ObjectProperties, claimName, [.. properties], []);
    }

    /// <summary>
    /// Marks selected elements of an array claim as individually disclosable; the array itself stays in
    /// the clear with the chosen elements replaced by disclosure placeholders.
    /// </summary>
    /// <param name="claimName">The array claim name (stays in the clear).</param>
    /// <param name="indices">The zero-based element indices to make disclosable (at least one, all non-negative).</param>
    public static DisclosureSelector ArrayElements(string claimName, params int[] indices)
    {
        ArgumentException.ThrowIfNullOrEmpty(claimName);
        ArgumentNullException.ThrowIfNull(indices);
        if (indices.Length == 0)
        {
            throw new ArgumentException("At least one index must be specified.", nameof(indices));
        }

        foreach (var i in indices)
        {
            if (i < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(indices), "Array element indices must be non-negative.");
            }
        }

        return new DisclosureSelector(DisclosureSelectorKind.ArrayElements, claimName, [], [.. indices]);
    }
}
