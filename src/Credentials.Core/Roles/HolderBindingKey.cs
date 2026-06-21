using NetCrypto;

namespace Credentials.Roles;

/// <summary>
/// A draft-free reference to the holder's <em>public</em> key for SD-JWT VC key binding (the <c>cnf</c>
/// confirmation key, FR-013). It carries neutral <c>NetCrypto</c> key material — never a substrate JWK
/// type — so no draft-version type appears on the public API (FR-051/D12); the engine converts it to the
/// confirmation key internally. Carrying a holder <see cref="HolderBindingKey"/> at issuance lets a later
/// holder presentation prove possession with a Key Binding JWT (the presentation/KB-JWT path itself is a
/// later milestone).
/// </summary>
public sealed class HolderBindingKey
{
    private HolderBindingKey(KeyType keyType, ReadOnlyMemory<byte> publicKey, string? multibase)
    {
        KeyType = keyType;
        PublicKey = publicKey;
        Multibase = multibase;
    }

    /// <summary>The holder key type.</summary>
    public KeyType KeyType { get; }

    /// <summary>The raw public-key bytes (empty when built from a multibase multikey).</summary>
    public ReadOnlyMemory<byte> PublicKey { get; }

    /// <summary>The multibase multikey form of the public key, or <see langword="null"/> when built from raw bytes.</summary>
    public string? Multibase { get; }

    /// <summary>Builds a holder-binding key from a multibase multikey (e.g. a <c>did:key</c> verification method's <c>publicKeyMultibase</c>).</summary>
    /// <param name="multibase">The multibase-encoded multikey public key.</param>
    public static HolderBindingKey FromMultikey(string multibase)
    {
        ArgumentException.ThrowIfNullOrEmpty(multibase);
        return new HolderBindingKey(default, default, multibase);
    }

    /// <summary>Builds a holder-binding key from raw public-key bytes and their key type.</summary>
    /// <param name="keyType">The holder key type.</param>
    /// <param name="publicKey">The raw public-key bytes.</param>
    public static HolderBindingKey FromPublicKey(KeyType keyType, ReadOnlyMemory<byte> publicKey)
    {
        if (publicKey.IsEmpty)
        {
            throw new ArgumentException("The public key must not be empty.", nameof(publicKey));
        }

        return new HolderBindingKey(keyType, publicKey, null);
    }
}
