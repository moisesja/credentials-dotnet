using NetCrypto;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>Mints real in-memory keys + the corresponding <c>did:key</c> identifiers for M1 round-trips.</summary>
internal static class TestKeys
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();

    public static TestKey New(KeyType keyType)
    {
        var keyPair = KeyGen.Generate(keyType);
        var did = $"did:key:{keyPair.MultibasePublicKey}";
        var verificationMethod = $"{did}#{keyPair.MultibasePublicKey}";
        return new TestKey(new KeyPairSigner(keyPair, Crypto), did, verificationMethod);
    }
}

internal sealed record TestKey(ISigner Signer, string Did, string VerificationMethod);
