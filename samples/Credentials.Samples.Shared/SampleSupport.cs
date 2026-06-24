using NetCrypto;

namespace Credentials.Samples.Shared;

/// <summary>Mints real in-memory keys + the matching <c>did:key</c> identifiers for the samples (offline).</summary>
public static class SampleKeys
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();

    /// <summary>Generates a fresh key of the given type and its <c>did:key</c> DID + verification method.</summary>
    /// <param name="keyType">The key type (default Ed25519).</param>
    public static SampleKey New(KeyType keyType = KeyType.Ed25519)
    {
        var keyPair = KeyGen.Generate(keyType);
        var did = $"did:key:{keyPair.MultibasePublicKey}";
        return new SampleKey(new KeyPairSigner(keyPair, Crypto), did, $"{did}#{keyPair.MultibasePublicKey}");
    }
}

/// <summary>An in-memory signing identity: a <c>NetCrypto.ISigner</c> + its <c>did:key</c> DID and verification method.</summary>
/// <param name="Signer">The signer (the engine never sees the raw private key).</param>
/// <param name="Did">The <c>did:key</c> DID.</param>
/// <param name="VerificationMethod">The DID URL of the verification method.</param>
public sealed record SampleKey(ISigner Signer, string Did, string VerificationMethod);

/// <summary>
/// Writes FR-tagged narration for a sample run to a caller-supplied <see cref="TextWriter"/> so the
/// same sample is runnable both as a console program (Console.Out) and from the smoke tests (a string
/// buffer). Output is human-readable, not machine-parsed.
/// </summary>
/// <param name="output">Where to write narration.</param>
public sealed class SampleNarrator(TextWriter output)
{
    /// <summary>Writes the sample's title banner and the requirements it demonstrates.</summary>
    /// <param name="title">The sample title.</param>
    /// <param name="requirements">The FR/NFR ids the sample exercises.</param>
    public void Banner(string title, params string[] requirements)
    {
        output.WriteLine($"== {title} ==");
        if (requirements.Length > 0) output.WriteLine($"   demonstrates: {string.Join(", ", requirements)}");
    }

    /// <summary>Writes a numbered/bulleted step line.</summary>
    /// <param name="message">The step description.</param>
    public void Step(string message) => output.WriteLine($" - {message}");

    /// <summary>Writes the sample's final outcome line.</summary>
    /// <param name="message">The outcome description.</param>
    public void Result(string message) => output.WriteLine($" => {message}");
}
