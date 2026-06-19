using System.Text.Json;
using DataProofsDotnet;

namespace Credentials;

/// <summary>
/// The single <see cref="JsonSerializerOptions"/> the credential core uses to serialize a document.
/// </summary>
/// <remarks>
/// <para>
/// For a credential <em>we</em> build, the bytes we serialize are the bytes the securing layer signs
/// and emits on the wire — so any divergence in escaping, null-handling, or naming would silently
/// break JCS/enveloping signatures. <see cref="Faithful"/> therefore mirrors
/// <see cref="DataProofsJsonOptions.Default"/> exactly.
/// </para>
/// <para>
/// To guarantee that mirror without drift, <see cref="Faithful"/> is <strong>derived from</strong>
/// the dependency's options via the <see cref="JsonSerializerOptions(JsonSerializerOptions)"/> copy
/// constructor — it is never a hand-maintained copy of the individual settings (conformance fix F1).
/// A dependency bump that changes the default is inherited automatically; a byte-mirror assertion in
/// the test-suite fails the build if the two ever diverge.
/// </para>
/// <para>
/// This is <em>faithful</em>, not <em>canonical</em>: it preserves the issuer's member order and is
/// not a canonicalization. Canonicalization (RDFC / JCS) is owned by <c>DataProofsDotnet</c> (FR-050).
/// </para>
/// </remarks>
public static class CredentialJson
{
    /// <summary>
    /// The faithful (not canonical) serializer options, inherited from
    /// <see cref="DataProofsJsonOptions.Default"/>. Read-only and safe to share across threads.
    /// </summary>
    public static JsonSerializerOptions Faithful { get; } = CreateFaithful();

    private static JsonSerializerOptions CreateFaithful()
    {
        // Copy every setting from the dependency's canonical options (encoder, null-handling,
        // naming policy, indentation, converters, resolver) rather than re-declaring them, so the
        // two can never silently desynchronize (fix F1).
        var options = new JsonSerializerOptions(DataProofsJsonOptions.Default);
        options.MakeReadOnly();
        return options;
    }
}
