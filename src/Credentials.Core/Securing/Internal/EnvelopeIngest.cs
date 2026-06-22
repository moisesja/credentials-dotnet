namespace Credentials.Securing;

/// <summary>
/// Materializes a <see cref="Credential"/> from raw wire bytes, routing by securing form: a JSON-object
/// credential is parsed directly; a compact JWS / COSE_Sign1 / SD-JWT VC envelope is decoded by its
/// mechanism (the sole importer of that substrate, FR-050). Shared by the verifier (to ingest verifier
/// input) and the holder (to ingest received credentials), so both route identically and neither
/// re-implements detection/decoding. Decode failure on a detected envelope, or any non-credential input,
/// throws <see cref="CredentialFormatException"/>.
/// </summary>
internal static class EnvelopeIngest
{
    public static Credential Ingest(ReadOnlyMemory<byte> wireBytes, SecuringMechanismRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        if (wireBytes.Length > CredentialDocument.MaxInputBytes)
        {
            throw new CredentialFormatException(
                $"The credential input is {wireBytes.Length} bytes, exceeding the maximum of {CredentialDocument.MaxInputBytes} bytes.");
        }

        var form = EnvelopeDetector.Detect(wireBytes.Span);
        if (form is not { } envelopeForm)
        {
            return Credential.Parse(wireBytes);
        }

        if (registry.GetMechanism(envelopeForm) is not IEnvelopeIngest ingest)
        {
            throw new CredentialFormatException(
                $"The input is an enveloped credential ({envelopeForm}) but no securing mechanism is registered to decode it.");
        }

        return ingest.Ingest(wireBytes);
    }
}
