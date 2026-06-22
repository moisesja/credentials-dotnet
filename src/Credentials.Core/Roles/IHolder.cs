namespace Credentials.Roles;

/// <summary>
/// The Holder role (FR-030/032/033/034): receives and holds credentials, inspects and presents them with
/// selective disclosure and holder binding, and assembles Verifiable Presentations bound to a holder key.
/// The holder never handles raw private keys — every binding signs through a caller-supplied
/// <c>NetCrypto.ISigner</c>, and all proof/binding mechanics are delegated to the securing layer (FR-050).
/// </summary>
public interface IHolder
{
    /// <summary>
    /// Ingests a received credential from its wire bytes (a JSON-object credential, or a compact JWS /
    /// COSE / SD-JWT VC token), returning a <see cref="HeldCredential"/>.
    /// </summary>
    /// <exception cref="CredentialFormatException">The bytes are not a recognizable credential.</exception>
    HeldCredential Ingest(ReadOnlyMemory<byte> credentialWireBytes);

    /// <summary>
    /// Inspects an SD-JWT VC the holder holds — its type, disclosable claims, and whether it supports
    /// holder binding — so the holder can choose what to reveal when presenting it (FR-032).
    /// </summary>
    /// <exception cref="System.InvalidOperationException">The held credential is not an SD-JWT VC.</exception>
    SdJwtInspection InspectSdJwt(HeldCredential held);

    /// <summary>
    /// Presents an SD-JWT VC (FR-032): reveals the chosen disclosures and appends a Key Binding JWT bound
    /// to the verifier's audience and nonce, returning the compact presentation. Honestly async over the
    /// holder signing operation.
    /// </summary>
    /// <exception cref="System.InvalidOperationException">The held credential is not an SD-JWT VC.</exception>
    /// <exception cref="CredentialFormatException">The held SD-JWT VC is malformed.</exception>
    Task<string> PresentSdJwtAsync(HeldCredential held, SdJwtPresentationRequest request, CancellationToken cancellationToken = default);

    /// <summary>Assembles an unsecured Verifiable Presentation from one or more credentials (FR-033).</summary>
    /// <exception cref="Validation.CredentialStructureException">The assembled presentation is not structurally valid.</exception>
    VerifiablePresentation BuildPresentation(VpAssemblyRequest request);

    /// <summary>
    /// Binds a presentation to the holder key with an embedded Data Integrity <c>authentication</c> proof
    /// carrying the verifier's challenge/domain (FR-034), returning the secured presentation.
    /// </summary>
    Task<VerifiablePresentation> BindWithDataIntegrityAsync(VerifiablePresentation presentation, VpBindingRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Binds a presentation to the holder key by signing it into a compact <c>vp+jwt</c> JWS (FR-034),
    /// returning the compact serialization.
    /// </summary>
    Task<string> BindWithJoseEnvelopeAsync(VerifiablePresentation presentation, VpBindingRequest request, CancellationToken cancellationToken = default);
}
