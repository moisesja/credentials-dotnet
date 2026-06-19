namespace Credentials;

/// <summary>
/// Reports which securing mechanisms and cryptosuites are available at runtime, discovered from the
/// registered mechanisms. Lets a caller (or <c>net-wallet-sdk</c>) enumerate supported suites without
/// binding to any draft-version type (FR-053).
/// </summary>
public interface ISecuringCapabilities
{
    /// <summary>The securing forms that have a registered, available mechanism.</summary>
    IReadOnlyCollection<SecuringForm> AvailableForms { get; }

    /// <summary>The available Data Integrity cryptosuite names (e.g. <c>eddsa-jcs-2022</c>), as opaque strings.</summary>
    IReadOnlyCollection<string> AvailableDataIntegritySuites { get; }

    /// <summary>True if the given selector names an available, supported mechanism + suite.</summary>
    bool IsSupported(SecuringSelector selector);
}
