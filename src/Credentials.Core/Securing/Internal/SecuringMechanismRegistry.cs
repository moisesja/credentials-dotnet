namespace Credentials.Securing;

/// <summary>
/// Resolves a securing form (+ cryptosuite) to its <see cref="ISecuringMechanism"/>, and reports the
/// available capabilities. Built from the registered mechanisms; immutable after construction.
/// </summary>
internal sealed class SecuringMechanismRegistry : ISecuringCapabilities
{
    private readonly IReadOnlyDictionary<SecuringForm, ISecuringMechanism> _byForm;

    public SecuringMechanismRegistry(IEnumerable<ISecuringMechanism> mechanisms)
    {
        ArgumentNullException.ThrowIfNull(mechanisms);

        var byForm = new Dictionary<SecuringForm, ISecuringMechanism>();
        foreach (var mechanism in mechanisms)
        {
            if (mechanism.IsAvailable)
            {
                byForm[mechanism.Form] = mechanism; // last registration wins
            }
        }

        _byForm = byForm;
        AvailableForms = byForm.Keys.ToArray();
        AvailableDataIntegritySuites =
            byForm.TryGetValue(SecuringForm.DataIntegrity, out var di) ? di.SuiteNames.ToArray() : [];
    }

    public IReadOnlyCollection<SecuringForm> AvailableForms { get; }

    public IReadOnlyCollection<string> AvailableDataIntegritySuites { get; }

    /// <summary>The mechanism for a form, or <see langword="null"/> if none is registered/available.</summary>
    public ISecuringMechanism? GetMechanism(SecuringForm form) => _byForm.GetValueOrDefault(form);

    /// <summary>
    /// Resolves the mechanism for an issuance request, validating that the requested cryptosuite is
    /// supported. Throws a clear <see cref="NotSupportedException"/> otherwise.
    /// </summary>
    public ISecuringMechanism ResolveForIssue(SecuringForm form, string? cryptosuite)
    {
        var mechanism = GetMechanism(form)
            ?? throw new NotSupportedException($"No securing mechanism is registered for form '{form}'.");

        if (form == SecuringForm.DataIntegrity)
        {
            if (string.IsNullOrEmpty(cryptosuite))
            {
                throw new ArgumentException("A Data Integrity cryptosuite name is required.", nameof(cryptosuite));
            }

            if (!mechanism.SuiteNames.Contains(cryptosuite, StringComparer.Ordinal))
            {
                throw new NotSupportedException(
                    $"The cryptosuite '{cryptosuite}' is not registered. Available: {string.Join(", ", mechanism.SuiteNames)}.");
            }
        }

        return mechanism;
    }

    public bool IsSupported(SecuringSelector selector)
    {
        var mechanism = GetMechanism(selector.Form);
        if (mechanism is null)
        {
            return false;
        }

        return selector.Form != SecuringForm.DataIntegrity
            || (selector.Cryptosuite is { } suite && mechanism.SuiteNames.Contains(suite, StringComparer.Ordinal));
    }
}
