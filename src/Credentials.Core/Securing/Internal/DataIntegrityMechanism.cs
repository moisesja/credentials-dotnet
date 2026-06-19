using System.Text.Json;
using Credentials.Validation;
using DataProofsDotnet.DataIntegrity;

namespace Credentials.Securing;

/// <summary>
/// The embedded Data Integrity securing mechanism — the single bridge to
/// <see cref="DataIntegrityProofPipeline"/>. It holds no proof or canonicalization logic of its own
/// (FR-050); it builds proof options, delegates, and maps the substrate result to the neutral seam
/// type. Verification pre-resolves each proof's verification method through the injected resolver so a
/// resolution failure is reported as <see cref="SecuringVerificationStatus.Unresolvable"/>
/// (→ Indeterminate) rather than being conflated with a cryptographic failure (→ Invalid/Failed).
/// </summary>
internal sealed class DataIntegrityMechanism : ISecuringMechanism
{
    private readonly DataIntegrityProofPipeline _pipeline;
    private readonly IVerificationMethodResolver _resolver;

    public DataIntegrityMechanism(DataIntegrityProofPipeline pipeline, IVerificationMethodResolver resolver)
    {
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
    }

    public SecuringForm Form => SecuringForm.DataIntegrity;

    public IReadOnlyCollection<string> SuiteNames => _pipeline.Suites.RegisteredNames;

    public bool IsAvailable => true;

    public async Task<SecureOutcome> SecureAsync(SecureRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = request.Cryptosuite,
            VerificationMethod = request.VerificationMethod,
            ProofPurpose = request.ProofPurpose,
            Created = request.Created is { } created ? Rfc3339.Format(created) : null,
        };

        var secured = await _pipeline.AddProofAsync(request.Document, proofOptions, request.Signer, cancellationToken)
            .ConfigureAwait(false);
        return new SecureOutcome(secured);
    }

    public async Task<SecuringVerificationResult> VerifyAsync(VerifyRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var verificationMethods = ReadVerificationMethods(request.Document);
        if (verificationMethods.Count == 0)
        {
            return SecuringVerificationResult.NoProof;
        }

        // Pre-resolve so an unresolvable verification method is Indeterminate, not a crypto Failure.
        var resolved = new List<ResolvedVerificationMethod>(verificationMethods.Count);
        foreach (var vm in verificationMethods)
        {
            ResolvedVerificationMethod? method;
            try
            {
                method = await _resolver.ResolveAsync(vm, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return SecuringVerificationResult.Unresolvable("verification_method_unresolvable");
            }

            if (method is null)
            {
                return SecuringVerificationResult.Unresolvable("verification_method_unresolvable");
            }

            resolved.Add(method);
        }

        var staticResolver = new StaticVerificationMethodResolver(resolved);
        var options = new ProofVerificationOptions
        {
            ExpectedProofPurpose = request.ExpectedProofPurpose,
            VerificationTime = request.VerificationTime,
        };

        var result = await _pipeline.VerifyAsync(request.Document, staticResolver, options, cancellationToken)
            .ConfigureAwait(false);

        if (result.Verified)
        {
            // Bind on the verification-method identifiers actually used (which the substrate confirmed
            // match the proofs and verified cryptographically) — never the resolver's self-declared
            // controller field, which an attacker-influenced DID document can forge.
            var methods = resolved
                .Select(method => method.Id)
                .Distinct(StringComparer.Ordinal)
                .ToList();
            return SecuringVerificationResult.Verified(methods);
        }

        // Map substrate problems to neutral codes; never surface upstream free-text (NFR-008).
        var problems = result.ProofResults
            .SelectMany(proof => proof.Problems)
            .Concat(result.Problems)
            .Select(problem => new SecuringProblem(problem.Code, null))
            .ToList();
        if (problems.Count == 0)
        {
            problems.Add(new SecuringProblem("proof_invalid", null));
        }

        return SecuringVerificationResult.Invalid(problems);
    }

    private static List<string> ReadVerificationMethods(JsonElement document)
    {
        var methods = new List<string>();
        if (document.ValueKind != JsonValueKind.Object || !document.TryGetProperty("proof", out var proof))
        {
            return methods;
        }

        switch (proof.ValueKind)
        {
            case JsonValueKind.Object:
                AddVerificationMethod(proof, methods);
                break;
            case JsonValueKind.Array:
                foreach (var entry in proof.EnumerateArray())
                {
                    if (entry.ValueKind == JsonValueKind.Object)
                    {
                        AddVerificationMethod(entry, methods);
                    }
                }

                break;
        }

        return methods;
    }

    private static void AddVerificationMethod(JsonElement proof, List<string> methods)
    {
        if (proof.TryGetProperty("verificationMethod", out var vm)
            && vm.ValueKind == JsonValueKind.String
            && vm.GetString() is { Length: > 0 } value
            && !methods.Contains(value, StringComparer.Ordinal))
        {
            methods.Add(value);
        }
    }
}
