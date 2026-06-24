using System.Reflection;
using Credentials;
using Credentials.TestSupport;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// NFR-005 / FR-051 / D12 surface confinement: no DataProofsDotnet.Jose or DataProofsDotnet.Cose
/// substrate type (<c>Jwk</c>, <c>JwsSigner</c>, <c>CoseAlgorithm</c>, <c>CoseSign1VerificationResult</c>,
/// <c>IJoseCryptoProvider</c>, <c>VcJose</c>, <c>VcCose</c>, and the SD-JWT draft types
/// <c>DisclosureFrame</c>, <c>SdJwtIssuerOptions</c>, <c>SdJwtVcVerificationResult</c>,
/// <c>ITypeMetadataResolver</c>, <c>SdJwtVcConstants</c>, …) may appear on the public credentials-dotnet
/// surface. They are confined to the internal mechanisms and adapters.
/// </summary>
public sealed class M3SurfaceConfinementTests
{
    [Fact]
    [FrTag("FR-050")]
    public void Public_surface_exposes_no_jose_or_cose_substrate_type()
    {
        var assembly = typeof(Credential).Assembly;
        var offenders = new List<string>();

        foreach (var type in assembly.GetExportedTypes())
        {
            foreach (var member in type.GetMembers(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                foreach (var referenced in ReferencedTypes(member))
                {
                    if (IsSubstrateType(referenced))
                    {
                        offenders.Add($"{type.FullName}.{member.Name} -> {referenced.FullName}");
                    }
                }
            }
        }

        offenders.Should().BeEmpty(
            "no DataProofsDotnet.Jose/.Cose type may appear on the public surface (NFR-005/FR-051): "
            + string.Join("; ", offenders));
    }

    [Theory]
    [InlineData("DataProofsDotnet.Jose.SdJwt.DisclosureFrame")]
    [InlineData("DataProofsDotnet.Jose.SdJwt.SdJwtIssuerOptions")]
    [InlineData("DataProofsDotnet.Jose.SdJwt.SdJwtVerificationOptions")]
    [InlineData("DataProofsDotnet.Jose.SdJwt.Vc.SdJwtVcVerificationResult")]
    [InlineData("DataProofsDotnet.Jose.SdJwt.Vc.SdJwtVcConstants")]
    [InlineData("DataProofsDotnet.Jose.SdJwt.Vc.ITypeMetadataResolver")]
    [InlineData("DataProofsDotnet.Jose.Jwk")]
    public void Public_surface_exposes_no_named_sdjwt_substrate_type(string substrateTypeName)
    {
        // M4 (FR-051/D12, fix F3): the SD-JWT VC draft types are confined to SdJwtVcMechanism +
        // TypeMetadataResolverAdapter — they must never appear on any public credentials-dotnet signature.
        var assembly = typeof(Credential).Assembly;

        var offenders = (
            from type in assembly.GetExportedTypes()
            from member in type.GetMembers(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
            from referenced in ReferencedTypes(member)
            where referenced.FullName == substrateTypeName
            select $"{type.FullName}.{member.Name}").ToList();

        offenders.Should().BeEmpty($"'{substrateTypeName}' must not appear on the public surface: {string.Join("; ", offenders)}");
    }

    private static IEnumerable<Type> ReferencedTypes(MemberInfo member)
    {
        switch (member)
        {
            case MethodInfo method:
                foreach (var t in Flatten(method.ReturnType))
                {
                    yield return t;
                }

                foreach (var p in method.GetParameters())
                {
                    foreach (var t in Flatten(p.ParameterType))
                    {
                        yield return t;
                    }
                }

                break;

            case ConstructorInfo ctor:
                foreach (var p in ctor.GetParameters())
                {
                    foreach (var t in Flatten(p.ParameterType))
                    {
                        yield return t;
                    }
                }

                break;

            case PropertyInfo property:
                foreach (var t in Flatten(property.PropertyType))
                {
                    yield return t;
                }

                break;

            case FieldInfo field:
                foreach (var t in Flatten(field.FieldType))
                {
                    yield return t;
                }

                break;
        }
    }

    private static IEnumerable<Type> Flatten(Type type)
    {
        var t = type;
        while (t.IsByRef || t.IsArray || t.IsPointer)
        {
            t = t.GetElementType()!;
        }

        yield return t;

        if (t.IsGenericType)
        {
            foreach (var arg in t.GetGenericArguments())
            {
                foreach (var nested in Flatten(arg))
                {
                    yield return nested;
                }
            }
        }
    }

    private static bool IsSubstrateType(Type type) =>
        type.Namespace is { } ns
        && (ns.StartsWith("DataProofsDotnet.Jose", StringComparison.Ordinal)
            || ns.StartsWith("DataProofsDotnet.Cose", StringComparison.Ordinal));
}
