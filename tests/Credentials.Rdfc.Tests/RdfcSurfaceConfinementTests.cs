using System.Reflection;
using FluentAssertions;
using Xunit;

namespace Credentials.Rdfc.Tests;

/// <summary>
/// NFR-005 / D3 surface confinement for the opt-in <c>Credentials.Rdfc</c> package: no substrate or
/// RDF-stack type (<c>DataProofsDotnet.*</c> — incl. the <c>bbs-2023</c> draft cryptosuite — or dotNetRDF
/// <c>VDS.RDF.*</c> / <c>Newtonsoft.Json.*</c>) may appear on the package's public surface. The
/// draft/substrate types are confined to the internal <c>Bbs2023Deriver</c> and the registration; the
/// public surface is the draft-free <c>IBbsDeriver</c> / <c>BbsDisclosureRequest</c> / the builder methods.
/// </summary>
public sealed class RdfcSurfaceConfinementTests
{
    [Fact]
    public void Public_surface_exposes_no_substrate_or_rdf_stack_type()
    {
        var assembly = typeof(IBbsDeriver).Assembly;
        var offenders = new List<string>();

        foreach (var type in assembly.GetExportedTypes())
        {
            foreach (var member in type.GetMembers(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                foreach (var referenced in ReferencedTypes(member))
                {
                    if (IsConfinedType(referenced))
                    {
                        offenders.Add($"{type.FullName}.{member.Name} -> {referenced.FullName}");
                    }
                }
            }
        }

        offenders.Should().BeEmpty(
            "no DataProofsDotnet / dotNetRDF / Newtonsoft type may appear on the public Credentials.Rdfc surface "
            + "(NFR-005/D3): " + string.Join("; ", offenders));
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

    private static bool IsConfinedType(Type type) =>
        type.Namespace is { } ns
        && (ns.StartsWith("DataProofsDotnet", StringComparison.Ordinal)
            || ns.StartsWith("VDS.RDF", StringComparison.Ordinal)
            || ns.StartsWith("Newtonsoft", StringComparison.Ordinal)
            || ns.StartsWith("AngleSharp", StringComparison.Ordinal)
            || ns.StartsWith("HtmlAgilityPack", StringComparison.Ordinal));
}
