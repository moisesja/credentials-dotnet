using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace Credentials.BbsGate;

/// <summary>
/// Reads from the test assemblies themselves which classes derive from which. A class that derives from a
/// <c>bbs-2023</c> class inherits its tests, and a result names the class that ran a test, not the one that
/// declares it. The base of a class is read from what the compiler wrote, not from the base list in the
/// source, where an alias can give it any name.
/// </summary>
internal static class TestTypes
{
    /// <summary>The classes of these assemblies that derive, however far, from one of the given classes.</summary>
    /// <param name="assemblies">The test assemblies, by path.</param>
    /// <param name="classes">Full names of classes, as the runtime writes them.</param>
    public static List<string> DerivedFrom(IEnumerable<string> assemblies, IReadOnlyCollection<string> classes)
    {
        var bases = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var assembly in assemblies)
        {
            using var image = new PEReader(File.OpenRead(assembly));
            var reader = image.GetMetadataReader();
            foreach (var handle in reader.TypeDefinitions)
            {
                bases[NameOf(reader, handle)!] = NameOf(reader, reader.GetTypeDefinition(handle).BaseType);
            }
        }

        bool Derives(string type)
        {
            for (var @base = bases.GetValueOrDefault(type); @base is not null; @base = bases.GetValueOrDefault(@base))
            {
                if (classes.Contains(@base))
                {
                    return true;
                }
            }

            return false;
        }

        return [.. bases.Keys.Where(Derives).Order(StringComparer.Ordinal)];
    }

    // The full name of a type, or of the type a base is an instance of: Namespace.Outer+Nested`1.
    private static string? NameOf(MetadataReader reader, EntityHandle handle)
    {
        // An interface, and the module's own type, have no base.
        if (handle.IsNil)
        {
            return null;
        }

        switch (handle.Kind)
        {
            case HandleKind.TypeDefinition:
                var definition = reader.GetTypeDefinition((TypeDefinitionHandle)handle);
                var declaring = definition.GetDeclaringType();
                return declaring.IsNil
                    ? Join(reader.GetString(definition.Namespace), reader.GetString(definition.Name))
                    : NameOf(reader, declaring) + "+" + reader.GetString(definition.Name);
            case HandleKind.TypeReference:
                var reference = reader.GetTypeReference((TypeReferenceHandle)handle);
                return reference.ResolutionScope.Kind == HandleKind.TypeReference
                    ? NameOf(reader, (EntityHandle)reference.ResolutionScope) + "+" + reader.GetString(reference.Name)
                    : Join(reader.GetString(reference.Namespace), reader.GetString(reference.Name));
            case HandleKind.TypeSpecification:
                // A base with type arguments, Contract<int>: an instance of a generic type, then the type.
                var signature = reader.GetBlobReader(reader.GetTypeSpecification((TypeSpecificationHandle)handle).Signature);
                return signature.ReadSignatureTypeCode() == SignatureTypeCode.GenericTypeInstance
                    && signature.ReadSignatureTypeCode() == SignatureTypeCode.TypeHandle
                    ? NameOf(reader, signature.ReadTypeHandle())
                    : null;
            default:
                return null;
        }
    }

    private static string Join(string @namespace, string name) => @namespace.Length == 0 ? name : $"{@namespace}.{name}";
}
