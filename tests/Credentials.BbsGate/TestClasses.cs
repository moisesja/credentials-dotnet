using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace Credentials.BbsGate;

/// <summary>
/// The classes whose tests have to fail without the native library, and which class a result belongs to.
/// Both are read from the test assemblies themselves, where no alias and no display name can give a class
/// another name.
/// </summary>
/// <remarks>
/// <para><b>In scope</b> are the <c>bbs-2023</c> classes <see cref="BbsScope"/> finds in source, every class
/// that derives from one of them, however far and through whatever assembly, because it inherits their
/// tests, and every class nested in one of them, wherever it is written.</para>
/// <para><b>The class of a result.</b> A result file names a test, not reliably its class. The class is
/// the longest class of the test's own assembly whose full name begins the test's name. Only when there is
/// none, which happens under some display names, is a test matched by a class's own name without its
/// namespace; that can take in a test of another class of the same name in the same assembly.</para>
/// </remarks>
internal sealed class TestClasses
{
    private readonly IReadOnlyDictionary<string, IReadOnlyCollection<string>> _byAssembly;

    /// <summary>For results that are made up: the classes in scope, and the classes of each assembly, if any are given.</summary>
    public TestClasses(IEnumerable<string> inScope, IReadOnlyDictionary<string, IReadOnlyCollection<string>>? byAssembly = null)
    {
        InScope = inScope.ToHashSet(StringComparer.Ordinal);
        _byAssembly = byAssembly ?? new Dictionary<string, IReadOnlyCollection<string>>();
    }

    /// <summary>The full names of the classes in scope, as the runtime writes them.</summary>
    public IReadOnlySet<string> InScope { get; }

    /// <summary>Reads the test assemblies, and the assemblies beside them that hold a base class of theirs.</summary>
    /// <param name="testAssemblies">The test assemblies, by path.</param>
    /// <param name="bbsClasses">The <c>bbs-2023</c> classes found in source.</param>
    public static TestClasses Read(IEnumerable<string> testAssemblies, IReadOnlyCollection<string> bbsClasses)
    {
        var bases = new Dictionary<string, string?>(StringComparer.Ordinal);
        var byAssembly = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        var read = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var toRead = new Queue<string>(testAssemblies.Select(Path.GetFullPath));
        while (toRead.TryDequeue(out var assembly))
        {
            if (!read.Add(assembly))
            {
                continue;
            }

            using var image = new PEReader(File.OpenRead(assembly));
            MetadataReader reader;
            try
            {
                reader = image.GetMetadataReader();
            }
            catch (Exception exception) when (exception is BadImageFormatException or InvalidOperationException)
            {
                throw new FormatException($"{assembly} is not an assembly, so the results that name it are not of a test run of this build.");
            }

            var types = new List<string>();
            foreach (var handle in reader.TypeDefinitions)
            {
                var name = NameOf(reader, handle)!;
                var @base = reader.GetTypeDefinition(handle).BaseType;
                types.Add(name);
                bases[name] = NameOf(reader, @base);

                // A base class can be in another assembly of the folder that has no tests of its own, a
                // support library, and have its own base there. That assembly is read too.
                var beside = AssemblyOf(reader, @base) is { } other ? Path.Combine(Path.GetDirectoryName(assembly)!, other + ".dll") : null;
                if (beside is not null && File.Exists(beside))
                {
                    toRead.Enqueue(beside);
                }
            }

            byAssembly.TryAdd(Path.GetFileName(assembly), types);
        }

        var inScope = new HashSet<string>(bbsClasses, StringComparer.Ordinal);
        for (var grown = true; grown;)
        {
            grown = false;
            foreach (var (type, @base) in bases)
            {
                var nestedIn = type.LastIndexOf('+') is var plus and > 0 ? type[..plus] : null;
                if ((@base is not null && inScope.Contains(@base)) || (nestedIn is not null && inScope.Contains(nestedIn)))
                {
                    grown |= inScope.Add(type);
                }
            }
        }

        return new TestClasses(inScope, byAssembly);
    }

    /// <summary>Whether a result is of a test of a class in scope.</summary>
    public bool Contains(TestResult result)
    {
        var classes = _byAssembly.GetValueOrDefault(result.Assembly);
        var exact = classes?.Where(@class => result.Test.StartsWith(@class + ".", StringComparison.Ordinal)).MaxBy(@class => @class.Length);
        if (exact is not null)
        {
            return InScope.Contains(exact);
        }

        // The result file did not give the class. By the class's own name, then, among the classes of
        // the test's assembly when they are known.
        var parts = result.Test.Split('.').SkipLast(1).ToHashSet(StringComparer.Ordinal);
        return (classes ?? InScope).Any(@class => parts.Contains(@class[(@class.LastIndexOf('.') + 1)..]) && InScope.Contains(@class));
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
                return InstanceOf(reader, handle) is { IsNil: false } generic ? NameOf(reader, generic) : null;
            default:
                return null;
        }
    }

    // The name of the assembly a base type is in, when that is another one.
    private static string? AssemblyOf(MetadataReader reader, EntityHandle handle)
    {
        if (handle.IsNil)
        {
            return null;
        }

        switch (handle.Kind)
        {
            case HandleKind.TypeReference:
                var scope = reader.GetTypeReference((TypeReferenceHandle)handle).ResolutionScope;
                return scope.Kind switch
                {
                    HandleKind.AssemblyReference => reader.GetString(reader.GetAssemblyReference((AssemblyReferenceHandle)scope).Name),
                    HandleKind.TypeReference => AssemblyOf(reader, (EntityHandle)scope),
                    _ => null,
                };
            case HandleKind.TypeSpecification:
                return AssemblyOf(reader, InstanceOf(reader, handle));
            default:
                return null;
        }
    }

    // A base with type arguments, Contract<int>, is written as an instance of a generic type: the type.
    private static EntityHandle InstanceOf(MetadataReader reader, EntityHandle specification)
    {
        var signature = reader.GetBlobReader(reader.GetTypeSpecification((TypeSpecificationHandle)specification).Signature);
        return signature.ReadSignatureTypeCode() == SignatureTypeCode.GenericTypeInstance
            && signature.ReadSignatureTypeCode() == SignatureTypeCode.TypeHandle
            ? signature.ReadTypeHandle()
            : default;
    }

    private static string Join(string @namespace, string name) => @namespace.Length == 0 ? name : $"{@namespace}.{name}";
}
