using System.Reflection;

namespace Credentials.ArchitectureTests;

/// <summary>
/// Locates the three shippable library assemblies (Credentials.Core,
/// Credentials.Extensions.DependencyInjection, Credentials.Rdfc) on disk and exposes a
/// <see cref="MetadataLoadContext"/> factory so their public surface can be inspected by metadata
/// only — without runtime-loading them (which would pull Credentials.Rdfc's transitive Newtonsoft
/// into this test host and invalidate the no-Newtonsoft closure assertion).
/// </summary>
internal static class LibrarySurface
{
    /// <summary>The three shippable library assembly simple names, in dependency order.</summary>
    public static readonly string[] LibraryNames =
    [
        "Credentials.Core",
        "Credentials.Extensions.DependencyInjection",
        "Credentials.Rdfc",
    ];

    // NOTE: declaration order matters — static field initializers run top-to-bottom, and
    // ResolveLibraryArtifacts() reads Configuration + RepoRoot, so those must initialize first.

    /// <summary>The build configuration (<c>Debug</c>/<c>Release</c>) this test run was built under.</summary>
    public static string Configuration { get; } = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).Parent!.Name;

    /// <summary>The repository root (the directory containing <c>Credentials.sln</c>).</summary>
    public static string RepoRoot { get; } = FindRepoRoot();

    /// <summary>Absolute path to each library's built <c>.dll</c>.</summary>
    public static IReadOnlyList<string> LibraryDllPaths { get; } = ResolveLibraryArtifacts(".dll");

    /// <summary>Absolute path to each library's generated XML documentation file.</summary>
    public static IReadOnlyList<string> LibraryXmlDocPaths { get; } = ResolveLibraryArtifacts(".xml");

    /// <summary>The built <c>.dll</c> path for the named library assembly.</summary>
    /// <param name="assemblyName">One of <see cref="LibraryNames"/>.</param>
    public static string DllPathFor(string assemblyName)
    {
        var index = Array.IndexOf(LibraryNames, assemblyName);
        if (index < 0) throw new ArgumentException($"'{assemblyName}' is not a known library.", nameof(assemblyName));
        return LibraryDllPaths[index];
    }

    /// <summary>
    /// Creates a metadata-only load context whose resolver spans the runtime directory plus every
    /// directory that holds a library or one of its dependencies, so signature types resolve.
    /// </summary>
    public static MetadataLoadContext CreateLoadContext()
    {
        var dllDirs = new List<string>
        {
            System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory(),
            AppContext.BaseDirectory, // Core + DI + their deps are copied here
            Path.Combine(RepoRoot, "src", "Credentials.Rdfc", "bin", Configuration, "net10.0"), // Rdfc + its deps
        };

        // Dedupe by assembly simple name (PathAssemblyResolver rejects duplicate simple names);
        // first directory listed wins, so the runtime + test-output copies take precedence.
        var byName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dir in dllDirs.Where(Directory.Exists))
        {
            foreach (var dll in Directory.EnumerateFiles(dir, "*.dll"))
            {
                var name = Path.GetFileNameWithoutExtension(dll);
                byName.TryAdd(name, dll);
            }
        }

        var resolver = new PathAssemblyResolver(byName.Values);
        return new MetadataLoadContext(resolver);
    }

    /// <summary>
    /// Flattens a (metadata) type into itself plus every type nested in it structurally — array and
    /// pointer element types, by-ref element types, and all generic type arguments, recursively — so
    /// a check over "every type referenced by a signature" sees through <c>Task&lt;IReadOnlyList&lt;T&gt;&gt;</c>.
    /// </summary>
    public static IEnumerable<Type> Flatten(Type? type)
    {
        if (type is null) yield break;
        if (type.HasElementType)
        {
            foreach (var t in Flatten(type.GetElementType())) yield return t;
            yield break;
        }

        yield return type;
        if (type.IsGenericType)
        {
            foreach (var arg in type.GetGenericArguments())
                foreach (var t in Flatten(arg))
                    yield return t;
        }
    }

    private static IReadOnlyList<string> ResolveLibraryArtifacts(string extension)
    {
        var paths = new List<string>(LibraryNames.Length);
        foreach (var name in LibraryNames)
        {
            // Core + DI are copied next to the test binary; Rdfc (referenced build-order-only) is not,
            // so fall back to its own build output directory.
            var local = Path.Combine(AppContext.BaseDirectory, name + extension);
            if (File.Exists(local))
            {
                paths.Add(local);
                continue;
            }

            var srcOutput = Path.Combine(RepoRoot, "src", name, "bin", Configuration, "net10.0", name + extension);
            if (!File.Exists(srcOutput))
                throw new FileNotFoundException($"Could not locate built artifact '{name}{extension}'. Looked in '{local}' and '{srcOutput}'.");
            paths.Add(srcOutput);
        }
        return paths;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Credentials.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not find repository root (no Credentials.sln above the test output directory).");
    }
}
