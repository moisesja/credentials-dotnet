using System.Reflection;
using Credentials.TestSupport;
using FluentAssertions;
using Xunit;

namespace Credentials.ArchitectureTests;

/// <summary>
/// NFR-002 (the static/reference half — a fast pre-check): no Newtonsoft.Json (nor dotNetRDF /
/// AngleSharp / HtmlAgilityPack, which drag it in) appears in the <em>compile-time reference closure</em>
/// of the default shippable libraries (Credentials.Core + Credentials.Extensions.DependencyInjection).
/// The opt-in Credentials.Rdfc is deliberately excluded — it is the sanctioned Newtonsoft carrier.
/// </summary>
/// <remarks>
/// This walks the libraries' own recorded reference graph via <see cref="MetadataLoadContext"/> rather
/// than inspecting which assemblies are loaded in the test process — the test SDK
/// (Microsoft.NET.Test.Sdk) loads its own Newtonsoft.Json, so a process-level "is Newtonsoft loaded"
/// assertion would be contaminated and meaningless.
/// <para>
/// SCOPE / KNOWN LIMITATION (verified by the M8a adversarial pass): the C# compiler only records a
/// reference to an assembly whose <em>types are actually used</em>, so this catches a Newtonsoft type
/// being <em>used</em> by the engine code (the common regression) but NOT an unused-yet-declared
/// <c>PackageReference</c> that drags Newtonsoft in transitively. The authoritative, package-level
/// guarantee is asserted by <c>Credentials.ConsumerProbe</c> via
/// <c>tools/check-no-newtonsoft-closure.sh</c> (`dotnet list package --include-transitive`), which runs
/// as the CI <c>no-newtonsoft</c> job. The two together cover NFR-002.
/// </para>
/// </remarks>
public sealed class ClosureTests
{
    private static readonly string[] BannedAssemblies =
        ["Newtonsoft.Json", "dotNetRDF", "AngleSharp", "HtmlAgilityPack"];

    [Theory]
    [FrTag("NFR-002")]
    [InlineData("Credentials.Core")]
    [InlineData("Credentials.Extensions.DependencyInjection")]
    public void DefaultLibrary_ReferenceClosure_HasNoNewtonsoft(string libraryName)
    {
        using var mlc = LibrarySurface.CreateLoadContext();
        var root = mlc.LoadFromAssemblyPath(LibrarySurface.DllPathFor(libraryName));

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var offenders = new List<string>();
        Walk(root, "(root) " + libraryName, mlc, visited, offenders);

        offenders.Should().BeEmpty(
            $"the transitive reference closure of {libraryName} must be Newtonsoft-free (NFR-002). Offending chains:\n"
            + string.Join("\n", offenders));
    }

    private static void Walk(Assembly assembly, string chain, MetadataLoadContext mlc, HashSet<string> visited, List<string> offenders)
    {
        var name = assembly.GetName().Name ?? "(unknown)";
        if (!visited.Add(name)) return;

        foreach (var reference in assembly.GetReferencedAssemblies())
        {
            var refName = reference.Name ?? "(unknown)";
            if (BannedAssemblies.Any(b => string.Equals(b, refName, StringComparison.OrdinalIgnoreCase)))
            {
                offenders.Add($"{chain} -> {refName}");
                continue;
            }

            // Recurse into every non-BCL reference (so a used Newtonsoft edge hidden behind any
            // intermediate package assembly is still found); skip only the vast, Newtonsoft-free
            // System.*/Microsoft.* runtime surface. The banned-name check above already ran for this
            // reference regardless of whether we recurse into it.
            if (IsBclAssembly(refName)) continue;

            Assembly? resolved = null;
            try { resolved = mlc.LoadFromAssemblyName(reference); }
            catch { /* unresolvable reference — its name was already checked above */ }
            if (resolved is not null)
                Walk(resolved, $"{chain} -> {refName}", mlc, visited, offenders);
        }
    }

    private static bool IsBclAssembly(string refName) =>
        refName.StartsWith("System", StringComparison.Ordinal)
        || refName.StartsWith("Microsoft", StringComparison.Ordinal)
        || refName.Equals("mscorlib", StringComparison.Ordinal)
        || refName.Equals("netstandard", StringComparison.Ordinal)
        || refName.Equals("WindowsBase", StringComparison.Ordinal);
}
