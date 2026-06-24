using System.Reflection;
using System.Xml.Linq;

namespace Credentials.Tools.ApiCoverage;

// Usage: api-coverage <cobertura.xml> <exclusions.txt> <lib1.dll> <lib2.dll> ...
// Exit 0 if every gateable public type of the libraries is covered (or exempted); 1 otherwise.
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.Error.WriteLine("usage: api-coverage <cobertura.xml> <exclusions.txt> <lib.dll> [<lib.dll> ...]");
            return 2;
        }

        var coberturaPath = args[0];
        var exclusionsPath = args[1];
        var libPaths = args[2..];

        var coveredRate = ParseCobertura(coberturaPath);
        var exclusions = ReadExclusions(exclusionsPath);

        var covered = new List<string>();
        var uncovered = new List<string>();
        var exempted = new List<string>();
        var notGateable = new List<string>();

        using var mlc = CreateLoadContext(libPaths);
        foreach (var libPath in libPaths)
        {
            foreach (var type in mlc.LoadFromAssemblyPath(libPath).GetExportedTypes())
            {
                var name = (type.FullName ?? type.Name).Replace('+', '.');
                if (IsCompilerGenerated(name)) continue;

                if (exclusions.Contains(name)) { exempted.Add(name); continue; }

                // Gateability is decided from REFLECTION, not from absence in cobertura: a type with no
                // executable members (interface, enum, delegate, a const-only static class) has nothing to
                // cover and is legitimately skipped. A gateable type (one with executable members) that is
                // absent from cobertura is treated as UNCOVERED — coverlet should have emitted it, so its
                // absence is a real gap, not a silent pass.
                if (!IsGateable(type)) { notGateable.Add(name); continue; }

                coveredRate.TryGetValue(name, out var rate); // absent => 0 => uncovered
                if (rate > 0) covered.Add(name); else uncovered.Add(name);
            }
        }

        Console.WriteLine($"api-coverage: {covered.Count} covered, {uncovered.Count} uncovered, {exempted.Count} exempted, {notGateable.Count} not-gateable (interface/enum/delegate/no-IL).");
        if (exempted.Count > 0)
            Console.WriteLine("  exempted (see exclusions file): " + string.Join(", ", exempted.OrderBy(x => x)));
        // Print the not-gateable set so it is auditable — an upward drift (a new no-IL public type) is
        // visible in the log rather than silently swallowed.
        if (notGateable.Count > 0)
            Console.WriteLine("  not-gateable (no executable IL to cover): " + string.Join(", ", notGateable.OrderBy(x => x)));

        if (uncovered.Count > 0)
        {
            Console.Error.WriteLine("\nFAIL: these public types are exercised by no sample and are not exempted:");
            foreach (var t in uncovered.OrderBy(x => x)) Console.Error.WriteLine("  - " + t);
            Console.Error.WriteLine("\nAdd a sample that exercises each, or add it to " + exclusionsPath + " with a reason.");
            return 1;
        }

        // Guard against a stale exclusion that now IS covered (keep the exempt list honest).
        var staleExclusions = exclusions
            .Where(e => coveredRate.TryGetValue(e, out var r) && r > 0)
            .OrderBy(x => x).ToList();
        if (staleExclusions.Count > 0)
        {
            Console.Error.WriteLine("\nFAIL: these exclusions are now covered by a sample — remove them from " + exclusionsPath + ":");
            foreach (var t in staleExclusions) Console.Error.WriteLine("  - " + t);
            return 1;
        }

        Console.WriteLine("api-coverage OK: every gateable public type is exercised by a sample.");
        return 0;
    }

    private static Dictionary<string, double> ParseCobertura(string path)
    {
        var rates = new Dictionary<string, double>(StringComparer.Ordinal);
        foreach (var cls in XDocument.Load(path).Descendants("class"))
        {
            var name = cls.Attribute("name")?.Value;
            if (name is null) continue;
            // Normalize nested-type separators to '.' to match reflection FullName (with '+' → '.').
            name = name.Replace('/', '.').Replace('+', '.');
            // Strip the compiler-generated nested state-machine suffix so it folds into its owner type.
            var slash = name.IndexOf(".<", StringComparison.Ordinal);
            if (slash >= 0) name = name[..slash];
            if (IsCompilerGenerated(name)) continue;

            var rate = double.TryParse(cls.Attribute("line-rate")?.Value,
                System.Globalization.CultureInfo.InvariantCulture, out var r) ? r : 0;
            rates[name] = Math.Max(rates.TryGetValue(name, out var existing) ? existing : 0, rate);
        }
        return rates;
    }

    private static HashSet<string> ReadExclusions(string path)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        if (!File.Exists(path)) return set;
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw;
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            line = line.Trim();
            if (line.Length > 0) set.Add(line);
        }
        return set;
    }

    // Async state machines and lambda closures both contain '<' in their type names.
    private static bool IsCompilerGenerated(string name) => name.Contains('<');

    // A type is gateable for code coverage iff it actually carries executable members. Interfaces,
    // enums, delegates, and const-only static classes have no instrumentable IL, so they are not
    // gateable (and need no exclusion); everything else (concrete/abstract/static classes, structs,
    // records) is, and must therefore be exercised by a sample or explicitly exempted.
    private static bool IsGateable(Type type)
    {
        if (type.IsInterface || type.IsEnum) return false;
        if (type.BaseType?.FullName is "System.MulticastDelegate" or "System.Delegate") return false;

        const BindingFlags flags =
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        // Constructors (incl. a static cctor) and any non-abstract method have a body to cover.
        return type.GetConstructors(flags).Length > 0
            || type.GetMethods(flags).Any(m => !m.IsAbstract);
    }

    private static MetadataLoadContext CreateLoadContext(string[] libPaths)
    {
        var paths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var dirs = new List<string> { System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory() };
        dirs.AddRange(libPaths.Select(p => Path.GetDirectoryName(Path.GetFullPath(p))!));
        foreach (var dir in dirs.Where(Directory.Exists))
            foreach (var dll in Directory.EnumerateFiles(dir, "*.dll"))
                paths.TryAdd(Path.GetFileNameWithoutExtension(dll), dll);
        return new MetadataLoadContext(new PathAssemblyResolver(paths.Values));
    }
}
