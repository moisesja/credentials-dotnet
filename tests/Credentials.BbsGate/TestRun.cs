using System.Xml.Linq;

namespace Credentials.BbsGate;

/// <summary>One result of one test, as a result file (TRX) records it. A theory has one for each row.</summary>
/// <param name="Assembly">The file name of the test assembly.</param>
/// <param name="Test">The test: namespace, class and method, without the arguments of a row.</param>
/// <param name="Row">The name of the result: the test, with the arguments of the row if it is one.</param>
/// <param name="Outcome">The outcome: <c>Passed</c>, <c>Failed</c>, or <c>NotExecuted</c> for a skip.</param>
/// <param name="Message">The message of a failure; empty otherwise.</param>
internal sealed record TestResult(string Assembly, string Test, string Row, string Outcome, string Message)
{
    /// <summary>What a result file calls a test that passed.</summary>
    public const string Passed = "Passed";

    /// <summary>What a result file calls a test that failed.</summary>
    public const string Failed = "Failed";
}

/// <summary>The result files of one test run.</summary>
/// <param name="Results">Every result.</param>
/// <param name="Assemblies">The test assemblies the results came from, by path.</param>
internal sealed record TestRun(IReadOnlyList<TestResult> Results, IReadOnlyList<string> Assemblies)
{
    /// <summary>Reads every result file in a folder.</summary>
    /// <exception cref="FormatException">A file with the extension of a result file is not one.</exception>
    public static TestRun Read(string directory)
    {
        var runs = new List<TestRun>();
        IEnumerable<string> files = Directory.Exists(directory)
            ? Directory.EnumerateFiles(directory, "*.trx", SearchOption.AllDirectories).Order(StringComparer.Ordinal)
            : [];
        foreach (var file in files)
        {
            try
            {
                runs.Add(Parse(XDocument.Load(file)));
            }
            catch (Exception exception) when (exception is System.Xml.XmlException or KeyNotFoundException or NullReferenceException or ArgumentException or InvalidOperationException)
            {
                throw new FormatException($"{file} is not the result file of a test run: {exception.Message}");
            }
        }

        return new TestRun(
            [.. runs.SelectMany(run => run.Results)],
            [.. runs.SelectMany(run => run.Assemblies).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)]);
    }

    /// <summary>
    /// Holds the results against the solution they are said to be of. A test project is one whose output
    /// folder has the test host in it; it has results when one of the assemblies the results came from is
    /// in that folder, whatever the assembly is called. The output folder is looked for where the
    /// assemblies with results have theirs (<c>bin/Release/net10.0</c>, say).
    /// </summary>
    /// <returns>
    /// The test projects of the solution that are built and have no results, by name; and the assemblies
    /// with results that are in the output folder of no project of the solution.
    /// </returns>
    /// <exception cref="FormatException">The file names no project.</exception>
    public static (List<string> WithoutResults, List<string> NotOfTheSolution) CompareWithSolution(string solutionFile, IReadOnlyList<string> assembliesWithResults)
    {
        var assemblies = assembliesWithResults.Select(Path.GetFullPath).ToList();
        var first = Path.GetDirectoryName(assemblies[0])!;
        var layout = Path.GetRelativePath(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(first)))!, first);
        var root = Path.GetDirectoryName(Path.GetFullPath(solutionFile))!;
        var projects = File.ReadLines(solutionFile)
            .Select(line => line.Split('"')).Where(parts => parts.Length > 5 && parts[5].EndsWith(".csproj", StringComparison.Ordinal))
            .Select(parts => Path.Combine(root, parts[5].Replace('\\', Path.DirectorySeparatorChar)))
            .ToList();
        if (projects.Count == 0)
        {
            throw new FormatException($"{solutionFile} names no project: it is not a solution.");
        }

        var outputs = projects.ToDictionary(project => Path.Combine(Path.GetDirectoryName(project)!, layout), Path.GetFileNameWithoutExtension, StringComparer.OrdinalIgnoreCase);
        var withResults = assemblies.Select(assembly => Path.GetDirectoryName(assembly)!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return (
            [.. outputs.Where(output => File.Exists(Path.Combine(output.Key, "testhost.dll")) && !withResults.Contains(output.Key)).Select(output => output.Value!)],
            [.. assemblies.Where(assembly => !outputs.ContainsKey(Path.GetDirectoryName(assembly)!))]);
    }

    /// <summary>Reads one result file.</summary>
    public static TestRun Parse(XDocument trx)
    {
        var ns = trx.Root!.Name.Namespace;
        var methods = trx.Descendants(ns + "UnitTest").ToDictionary(
            test => (string)test.Attribute("id")!,
            test => test.Element(ns + "TestMethod")!);

        var results = trx.Descendants(ns + "UnitTestResult").Select(result =>
        {
            var method = methods[(string)result.Attribute("testId")!];
            return new TestResult(
                Path.GetFileName((string?)method.Attribute("codeBase") ?? throw new InvalidOperationException("a test without the path of its assembly")),
                TestNameOf(method),
                (string)result.Attribute("testName")!,
                (string)result.Attribute("outcome")!,
                (string?)result.Descendants(ns + "Message").FirstOrDefault() ?? string.Empty);
        }).ToList();
        var assemblies = methods.Values.Select(method => (string?)method.Attribute("codeBase") ?? throw new InvalidOperationException("a test without the path of its assembly"))
            .Distinct(StringComparer.Ordinal).ToList();
        return new TestRun(results, assemblies);
    }

    // The full name of the test: the class, a dot, the method. A result file gives the method with the
    // class before it or without, and with the arguments of a row after it. It works the class out from
    // the name the test is shown under, so for a test with a display name of its own the "class" can be
    // cut short and the rest be in the "method"; put together they are the full name again.
    private static string TestNameOf(XElement method)
    {
        var @class = (string)method.Attribute("className")!;
        var name = (string)method.Attribute("name")!;
        var arguments = name.IndexOf('(', StringComparison.Ordinal);
        name = arguments < 0 ? name : name[..arguments];
        return name.StartsWith(@class + ".", StringComparison.Ordinal) ? name : $"{@class}.{name}";
    }
}
