using System.Diagnostics;
using Credentials.BbsGate;

// The no-library gate (issue #57). See tools/check-bbs-tests-without-library.sh for what it is given.
//
//   --repo <dir>                    the repository root
//   --with-library-results <dir>    the result files (TRX) of the normal test run
//   --solution <file>               every test project of this solution has to be in those results
//                                   (required)
//   --filter <expression>           the filter of that run, used again for the run without the library
//   --list <file>                   the tests that need no native library
//   --availability-check <test>     the test that passes exactly when the library loads
//   --expect <file>                 pass when the findings are exactly these (the self-test), not when there are none
//   --work <dir>                    where to put the copies, and keep them; artifacts/bbs-gate in the
//                                   repository otherwise, deleted at the end. It has to be inside the
//                                   repository: some tests find their sources from where they run.
var options = new Dictionary<string, string>(StringComparer.Ordinal);
for (var i = 0; i + 1 < args.Length; i += 2)
{
    options[args[i]] = args[i + 1];
}

string Required(string name) => options.TryGetValue(name, out var value)
    ? value
    : throw new ArgumentException($"{name} is required. See the head of Program.cs.");

try
{
    var clock = Stopwatch.StartNew();
    var repository = Path.GetFullPath(Required("--repo"));
    var with = TestRun.Read(Required("--with-library-results"));
    if (with.Assemblies.Count == 0)
    {
        throw new InvalidOperationException($"No result file in {Required("--with-library-results")}: run the tests with a trx logger first.");
    }

    var keep = options.ContainsKey("--work");
    var work = keep ? Path.GetFullPath(options["--work"]) : Path.Combine(repository, "artifacts", "bbs-gate");
    if (Directory.Exists(work))
    {
        Directory.Delete(work, recursive: true);
    }

    Directory.CreateDirectory(work);

    // What the gate objects to: a key, which the self-test compares, and the text for a reader.
    var findings = new List<(string Key, string Text)>();
    void Problem(string text) => findings.Add((text, text));

    // The results have to cover every test project of the solution. A result file that went missing
    // would otherwise take its tests out of both runs.
    // The results have to cover every test project of the solution. A result file that went missing
    // would otherwise take its tests out of both runs.
    foreach (var missing in TestRun.TestAssembliesWithoutResults(Required("--solution"), with.Assemblies))
    {
        Problem($"{Path.GetFileName(missing)} is a test assembly of the solution and has no result file among those "
            + "of the normal run, so its tests would be in neither run.");
    }

    // The run without the library: every test assembly of the normal run, from a copy with the library's
    // files removed. The copy is of everything under tests/ (but for obj and the other outputs), at the
    // same paths under the work folder as under the repository: a test that reads a file beside its
    // project or in the one next to it, or looks for the repository above it, finds what it finds in the
    // normal run. GITHUB_ACTIONS=true, so that a missing library has to fail a guarded test on any host.
    foreach (var folder in Directory.EnumerateDirectories(Path.Combine(repository, "tests")))
    {
        CopyDirectory(folder, Path.Combine(work, "tests", Path.GetFileName(folder)), skip: ["bin", "obj"]);
    }

    var removed = 0;
    var runs = new List<(string Name, int Index, Process Process, Task<string> Output, Task<string> Errors)>();
    foreach (var (assembly, index) in with.Assemblies.Select((assembly, index) => (Path.GetFullPath(assembly), index)))
    {
        var name = Path.GetFileNameWithoutExtension(assembly);
        var output = Path.GetDirectoryName(assembly)!;
        var inRepository = !Path.GetRelativePath(repository, output).StartsWith("..", StringComparison.Ordinal);
        var copy = Path.Combine(work, inRepository ? Path.GetRelativePath(repository, output) : $"{index}-{name}");
        CopyDirectory(output, copy, skip: []);
        foreach (var library in Directory.EnumerateFiles(copy, "*", SearchOption.AllDirectories)
                     .Where(file => Path.GetFileName(file).Contains("zkryptium_ffi", StringComparison.OrdinalIgnoreCase)).ToList())
        {
            File.Delete(library);
            removed++;
        }

        var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in (string[])["test", Path.Combine(copy, Path.GetFileName(assembly)),
                     "--logger", $"trx;LogFileName={index}-{name}.trx", "--results-directory", Path.Combine(work, "results")])
        {
            start.ArgumentList.Add(argument);
        }

        if (options.TryGetValue("--filter", out var filter))
        {
            start.ArgumentList.Add("--filter");
            start.ArgumentList.Add(filter);
        }

        start.Environment["GITHUB_ACTIONS"] = "true";
        // The assemblies run side by side, as they do in the normal run.
        var process = Process.Start(start)!;
        runs.Add((name, index, process, process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync()));
    }

    foreach (var (name, index, process, output, errors) in runs)
    {
        process.WaitForExit();
        var log = output.Result + errors.Result;
        File.WriteAllText(Path.Combine(work, $"{index}-{name}.log"), log);
        if (!File.Exists(Path.Combine(work, "results", $"{index}-{name}.trx")))
        {
            Problem($"{name} produced no result file without the library (exit code {process.ExitCode}):\n"
                + string.Join("\n", log.Split('\n').TakeLast(15)));
        }

        process.Dispose();
    }

    if (removed == 0)
    {
        Problem("no file of the native library (zkryptium_ffi) was found in any test output folder, so nothing was hidden.");
    }

    var without = TestRun.Read(Path.Combine(work, "results"));
    var scope = BbsScope.Scan(BbsScope.ReadSources(repository));
    string[] bbsClasses = [.. scope.Classes, .. TestTypes.DerivedFrom(with.Assemblies, scope.Classes)];
    var listFile = options.GetValueOrDefault("--list", Path.Combine(repository, "tests", "Credentials.BbsGate", "need-no-native-library.txt"));
    var list = NoLibraryGate.ReadList(File.ReadLines(listFile));
    var check = options.GetValueOrDefault(
        "--availability-check", "Credentials.Rdfc.Tests.BbsNativeLibraryTests.Bbs_native_library_loads_wherever_it_has_to");

    findings.AddRange(NoLibraryGate.Compare(with.Results, without.Results, scope.Findings, bbsClasses, list, check)
        .Select(finding => (finding.Key, finding.ToString())));
    if (!keep)
    {
        try
        {
            Directory.Delete(work, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A test host can hold a file a moment longer than it lives. The copies are in artifacts/, which
            // nothing else reads, and the next run deletes them first.
            Console.WriteLine($"bbs-2023 gate: could not delete {work} ({exception.Message}).");
        }
    }

    Console.WriteLine($"bbs-2023 gate: {with.Assemblies.Count} test assemblies, {with.Results.Count} results with the library and "
        + $"{without.Results.Count} without it ({removed} library files removed); {bbsClasses.Length} bbs-2023 classes, "
        + $"{list.Count} tests on the list; {clock.Elapsed.TotalSeconds:F0} s.");

    // One verdict, read two ways. The gate passes when it has no finding. The self-test passes when the
    // findings are exactly the ones a project of deliberately wrong tests is known to have.
    if (options.TryGetValue("--expect", out var expectedFile))
    {
        var expected = File.ReadLines(expectedFile).Select(line => line.Trim()).Where(line => line.Length > 0 && !line.StartsWith('#')).Order(StringComparer.Ordinal).ToList();
        var actual = findings.Select(finding => finding.Key).Order(StringComparer.Ordinal).ToList();
        foreach (var line in actual)
        {
            Console.WriteLine("  reported: " + line);
        }

        if (expected.SequenceEqual(actual, StringComparer.Ordinal))
        {
            Console.WriteLine($"bbs-2023 gate self-test OK: the gate reported exactly the {expected.Count} findings it has to.");
            return 0;
        }

        Console.Error.WriteLine("bbs-2023 gate self-test FAILED: the gate did not report exactly what it has to.");
        foreach (var line in expected.Except(actual))
        {
            Console.Error.WriteLine("  missing:    " + line);
        }

        foreach (var line in actual.Except(expected))
        {
            Console.Error.WriteLine("  unexpected: " + line);
        }

        return 1;
    }

    if (findings.Count == 0)
    {
        Console.WriteLine("bbs-2023 gate OK: without the native library every test of a bbs-2023 class failed by the helper's check, every listed test passed, and no other test changed.");
        return 0;
    }

    Console.Error.WriteLine($"bbs-2023 gate FAILED: {findings.Count} finding(s).");
    foreach (var finding in findings)
    {
        Console.Error.WriteLine("  " + finding.Text);
    }

    return 1;
}
catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or FormatException or IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine("bbs-2023 gate could not run: " + exception.Message);
    return 2;
}

static void CopyDirectory(string from, string to, string[] skip)
{
    Directory.CreateDirectory(to);
    foreach (var file in Directory.EnumerateFiles(from))
    {
        File.Copy(file, Path.Combine(to, Path.GetFileName(file)), overwrite: true);
    }

    foreach (var directory in Directory.EnumerateDirectories(from).Where(directory => !skip.Contains(Path.GetFileName(directory))))
    {
        CopyDirectory(directory, Path.Combine(to, Path.GetFileName(directory)), skip: []);
    }
}
