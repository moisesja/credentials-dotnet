using System.Diagnostics;
using Credentials.BbsGate;

// The no-library gate (issue #57). See tools/check-bbs-tests-without-library.sh for what it is given.
//
//   --repo <dir>                    the repository root (required)
//   --with-library-results <dir>    the result files (TRX) of the normal test run (required)
//   --solution <file>               the solution those results are of: each result has to be of one of
//                                   its test projects, and each of its test projects has to have results
//                                   (required)
//   --filter <expression>           the filter of that run, used again for the run without the library
//   --list <file>                   the tests that need no native library
//   --availability-check <test>     the test that passes exactly when the library loads
//   --expect <file>                 pass when the findings are exactly these (the self-test), not when there are none
//   --work <dir>                    an existing folder to work in and to keep what the run leaves: inside
//                                   the repository, because some tests find their sources from where they
//                                   run; not under tests/, which the gate copies; and not reached
//                                   through a link.
//
// The gate never deletes, overwrites or truncates anything it did not create in the same run. It checks
// every argument before it writes anything. Then it makes one new folder of its own, in --work or, without
// it, in artifacts/bbs-gate of the repository (which it makes if it is not there, and leaves), and writes
// only inside that folder. At the end it deletes that folder and nothing else; with --work, after a run
// that got as far as its verdict, it keeps the folder and prints its path. A run that is killed leaves its
// folder behind, and no later run removes it: delete artifacts/bbs-gate by hand when it has grown.
//
// Exit code: 0 the gate passes, 1 it has findings, 2 it could not run, which includes every wrong call.
string[] known = ["--repo", "--with-library-results", "--solution", "--filter", "--list", "--availability-check", "--expect", "--work"];
OwnFolder? own = null;
var reachedItsVerdict = false;
var keep = false;

try
{
    var clock = Stopwatch.StartNew();

    // The arguments, all of them, before the first write.
    var options = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var i = 0; i < args.Length; i += 2)
    {
        if (!known.Contains(args[i]))
        {
            throw new ArgumentException($"'{args[i]}' is not an option of the gate. See the head of Program.cs.");
        }

        if (i + 1 == args.Length || args[i + 1].Length == 0)
        {
            throw new ArgumentException($"{args[i]} needs a value.");
        }

        if (!options.TryAdd(args[i], args[i + 1]))
        {
            throw new ArgumentException($"{args[i]} is given twice.");
        }
    }

    string Required(string name) => options.TryGetValue(name, out var value)
        ? value
        : throw new ArgumentException($"{name} is required. See the head of Program.cs.");
    string ExistingFile(string name, string path) => File.Exists(path)
        ? Path.GetFullPath(path)
        : throw new ArgumentException($"{name}: there is no file {Path.GetFullPath(path)}.");

    var repository = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Required("--repo")));
    if (!Directory.Exists(Path.Combine(repository, "tests")))
    {
        throw new ArgumentException($"--repo: {repository} is not the repository: it has no tests folder.");
    }

    var solution = ExistingFile("--solution", Required("--solution"));
    var list = NoLibraryGate.ReadList(File.ReadLines(ExistingFile(
        "--list", options.GetValueOrDefault("--list", Path.Combine(repository, "tests", "Credentials.BbsGate", "need-no-native-library.txt")))));
    var expected = options.TryGetValue("--expect", out var expectedFile)
        ? File.ReadLines(ExistingFile("--expect", expectedFile)).Select(line => line.Trim()).Where(line => line.Length > 0 && !line.StartsWith('#')).Order(StringComparer.Ordinal).ToList()
        : null;
    var check = options.GetValueOrDefault(
        "--availability-check", "Credentials.Rdfc.Tests.BbsNativeLibraryTests.Bbs_native_library_loads_wherever_it_has_to");

    var with = TestRun.Read(Required("--with-library-results"));
    if (with.Assemblies.Count == 0)
    {
        throw new ArgumentException($"--with-library-results: no result file in {Path.GetFullPath(Required("--with-library-results"))}. Run the tests with a trx logger first.");
    }

    if (with.Assemblies.FirstOrDefault(assembly => !File.Exists(assembly)) is { } gone)
    {
        throw new ArgumentException($"--with-library-results: the results are of {gone}, which is not there. They are not the results of this build.");
    }

    var (withoutResults, notOfTheSolution) = TestRun.CompareWithSolution(solution, with.Assemblies);
    if (notOfTheSolution.Count > 0)
    {
        throw new ArgumentException($"--solution: the results are of {notOfTheSolution[0]}, which is not the output of a project of {solution}.");
    }

    // Where the gate works: a folder inside the repository, not under tests/ (which is copied into the
    // work folder and read for test sources), and not reached through a link, which could lead anywhere.
    keep = options.TryGetValue("--work", out var givenWork);
    var parent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(keep ? givenWork! : Path.Combine(repository, "artifacts", "bbs-gate")));
    var what = keep ? "--work" : "the folder the gate works in without --work";
    if (keep && !Directory.Exists(parent))
    {
        throw new ArgumentException($"--work: there is no folder {parent}. The gate makes one folder of its own in it, not the folder itself.");
    }

    if (!Paths.IsInside(repository, parent))
    {
        throw new ArgumentException($"{what}: {parent} is not a folder inside the repository {repository}. The gate works inside the "
            + "repository, in a folder other than the root, because some tests find their sources from where they run.");
    }

    var below = Path.GetRelativePath(repository, parent).Split(Path.DirectorySeparatorChar);
    if (string.Equals(below[0], "tests", StringComparison.OrdinalIgnoreCase))
    {
        throw new ArgumentException($"{what}: {parent} is under tests/, which the gate copies and reads for test sources.");
    }

    for (var depth = 1; depth <= below.Length; depth++)
    {
        var part = Path.Combine([repository, .. below[..depth]]);
        if (File.Exists(part) || (Directory.Exists(part) && new DirectoryInfo(part).LinkTarget is not null))
        {
            throw new ArgumentException($"{what}: {part} is a file or a link. The gate works in a real folder of the repository.");
        }
    }

    if (with.Assemblies.Select(assembly => Path.GetDirectoryName(Path.GetFullPath(assembly))!)
            .FirstOrDefault(output => output == parent || Paths.IsInside(output, parent)) is { } holder)
    {
        throw new ArgumentException($"{what}: {parent} is in {holder}, the folder of a test assembly, which the gate copies.");
    }

    // What is read is read now, too: the sources, for the bbs-2023 classes, and the assemblies, for the
    // classes that derive from them. A result file that is not of a test assembly stops the gate here.
    var scope = BbsScope.Scan(BbsScope.ReadSources(repository));
    var classes = TestClasses.Read(with.Assemblies, scope.Classes);

    // The first write: one new folder, the gate's own. Everything else it writes or deletes is inside it.
    if (!keep)
    {
        Directory.CreateDirectory(parent);
    }

    own = OwnFolder.MakeIn(parent, () => Guid.NewGuid().ToString("N")[..8]);
    var work = own.Path;
    string Mine(string path) => Paths.IsInside(work, path)
        ? Path.GetFullPath(path)
        : throw new InvalidOperationException($"The gate was about to write to {Path.GetFullPath(path)}, which is outside the folder it made, {work}. It writes nowhere else.");

    // What the gate objects to: a key, which the self-test compares, and the text for a reader.
    var findings = new List<(string Key, string Text)>();
    void Problem(string text) => findings.Add((text, text));

    // The results have to cover every test project of the solution. A result file that went missing
    // would otherwise take its tests out of both runs.
    foreach (var project in withoutResults)
    {
        Problem($"{project} is a test project of the solution and none of the result files of the normal run is from it, "
            + "so its tests would be in neither run. Either a result file went missing, or the filter excludes "
            + "every test of the project, in which case none is written: keep at least one test of each test "
            + "project in the filtered run.");
    }

    // The run without the library: every test assembly of the normal run, from a copy with the library's
    // files removed. The copy is of everything under tests/ (but for obj and the other outputs), at the
    // same paths under the work folder as under the repository: a test that reads a file beside its
    // project or in the one next to it, or looks for the repository above it, finds what it finds in the
    // normal run. GITHUB_ACTIONS=true, so that a missing library has to fail a guarded test on any host.
    Directory.CreateDirectory(Mine(Path.Combine(work, "tests")));
    foreach (var file in Directory.EnumerateFiles(Path.Combine(repository, "tests")))
    {
        File.Copy(file, Mine(Path.Combine(work, "tests", Path.GetFileName(file))));
    }

    foreach (var folder in Directory.EnumerateDirectories(Path.Combine(repository, "tests")))
    {
        Paths.Copy(folder, Path.Combine(work, "tests", Path.GetFileName(folder)), skip: ["bin", "obj"], Mine, own.Is);
    }

    var removed = 0;
    var runs = new List<(string Name, int Index, Process Process, Task<string> Output, Task<string> Errors)>();
    foreach (var (assembly, index) in with.Assemblies.Select((assembly, index) => (Path.GetFullPath(assembly), index)))
    {
        var name = Path.GetFileNameWithoutExtension(assembly);
        var output = Path.GetDirectoryName(assembly)!;

        // An output folder inside the repository keeps its path under the work folder. One that is
        // elsewhere, on another drive for one, gets a folder of its own there.
        var copy = Mine(Path.Combine(work, Paths.IsInside(repository, output) ? Path.GetRelativePath(repository, output) : $"{index}-{name}"));
        Paths.Copy(output, copy, skip: [], Mine, own.Is);
        foreach (var library in Directory.EnumerateFiles(copy, "*", SearchOption.AllDirectories)
                     .Where(file => Path.GetFileName(file).Contains("zkryptium_ffi", StringComparison.OrdinalIgnoreCase)).ToList())
        {
            File.Delete(Mine(library));
            removed++;
        }

        var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in (string[])["test", Path.Combine(copy, Path.GetFileName(assembly)),
                     "--logger", $"trx;LogFileName={index}-{name}.trx", "--results-directory", Mine(Path.Combine(work, "results"))])
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
        File.WriteAllText(Mine(Path.Combine(work, $"{index}-{name}.log")), log);
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
    if (without.Results.Count == 0)
    {
        // Not a finding about a test: the second run did not happen at all. A filter that cannot be
        // read does this.
        throw new InvalidOperationException("the run without the library produced no result at all. Either --filter is "
            + $"not a filter the tests can be run with, or `dotnet test` could not run them:\n{findings.LastOrDefault().Text}");
    }

    findings.AddRange(NoLibraryGate.Compare(with.Results, without.Results, scope.Findings, classes, list, check)
        .Select(finding => (finding.Key, finding.ToString())));

    Console.WriteLine($"bbs-2023 gate: {with.Assemblies.Count} test assemblies, {with.Results.Count} results with the library and "
        + $"{without.Results.Count} without it ({removed} library files removed); {classes.InScope.Count} bbs-2023 classes, "
        + $"{list.Count} tests on the list; {clock.Elapsed.TotalSeconds:F0} s.");
    reachedItsVerdict = true;

    // One verdict, read two ways. The gate passes when it has no finding. The self-test passes when the
    // findings are exactly the ones a project of deliberately wrong tests is known to have.
    if (expected is not null)
    {
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
catch (Exception exception)
{
    // Whatever stops the gate, a wrong argument, a file that is not what it should be, a full disk, is
    // "could not run". Nothing here is a verdict about a test.
    Console.Error.WriteLine("bbs-2023 gate could not run: " + exception.Message);
    return 2;
}
finally
{
    // The gate's own folder, and nothing else. It stays only when it was asked for with --work and the
    // run got as far as its verdict; a run that stopped before that leaves nothing of use.
    if (own is not null)
    {
        if (keep && reachedItsVerdict)
        {
            Console.WriteLine($"bbs-2023 gate: the copies, logs and results of this run are in {own.Path}.");
        }
        else
        {
            try
            {
                Directory.Delete(own.Path, recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // A test host can hold a file a moment longer than it lives. Nothing removes the folder
                // later: it can be deleted by hand.
                Console.WriteLine($"bbs-2023 gate: could not delete its folder {own.Path} ({exception.Message}). It stays until someone deletes it.");
            }
        }
    }
}
