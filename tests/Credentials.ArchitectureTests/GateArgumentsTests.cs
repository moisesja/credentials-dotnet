using System.Diagnostics;
using System.Security.Cryptography;
using Credentials.BbsGate;
using FluentAssertions;
using Xunit;

namespace Credentials.ArchitectureTests;

/// <summary>
/// The gate program of <c>tests/Credentials.BbsGate</c>, run as a process with arguments that are wrong.
/// It has to exit with 2 and leave every file and folder as it found them: the gate checks all its
/// arguments before it writes anything, and never deletes what it did not create in the same run.
/// </summary>
/// <remarks>
/// The first case is the one the review of PR #72 found at b3aa49b: <c>--work</c> pointed at a folder
/// outside the repository and <c>--solution</c> left out. The program said that <c>--solution</c> is
/// required, exited with 2, and had already deleted the folder.
/// </remarks>
public sealed class GateArgumentsTests
{
    // Each wrong call: its name, its arguments (from the arguments of a right call, and a way to name a
    // path in the sandbox), and something the gate has to say about it, so that it is refused for the
    // reason the name gives.
    private static readonly Dictionary<string, (Func<string[], Func<string[], string>, string[]> Arguments, string Says)> Calls = new()
    {
        ["the case of the review: --work outside the repository, and no --solution"] =
            ((_, at) => ["--repo", at(["repo"]), "--with-library-results", at(["results"]), "--work", at(["outside"])], "--solution is required"),
        ["--work outside the repository"] = ((valid, at) => [.. valid, "--work", at(["outside"])], "is not a folder inside the repository"),
        ["--work outside the repository, with a separator at its end"] =
            ((valid, at) => [.. valid, "--work", at(["outside"]) + Path.DirectorySeparatorChar], "is not a folder inside the repository"),
        ["--work is the repository itself"] = ((valid, at) => [.. valid, "--work", at(["repo"])], "is not a folder inside the repository"),
        ["--work is a folder above the repository"] = ((valid, at) => [.. valid, "--work", at([])], "is not a folder inside the repository"),
        ["--work is . and the gate is run from the repository"] = ((valid, _) => [.. valid, "--work", "."], "is not a folder inside the repository"),
        ["--work is .. and the gate is run from the repository"] = ((valid, _) => [.. valid, "--work", ".."], "is not a folder inside the repository"),
        ["--work by a path that leaves the repository"] =
            ((valid, at) => [.. valid, "--work", Path.Combine(at(["repo", "artifacts"]), "..", "..", "outside")], "is not a folder inside the repository"),
        ["--work under tests"] = ((valid, at) => [.. valid, "--work", at(["repo", "tests", "x"])], "is under tests/"),
        // Where letter case is not told apart, the next three are folders that are there, by another name.
        // Elsewhere they are not there. Either way the gate has to refuse them.
        ["--work under tests by another spelling"] = ((valid, at) => [.. valid, "--work", at(["repo", "TESTS", "x"])], "--work"),
        ["--work under tests by a letter the file system may fold"] = ((valid, at) => [.. valid, "--work", at(["repo", "teſts", "x"])], "could not run"),
        ["--work inside the repository by a name in other letter case"] = ((valid, at) => [.. valid, "--work", at(["REPO", "artifacts", "work"])], "--work"),
        ["--work is a file"] = ((valid, at) => [.. valid, "--work", at(["repo", "list.txt"])], "--work"),
        ["--work that is not there"] = ((valid, at) => [.. valid, "--work", at(["repo", "artifacts", "new", "folder"])], "there is no folder"),
        ["--work that holds files, and no --solution"] =
            ((_, at) => ["--repo", at(["repo"]), "--with-library-results", at(["results"]), "--list", at(["repo", "list.txt"]), "--work", at(["repo", "artifacts", "work"])],
                "--solution is required"),
        ["--work is a link inside the repository to a folder outside it"] = ((valid, at) => [.. valid, "--work", at(["repo", "artifacts", "link"])], "is a file or a link"),
        ["--work is a link to a path that goes through another link"] = ((valid, at) => [.. valid, "--work", at(["repo", "artifacts", "second-link"])], "is a file or a link"),
        ["tests holds a link to the folder the gate works in"] = ((valid, at) => [.. valid, "--work", at(["repo", "artifacts", "work"])], "the folder the gate made"),
        ["an option without a value"] = ((valid, _) => [.. valid, "--work"], "needs a value"),
        ["an option with an empty value"] = ((valid, _) => [.. valid, "--work", ""], "needs a value"),
        ["an option the program does not have"] = ((valid, at) => [.. valid, "--wrok", at(["repo", "artifacts", "work"])], "is not an option"),
        ["an option given twice"] = ((valid, at) => [.. valid, "--work", at(["repo", "artifacts", "work"]), "--work", at(["outside"])], "is given twice"),
        ["no --repo"] = ((valid, _) => valid[2..], "--repo is required"),
        ["--repo without a tests folder"] = ((valid, at) => ["--repo", at(["outside"]), .. valid[2..]], "has no tests folder"),
        ["--solution that is not there"] = ((valid, at) => ["--repo", at(["repo"]), "--solution", at(["repo", "No.sln"]), .. valid[4..]], "--solution: there is no file"),
        ["--solution that names no project"] = ((valid, at) => ["--repo", at(["repo"]), "--solution", at(["repo", "list.txt"]), .. valid[4..]], "names no project"),
        ["--solution of other projects than the results are of"] =
            ((valid, at) => ["--repo", at(["repo"]), "--solution", at(["repo", "Other.sln"]), .. valid[4..]], "is not the output of a project"),
        ["--list that is not there"] = ((valid, at) => [.. valid[..6], "--list", at(["repo", "no-list.txt"])], "--list: there is no file"),
        ["--expect that is not there"] = ((valid, at) => [.. valid, "--expect", at(["repo", "no-expectations.txt"])], "--expect: there is no file"),
        ["--with-library-results without result files"] =
            ((valid, at) => [.. valid[..4], "--with-library-results", at(["outside"]), .. valid[6..]], "no result file"),
        ["a result file that is not one"] = ((valid, at) => [.. valid[..4], "--with-library-results", at(["not-results"]), .. valid[6..]], "is not the result file of a test run"),
        ["a result file without the path of its assembly"] =
            ((valid, at) => [.. valid[..4], "--with-library-results", at(["no-assembly"]), .. valid[6..]], "is not the result file of a test run"),
        ["results of a file that is not an assembly"] =
            ((valid, at) => ["--repo", at(["repo"]), "--solution", at(["repo", "Text.sln"]), "--with-library-results", at(["of-a-text-file"]), .. valid[6..]], "is not an assembly"),
        ["results of an assembly in the repository root"] =
            ((valid, at) => [.. valid[..4], "--with-library-results", at(["of-the-root"]), .. valid[6..]], "is not the output of a project"),
    };

    /// <summary>The names of the wrong calls.</summary>
    public static IEnumerable<object[]> WrongCalls() =>
        // A link cannot be made without a privilege on Windows; those cases are there on the other platforms.
        Calls.Keys.Where(call => !OperatingSystem.IsWindows() || !call.Contains("link", StringComparison.Ordinal)).Select(call => new object[] { call });

    [Theory]
    [MemberData(nameof(WrongCalls))]
    public void A_wrong_call_exits_with_2_and_touches_nothing(string call)
    {
        var sandbox = Directory.CreateTempSubdirectory("gate-arguments-").FullName;
        try
        {
            string At(params string[] parts) => Path.Combine([sandbox, .. parts]);
            void Write(string content, params string[] parts)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(At(parts))!);
                File.WriteAllText(At(parts), content);
            }

            static string Solution(string project) =>
                $"Project(\"{{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}}\") = \"{project}\", \"tests\\{project}\\{project}.csproj\", \"{{0}}\"\n";
            static string Results(string assembly) => $"""
                <TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
                  <Results><UnitTestResult testId="1" testName="Some.Tests.SomeTests.Adds" outcome="Passed" /></Results>
                  <TestDefinitions>
                    <UnitTest name="Some.Tests.SomeTests.Adds" id="1"><TestMethod {assembly} className="Some.Tests.SomeTests" name="Adds" /></UnitTest>
                  </TestDefinitions>
                </TestRun>
                """;

            // A repository in small: a solution with one test project, whose assembly is a real one (this
            // one), a list, and the results of a normal run. The arguments in `valid` are a right call.
            var assembly = At("repo", "tests", "Some.Tests", "bin", "Release", "net10.0", "Some.Tests.dll");
            Write(Solution("Some.Tests"), "repo", "Some.sln");
            Write("<Project />", "repo", "tests", "Some.Tests", "Some.Tests.csproj");
            Write("// a test source file\n", "repo", "tests", "Some.Tests", "SomeTests.cs");
            Write("// another\n", "repo", "tests", "x", "Vector.cs");
            Directory.CreateDirectory(Path.GetDirectoryName(assembly)!);
            File.Copy(typeof(GateArgumentsTests).Assembly.Location, assembly);
            Write("# no test needs listing\n", "repo", "list.txt");
            Write(Results($"codeBase=\"{assembly}\""), "results", "normal.trx");

            // For the calls that are wrong in their solution or their results.
            Write(Solution("Other.Tests"), "repo", "Other.sln");
            Write(Solution("Text.Tests"), "repo", "Text.sln");
            Write("not an assembly", "repo", "tests", "Text.Tests", "bin", "Release", "net10.0", "Text.Tests.dll");
            Write("this is not xml", "not-results", "normal.trx");
            Write(Results(string.Empty), "no-assembly", "normal.trx");
            Write(Results($"codeBase=\"{At("repo", "tests", "Text.Tests", "bin", "Release", "net10.0", "Text.Tests.dll")}\""), "of-a-text-file", "normal.trx");
            Write(Results($"codeBase=\"{At("repo", "list.txt")}\""), "of-the-root", "normal.trx");

            // What must still be there afterwards, untouched: a folder outside the repository, a work
            // folder inside it, and the folder the gate works in when it is given none.
            Write("not the gate's", "outside", "keep-me.txt");
            Write("not the gate's", "outside", "below", "keep-me.txt");
            Write("not the gate's", "repo", "artifacts", "work", "keep-me.txt");
            Write("not the gate's", "repo", "artifacts", "bbs-gate", "keep-me.txt");
            if (call.Contains("--work is a link", StringComparison.Ordinal))
            {
                Directory.CreateSymbolicLink(At("repo", "artifacts", "link"), At("outside"));
                Directory.CreateSymbolicLink(At("repo", "artifacts", "second-link"), At("repo", "artifacts", "link", "below"));
            }
            else if (call.Contains("tests holds a link", StringComparison.Ordinal))
            {
                Directory.CreateSymbolicLink(At("repo", "tests", "linked"), At("repo", "artifacts"));
            }

            string[] valid = ["--repo", At("repo"), "--solution", At("repo", "Some.sln"), "--with-library-results", At("results"), "--list", At("repo", "list.txt")];
            var (arguments, says) = (Calls[call].Arguments(valid, At), Calls[call].Says);
            var before = Snapshot(sandbox);

            var (exitCode, output) = RunTheGate(arguments, call.Contains("run from the repository", StringComparison.Ordinal) ? At("repo") : sandbox);

            Snapshot(sandbox).Should().Equal(before, "a wrong call must not create, change or delete anything. The gate said:\n{0}", output);
            exitCode.Should().Be(2, "a call the gate cannot carry out ends with 2. The gate said:\n{0}", output);
            output.Should().Contain(says, "that is what is wrong with this call");
        }
        finally
        {
            Directory.Delete(sandbox, recursive: true);
        }
    }

    /// <summary>
    /// The one folder a run may delete is one it has just made. A name that is taken, by a folder or by a
    /// file, stops the gate, and what has the name is left as it is: the gate picks the name at random, so
    /// a folder a killed run left behind can have it.
    /// </summary>
    [Fact]
    public void The_gates_own_folder_is_never_one_that_was_there()
    {
        var parent = Directory.CreateTempSubdirectory("gate-own-folder-").FullName;
        try
        {
            Directory.CreateDirectory(Path.Combine(parent, "deadbeef", "below"));
            File.WriteAllText(Path.Combine(parent, "deadbeef", "below", "keep-me.txt"), "not the gate's");
            File.WriteAllText(Path.Combine(parent, "0a1b2c3d"), "not the gate's");
            var before = Snapshot(parent);

            foreach (var taken in (string[])["deadbeef", "0a1b2c3d"])
            {
                var make = () => OwnFolder.MakeIn(parent, () => taken);
                make.Should().Throw<InvalidOperationException>().WithMessage("*already there*");
            }

            Snapshot(parent).Should().Equal(before);

            var own = OwnFolder.MakeIn(parent, () => "c0ffee00");
            own.Path.Should().Be(Path.Combine(parent, "c0ffee00"));
            own.Is(own.Path).Should().BeTrue();
            own.Is(Path.Combine(parent, "deadbeef")).Should().BeFalse();
            own.Is(parent).Should().BeFalse();
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    /// <summary>
    /// Every path the gate writes to or deletes has to be inside the one folder it made. "Inside" is by
    /// the full path: below the folder, not the folder itself, not a folder beside it whose name begins
    /// the same, and not whatever a path that begins with two dots happens to be.
    /// </summary>
    [Theory]
    [InlineData("work", "work/tests/Some.Tests/bin", true)]
    [InlineData("work", "work/..name", true)] // a name that begins with two dots is a name
    [InlineData("work", "work/a/../b", true)]
    [InlineData("work", "work", false)] // the folder itself
    [InlineData("work", "work/", false)]
    [InlineData("work", "work/..", false)]
    [InlineData("work", "work/../outside", false)]
    [InlineData("work", "work-of-another-run/tests", false)] // beside it, with a name that begins the same
    [InlineData("work", "WORK/tests", false)] // letter for letter
    [InlineData("work", "", false)]
    public void A_path_is_inside_a_folder_only_if_it_is_below_it(string folder, string path, bool inside)
    {
        var root = Path.Combine(Path.GetTempPath(), "gate-paths");

        Paths.IsInside(Path.Combine(root, folder), Path.Combine(root, path)).Should().Be(inside);
        Paths.IsInside(Path.Combine(root, folder) + Path.DirectorySeparatorChar, Path.Combine(root, path)).Should().Be(inside);
    }

    /// <summary>
    /// On Windows a path on another drive has no path relative to the folder, and joining it to the folder
    /// gives the path itself. So "inside" is never asked of a relative path.
    /// </summary>
    [Fact]
    public void A_path_on_another_drive_is_not_inside()
    {
        if (OperatingSystem.IsWindows())
        {
            Paths.IsInside(@"C:\repo\artifacts\run", @"D:\elsewhere\tests\bin").Should().BeFalse();
            Paths.IsInside(@"C:\repo\artifacts\run", Path.Combine(@"C:\repo\artifacts\run", @"D:\elsewhere\tests\bin")).Should().BeFalse();
        }

        // Everywhere: a rooted path joined to the folder is that rooted path, and is not inside.
        var folder = Path.Combine(Path.GetTempPath(), "gate-paths", "run");
        var elsewhere = Path.Combine(Path.GetTempPath(), "gate-paths", "elsewhere");
        Paths.IsInside(folder, Path.Combine(folder, elsewhere)).Should().BeFalse();
    }

    // Every folder, and every file with a hash of what is in it.
    private static List<string> Snapshot(string root) =>
    [
        .. Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal)
            .Select(entry => Path.GetRelativePath(root, entry).Replace('\\', '/')
                + (Directory.Exists(entry) ? "/" : " " + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(entry))))),
    ];

    private static (int ExitCode, string Output) RunTheGate(string[] arguments, string workingDirectory)
    {
        // The tool is a reference of this project, so it sits beside this assembly; `dotnet` runs it.
        var host = Environment.ProcessPath is { } path && Path.GetFileNameWithoutExtension(path) == "dotnet" ? path : "dotnet";
        var start = new ProcessStartInfo(host)
        {
            WorkingDirectory = workingDirectory, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
        };
        start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "Credentials.BbsGate.dll"));
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        return (process.ExitCode, output.Result + errors.Result);
    }
}
