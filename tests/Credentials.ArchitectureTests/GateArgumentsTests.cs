using System.Diagnostics;
using System.Security.Cryptography;
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
    /// <summary>The names of the wrong calls; <see cref="Arguments"/> has the arguments of each.</summary>
    public static IEnumerable<object[]> WrongCalls() =>
    [
        ["the case of the review: --work outside the repository, and no --solution"],
        ["--work outside the repository"],
        ["--work is the repository itself"],
        ["--work is a folder above the repository"],
        ["--work under tests"],
        ["--work is a file"],
        ["--work by a path that leaves the repository"],
        ["--work that holds files, and no --solution"],
        ["an option without a value"],
        ["an option the program does not have"],
        ["an option given twice"],
        ["no --repo"],
        ["--repo without a tests folder"],
        ["--solution that is not there"],
        ["--list that is not there"],
        ["--expect that is not there"],
        ["--with-library-results without result files"],
    ];

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

            // A repository in small: a solution with one test project, a list, and results of a normal run.
            var assembly = At("repo", "tests", "Some.Tests", "bin", "Release", "net10.0", "Some.Tests.dll");
            Write("Project(\"{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}\") = \"Some.Tests\", \"tests\\Some.Tests\\Some.Tests.csproj\", \"{0}\"\n", "repo", "Some.sln");
            Write("<Project />", "repo", "tests", "Some.Tests", "Some.Tests.csproj");
            Write("// a test source file\n", "repo", "tests", "Some.Tests", "SomeTests.cs");
            Write(string.Empty, "repo", "tests", "Some.Tests", "bin", "Release", "net10.0", "Some.Tests.dll");
            Write("# no test needs listing\n", "repo", "list.txt");
            Write($"""
                <TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
                  <Results><UnitTestResult testId="1" testName="Some.Tests.SomeTests.Adds" outcome="Passed" /></Results>
                  <TestDefinitions>
                    <UnitTest name="Some.Tests.SomeTests.Adds" id="1"><TestMethod codeBase="{assembly}" className="Some.Tests.SomeTests" name="Adds" /></UnitTest>
                  </TestDefinitions>
                </TestRun>
                """, "results", "normal.trx");

            // What must still be there afterwards, untouched: a folder outside the repository, a work
            // folder inside it, and the folder the gate works in when it is given none.
            Write("not the gate's", "outside", "keep-me.txt");
            Write("not the gate's", "repo", "artifacts", "work", "keep-me.txt");
            Write("not the gate's", "repo", "artifacts", "bbs-gate", "keep-me.txt");

            string[] valid = ["--repo", At("repo"), "--solution", At("repo", "Some.sln"), "--with-library-results", At("results"), "--list", At("repo", "list.txt")];
            string[] arguments = Arguments(call, valid, At);
            var before = Snapshot(sandbox);

            var (exitCode, output) = RunTheGate(arguments, sandbox);

            Snapshot(sandbox).Should().Equal(before, "a wrong call must not create, change or delete anything. The gate said:\n{0}", output);
            exitCode.Should().Be(2, "a call the gate cannot carry out ends with 2. The gate said:\n{0}", output);
        }
        finally
        {
            Directory.Delete(sandbox, recursive: true);
        }
    }

    private static string[] Arguments(string call, string[] valid, Func<string[], string> at) => call switch
    {
        "the case of the review: --work outside the repository, and no --solution" =>
            ["--repo", at(["repo"]), "--with-library-results", at(["results"]), "--work", at(["outside"])],
        "--work outside the repository" => [.. valid, "--work", at(["outside"])],
        "--work is the repository itself" => [.. valid, "--work", at(["repo"])],
        "--work is a folder above the repository" => [.. valid, "--work", at([])],
        "--work under tests" => [.. valid, "--work", at(["repo", "tests", "work"])],
        "--work is a file" => [.. valid, "--work", at(["repo", "list.txt"])],
        "--work by a path that leaves the repository" => [.. valid, "--work", Path.Combine(at(["repo", "artifacts"]), "..", "..", "outside")],
        "--work that holds files, and no --solution" =>
            ["--repo", at(["repo"]), "--with-library-results", at(["results"]), "--list", at(["repo", "list.txt"]), "--work", at(["repo", "artifacts", "work"])],
        "an option without a value" => [.. valid, "--work"],
        "an option the program does not have" => [.. valid, "--wrok", at(["repo", "artifacts", "work"])],
        "an option given twice" => [.. valid, "--work", at(["repo", "artifacts", "work"]), "--work", at(["outside"])],
        "no --repo" => valid[2..],
        "--repo without a tests folder" => ["--repo", at(["outside"]), .. valid[2..]],
        "--solution that is not there" => ["--repo", at(["repo"]), "--solution", at(["repo", "No.sln"]), .. valid[4..]],
        "--list that is not there" => [.. valid[..6], "--list", at(["repo", "no-list.txt"])],
        "--expect that is not there" => [.. valid, "--expect", at(["repo", "no-expectations.txt"])],
        "--with-library-results without result files" => [.. valid[..4], "--with-library-results", at(["outside"]), .. valid[6..]],
        _ => throw new ArgumentOutOfRangeException(nameof(call), call, "no such call"),
    };

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
