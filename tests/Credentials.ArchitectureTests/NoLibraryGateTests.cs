using System.Xml.Linq;
using Credentials.BbsGate;
using FluentAssertions;
using Xunit;

namespace Credentials.ArchitectureTests;

/// <summary>
/// Tests of the comparison at the heart of the gate for <c>bbs-2023</c> tests (issue #57): two runs of the
/// same tests, with and without NetCrypto's native BBS library, on results made up here. The gate itself
/// runs on every CI leg, and its self-test runs real tests that are wrong in each of these ways
/// (<c>tests/Credentials.GateFixtures</c>).
/// </summary>
public sealed class NoLibraryGateTests
{
    private const string Check = "Some.Tests.Bbs2023Tests.The_library_loads";
    private const string Passed = TestResult.Passed;
    private const string Failed = TestResult.Failed;
    private const string Skipped = "NotExecuted";
    private const string ByTheHelper = "System.InvalidOperationException : NetCrypto ships the BBS native library (zkryptium_ffi) for osx-arm64, but it did not load in this process";
    private static readonly string[] BbsClasses = ["Some.Tests.Bbs2023Tests", "Some.Tests.Bbs2023Tests+Nested"];

    // One line for each case: the outcomes of a test with the library, its outcomes without, whether it is
    // on the list, and the finding the gate has to make of it (none when that is null). A failure here is
    // the helper's.
    [Theory]
    [InlineData("Some.Tests.Bbs2023Tests.Derives", "Passed", "Failed", false, null)] // guarded: in order
    [InlineData("Some.Tests.Bbs2023Tests.Derives", "Passed", "Passed", false, NoLibraryGate.Rules.Passed)] // the reviewer's cases 1 and 2
    [InlineData("Some.Tests.Bbs2023Tests.Derives", "Passed", "NotExecuted", false, NoLibraryGate.Rules.Skipped)] // a skip before the call
    [InlineData("Some.Tests.Bbs2023Tests.Derives", "Passed", "", false, NoLibraryGate.Rules.NoResult)] // a test that is gone
    [InlineData("Some.Tests.Bbs2023Tests.Derives", "Passed,Passed,Passed", "", false, NoLibraryGate.Rules.NoResult)] // a theory whose rows come up empty
    [InlineData("Some.Tests.Bbs2023Tests.Derives", "Passed,Passed,Passed", "Failed", false, null)] // rows may differ between the runs
    [InlineData("Some.Tests.Bbs2023Tests.Derives", "Passed,Passed", "Failed,Passed", false, NoLibraryGate.Rules.Passed)] // one row is not guarded
    [InlineData("Some.Tests.Bbs2023Tests.Derives", "Passed,Passed", "Failed,NotExecuted", false, NoLibraryGate.Rules.Skipped)]
    [InlineData("Some.Tests.Bbs2023Tests.Derives", "NotExecuted", "NotExecuted", false, NoLibraryGate.Rules.Skipped)] // switched off: it never runs
    [InlineData("Some.Tests.Bbs2023Tests.Derives", "", "Passed", false, NoLibraryGate.Rules.Passed)] // it ran only without the library
    [InlineData("Some.Tests.Bbs2023Tests.Registers", "Passed", "Passed", true, null)] // listed: in order
    [InlineData("Some.Tests.Bbs2023Tests.Registers", "Passed", "Failed", true, NoLibraryGate.Rules.ListedDidNotPass)]
    [InlineData("Some.Tests.Bbs2023Tests.Registers", "Passed", "NotExecuted", true, NoLibraryGate.Rules.ListedDidNotPass)]
    [InlineData("Some.Tests.Bbs2023Tests.Registers", "Passed", "", true, NoLibraryGate.Rules.ListedDidNotPass)]
    [InlineData("Some.Tests.Bbs2023Tests+Nested.Derives", "Passed", "Passed", false, NoLibraryGate.Rules.Passed)] // a nested class is a class of its own
    [InlineData("Some.Tests.OrdinaryTests.Adds", "Passed", "Passed", false, null)] // another class: unchanged
    [InlineData("Some.Tests.OrdinaryTests.Adds", "NotExecuted", "NotExecuted", false, null)]
    [InlineData("Some.Tests.OrdinaryTests.Adds", "Passed", "Failed", false, NoLibraryGate.Rules.ChangedOutsideScope)] // it needs the library after all
    [InlineData("Some.Tests.OrdinaryTests.Adds", "Passed", "NotExecuted", false, NoLibraryGate.Rules.ChangedOutsideScope)]
    [InlineData("Some.Tests.OrdinaryTests.Adds", "Passed", "", false, NoLibraryGate.Rules.ChangedOutsideScope)]
    public void A_test_is_judged_by_what_it_does_without_the_library(string test, string with, string without, bool listed, string? finding)
    {
        var findings = NoLibraryGate.Compare(
            [R(Check, Passed), .. Results(test, with)], [R(Check, Failed), .. Results(test, without)], [], BbsClasses, listed ? [test] : [], Check);

        findings.Select(f => f.Key).Should().Equal(finding is null ? [] : [$"{finding} {test}"]);
    }

    /// <summary>
    /// A test of a <c>bbs-2023</c> class that fails without the library has to fail by the helper's check.
    /// Any other failure may come from where the second run sits, a file the copy does not have for one,
    /// and such a test can pass on a real host without the library.
    /// </summary>
    [Theory]
    [InlineData("System.IO.DirectoryNotFoundException : Could not find a part of the path '/repo/artifacts/Vectors/pointer.txt'.")]
    [InlineData("Assert.True() Failure\nExpected: True\nActual:   False")]
    [InlineData("NetCrypto.BbsUnavailableException : BBS native library (zkryptium_ffi) not found for this platform.")] // the library's own exception, not the helper's
    [InlineData("")]
    public void A_failure_has_to_be_the_helpers(string message)
    {
        const string test = "Some.Tests.Bbs2023Tests.Derives";
        TestResult[] with = [R(Check, Passed), R(test, Passed, "(row: 1)"), R(test, Passed, "(row: 2)")];
        TestResult[] without = [R(Check, Failed), R(test, Failed, "(row: 1)"), R(test, Failed, "(row: 2)") with { Message = message }];

        var findings = NoLibraryGate.Compare(with, without, [], BbsClasses, [], Check);

        findings.Select(f => f.Key).Should().Equal($"{NoLibraryGate.Rules.FailedOtherwise} {test}");
    }

    /// <summary>
    /// A test outside the <c>bbs-2023</c> classes is compared row for row. Two rows that trade places, one
    /// for a host with the library and one for a host without, give the same outcomes in another order.
    /// </summary>
    [Fact]
    public void Any_other_test_does_the_same_in_both_runs_row_for_row()
    {
        const string test = "Some.Tests.HostTests.Does_what_the_host_can";
        TestResult[] with = [R(Check, Passed), R(test, Passed, "(nativeProofs: True)"), R(test, Skipped, "(nativeProofs: False)")];
        TestResult[] same = [R(Check, Failed), R(test, Skipped, "(nativeProofs: False)"), R(test, Passed, "(nativeProofs: True)")];
        TestResult[] traded = [R(Check, Failed), R(test, Skipped, "(nativeProofs: True)"), R(test, Passed, "(nativeProofs: False)")];

        NoLibraryGate.Compare(with, same, [], BbsClasses, [], Check).Should().BeEmpty();
        NoLibraryGate.Compare(with, traded, [], BbsClasses, [], Check).Select(f => f.Key)
            .Should().Equal($"{NoLibraryGate.Rules.ChangedOutsideScope} {test}");
    }

    /// <summary>
    /// A test belongs to a <c>bbs-2023</c> class when the class's own name is a part of its name before the
    /// method. The class a result file gives is not relied on: for a test with a display name of its own
    /// it can be cut short, or be the name of the assembly.
    /// </summary>
    [Theory]
    [InlineData("Some.Tests.Bbs2023Tests.Derives", true)]
    [InlineData("Some.Tests.Bbs2023Tests+Nested.Derives", true)]
    [InlineData("Some.Bbs2023Tests.Derives", true)] // the class a result file gives can lack a part of the namespace,
    [InlineData("Bbs2023Tests.Derives", true)] // or all of it,
    [InlineData("Some.Tests.dll.Bbs2023Tests.Derives", true)] // or be something else: the class's own name decides
    [InlineData("Some.Tests.Bbs2023Tests+Other.Derives", false)] // a nested class the scan did not list
    [InlineData("Some.Tests.Bbs2023TestsOfAnotherKind.Derives", false)] // another class whose name begins the same
    [InlineData("Some.Tests.OrdinaryTests.Bbs2023Tests", false)] // a method named like the class
    [InlineData("Some.Tests.Derives", false)]
    public void A_test_of_a_bbs_2023_class_is_known_by_its_full_name(string test, bool inScope)
    {
        var findings = NoLibraryGate.Compare([R(Check, Passed), R(test, Passed)], [R(Check, Failed), R(test, Passed)], [], BbsClasses, [], Check);

        findings.Select(f => f.Key).Should().Equal(inScope ? [$"{NoLibraryGate.Rules.Passed} {test}"] : []);
    }

    /// <summary>
    /// Rows that are named by a value made at run time, a new identifier or the time, are not the same rows
    /// in two runs. Such a test is compared outcome for outcome.
    /// </summary>
    [Fact]
    public void Rows_made_at_run_time_are_compared_by_their_outcomes()
    {
        const string test = "Some.Tests.OrdinaryTests.A_fresh_id_round_trips";
        TestResult[] with = [R(Check, Passed), R(test, Passed, "(id: 1b4e)"), R(test, Passed, "(id: 9c1f)")];
        TestResult[] without = [R(Check, Failed), R(test, Passed, "(id: 77aa)"), R(test, Passed, "(id: 03d2)")];
        TestResult[] oneFails = [R(Check, Failed), R(test, Passed, "(id: 77aa)"), R(test, Failed, "(id: 03d2)")];

        NoLibraryGate.Compare(with, without, [], BbsClasses, [], Check).Should().BeEmpty();
        NoLibraryGate.Compare(with, oneFails, [], BbsClasses, [], Check).Select(f => f.Key)
            .Should().Equal($"{NoLibraryGate.Rules.ChangedOutsideScope} {test}");
    }

    /// <summary>An entry of the list names one test. A test whose name only begins like it is not covered.</summary>
    [Fact]
    public void An_entry_of_the_list_covers_the_one_test_it_names()
    {
        TestResult[] with = [R(Check, Passed), R("Some.Tests.Bbs2023Tests.Registers", Passed), R("Some.Tests.Bbs2023Tests.Registers_and_derives", Passed)];
        TestResult[] without = [R(Check, Failed), R("Some.Tests.Bbs2023Tests.Registers", Passed), R("Some.Tests.Bbs2023Tests.Registers_and_derives", Passed)];

        var findings = NoLibraryGate.Compare(with, without, [], BbsClasses, ["Some.Tests.Bbs2023Tests.Registers"], Check);

        findings.Select(f => f.Key).Should().Equal($"{NoLibraryGate.Rules.Passed} Some.Tests.Bbs2023Tests.Registers_and_derives");
    }

    /// <summary>
    /// A test source file that the scan could not read one way may declare a <c>bbs-2023</c> class the scan
    /// did not list. It fails the gate, whatever the tests did.
    /// </summary>
    [Fact]
    public void A_file_without_a_single_reading_fails_the_gate()
    {
        var unreadable = new BbsScope.Finding(BbsScope.Rules.ConditionalCompilation, "tests/Some.Tests/Bbs2023Tests.cs", "'#if NET10_0'");

        var findings = NoLibraryGate.Compare([R(Check, Passed)], [R(Check, Failed)], [unreadable], BbsClasses, [], Check);

        findings.Select(f => f.Key).Should().Equal($"{BbsScope.Rules.ConditionalCompilation} tests/Some.Tests/Bbs2023Tests.cs");
    }

    /// <summary>Results, scope and list go by the name of a test, so a name has to mean one test.</summary>
    [Fact]
    public void A_test_name_in_two_assemblies_is_reported()
    {
        const string test = "Some.Tests.Bbs2023Tests.Registers";
        TestResult[] with = [R(Check, Passed), R(test, Passed), R(test, Passed) with { Assembly = "Other.Tests.dll" }];
        TestResult[] without = [R(Check, Failed), R(test, Passed), R(test, Passed) with { Assembly = "Other.Tests.dll" }];

        var findings = NoLibraryGate.Compare(with, without, [], BbsClasses, [test], Check);

        findings.Select(f => f.Key).Should().Equal($"{NoLibraryGate.Rules.SameNameInTwoAssemblies} {test}");
    }

    [Theory]
    [InlineData("Some.Tests.Bbs2023Tests.Gone")] // no such test ran
    [InlineData("Some.Tests.OrdinaryTests.Adds")] // its class is not a bbs-2023 class
    [InlineData("Some.Tests.Bbs2023Tests.*")] // an entry names one test, not a class
    public void An_entry_of_the_list_that_names_nothing_in_scope_is_reported(string entry)
    {
        TestResult[] with = [R(Check, Passed), R("Some.Tests.OrdinaryTests.Adds", Passed)];
        TestResult[] without = [R(Check, Failed), R("Some.Tests.OrdinaryTests.Adds", Passed)];

        var findings = NoLibraryGate.Compare(with, without, [], BbsClasses, [entry], Check);

        findings.Select(f => f.Key).Should().Equal($"{NoLibraryGate.Rules.StaleListing} {entry}");
    }

    // The second run has to be a run without the library, or every guarded test would "fail to fail" for
    // another reason, or pass for none.
    [Theory]
    [InlineData("Passed", "Passed")] // the library was not hidden
    [InlineData("Passed", "NotExecuted")]
    [InlineData("Passed", "")] // the check did not run in the second run
    [InlineData("", "Failed")] // or in the first
    [InlineData("Failed", "Failed")] // the library was missing all along
    public void The_run_without_the_library_has_to_be_one(string with, string without)
    {
        var findings = NoLibraryGate.Compare(Results(Check, with), Results(Check, without), [], BbsClasses, [], Check);

        findings.Select(f => f.Rule).Should().Contain(NoLibraryGate.Rules.NotANoLibraryRun);
    }

    [Fact]
    public void The_list_is_read_as_tests_and_reasons()
    {
        NoLibraryGate.ReadList(["# a comment", "", "Some.Tests.Bbs2023Tests.Registers | registration only", "  Some.Tests.Bbs2023Tests.Maps|a | b  "])
            .Should().Equal("Some.Tests.Bbs2023Tests.Registers", "Some.Tests.Bbs2023Tests.Maps");

        foreach (var line in (string[])["Some.Tests.Bbs2023Tests.Registers", "Some.Tests.Bbs2023Tests.Registers |", "| a reason"])
        {
            var read = () => NoLibraryGate.ReadList([line]);
            read.Should().Throw<FormatException>("an entry without a test or without a reason is not an entry: {0}", line);
        }
    }

    /// <summary>
    /// A result file names a test by its class and its method, and a row of a theory by its arguments too.
    /// For a test with a display name that is the end of its full name, the file cuts the class short and
    /// leaves the rest in the method; the two together are the full name again.
    /// </summary>
    [Fact]
    public void A_result_file_is_read_by_test_and_row()
    {
        var trx = XDocument.Parse("""
            <TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
              <Results>
                <UnitTestResult testId="1" testName="Some.Tests.Bbs2023Tests.Derives" outcome="Passed" />
                <UnitTestResult testId="2" testName="Some.Tests.Bbs2023Tests.Reveals(pointer: &quot;/a(b)&quot;)" outcome="Failed">
                  <Output><ErrorInfo><Message>System.InvalidOperationException : it did not load</Message><StackTrace>at X</StackTrace></ErrorInfo></Output>
                </UnitTestResult>
                <UnitTestResult testId="3" testName="Some.Tests.Bbs2023Tests.Reveals(pointer: &quot;/c&quot;)" outcome="NotExecuted" />
                <UnitTestResult testId="4" testName="Bbs2023Tests.Named" outcome="Passed" />
              </Results>
              <TestDefinitions>
                <UnitTest name="Some.Tests.Bbs2023Tests.Derives" storage="/repo/tests/some.tests/bin/some.tests.dll" id="1">
                  <TestMethod codeBase="/repo/tests/Some.Tests/bin/Some.Tests.dll" className="Some.Tests.Bbs2023Tests" name="Derives" />
                </UnitTest>
                <UnitTest name="Some.Tests.Bbs2023Tests.Reveals(pointer: &quot;/a(b)&quot;)" storage="/repo/tests/some.tests/bin/some.tests.dll" id="2">
                  <TestMethod codeBase="/repo/tests/Some.Tests/bin/Some.Tests.dll" className="Some.Tests.Bbs2023Tests" name="Some.Tests.Bbs2023Tests.Reveals(pointer: &quot;/a(b)&quot;)" />
                </UnitTest>
                <UnitTest name="Some.Tests.Bbs2023Tests.Reveals(pointer: &quot;/c&quot;)" storage="/repo/tests/some.tests/bin/some.tests.dll" id="3">
                  <TestMethod codeBase="/repo/tests/Some.Tests/bin/Some.Tests.dll" className="Some.Tests.Bbs2023Tests" name="Reveals(pointer: &quot;/c&quot;)" />
                </UnitTest>
                <UnitTest name="Bbs2023Tests.Named" storage="/repo/tests/some.tests/bin/some.tests.dll" id="4">
                  <TestMethod codeBase="/repo/tests/Some.Tests/bin/Some.Tests.dll" className="Some.Tests" name="Bbs2023Tests.Named" />
                </UnitTest>
              </TestDefinitions>
            </TestRun>
            """);

        var run = TestRun.Parse(trx);

        run.Assemblies.Should().Equal("/repo/tests/Some.Tests/bin/Some.Tests.dll");
        run.Results.Should().Equal(
            new TestResult("Some.Tests.dll", "Some.Tests.Bbs2023Tests.Derives", "Some.Tests.Bbs2023Tests.Derives", Passed, string.Empty),
            new TestResult("Some.Tests.dll", "Some.Tests.Bbs2023Tests.Reveals", "Some.Tests.Bbs2023Tests.Reveals(pointer: \"/a(b)\")", Failed, "System.InvalidOperationException : it did not load"),
            new TestResult("Some.Tests.dll", "Some.Tests.Bbs2023Tests.Reveals", "Some.Tests.Bbs2023Tests.Reveals(pointer: \"/c\")", Skipped, string.Empty),
            new TestResult("Some.Tests.dll", "Some.Tests.Bbs2023Tests.Named", "Bbs2023Tests.Named", Passed, string.Empty));
    }

    /// <summary>
    /// The gate takes the test assemblies from the result files it is given. If the file of one went
    /// missing, its tests would be in neither run and nothing would say so; so every test project of the
    /// solution that is built has to be among them.
    /// </summary>
    [Fact]
    public void A_test_project_of_the_solution_without_results_is_found()
    {
        var root = Directory.CreateTempSubdirectory("bbs-gate-");
        try
        {
            string Output(string project, params string[] files)
            {
                var output = Path.Combine(root.FullName, "tests", project, "bin", "Release", "net10.0");
                Directory.CreateDirectory(output);
                foreach (var file in files)
                {
                    File.WriteAllText(Path.Combine(output, file), string.Empty);
                }

                return Path.Combine(output, project + ".dll");
            }

            var withResults = Output("Some.Tests", "Some.Tests.dll", "testhost.dll");
            var withoutResults = Output("Other.Tests", "Other.Tests.dll", "testhost.dll");
            Output("Some.Tool", "Some.Tool.dll"); // not a test project: no test host
            Output("Unbuilt.Tests"); // not built
            var solution = Path.Combine(root.FullName, "Some.sln");
            File.WriteAllLines(solution, ((string[])["Some.Tests", "Other.Tests", "Some.Tool", "Unbuilt.Tests"]).Select(project =>
                $"Project(\"{{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}}\") = \"{project}\", \"tests\\{project}\\{project}.csproj\", \"{{{Guid.NewGuid()}}}\""));

            TestRun.TestAssembliesWithoutResults(solution, [withResults]).Should().Equal(withoutResults);
            TestRun.TestAssembliesWithoutResults(solution, [withResults, withoutResults]).Should().BeEmpty();
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    private static TestResult R(string test, string outcome, string row = "") =>
        new("Some.Tests.dll", test, test + row, outcome, outcome == Failed ? ByTheHelper : string.Empty);

    private static TestResult[] Results(string test, string outcomes) =>
        [.. outcomes.Split(',', StringSplitOptions.RemoveEmptyEntries).Select((outcome, row) => R(test, outcome, $"(row: {row})"))];
}
