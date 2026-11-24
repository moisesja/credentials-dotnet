using FluentAssertions;
using Xunit;

namespace Credentials.ArchitectureTests;

/// <summary>
/// Holds every <c>bbs-2023</c> test to the rule of issue #57, which <see cref="BbsTestConvention"/> states
/// and checks on the syntax tree of the test sources: a test in a <c>bbs-2023</c> test file begins with
/// <c>BbsNativeLibrary.RequireOrSkip();</c> under a skippable attribute, or is named below as needing no
/// native library. This assembly must not load <c>Credentials.Rdfc</c>, so it reads sources, as
/// <see cref="FrCoverageGateTests"/> does.
/// </summary>
/// <remarks>
/// The scan is itself under test. <c>BbsTestConventionFixtures/</c> holds small source files, each a way of
/// writing a test that must be reported or a legitimate form that must not be, and each says in its first
/// lines what the scan has to find in it. They have a <c>.cs.txt</c> extension so that they are never
/// compiled and never scanned as tests.
/// </remarks>
public sealed class BbsTestConventionTests
{
    private const string Rdfc = "Credentials.Rdfc.Tests.";
    private const string Self = "Credentials.ArchitectureTests.BbsTestConventionTests.";

    /// <summary>
    /// The tests in <c>bbs-2023</c> test files that need no native library, each with the reason. Every other
    /// test in such a file must begin with the helper call.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> NeedNoNativeLibrary = new Dictionary<string, string>
    {
        [Rdfc + "Bbs2023SelectiveDisclosureTests.Bbs_issuance_is_gated"] =
            "asserts the issuance gate, which refuses before any BBS call",
        [Rdfc + "Bbs2023SelectiveDisclosureTests.UseBbs2023_adds_the_suite_to_capabilities_and_registers_the_deriver"] =
            "registration only",
        [Rdfc + "Bbs2023SelectiveDisclosureTests.UseBbs2023_is_idempotent"] =
            "registration only",
        [Rdfc + "BbsNativeLibraryTests.A_missing_library_skips_only_off_github_actions_on_an_unshipped_platform"] =
            "pins the rule, a pure function",
        [Rdfc + "BbsNativeLibraryTests.The_rule_is_carried_out_on_the_calling_test"] =
            "pins what an outcome does to a test",
        [Rdfc + "BbsNativeLibraryTests.The_inputs_of_the_rule_come_from_this_host"] =
            "pins where the rule's inputs come from",
        [Rdfc + "BbsNativeLibraryTests.Without_the_library_the_call_fails_or_skips_and_never_returns"] =
            "runs the helper where the library is refused; it must not skip",
        [Rdfc + "BbsNativeLibraryTests.A_platform_maps_to_its_runtime_identifier"] =
            "pins the platform mapping, a pure function",
        [Rdfc + "BbsNativeLibraryTests.Netcrypto_declares_the_bbs_native_library_for_exactly_the_documented_platforms"] =
            "reads the .deps.json; it is skippable for a runtime-specific build, not for the library",
        [Rdfc + "RdfcSurfaceConfinementTests.Public_surface_exposes_no_substrate_or_rdf_stack_type"] =
            "reflects over the public surface; it names a bbs-2023 type and calls nothing",
        [Self + nameof(Every_test_in_a_bbs_2023_test_file_begins_with_the_helper_call_or_is_listed)] = "this scan",
        [Self + nameof(A_fixture_is_reported_exactly_as_its_header_says)] = "this scan, over its fixtures",
        [Self + nameof(The_fixtures_hold_both_cases_of_the_review_and_the_legitimate_forms)] = "this scan's fixtures",
        [Self + nameof(The_first_case_of_the_review_is_reported_on_the_real_test_file)] = "this scan, over an altered copy",
        [Self + nameof(Only_the_build_output_of_a_project_is_left_out_of_the_scan)] = "this scan's choice of files",
    };

    private static string FixtureDirectory =>
        Path.Combine(LibrarySurface.RepoRoot, "tests", "Credentials.ArchitectureTests", "BbsTestConventionFixtures");

    [Fact]
    public void Every_test_in_a_bbs_2023_test_file_begins_with_the_helper_call_or_is_listed()
    {
        var result = BbsTestConvention.Scan(TestSources(), [.. NeedNoNativeLibrary.Keys]);

        result.Findings.Should().BeEmpty(
            "every test in a bbs-2023 test file must begin with BbsNativeLibrary.RequireOrSkip(); under "
            + "[SkippableFact] or [SkippableTheory], or be on the list of tests that need no native library:\n"
            + string.Join("\n", result.Findings));

        // The scan has to see each kind of bbs-2023 test there is, or an empty result would mean nothing.
        result.GuardedTests.Should().Contain(
        [
            Rdfc + "Bbs2023SelectiveDisclosureTests.Bbs_derive_then_verify_round_trips", // a fact; the trait is on the class
            Rdfc + "Bbs2023SelectiveDisclosureTests.Bbs_malformed_reveal_pointer_maps_to_credential_format_exception", // a theory
            Rdfc + "BbsNativeLibraryTests.Bbs_native_library_loads_wherever_it_has_to",
            "Credentials.InteropTests.Bbs2023InteropTests.Bbs_derived_proof_pins_the_vc_di_bbs_wire_format_and_verifies",
            "Credentials.SampleSmokeTests.SampleSmokeTests.Bbs2023", // the trait is on the method
        ]);
        result.ListedTests.Should().BeEquivalentTo(NeedNoNativeLibrary.Keys);
    }

    /// <summary>The names of the fixture files.</summary>
    public static IEnumerable<object[]> Fixtures() =>
        Directory.EnumerateFiles(FixtureDirectory, "*.cs.txt").Order(StringComparer.Ordinal)
            .Select(path => new object[] { Path.GetFileName(path) });

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void A_fixture_is_reported_exactly_as_its_header_says(string fixture)
    {
        var (expected, listed, text) = ReadFixture(fixture);

        var result = BbsTestConvention.Scan([new BbsTestConvention.Source(fixture, text)], listed);

        result.Findings.Select(f => $"{f.Rule} {f.Subject}").Should().BeEquivalentTo(
            expected, "that is what the header of {0} expects. The scan reported:\n{1}", fixture, string.Join("\n", result.Findings));
    }

    [Fact]
    public void The_fixtures_hold_both_cases_of_the_review_and_the_legitimate_forms()
    {
        var fixtures = Fixtures().Select(row => (string)row[0]).ToList();

        fixtures.Should().Contain(
        [
            "review-1-call-in-a-block-comment.cs.txt",
            "review-2-trait-before-the-test-attribute-and-an-early-return.cs.txt",
        ]);

        // Both directions are covered: fixtures that must be reported, and fixtures that must not be.
        var expectations = fixtures.Select(f => ReadFixture(f).Expected.Count).ToList();
        expectations.Should().Contain(count => count == 0, "a fixture of legitimate forms must expect nothing");
        expectations.Count(count => count > 0).Should().BeGreaterThanOrEqualTo(30);
    }

    /// <summary>
    /// The first case of the review of PR #72, as the reviewer made it: every helper call in the real
    /// <c>Bbs2023SelectiveDisclosureTests</c> replaced by the same text in a block comment. A scan of text
    /// took that for a call.
    /// </summary>
    [Fact]
    public void The_first_case_of_the_review_is_reported_on_the_real_test_file()
    {
        const string call = "BbsNativeLibrary.RequireOrSkip();";
        var listed = NeedNoNativeLibrary.Keys.ToList();
        var sources = TestSources();
        var target = sources.Single(s => s.Path.EndsWith("Bbs2023SelectiveDisclosureTests.cs", StringComparison.Ordinal));
        var guardedThere = BbsTestConvention.Scan(sources, listed).GuardedTests
            .Where(id => id.StartsWith(Rdfc + "Bbs2023SelectiveDisclosureTests.", StringComparison.Ordinal))
            .ToList();
        guardedThere.Should().HaveCountGreaterThanOrEqualTo(11);

        var altered = target with { Text = target.Text.Replace(call, $"/* {call} */", StringComparison.Ordinal) };
        altered.Text.Should().NotBe(target.Text);
        var result = BbsTestConvention.Scan([.. sources.Where(s => s != target), altered], listed);

        result.Findings.Select(f => $"{f.Rule} {f.Subject}").Should().BeEquivalentTo(
            guardedThere.Select(id => $"{BbsTestConvention.Rules.UnguardedTest} {id}"));
    }

    [Theory]
    [InlineData("Credentials.Rdfc.Tests/obj/Release/net10.0/Generated.cs", true)]
    [InlineData("Credentials.Rdfc.Tests/bin/Release/net10.0/Copied.cs", true)]
    [InlineData("Credentials.Rdfc.Tests/Bbs2023SelectiveDisclosureTests.cs", false)]
    [InlineData("Credentials.Rdfc.Tests/Vectors/obj/Bbs2023VectorTests.cs", false)] // compiled: only the project's own obj is not
    [InlineData("Credentials.Rdfc.Tests/Vectors/bin/Bbs2023VectorTests.cs", false)]
    public void Only_the_build_output_of_a_project_is_left_out_of_the_scan(string pathUnderTests, bool leftOut)
    {
        BbsTestConvention.IsProjectBuildOutput(pathUnderTests).Should().Be(leftOut);
        BbsTestConvention.IsProjectBuildOutput(pathUnderTests.Replace('/', '\\')).Should().Be(leftOut);
    }

    private static List<BbsTestConvention.Source> TestSources()
    {
        var testsRoot = Path.Combine(LibrarySurface.RepoRoot, "tests");
        return Directory.EnumerateFiles(testsRoot, "*.cs", SearchOption.AllDirectories)
            .Where(file => !BbsTestConvention.IsProjectBuildOutput(Path.GetRelativePath(testsRoot, file)))
            .Select(file => new BbsTestConvention.Source(Path.GetRelativePath(LibrarySurface.RepoRoot, file), File.ReadAllText(file)))
            .ToList();
    }

    // A fixture says what the scan must find in it, in comment lines before the code:
    //   // expect: <rule> <subject>     one line for each finding
    //   // expect: nothing             for a fixture of legitimate forms
    //   // listed: <full test name>    a test the fixture's caller lists as needing no native library
    private static (List<string> Expected, List<string> Listed, string Text) ReadFixture(string fixture)
    {
        var text = File.ReadAllText(Path.Combine(FixtureDirectory, fixture));
        var header = text.Split('\n').Select(line => line.Trim()).TakeWhile(line => line.StartsWith("//", StringComparison.Ordinal)).ToList();

        var expectations = header.Where(line => line.StartsWith("// expect:", StringComparison.Ordinal))
            .Select(line => line["// expect:".Length..].Trim()).ToList();
        expectations.Should().NotBeEmpty("{0} must say what it expects", fixture);
        if (expectations.Contains("nothing"))
        {
            expectations.Should().Equal(["nothing"], "{0} expects nothing, or it lists its findings", fixture);
            expectations.Clear();
        }

        var listed = header.Where(line => line.StartsWith("// listed:", StringComparison.Ordinal))
            .Select(line => line["// listed:".Length..].Trim()).ToList();
        return (expectations, listed, text);
    }
}
