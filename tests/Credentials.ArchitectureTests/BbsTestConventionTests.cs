using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using FluentAssertions;
using Microsoft.CodeAnalysis.CSharp;
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
        [Self + nameof(The_fixtures_hold_the_cases_of_the_review_and_the_legitimate_forms)] = "this scan's fixtures",
        [Self + nameof(The_first_case_of_the_review_is_reported_on_the_real_test_file)] = "this scan, over an altered copy",
        [Self + nameof(The_third_case_of_the_review_is_reported_on_the_real_test_file)] = "this scan, over an altered copy",
        [Self + nameof(The_third_case_of_the_review_is_reported_whatever_the_condition)] = "this scan, over an altered fixture",
        [Self + nameof(Every_source_file_but_the_build_output_of_a_project_is_scanned)] = "this scan's choice of files",
        [Self + nameof(The_scan_reads_the_files_a_project_compiles_by_default)] = "this scan's choice of files, on disk",
        [Self + nameof(The_scan_parses_at_the_language_version_of_the_build)] = "this scan's parse options",
        [Self + nameof(The_attribute_the_test_sources_declare_is_accepted_only_as_a_plain_attribute)] = "this scan's one exemption",
    };

    private static string FixtureDirectory =>
        Path.Combine(LibrarySurface.RepoRoot, "tests", "Credentials.ArchitectureTests", "BbsTestConventionFixtures");

    [Fact]
    public void Every_test_in_a_bbs_2023_test_file_begins_with_the_helper_call_or_is_listed()
    {
        var result = BbsTestConvention.Scan(BbsTestConvention.ReadSources(LibrarySurface.RepoRoot), [.. NeedNoNativeLibrary.Keys]);

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
            "Credentials.SampleSmokeTests.Bbs2023SampleSmokeTests.Bbs2023", // the trait is on the method
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
    public void The_fixtures_hold_the_cases_of_the_review_and_the_legitimate_forms()
    {
        var fixtures = Fixtures().Select(row => (string)row[0]).ToList();

        fixtures.Should().Contain(
        [
            "review-1-call-in-a-block-comment.cs.txt",
            "review-2-trait-before-the-test-attribute-and-an-early-return.cs.txt",
            ThirdCaseOfTheReview,
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
        var sources = BbsTestConvention.ReadSources(LibrarySurface.RepoRoot);
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

    private const string ThirdCaseOfTheReview = "review-3-whole-file-under-a-condition.cs.txt";

    /// <summary>
    /// The third case of the review of PR #72 on the real <c>Bbs2023SelectiveDisclosureTests</c>: the whole
    /// file under a symbol the build defines. The scan defines no symbols, so it read an empty file, took it
    /// for one that has nothing to do with <c>bbs-2023</c> and reported nothing.
    /// </summary>
    [Fact]
    public void The_third_case_of_the_review_is_reported_on_the_real_test_file()
    {
        var listed = NeedNoNativeLibrary.Keys.ToList();
        var sources = BbsTestConvention.ReadSources(LibrarySurface.RepoRoot);
        var target = sources.Single(s => s.Path.EndsWith("Bbs2023SelectiveDisclosureTests.cs", StringComparison.Ordinal));
        var listedThere = listed.Where(id => id.StartsWith(Rdfc + "Bbs2023SelectiveDisclosureTests.", StringComparison.Ordinal)).ToList();
        listedThere.Should().NotBeEmpty();

        var altered = target with { Text = $"#if NET10_0\n{target.Text}\n#endif\n" };
        var result = BbsTestConvention.Scan([.. sources.Where(s => s != target), altered], listed);

        // The condition is reported on the file. Its tests are in text the scan does not read, so the
        // ones on the list are reported as not found, too.
        result.Findings.Select(f => $"{f.Rule} {f.Subject} in {f.File}").Should().BeEquivalentTo(
        [
            $"{BbsTestConvention.Rules.ConditionalCompilation} (file) in {target.Path}",
            .. listedThere.Select(id => $"{BbsTestConvention.Rules.StaleListing} {id} in (list)"),
        ]);
    }

    /// <summary>
    /// The same case under other conditions. The scan does not work out which of them a build meets: the
    /// build's symbols come from the SDK, the project files and the command line.
    /// </summary>
    [Theory]
    [InlineData("NET")]
    [InlineData("NET10_0_OR_GREATER")]
    [InlineData("NETCOREAPP")]
    [InlineData("DEBUG")]
    [InlineData("RELEASE")]
    [InlineData("TRACE")]
    [InlineData("!NETFRAMEWORK")]
    [InlineData("NET && !NETFRAMEWORK")]
    [InlineData("(DEBUG || RELEASE)")]
    [InlineData("true")]
    [InlineData("false")]
    public void The_third_case_of_the_review_is_reported_whatever_the_condition(string condition)
    {
        var (_, listed, text) = ReadFixture(ThirdCaseOfTheReview);
        var altered = text.Replace("#if NET10_0", "#if " + condition, StringComparison.Ordinal);
        altered.Should().NotBe(text);

        var result = BbsTestConvention.Scan([new BbsTestConvention.Source(ThirdCaseOfTheReview, altered)], listed);

        result.Findings.Select(f => $"{f.Rule} {f.Subject}").Should().Contain($"{BbsTestConvention.Rules.ConditionalCompilation} (file)");
    }

    [Theory]
    [InlineData("Credentials.Rdfc.Tests/Bbs2023SelectiveDisclosureTests.cs", true)]
    [InlineData("Credentials.Rdfc.Tests/Bbs2023SelectiveDisclosureTests.CS", true)] // the build matches the extension in any case
    [InlineData("Credentials.Rdfc.Tests/Bbs2023SelectiveDisclosureTests.Cs", true)]
    [InlineData("Credentials.Rdfc.Tests/.Bbs2023SelectiveDisclosureTests.cs", true)] // a hidden file is compiled
    [InlineData("Credentials.Rdfc.Tests/Vectors/obj/Bbs2023VectorTests.cs", true)] // compiled: only the project's own obj is not
    [InlineData("Credentials.Rdfc.Tests/Vectors/bin/Bbs2023VectorTests.cs", true)]
    [InlineData("Credentials.Rdfc.Tests/Bin/Bbs2023VectorTests.cs", true)] // on Linux a folder of its own, and compiled
    [InlineData("Credentials.Rdfc.Tests/.hidden/Bbs2023VectorTests.cs", true)] // not compiled, and scanned all the same
    [InlineData("Credentials.Rdfc.Tests/obj/Release/net10.0/Generated.cs", false)]
    [InlineData("Credentials.Rdfc.Tests/bin/Release/net10.0/Copied.cs", false)]
    [InlineData("Credentials.Rdfc.Tests/Bbs2023SelectiveDisclosureTests.cs.txt", false)]
    [InlineData("Credentials.Rdfc.Tests/Credentials.Rdfc.Tests.csproj", false)]
    [InlineData("Credentials.Rdfc.Tests/Vectors/bbs.cs/vector.json", false)]
    public void Every_source_file_but_the_build_output_of_a_project_is_scanned(string pathUnderTests, bool scanned)
    {
        BbsTestConvention.IsTestSource(pathUnderTests).Should().Be(scanned);
        BbsTestConvention.IsTestSource(pathUnderTests.Replace('/', '\\')).Should().Be(scanned);
    }

    /// <summary>
    /// The files are found on disk as the build finds them, on the platform this runs on: a pattern for
    /// the extension is matched by letter case on Linux, where the build matches it without. A file with
    /// bytes that are not UTF-8 is read, and reported.
    /// </summary>
    [Fact]
    public void The_scan_reads_the_files_a_project_compiles_by_default()
    {
        var root = Directory.CreateTempSubdirectory("bbs-test-convention-");
        try
        {
            void Write(string path, params byte[] bytes)
            {
                var file = Path.Combine(root.FullName, "tests", "Some.Tests", path);
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                File.WriteAllBytes(file, [.. "// a source file\n"u8, .. bytes]);
            }

            Write("Lower.cs");
            Write("Upper.CS");
            Write("Mixed.Cs");
            Write(".Hidden.cs");
            Write("Vectors/bin/Nested.cs");
            Write("NotUtf8.cs", [.. "// caf"u8, 0xE9, (byte)'\n']);
            Write("bin/Release/net10.0/Copied.cs");
            Write("obj/Release/net10.0/Generated.cs");
            Write("Notes.cs.txt");
            Write("Some.Tests.csproj");

            var sources = BbsTestConvention.ReadSources(root.FullName);

            sources.Select(s => s.Path.Replace('\\', '/')).Should().BeEquivalentTo(
            [
                "tests/Some.Tests/Lower.cs", "tests/Some.Tests/Upper.CS", "tests/Some.Tests/Mixed.Cs",
                "tests/Some.Tests/.Hidden.cs", "tests/Some.Tests/Vectors/bin/Nested.cs", "tests/Some.Tests/NotUtf8.cs",
            ]);
            BbsTestConvention.Scan(sources, []).Findings.Select(f => $"{f.Rule} {f.Subject} in {f.File.Replace('\\', '/')}")
                .Should().Equal($"{BbsTestConvention.Rules.NotUtf8} (file) in tests/Some.Tests/NotUtf8.cs");
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    /// <summary>
    /// The scan knows <c>[FrTag]</c>, which the test sources declare themselves, so the declaration is the
    /// one type that may be named like an attribute the scan knows. Only as what it is: in its own file,
    /// with <c>Attribute</c> as its one base. With <c>FactAttribute</c> as its base, every method under
    /// <c>[FrTag]</c> would be a test the scan does not see.
    /// </summary>
    [Theory]
    [InlineData("tests/Some.Tests/FrTagAttribute.cs", "public sealed class FrTagAttribute : Attribute { }", null)]
    [InlineData("tests/Some.Tests/FrTagAttribute.cs", "public sealed class FrTagAttribute : Xunit.FactAttribute { }", "name-shadowed FrTagAttribute")]
    [InlineData("tests/Some.Tests/FrTagAttribute.cs", "public sealed class FrTagAttribute : Attribute, Xunit.Sdk.ITraitAttribute { }", "name-shadowed FrTagAttribute")]
    [InlineData("tests/Some.Tests/FrTagAttribute.cs", "public sealed class FrTagAttribute { }", "name-shadowed FrTagAttribute")]
    [InlineData("tests/Some.Tests/Tags.cs", "public sealed class FrTagAttribute : Attribute { }", "name-shadowed FrTagAttribute")]
    [InlineData("tests/Some.Tests/FrTagAttribute.cs", "public sealed class FrTagAttribute : Attribute { } public class Attribute { }", "name-shadowed Attribute")]
    public void The_attribute_the_test_sources_declare_is_accepted_only_as_a_plain_attribute(string path, string declaration, string? finding)
    {
        var result = BbsTestConvention.Scan([new BbsTestConvention.Source(path, "namespace Some.Tests;\n" + declaration)], []);

        result.Findings.Select(f => $"{f.Rule} {f.Subject}").Should().Equal(finding is null ? [] : [finding]);
    }

    /// <summary>
    /// The scan parses at one language version, and it has to be the one the build compiles at. The
    /// compiler records the version it used in the symbols of every assembly it builds, this one included.
    /// </summary>
    [Fact]
    public void The_scan_parses_at_the_language_version_of_the_build()
    {
        var assembly = typeof(BbsTestConventionTests).Assembly.Location;
        using var image = new PEReader(File.OpenRead(assembly));
        image.TryOpenAssociatedPortablePdb(assembly, path => File.Exists(path) ? File.OpenRead(path) : null, out var symbols, out _)
            .Should().BeTrue("the symbols of {0} say which language version the build compiled at", assembly);

        using (symbols)
        {
            var reader = symbols!.GetMetadataReader();
            var options = reader.GetCustomDebugInformation(EntityHandle.ModuleDefinition)
                .Select(reader.GetCustomDebugInformation)
                .Where(information => reader.GetGuid(information.Kind) == CompilationOptions)
                .Select(information => Encoding.UTF8.GetString(reader.GetBlobBytes(information.Value)).Split('\0'))
                .Single();
            var built = options[Array.IndexOf(options, "language-version") + 1];

            built.Should().Be(BbsTestConvention.Language.ToDisplayString(),
                "the scan must parse the test sources at the language version the build compiles them at. "
                + "Set BbsTestConvention.Language to it, with a Microsoft.CodeAnalysis.CSharp that knows it");
        }
    }

    // The kind of the record in portable symbols that holds the compiler's options, as pairs of names and values.
    private static readonly Guid CompilationOptions = new("B5FEEC05-8CD0-4A83-96DA-466284BB4BD8");

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
