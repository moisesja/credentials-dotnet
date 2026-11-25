using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using Credentials.BbsGate;
using FluentAssertions;
using Microsoft.CodeAnalysis.CSharp;
using Xunit;
using Wiring = Credentials.ArchitectureTests.BbsScopeTests.Contract<int>;

namespace Credentials.ArchitectureTests;

/// <summary>
/// Tests of <see cref="BbsScope"/>, the one thing the gate for <c>bbs-2023</c> tests reads from source:
/// which test classes are <c>bbs-2023</c> classes. Whether a test is guarded is not read from source; the
/// gate runs it without the native library (issue #57, <c>tools/check-bbs-tests-without-library.sh</c>).
/// </summary>
/// <remarks>
/// <c>BbsScopeFixtures/</c> holds small source files. Each says in its first lines what the scan has to
/// report for it (<c>// expect:</c>) and, where that is the point, which classes it has to find
/// (<c>// scope:</c>). They have a <c>.cs.txt</c> extension so that they are never compiled or scanned.
/// </remarks>
public sealed class BbsScopeTests
{
    private const string ThirdCaseOfTheReview = "review-3-whole-file-under-a-condition.cs.txt";

    private static string FixtureDirectory =>
        Path.Combine(LibrarySurface.RepoRoot, "tests", "Credentials.ArchitectureTests", "BbsScopeFixtures");

    [Fact]
    public void Every_test_source_has_one_reading_and_the_bbs_2023_classes_are_found()
    {
        var result = BbsScope.Scan(BbsScope.ReadSources(LibrarySurface.RepoRoot));

        result.Findings.Should().BeEmpty("a test source file has to parse, be UTF-8 and use no #if, or the scan "
            + "cannot say which classes it declares:\n" + string.Join("\n", result.Findings));
        result.Classes.Should().Contain(
        [
            "Credentials.Rdfc.Tests.Bbs2023SelectiveDisclosureTests",
            "Credentials.Rdfc.Tests.BbsNativeLibraryTests",
            "Credentials.Rdfc.Tests.BbsNativeLibraryTests+ContextWithoutTheBbsLibrary",
            "Credentials.InteropTests.Bbs2023InteropTests",
            "Credentials.SampleSmokeTests.Bbs2023SampleSmokeTests",
        ]);
        result.Classes.Should().NotContain("Credentials.SampleSmokeTests.SampleSmokeTests", "its file names nothing of bbs-2023");
    }

    /// <summary>The names of the fixture files.</summary>
    public static IEnumerable<object[]> Fixtures() =>
        Directory.EnumerateFiles(FixtureDirectory, "*.cs.txt").Order(StringComparer.Ordinal)
            .Select(path => new object[] { Path.GetFileName(path) });

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void A_fixture_is_read_exactly_as_its_header_says(string fixture)
    {
        var (expected, scope, text) = ReadFixture(fixture);

        var result = BbsScope.Scan([new BbsScope.Source(fixture, text)]);

        result.Findings.Select(f => $"{f.Rule} (file)").Should().BeEquivalentTo(
            expected, "that is what the header of {0} expects. The scan reported:\n{1}", fixture, string.Join("\n", result.Findings));
        if (scope is not null)
        {
            result.Classes.Should().BeEquivalentTo(scope, "those are the bbs-2023 classes the header of {0} names", fixture);
        }
    }

    /// <summary>
    /// A class that derives from a <c>bbs-2023</c> class inherits its tests, and a class nested in one is
    /// part of it. Both are read from the assembly, where no alias and no partial declaration can hide
    /// them; here, from this assembly, for the classes below.
    /// </summary>
    [Fact]
    public void A_class_that_derives_from_a_bbs_2023_class_or_is_nested_in_one_is_found_in_the_assembly()
    {
        const string here = "Credentials.ArchitectureTests.BbsScopeTests+";

        var classes = TestClasses.Read([typeof(BbsScopeTests).Assembly.Location], [here + "Contract`1"]);

        classes.InScope.Should().BeEquivalentTo(
            here + "Contract`1", here + "Contract`1+Rows", here + "DefaultWiring", here + "FurtherWiring", here + "FurtherWiring+Inner");
    }

    internal abstract class Contract<T>
    {
        private sealed class Rows;
    }

    private class DefaultWiring : Wiring;

    private sealed class FurtherWiring : DefaultWiring
    {
        private sealed class Inner;
    }

    /// <summary>
    /// The third case of the review of PR #72, on the real <c>Bbs2023SelectiveDisclosureTests</c>: the whole
    /// file under a symbol the build defines. A scan that defines no symbols reads an empty file, so the
    /// class would silently leave the scope. The condition is what is reported.
    /// </summary>
    [Fact]
    public void The_third_case_of_the_review_is_reported_on_the_real_test_file()
    {
        var sources = BbsScope.ReadSources(LibrarySurface.RepoRoot);
        var target = sources.Single(s => s.Path.EndsWith("Bbs2023SelectiveDisclosureTests.cs", StringComparison.Ordinal));
        var altered = target with { Text = $"#if NET10_0\n{target.Text}\n#endif\n" };

        var result = BbsScope.Scan([.. sources.Where(s => s != target), altered]);

        result.Findings.Select(f => $"{f.Rule} in {f.File}").Should().Equal($"{BbsScope.Rules.ConditionalCompilation} in {target.Path}");
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
        var text = ReadFixture(ThirdCaseOfTheReview).Text;
        var altered = text.Replace("#if NET10_0", "#if " + condition, StringComparison.Ordinal);
        altered.Should().NotBe(text);

        var result = BbsScope.Scan([new BbsScope.Source(ThirdCaseOfTheReview, altered)]);

        result.Findings.Select(f => f.Rule).Should().Equal(BbsScope.Rules.ConditionalCompilation);
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
        BbsScope.IsTestSource(pathUnderTests).Should().Be(scanned);
        BbsScope.IsTestSource(pathUnderTests.Replace('/', '\\')).Should().Be(scanned);
    }

    /// <summary>
    /// The files are found on disk as the build finds them, on the platform this runs on: a pattern for
    /// the extension is matched by letter case on Linux, where the build matches it without. A file with
    /// bytes that are not UTF-8 is read, and reported.
    /// </summary>
    [Fact]
    public void The_scan_reads_the_files_a_project_compiles_by_default()
    {
        var root = Directory.CreateTempSubdirectory("bbs-scope-");
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

            var sources = BbsScope.ReadSources(root.FullName);

            sources.Select(s => s.Path.Replace('\\', '/')).Should().BeEquivalentTo(
            [
                "tests/Some.Tests/Lower.cs", "tests/Some.Tests/Upper.CS", "tests/Some.Tests/Mixed.Cs",
                "tests/Some.Tests/.Hidden.cs", "tests/Some.Tests/Vectors/bin/Nested.cs", "tests/Some.Tests/NotUtf8.cs",
            ]);
            BbsScope.Scan(sources).Findings.Select(f => $"{f.Rule} in {f.File.Replace('\\', '/')}")
                .Should().Equal($"{BbsScope.Rules.NotUtf8} in tests/Some.Tests/NotUtf8.cs");
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    /// <summary>
    /// The scan parses at one language version, and it has to be the one the build compiles at. The
    /// compiler records the version it used in the symbols of every assembly it builds, this one included.
    /// </summary>
    [Fact]
    public void The_scan_parses_at_the_language_version_of_the_build()
    {
        var assembly = typeof(BbsScopeTests).Assembly.Location;
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

            built.Should().Be(BbsScope.Language.ToDisplayString(),
                "the scan must parse the test sources at the language version the build compiles them at. "
                + "Set BbsScope.Language to it, with a Microsoft.CodeAnalysis.CSharp that knows it");
        }
    }

    // The kind of the record in portable symbols that holds the compiler's options, as pairs of names and values.
    private static readonly Guid CompilationOptions = new("B5FEEC05-8CD0-4A83-96DA-466284BB4BD8");

    // A fixture says what the scan must report for it, in comment lines before the code:
    //   // expect: <rule> (file)       one line for each finding, or `// expect: nothing`
    //   // scope: <full class name>    one line for each bbs-2023 class, or `// scope: none`; optional
    private static (List<string> Expected, List<string>? Scope, string Text) ReadFixture(string fixture)
    {
        var text = File.ReadAllText(Path.Combine(FixtureDirectory, fixture));
        var header = text.Split('\n').Select(line => line.Trim()).TakeWhile(line => line.StartsWith("//", StringComparison.Ordinal)).ToList();
        List<string> Lines(string prefix) => header.Where(line => line.StartsWith(prefix, StringComparison.Ordinal))
            .Select(line => line[prefix.Length..].Trim()).ToList();

        var expectations = Lines("// expect:");
        expectations.Should().NotBeEmpty("{0} must say what it expects", fixture);
        if (expectations.Contains("nothing"))
        {
            expectations.Should().Equal(["nothing"], "{0} expects nothing, or it lists its findings", fixture);
            expectations.Clear();
        }

        var scope = Lines("// scope:");
        return (expectations, scope.Count == 0 ? null : [.. scope.Where(name => name != "none")], text);
    }
}
