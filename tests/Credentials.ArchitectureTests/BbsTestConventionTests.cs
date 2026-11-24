using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace Credentials.ArchitectureTests;

/// <summary>
/// Keeps every <c>bbs-2023</c> test on the rule of issue #57. A test that needs NetCrypto's native BBS
/// library has to call <c>BbsNativeLibrary.RequireOrSkip()</c>, or it could pass on a host without the
/// library: a test that only expects an exception gets one from the missing library too. Scans the test
/// sources, like <see cref="FrCoverageGateTests"/> (deterministic; this assembly must not load
/// <c>Credentials.Rdfc</c>, so it cannot reflect over the test assemblies that use it).
/// </summary>
/// <remarks>
/// <para>What it reads from the source text:</para>
/// <list type="bullet">
/// <item>a <b>test</b> is a method under <c>[Fact]</c>, <c>[Theory]</c>, <c>[SkippableFact]</c> or
/// <c>[SkippableTheory]</c>; its text runs from that attribute to the next test's;</item>
/// <item>a <b>bbs-2023 test</b> carries <c>[Trait("Category", "Bbs")]</c>, on the method or on the first
/// class of its file;</item>
/// <item>a file <b>wires bbs-2023</b> when it calls <c>UseBbs2023(</c> or constructs the cryptosuite.</item>
/// </list>
/// <para>It checks text, not behaviour. It does not see a test that reaches <c>bbs-2023</c> only through
/// code in another file and carries no trait, and it does not check that the call comes before the first
/// use. The line comments are stripped first, so a commented-out call does not count.</para>
/// </remarks>
public sealed partial class BbsTestConventionTests
{
    private const string HelperCall = "BbsNativeLibrary.RequireOrSkip();";

    /// <summary>
    /// The <c>bbs-2023</c> tests that need no native library, each with the reason. Every other
    /// <c>bbs-2023</c> test must be skippable and call the helper.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> NeedNoNativeLibrary = new Dictionary<string, string>
    {
        ["Bbs2023SelectiveDisclosureTests.Bbs_issuance_is_gated"] =
            "asserts the issuance gate, which refuses before any BBS call",
        ["Bbs2023SelectiveDisclosureTests.UseBbs2023_adds_the_suite_to_capabilities_and_registers_the_deriver"] =
            "registration only",
        ["Bbs2023SelectiveDisclosureTests.UseBbs2023_is_idempotent"] =
            "registration only",
        ["BbsNativeLibraryTests.A_missing_library_skips_only_off_github_actions_on_an_unshipped_platform"] =
            "pins the rule, a pure function",
        ["BbsNativeLibraryTests.The_rule_is_carried_out_on_the_calling_test"] =
            "pins what an outcome does to a test",
        ["BbsNativeLibraryTests.The_inputs_of_the_rule_come_from_this_host"] =
            "pins where the rule's inputs come from",
        ["BbsNativeLibraryTests.Without_the_library_the_call_fails_or_skips_and_never_returns"] =
            "runs the helper where the library is refused; it must not skip",
        ["BbsNativeLibraryTests.A_platform_maps_to_its_runtime_identifier"] =
            "pins the platform mapping, a pure function",
        ["BbsNativeLibraryTests.Netcrypto_declares_the_bbs_native_library_for_exactly_the_documented_platforms"] =
            "reads the .deps.json; it is skippable for a runtime-specific build, not for the library",
    };

    [Fact]
    public void Every_bbs_test_calls_the_native_library_helper_or_is_listed_as_not_needing_it()
    {
        var bbsTests = ScanTests().Where(t => t.IsBbs).ToList();

        var offenders = bbsTests
            .Where(t => !NeedNoNativeLibrary.ContainsKey(t.Id) && !(t.IsSkippable && t.CallsHelper))
            .Select(t => $"{t.Id} ({(t.IsSkippable ? "skippable" : "not skippable")}, "
                         + $"{(t.CallsHelper ? "calls the helper" : "does not call the helper")})")
            .ToList();

        offenders.Should().BeEmpty(
            "a bbs-2023 test must be a [SkippableFact] or [SkippableTheory] that calls " + HelperCall
            + " Without that call it can pass on a host without the native library. If the test needs no "
            + "native library, add it to NeedNoNativeLibrary with the reason. Offending:\n"
            + string.Join("\n", offenders));

        // The scan has to see each kind of bbs-2023 test there is, or an empty result would mean nothing.
        string[] known =
        [
            "Bbs2023SelectiveDisclosureTests.Bbs_derive_then_verify_round_trips", // class trait, fact
            "Bbs2023SelectiveDisclosureTests.Bbs_malformed_reveal_pointer_maps_to_credential_format_exception", // theory
            "Bbs2023InteropTests.Bbs_derived_proof_pins_the_vc_di_bbs_wire_format_and_verifies",
            "BbsNativeLibraryTests.Bbs_native_library_loads_wherever_it_has_to",
            "SampleSmokeTests.Bbs2023", // method trait
        ];
        bbsTests.Where(t => t.IsSkippable && t.CallsHelper).Select(t => t.Id).Should().Contain(known);
    }

    [Fact]
    public void Every_test_file_that_wires_bbs_2023_is_in_the_bbs_category()
    {
        var offenders = ScanTests()
            .Where(t => t.FileWiresBbs && !t.IsBbs)
            .Select(t => $"{t.Id} in {t.File}")
            .ToList();

        offenders.Should().BeEmpty(
            "a test file that calls UseBbs2023 or constructs the bbs-2023 cryptosuite must carry the Bbs "
            + "category trait on its class, so that the rule for bbs-2023 tests applies to every test in it. "
            + "Offending:\n" + string.Join("\n", offenders));
    }

    [Fact]
    public void The_tests_listed_as_needing_no_native_library_exist_and_do_not_call_the_helper()
    {
        var bbsTests = ScanTests().Where(t => t.IsBbs).ToDictionary(t => t.Id);

        var stale = NeedNoNativeLibrary.Keys.Where(id => !bbsTests.ContainsKey(id)).ToList();
        stale.Should().BeEmpty("NeedNoNativeLibrary names a test that is not a bbs-2023 test any more: "
            + string.Join(", ", stale));

        var contradictory = NeedNoNativeLibrary.Keys.Where(id => bbsTests[id].CallsHelper).ToList();
        contradictory.Should().BeEmpty("a test that calls the helper needs the library; remove it from "
            + "NeedNoNativeLibrary: " + string.Join(", ", contradictory));
    }

    private sealed record ScannedTest(
        string File, string Id, bool IsSkippable, bool IsBbs, bool CallsHelper, bool FileWiresBbs);

    private static List<ScannedTest> ScanTests()
    {
        var testsRoot = Path.Combine(LibrarySurface.RepoRoot, "tests");
        var found = new List<ScannedTest>();

        foreach (var file in Directory.EnumerateFiles(testsRoot, "*.cs", SearchOption.AllDirectories))
        {
            // Skip build output.
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") ||
                file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")) continue;

            // Strip line comments, so that commented-out code and documentation count for nothing.
            var lines = File.ReadLines(file).Select(WithoutLineComment).ToArray();

            var classLine = Array.FindIndex(lines, line => ClassRegex().IsMatch(line));
            var attributeLines = Enumerable.Range(0, lines.Length).Where(i => TestAttributeRegex().IsMatch(lines[i])).ToArray();
            if (classLine < 0 || attributeLines.Length == 0) continue;

            var className = ClassRegex().Match(lines[classLine]).Groups[1].Value;
            var classIsBbs = lines.Take(classLine).Any(line => BbsTraitRegex().IsMatch(line));
            var fileWiresBbs = lines.Any(line => WiresBbsRegex().IsMatch(line));

            for (var n = 0; n < attributeLines.Length; n++)
            {
                var start = attributeLines[n];
                var end = n + 1 < attributeLines.Length ? attributeLines[n + 1] : lines.Length;

                // The attributes of a method may begin above its test attribute.
                var top = start;
                while (top > 0 && lines[top - 1].TrimStart().StartsWith('[')) top--;

                var signature = Enumerable.Range(start, end - start).FirstOrDefault(i => MethodRegex().IsMatch(lines[i]), -1);
                var name = signature < 0 ? $"<no method found at line {start + 1}>" : MethodRegex().Match(lines[signature]).Groups[1].Value;
                var bodyFrom = signature < 0 ? start : signature;

                found.Add(new ScannedTest(
                    File: Path.GetRelativePath(LibrarySurface.RepoRoot, file),
                    Id: $"{className}.{name}",
                    IsSkippable: TestAttributeRegex().Match(lines[start]).Groups["skippable"].Success,
                    IsBbs: classIsBbs || lines[top..(bodyFrom + 1)].Any(line => BbsTraitRegex().IsMatch(line)),
                    CallsHelper: lines[bodyFrom..end].Any(line => line.Contains(HelperCall, StringComparison.Ordinal)),
                    FileWiresBbs: fileWiresBbs));
            }
        }

        return found;
    }

    private static string WithoutLineComment(string line)
    {
        var comment = line.IndexOf("//", StringComparison.Ordinal);
        return comment >= 0 ? line[..comment] : line;
    }

    [GeneratedRegex("""^\s*\[\s*(?<skippable>Skippable)?(?:Fact|Theory)\b""")]
    private static partial Regex TestAttributeRegex();

    [GeneratedRegex("""Trait\s*\(\s*"Category"\s*,\s*"Bbs"\s*\)""")]
    private static partial Regex BbsTraitRegex();

    [GeneratedRegex("""\bclass\s+(\w+)""")]
    private static partial Regex ClassRegex();

    [GeneratedRegex("""\bpublic\s+(?:static\s+)?(?:async\s+)?[\w<>\[\],.?]+\s+(\w+)\s*\(""")]
    private static partial Regex MethodRegex();

    [GeneratedRegex("""\bUseBbs2023\s*\(|\bnew\s+Bbs2023Cryptosuite\s*\(""")]
    private static partial Regex WiresBbsRegex();
}
