using System.Text.RegularExpressions;
using Credentials.TestSupport;
using FluentAssertions;
using Xunit;

namespace Credentials.ArchitectureTests;

/// <summary>
/// The requirement-coverage gate: every requirement in the PRD §8 table (see
/// <see cref="RequirementIds"/>) must have at least one test tagged with <c>[FrTag("…")]</c>, so a
/// new FR cannot land untested. Scans the test sources for the literal tags (deterministic; no
/// cross-assembly reflection).
/// </summary>
public sealed partial class FrCoverageGateTests
{
    /// <summary>
    /// Requirements whose tagged tests live in a not-yet-merged PR of the M8 series. Each is logged
    /// (not silently skipped) and removed from this map when its PR lands, so the gate never reports a
    /// requirement as covered that has no test yet.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> DeferredToLaterPr = new Dictionary<string, string>
    {
        ["NFR-007"] = "conformance shim + interop vectors land in PR-C (M8c); tagged there.",
    };

    [Fact]
    [FrTag("NFR-009")] // this gate is itself part of the verification-completeness story
    public void EveryRequirement_HasAtLeastOneTaggedTest()
    {
        var tagged = ScanTaggedRequirementIds();

        var missing = new List<string>();
        var deferred = new List<string>();
        foreach (var id in RequirementIds.All)
        {
            if (tagged.Contains(id)) continue;
            if (DeferredToLaterPr.TryGetValue(id, out var reason))
            {
                deferred.Add($"{id}: DEFERRED — {reason}");
                continue;
            }
            missing.Add($"{id} ({RequirementIds.Describe(id)})");
        }

        // Surface the honest skip list in the test output.
        if (deferred.Count > 0)
            Console.WriteLine("FrCoverage deferred (logged, not failed):\n  " + string.Join("\n  ", deferred));

        missing.Should().BeEmpty(
            "every PRD §8 requirement must have at least one [FrTag]-tagged test. Untagged:\n" + string.Join("\n", missing));

        // Guard against a typo'd tag that matches no defined requirement.
        var unknown = tagged.Where(t => RequirementIds.Describe(t) is null).ToList();
        unknown.Should().BeEmpty("a [FrTag] references an id not defined in RequirementIds: " + string.Join(", ", unknown));
    }

    private static HashSet<string> ScanTaggedRequirementIds()
    {
        var testsRoot = Path.Combine(LibrarySurface.RepoRoot, "tests");
        var ids = new HashSet<string>(StringComparer.Ordinal);

        foreach (var file in Directory.EnumerateFiles(testsRoot, "*.cs", SearchOption.AllDirectories))
        {
            // Skip build output.
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") ||
                file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")) continue;

            // Strip line comments before matching so a commented-out `// [FrTag("FR-xxx")]` cannot
            // hollowly satisfy the gate (a [FrTag] must be a real, applied attribute).
            foreach (var rawLine in File.ReadLines(file))
            {
                var comment = rawLine.IndexOf("//", StringComparison.Ordinal);
                var line = comment >= 0 ? rawLine[..comment] : rawLine;
                foreach (Match m in FrTagRegex().Matches(line))
                    ids.Add(m.Groups[1].Value);
            }
        }
        return ids;
    }

    [GeneratedRegex("""\[\s*FrTag\s*\(\s*"((?:FR|NFR)-\d+)"\s*\)\s*\]""")]
    private static partial Regex FrTagRegex();
}
