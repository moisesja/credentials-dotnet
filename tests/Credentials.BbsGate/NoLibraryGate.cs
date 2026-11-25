namespace Credentials.BbsGate;

/// <summary>
/// Compares two runs of the same tests, one with NetCrypto's native BBS library and one without it, and
/// reports every test that is not guarded. A test of a <c>bbs-2023</c> class has to fail without the
/// library, and by the helper's own failure: passing, being skipped, producing no result at all and
/// failing for another reason are each a finding.
/// </summary>
/// <remarks>
/// A test of a <c>bbs-2023</c> class is judged as a whole, by class and method: the rows of a theory can
/// differ between the two runs, and a theory whose rows come up empty without the library produces no
/// result at all. Any other test has to do the same thing in both runs, row for row.
/// </remarks>
internal static class NoLibraryGate
{
    // What both failure messages of BbsNativeLibrary.RequireOrSkip() contain, and no other message does:
    // NetCrypto's own exception names the library too, and says "not found". A failure without them is
    // some other failure, such as a file the test did not find, and proves nothing about the library.
    private static readonly string[] HelperFailure = ["BBS native library (zkryptium_ffi)", "did not load"];

    /// <summary>One thing the gate objects to.</summary>
    /// <param name="Rule">The rule, one of the constants of <see cref="Rules"/>.</param>
    /// <param name="Test">The test, by namespace, class and method, or the entry of the list.</param>
    /// <param name="Detail">What happened and what to do.</param>
    public sealed record Finding(string Rule, string Test, string Detail)
    {
        /// <summary>The finding without its explanation, as the expectations of the self-test write it.</summary>
        public string Key => $"{Rule} {Test}";

        /// <inheritdoc />
        public override string ToString() => $"{Key}: {Detail}";
    }

    /// <summary>The names of the rules, as they appear in findings.</summary>
    public static class Rules
    {
        /// <summary>A test of a <c>bbs-2023</c> class passed without the library.</summary>
        public const string Passed = "passed-without-the-library";

        /// <summary>A test of a <c>bbs-2023</c> class was skipped without the library, where it has to fail.</summary>
        public const string Skipped = "skipped-without-the-library";

        /// <summary>A test of a <c>bbs-2023</c> class ran with the library and produced no result without it.</summary>
        public const string NoResult = "no-result-without-the-library";

        /// <summary>A test of a <c>bbs-2023</c> class failed without the library, but not by the helper's failure.</summary>
        public const string FailedOtherwise = "failed-for-another-reason";

        /// <summary>A test on the list of those that need no native library did not pass without it.</summary>
        public const string ListedDidNotPass = "listed-test-did-not-pass";

        /// <summary>The list names a test that did not run, or one whose class is not a <c>bbs-2023</c> class.</summary>
        public const string StaleListing = "stale-listing";

        /// <summary>A test of another class did something else without the library.</summary>
        public const string ChangedOutsideScope = "outcome-changed-outside-bbs-2023";

        /// <summary>Two test assemblies have a test of the same name, and the gate could not tell them apart.</summary>
        public const string SameNameInTwoAssemblies = "same-name-in-two-assemblies";

        /// <summary>The second run was not a run without the library.</summary>
        public const string NotANoLibraryRun = "not-a-no-library-run";
    }

    /// <summary>Reads the list of tests that need no native library: on each line a test, a bar, the reason.</summary>
    public static List<string> ReadList(IEnumerable<string> lines)
    {
        var entries = new List<string>();
        foreach (var line in lines.Select(line => line.Trim()).Where(line => line.Length > 0 && !line.StartsWith('#')))
        {
            var parts = line.Split('|', 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2 || parts[0].Length == 0 || parts[1].Length == 0)
            {
                throw new FormatException($"An entry of the list is '<test> | <reason>'; this one is not: {line}");
            }

            entries.Add(parts[0]);
        }

        return entries;
    }

    /// <summary>Compares the two runs.</summary>
    /// <param name="with">The results of the run with the library.</param>
    /// <param name="without">The results of the run without it.</param>
    /// <param name="unreadable">The test source files without a single reading, from <see cref="BbsScope"/>.</param>
    /// <param name="bbsClasses">The <c>bbs-2023</c> classes, from <see cref="BbsScope"/> and <see cref="TestTypes"/>.</param>
    /// <param name="needNoNativeLibrary">The tests that have to pass without the library.</param>
    /// <param name="availabilityCheck">The test that passes exactly when the library loads.</param>
    public static List<Finding> Compare(
        IReadOnlyCollection<TestResult> with,
        IReadOnlyCollection<TestResult> without,
        IReadOnlyCollection<BbsScope.Finding> unreadable,
        IReadOnlyCollection<string> bbsClasses,
        IReadOnlyCollection<string> needNoNativeLibrary,
        string availabilityCheck)
    {
        // A file the scan could not read one way may declare a bbs-2023 class the scan did not list.
        var findings = unreadable.Select(finding => new Finding(finding.Rule, finding.File, finding.Detail)).ToList();
        var before = with.ToLookup(result => result.Test, StringComparer.Ordinal);
        var after = without.ToLookup(result => result.Test, StringComparer.Ordinal);
        static string Show(IEnumerable<TestResult> results)
        {
            var outcomes = results.Select(result => result.Outcome).Order(StringComparer.Ordinal).ToList();
            return outcomes.Count == 0 ? "no result" : string.Join(", ", outcomes);
        }

        static bool All(IEnumerable<TestResult> results, string outcome) =>
            results.Any() && results.All(result => result.Outcome == outcome);

        // A test of a bbs-2023 class: the class's own name, after its namespace, is a part of the test's
        // name before the method. Namespaces are left out of it, because a result file does not give the
        // class reliably: for a test with a display name of its own it can give the namespace, or the
        // name of the assembly. A class of the same name in another namespace is taken in with it.
        var ownNames = bbsClasses.Select(@class => @class[(@class.LastIndexOf('.') + 1)..]).ToHashSet(StringComparer.Ordinal);
        bool IsInScope(string test) => test.Split('.').SkipLast(1).Any(ownNames.Contains);

        // The second run has to be what it claims to be, or everything below would pass for nothing.
        if (!All(before[availabilityCheck], TestResult.Passed) || !All(after[availabilityCheck], TestResult.Failed))
        {
            findings.Add(new Finding(Rules.NotANoLibraryRun, availabilityCheck, "the availability check has to pass with the "
                + $"library and fail without it; it gave {Show(before[availabilityCheck])}, then {Show(after[availabilityCheck])}. "
                + "The library was not hidden, or the check did not run."));
        }

        foreach (var test in with.Concat(without).Select(result => result.Test).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            if (with.Concat(without).Where(result => result.Test == test).Select(result => result.Assembly).Distinct(StringComparer.Ordinal).Count() > 1)
            {
                findings.Add(new Finding(Rules.SameNameInTwoAssemblies, test, "two test assemblies have a test of this "
                    + "name, and the gate and its list tell tests apart by name. Give one of them another name."));
            }

            if (!IsInScope(test))
            {
                // Any other test does the same thing in both runs: row for row where the rows are the same
                // ones, and outcome for outcome where they are not, as when a row is named by a value made
                // at run time.
                var sameRows = before[test].Select(result => result.Row).Order(StringComparer.Ordinal)
                    .SequenceEqual(after[test].Select(result => result.Row).Order(StringComparer.Ordinal), StringComparer.Ordinal);
                List<string> Rows(IEnumerable<TestResult> results) =>
                    results.Select(result => sameRows ? $"{result.Row}: {result.Outcome}" : result.Outcome).Order(StringComparer.Ordinal).ToList();
                if (!Rows(before[test]).SequenceEqual(Rows(after[test]), StringComparer.Ordinal))
                {
                    var changed = Rows(after[test]).Except(Rows(before[test])).Concat(Rows(before[test]).Except(Rows(after[test]))).First();
                    findings.Add(new Finding(Rules.ChangedOutsideScope, test, $"with the library: {Show(before[test])}; without "
                        + $"it: {Show(after[test])} (for one, '{changed}'). If the test needs the native library: its class "
                        + "is not a bbs-2023 class, because its file names nothing of bbs-2023; name the suite in that "
                        + "file and begin the test with BbsNativeLibrary.RequireOrSkip(). If it does not, it depends on "
                        + "something else that differs between the two runs, such as where its assembly sits."));
                }
            }
            else if (needNoNativeLibrary.Contains(test))
            {
                if (!All(after[test], TestResult.Passed))
                {
                    findings.Add(new Finding(Rules.ListedDidNotPass, test, $"without the library: {Show(after[test])}. A test "
                        + "on the list of those that need no native library has to pass without it. Take it off the "
                        + "list and begin it with BbsNativeLibrary.RequireOrSkip()."));
                }
            }
            else if (!after[test].Any())
            {
                findings.Add(new Finding(Rules.NoResult, test, $"with the library: {Show(before[test])}; without it the test "
                    + "produced no result, so nothing shows that it did not run. A theory whose rows depend on the "
                    + "library does that. Give it rows that do not, and begin it with BbsNativeLibrary.RequireOrSkip()."));
            }
            else if (after[test].Any(result => result.Outcome == TestResult.Passed))
            {
                findings.Add(new Finding(Rules.Passed, test, $"without the library: {Show(after[test])}. A test of a "
                    + "bbs-2023 class has to fail there. Begin it with BbsNativeLibrary.RequireOrSkip(), or, if it needs "
                    + "no native library, add it to the list with the reason."));
            }
            else if (!All(after[test], TestResult.Failed))
            {
                findings.Add(new Finding(Rules.Skipped, test, $"without the library: {Show(after[test])}. Where the library "
                    + "has to load, a test of a bbs-2023 class has to fail, not skip. Something skips it before or "
                    + "instead of BbsNativeLibrary.RequireOrSkip(); a test switched off with Skip = \"...\" is reported "
                    + "here too."));
            }
            else if (after[test].FirstOrDefault(result => !HelperFailure.All(part => result.Message.Contains(part, StringComparison.Ordinal))) is { } other)
            {
                findings.Add(new Finding(Rules.FailedOtherwise, test, "without the library it failed, but not by the failure "
                    + $"of BbsNativeLibrary.RequireOrSkip(): '{other.Message.Split('\n')[0].Trim()}'. That proves nothing about "
                    + "the library: the test may pass on a host without it. Begin it with the call."));
            }
        }

        foreach (var entry in needNoNativeLibrary.Order(StringComparer.Ordinal).Where(entry => !before[entry].Any() || !IsInScope(entry)))
        {
            findings.Add(new Finding(Rules.StaleListing, entry, "the list names a test that did not run with the library, or "
                + "one whose class is not a bbs-2023 class. Remove the entry."));
        }

        return findings;
    }
}
