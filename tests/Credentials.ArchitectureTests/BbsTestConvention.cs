using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Credentials.ArchitectureTests;

/// <summary>
/// The rule every <c>bbs-2023</c> test has to follow (issue #57), checked on the syntax tree of the test
/// sources. A test that needs NetCrypto's native BBS library has to begin with
/// <c>BbsNativeLibrary.RequireOrSkip();</c>, or it could pass on a host without the library: a test that
/// only expects an exception gets one from the missing library too.
/// </summary>
/// <remarks>
/// <para><b>One tree for a file.</b> Everything below is decided from the syntax tree of a file, so the
/// tree has to be the one the build compiles. Three things could make it another, and each is a finding in
/// any test source file, before anything is asked of the tree: a syntax error, bytes that are not UTF-8,
/// and conditional compilation. The scan defines no symbols and does not try to follow the build's: a file
/// under a condition has more than one reading, and the scan cannot know which one a build takes. It
/// parses at <see cref="Language"/>, the language version of the build.</para>
/// <para><b>Scope.</b> A file is a <c>bbs-2023</c> test file when its code, not its comments, has an
/// identifier that contains "bbs" in any letter case, a string that names the suite or one of its types, or
/// the <c>Bbs</c> category trait. Every test in such a file is checked, whichever class it is in.</para>
/// <para><b>The rule.</b> Each of those tests either is a <c>[SkippableFact]</c> or
/// <c>[SkippableTheory]</c> that returns <c>void</c> or <c>Task</c>, whose body's first statement is the
/// call, and that is in the <c>Bbs</c> category; or it is named on the caller's list of tests that need no
/// native library. The class of a test is sealed and not partial, so that no other file adds to it.</para>
/// <para><b>Nothing skips before the call.</b> Where the library has to load, the call fails the test. A
/// skip that runs before the first statement of the test would turn that into a skip, so in a
/// <c>bbs-2023</c> test file only the body of a test, and the helper, may name what skips: not a
/// constructor, an initializer, <c>InitializeAsync</c>, the data of a theory or an attribute.</para>
/// <para><b>What the scan does not understand, it reports.</b> A syntax tree has no types, so the scan
/// cannot follow a custom attribute, a base class or another thing named like the helper. In a
/// <c>bbs-2023</c> test file those are findings: an attribute it does not know wherever it sits, except on
/// a parameter or a return value; a base type it does not know; a partial type; a static import.</para>
/// <para><b>The names it trusts.</b> The scan takes a handful of names for what they mean in xUnit and the
/// base library: the attributes and base types it knows, and <c>Task</c>. A type, a delegate or an alias
/// of one of those names, declared in any test source file, would be used in its place, so it is a
/// finding in any file. So are an attribute of the assembly that the scan does not know and a global
/// static import, which reach every file of a project.</para>
/// <para><b>What it cannot see.</b> It reads the files under <c>tests/</c> that a project compiles by
/// default, <see cref="IsTestSource"/>, and nothing else, and it reads names, not what they resolve to. It
/// does not see:</para>
/// <list type="bullet">
/// <item>a test in a file whose code names nothing of <c>bbs-2023</c>. It may reach the suite through code
/// in another file (a shared provider factory, a stored credential, a loop over the registered suites),
/// or in its own, by reflection on a name it puts together when it runs;</item>
/// <item>a skip before the call that names nothing the scan reads: one that comes from code in another
/// file, which a constructor or an initializer calls under a name of its own, or one made by reflection;</item>
/// <item>what the build takes from anywhere else: a project file, generated code, a source file outside
/// <c>tests/</c>, another assembly. Any of those can give the helper's name or an attribute's name a
/// different meaning, and a project file can also compile a file the scan leaves out;</item>
/// <item>a construct that its parser and the compiler of the build read differently. Both are Roslyn, at
/// one language version, but not the same release;</item>
/// <item>the body of a test on the list: the list is a judgement, kept by review.</item>
/// </list>
/// <para>Only running the tests without the library closes those.</para>
/// </remarks>
internal static class BbsTestConvention
{
    /// <summary>The helper type every guarded test calls.</summary>
    public const string HelperType = "BbsNativeLibrary";

    /// <summary>The helper method every guarded test calls first.</summary>
    public const string HelperMethod = "RequireOrSkip";

    /// <summary>
    /// The language version the scan parses at. It has to be the one the build compiles at, because a
    /// later version can read the same text another way; the parser's own latest is a version ahead of the
    /// SDK's. A test compares it with the version the compiler recorded for this assembly.
    /// </summary>
    public const LanguageVersion Language = LanguageVersion.CSharp14;

    private static readonly string[] SkippableTestAttributes = ["SkippableFact", "SkippableTheory"];
    private static readonly string[] PlainTestAttributes = ["Fact", "Theory"];

    // Every attribute that may be written in a bbs-2023 test file, and on the assembly in any test source
    // file: the test attributes, what goes with them, and two from the base library that do nothing to a
    // test. Any other name could be a test attribute the scan cannot recognise (a custom one, or an alias),
    // or one that xUnit runs before each test, so it is a finding until it is added here.
    private static readonly string[] KnownAttributes =
    [
        .. SkippableTestAttributes, .. PlainTestAttributes,
        "Trait", "FrTag", "InlineData", "MemberData", "ClassData",
        "Obsolete", "MethodImpl",
    ];

    // The one known attribute that the test sources declare themselves, the file that declares it, and
    // the one base it may have there: with FactAttribute as its base it would be a test attribute.
    private const string DeclaredAttribute = "FrTagAttribute";
    private const string DeclaredAttributeFile = "FrTagAttribute.cs";
    private const string DeclaredAttributeBase = "Attribute";

    // What a test may return besides void, by name. Like the known attributes and base types, the name is
    // trusted to mean the type of the base library. Not ValueTask: xUnit 2 does not await one, so a test
    // that returns it passes whatever it throws.
    private const string TaskType = "Task";

    // What skips a test when it is called: Xunit.Skip, its exception, and the helper's own Enforce, which
    // carries out whatever outcome its caller chooses.
    private static readonly string[] WhatSkips = ["Skip", "SkipException", "Enforce"];

    // What a type in a bbs-2023 test file may list after its name. Anything else could be a base class
    // that brings tests, or members named like the helper, from another file.
    private static readonly string[] KnownBaseTypes =
    [
        "IDisposable", "IAsyncLifetime", "IClassFixture", "IEquatable", "TheoryData", "Exception", "AssemblyLoadContext",
    ];

    // The two spellings of the helper type the first statement may use, each written as a name: a string
    // that holds one of them is not the type. Neither can be made to mean something else: the scan reports
    // anything else declared with the bare name, and the second begins with the keyword `global`, which
    // nothing can be declared as.
    private static readonly string[] HelperTypeSpellings = [HelperType, $"global::Credentials.TestSupport.{HelperType}"];

    /// <summary>One source file to scan.</summary>
    /// <param name="Path">The path, as reported in findings.</param>
    /// <param name="Text">The file's text.</param>
    public sealed record Source(string Path, string Text);

    /// <summary>One thing the scan objects to.</summary>
    /// <param name="Rule">The rule, one of the constants of <see cref="Rules"/>.</param>
    /// <param name="Subject">The test, type or file the finding is about.</param>
    /// <param name="File">The file it was found in.</param>
    /// <param name="Detail">What is wrong and what to do.</param>
    public sealed record Finding(string Rule, string Subject, string File, string Detail)
    {
        /// <inheritdoc />
        public override string ToString() => $"{Rule} {Subject} ({File}): {Detail}";
    }

    /// <summary>The outcome of a scan.</summary>
    /// <param name="Findings">Everything the scan objects to. Empty when the sources follow the rule.</param>
    /// <param name="GuardedTests">The tests that begin with the helper call.</param>
    /// <param name="ListedTests">The tests accepted because they are on the caller's list.</param>
    /// <param name="BbsFiles">The files the scan took for <c>bbs-2023</c> test files.</param>
    public sealed record Result(
        IReadOnlyList<Finding> Findings,
        IReadOnlyList<string> GuardedTests,
        IReadOnlyList<string> ListedTests,
        IReadOnlyList<string> BbsFiles);

    /// <summary>The names of the rules, as they appear in findings.</summary>
    public static class Rules
    {
        /// <summary>The file does not parse.</summary>
        public const string SyntaxError = "syntax-error";

        /// <summary>The file has bytes that are not UTF-8, which the compiler reads by a code page of the machine.</summary>
        public const string NotUtf8 = "not-utf-8";

        /// <summary>A test neither begins with the helper call under a skippable attribute nor is listed.</summary>
        public const string UnguardedTest = "unguarded-test";

        /// <summary>An attribute of a test carries <c>Skip = "..."</c>: the test, or a row of it, may never run.</summary>
        public const string StaticSkip = "static-skip";

        /// <summary>A test attribute has an argument without a name: for a skippable one, an exception type that turns a failure into a skip.</summary>
        public const string TestAttributeArguments = "test-attribute-arguments";

        /// <summary>A test returns something other than <c>void</c> or <c>Task</c>, so what it throws may be lost.</summary>
        public const string ReturnType = "return-type";

        /// <summary>A guarded test is not in the <c>Bbs</c> category.</summary>
        public const string NotInCategory = "not-in-category";

        /// <summary>An attribute the scan does not know, in a <c>bbs-2023</c> test file or on the assembly.</summary>
        public const string UnknownAttribute = "unknown-attribute";

        /// <summary>Something outside the body of a test names what skips, so it can skip before the helper call.</summary>
        public const string SkipOutsideATest = "skip-outside-a-test";

        /// <summary>A type, a delegate or an alias is named like a name the scan trusts: an attribute, a base type, a task.</summary>
        public const string NameShadowed = "name-shadowed";

        /// <summary>A type lists a base type the scan does not know.</summary>
        public const string BaseType = "base-type";

        /// <summary>A partial type: its other parts, with a constructor or the attributes of a member, may be in another file.</summary>
        public const string PartialType = "partial-type";

        /// <summary>The class of a test is not sealed: a class in another file can derive from it and run before its tests.</summary>
        public const string UnsealedTestClass = "unsealed-test-class";

        /// <summary>A test source file uses conditional compilation, so the scan may not see what is compiled.</summary>
        public const string ConditionalCompilation = "conditional-compilation";

        /// <summary>A static import, which may bring in a member named like the helper or one that skips: in a <c>bbs-2023</c> test file, or a global one in any file.</summary>
        public const string StaticImport = "static-import";

        /// <summary>An alias named like the helper, or an <c>extern alias</c>.</summary>
        public const string Alias = "alias";

        /// <summary>Something else is named like the helper.</summary>
        public const string HelperShadowed = "helper-shadowed";

        /// <summary>Two tests have the same name, so the list could not tell them apart.</summary>
        public const string DuplicateTest = "duplicate-test";

        /// <summary>A test attribute sits on something that is not a method in a type.</summary>
        public const string Unclassifiable = "unclassifiable";

        /// <summary>The list names a test that is not there.</summary>
        public const string StaleListing = "stale-listing";

        /// <summary>The list names a test that begins with the helper call.</summary>
        public const string ListedButGuarded = "listed-but-guarded";
    }

    /// <summary>
    /// Whether a file under <c>tests/</c> is one a test project compiles by default: a file whose extension
    /// is <c>.cs</c> in any letter case, as the build matches it on every platform, outside the project's
    /// build output. Hidden files count. So does a file in a folder the build passes over, one whose name
    /// begins with a dot: scanning more than is compiled costs nothing.
    /// </summary>
    /// <param name="pathUnderTests">The path relative to <c>tests/</c>.</param>
    public static bool IsTestSource(string pathUnderTests) =>
        pathUnderTests.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) && !IsProjectBuildOutput(pathUnderTests);

    // The build output of a test project: its own bin or obj folder, which the build does not compile. A
    // folder of that name further down is compiled like any other, and so is one whose name differs by
    // letter case, where that is another folder.
    private static bool IsProjectBuildOutput(string pathUnderTests)
    {
        var parts = pathUnderTests.Split('/', '\\');
        return parts.Length > 2 && parts[1] is "bin" or "obj";
    }

    /// <summary>Reads every test source file of the repository, each with its path from the root.</summary>
    /// <param name="repositoryRoot">The folder that holds <c>tests/</c>.</param>
    public static List<Source> ReadSources(string repositoryRoot)
    {
        // Every file is listed and the extension is matched here: a "*.cs" pattern is matched by the
        // letter case of the platform, and on Linux that leaves out a file the build compiles.
        var testsRoot = System.IO.Path.Combine(repositoryRoot, "tests");
        return Directory.EnumerateFiles(testsRoot, "*", SearchOption.AllDirectories)
            .Where(file => IsTestSource(System.IO.Path.GetRelativePath(testsRoot, file)))
            .Select(file => new Source(System.IO.Path.GetRelativePath(repositoryRoot, file), File.ReadAllText(file)))
            .ToList();
    }

    /// <summary>Scans the sources and reports everything that does not follow the rule.</summary>
    /// <param name="sources">The test source files.</param>
    /// <param name="needNoNativeLibrary">The full names of the tests accepted without the helper call.</param>
    public static Result Scan(IEnumerable<Source> sources, IReadOnlyCollection<string> needNoNativeLibrary)
    {
        var findings = new List<Finding>();
        var guarded = new List<string>();
        var listed = new List<string>();
        var bbsFiles = new List<string>();
        var seenTests = new HashSet<string>(StringComparer.Ordinal);
        var helperTypes = new List<(string File, bool FileHasTests)>();

        foreach (var source in sources)
        {
            var tree = CSharpSyntaxTree.ParseText(source.Text, new CSharpParseOptions(Language), source.Path);
            var root = tree.GetCompilationUnitRoot();
            void Report(string rule, string subject, string detail) =>
                findings.Add(new Finding(rule, subject, source.Path, detail));

            // The scan reads one tree for a file. These three could make the build compile something else
            // from the same file, so each is a finding in every test source file, whatever the file names:
            // only after them is anything decided from the tree, a file being out of scope included.
            if (source.Text.Contains(ReplacementCharacter))
            {
                Report(Rules.NotUtf8, "(file)", "the file has a replacement character: bytes of it are not UTF-8, or the "
                    + "character is written in it. The compiler reads such bytes by a code page of the machine, so it "
                    + "may not read what the scan reads. Save the file as UTF-8, and write the character as an escape.");
            }

            var errors = tree.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
            if (errors.Count > 0)
            {
                Report(Rules.SyntaxError, "(file)", "the file does not parse, so it cannot be checked: " + errors[0].GetMessage());
                continue;
            }

            var conditional = root.DescendantTrivia().FirstOrDefault(IsConditionalCompilation);
            if (!conditional.IsKind(SyntaxKind.None))
            {
                Report(Rules.ConditionalCompilation, "(file)", $"'{conditional.ToString().Trim()}': the scan reads one "
                    + "branch of a condition and the build may compile another, which could hold a bbs-2023 test or "
                    + "give an attribute another meaning. Do not use conditional compilation in a test source file; "
                    + "decide at run time instead.");
            }

            var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>().ToList();
            var fileHasTests = methods.Any(m => TestAttributesOf(m).Count > 0);
            helperTypes.AddRange(root.DescendantNodes().OfType<BaseTypeDeclarationSyntax>()
                .Where(type => type.Identifier.ValueText == HelperType)
                .Select(_ => (source.Path, fileHasTests)));

            // These change what a name means, or what happens to a test, in every file of the project, so
            // they are checked in every file, a bbs-2023 test file or not.
            CheckTrustedNames(root, source.Path, Report);
            foreach (var unknown in root.AttributeLists.SelectMany(list => list.Attributes).Select(SimpleNameOf).Where(n => !KnownAttributes.Contains(n)))
            {
                Report(Rules.UnknownAttribute, "(assembly)", $"[{unknown}] is not an attribute this scan knows. An attribute "
                    + "of the assembly applies to every test in it, and xUnit runs some kinds before each test, where "
                    + "they can skip it. Add the name to KnownAttributes if it does nothing of the kind.");
            }

            foreach (var import in root.Usings.Where(u => IsStatic(u) && u.GlobalKeyword.IsKind(SyntaxKind.GlobalKeyword)))
            {
                Report(Rules.StaticImport, import.Name?.ToString() ?? "(global using static)", "a global static import "
                    + "brings the members of a type into every file of the project by their bare names, the ones "
                    + "that skip among them. Do not use one in a test project.");
            }

            if (!TouchesBbs(root))
            {
                continue;
            }

            bbsFiles.Add(source.Path);
            CheckFile(root, Report);

            // A test attribute anywhere but on a method. On a property accessor xUnit runs it; elsewhere it
            // does not. Either way the scan has no test here to check, and says so.
            foreach (var attribute in root.DescendantNodes().OfType<AttributeSyntax>()
                         .Where(a => IsTestAttribute(SimpleNameOf(a)) && a.Parent?.Parent is not MethodDeclarationSyntax))
            {
                Report(Rules.Unclassifiable, $"[{attribute}]", "a test attribute on something that is not a method; "
                    + "the scan cannot check it. Put it on a method of a class.");
            }

            // Every attribute in the file has to be one the scan knows, wherever it sits. xUnit runs a
            // test attribute on a property accessor, an operator or an event as it does on a method, and
            // it runs some kinds of attribute on a class before each test. A parameter and a return value
            // are not run; the attributes of the assembly are checked above, in every file.
            foreach (var attribute in root.DescendantNodes().OfType<AttributeSyntax>()
                         .Where(a => !KnownAttributes.Contains(SimpleNameOf(a)) && a.Parent is AttributeListSyntax list
                             && list.Parent is not ParameterSyntax and not CompilationUnitSyntax
                             && list.Target?.Identifier.ValueText != "return"))
            {
                var subject = attribute.Parent!.Parent switch
                {
                    MethodDeclarationSyntax method => FullNameOf(method),
                    BaseTypeDeclarationSyntax type => type.Identifier.ValueText,
                    _ => $"[{attribute}]",
                };
                Report(Rules.UnknownAttribute, subject, $"[{SimpleNameOf(attribute)}] is not an attribute this scan knows. It "
                    + "could make what it sits on a test, or run before a test and skip it. Use a plain xUnit "
                    + "attribute, or add the name to KnownAttributes if it does neither.");
            }

            foreach (var method in methods)
            {
                var id = FullNameOf(method);

                var testAttributes = TestAttributesOf(method);
                if (testAttributes.Count == 0)
                {
                    continue;
                }

                if (!seenTests.Add(id))
                {
                    Report(Rules.DuplicateTest, id, "two tests have this name; give each its own.");
                }

                if (method.Parent is not TypeDeclarationSyntax)
                {
                    Report(Rules.Unclassifiable, id, "a test that is not directly in a class.");
                    continue;
                }

                if (AttributesOf(method).Any(HasStaticSkip))
                {
                    Report(Rules.StaticSkip, id, "an attribute of the test sets Skip, so the test or one of its rows never runs. Remove it.");
                }

                if (testAttributes.Any(a => a.ArgumentList?.Arguments.Any(arg => arg.NameEquals is null) == true))
                {
                    Report(Rules.TestAttributeArguments, id, "the test attribute has an argument without a name. On a "
                        + "skippable attribute that is an exception type, and it turns the helper's failure into a skip.");
                }

                if (!ReturnsVoidOrTask(method))
                {
                    Report(Rules.ReturnType, id, $"it returns {method.ReturnType}. The scan accepts void and Task, which "
                        + "xUnit runs to the end and sees fail. An iterator is never run, and a ValueTask is not awaited, "
                        + "so what the helper call throws would be lost. Return void or Task.");
                }

                var skippable = testAttributes.All(a => SkippableTestAttributes.Contains(SimpleNameOf(a)));
                var beginsWithTheCall = BeginsWithTheHelperCall(method);

                if (needNoNativeLibrary.Contains(id))
                {
                    listed.Add(id);
                    if (beginsWithTheCall)
                    {
                        Report(Rules.ListedButGuarded, id, "a test that calls the helper needs the library; take it off the list.");
                    }

                    continue;
                }

                if (!skippable || !beginsWithTheCall)
                {
                    Report(Rules.UnguardedTest, id,
                        (skippable ? string.Empty : "it is not a [SkippableFact] or [SkippableTheory]; ")
                        + (beginsWithTheCall ? string.Empty : $"the first statement of its body is not {HelperType}.{HelperMethod}(); ")
                        + "without that it can pass on a host without the native library. If it needs no native "
                        + "library, add it to the list with the reason.");
                    continue;
                }

                guarded.Add(id);
                if (!IsInBbsCategory(method))
                {
                    Report(Rules.NotInCategory, id, "a test that needs the library must carry [Trait(\"Category\", \"Bbs\")], "
                        + "on itself or on its own class, so that the Bbs filter selects it.");
                }
            }

            foreach (var type in root.DescendantNodes().OfType<TypeDeclarationSyntax>())
            {
                if (type.Modifiers.Any(SyntaxKind.PartialKeyword))
                {
                    Report(Rules.PartialType, type.Identifier.ValueText, "another part of a partial type can be in a file "
                        + "the scan does not take for a bbs-2023 test file, with a constructor that runs before the "
                        + "tests here or the attributes of a member declared here. Do not use one in a bbs-2023 test file.");
                }

                if (type is ClassDeclarationSyntax or RecordDeclarationSyntax
                    && !type.Modifiers.Any(SyntaxKind.SealedKeyword) && !type.Modifiers.Any(SyntaxKind.StaticKeyword)
                    && type.Members.OfType<MethodDeclarationSyntax>().Any(member => TestAttributesOf(member).Count > 0))
                {
                    Report(Rules.UnsealedTestClass, type.Identifier.ValueText, "a class in another file can derive from it, "
                        + "inherit its tests and run a constructor before them. Seal the class.");
                }

                foreach (var baseType in (type.BaseList?.Types ?? []).Select(b => SimpleNameOf(b.Type)).Where(n => !KnownBaseTypes.Contains(n)))
                {
                    Report(Rules.BaseType, type.Identifier.ValueText, $"it derives from {baseType}. A base class can bring "
                        + "tests, or a member named like the helper, from another file. Add the name to KnownBaseTypes "
                        + "if it is an interface or brings neither.");
                }
            }

            // A skip that runs before the first statement of a test turns the helper's failure into a skip:
            // in a constructor, an initializer, InitializeAsync or the data of a theory. So only the body
            // of a test may name what skips, and the helper itself. The attributes of a test are not its
            // body: an argument there can hand the skip to its data.
            foreach (var type in root.DescendantNodes().OfType<IdentifierNameSyntax>().Where(NamesWhatSkips)
                         .Where(name => !name.Ancestors().Any(node =>
                             node is BlockSyntax or ArrowExpressionClauseSyntax
                                 && node.Parent is MethodDeclarationSyntax method && TestAttributesOf(method).Count > 0
                             || node is BaseTypeDeclarationSyntax { Identifier.ValueText: HelperType }))
                         .Select(name => name.Ancestors().OfType<BaseTypeDeclarationSyntax>().FirstOrDefault()?.Identifier.ValueText ?? "(file)")
                         .Distinct())
            {
                Report(Rules.SkipOutsideATest, type, "it names Skip, SkipException or Enforce outside the body of a test. A "
                    + "skip in a constructor, an initializer, InitializeAsync, the data of a theory or an attribute's "
                    + "argument runs before the helper call and turns its failure into a skip. Skip in the body of "
                    + "the test, after the call. "
                    + "(A method of another kind that is called Skip, as LINQ's is, is reported too: the scan cannot "
                    + "tell them apart.)");
            }
        }

        foreach (var (file, _) in helperTypes.Where(h => h.FileHasTests || helperTypes.Count > 1))
        {
            findings.Add(new Finding(Rules.HelperShadowed, HelperType, file,
                $"there must be one type named {HelperType}, in a file without tests; a second one could be called in its place."));
        }

        foreach (var stale in needNoNativeLibrary.Where(id => !listed.Contains(id)))
        {
            findings.Add(new Finding(Rules.StaleListing, stale, "(list)", "the list names a test that the scan did not find in a bbs-2023 test file."));
        }

        return new Result(findings, guarded, listed, bbsFiles);
    }

    // What a decoder puts in the place of bytes that are not UTF-8.
    private const char ReplacementCharacter = '\uFFFD';

    // A file with one of these has code the build may or may not compile. `#if` opens every condition: an
    // `#elif` or `#else` without one is a syntax error. `#define` and `#undef` are reported with it,
    // because a symbol also decides which calls of a [Conditional] method are compiled.
    private static bool IsConditionalCompilation(SyntaxTrivia trivia) => trivia.Kind() is
        SyntaxKind.IfDirectiveTrivia or SyntaxKind.DefineDirectiveTrivia or SyntaxKind.UndefDirectiveTrivia;

    // Names in code only: comments and documentation are trivia, not tokens, and there is no disabled text
    // to miss, because conditional compilation is reported before this is asked. The value of a token is
    // used, not its spelling, so that an escape or an invisible character changes nothing.
    private static bool TouchesBbs(CompilationUnitSyntax root) =>
        root.DescendantTokens().Any(token =>
            (token.IsKind(SyntaxKind.IdentifierToken) && token.ValueText.Contains("bbs", StringComparison.OrdinalIgnoreCase))
            || (IsStringToken(token) && NamesBbsInAString.IsMatch(token.ValueText)))
        || root.DescendantNodes().OfType<AttributeSyntax>().Any(IsBbsCategoryTrait);

    // In a string, the suite's name in any case, or a name that begins with Bbs or IBbs. Just "bbs"
    // anywhere would take in any file with a long enough base64 value in it. (Not a generated regex: that
    // is a partial method, which this scan reports in a file that names bbs-2023, as this one does.)
    private static readonly Regex NamesBbsInAString =
        new("(?i:bbs-?2023)|(?<![A-Za-z0-9+/=_-])I?Bbs(?![a-z])", RegexOptions.CultureInvariant);

    private static bool IsStringToken(SyntaxToken token) => token.Kind() is
        SyntaxKind.StringLiteralToken or SyntaxKind.Utf8StringLiteralToken
        or SyntaxKind.InterpolatedStringTextToken
        or SyntaxKind.SingleLineRawStringLiteralToken or SyntaxKind.MultiLineRawStringLiteralToken
        or SyntaxKind.Utf8SingleLineRawStringLiteralToken or SyntaxKind.Utf8MultiLineRawStringLiteralToken;

    // A type, a delegate or an alias named like a name the scan trusts gives that name another meaning: a
    // TraitAttribute that derives from FactAttribute makes [Trait] a test attribute, a TheoryData of the
    // project's own can skip in its constructor, and a Task with a method builder of its own can swallow
    // what the helper throws. Checked in every file.
    private static void CheckTrustedNames(CompilationUnitSyntax root, string path, Action<string, string, string> report)
    {
        static bool IsTrusted(string name) =>
            KnownAttributes.Contains(name) || KnownAttributes.Any(known => name == known + "Attribute")
            || KnownBaseTypes.Contains(name) || name == TaskType || name == DeclaredAttributeBase;

        foreach (var declaration in root.DescendantNodes().OfType<MemberDeclarationSyntax>())
        {
            var name = declaration switch
            {
                BaseTypeDeclarationSyntax type => type.Identifier.ValueText,
                DelegateDeclarationSyntax @delegate => @delegate.Identifier.ValueText,
                _ => null,
            };
            var isTheDeclaredOne = name == DeclaredAttribute
                && System.IO.Path.GetFileName(path.Replace('\\', '/')) == DeclaredAttributeFile
                && declaration is ClassDeclarationSyntax { BaseList.Types: [{ Type: IdentifierNameSyntax { Identifier.ValueText: DeclaredAttributeBase } }] };
            if (name is not null && IsTrusted(name) && !isTheDeclaredOne)
            {
                report(Rules.NameShadowed, name, "a type named like one this scan trusts would be used in its place, "
                    + "and the scan could not tell. Give it another name.");
            }
        }

        foreach (var alias in root.DescendantNodes().OfType<UsingDirectiveSyntax>().Where(u => u.Alias is not null))
        {
            var name = alias.Alias!.Name.Identifier.ValueText;
            if (IsTrusted(name))
            {
                report(Rules.NameShadowed, name, "an alias named like a type this scan trusts gives that name another "
                    + "meaning. Give it another name.");
            }
            else if (name == HelperType)
            {
                report(Rules.Alias, name, "an alias named like the helper sends the call somewhere else. Remove it.");
            }
        }
    }

    private static bool IsStatic(UsingDirectiveSyntax import) => import.StaticKeyword.IsKind(SyntaxKind.StaticKeyword);

    // The checks that are about a bbs-2023 test file as a whole.
    private static void CheckFile(CompilationUnitSyntax root, Action<string, string, string> report)
    {
        foreach (var import in root.DescendantNodes().OfType<UsingDirectiveSyntax>().Where(u => IsStatic(u) && !u.GlobalKeyword.IsKind(SyntaxKind.GlobalKeyword)))
        {
            report(Rules.StaticImport, import.Name?.ToString() ?? "(using static)", "a static import can bring in a member "
                + "named like the helper, from a file the scan would not connect with this one. Do not use one in a "
                + "bbs-2023 test file.");
        }

        foreach (var alias in root.DescendantNodes().OfType<ExternAliasDirectiveSyntax>())
        {
            report(Rules.Alias, alias.Identifier.ValueText, "an extern alias can rename anything. Do not use one in a bbs-2023 test file.");
        }

        // A variable, parameter or member named like the helper would be called in its place. Types of
        // that name are counted across all files by the caller.
        foreach (var token in root.DescendantTokens().Where(t =>
                     t.IsKind(SyntaxKind.IdentifierToken) && t.ValueText == HelperType
                     && t.Parent is not IdentifierNameSyntax and not BaseTypeDeclarationSyntax))
        {
            report(Rules.HelperShadowed, HelperType, $"line {token.GetLocation().GetLineSpan().StartLinePosition.Line + 1} "
                + $"declares something named {HelperType}; a call to it would not be the helper.");
        }
    }

    // What skips, named in a way that can run it. `SkipException` and `Enforce` wherever they are named.
    // `Skip` too, unless it only reads a member of that name, as `Outcome.Skip` does, or names an argument:
    // `Skip = "..."` on an attribute is the static-skip rule's.
    private static bool NamesWhatSkips(IdentifierNameSyntax name) =>
        WhatSkips.Contains(name.Identifier.ValueText)
        && (name.Identifier.ValueText != "Skip" || !(ReadsAMember(name) || name.Parent is NameEqualsSyntax));

    // `x.Name` where nothing is done with it but to take its value: it is not called, and no member of it
    // is taken.
    private static bool ReadsAMember(IdentifierNameSyntax name) =>
        name.Parent is MemberAccessExpressionSyntax access && access.Name == name
        && access.Parent is not InvocationExpressionSyntax and not MemberAccessExpressionSyntax;

    // Every attribute written on the method, whatever its list says it applies to: the target can be
    // spelled in ways that are not the keyword, and a test attribute compiles under none but the method's.
    private static IEnumerable<AttributeSyntax> AttributesOf(MethodDeclarationSyntax method) =>
        method.AttributeLists.SelectMany(list => list.Attributes);

    private static List<AttributeSyntax> TestAttributesOf(MethodDeclarationSyntax method) =>
        AttributesOf(method).Where(a => IsTestAttribute(SimpleNameOf(a))).ToList();

    private static bool IsTestAttribute(string simpleName) =>
        SkippableTestAttributes.Contains(simpleName) || PlainTestAttributes.Contains(simpleName);

    private static bool HasStaticSkip(AttributeSyntax attribute) =>
        attribute.ArgumentList?.Arguments.Any(a => a.NameEquals?.Name.Identifier.ValueText == "Skip") == true;

    // The last name of an attribute, without a namespace, an alias qualifier or the "Attribute" suffix.
    private static string SimpleNameOf(AttributeSyntax attribute)
    {
        var name = SimpleNameOf(attribute.Name);
        return name.Length > "Attribute".Length && name.EndsWith("Attribute", StringComparison.Ordinal)
            ? name[..^"Attribute".Length]
            : name;
    }

    private static string SimpleNameOf(TypeSyntax name) => name switch
    {
        QualifiedNameSyntax qualified => qualified.Right.Identifier.ValueText,
        AliasQualifiedNameSyntax aliasQualified => aliasQualified.Name.Identifier.ValueText,
        SimpleNameSyntax simple => simple.Identifier.ValueText,
        _ => name.ToString(),
    };

    // [Trait("Category", "Bbs")], with both arguments written as string literals, on the method or on the
    // class it is in. xUnit does not pass a trait from an outer class down to a nested one.
    private static bool IsInBbsCategory(MethodDeclarationSyntax method) =>
        AttributesOf(method).Any(IsBbsCategoryTrait)
        || (method.Parent is BaseTypeDeclarationSyntax type
            && type.AttributeLists.SelectMany(list => list.Attributes).Any(IsBbsCategoryTrait));

    private static bool IsBbsCategoryTrait(AttributeSyntax attribute) =>
        SimpleNameOf(attribute) == "Trait"
        && attribute.ArgumentList is { Arguments: { Count: 2 } arguments }
        && arguments.All(a => a.NameEquals is null && a.NameColon is null)
        && StringValueOf(arguments[0].Expression) == "Category"
        && StringValueOf(arguments[1].Expression) == "Bbs";

    private static string? StringValueOf(ExpressionSyntax expression) =>
        expression is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression)
            ? literal.Token.ValueText
            : null;

    // The body is a block, and its first statement is exactly `BbsNativeLibrary.RequireOrSkip();`. First,
    // so that the call cannot sit in dead code, in a lambda that is never invoked or after a return.
    private static bool BeginsWithTheHelperCall(MethodDeclarationSyntax method) =>
        method.Body?.Statements.FirstOrDefault() is ExpressionStatementSyntax
        {
            Expression: InvocationExpressionSyntax
            {
                ArgumentList.Arguments.Count: 0,
                Expression: MemberAccessExpressionSyntax
                {
                    RawKind: (int)SyntaxKind.SimpleMemberAccessExpression,
                    Name: IdentifierNameSyntax { Identifier.ValueText: HelperMethod },
                    Expression: var target,
                },
            },
        }
        && HelperTypeSpellings.Contains(SpellingOf(target));

    // void or Task, the two things xUnit 2 runs to the end and sees fail. The name is trusted; a type of
    // the test sources' own that has it is reported in any file.
    private static bool ReturnsVoidOrTask(MethodDeclarationSyntax method) => method.ReturnType switch
    {
        PredefinedTypeSyntax predefined => predefined.Keyword.IsKind(SyntaxKind.VoidKeyword),
        IdentifierNameSyntax or QualifiedNameSyntax { Right: IdentifierNameSyntax } =>
            SimpleNameOf(method.ReturnType) == TaskType,
        _ => false,
    };

    // A name as its identifiers and separators, without trivia and with every identifier by its value.
    // Null for anything that is not written as a name: the value of a string is its text, too. Null also
    // for a name with an identifier `global` in it: `@global::` is an alias, not the global namespace.
    private static string? SpellingOf(ExpressionSyntax name)
    {
        var tokens = name.DescendantTokens().ToList();
        return tokens.All(token => token.Kind() is SyntaxKind.DotToken or SyntaxKind.ColonColonToken or SyntaxKind.GlobalKeyword
                || (token.IsKind(SyntaxKind.IdentifierToken) && token.ValueText != "global"))
            ? string.Concat(tokens.Select(token => token.ValueText))
            : null;
    }

    private static string FullNameOf(MethodDeclarationSyntax method)
    {
        var parts = new Stack<string>();
        parts.Push(method.Identifier.ValueText);
        for (var node = method.Parent; node is not null; node = node.Parent)
        {
            switch (node)
            {
                case BaseTypeDeclarationSyntax type:
                    parts.Push(type.Identifier.ValueText);
                    break;
                case BaseNamespaceDeclarationSyntax @namespace:
                    parts.Push(@namespace.Name.ToString());
                    break;
            }
        }

        return string.Join(".", parts);
    }
}
