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
/// <para><b>Scope.</b> A file is a <c>bbs-2023</c> test file when its code, not its comments, has an
/// identifier that contains "bbs" in any letter case, a string that names the suite or one of its types, or
/// the <c>Bbs</c> category trait. Every test in such a file is checked, whichever class it is in.</para>
/// <para><b>The rule.</b> Each of those tests either is a <c>[SkippableFact]</c> or
/// <c>[SkippableTheory]</c> that returns <c>void</c> or a task, whose body's first statement is the call,
/// and that is in the <c>Bbs</c> category; or it is named on the caller's list of tests that need no
/// native library.</para>
/// <para><b>What the scan does not understand, it reports.</b> A syntax tree has no types, so the scan
/// cannot follow a custom test attribute, a base class or another thing named like the helper. In a
/// <c>bbs-2023</c> test file those are findings, as are a syntax error, conditional compilation, a partial
/// method and a static import. A type or an alias named like an attribute the scan knows is a finding in
/// any test file, because it would change what that attribute means everywhere.</para>
/// <para><b>What it cannot see.</b> It reads the C# sources under <c>tests/</c> and nothing else, and it
/// reads names, not what they resolve to. It does not see:</para>
/// <list type="bullet">
/// <item>a test that reaches <c>bbs-2023</c> only through code in another file, in a file that names nothing
/// of it: a shared provider factory, a stored credential, a loop over the registered suites;</item>
/// <item>what the build takes from anywhere else: a project file, generated code, a source file outside
/// <c>tests/</c>, another assembly. Any of those can give the helper's name or an attribute's name a
/// different meaning;</item>
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

    private static readonly string[] SkippableTestAttributes = ["SkippableFact", "SkippableTheory"];
    private static readonly string[] PlainTestAttributes = ["Fact", "Theory"];

    // Every attribute a method in a bbs-2023 test file may carry: the test attributes, what goes with
    // them, and a few from the base library that cannot make a method a test. Any other name could be a
    // test attribute the scan cannot recognise (a custom one, or an alias), so it is a finding until it is
    // added here.
    private static readonly string[] KnownMethodAttributes =
    [
        .. SkippableTestAttributes, .. PlainTestAttributes,
        "Trait", "FrTag", "InlineData", "MemberData", "ClassData",
        "Obsolete", "MethodImpl", "GeneratedRegex", "SuppressMessage", "DoesNotReturn", "DebuggerStepThrough",
    ];

    // The one known attribute that the test sources declare themselves, and the file that declares it.
    private const string DeclaredAttribute = "FrTagAttribute";
    private const string DeclaredAttributeFile = "FrTagAttribute.cs";

    // What a type in a bbs-2023 test file may list after its name. Anything else could be a base class
    // that brings tests, or members named like the helper, from another file.
    private static readonly string[] KnownBaseTypes =
    [
        "IDisposable", "IAsyncDisposable", "IAsyncLifetime", "IClassFixture", "ICollectionFixture",
        "IEquatable", "TheoryData", "Exception", "AssemblyLoadContext",
    ];

    // The two spellings of the helper type the first statement may use. Neither can be made to mean a
    // field or a property: the scan reports anything else declared with the bare name, and nothing
    // declared in a class can stand in for `global::`.
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

        /// <summary>A test neither begins with the helper call under a skippable attribute nor is listed.</summary>
        public const string UnguardedTest = "unguarded-test";

        /// <summary>An attribute of a test carries <c>Skip = "..."</c>: the test, or a row of it, would never run.</summary>
        public const string StaticSkip = "static-skip";

        /// <summary>A test attribute has an argument without a name: for a skippable one, an exception type that turns a failure into a skip.</summary>
        public const string TestAttributeArguments = "test-attribute-arguments";

        /// <summary>A test returns something other than <c>void</c> or a task, so its body may never run.</summary>
        public const string ReturnType = "return-type";

        /// <summary>A guarded test is not in the <c>Bbs</c> category.</summary>
        public const string NotInCategory = "not-in-category";

        /// <summary>A method carries an attribute the scan does not know.</summary>
        public const string UnknownAttribute = "unknown-attribute";

        /// <summary>A type or an alias is named like an attribute the scan knows.</summary>
        public const string AttributeShadowed = "attribute-shadowed";

        /// <summary>A type lists a base type the scan does not know.</summary>
        public const string BaseType = "base-type";

        /// <summary>A partial method: its attributes may be in another file.</summary>
        public const string PartialMethod = "partial-method";

        /// <summary>The file uses conditional compilation, so the scan may not see what is compiled.</summary>
        public const string ConditionalCompilation = "conditional-compilation";

        /// <summary>The file imports the static members of a type, which may include one named like the helper.</summary>
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
    /// Whether a path under <c>tests/</c> is the build output of a test project: its <c>bin</c> or
    /// <c>obj</c> folder. A folder of that name further down is compiled like any other, so it is scanned.
    /// </summary>
    /// <param name="pathUnderTests">The path relative to <c>tests/</c>.</param>
    public static bool IsProjectBuildOutput(string pathUnderTests)
    {
        var parts = pathUnderTests.Split('/', '\\');
        return parts.Length > 2 && parts[1] is "bin" or "obj";
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
            var tree = CSharpSyntaxTree.ParseText(
                source.Text, new CSharpParseOptions(LanguageVersion.Latest), source.Path);
            var root = tree.GetCompilationUnitRoot();
            void Report(string rule, string subject, string detail) =>
                findings.Add(new Finding(rule, subject, source.Path, detail));

            var errors = tree.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
            if (errors.Count > 0)
            {
                Report(Rules.SyntaxError, "(file)", "the file does not parse, so it cannot be checked: " + errors[0].GetMessage());
                continue;
            }

            var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>().ToList();
            var fileHasTests = methods.Any(m => TestAttributesOf(m).Count > 0);
            helperTypes.AddRange(root.DescendantNodes().OfType<BaseTypeDeclarationSyntax>()
                .Where(type => type.Identifier.ValueText == HelperType)
                .Select(_ => (source.Path, fileHasTests)));

            // These two change what a name means in every file that sees them, so they are checked in
            // every file, a bbs-2023 test file or not.
            CheckNamesOfKnownAttributes(root, source.Path, Report);

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

            foreach (var method in methods)
            {
                var id = FullNameOf(method);

                foreach (var unknown in AttributesOf(method).Select(SimpleNameOf).Where(n => !KnownMethodAttributes.Contains(n)))
                {
                    Report(Rules.UnknownAttribute, id, $"[{unknown}] is not an attribute this scan knows. It could make "
                        + "the method a test. Use a plain xUnit attribute, or add the name to KnownMethodAttributes.");
                }

                if (method.Modifiers.Any(SyntaxKind.PartialKeyword))
                {
                    Report(Rules.PartialMethod, id, "a partial method can have its test attribute in another file. "
                        + "Do not use one in a bbs-2023 test file.");
                }

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

                if (!ReturnsVoidOrATask(method))
                {
                    Report(Rules.ReturnType, id, $"it returns {method.ReturnType}. xUnit does not enumerate or await "
                        + "that, so the body, the helper call included, may never run. Return void, Task or ValueTask.");
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
                foreach (var baseType in (type.BaseList?.Types ?? []).Select(b => SimpleNameOf(b.Type)).Where(n => !KnownBaseTypes.Contains(n)))
                {
                    Report(Rules.BaseType, type.Identifier.ValueText, $"it derives from {baseType}. A base class can bring "
                        + "tests, or a member named like the helper, from another file. Add the name to KnownBaseTypes "
                        + "if it is an interface or brings neither.");
                }
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

    // Names in code only: comments, documentation and disabled text are trivia, not tokens. The value of a
    // token is used, not its spelling, so that an escape or an invisible character changes nothing.
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

    // A type or an alias named like an attribute the scan knows gives that attribute another meaning: a
    // TraitAttribute that derives from FactAttribute makes [Trait] a test attribute. Checked in every file.
    private static void CheckNamesOfKnownAttributes(CompilationUnitSyntax root, string path, Action<string, string, string> report)
    {
        static bool IsKnownAttributeName(string name) =>
            KnownMethodAttributes.Contains(name) || KnownMethodAttributes.Any(known => name == known + "Attribute");

        foreach (var type in root.DescendantNodes().OfType<BaseTypeDeclarationSyntax>()
                     .Where(t => IsKnownAttributeName(t.Identifier.ValueText)))
        {
            var isTheDeclaredOne = type.Identifier.ValueText == DeclaredAttribute
                && System.IO.Path.GetFileName(path.Replace('\\', '/')) == DeclaredAttributeFile;
            if (!isTheDeclaredOne)
            {
                report(Rules.AttributeShadowed, type.Identifier.ValueText, "a type named like an attribute this scan "
                    + "knows would be used in its place, and the scan could not tell. Give it another name.");
            }
        }

        foreach (var alias in root.DescendantNodes().OfType<UsingDirectiveSyntax>().Where(u => u.Alias is not null))
        {
            var name = alias.Alias!.Name.Identifier.ValueText;
            if (IsKnownAttributeName(name))
            {
                report(Rules.AttributeShadowed, name, "an alias named like an attribute this scan knows gives that "
                    + "attribute another meaning. Give it another name.");
            }
            else if (name == HelperType)
            {
                report(Rules.Alias, name, "an alias named like the helper sends the call somewhere else. Remove it.");
            }
        }
    }

    // The checks that are about a bbs-2023 test file as a whole.
    private static void CheckFile(CompilationUnitSyntax root, Action<string, string, string> report)
    {
        var conditional = root.DescendantTrivia(descendIntoTrivia: true).FirstOrDefault(trivia => trivia.Kind() is
            SyntaxKind.IfDirectiveTrivia or SyntaxKind.ElifDirectiveTrivia or SyntaxKind.ElseDirectiveTrivia
            or SyntaxKind.DefineDirectiveTrivia or SyntaxKind.UndefDirectiveTrivia);
        if (!conditional.IsKind(SyntaxKind.None))
        {
            report(Rules.ConditionalCompilation, "(file)", $"'{conditional.ToString().Trim()}': with conditional compilation "
                + "the scan may not see the code that is compiled. Do not use it in a bbs-2023 test file.");
        }

        foreach (var import in root.DescendantNodes().OfType<UsingDirectiveSyntax>().Where(u => u.StaticKeyword.IsKind(SyntaxKind.StaticKeyword)))
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

    // The attributes that apply to the method itself: a list that targets the return value cannot hold a
    // test attribute.
    private static IEnumerable<AttributeSyntax> AttributesOf(MethodDeclarationSyntax method) =>
        method.AttributeLists
            .Where(list => list.Target is null || list.Target.Identifier.IsKind(SyntaxKind.MethodKeyword))
            .SelectMany(list => list.Attributes);

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

    // void, Task or ValueTask, not a generic type: anything else is something xUnit may not run to the end.
    private static bool ReturnsVoidOrATask(MethodDeclarationSyntax method) => method.ReturnType switch
    {
        PredefinedTypeSyntax predefined => predefined.Keyword.IsKind(SyntaxKind.VoidKeyword),
        IdentifierNameSyntax or QualifiedNameSyntax { Right: IdentifierNameSyntax } =>
            SimpleNameOf(method.ReturnType) is "Task" or "ValueTask",
        _ => false,
    };

    // A name as its identifiers and separators, without trivia and with every identifier by its value.
    private static string SpellingOf(ExpressionSyntax name) =>
        string.Concat(name.DescendantTokens().Select(token => token.ValueText));

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
