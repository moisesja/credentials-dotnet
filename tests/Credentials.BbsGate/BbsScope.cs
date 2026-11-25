using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Credentials.BbsGate;

/// <summary>
/// Says which test classes are <c>bbs-2023</c> classes: the types declared in a test source file whose
/// code names anything of <c>bbs-2023</c>. That is all it decides. Whether a test of such a class is
/// guarded is found out by running it without the native library (<see cref="NoLibraryGate"/>), and what
/// a test is, is xUnit's to say.
/// </summary>
/// <remarks>
/// <para><b>Scope.</b> A file names <c>bbs-2023</c> when its code, not its comments, has an identifier
/// that contains "bbs" in any letter case, or a string that names the suite or one of its types (the
/// <c>Bbs</c> category is such a string). Every type declared in such a file is a <c>bbs-2023</c> class.
/// A class that derives from one of them is one too, since it inherits their tests; the gate reads that
/// from the test assemblies (<see cref="TestTypes"/>), not from source.</para>
/// <para><b>One reading of a file.</b> The decision is read off the syntax tree, so the tree has to be the
/// one the build compiles. Three things could make it another, and each is a finding in any test source
/// file: a syntax error, bytes that are not UTF-8, and <c>#if</c>. The scan defines no symbols and does not
/// follow the build's; a file under a condition has more than one reading. It parses at
/// <see cref="Language"/>, the language version of the build.</para>
/// <para><b>What it cannot see.</b> A test in a file that names nothing of <c>bbs-2023</c> is not in scope.
/// If such a test fails or skips without the library, the gate reports it all the same, because it
/// compares every test; if it passes both times, nothing does. And it reads only the files under
/// <c>tests/</c> that a project compiles by default.</para>
/// </remarks>
internal static class BbsScope
{
    /// <summary>
    /// The language version the scan parses at. It has to be the one the build compiles at, because a
    /// later version can read the same text another way; the parser's own latest is a version ahead of the
    /// SDK's. A test compares it with the version the compiler recorded for a test assembly.
    /// </summary>
    public const LanguageVersion Language = LanguageVersion.CSharp14;

    /// <summary>One source file to scan.</summary>
    public sealed record Source(string Path, string Text);

    /// <summary>One file the scan cannot read as the build does.</summary>
    public sealed record Finding(string Rule, string File, string Detail)
    {
        /// <inheritdoc />
        public override string ToString() => $"{Rule} ({File}): {Detail}";
    }

    /// <summary>The outcome of a scan.</summary>
    /// <param name="Findings">The files that have no single reading. Empty when all is well.</param>
    /// <param name="Classes">The <c>bbs-2023</c> classes, each by its full name as the runtime writes it.</param>
    public sealed record Result(IReadOnlyList<Finding> Findings, IReadOnlyList<string> Classes);

    /// <summary>The names of the rules, as they appear in findings.</summary>
    public static class Rules
    {
        /// <summary>The file does not parse.</summary>
        public const string SyntaxError = "syntax-error";

        /// <summary>The file has bytes that are not UTF-8, which the compiler reads by a code page of the machine.</summary>
        public const string NotUtf8 = "not-utf-8";

        /// <summary>The file uses conditional compilation, so the scan may not read what is compiled.</summary>
        public const string ConditionalCompilation = "conditional-compilation";
    }

    /// <summary>
    /// Whether a file under <c>tests/</c> is one a test project compiles by default: a file whose extension
    /// is <c>.cs</c> in any letter case, as the build matches it on every platform, outside the project's
    /// own <c>bin</c> and <c>obj</c> folders. Hidden files count, and so does a file in a folder the build
    /// passes over: scanning more than is compiled costs nothing.
    /// </summary>
    /// <param name="pathUnderTests">The path relative to <c>tests/</c>.</param>
    public static bool IsTestSource(string pathUnderTests)
    {
        var parts = pathUnderTests.Split('/', '\\');
        var isBuildOutput = parts.Length > 2 && parts[1] is "bin" or "obj";
        return pathUnderTests.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) && !isBuildOutput;
    }

    /// <summary>Reads every test source file of the repository, each with its path from the root.</summary>
    /// <param name="repositoryRoot">The folder that holds <c>tests/</c>.</param>
    public static List<Source> ReadSources(string repositoryRoot)
    {
        // Every file is listed and the extension is matched here: a "*.cs" pattern is matched by the
        // letter case of the platform, and on Linux that leaves out a file the build compiles.
        var testsRoot = Path.Combine(repositoryRoot, "tests");
        return Directory.EnumerateFiles(testsRoot, "*", SearchOption.AllDirectories)
            .Where(file => IsTestSource(Path.GetRelativePath(testsRoot, file)))
            .Select(file => new Source(Path.GetRelativePath(repositoryRoot, file), File.ReadAllText(file)))
            .ToList();
    }

    /// <summary>Scans the sources: the files without a single reading, and the <c>bbs-2023</c> classes.</summary>
    public static Result Scan(IEnumerable<Source> sources)
    {
        var findings = new List<Finding>();
        var classes = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var source in sources)
        {
            // What a decoder puts in the place of bytes that are not UTF-8.
            if (source.Text.Contains('\uFFFD'))
            {
                findings.Add(new Finding(Rules.NotUtf8, source.Path, "the file has a replacement character: bytes of it "
                    + "are not UTF-8, or the character is written in it. The compiler reads such bytes by a code page "
                    + "of the machine, so it may not read what the scan reads. Save the file as UTF-8, and write the "
                    + "character as an escape."));
            }

            var tree = CSharpSyntaxTree.ParseText(source.Text, new CSharpParseOptions(Language), source.Path);
            var root = tree.GetCompilationUnitRoot();
            var error = tree.GetDiagnostics().FirstOrDefault(d => d.Severity == DiagnosticSeverity.Error);
            if (error is not null)
            {
                findings.Add(new Finding(Rules.SyntaxError, source.Path, "the file does not parse, so the scan cannot "
                    + "say what it declares: " + error.GetMessage()));
                continue;
            }

            // `#if` opens every condition: an `#elif` or `#else` without one is a syntax error.
            var condition = root.DescendantTrivia().FirstOrDefault(trivia => trivia.IsKind(SyntaxKind.IfDirectiveTrivia));
            if (!condition.IsKind(SyntaxKind.None))
            {
                findings.Add(new Finding(Rules.ConditionalCompilation, source.Path, $"'{condition.ToString().Trim()}': the "
                    + "scan reads one branch of a condition and the build may compile another, which could hold a "
                    + "bbs-2023 test class. Do not use conditional compilation in a test source file; decide at run "
                    + "time instead."));
            }

            if (NamesBbs(root))
            {
                classes.UnionWith(root.DescendantNodes().OfType<BaseTypeDeclarationSyntax>().Select(FullNameOf));
            }
        }

        return new Result(findings, [.. classes]);
    }

    // Names in code only: comments and documentation are trivia, not tokens, and there is no disabled text
    // to miss, because a condition is a finding. The value of a token is used, not its spelling, so that
    // an escape or an invisible character changes nothing.
    private static bool NamesBbs(CompilationUnitSyntax root) =>
        root.DescendantTokens().Any(token =>
            (token.IsKind(SyntaxKind.IdentifierToken) && token.ValueText.Contains("bbs", StringComparison.OrdinalIgnoreCase))
            || (IsStringToken(token) && NamesBbsInAString.IsMatch(token.ValueText)));

    // In a string, the suite's name, or a word that begins with bbs or Ibbs, in any letter case: "Bbs",
    // "BBS", "BbsProof". Just "bbs" anywhere would take in any file with a long enough base64 value in it.
    private static readonly Regex NamesBbsInAString =
        new("(?i:bbs-?2023)|(?<![A-Za-z0-9+/=_-])(?i:I?bbs)(?![a-z])", RegexOptions.CultureInvariant);

    private static bool IsStringToken(SyntaxToken token) => token.Kind() is
        SyntaxKind.StringLiteralToken or SyntaxKind.Utf8StringLiteralToken
        or SyntaxKind.InterpolatedStringTextToken
        or SyntaxKind.SingleLineRawStringLiteralToken or SyntaxKind.MultiLineRawStringLiteralToken
        or SyntaxKind.Utf8SingleLineRawStringLiteralToken or SyntaxKind.Utf8MultiLineRawStringLiteralToken;

    // The full name of a type as the runtime, and so a result file, writes it: the namespace, then the
    // types from the outermost in, joined by '+', each with its number of type parameters.
    private static string FullNameOf(BaseTypeDeclarationSyntax type)
    {
        var types = new Stack<string>();
        var namespaces = new Stack<string>();
        for (SyntaxNode? node = type; node is not null; node = node.Parent)
        {
            switch (node)
            {
                case BaseTypeDeclarationSyntax declared:
                    var arity = (declared as TypeDeclarationSyntax)?.TypeParameterList?.Parameters.Count ?? 0;
                    types.Push(declared.Identifier.ValueText + (arity > 0 ? $"`{arity}" : string.Empty));
                    break;
                case BaseNamespaceDeclarationSyntax @namespace:
                    // By the value of each identifier: `@base` is the namespace `base`.
                    namespaces.Push(string.Join(".", @namespace.Name.DescendantTokens()
                        .Where(token => token.IsKind(SyntaxKind.IdentifierToken)).Select(token => token.ValueText)));
                    break;
            }
        }

        var name = string.Join("+", types);
        return namespaces.Count > 0 ? string.Join(".", namespaces) + "." + name : name;
    }
}
