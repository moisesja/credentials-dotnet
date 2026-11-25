using Credentials.TestSupport;
using DataProofsDotnet.Rdfc.DataIntegrity;
using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// A theory whose rows exist only where the native library loaded. Its body begins with the helper call,
/// and without the library the body never runs: there are no rows, and xUnit reports nothing for the
/// test. The gate has to report <c>no-result-without-the-library</c>.
/// </summary>
[Trait("Category", "Bbs")]
public sealed class RowsThatEndEarlyTests
{
    public static IEnumerable<object[]> RevealPointers()
    {
        if (!new Bbs2023Cryptosuite().IsAvailable)
        {
            yield break;
        }

        yield return ["/credentialSubject/gpa"];
        yield return ["/credentialSubject/alumniOf"];
    }

    [SkippableTheory]
    [MemberData(nameof(RevealPointers), DisableDiscoveryEnumeration = true)]
    public void Rows_that_end_early(string pointer)
    {
        BbsNativeLibrary.RequireOrSkip();
        Assert.StartsWith("/", pointer);
    }
}

/// <summary>
/// A theory whose rows are built once and kept, as a test does whose vectors are slow to sign. Without the
/// library the first enumeration throws after the empty list has been stored; xUnit falls back to one test
/// case without a word, and the second enumeration returns the empty list. Nothing is reported for the
/// test. The gate has to report <c>no-result-without-the-library</c>.
/// </summary>
[Trait("Category", "Bbs")]
public sealed class CachedRowsTests
{
    private static List<object[]>? _vectors;

    public static IEnumerable<object[]> Vectors()
    {
        if (_vectors is null)
        {
            _vectors = [];
            foreach (var pointer in (string[])["/credentialSubject/gpa", "/credentialSubject/alumniOf"])
            {
                _vectors.Add([pointer, Sign(pointer)]);
            }
        }

        return _vectors;
    }

    [SkippableTheory]
    [MemberData(nameof(Vectors))]
    public void Rows_built_once_and_kept(string pointer, string signed)
    {
        BbsNativeLibrary.RequireOrSkip();
        Assert.EndsWith(pointer, signed);
    }

    private static string Sign(string pointer) => new Bbs2023Cryptosuite().IsAvailable
        ? "signed:" + pointer
        : throw new NotSupportedException("signing a base credential needs the native library");
}
