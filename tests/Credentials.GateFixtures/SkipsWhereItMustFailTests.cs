using Credentials.TestSupport;
using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// The test begins with the helper call, and the constructor skips before the test is reached. Where the
/// library has to load, the call would fail the test; the skip comes first. The gate has to report
/// <c>skipped-without-the-library</c>.
/// </summary>
[Trait("Category", "Bbs")]
public sealed class SkipsWhereItMustFailTests
{
    public SkipsWhereItMustFailTests()
    {
        Skip.IfNot(BbsNativeLibrary.IsAvailable, "bbs-2023 needs the native library");
    }

    [SkippableFact]
    public void Guarded_and_skipped_by_the_constructor()
    {
        BbsNativeLibrary.RequireOrSkip();
    }
}
