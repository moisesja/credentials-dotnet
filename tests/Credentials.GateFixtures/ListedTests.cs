using Credentials.TestSupport;
using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// Both tests are on this project's list of tests that need no native library. The first does need it, so
/// the gate has to report <c>listed-test-did-not-pass</c>; the second passes without it and is in order.
/// </summary>
public sealed class ListedTests
{
    [SkippableFact]
    public void Listed_and_needs_the_library()
    {
        BbsNativeLibrary.RequireOrSkip();
    }

    [Fact]
    public void Listed_and_needs_no_library()
    {
        Assert.Equal(5, BbsNativeLibrary.ShippedRuntimeIdentifiers.Count);
    }
}
