using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// Nothing in this file names the suite, not even its namespace, which is why this project is not named
/// after the gate. So its class is outside the scope the scan draws. The first test
/// needs the native library all the same, through a helper in another file, and fails without it. The gate
/// compares every test, and has to report <c>outcome-changed-outside-bbs-2023</c> for it. The second is
/// an ordinary test.
/// </summary>
public sealed class OrdinaryTests
{
    [Fact]
    public void Reaches_the_suite_through_another_file()
    {
        Assert.True(Suites.SelectiveDisclosureIsAvailable());
    }

    [Fact]
    public void Adds()
    {
        Assert.Equal(2, 1 + 1);
    }
}
