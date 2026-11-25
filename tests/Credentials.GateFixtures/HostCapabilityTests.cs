using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// Nothing in this file names the suite. The theory has one row for a host with the native library and one
/// for a host without, and skips the row that is not for this host: with the library it is passed and
/// skipped, without it skipped and passed. The outcomes are the same and the rows have traded places; the
/// gate compares row for row and has to report <c>outcome-changed-outside-bbs-2023</c>.
/// </summary>
public sealed class HostCapabilityTests
{
    [SkippableTheory]
    [InlineData(true)]
    [InlineData(false)]
    public void Selective_disclosure_does_what_the_host_can_do(bool nativeProofs)
    {
        Skip.If(nativeProofs != Suites.SelectiveDisclosureIsAvailable(), "this row is for the other kind of host");
        Assert.Equal(nativeProofs, Suites.SelectiveDisclosureIsAvailable());
    }
}
