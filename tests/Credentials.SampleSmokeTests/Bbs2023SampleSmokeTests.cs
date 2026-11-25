using Credentials.TestSupport;
using Xunit;

namespace Credentials.SampleSmokeTests;

/// <summary>
/// The smoke test of the <c>bbs-2023</c> sample, in a class and a file of its own (see the remarks on
/// <see cref="SampleSmokeTests"/>).
/// </summary>
public sealed class Bbs2023SampleSmokeTests
{
    // The bbs-2023 sample needs NetCrypto's native BBS library and throws without it. Without the library this
    // test fails where the library has to load and is skipped, with a reason, elsewhere; it is never reported
    // as passed (issue #57).
    [SkippableFact]
    [Trait("Category", "Bbs")]
    public Task Bbs2023()
    {
        BbsNativeLibrary.RequireOrSkip();
        return SampleSmokeTests.Run(Samples.Bbs2023.Program.RunAsync);
    }
}
