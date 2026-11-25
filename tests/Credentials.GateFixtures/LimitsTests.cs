using Credentials.TestSupport;
using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// Two things the gate does not see, kept here so that they are stated by code and not only in words. It
/// reports neither test, and <c>expected-findings.txt</c> has neither.
/// </summary>
[Trait("Category", "Bbs")]
public sealed class LimitsTests
{
    private static string Recorded => Path.Combine(AppContext.BaseDirectory, "recorded-by-an-earlier-test.txt");

    // The gate runs on the platforms of the CI legs, and NetCrypto ships the library for each of them. On
    // a platform it does not ship for, this test is skipped before the call, where the call would fail it
    // on GitHub Actions. No run of the gate is on such a platform.
    [SkippableFact]
    public void Skips_on_a_platform_the_library_is_not_shipped_for()
    {
        Skip.IfNot(BbsNativeLibrary.IsShippedForHost, $"NetCrypto ships no BBS library for {BbsNativeLibrary.HostRuntimeIdentifier}.");
        BbsNativeLibrary.RequireOrSkip();
    }

    // The second run starts from a copy of the output folder as the first run left it. The file is there,
    // so this test reaches the call and fails by it. On a host where the library never loaded no test
    // would have written the file, and this one would be skipped.
    [SkippableFact]
    public void Depends_on_what_an_earlier_run_left_beside_the_assembly()
    {
        if (BbsNativeLibrary.IsAvailable)
        {
            File.WriteAllText(Recorded, "bbs-2023");
        }

        Skip.IfNot(File.Exists(Recorded), "Nothing has been recorded on this host yet.");
        BbsNativeLibrary.RequireOrSkip();
    }
}
