using Credentials.TestSupport;
using DataProofsDotnet.Rdfc.DataIntegrity;
using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// What a <c>bbs-2023</c> test has to look like: these fail without the native library, and the gate has
/// nothing to say about them. The self-test uses the first as its availability check.
/// </summary>
[Trait("Category", "Bbs")]
public sealed class GuardedTests
{
    [SkippableFact]
    public void The_native_library_loads()
    {
        BbsNativeLibrary.RequireOrSkip();
        Assert.True(new Bbs2023Cryptosuite().IsAvailable);
    }

    [SkippableTheory]
    [InlineData("/credentialSubject/gpa")]
    [InlineData("/credentialSubject/alumniOf")]
    public void A_guarded_theory(string pointer)
    {
        BbsNativeLibrary.RequireOrSkip();
        Assert.StartsWith("/", pointer);
    }
}
