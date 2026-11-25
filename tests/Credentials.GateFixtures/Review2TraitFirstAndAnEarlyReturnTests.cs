using DataProofsDotnet.Rdfc.DataIntegrity;
using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// The second case of the review of PR #72: the test attribute is written second in its list, after the
/// trait, and the body returns early. A scan that looked for a test attribute at the start of a line did
/// not see a test. Without the library it passes; the gate has to report <c>passed-without-the-library</c>.
/// </summary>
public sealed class Review2TraitFirstAndAnEarlyReturnTests
{
    [Trait("Category", "Bbs"), SkippableFact]
    public void Trait_first_and_an_early_return()
    {
        if (!new Bbs2023Cryptosuite().IsAvailable)
        {
            return;
        }

        Assert.Equal("bbs-2023", Bbs2023Cryptosuite.CryptosuiteName);
    }
}
