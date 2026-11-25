using DataProofsDotnet.Rdfc.DataIntegrity;
using Xunit;

namespace Credentials.GateFixtures.Support;

/// <summary>
/// A base class of tests in a support library, in a file that names <c>bbs-2023</c>. Its test returns early
/// without the library. It runs in the fixture project, two classes further down.
/// </summary>
public abstract class SupportContract
{
    [Fact]
    public void Inherited_through_a_support_assembly()
    {
        if (!new Bbs2023Cryptosuite().IsAvailable)
        {
            return;
        }

        Assert.Equal("bbs-2023", Bbs2023Cryptosuite.CryptosuiteName);
    }
}
