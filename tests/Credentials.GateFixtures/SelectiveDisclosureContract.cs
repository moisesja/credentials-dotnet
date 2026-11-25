using DataProofsDotnet.Rdfc.DataIntegrity;
using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// A base class of tests, in a file that names <c>bbs-2023</c>. Its test returns early without the
/// library. It runs as a test of the class that derives from it, <see cref="DefaultWiringContractTests"/>,
/// whose own file names nothing of the suite; that class is a <c>bbs-2023</c> class all the same, and the
/// gate has to report <c>passed-without-the-library</c> under its name.
/// </summary>
public abstract class SelectiveDisclosureContract
{
    [Fact]
    public void A_base_proof_can_be_signed()
    {
        if (!new Bbs2023Cryptosuite().IsAvailable)
        {
            return;
        }

        Assert.Equal("bbs-2023", Bbs2023Cryptosuite.CryptosuiteName);
    }
}

/// <summary>A test under a display name that is the end of its full name, for which a result file gives
/// the namespace as the class. The gate has to report it under its full name.</summary>
public sealed class Bbs2023NamedTests
{
    [Fact(DisplayName = "Bbs2023NamedTests.Named_by_class_and_method")]
    public void Named_by_class_and_method()
    {
        if (!new Bbs2023Cryptosuite().IsAvailable)
        {
            return;
        }

        Assert.Equal("bbs-2023", Bbs2023Cryptosuite.CryptosuiteName);
    }
}
