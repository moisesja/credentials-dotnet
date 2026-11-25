using DataProofsDotnet.Rdfc.DataIntegrity;
using Xunit;

/// <summary>
/// A test class without a namespace, its test under a display name that is the end of its full name. A
/// result file then gives the name of the assembly as the class. The gate knows a test of a
/// <c>bbs-2023</c> class by the class's own name and has to report <c>passed-without-the-library</c>.
/// </summary>
public sealed class Bbs2023ShortNameTests
{
    [Fact(DisplayName = "ShortNameTests.Named_from_inside_the_class_name")]
    public void Named_from_inside_the_class_name()
    {
        if (!new Bbs2023Cryptosuite().IsAvailable)
        {
            return;
        }

        Assert.Equal("bbs-2023", Bbs2023Cryptosuite.CryptosuiteName);
    }
}
