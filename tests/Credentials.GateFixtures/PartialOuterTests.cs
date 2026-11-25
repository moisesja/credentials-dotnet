using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// The other part of the class, in a file that names nothing of the suite, with a test class nested in it.
/// A type nested in a <c>bbs-2023</c> class is one, wherever it is written; the gate has to report
/// <c>passed-without-the-library</c> for the nested test.
/// </summary>
public sealed partial class PartialOuterTests
{
    public sealed class Inner
    {
        [Fact]
        public void In_a_class_nested_in_the_other_part()
        {
            if (!Suites.SelectiveDisclosureIsAvailable())
            {
                return;
            }

            Assert.True(Suites.SelectiveDisclosureIsAvailable());
        }
    }
}
