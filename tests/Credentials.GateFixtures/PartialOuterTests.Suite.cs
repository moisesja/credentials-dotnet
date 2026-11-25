using Credentials.TestSupport;
using Xunit;

namespace Credentials.GateFixtures;

/// <summary>The part of a partial class that names <c>bbs-2023</c>. Its test is guarded.</summary>
public sealed partial class PartialOuterTests
{
    [SkippableFact]
    public void In_the_part_that_names_the_suite()
    {
        BbsNativeLibrary.RequireOrSkip();
    }
}
