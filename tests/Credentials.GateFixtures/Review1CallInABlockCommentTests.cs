using Credentials.TestSupport;
using DataProofsDotnet.Rdfc.DataIntegrity;
using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// The first case of the review of PR #72: the helper call is there as text, inside a block comment. A scan
/// of the sources as text took it for a call. Without the library the test returns early and passes; the
/// gate has to report <c>passed-without-the-library</c>.
/// </summary>
[Trait("Category", "Bbs")]
public sealed class Review1CallInABlockCommentTests
{
    [SkippableFact]
    public void The_call_is_in_a_block_comment()
    {
        /* BbsNativeLibrary.RequireOrSkip(); */
        if (!new Bbs2023Cryptosuite().IsAvailable)
        {
            return;
        }

        Assert.True(BbsNativeLibrary.IsAvailable);
    }
}
