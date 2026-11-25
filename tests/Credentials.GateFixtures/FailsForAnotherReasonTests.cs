using DataProofsDotnet.Rdfc.DataIntegrity;
using Xunit;

namespace Credentials.GateFixtures;

/// <summary>
/// Tests of a <c>bbs-2023</c> class that do not call the helper. The first fails without the library, by an
/// assertion of its own: a failure, but not the helper's, and the gate has to report
/// <c>failed-for-another-reason</c>. The second reads a file beside its project and then returns early. The
/// gate copies the project folder as well as the output, so the file is there, the test passes, and the
/// gate has to report <c>passed-without-the-library</c>; with the output alone it would have failed on the
/// missing file and looked guarded.
/// </summary>
[Trait("Category", "Bbs")]
public sealed class FailsForAnotherReasonTests
{
    [Fact]
    public void Fails_by_an_assertion_of_its_own()
    {
        Assert.True(new Bbs2023Cryptosuite().IsAvailable);
    }

    [Fact]
    public async Task Reads_a_vector_beside_the_project_and_returns_early()
    {
        // The vectors sit beside the project file; bin/Release/net10.0 is three folders below it.
        var vector = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Vectors", "mandatory-pointer.txt"));
        var pointer = (await File.ReadAllTextAsync(vector)).Trim();
        if (!new Bbs2023Cryptosuite().IsAvailable)
        {
            return;
        }

        Assert.Equal("/issuer", pointer);
    }
}
