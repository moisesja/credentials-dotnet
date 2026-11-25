using DataProofsDotnet.Rdfc.DataIntegrity;

namespace Credentials.GateFixtures;

/// <summary>A helper that reaches <c>bbs-2023</c> for a test in a file that names nothing of it.</summary>
internal static class Suites
{
    public static bool SelectiveDisclosureIsAvailable() => new Bbs2023Cryptosuite().IsAvailable;
}
