using Credentials.GateFixtures.Support;

namespace Credentials.GateFixtures;

/// <summary>
/// Nothing here names the suite. The class inherits a test from a <c>bbs-2023</c> class two levels up, and
/// the class between them is in a support assembly that has no test results of its own. The gate reads
/// that assembly too, and has to report <c>passed-without-the-library</c> under this class's name.
/// </summary>
public sealed class ThroughASupportAssemblyTests : WiringBase
{
}
