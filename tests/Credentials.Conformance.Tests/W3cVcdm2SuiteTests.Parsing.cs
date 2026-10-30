using FluentAssertions;
using Xunit;

namespace Credentials.Conformance.Tests;

/// <summary>
/// Pins the mocha spec-reporter parsing the gate relies on. The suite itself only runs on CI, so this
/// runs everywhere: a parser that silently found no failures would otherwise let an unknown failure pass.
/// </summary>
public sealed partial class W3cVcdm2SuiteTests
{
    // A trimmed excerpt of a real run (2026-10-30): the tree lists failing tests by number, then the
    // summary repeats each failure as a numbered block ending in the assertion line.
    private const string MochaExcerpt = """
          Names and Descriptions
            credentials-dotnet
              1) If present, the value of the name property MUST be a string or a language value object as described in 11.1 Language and Base Direction.
              2) If present, the value of the description property MUST be a string or a language value object as described in 11.1 Language and Base Direction.

          Related Resources
            credentials-dotnet
              ✔ The value of the relatedResource property MUST be one or more objects. (41ms)
              3) If the digest provided by the issuer does not match the digest computed for the retrieved resource, the conforming verifier implementation MUST produce an error.


          54 passing (3s)
          3 failing

          1) Names and Descriptions
               credentials-dotnet
                 If present, the value of the name property MUST be a string or a language value object as described in 11.1 Language and Base Direction.:

              AssertionError [ERR_ASSERTION]: Got unwanted rejection: Failed to accept a VC using `name` with language & direction expressed.
                  at async Context.<anonymous> (tests/4.06-names-and-descriptions.js:57:9)

          2) Names and Descriptions
               credentials-dotnet
                 If present, the value of the description property MUST be a string or a language value object as described in 11.1 Language and Base Direction.:

              AssertionError [ERR_ASSERTION]: Got unwanted rejection: Failed to accept a VC using `description` with language & direction expressed.
                  at async Context.<anonymous> (tests/4.06-names-and-descriptions.js:82:9)

          3) Related Resources
               credentials-dotnet
                 If the digest provided by the issuer does not match the digest computed for the retrieved resource, the conforming verifier implementation MUST produce an error.:

              AssertionError [ERR_ASSERTION]: Missing expected rejection: Failed to reject a VC with a relatedResource with wrong digest.
                  at async Context.<anonymous> (tests/4.10-related-resources.js:60:9)

        """;

    [Fact]
    public void Failure_parsing_yields_one_assertion_message_per_failure()
    {
        var failures = ParseFailures(MochaExcerpt);

        failures.Should().Equal(
            "Got unwanted rejection: Failed to accept a VC using `name` with language & direction expressed.",
            "Got unwanted rejection: Failed to accept a VC using `description` with language & direction expressed.",
            "Missing expected rejection: Failed to reject a VC with a relatedResource with wrong digest.");
        failures.Should().HaveCount(ParseCount(MochaExcerpt, "failing"));
        ParseCount(MochaExcerpt, "passing").Should().Be(54);
    }

    [Fact]
    public void Failure_parsing_matches_the_known_failure_list_by_message()
    {
        var failures = ParseFailures(MochaExcerpt);

        failures.Should().OnlyContain(f => KnownFailures.Any(k => f.Contains(k, StringComparison.Ordinal)));
    }

    [Fact]
    public void Failure_parsing_keeps_a_failure_without_an_assertion_line()
    {
        // A timeout or thrown TypeError has no "AssertionError:" line; it must still count as an (unknown) failure.
        const string output = """
              1 passing (1s)
              1 failing

              1) Some suite
                   some test:
                 Error: Timeout of 15000ms exceeded. For async tests and hooks, ensure "done()" is called.

            """;

        ParseFailures(output).Should().Equal("Timeout of 15000ms exceeded. For async tests and hooks, ensure \"done()\" is called.");
    }

    [Fact]
    public void Failure_parsing_finds_nothing_when_the_run_had_no_failures()
    {
        ParseFailures("  59 passing (3s)\n").Should().BeEmpty();
    }
}
