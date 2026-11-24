using Credentials.TestSupport;
using FluentAssertions;
using Xunit;

namespace Credentials.SampleSmokeTests;

/// <summary>
/// Runs each sample's <c>Program.RunAsync</c> in-process. Every sample throws on an unexpected outcome
/// (e.g. a credential that should verify but doesn't), so "completes without throwing + produced
/// narration" is the assertion. Under coverlet this run also drives the api-coverage gate.
/// </summary>
public sealed class SampleSmokeTests
{
    private static async Task Run(Func<TextWriter, IServiceProvider?, Task> sample)
    {
        var buffer = new StringWriter();
        await sample(buffer, null);
        buffer.ToString().Should().NotBeNullOrWhiteSpace("a sample must narrate what it did");
    }

    [Fact] public Task DataIntegrity() => Run(Samples.DataIntegrity.Program.RunAsync);
    [Fact] public Task DataIntegrityRdfc() => Run(Samples.DataIntegrityRdfc.Program.RunAsync);
    [Fact] public Task JoseEnvelope() => Run(Samples.JoseEnvelope.Program.RunAsync);
    [Fact] public Task CoseEnvelope() => Run(Samples.CoseEnvelope.Program.RunAsync);
    [Fact] public Task SdJwtVc() => Run(Samples.SdJwtVc.Program.RunAsync);
    [Fact] public Task SdJwtPresentation() => Run(Samples.SdJwtPresentation.Program.RunAsync);
    [Fact] public Task PresentationDataIntegrity() => Run(Samples.PresentationDataIntegrity.Program.RunAsync);
    [Fact] public Task PresentationJose() => Run(Samples.PresentationJose.Program.RunAsync);
    [Fact] public Task StatusList() => Run(Samples.StatusList.Program.RunAsync);
    [Fact] public Task Schema() => Run(Samples.Schema.Program.RunAsync);
    [Fact] public Task IssuerTrust() => Run(Samples.IssuerTrust.Program.RunAsync);
    [Fact] public Task Vcdm11() => Run(Samples.Vcdm11.Program.RunAsync);
    [Fact] public Task FullPipeline() => Run(Samples.FullPipeline.Program.RunAsync);

    // The bbs-2023 sample needs NetCrypto's native BBS library and throws without it. Without the library this
    // test fails where the library has to load and is skipped, with a reason, elsewhere; it is never reported
    // as passed (issue #57).
    [SkippableFact]
    [Trait("Category", "Bbs")]
    public Task Bbs2023()
    {
        BbsNativeLibrary.RequireOrSkip();
        return Run(Samples.Bbs2023.Program.RunAsync);
    }
}
