using Microsoft.Extensions.DependencyInjection;

namespace Credentials.ConsumerProbe;

// Genuinely consumes the packed Credentials.Core + Credentials.Extensions.DependencyInjection
// packages, so their full dependency graph is pulled into this project's restore — which is what the
// no-Newtonsoft closure assertion inspects.
internal static class Probe
{
    internal static void Touch()
    {
        var services = new ServiceCollection();
        services.AddCredentials(b => b.UseNetDid());
        _ = services.BuildServiceProvider();
    }
}
