using System.Runtime.InteropServices;
using NetCrypto;
using Xunit;

namespace Credentials.TestSupport;

/// <summary>
/// The one place that decides what a test does when NetCrypto's native BBS library (<c>zkryptium_ffi</c>),
/// which every <c>bbs-2023</c> operation needs, did not load in the test process (issue #57).
/// </summary>
/// <remarks>
/// <para>A test that needs the library is a <c>[SkippableFact]</c> or <c>[SkippableTheory]</c> that calls
/// <see cref="RequireOrSkip"/> before it touches <c>bbs-2023</c>. When the library did not load, the test is
/// never reported as passed:</para>
/// <list type="bullet">
/// <item>it <b>fails</b> where the library has to be there: on a platform NetCrypto ships it for
/// (<see cref="ShippedRuntimeIdentifiers"/>), and on GitHub Actions whatever the platform;</item>
/// <item>it is <b>skipped</b>, with a reason, on any other host.</item>
/// </list>
/// <para>The decision is made in each test process, so it holds for every test assembly and for any
/// subset of the tests. On GitHub Actions, which sets <c>GITHUB_ACTIONS=true</c> in the environment the
/// tests run in, no such test can be skipped: a green run means each of them ran.</para>
/// <para>A test that uses <c>bbs-2023</c> without this call is not covered: without the library it fails if
/// it expects success, but it can pass if all it expects is an exception. <c>BbsTestConventionTests</c> (in
/// <c>Credentials.ArchitectureTests</c>) reads the test sources and fails when a <c>bbs-2023</c> test lacks
/// the call.</para>
/// </remarks>
public static class BbsNativeLibrary
{
    /// <summary>What a test that needs the library does.</summary>
    public enum Outcome
    {
        /// <summary>The library loaded: the test runs.</summary>
        Run,

        /// <summary>The library did not load although it has to: the test fails.</summary>
        Fail,

        /// <summary>The library did not load on a host where that is expected: the test is skipped.</summary>
        Skip,
    }

    /// <summary>
    /// The runtime identifiers NetCrypto ships the library for. <c>docs/conformance.md</c> lists the same
    /// five, and <c>BbsNativeLibraryTests</c> pins this list against the resolved NetCrypto package.
    /// </summary>
    public static IReadOnlyList<string> ShippedRuntimeIdentifiers { get; } =
        ["linux-arm64", "linux-x64", "osx-arm64", "osx-x64", "win-x64"];

    /// <summary>
    /// Whether the library loaded in this process. NetCrypto probes once per process, so the answer never
    /// changes while the tests run.
    /// </summary>
    public static bool IsAvailable { get; } = new DefaultBbsCryptoProvider().IsAvailable;

    /// <summary>
    /// This host's platform as an operating system and an architecture, named like a runtime identifier
    /// (see <see cref="RuntimeIdentifierFor"/>).
    /// </summary>
    /// <remarks>
    /// It is not <see cref="RuntimeInformation.RuntimeIdentifier"/>: that value depends on how the runtime
    /// was built, and the <c>DOTNET_RUNTIME_ID</c> environment variable overrides it. It also does not tell a
    /// musl Linux from a glibc one. NetCrypto's Linux builds are glibc builds, so on musl the library does
    /// not load and the tests fail, as they do on a glibc older than the builds need.
    /// </remarks>
    public static string HostRuntimeIdentifier { get; } =
        RuntimeIdentifierFor(HostOperatingSystem(), RuntimeInformation.ProcessArchitecture);

    /// <summary>Whether NetCrypto ships the library for this host's platform.</summary>
    public static bool IsShippedForHost { get; } = ShippedRuntimeIdentifiers.Contains(HostRuntimeIdentifier);

    /// <summary>Whether this is a GitHub Actions run, which sets <c>GITHUB_ACTIONS=true</c> on every runner.</summary>
    public static bool RunsOnGitHubActions { get; } =
        string.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Call before a test touches <c>bbs-2023</c>. Returns when the library loaded; otherwise fails or skips
    /// the calling test, as <see cref="OutcomeFor"/> decides for this host.
    /// </summary>
    /// <exception cref="InvalidOperationException">The library did not load although it has to.</exception>
    public static void RequireOrSkip() =>
        Enforce(OutcomeFor(IsAvailable, IsShippedForHost, RunsOnGitHubActions));

    /// <summary>
    /// The rule behind <see cref="RequireOrSkip"/>: a missing library is a failure on a platform NetCrypto
    /// ships it for and on GitHub Actions, and a skip only elsewhere.
    /// </summary>
    /// <param name="available">Whether the library loaded.</param>
    /// <param name="shippedForHost">Whether NetCrypto ships the library for the host's platform.</param>
    /// <param name="onGitHubActions">Whether this is a GitHub Actions run.</param>
    public static Outcome OutcomeFor(bool available, bool shippedForHost, bool onGitHubActions) =>
        available ? Outcome.Run
        : shippedForHost || onGitHubActions ? Outcome.Fail
        : Outcome.Skip;

    /// <summary>
    /// Carries an outcome out on the calling test: returns for <see cref="Outcome.Run"/>, skips the test for
    /// <see cref="Outcome.Skip"/>, and throws for <see cref="Outcome.Fail"/> or any other value.
    /// </summary>
    /// <param name="outcome">The outcome to carry out.</param>
    /// <exception cref="InvalidOperationException">The outcome is <see cref="Outcome.Fail"/>.</exception>
    public static void Enforce(Outcome outcome)
    {
        switch (outcome)
        {
            case Outcome.Run:
                return;

            case Outcome.Skip:
                Skip.If(
                    true,
                    $"The BBS native library (zkryptium_ffi) did not load on this host ({HostRuntimeIdentifier}), and "
                    + $"NetCrypto ships it only for {string.Join(", ", ShippedRuntimeIdentifiers)}. bbs-2023 is not "
                    + "tested here. See docs/conformance.md.");
                return;

            default:
                throw new InvalidOperationException(
                    IsShippedForHost
                        ? $"NetCrypto ships the BBS native library (zkryptium_ffi) for {HostRuntimeIdentifier}, but it "
                          + "did not load in this process, so bbs-2023 cannot be tested here. Check the NetCrypto "
                          + $"package's runtimes/{HostRuntimeIdentifier}/native asset."
                          + (OperatingSystem.IsLinux()
                              ? " Its Linux builds are glibc builds that need glibc 2.34 or later; they do not load "
                                + "on musl."
                              : string.Empty)
                          + " See docs/conformance.md."
                        : $"The BBS native library (zkryptium_ffi) did not load on {HostRuntimeIdentifier}, a platform "
                          + "NetCrypto does not ship it for, and this is a GitHub Actions run. A CI leg must not leave "
                          + "bbs-2023 untested under a green check. See docs/conformance.md.");
        }
    }

    /// <summary>
    /// Names a platform the way .NET names a portable runtime identifier: <c>linux-x64</c>,
    /// <c>osx-arm64</c>, <c>win-x64</c>.
    /// </summary>
    /// <param name="operatingSystem">The operating system.</param>
    /// <param name="architecture">The process architecture.</param>
    public static string RuntimeIdentifierFor(OSPlatform operatingSystem, Architecture architecture)
    {
        var family =
            operatingSystem == OSPlatform.Windows ? "win"
            : operatingSystem == OSPlatform.OSX ? "osx"
            : operatingSystem.ToString().ToLowerInvariant();

        return $"{family}-{architecture.ToString().ToLowerInvariant()}";
    }

    private static OSPlatform HostOperatingSystem()
    {
        OSPlatform[] known = [OSPlatform.Windows, OSPlatform.OSX, OSPlatform.Linux, OSPlatform.FreeBSD];
        foreach (var candidate in known)
        {
            if (RuntimeInformation.IsOSPlatform(candidate))
            {
                return candidate;
            }
        }

        return OSPlatform.Create("unknown");
    }
}
