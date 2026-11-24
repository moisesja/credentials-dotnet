using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text.Json;
using Credentials.TestSupport;
using DataProofsDotnet.Rdfc.DataIntegrity;
using FluentAssertions;
using Xunit;

namespace Credentials.Rdfc.Tests;

/// <summary>
/// Pins <see cref="BbsNativeLibrary"/>, which keeps the <c>bbs-2023</c> tests honest (issue #57): a test that
/// needs NetCrypto's native BBS library fails where the library has to load and is skipped, visibly, only
/// where it is not shipped. It never reports Passed without running.
/// </summary>
/// <remarks>
/// With the library present, which is the case on every CI leg, <see cref="BbsNativeLibrary.RequireOrSkip"/>
/// just returns, and a regression in it would go unnoticed until the day the library is missing. So this
/// class runs the call against a copy of NetCrypto that cannot load the library, and pins the rule, what it
/// does to a test, and where its inputs come from.
/// </remarks>
[Trait("Category", "Bbs")]
public sealed class BbsNativeLibraryTests
{
    /// <summary>
    /// The named check that the library is there. It applies the same rule as every other test that needs
    /// the library, so it fails on a platform NetCrypto ships for and on GitHub Actions, and it also requires
    /// the product's own answer to match the one the tests act on.
    /// </summary>
    [SkippableFact]
    public void Bbs_native_library_loads_wherever_it_has_to()
    {
        BbsNativeLibrary.RequireOrSkip();

        // The helper says the library loaded. The product asks DataProofs' suite, which today reads the same
        // NetCrypto flag; this keeps the tests from running on an answer the product does not share.
        new Bbs2023Cryptosuite().IsAvailable.Should().BeTrue(
            "the test helper says the library loaded, and the bbs-2023 cryptosuite must agree");
    }

    [Theory]
    // The library loaded: run, wherever that is.
    [InlineData(true, true, true, BbsNativeLibrary.Outcome.Run)]
    [InlineData(true, true, false, BbsNativeLibrary.Outcome.Run)]
    [InlineData(true, false, true, BbsNativeLibrary.Outcome.Run)]
    [InlineData(true, false, false, BbsNativeLibrary.Outcome.Run)]
    // It did not load where NetCrypto ships it: fail, on a developer machine too.
    [InlineData(false, true, true, BbsNativeLibrary.Outcome.Fail)]
    [InlineData(false, true, false, BbsNativeLibrary.Outcome.Fail)]
    // It did not load on a platform NetCrypto does not ship for: fail on GitHub Actions, skip elsewhere.
    [InlineData(false, false, true, BbsNativeLibrary.Outcome.Fail)]
    [InlineData(false, false, false, BbsNativeLibrary.Outcome.Skip)]
    public void A_missing_library_skips_only_off_github_actions_on_an_unshipped_platform(
        bool available, bool shippedForHost, bool onGitHubActions, BbsNativeLibrary.Outcome expected)
    {
        BbsNativeLibrary.OutcomeFor(available, shippedForHost, onGitHubActions).Should().Be(expected);
    }

    [Fact]
    public void The_rule_is_carried_out_on_the_calling_test()
    {
        var run = () => BbsNativeLibrary.Enforce(BbsNativeLibrary.Outcome.Run);
        var fail = () => BbsNativeLibrary.Enforce(BbsNativeLibrary.Outcome.Fail);
        var skip = () => BbsNativeLibrary.Enforce(BbsNativeLibrary.Outcome.Skip);

        run.Should().NotThrow();
        fail.Should().ThrowExactly<InvalidOperationException>().WithMessage("*did not load*");
        skip.Should().ThrowExactly<SkipException>().WithMessage("*did not load*");
    }

    [Fact]
    public void The_inputs_of_the_rule_come_from_this_host()
    {
        // GitHub Actions sets GITHUB_ACTIONS=true on every runner.
        BbsNativeLibrary.RunsOnGitHubActions.Should().Be(
            string.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.OrdinalIgnoreCase));

        // The host is named after its operating system and its process architecture.
        var host = BbsNativeLibrary.HostRuntimeIdentifier;
        host.Should().EndWith("-" + RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant());
        if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
        {
            host.Should().StartWith(OperatingSystem.IsWindows() ? "win-" : OperatingSystem.IsMacOS() ? "osx-" : "linux-");
        }

        // Where the library loaded, the platform is one NetCrypto ships it for. And every CI leg runs on
        // such a platform (docs/conformance.md has the table). Between them these two check the host
        // detection on every machine the tests normally run on, Windows included.
        (BbsNativeLibrary.IsShippedForHost || !BbsNativeLibrary.IsAvailable).Should().BeTrue(
            $"the library loaded on {host}, which is not in BbsNativeLibrary.ShippedRuntimeIdentifiers");
        (BbsNativeLibrary.IsShippedForHost || !BbsNativeLibrary.RunsOnGitHubActions).Should().BeTrue(
            $"a GitHub Actions leg runs on {host}, which is not in BbsNativeLibrary.ShippedRuntimeIdentifiers");
    }

    /// <summary>
    /// The end-to-end check, on every host and every CI leg: what <see cref="BbsNativeLibrary.RequireOrSkip"/>
    /// really does when the library is not there. In this process the library is normally loaded, so the test
    /// loads a second copy of NetCrypto and of the helper into a load context that refuses to load
    /// <c>zkryptium_ffi</c>. To that copy the library is missing, as it is on a host without it.
    /// </summary>
    /// <remarks>
    /// This works because NetCrypto reaches the library through an ordinary P/Invoke, which the runtime
    /// resolves by asking the load context of the calling assembly (<c>LoadUnmanagedDll</c>). If a NetCrypto
    /// release loads the library another way, by an absolute path or through an import resolver of its own,
    /// the context is no longer asked, the copy finds the library, and the <c>IsAvailable</c> assertion below
    /// fails. That failure says this test needs another way to withhold the library. It does not say
    /// <c>bbs-2023</c> is broken.
    /// </remarks>
    [Fact]
    public void Without_the_library_the_call_fails_or_skips_and_never_returns()
    {
        var context = new ContextWithoutTheBbsLibrary();
        var helper = context.LoadFromAssemblyPath(typeof(BbsNativeLibrary).Assembly.Location)
            .GetType(typeof(BbsNativeLibrary).FullName!, throwOnError: true)!;
        helper.Should().NotBeSameAs(typeof(BbsNativeLibrary), "the copy must have its own NetCrypto probe");

        helper.GetProperty(nameof(BbsNativeLibrary.IsAvailable))!.GetValue(null).Should().Be(
            false, "the load context refused to load the library");

        var call = () => helper.GetMethod(nameof(BbsNativeLibrary.RequireOrSkip))!.Invoke(null, null);
        var thrown = call.Should().Throw<TargetInvocationException>().Which.InnerException;

        // The same host, with the library missing: a failure wherever it has to load, a skip elsewhere.
        var expected = BbsNativeLibrary.OutcomeFor(
            available: false, BbsNativeLibrary.IsShippedForHost, BbsNativeLibrary.RunsOnGitHubActions);
        if (expected == BbsNativeLibrary.Outcome.Fail)
        {
            thrown.Should().BeOfType<InvalidOperationException>().Which.Message.Should().Contain("did not load");
        }
        else
        {
            thrown.Should().BeOfType<SkipException>().Which.Message.Should().Contain("did not load");
        }
    }

    [Theory]
    // The five platforms NetCrypto ships the library for.
    [InlineData("LINUX", Architecture.X64, "linux-x64", true)]
    [InlineData("LINUX", Architecture.Arm64, "linux-arm64", true)]
    [InlineData("OSX", Architecture.X64, "osx-x64", true)]
    [InlineData("OSX", Architecture.Arm64, "osx-arm64", true)]
    [InlineData("WINDOWS", Architecture.X64, "win-x64", true)]
    // Platforms it does not ship for.
    [InlineData("LINUX", Architecture.Arm, "linux-arm", false)]
    [InlineData("WINDOWS", Architecture.Arm64, "win-arm64", false)]
    [InlineData("WINDOWS", Architecture.X86, "win-x86", false)]
    [InlineData("FREEBSD", Architecture.X64, "freebsd-x64", false)]
    public void A_platform_maps_to_its_runtime_identifier(
        string operatingSystem, Architecture architecture, string expected, bool shipped)
    {
        var identifier = BbsNativeLibrary.RuntimeIdentifierFor(OSPlatform.Create(operatingSystem), architecture);

        identifier.Should().Be(expected);
        BbsNativeLibrary.ShippedRuntimeIdentifiers.Contains(identifier).Should().Be(shipped);
    }

    /// <summary>
    /// Pins what the NetCrypto package declares: the library, under its real file name, for exactly the
    /// platforms the helper and <c>docs/conformance.md</c> list. It proves the declaration, on any host; only
    /// a run on the platform itself proves that the binary loads.
    /// </summary>
    [SkippableFact]
    public void Netcrypto_declares_the_bbs_native_library_for_exactly_the_documented_platforms()
    {
        // The .deps.json next to this assembly is what the .NET host resolves native assets from. It is
        // written from the restored package graph on every build.
        var depsFile = Path.Combine(
            AppContext.BaseDirectory, typeof(BbsNativeLibraryTests).Assembly.GetName().Name + ".deps.json");
        using var deps = JsonDocument.Parse(File.ReadAllBytes(depsFile));

        // A runtime-specific build (dotnet build -r <rid>) lists only that platform's assets, so it cannot
        // answer the question. CI builds the portable form; on GitHub Actions this fails and does not skip.
        if (deps.RootElement.GetProperty("runtimeTarget").GetProperty("name").GetString()!.Contains('/'))
        {
            BbsNativeLibrary.RunsOnGitHubActions.Should().BeFalse(
                "CI has to test the portable build: the .deps.json of a runtime-specific build lists the native "
                + "assets of one platform only");
            Skip.If(true, "This is a runtime-specific build; its .deps.json lists the native assets of one platform only.");
        }

        var declared = new SortedDictionary<string, string>(StringComparer.Ordinal); // asset path → rid
        foreach (var target in deps.RootElement.GetProperty("targets").EnumerateObject())
        {
            foreach (var library in target.Value.EnumerateObject())
            {
                if (!library.Name.StartsWith("NetCrypto/", StringComparison.Ordinal)
                    || !library.Value.TryGetProperty("runtimeTargets", out var runtimeTargets))
                {
                    continue;
                }

                foreach (var asset in runtimeTargets.EnumerateObject())
                {
                    if (asset.Name.Contains("zkryptium", StringComparison.OrdinalIgnoreCase)
                        && asset.Value.GetProperty("assetType").GetString() == "native")
                    {
                        declared.Add(asset.Name, asset.Value.GetProperty("rid").GetString()!);
                    }
                }
            }
        }

        string[] expected =
        [
            "runtimes/linux-arm64/native/libzkryptium_ffi.so",
            "runtimes/linux-x64/native/libzkryptium_ffi.so",
            "runtimes/osx-arm64/native/libzkryptium_ffi.dylib",
            "runtimes/osx-x64/native/libzkryptium_ffi.dylib",
            "runtimes/win-x64/native/zkryptium_ffi.dll",
        ];

        declared.Keys.Should().Equal(
            expected,
            "the NetCrypto package must carry the BBS native library for exactly the documented platforms. If "
            + "NetCrypto dropped one, bbs-2023 no longer works there; if it added or renamed one, update this "
            + "list, BbsNativeLibrary.ShippedRuntimeIdentifiers and docs/conformance.md");

        declared.Values.Should().Equal(
            BbsNativeLibrary.ShippedRuntimeIdentifiers.Order(StringComparer.Ordinal),
            "BbsNativeLibrary.ShippedRuntimeIdentifiers must be the platforms NetCrypto declares the library for");
    }

    // Loads its own copies of the helper and of NetCrypto, so that NetCrypto's once-per-process probe runs
    // again, and answers that probe as a host without the library would: the load fails.
    private sealed class ContextWithoutTheBbsLibrary : AssemblyLoadContext
    {
        protected override Assembly? Load(AssemblyName assemblyName) =>
            assemblyName.Name is "NetCrypto" or "Credentials.TestSupport"
                ? LoadFromAssemblyPath(Path.Combine(AppContext.BaseDirectory, assemblyName.Name + ".dll"))
                : null; // everything else is shared with the test process

        protected override IntPtr LoadUnmanagedDll(string unmanagedDllName) =>
            unmanagedDllName.Contains("zkryptium", StringComparison.OrdinalIgnoreCase)
                ? throw new DllNotFoundException($"{unmanagedDllName} is withheld from this load context.")
                : IntPtr.Zero;
    }
}
