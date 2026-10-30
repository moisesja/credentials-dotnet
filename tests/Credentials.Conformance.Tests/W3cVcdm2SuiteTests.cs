using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace Credentials.Conformance.Tests;

/// <summary>
/// Runs the W3C VCDM 2.0 interoperability test suite (the Node suite) against the ASP.NET shim on
/// loopback and gates on two conditions: every failing suite test must be one of the <b>named</b> known
/// failures below, and the passing count must not drop below the floor. Naming the failures means a new
/// regression cannot hide behind the count: a failure outside the list fails the gate however many tests
/// pass. The engine passes the structural/issue/verify core of the suite; the known failures are documented
/// one by one, with their reasons, in <c>docs/conformance.md</c>. This is a tracked baseline, not a
/// full-conformance claim.
/// </summary>
public sealed partial class W3cVcdm2SuiteTests
{
    // The suite tests the engine does not pass (54 of 59 pass), keyed on the suite's own assertion message,
    // which is the stable identifier the suite prints for a failed expectation. Each entry is explained in
    // docs/conformance.md. When one starts passing, the run prints a notice: remove the entry, raise the
    // floor, and update the doc.
    private static readonly string[] KnownFailures =
    [
        // RDFC suites refuse `@direction` since DataProofs 1.5.0 (fail-closed data-loss detection; the Data
        // Integrity specs define no lossless canonicalization of direction). The shim issues eddsa-rdfc-2022.
        "Failed to accept a VC using `name` with language & direction expressed.",
        "Failed to accept a VC using `description` with language & direction expressed.",
        "Failed to accept a VC using `issuer.name` with language & direction expressed.",
        "Failed to accept a VC using `issuer.description` with language & direction expressed.",
        // relatedResource digest verification (fetch + hash) is a deferred follow-up.
        "Failed to reject a VC with a relatedResource with wrong digest.",
    ];

    // The passing count the engine must not drop below: 59 suite tests minus the 5 known failures. A
    // sanity floor beside the named list, so a run that executes nothing cannot pass with zero failures.
    private const int PassingFloor = 54;

    [SkippableFact]
    [Trait("Category", "Conformance")]
    public async Task W3C_VCDM2_suite_meets_the_conformance_baseline()
    {
        var suiteDir = Environment.GetEnvironmentVariable("VCDM2_SUITE_DIR");
        Skip.If(string.IsNullOrWhiteSpace(suiteDir) || !Directory.Exists(suiteDir),
            "VCDM2_SUITE_DIR is not set to a prepared W3C suite checkout (conformance.yml prepares it).");
        Skip.IfNot(IsOnPath("node") && IsOnPath("npx"), "node/npx are not available.");

        var port = FreeTcpPort();
        var baseUrl = $"http://127.0.0.1:{port}";
        using var shim = StartShim(baseUrl);
        try
        {
            var issuerDid = await WaitForShimAsync(baseUrl, TimeSpan.FromSeconds(60));
            WriteLocalConfig(suiteDir!, baseUrl, issuerDid);

            var (output, exitCode) = await RunSuiteAsync(suiteDir!, baseUrl, issuerDid, TimeSpan.FromMinutes(8));
            var passing = ParseCount(output, "passing");
            var failing = ParseCount(output, "failing");
            var failures = ParseFailures(output);
            Console.WriteLine($"W3C VCDM 2.0 suite: {passing} passing, {failing} failing (mocha exit {exitCode}, floor {PassingFloor}, {KnownFailures.Length} known failures).");

            var unexpected = failures.Where(f => !KnownFailures.Any(k => f.Contains(k, StringComparison.Ordinal))).ToList();
            var nowPassing = KnownFailures.Where(k => !failures.Any(f => f.Contains(k, StringComparison.Ordinal))).ToList();
            if (nowPassing.Count > 0)
            {
                Console.WriteLine("NOTICE: known failures that now pass. Remove them from KnownFailures, raise PassingFloor, and update docs/conformance.md:\n  "
                    + string.Join("\n  ", nowPassing));
            }

            // Fail closed if the failure section could not be parsed: an unparsed failure is an unknown one.
            if (failing > 0)
            {
                failures.Should().HaveCount(failing, $"every mocha failure must be parsed so it can be checked against the known list. Output:\n{output}");
            }

            unexpected.Should().BeEmpty(
                $"every failing W3C suite test must be a documented known failure (docs/conformance.md). Unexpected:\n  {string.Join("\n  ", unexpected)}\nOutput:\n{output}");
            passing.Should().BeGreaterThanOrEqualTo(PassingFloor,
                $"the engine must not regress below {PassingFloor} passing W3C suite tests. Output:\n{output}");
        }
        finally
        {
            TryKill(shim);
        }
    }

    private static Process StartShim(string baseUrl)
    {
        var dll = LocateShimDll();
        var psi = new ProcessStartInfo("dotnet", $"\"{dll}\"")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.Environment["ASPNETCORE_URLS"] = baseUrl;
        return Process.Start(psi) ?? throw new InvalidOperationException("failed to start the shim process");
    }

    private static async Task<string> WaitForShimAsync(string baseUrl, TimeSpan timeout)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var json = await http.GetStringAsync(baseUrl + "/");
                return JsonDocument.Parse(json).RootElement.GetProperty("issuer").GetString()!;
            }
            catch
            {
                await Task.Delay(500);
            }
        }
        throw new TimeoutException("the shim did not become ready in time");
    }

    private static void WriteLocalConfig(string suiteDir, string baseUrl, string issuerDid)
    {
        // The suite injects the configured issuer id as credential.issuer, so pointing it at the shim's
        // own did:key makes issuance satisfy the engine's issuer-binding. testAllImplementations:false
        // keeps the run hermetic (no remote implementations).
        var config = """
            const baseUrl = process.env.BASE_URL;
            const issuer = process.env.ISSUER_DID;
            module.exports = {
              settings: { enableInteropTests: false, testAllImplementations: false },
              implementations: [{
                name: 'credentials-dotnet',
                implementation: 'credentials-dotnet',
                issuers: [{ id: issuer, endpoint: `${baseUrl}/credentials/issue`, tags: ['vc2.0'], options: {} }],
                verifiers: [{ id: issuer, endpoint: `${baseUrl}/credentials/verify`, tags: ['vc2.0'], options: {} }],
                vpVerifiers: [{ id: issuer, endpoint: `${baseUrl}/presentations/verify`, tags: ['vc2.0'], options: {} }],
              }]
            };
            """;
        File.WriteAllText(Path.Combine(suiteDir, "localConfig.cjs"), config);
    }

    private static async Task<(string Output, int ExitCode)> RunSuiteAsync(string suiteDir, string baseUrl, string issuerDid, TimeSpan timeout)
    {
        var psi = new ProcessStartInfo("npx", "mocha tests/ --timeout 15000 --preserve-symlinks --reporter spec")
        {
            WorkingDirectory = suiteDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.Environment["BASE_URL"] = baseUrl;
        psi.Environment["ISSUER_DID"] = issuerDid;

        var proc = Process.Start(psi)!;
        var stdout = proc.StandardOutput.ReadToEndAsync();
        var stderr = proc.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(timeout);
        try { await proc.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException) { TryKill(proc); throw new TimeoutException("the W3C suite did not finish in time"); }

        return (await stdout + "\n" + await stderr, proc.ExitCode);
    }

    private static int ParseCount(string output, string label)
    {
        var m = Regex.Match(output, $@"(\d+)\s+{label}");
        return m.Success ? int.Parse(m.Groups[1].Value) : 0;
    }

    // The spec reporter ends with "N failing" followed by one numbered block per failure: the suite/test
    // title lines, then the error line ("AssertionError [ERR_ASSERTION]: <message>"). The message is the
    // suite's own stable identifier for the failed expectation; it is what KnownFailures is keyed on.
    internal static List<string> ParseFailures(string output)
    {
        var failures = new List<string>();
        var summary = Regex.Match(output, @"(?m)^\s*\d+\s+failing\s*$");
        if (!summary.Success)
        {
            return failures;
        }

        var section = output[(summary.Index + summary.Length)..];
        foreach (var block in Regex.Split(section, @"(?m)^\s*\d+\)\s").Skip(1))
        {
            var error = Regex.Match(block, @"(?m)^\s*\w*Error(?:\s\[[^\]]*\])?:\s*(.+?)\s*$");
            failures.Add(error.Success ? error.Groups[1].Value : block.Trim().Split('\n')[0].Trim());
        }

        return failures;
    }

    private static string LocateShimDll()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Credentials.sln"))) dir = dir.Parent;
        var root = dir?.FullName ?? throw new DirectoryNotFoundException("repo root not found");
        var config = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).Parent?.Name ?? "Debug";
        foreach (var c in new[] { config, "Debug", "Release" })
        {
            // Glob the TFM directory rather than hardcoding it, so a framework bump can't silently break this.
            var binDir = Path.Combine(root, "tests", "Credentials.Conformance.VcApi", "bin", c);
            if (!Directory.Exists(binDir)) continue;
            var found = Directory.GetFiles(binDir, "Credentials.Conformance.VcApi.dll", SearchOption.AllDirectories);
            if (found.Length > 0) return found[0];
        }
        throw new FileNotFoundException("Credentials.Conformance.VcApi.dll not found — build the shim first.");
    }

    private static int FreeTcpPort()
    {
        var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static bool IsOnPath(string exe)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(exe, "--version") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false });
            p!.WaitForExit(10_000);
            return p.HasExited && p.ExitCode == 0;
        }
        catch { return false; }
    }

    private static void TryKill(Process? p)
    {
        try { if (p is not null && !p.HasExited) p.Kill(entireProcessTree: true); }
        catch { /* best effort */ }
    }
}
