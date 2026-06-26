using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace Credentials.Conformance.Tests;

/// <summary>
/// Runs the W3C VCDM 2.0 interoperability test suite (the Node suite) against the ASP.NET shim on
/// loopback and asserts a conformance baseline. The engine passes the structural/issue/verify core of
/// the suite. The two not-yet-passing tests exercise capabilities deferred from this engine: full JSON-LD
/// term mapping (detecting a well-formed-but-unmapped <c>type</c>, which an STJ-only engine cannot resolve
/// without context expansion) and <c>relatedResource</c> digest hash-verification (a verifier-side
/// fetch+hash deferred to a follow-up). See <c>docs/conformance.md</c>. The baseline guards against
/// regressions below the established pass count without claiming full conformance.
/// </summary>
public sealed partial class W3cVcdm2SuiteTests
{
    // The number of suite tests the engine currently passes (57 of 59; the 2 remaining are documented in
    // docs/conformance.md). Raising this when the engine improves is expected; a drop below it is a
    // regression and fails the gate.
    private const int PassingBaseline = 57;

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
            Console.WriteLine($"W3C VCDM 2.0 suite: {passing} passing, {failing} failing (mocha exit {exitCode}, baseline {PassingBaseline}).");

            passing.Should().BeGreaterThanOrEqualTo(PassingBaseline,
                $"the engine must not regress below {PassingBaseline} passing W3C suite tests. Output:\n{output}");
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
