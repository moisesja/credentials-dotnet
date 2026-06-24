using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Verification;
using NetCrypto;

// Minimal ASP.NET VC-API shim over IIssuer/IVerifier for the W3C VCDM 2.0 test suite (loopback).
//   POST /credentials/issue        { credential, options }        -> 201 { verifiableCredential }
//   POST /credentials/verify       { verifiableCredential, options } -> 200 { verified } | >=400
//   POST /presentations/verify     { verifiablePresentation, options } -> 200 { verified } | >=400
//   GET  /                          -> { issuer } (the shim's did:key, written into the suite's localConfig)
// The suite injects the configured issuer id as `credential.issuer`, so configuring it to this shim's
// did:key makes issuance satisfy the engine's issuer-binding without any field rewriting.

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Services.AddCredentials(b => b.UseNetDid().UseRdfcSuites());

var app = builder.Build();

// One fixed issuer identity for the lifetime of the shim.
var keyPair = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
var issuerDid = $"did:key:{keyPair.MultibasePublicKey}";
var issuerVm = $"{issuerDid}#{keyPair.MultibasePublicKey}";
var signer = new KeyPairSigner(keyPair, new DefaultCryptoProvider());

app.MapGet("/", () => Results.Json(new { issuer = issuerDid }));

app.MapPost("/credentials/issue", async (JsonElement body, IIssuer issuer) =>
{
    if (!body.TryGetProperty("credential", out var credential))
        return Results.Json(new { errors = new[] { "missing 'credential'" } }, statusCode: 400);
    try
    {
        var unsecured = Credential.Parse(credential.GetRawText());
        // A conforming issuer rejects a structurally-invalid credential rather than signing it (the
        // suite's negative issue cases expect this).
        var structure = unsecured.ValidateStructure();
        if (!structure.IsValid)
            return Results.Json(new { errors = structure.Problems.Select(p => p.Code).ToArray() }, statusCode: 400);

        var issued = await issuer.IssueAsync(unsecured, new DataIntegrityIssuanceRequest
        {
            Cryptosuite = "eddsa-rdfc-2022",
            Signer = signer,
            VerificationMethod = issuerVm,
        });
        return Results.Json(new { verifiableCredential = JsonNode.Parse(issued.Credential.ToBytes()) }, statusCode: 201);
    }
    catch (Exception ex)
    {
        // The suite's negative issue cases expect rejection (assert.rejects) => HTTP >= 400.
        return Results.Json(new { errors = new[] { ex.Message } }, statusCode: 400);
    }
});

app.MapPost("/credentials/verify", async (JsonElement body, IVerifier verifier) =>
{
    if (!body.TryGetProperty("verifiableCredential", out var vc))
        return Results.Json(new { errors = new[] { "missing 'verifiableCredential'" } }, statusCode: 400);
    try
    {
        var credential = Credential.Parse(vc.GetRawText());
        var result = await verifier.VerifyCredentialAsync(credential);
        return result.Decision == VerificationDecision.Accepted
            ? Results.Json(new { verified = true, results = new { }, problemDetails = Array.Empty<object>() })
            // A non-conforming / unverifiable credential must reject as HTTP >= 400 (assert.rejects).
            : Results.Json(new { verified = false, problemDetails = new[] { new { detail = result.ToString() } } }, statusCode: 400);
    }
    catch (Exception ex)
    {
        return Results.Json(new { errors = new[] { ex.Message } }, statusCode: 400);
    }
});

app.MapPost("/presentations/verify", async (JsonElement body, IVerifier verifier) =>
{
    if (!body.TryGetProperty("verifiablePresentation", out var vp))
        return Results.Json(new { errors = new[] { "missing 'verifiablePresentation'" } }, statusCode: 400);

    string? challenge = null, domain = null;
    if (body.TryGetProperty("options", out var opts) && opts.ValueKind == JsonValueKind.Object)
    {
        if (opts.TryGetProperty("challenge", out var c) && c.ValueKind == JsonValueKind.String) challenge = c.GetString();
        if (opts.TryGetProperty("domain", out var d) && d.ValueKind == JsonValueKind.String) domain = d.GetString();
    }

    try
    {
        var presentation = VerifiablePresentation.Parse(vp.GetRawText());
        // The suite submits both signed and UNSIGNED presentations, so holder binding is not required;
        // when a binding IS present, its challenge/domain are still checked against the suite's values.
        var result = await verifier.VerifyPresentationAsync(presentation, new PresentationVerificationOptions
        {
            RequireHolderBinding = false,
            ExpectedChallenge = challenge,
            ExpectedDomain = domain,
        });
        return result.Decision == VerificationDecision.Accepted
            ? Results.Json(new { verified = true, problemDetails = Array.Empty<object>() })
            : Results.Json(new { verified = false, problemDetails = new[] { new { detail = result.ToString() } } }, statusCode: 400);
    }
    catch (Exception ex)
    {
        return Results.Json(new { errors = new[] { ex.Message } }, statusCode: 400);
    }
});

app.Run();
