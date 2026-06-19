# Lessons

Patterns learned while building credentials-dotnet. Reviewed at session start.

## Ground dependency surfaces against the real packages before coding (2026-06-18)

The implementation plan was synthesized from agent recon, which got most things right but
hallucinated specifics. Before scaffolding M0, verifying against the local NuGet cache and the
sibling repos caught:

- `JsonSchema.Net` real version is **7.3.2**, not the plan's `9.2.2`.
- `NetCrypto` 1.1.0 has **no public RNG abstraction** — the plan's `F9` assumed an `IRandomProvider`
  seam to lift; the engine wraps the BCL RNG instead (digests still go through `NetCrypto.Hash`).
- `ISigner` lives in `NetCrypto`, not `NetDid`.

**Rule:** treat a plan's package versions and type names as claims to verify, not facts. Check
`~/.nuget/packages/<id>` for real versions and read the dependency's source for real signatures
before writing the csproj or the first call site. This is verifying an API to write compiling code,
not "figuring out whether the dependency exists."

## Match house conventions by reading siblings, not inventing (2026-06-18)

`zcap-dotnet` and `didcomm-dotnet` are the templates: Central Package Management, the
`Directory.Build.props/.targets` shape, `global.json` pinning, xunit + FluentAssertions **7.0.0**
(deliberately the last free-license version — do not bump to 8.x), NSubstitute. Copy these rather
than choosing fresh.

## `DefaultIgnoreCondition.WhenWritingNull` does not strip nulls from a `JsonObject` (2026-06-18)

It applies to POCO property serialization; an explicit `null` member in a `System.Text.Json`
`JsonObject` is written as `"key":null`. Don't assert null-omission for node trees — assert
serializer-option parity with the dependency instead (the F1 byte-mirror covers null handling).
