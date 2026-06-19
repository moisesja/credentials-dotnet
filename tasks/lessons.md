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

## Run adversarial agents on generated code BEFORE committing (2026-06-18)

AGENTS.md mandates it, and it paid off: three adversarial agents found a critical duplicate-key bug
plus several validator false-accepts in code that built clean and passed its own 70 tests. Design-phase
adversarial review is not a substitute for attacking the actual implementation.

## System.Text.Json parsing gotchas surfaced by the adversarial pass (2026-06-18)

- **Duplicate keys:** `JsonNode.Parse` admits duplicate object keys by default and throws
  `ArgumentException` (not `JsonException`) **lazily on first member access** — so a `catch (JsonException)`
  at parse misses it and it surfaces deep in unrelated code. Set `JsonDocumentOptions.AllowDuplicateProperties = false`
  (real .NET 10 API) to reject them eagerly as a catchable `JsonException`.
- **`JsonShape.IsString("")` is true:** an empty/whitespace string is structurally a string, so identity/type
  gates (`issuer.id`, `credentialStatus.type`, …) need a non-blank check, not just an is-string check.
- **No implicit input-size bound:** `JsonNode.Parse` bounds depth (via `MaxDepth`) but not total bytes; cap
  untrusted input length explicitly.
