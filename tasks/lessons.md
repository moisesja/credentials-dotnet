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

## Bind the credential issuer to the verification-method IDENTIFIER, not a controller field (2026-06-19)

A cryptographically valid Data Integrity proof says nothing about *who* issued the credential. The
`verificationMethod`'s self-declared `controller` field is attacker-controllable for any DID method whose
document the attacker can publish (did:web, custom resolvers). Bind `issuer` to the **base DID of the
proof's verificationMethod** (where the signing key lives) — to claim issuer=victim the attacker would
need victim's key, or the signature fails. Safe-looking with did:key only because there controller == DID
== key. The DataProofs pipeline verifies the signature + the VM's own relationships, but NOT the
credential-level issuer binding — that is the VC engine's job.

## Verifying a fetched artifact's own proof is not enough — bind it to the right issuer (2026-06-19)

The M2 status stage verified the fetched Bitstring Status List credential's own proof (fix E2) but did
not check that the list's issuer was the *credential's* issuer. A valid proof only proves the list is
signed by **someone**, not by the **right** someone — so an attacker who can influence what the fetch
hook returns (SSRF, cache poisoning, a colluding intermediary, DNS spoofing) substitutes an all-clear
list validly self-signed by an unrelated `did:key` and silently masks a real revocation. The adversarial
agent reproduced exactly this. Fix: after the recursive proof verifies, bind `list.issuer == credential.issuer`
(mismatch ⇒ Indeterminate, fail-closed). This is the same shape as the M1 issuer-binding lesson, one
level down: **every externally-fetched, separately-signed artifact the verifier trusts (status list,
`JsonSchemaCredential`, future schema VCs) must be bound to an expected authority, not merely
proof-checked.** When you recurse a sub-credential through the verifier, ask "signed by whom, and is that
who I require?" — not just "is the signature valid?".

## Don't hand a trust/policy hook more than its decision needs (2026-06-19)

`IssuerTrustContext` originally carried the whole credential `Document`, which includes
`credentialSubject` claims — an adversarial agent read an `ssn` out of it. An issuer-trust decision is
about *identity* (issuer DID, verification method, types, mechanism); giving the hook subject claims both
contradicts the "never claims/keys" contract (NFR-008) and invites trust logic to couple to subject data.
Removed `Document`. **Rule:** a context object passed to an injected policy should expose the minimum the
decision legitimately needs; adding a field later is non-breaking, removing one is breaking — so start
minimal.

## Overflow-guard size arithmetic on any attacker- or caller-influenced length (2026-06-19)

Two latent overflow bugs the codec adversarial agent found by running: `(maxInflatedBytes/3 + 1)*4`
wrapped negative at `long.MaxValue` (then `checked((int)…)` threw an *uncaught* `OverflowException`,
not the `FormatException` the call sites catch), and `(lengthBits + 7) / 8` overflowed `int` to a
negative allocation at `int.MaxValue`. Neither was reachable through current callers (all pass the 16 MiB
default), but "not reachable today" is a latent trap for the next caller. **Rule:** compute size/length
bounds in `long`, clamp before narrowing to `int`, and bound allocations to the same ceiling the decoder
enforces — even for caller-supplied (not just wire-supplied) values.

## A throw-based vs result-style substrate verify both reduce to the same neutral seam — but classify BEFORE the crypto call (2026-06-20)

The M3 enveloping mechanisms wrap two differently-shaped DataProofs verify APIs: `VcJose.VerifyCredential`
is **synchronous and throws** (`MalformedJoseException` for a wrong/absent `typ`/`cty`, `JoseCryptoException`
for a bad signature — and, fatally for naive code, `JoseCryptoException` *also* when the key resolver returns
null), while `VcCose.Verify` is **result-style** (`Verified==false` + a `Failure.Code`). The F7 rule (bad
signature ⇒ `Failed`; resolver/IO failure ⇒ `Indeterminate`; never conflate, never throw past the stage) is
easy to get wrong on the JOSE side because "bad signature" and "couldn't find the key" are the *same
exception type*. **Rule:** resolve the verification key **asynchronously, out-of-band, before** calling a
synchronous substrate verify — classify a null/failed resolution as `Unresolvable`→`Indeterminate` up front,
then pass a constant resolver to the substrate so the only thing its exception can mean is a real crypto/
structural failure → `Failed`. This also keeps the role honestly async over a sync FFI (no fake
`Task.FromResult`, F5). The adversarial pass specifically tried to make a forged signature land on
`Indeterminate` (which a non-strict policy would accept) and could not.

## Bind an enveloping credential's issuer to the kid by look-up-then-bind, even when the kid is unauthenticated (2026-06-20)

The same issuer-binding lesson as M1/M2, one more level down: an enveloping (JOSE/COSE) proof has no
in-document `verificationMethod` — the only signer identifier is the JWS protected-header `kid` or the COSE
key id (which in COSE is **unprotected**, label 4). Binding still works and stays safe because the `kid` is
used **only to look up a key**, never trusted for authorization: resolve the `kid`'s published key, verify
the signature against *that* key, then require `BaseDid(kid) == inner.issuer.id`. To forge `issuer=victim`
the attacker must sign under a `kid` whose base DID is the victim's — which makes the resolver fetch the
victim's key, so the attacker's signature fails. A missing `kid` **fails closed** (we cannot identify the
signer ⇒ reject, not Indeterminate). The unprotected COSE `kid` is a non-issue under this model — an
adversary rewriting it only changes *which key we look up*, and a mismatch then fails the signature or the
bind. **Rule:** for any token-shaped credential, derive the signer identity from the header, resolve the
key under it, and bind the signed issuer to that identity — never accept a self-asserted issuer or trust an
unauthenticated header field for authorization.

## Make sign-exact-bytes self-enforcing: assert the substrate-verified payload equals what the stages validate (2026-06-20)

For enveloping, the verifier decodes the inner credential at ingest (to drive the structure/validity/status/
schema stages) and *separately* verifies the envelope in the proof stage. The two only stay consistent if
the verifier's payload decode and the substrate's payload decode produce identical bytes — which they do
today (same BCL `Base64Url`, same segment; the JWS signature covers the literal ASCII `header.payload`), and
the adversarial pass proved no divergent payload is constructible. But that safety was *emergent* from a
substrate implementation detail. **Rule:** when two code paths must agree on "the bytes the signature
covers," make it explicit — have the mechanism compare the substrate-returned verified payload to the inner
document the stages will validate and fail (`envelope_payload_mismatch`) on any mismatch. It converts
"provably safe given the current substrate" into "safe regardless of how the substrate decodes," for a few
lines and one extra seam field.

## Transitive deps defeat "no Newtonsoft in the closure" even with a clean public API (2026-06-19)

Referencing `DataProofsDotnet.Rdfc` (for RDFC suites) pulled dotNetRDF → Newtonsoft.Json + AngleSharp +
HtmlAgilityPack into EVERY consumer's closure, violating NFR-002's closure clause even though no
Newtonsoft type was on our public API. Fix: keep the default System.Text.Json-only (JCS suites) and put
RDFC behind an opt-in package (`Credentials.Rdfc`) that contributes `ICryptosuite` services to a
DI-collected registry. Also watch for *unused* substrate DI packages (`DataProofsDotnet.Extensions.DependencyInjection`)
silently re-introducing the same transitive — check `dotnet list package --include-transitive`.
