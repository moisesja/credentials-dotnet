# Lessons

Patterns learned while building credentials-dotnet. Reviewed at session start.

## A contract enforced only by an upstream construction convention is NOT enforced — guard it at the role boundary (2026-06-22)

M7's "issuance is VCDM 2.0 only" (D8) was *assumed* true because `CredentialBuilder.Seal()` always pins
`V2_0` — so every credential built the normal way is 2.0. But `IIssuer.IssueAsync` accepted *any* unsecured
`Credential`, and `Credential.Parse(1.1 json)` produces a 1.1 unsecured credential, which the issuer would
then sign for any form (DI/JOSE/COSE/SD-JWT). My own M7 test helper minted a 1.1 credential through the public
issuer — proving the contract was a convention, not an enforced invariant. The PR reviewer (correctly) treated
this as blocking: the PR *contradicted its own stated contract*. Fix: a `credential.Version != V2_0` guard at
the `IssueAsync` boundary, before the form switch. **Rule:** when a doc/PRD states a contract ("we only
issue/accept/emit X"), enforce it at the public API boundary that the contract is about — not by relying on the
fact that the *usual* construction path happens to satisfy it. Ask: "can a caller reach this API with an input
that violates the contract, via any public constructor/parser/factory?" If yes (here: `Parse`), the boundary
needs an explicit guard + a negative test. Bonus tell: if a *test* has to do something the contract forbids to
set up a fixture (mint 1.1 to test 1.1 verify), that setup is itself evidence the boundary is unguarded — route
the fixture through a lower-level/internal path and guard the public one.

## A version/enum branch must handle every case explicitly — a boolean split silently lumps the third case with the wrong one (2026-06-22)

M7's first cut of the version-aware validity diagnostic used `var isV11 = credential.Version == V1_1;` then
`isV11 ? (1.1 members) : (2.0 members)`. That `else` quietly swept `VcdmVersion.Unknown` in with `V2_0`, so an
Unknown-version credential's expiry diagnostic named `/validUntil` even though the window had actually been
read (via `ValidityProjection`'s Unknown best-effort fallback) from `expirationDate` — the pointer named a
member that wasn't in the document. No security impact (Unknown is rejected by structure anyway), but the
adversarial pass (ATK5) caught the dishonest diagnostic. The fix was a `switch` on the three-valued enum with
an explicit `Unknown` arm that mirrors the projection's fallback. **Rule:** when a three-(or-more)-valued enum
(`VcdmVersion`, securing form, decision) drives behavior, branch with a `switch` over all cases, not a boolean
over one — and make every consumer of the value agree on the third case (here: the diagnostic must name the
member the *projection* actually read for Unknown, not whatever the two-way split defaulted to). A boolean
split is fine only when the two outcomes are genuinely exhaustive.

## Validate every review concern against the real code before acting — reviewers misread too (2026-06-22)

The M6 PR review (itself a Claude Code review) named its two highest-priority "must fix before merge" items: a
credential-level holder-binding **fail-open**, and a `BindHolder` empty-VM-list **bug**. Both were wrong. The
fail-open didn't exist — the SD-JWT substrate already fails closed (`KB_JWT_AUDIENCE_UNCHECKED` /
`KB_JWT_NONCE_UNCHECKED` when a binding is present but the verifier supplied no `aud`/`nonce` to pin it).
The empty-VM "bug" was guarded by an explicit `Count == 0 ||` clause the reviewer's quoted snippet omitted
(`All()` returns true on an empty sequence, so the leading `Count == 0` is exactly what prevents the fail-open
they feared). **Rule:** treat a review like an adversarial finding — reproduce each claim against the actual
source and the real dependency behavior (decompile/read the substrate if the claim hinges on it) before
changing anything. The cost of trusting a confident-but-wrong "fix" is a regression or a needless,
footgun-carrying rewrite. The valid residue (here: a narrow catch, an undocumented invariant, missing tests)
is still worth fixing — but separate it from the misreads with evidence, and *say which were which*.

## When two representations of the same payload share one request, assert which is authoritative — don't just comment it (2026-06-22)

`SecureRequest` carries both `Document` (a `JsonElement`) and `Payload` (raw bytes). The embedded Data
Integrity path signs `Document`; the enveloping JOSE/COSE paths sign `Payload` and ignore `Document`. The
holder's `vp+jwt` binding deliberately makes them DIVERGE — it injects `nonce`/`aud` into `Payload` only, so
the freshness is in the signed bytes (F1). That's correct, but a future enveloping mechanism (or a careless
refactor) that read `Document` instead of `Payload` would silently sign the freshness-stripped bytes —
re-opening the replay hole — and nothing would catch it because `Document` is validly populated. **Rule:**
when a request has two representations of "the thing to sign" and only one is authoritative per path, encode
the invariant in code, not just prose — assert the authoritative field is present (the enveloping mechanisms
now throw if `Payload.IsEmpty`) so the wrong-field mistake fails loudly instead of producing a valid signature
over the wrong bytes. A silent valid-signature-over-wrong-bytes is the most dangerous failure mode in a
signing seam.

## A fail-open substrate check makes the orchestrator responsible for enforcing the expectation's presence (2026-06-22)

The DataProofs substrate only checks `challenge`/`domain` when the verifier supplies a non-null expectation
(`ExpectedChallenge != null`) — so a verifier that *requires* a holder binding but forgets to set
`ExpectedChallenge` would accept **any** captured presentation (the binding verifies, the freshness is never
checked). The substrate is fail-open *by design* (the expectation is optional); the fail-**closed** policy is
the caller's to add. M6's adversarial pass (F2) caught this: `RequireHolderBinding == true &&
ExpectedChallenge == null` now fails (`holder_binding_challenge_required`) before the binding check runs.
**Rule:** whenever a substrate enforces a security property only when an expectation is supplied (fail-open),
and your layer exposes a `Require…` flag, the flag must *also* require the corresponding expectation to be
present — never let "required" mean "verify the signature but skip the replay defence." Test the
require-but-omit-expectation path explicitly, not just the happy path.

## When the signing substrate has no header-claim hook, bind freshness *into the signed payload* (2026-06-22)

The `vp+jwt` holder binding uses the generic compact-JWS builder, which signs a payload but exposes no hook
to add protected header claims (`nonce`/`aud`). So a naive `vp+jwt` is a **bearer token**: capture it, replay
it (F1). The fix is to inject the verifier's `nonce` (= challenge) and `aud` (= domain) as **members of the
VP JSON before signing**, so the holder's signature covers them, and have the verifier require them to equal
its own fresh expectations. **Rule:** replay defence requires the freshness values to be *inside the
signature's coverage*. If the envelope API won't let you put them in the header, put them in the signed body
— and always pair "holder signed a nonce" with "verifier checks the nonce equals what it just issued," or you
have proof-of-possession without proof-of-freshness. (Contrast the DI path, where the substrate's
`DataIntegrityProof.Challenge`/`Domain` are already in the proof's signed scope — there you only thread the
expectation through; F1 only bit the path where the substrate gave no slot.)

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

## When a credential carries two identifiers for the same thing, bind on one but require both agree (2026-06-21)

M4's SD-JWT VC carries a VCDM credential as the SD-JWT claims set, so it has **two** issuer identifiers:
the SD-JWT `iss` claim (the binding anchor) and the VCDM `issuer` member (what `Credential.Issuer` and the
issuer-trust hook read). The proof stage bound `BaseDid(kid) == iss`, but nothing required `iss == issuer`.
An attacker signed with their **own** key under `iss = attacker` (so binding + signature pass) while setting
`issuer = victim` — the credential verified Accepted, `Credential.Issuer.Id` reported the victim, and an
allowlist trust policy keyed on the issuer returned Trusted. The self-consistent-forgery-with-disagreeing-
signed-identity-fields class CLAUDE.md flags, made possible purely because two code paths read two different
(both signed, both attacker-controlled) fields. **Rule:** when a format exposes the same authority under two
names, (a) bind on one, (b) **require the two to be equal** as a definitive proof failure when both are
present (here `iss == issuer`, safe because legitimate issuance always sets them equal), and (c) make every
downstream consumer (binding, trust, the consumer-visible accessor) read the **same** anchor. A guard that
only reconciles "clear vs disclosed" for a field misses "field-A vs field-B".

## A selective-disclosure stage is only as strong as the "must-stay-in-the-clear" set — and it's bigger than the substrate's (2026-06-21)

The SD-JWT VC verifier runs structure/validity/status/schema over the issuer-JWT **cleartext**, where a
selectively-disclosable member is replaced by an `_sd` digest. The substrate's reserved set is the JWT one
(`iss/nbf/exp/cnf/vct/vct#integrity/status`) — but the engine's stages read the **VCDM** members
(`validFrom/validUntil/issuanceDate/expirationDate/credentialStatus/credentialSchema`), which the substrate
treats as ordinary and happily lets you disclose. Marking `validUntil` disclosable hid it from
`CheckValidity` ⇒ an **expired credential verified**; a disclosable `credentialStatus` ⇒ **revocation
Skipped**. Hiding a member that gates a check silently disables the check. **Rule:** every member a verifier
stage reads must be forced to stay in the clear — enumerate them yourself (don't inherit the substrate's
narrower reserved list), forbid disclosing them at issuance, **and** add a verify-side guard that rejects any
such member present in the reconstructed payload but absent from the cleartext the stages validate (catches
credentials crafted outside your issuer). The most robust variant is to run the stages over the
substrate-verified disclosed payload, not the cleartext.

**Residual the verifier cannot close (RFC 9901 §4.2.7):** the guards above catch a member that is *revealed*
via a disclosure but missing from the validated document. They cannot catch a holder who simply *withholds*
the disclosure — the leftover `_sd` digest is dropped as a decoy, indistinguishable from a real one, so a
"hidden expiry/status" looks identical to "no expiry/status." This is inherent to SD-JWT (the spec carries
it for `iss`/`nbf`/`exp`/`status` too); the only defence is **issuer-side** — keep validity/status claims
non-disclosable so they're always in the clear — which a conformant issuer (and *our* issuer) does, making
its own credentials immune. Don't claim a verifier-side fix you can't make: document the boundary, make your
own issuance immune, and push the third-party-issuer policy (presentation completeness / Type-Metadata
disclosability) to where it belongs. The lesson: a selective-disclosure verifier's reach stops at "what was
revealed"; "what was withheld" is the issuer's responsibility to make impossible.

## "Can't find the key" must split into "DID didn't resolve" (Indeterminate) vs "DID has no such method" (Failed) (2026-06-21)

The shared `NetDidEnvelopeKeyResolver` (JOSE/COSE from M3, SD-JWT from M4) returned `null` for two very
different situations: the DID couldn't be resolved at all (IO/network/unknown method — genuinely unknown ⇒
Indeterminate) **and** the DID resolved fine but its document doesn't publish the referenced verification
method (a definitive negative — the issuer's published key set does not authorize that `kid`). Collapsing
both to `null → Unresolvable → Indeterminate` let an attacker mangle a tampered/forged credential's `kid`
**fragment** (leaving the base DID resolvable) to downgrade a definitive bad signature to Indeterminate,
which a non-strict policy soft-accepts — defeating the F7 invariant "a forgery must never land on
Indeterminate." **Rule:** a resolver feeding an F7 classification must return a **tri-state** (Resolved /
DidUnresolvable / MethodNotFound), not a nullable. DID-resolved-but-method-absent is Failed, not
Indeterminate; only a genuine resolution/IO failure is Indeterminate. The attacker controls the `kid`, so any
attacker-chosen value that doesn't resolve to a key must be a definitive failure, never "unknown".

## An informational, non-gating verifier hook must not be able to change the verdict (2026-06-21)

The optional SD-JWT VC Type Metadata resolver is informational (M4 doesn't gate on it), but a throwing
resolver propagated out of the substrate verify and was mapped to Indeterminate — so a misconfigured/flaky
(or hostile) resolver could turn an otherwise cryptographically valid credential into Indeterminate (a
soft-DoS). **Rule:** an informational/non-gating hook must be wrapped so a fault becomes "no result"
(best-effort), never a verification outcome; reserve Indeterminate for faults in checks that actually gate the
decision. (A gating hook is the opposite — its fault *should* be Indeterminate, fail-closed.)

## The withheld-disclosure residual is mechanism-independent — it recurs on every selective-disclosure path (2026-06-22)

M4 (SD-JWT) and M5 (bbs-2023) are different mechanisms but hit the *identical* residual: a holder who
**withholds** a verification-critical claim (`validUntil`, `credentialStatus`) the issuer made
selectively-disclosable produces a genuinely valid proof over the reduced set, and the verifier cannot tell
"the credential never had an expiry" from "the holder hid the expiry." Both times the adversarial pass
confirmed an expired/revoked credential Accepts. The defence is the same and is **issuer-side**: those
claims must be non-disclosable (SD-JWT reserved set) / in the mandatory group (bbs-2023, where disclosure is
cryptographically enforced). The verifier-side guards only catch a *revealed-but-inconsistent* member, never
an *omitted* one. **Rule:** when you add any new selective-disclosure mechanism, the verification-critical
member set (`validFrom`/`validUntil`/`issuanceDate`/`expirationDate`/`credentialStatus`/`credentialSchema`/
`issuer`/`id`/`type`/`@context`) must be forced-revealed at issuance, and you must *document the residual*
for credentials this engine verifies but did not issue — don't re-discover it per mechanism. Where this
engine issues, it makes them non-disclosable (so its own credentials are immune); where it only verifies
(e.g. M5's gated issuance), it is the third-party issuer's responsibility and the most you can do is document
+ enforce-at-issuance-when-it-ships.

## Map a throwing substrate's argument exceptions at the boundary, or you leak its types and break your own contract (2026-06-22)

The bbs-2023 deriver caught the substrate's `BbsUnavailableException` and `ProofGenerationException` but not
the `ArgumentException`/`ArgumentNullException` that the substrate's JSON-Pointer parser throws on a
malformed reveal pointer (missing leading `/`, a null element — a trivially common caller mistake). The
adversarial pass turned a holder-supplied bad pointer into an uncaught exception that (a) violated the
method's documented `CredentialFormatException` contract — a caller's `catch (CredentialFormatException)`
misses it → a wallet 500 — and (b) surfaced the internal substrate `JsonPointer` type across the boundary
NFR-005 means to keep clean. **Rule:** at a mechanism boundary that forwards caller-controlled input into a
throw-based substrate, enumerate *every* exception the substrate throws on bad input (not just the
crypto/availability ones) and map them to your documented exception type — `ArgumentException` covers
`ArgumentNullException`; order it after the more-specific catches; keep the top-level null-argument guards
(real programming errors) propagating. Malformed input must never escape as a raw substrate exception.

## Transitive deps defeat "no Newtonsoft in the closure" even with a clean public API (2026-06-19)

Referencing `DataProofsDotnet.Rdfc` (for RDFC suites) pulled dotNetRDF → Newtonsoft.Json + AngleSharp +
HtmlAgilityPack into EVERY consumer's closure, violating NFR-002's closure clause even though no
Newtonsoft type was on our public API. Fix: keep the default System.Text.Json-only (JCS suites) and put
RDFC behind an opt-in package (`Credentials.Rdfc`) that contributes `ICryptosuite` services to a
DI-collected registry. Also watch for *unused* substrate DI packages (`DataProofsDotnet.Extensions.DependencyInjection`)
silently re-introducing the same transitive — check `dotnet list package --include-transitive`.
