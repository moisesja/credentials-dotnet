# PR-A — Security fixes (v1.0.0 readiness, 1 of 4)

**Status:** PLAN — awaiting approval before any source/test edit.
**Branch (proposed):** `fix/v1-security-tristate-ssrf` off `main`.
**Scope:** the two must-fix security findings from the v1.0.0 readiness review. Compliance (PR-B),
robustness cleanup (PR-C), and the 1.0.0 release (PR-D) are out of scope here and land as later PRs.

Roadmap context (gated workflow — human merges each before the next): **A security** → B compliance →
C cleanup → D release.

---

## Finding S1 — Embedded Data Integrity key-resolution is not tri-state (F7 break on the primary path)

**Severity:** High. Default policy (`TreatIndeterminateAsFailure=true`) masks it (Indeterminate→Rejected),
so out-of-the-box deployments are NOT exploitable. It bites under a non-strict policy
(`TreatIndeterminateAsFailure=false`), and it emits a dishonest diagnostic even by default.

**Root cause (traced end-to-end):**
- `NetDidVerificationMethodResolver.ResolveAsync` ([NetDidVerificationMethodResolver.cs](../src/Credentials.Core/Resolution/NetDidVerificationMethodResolver.cs)) returns nullable `ResolvedVerificationMethod?` and collapses **two** outcomes to `null`:
  - base DID unresolvable (IO/network/unknown method) — genuinely unknown → should be Indeterminate ✓
  - DID resolves but the referenced VM fragment is absent / key unusable (lines 64-91) — a definitive negative → should be **Failed** ✗ (currently null too)
- `DataIntegrityMechanism.VerifyAsync` ([:81-84](../src/Credentials.Core/Securing/Internal/DataIntegrityMechanism.cs)) maps `null` → `SecuringVerificationResult.Unresolvable(...)`.
- `DefaultVerifier` maps `SecuringVerificationStatus.Unresolvable → CheckResult.Indeterminate` ([:467](../src/Credentials.Core/Roles/DefaultVerifier.cs)) and `Invalid → CheckResult.Failed` ([:466](../src/Credentials.Core/Roles/DefaultVerifier.cs)).
- `DecisionComposer` ([:34-38](../src/Credentials.Core/Verification/DecisionComposer.cs)): under a non-strict policy an Indeterminate proof check yields overall **Indeterminate** (soft-accepted), not Rejected.

**Attack:** take any DI credential, mangle the proof's `verificationMethod` fragment to a non-existent
one over a still-resolvable base DID (e.g. `did:key:zABC#bogus`). The mechanism early-returns
`Unresolvable` **before** the substrate crypto runs → Indeterminate. A non-strict verifier soft-accepts a
forged/tampered credential. (For `did:key`, `did:web`, custom resolvers alike — the base DID resolves, the
fragment doesn't.) The enveloping path (JOSE/COSE/SD-JWT) already defends this via the tri-state
`EnvelopeKeyResolution` + regression test `SdJwtVc_mangled_kid_fragment_is_failed_not_indeterminate`; the
embedded DI path — the most common form — lacks both. This is the long-tracked open gap.

**Fix (mirror the envelope tri-state; all changes internal — no public surface delta):**

1. **New file** `src/Credentials.Core/Resolution/IVerificationMethodTriResolver.cs` — engine-internal,
   symmetric with `IEnvelopeKeyResolver`:
   - `enum VerificationMethodResolutionStatus { Resolved, DidUnresolvable, MethodNotFound }`
   - `readonly record struct VerificationMethodResolution` with `Status`, `Method` (substrate
     `ResolvedVerificationMethod?`, meaningful only when `Resolved`), and `Resolved(method)` /
     `DidUnresolvable` / `MethodNotFound` factories.
   - `internal interface IVerificationMethodTriResolver { Task<VerificationMethodResolution> ResolveAsync(string vmUrl, CancellationToken ct = default); }`
2. **`NetDidVerificationMethodResolver.cs`** — implement `IVerificationMethodTriResolver` instead of the
   substrate `IVerificationMethodResolver` (nothing else consumes the substrate interface; the substrate
   pipeline still gets a `StaticVerificationMethodResolver` built from the resolved methods). Return:
   - base DID unresolved / `ResolutionMetadata.Error` → `DidUnresolvable`
   - VM list empty / fragment not found / key material unusable → `MethodNotFound`
   - otherwise → `Resolved(method)`.
   Update the class XML summary (the current "null → Indeterminate" comment is the bug, replace it).
3. **`DataIntegrityMechanism.cs`** — depend on `IVerificationMethodTriResolver`; in the pre-resolve loop,
   collect across **all** verification methods and prefer fail-closed:
   - any `MethodNotFound` → `SecuringVerificationResult.Invalid("verification_method_not_found")` (→ Failed)
   - else any `DidUnresolvable` → `SecuringVerificationResult.Unresolvable("verification_method_unresolvable")` (→ Indeterminate)
   - else all `Resolved` → proceed with the substrate pipeline (unchanged).
   Update the class XML summary to state the tri-state distinction (matching the envelope mechanisms).
4. **`CredentialsServiceCollectionExtensions.cs`** ([:64-77](../src/Credentials.Extensions.DependencyInjection/CredentialsServiceCollectionExtensions.cs)) — register `IVerificationMethodTriResolver` (was `IVerificationMethodResolver`) and feed it to `DataIntegrityMechanism`.

**Tests (TDD: RED first, confirm the current bug, then GREEN):**
- `tests/Credentials.Core.Tests/NetDidVerificationMethodResolverTests.cs` — convert to the tri-state; add
  the missing-fragment case directly: valid VM → `Resolved`; unresolvable base DID → `DidUnresolvable`;
  **resolvable base DID + bogus fragment → `MethodNotFound`** (the previously-uncovered case).
- `tests/Credentials.Extensions.DependencyInjection.Tests/M1IssueVerifyTests.cs` — add, modeled on the M4
  test (covers CLAUDE.md "post-sign tampering" + the non-strict-policy soft-accept):
  - `DataIntegrity_mangled_verification_method_fragment_is_failed_not_indeterminate`: issue a DI
    credential (did:key Ed25519), replace `proof.verificationMethod` fragment with a bogus one (base DID
    still resolvable). Assert strict `Check(Proof).Status == Failed` + diagnostic code
    `verification_method_not_found`; assert non-strict (`TreatIndeterminateAsFailure=false`)
    `Decision == Rejected`.
  - Companion (guard against over-correction): a genuinely-unresolvable **base** DID stays Indeterminate
    (extend/confirm the existing `Unresolvable_verification_method_is_indeterminate` to assert
    `Check(Proof).Status == Indeterminate` under a non-strict policy).

---

## Finding S2 — SSRF / HTTPS-downgrade via unrestricted HTTP redirects (opt-in HTTP hooks)

**Severity:** High. The optional HTTP status/schema fetchers validate the scheme of the **initial** URL
only, but the named `HttpClient` follows 3xx redirects by default (`AllowAutoRedirect=true`), so an HTTPS
URL can redirect to `http://169.254.169.254/…`, an internal host, or cleartext — silently breaking the
library's explicit "HTTPS is required by default" promise. (The three redirect-related review findings
collapse to this one root cause.) Core stays egress-agnostic; this is confined to the opt-in DI HTTP layer.

**Root cause:** `HttpFetch.TryGetAsync` ([:21-30](../src/Credentials.Extensions.DependencyInjection/Http/HttpFetch.cs)) checks `uri.Scheme` once; `CredentialsBuilder.UseHttpStatusListFetcher`/`UseHttpSchemaResolver` ([:123,155](../src/Credentials.Extensions.DependencyInjection/CredentialsBuilder.cs)) register `AddHttpClient(HttpFetch.ClientName)` with no handler config → default redirect-following.

**Fix (disable auto-redirect on the library's named client — a status list / schema is a single canonical
document; no public surface change):**
- In `CredentialsBuilder`, add a private `ConfigureNamedHttpClient()` helper:
  `Services.AddHttpClient(HttpFetch.ClientName).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false })`.
  Call it from both `UseHttpStatusListFetcher` and `UseHttpSchemaResolver` (replacing the bare
  `AddHttpClient` calls). Disabling redirects means the GET to the internal/redirected host **never fires**
  (defence is preventive, not a post-hoc response check).
- Update both methods' XML docs: the HTTPS-only guarantee now holds through redirects (auto-redirect
  disabled); a caller who genuinely needs redirects must reconfigure the `"credentials-dotnet"` named
  client themselves (and owns the SSRF posture if they do).

**Test:** `tests/Credentials.Extensions.DependencyInjection.Tests/HttpFetchRedirectTests.cs` — loopback
`System.Net.HttpListener` with endpoint A (`302 Location: <B>`) and endpoint B (`200`, increments a hit
counter). Build the provider via `AddCredentials().UseHttpStatusListFetcher()`, resolve `IStatusListFetcher`,
fetch A. Assert: B's hit counter stays **0** and the result is `NotFound` (redirect not followed). Control:
a direct fetch of B returns `Found`. (Internals are visible to this test project, so `HttpFetch.TryGetAsync`
can be exercised directly too if the listener-via-public-seam proves flaky.)

---

## Cross-cutting verification (Definition of Done for PR-A)
- [ ] RED: write the S1 + S2 tests first, run them, confirm they FAIL on current `main` (prove the bugs).
- [ ] GREEN: apply the fixes; the new tests pass.
- [ ] Full suite green: `dotnet test -c Release` (all ~360 + new tests), 0 warnings (`dotnet build -c Release`).
- [ ] No public-API delta: `PublicAPI.Unshipped.txt` unchanged; ApiCompat / PublicAPI / no-Newtonsoft /
      FrCoverage gates green (PR-A is behavior-only).
- [ ] Adversarial re-verification: spawn refute-by-default agents on the two fixes — specifically try to
      (a) still land a mangled-fragment DI forgery on Indeterminate, and (b) still follow a redirect to an
      internal host — and confirm both fail. Clean up any throwaway tests; leave the tree clean.
- [ ] `CHANGELOG.md` [Unreleased] → Security: S1 (DI tri-state key resolution / F7) + S2 (redirect SSRF).
- [ ] `tasks/lessons.md`: "the tri-state F7 fix must cover EVERY verification-method resolver, not just the
      enveloping one — an asymmetric defense leaves the primary path exposed"; and "validating only the
      initial request URL is insufficient when the client follows redirects — disable auto-redirect on a
      first-party fetch client."
- [ ] Review section appended to this file.

## Risks / notes
- Dropping the substrate `IVerificationMethodResolver` from `NetDidVerificationMethodResolver`: confirmed
  the only consumer is `DataIntegrityMechanism`; the substrate pipeline is fed `StaticVerificationMethodResolver`,
  not our resolver, so the substrate interface is no longer needed on our type.
- Multi-proof credentials: the fail-closed precedence (any MethodNotFound ⇒ Failed) is stricter than
  today's short-circuit-on-first-null; intentional and safe.
- `ConfigurePrimaryHttpMessageHandler` sets the primary handler; a caller who later configures their own
  primary handler (registration-order-last) wins — documented as their responsibility.

---

## Review (2026-06-25) — DONE

**Status:** implemented, verified, adversarially re-verified. Ready for human review/merge.

**What landed**
- S1 (DI tri-state F7): new internal `IVerificationMethodTriResolver` + `VerificationMethodResolution`
  (`Resolved | DidUnresolvable | MethodNotFound`); `NetDidVerificationMethodResolver` returns it;
  `DataIntegrityMechanism` maps `MethodNotFound → Invalid("verification_method_not_found")` (Failed) and
  `DidUnresolvable → Unresolvable` (Indeterminate), fail-closed across multi-proof; DI registration swapped.
- S2 (redirect SSRF): `CredentialsBuilder.ConfigureFetchHttpClient()` registers the named client with
  `AllowAutoRedirect = false`; both `UseHttp*` methods use it; docstrings made precise ("by default";
  caller that replaces the primary handler owns the redirect posture).
- All changes **internal / behaviour-only — no public API delta** (PublicAPI files untouched; 0-warning
  build ⇒ RS0016/17 clean; no new package refs ⇒ no-Newtonsoft closure + api-coverage unaffected).

**Verification**
- RED proven on `main`: mangled fragment → `Indeterminate` (want Failed); redirect → followed (`{}` body
  returned). GREEN after fix: both pass.
- Full suite: **0 failures** (Core 145, DI 159 (+2), Architecture 9, RoundTrip 9, Rdfc 21, Interop 5,
  SampleSmoke 14); only the conformance `SkippableFact` skipped (no Node/suite locally). 0-warning build.
- Adversarial pass (3 refute-by-default agents): **S1 holds** (multi-proof fail-closed; holder-binding VP
  path uses the same mechanism, covered), **regression-hunt holds** (internal-only interface, no public
  leak, HTTP defaults intact). **S2** raised a "caller-override" path — adjudicated **not an attacker
  capability** (attacker controls only the credential URL, not DI registration; a bare
  `AddHttpClient("credentials-dotnet")` does not clobber the setting; only an explicit primary-handler
  replacement does, which is the documented caller-owns-egress contract). Acted on its one valid point —
  documentation over-claim — by qualifying the docstrings with "by default". Idempotency-guard suggestion
  declined (registering identical config twice is idempotent; a guard would not prevent caller override).

**Lessons captured:** the tri-state F7 fix must cover every VM resolver (asymmetric defense = no defense);
validating only the initial request URL is insufficient when the client follows redirects.
