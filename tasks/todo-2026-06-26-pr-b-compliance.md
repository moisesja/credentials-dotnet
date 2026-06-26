# PR-B — VCDM 2.0 compliance hardening (v1.0.0 readiness, 2 of 4)

**Status:** PLAN — awaiting approval before any source/test/doc edit.
**Branch (proposed):** `feat/v1-compliance-hardening` off `main` (PR-A merged).
**Goal:** close the achievable VCDM 2.0 structural-conformance gaps and **raise the W3C suite baseline
above 43/59**, landing the stricter validation *inside* the 1.0.0 major (so it isn't a breaking 1.0.x change).
Path to release: PR-A ✅ → **B compliance** → C cleanup → D release.

## Key facts (from reading the W3C suite at /tmp/vcdm2-suite + the shim)
- Every target test POSTs a fixture to **`/credentials/issue`** and expects **HTTP 400/422** to reject (or 2xx
  to accept). The shim calls `IIssuer.IssueAsync`, which runs `StructuralValidator` (via `CredentialBuilder.Seal`)
  before signing — so **the structural validator is the single lever** for almost all of this.
- A/B/C and relatedResource negatives (a)–(d) are **purely structural** (decidable from the JSON). Only the
  relatedResource **digest-mismatch** (e)/(f) needs real fetch+SHA-384, and the suite's digest fixtures are
  **stale (suite bug #166)** — chasing them is hazardous.
- "Not a URL" in the suite = **not an absolute URI with a scheme** (embedded space, no `scheme:`, `null`,
  integer, or an *array* of identifiers). **DIDs and URNs MUST pass** (positive fixtures use `did:example:…`,
  `urn:…`, `https://…`).

---

## Work items

### B1 — Identifier-URL validation (StructuralValidator) — closes 4.04 / 4.07 / 4.10 / 4.11 negatives
Add a `JsonShape.IsAbsoluteUri(node)` helper: a single JSON **string**, `Uri.TryCreate(s, UriKind.Absolute, out var u)`
**and** `u.Scheme` present **and** no whitespace in `s`. Then, **if present**, require an absolute URI for:
- `credential.id` (already must be single non-blank → add URI; reject array/`null`).
- `issuer` bare string, and `issuer.id` on the object form.
- `credentialStatus.id` (optional — only if present), `credentialSchema.id` (required, already; add URI),
  `refreshService.id` (optional), `relatedResource.id` (required; see B4).
- Reject a **multi-valued** `id`/`credentialStatus.id`/`credentialSubject.id` (array) — distinct `*.id_not_single` code.
New problem codes: `id.not_url`, `issuer.not_url`, `credentialStatus.id_not_url`, `credentialSchema.id_not_url`, etc.

### B2 — `proofPurpose` guard at issuance (DefaultIssuer) — DI 1.0 §3.2
In `DefaultIssuer.IssueAsync`, for the Data Integrity form, reject (throw `ArgumentException`/`InvalidOperationException`,
matching the M7 boundary-guard pattern) when `request.ProofPurpose != ProofPurpose.AssertionMethod`. Negative test.

### B3 — `refreshService.type` (StructuralValidator) — 5-advanced-concepts §refreshing
Validate `refreshService` like the other typed members: single object or array; each entry an object with a
non-blank `type`; reject missing type. (`id` optional → covered by B1 if present.)

### B4 — relatedResource **structural** (StructuralValidator) — 5-advanced-concepts §5.3 (a)–(d)
`relatedResource` is a single object or array of objects; each entry must (a) be an object [reject array-of-strings],
(b) have an `id` [B1 URI], (c) have a **unique** `id` across the list, (d) carry **at least one** of `digestSRI` /
`digestMultibase`. Codes `relatedResource.{not_object,missing_id,duplicate_id,missing_digest}`.

### B5 — `name` / `description` §11.1 language value objects (StructuralValidator)
At the credential top level **and** on the `issuer` object: if `name`/`description` is an object (or array of
objects), each object is **closed** — only `@value`, `@language`, `@direction` permitted; reject any other key
(`*.invalid_language_object`). A plain string or absence is always valid.

### B6 — relatedResource **digest integrity** (e)/(f) — DECISION (see below)
The spec's actual "integrity": fetch each `relatedResource.id`, compute SHA-384, compare to `digestSRI`/`digestMultibase`.
Architecturally this is a **verifier-side stage gated on an optional resolver hook** (mirrors status/schema) — NOT
issuer-side. The suite asserts e/f on the **issuer** and against **stale fixtures (#166)**, so it will likely **not
flip green** regardless. **Recommendation:** ship B1–B5 (structural) in this PR; implement the verifier-side
integrity stage as a focused follow-up (PR-B2 or PR-C) and **document e/f honestly** as a gap (suite #166 +
issuer-endpoint mismatch). Alternative: include the verifier stage now (bigger PR, new `IRelatedResourceResolver`
hook + stage + DI + tests). **Your call at plan approval.**

### B7 — Re-measure conformance + raise the baseline (honest)
After B1–B5: clone+build the shim, run `w3c/vc-data-model-2.0-test-suite` (node available), read the **actual**
new passing count, set `W3cVcdm2SuiteTests.PassingBaseline` to the measured value, and rewrite the
[docs/conformance.md](docs/conformance.md) table to reflect what now passes and the residual gaps (JSON-LD term
mapping stays the documented non-goal; relatedResource e/f per B6 decision; any 4.05-types/4.13-VP items remain).
**Never raise the number above what the suite actually reports.**

---

## Known subtleties to resolve *during implementation by running the suite* (not guesses to hardcode)
- **issuer object without `id`:** VCDM §4.7 says an object issuer MUST have an id-URL, so the engine's current
  `issuer.object_missing_id` rejection is spec-correct. The investigation flagged a possible `issuer: {}` accept
  fixture — verify the real fixture; if it genuinely expects accept, document it rather than relax a spec rule.
- **Stricter validation must not regress the engine's own tests / currently-passing suite tests.** All internal
  fixtures use `did:`/`urn:`/`https:` (valid URIs), so B1 should be safe — confirm by running the full suite +
  the engine test suite after each item.

## Verification / DoD
- [ ] Each item lands with structural-validator unit tests (positive + the exact suite negatives) in
      `Credentials.Core.Tests/StructuralValidatorTests.cs`; B2 with a `DefaultIssuer` negative test.
- [ ] Full `dotnet test` green, 0-warning build, no **public API** delta unless B6's hook is included (then
      PublicAPI.Unshipped + samples/api-coverage updated).
- [ ] W3C suite re-run; `PassingBaseline` raised to the measured value; `conformance.md` rewritten honestly.
- [ ] Adversarial pass: confirm the new rules don't over-reject valid VCDM (DIDs/URNs/multi-subject/language
      arrays) and don't open any bypass; confirm B2 can't be evaded.
- [ ] CHANGELOG [Unreleased] (Added/Changed: compliance hardening + new baseline) + lessons; review section here.

## Risks
- Over-strict URI check rejecting a legitimate identifier (mitigate: absolute-URI-with-scheme, **not** http-only;
  unit-test DIDs/URNs/URLs explicitly).
- B6 scope creep — defaulting to structural-only in this PR keeps it focused; the hook is a clean follow-up.
- Suite #166 stale digests — do not chase; pin/document.

---

## Review (2026-06-26) — DONE

**Scope decision:** B6 settled as **structural now; hash-verify deferred to a focused follow-up** (the user
corrected my stale-#166 premise — issue #166 is closed and the fixture digest is current, so hash-verify
*will* pass the suite; it remains a deliberate follow-up to design its 1.0 public hook properly).

**What landed (all internal / private — no public API delta):**
- `JsonShape.IsAbsoluteUri` (absolute-URI-with-scheme; DIDs/URNs/URLs pass; whitespace/scheme-less/null/array reject).
- `StructuralValidator`: identifier-URL on `id`/`issuer`/`credentialStatus.id`/`credentialSchema.id`/
  `credentialSubject.id`/`refreshService.id`/`relatedResource.id`; `refreshService.type`; `relatedResource`
  structural (object/unique-URL-id/≥1 digest); `name`/`description` §11.1 closed language objects (top-level + issuer).
- `DefaultIssuer`: proofPurpose=assertionMethod guard at the role boundary.

**Result:** W3C suite **43 → 57 / 59** (measured twice, deterministic). The 2 remaining are exactly the
unmapped-`type` JSON-LD non-goal and the deferred relatedResource digest — both named in `docs/conformance.md`.
`PassingBaseline` raised to 57; gate verified passing. Full suite green (Core 172 (+25), DI 161 (+1)),
0-warning build.

**Adversarial pass (2 lanes, refute-by-default): HOLDS** — no false-positives (every legitimate identifier
scheme + valid language/relatedResource/refreshService shape passes), no bypasses, no regressions; proofPurpose
guard correctly Ordinal + role-boundary-positioned + DI-only.

**Also:** README Status section de-staled (was "M0 / early development") and pointed at `docs/conformance.md`;
lessons captured (verify "blocked by bug #N" claims against the live tracker + reproduce; tightening belongs
in the major). Deferred follow-up tracked: relatedResource digest hash-verify (+ the two PR-13 backlog edges —
fragment-less `methods[0]`, query-string-in-VM match).
