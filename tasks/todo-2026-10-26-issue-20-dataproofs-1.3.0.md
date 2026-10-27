# Task — Issue #20: Rebuild against DataProofs 1.3.0 (JOSE/SD-JWT `MissingMethodException`) + v1.2.0 release

Status: **APPROVED 2026-10-26, with changes: version 1.2.0; NetCrypto 1.7.1 (latest) instead of the
1.4.0 floor. IMPLEMENTED on branch `fix/dataproofs-1.3.0-issue-20` and verified (see Review).**
The "Problem" and "Findings" evidence comes from a scratch worktree of `main@d06943c`.

## Problem (verified, not taken on trust)

`Credentials.Core` 1.1.1 is compiled against `DataProofsDotnet.Jose` 1.1.0. Jose 1.3.0 replaced
`JwsSigner..ctor(ISigner, string)` with `..ctor(ISigner, string, JwsKidPlacement)`. The change is
source-compatible but breaks binary compatibility; the Jose XML docs for both versions confirm this. Any
app that resolves Jose 1.3.0 hits `MissingMethodException` on every Credentials JOSE signing path. That
includes every app on `DidComm.Core` 1.4.1, which floors `DataProofsDotnet.Jose >= 1.3.0`.

**Reproduced** with a scratch consumer app that references `DidComm.Core` 1.4.1 and the published
`Credentials.*` 1.1.1, running all 14 repo samples: **10/14 pass**. The 4 failures all throw
`Method not found: 'Void DataProofsDotnet.Jose.Signing.JwsSigner..ctor(NetCrypto.ISigner, System.String)'`:

- `JoseEnvelope`: `vc+jwt` issuance
- `SdJwtVc`: SD-JWT VC issuance
- `SdJwtPresentation`: holder KB-JWT
- `PresentationJose`: holder `vp+jwt`. **The issue doesn't name this path.** It reaches the same constructor
  through `JoseEnvelopingMechanism`.

Root cause beyond this instance: DataProofs' 1.3.0 changelog states that *"binary compatibility is
explicitly out of scope for this project"*. Its minor releases can break binary compatibility, so
Credentials must be rebuilt whenever its DataProofs floor moves.

## Findings beyond the issue

1. **NetDid 3.x is in the same graph.** `DidComm.Core` 1.4.1 also floors `NetDid.Core >= 3.1.0` and
   `NetCrypto >= 1.5.0`, so a combined app loads NetDid.Core **3.1.0** under Credentials, which is compiled
   against 2.3.0. This was checked at runtime. With the trial build, the DidComm consumer passes **14/14**
   samples, running NetDid.Core 3.1.0 alongside NetDid.Method.Key and NetDid.Extensions.DependencyInjection
   2.3.0. That covers did:key resolution for DI, JOSE and COSE verification, presentations and status lists.
   The net-did 3.0.0 changelog agrees: every change 2.x consumers compile against is additive.
   → **No NetDid bump in this release.** Moving to NetDid 3.x is an optional follow-up, not needed for #20.
2. **The AngleSharp security pin from #18 is now redundant.** `DataProofsDotnet.Rdfc` 1.3.0 itself floors
   `AngleSharp >= 1.6.0`, a patched version. Credentials' 1.5.2 pin is what caused item 3 of the issue
   (the `NU1605` downgrade). Kept, it has to be bumped every time DataProofs raises its floor. Trial check
   without the pin: AngleSharp resolves to 1.6.0 in Rdfc and Conformance.VcApi, **0 vulnerable packages
   across 29 projects**, and the build has 0 warnings. → **Remove the pin.** The alternative is a one-line
   bump to 1.6.0, which leaves the same trap for the next DataProofs release.
3. **`main` CI is red on push too**, not just the scheduled job. Today's `AGENTS instructions` commit
   (run 40422367272) fails restore with `NU1902` on `Microsoft.Build.Tasks.Git` 10.0.300
   (GHSA-23fw-v26w-5fgq). Bumping SourceLink fixes both.
4. **The scheduled Conformance workflow is `disabled_inactivity`.** GitHub disabled it after 60 days with
   no repo activity; its last run was 2026-09-19. Merging this fix will not make it run again. It has to be
   re-enabled (`gh workflow enable Conformance`) for the issue's "scheduled CI green" criterion to be met.
5. **DataProofs 1.2.0–1.3.0 also changed `kid` handling.** The changes: `kid` placement, unprotected-`kid`
   reads, and header-disjointness enforcement. Its security note warns that an unprotected `kid` is not
   a signer identity. Credentials parses only **compact** JWS (`JwsParser.ParseCompact`,
   `JoseEnvelopingMechanism.cs:140`, and `VcJose` / SD-JWT compact), which has no unprotected header,
   so the risk should not apply. The adversarial pass below has to confirm that rather than assume it.

## Changes (branch `fix/dataproofs-1.3.0-issue-20`)

- [x] `Directory.Packages.props`
  - `DataProofsDotnet.Core/Jose/Cose/Rdfc/Extensions.DependencyInjection` 1.1.0 → **1.3.0**, with a
    comment explaining why: #20, the binary break, and DataProofs' no-binary-compat policy.
  - `NetCrypto` 1.2.0 → **1.7.1**, your choice; the plan proposed the 1.4.0 floor.
    `DataProofsDotnet.Core 1.3.0` floors ≥ 1.4.0. The 1.4.0 → 1.7.1 changes are additive (key-store
    custody APIs and hardening). One verify-side change matters: **from 1.5.0, high-S ES256K signatures
    are accepted**, so ECDSA signatures are malleable. That's recorded in the props comment and added to
    the adversarial brief.
  - `Microsoft.SourceLink.GitHub` 10.0.300 → **10.0.403**, the latest stable 10.0.x, which patches
    GHSA-23fw-v26w-5fgq. Build-only (`PrivateAssets=All`), so it doesn't appear in consumers' graphs.
  - Remove the `AngleSharp` `PackageVersion` and its #18 security-pin comment (finding 2).
  - Update the header comment's "verified against the local NuGet cache" date and issue reference.
- [x] `src/Credentials.Rdfc/Credentials.Rdfc.csproj`: remove the `AngleSharp` `PackageReference` and its comment.
- [x] `Directory.Build.props`: `CredentialsVersion` 1.1.1 → **1.2.0** (see the version decision below).
- [x] `CHANGELOG.md`: a `## v1.2.0 - 10/26/2026` entry covering:
  - built against DataProofs 1.3.0; requires Jose ≥ 1.3.0; fixes `MissingMethodException` on all four
    JOSE signing paths
  - needed by apps on `DidComm.Core` ≥ 1.4.1; apps still on Jose 1.2.x stay on 1.1.1
  - SourceLink GHSA bump
  - AngleSharp pin removed (now carried upstream)
  - NetDid 3.1.0 verified to work at runtime
  - no public API change (ApiCompat)
- No source or test changes are expected; the trial needed none. No docs pin these versions; grep of
  `docs/` and `README.md` came back empty.

### Version decision: recommend **1.2.0** (the issue suggested 1.1.2, or 1.2.0)

The repo already treats a dependency-floor raise as a minor bump: v1.1.0 (#16) was purely a NetDid /
NetCrypto floor raise. This release does more. It forces consumers off Jose 1.2.x, and a consumer pinned
there gets `NU1605` on upgrade. A patch number would understate that.

## Verification plan (on the real branch, not just the trial)

- [x] `dotnet restore` clean; `dotnet build -c Release -warnaserror`: 0 warnings / 0 errors.
- [x] `dotnet test --filter "Category!=Conformance"`: expect 391 passed (Core 172, DI 161, Rdfc 21,
      SampleSmoke 14, Architecture 9, RoundTrip 9, Interop 5).
- [x] `dotnet list … --vulnerable --include-transitive`: 0 across all projects.
- [x] `tools/check-no-newtonsoft-closure.sh`: NFR-002 OK.
- [x] `tools/check-api-compat.sh`: no breaking changes vs the published 1.1.1 for Core, DI and Rdfc.
- [x] `dotnet pack -p:CredentialsVersion=1.2.0`, then inspect the nuspecs:
      - Core: DataProofs Core/Jose/Cose ≥ 1.3.0, NetCrypto ≥ 1.7.1
      - Rdfc: DataProofs.Rdfc ≥ 1.3.0 and **no** AngleSharp entry
- [x] **Consumer check** (issue "Done when" #2), rerun from the branch's packs in a scratch app with
      `DidComm.Core` 1.4.1:
      - the four JOSE / SD-JWT / KB-JWT / `vp+jwt` samples issue and verify with no `MissingMethodException`
      - expected 14/14, plus loaded-assembly versions printed
      - control with published 1.1.1: 10/14
- [ ] **Adversarial agent** (CLAUDE.md requirement). Brief:
      - attack Credentials' JOSE, SD-JWT, KB-JWT, `vp+jwt` and COSE verification under DataProofs 1.3.0
      - kid rewrites and unprotected / duplicate headers; General/Flattened JSON passed where compact is expected
      - both post-sign tampering and self-consistent forged documents whose signed `kid`/`iss` disagree
        with the issuer
      - also confirm the signed bytes for `vc+jwt`, `dc+sd-jwt` and `kb+jwt` are unchanged from 1.1.0
        (`kid` still protected)
      - report findings in detail; any real finding gets fixed with a regression test before the PR

## Review: adversarial pass (8 probe tests, each run on the new AND the old dependencies)

The upgrade introduces **no exploitable regression**. I checked each claim against the source before
recording it, as lessons.md requires.

- **Unsigned / unprotected `kid` (DataProofs 1.2–1.3): not reachable.** The hypothesis holds, for a
  stronger reason than "compact has no unprotected header". `EnvelopeDetector` routes `{…}` input to the
  Data Integrity path, and only base64url text with exactly two dots reaches JOSE. Credentials also reads
  the `kid` itself from the signed segment and passes DataProofs a constant resolver, so it never uses
  `SignerKid`. Six compact `kid` forgeries were tried: each was rejected by `issuer_binding`,
  `holder_binding` or `PROOF_VERIFICATION_ERROR`.
- **Signed bytes unchanged.** The `kid` stays in the protected header for vc+jwt, the SD-JWT issuer
  JWT, KB-JWT and vp+jwt. Fixed-seed Ed25519 vc+jwt / vp+jwt / vc+cose output is byte-identical between
  old and new dependencies.
- **ES256K high-S (NetCrypto ≥ 1.5.0): behaviour change, not exploitable.** Tokens whose signature
  `S` is replaced by `n − S` now verify. Freshness and binding checks still reject a replay: a stale
  nonce gives `holder_binding_replay`, and `sd_hash` covers the issuer signature. Recorded in the
  CHANGELOG with consumer guidance.
- **Exception contract unchanged.** Hostile headers produce Failed, never an escaped exception, and
  never a wrong Failed-vs-Indeterminate classification.
- **DataProofs 1.1.0 → 1.3.0 source diff** touches only `Jose/Signing/*` and the Rdfc csproj. Core,
  COSE, SD-JWT and bbs-2023/RDFC are unchanged.

**Findings outside #20's scope. None was caused by this upgrade; each reproduces identically on the old
dependencies:**

- **Security-relevant findings in Credentials** were reported privately in a draft GitHub security
  advisory, as `SECURITY.md` requires, rather than recorded here. They are targeted for v1.2.0, so the
  `v1.2.0` tag waits for that fix.
- **Upstream (DataProofs), harmless here:** a signed protected header with an invalid-UTF-8 member name
  is Accepted, which contradicts DataProofs 1.3.0's changelog. It is inside the signature, so it cannot be
  exploited. Filed upstream.
- **Credentials, interop nit, fails closed:** a vc+jwt with a trailing `\n` is rejected
  `envelope_malformed`. `JoseEnvelopingMechanism` doesn't trim it; `SdJwtVcMechanism` does.

**Regression guards kept:** `tests/Credentials.Extensions.DependencyInjection.Tests/JoseSubstrateRegressionTests.cs`.
This ports four of the adversarial probes into assertion-only tests:
- JSON-serialized JWS with an unsigned `kid` is never accepted through any entry point
- compact forgeries whose signed `kid` disagrees with the issuer or holder are rejected
- every emitted token carries its `kid` in the protected header
- hostile headers fail without an escaped exception, and a bad signature is Failed, not Indeterminate

## Release / outward actions (each needs your go-ahead)

- [ ] Commit, push, open a PR that closes #20. Then **wait for review and address comments before
      anything else** (lesson 2026-06-23).
- [ ] After merge: `gh workflow enable Conformance` (finding 4), then trigger one `workflow_dispatch` run
      to show the scheduled job is green.
- [ ] Push tag `v1.2.0` to publish to nuget.org. **Irreversible.** Left to you, as with v1.1.1.
      **Delayed by your decision until the security-advisory fix lands, so it ships in v1.2.0.** Update the
      CHANGELOG's v1.2.0 date when tagging.

## Out of scope (proposed follow-ups, separate issues if you want them)

- **Latest-dependencies CI job:** a scheduled job that floats DataProofs, NetDid and NetCrypto to the newest
  packages and runs the signing tests plus the DidComm consumer check. Given DataProofs' stated
  no-binary-compat policy, this is the structural guard against a repeat. It needs its own design
  (floating CPM versions vs. a consumer-app harness), so it doesn't belong in a dependency-only patch.
- **`EnablePackageValidation`:** largely covered already by `tools/check-api-compat.sh`, and it would not
  have caught a dependency-side break.
- **NetDid 3.x floor:** not required (finding 1); revisit when Credentials needs a 3.x API.

## Trial evidence (scratch worktree, `main@d06943c`, the four issue bumps)

- Restore clean; Release build 0 warnings / 0 errors; tests 391 passed (matches the issue).
- Consumer + `DidComm.Core` 1.4.1: trial build 14/14 vs. published 1.1.1 10/14. Loaded at runtime: Jose 1.3.0,
  NetCrypto 1.5.0, NetDid.Core 3.1.0.
- ApiCompat: no breaking changes for any of the 3 packages vs 1.1.1.
- AngleSharp pin removed: 1.6.0 resolved transitively, 0 vulnerable, 0 warnings.
