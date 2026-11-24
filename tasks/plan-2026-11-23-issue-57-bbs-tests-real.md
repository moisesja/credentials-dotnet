# Plan: issue #57, bbs-2023 tests that fail or skip visibly without the BBS native library

**Status:** awaiting approval. Until it is approved, this file is the only change on the branch.
**Date:** 2026-11-23
**Branch:** `test/issue-57-bbs-tests-real` (from `main` @ 66ab8ce)
**Tracking:** issue #57, step 1 of epic #25. The PR will say `Closes #57`: the change is tests, one sample, CI
and docs, and nothing in the published packages changes.

## Owner's intent

Epic #25, instruction 7: "Tests have to run for real. Do #57 first. A BBS test that returns early without the
native library does not count as evidence." Every later sub-issue of the epic adds `bbs-2023` tests, so their
evidence is only as good as this step.

Issue #57 is done when:

1. One test asserts that the BBS native library is available on the runtime identifiers CI runs, and fails
   when it is not.
2. The silent guards become visible skips (`Skip.IfNot`, as the interop tests do) or go away.
3. The sample smoke test fails, or is reported as skipped, when the sample took its "unavailable" branch.
4. It is decided whether CI gets a macOS leg.
5. `docs/conformance.md` names the platforms on which `bbs-2023` is exercised in CI, and the platforms
   NetCrypto ships the native library for.

## What is there today

Checked on 2026-11-23 on `main` @ 66ab8ce, on the development machine (macOS 26.6.2, `osx-arm64`, SDK
10.0.404). "Run" means I ran it; "read" means I read the code or a log.

**Where `bbs-2023` runs.** Three files, and no others in `tests/`, `samples/` or `tools/` (searched for the
cryptosuite, the deriver, the registration call, BLS key types and every early `return`):

| File | Guard today | Result without the library |
|---|---|---|
| `tests/Credentials.Rdfc.Tests/Bbs2023SelectiveDisclosureTests.cs` | `if (!BbsAvailable) { return; }` in 11 methods (14 test cases; one is a theory with four rows) | Passed, silently |
| `tests/Credentials.InteropTests/Bbs2023InteropTests.cs` | `Skip.IfNot(Available, …)` in 2 tests | Skipped, with a reason |
| `samples/Credentials.Sample.Bbs2023/Program.cs` | prints "skipped: …" and returns | `SampleSmokeTests.Bbs2023` Passed, silently |

The issue counted twelve guards. The text occurs twelve times: eleven are guards and one is the comment that
describes them. Three tests in the first file have no guard and need none (`Bbs_issuance_is_gated`,
`UseBbs2023_adds_the_suite_to_capabilities_and_registers_the_deriver`, `UseBbs2023_is_idempotent`).

**The gap, reproduced (run).** A *hidden-library run* in this plan means: copy a project's build output to a
scratch directory, delete `runtimes/<this host's identifier>/native/*zkryptium_ffi*` from the copy, and run
`dotnet test <copy>/<Project>.dll`. The .NET host loads the library from that folder, so this is what a host
without the library looks like. On `main`:

| Hidden-library run | Result |
|---|---|
| `Credentials.Rdfc.Tests` | 29 Passed, 0 Skipped, exit 0. The 14 guarded cases each "pass" in under 1 ms. |
| `Credentials.SampleSmokeTests` | 14 Passed, exit 0. `Bbs2023` passes in 2 ms. |
| `Credentials.InteropTests` | 3 Passed, 2 Skipped (the two BBS tests), exit 0. |
| The sample itself (`dotnet Credentials.Sample.Bbs2023.dll`) | prints "skipped: the native BBS library is unavailable…", exit 0. |

**With the library (run).** The whole suite passes locally: 455 Passed, 0 Skipped (the W3C fact is filtered
out, as in CI).

**CI (read from the log of run 45305843116 on 66ab8ce).** Both legs show the same 455 Passed and 0 Skipped,
including the two skippable interop tests, so the library did load on `linux-x64` and `win-x64`. Nothing
asserts it. The legs took 33 s (Ubuntu) and 92 s (Windows).

**How availability is decided (read, upstream source at the released commits).** DataProofs 2.1.0's
`Bbs2023Cryptosuite.IsAvailable` returns NetCrypto 1.7.1's `DefaultBbsCryptoProvider.IsAvailable`. That is
set once per process by calling into the library and catching `DllNotFoundException`,
`EntryPointNotFoundException` and `BadImageFormatException`.

**What NetCrypto 1.7.1 ships (run: package contents and binary headers).** `zkryptium_ffi` for five runtime
identifiers: `linux-arm64`, `linux-x64`, `osx-arm64`, `osx-x64`, `win-x64`. The two Linux binaries are glibc
builds that need glibc 2.34 or later. Each test project's `.deps.json` declares exactly those five.
moisesja/crypto-dotnet#34 (open) asks for more.

**The FR-014 / FR-031 / FR-042 gate (read).** `FrCoverageGateTests` scans the test sources for `[FrTag]`
attributes. It cannot know whether a tagged test ran. FR-031's only tagged test and one of FR-042's are among
the eleven.

## Decisions

Decisions 2, 5, 6, 7, 8 and 9 are judgement calls the owner can overturn; each names the alternative.

1. **Three outcomes, by host.** CI legs are always in one of the first two rows, so a green CI run means the
   `bbs-2023` tests ran.

   | Host | Availability test | Other tests that need the library | Sample smoke test |
   |---|---|---|---|
   | One of the five platforms, library loads | Passes | Run | Runs |
   | One of the five platforms, library does not load | **Fails** | Skipped, with a reason | Skipped, with a reason |
   | Any other platform (`win-arm64`, for example) | Skipped, with a reason | Skipped, with a reason | Skipped, with a reason |

   This is the issue's own design: one test fails, the rest skip visibly. Removing the guards outright was the
   alternative. It would turn every `bbs-2023` test red on a platform upstream does not ship for, where there
   is nothing to fix.

2. **"One of the five platforms" is decided from the operating system and the process architecture**, mapped
   to an identifier such as `linux-x64` and looked up in one list of five. It does not read
   `RuntimeInformation.RuntimeIdentifier`, whose value can depend on how the SDK was built. A mapping that
   cannot vary is what keeps the availability test from being skipped on a CI leg.
   - Consequence: a Linux host on musl (Alpine), or on glibc older than 2.34, is `linux-x64` or `linux-arm64`
     to this test, the library does not load there, and the availability test fails. That is accurate:
     `bbs-2023` does not work on that host although its platform is on the list. The docs will say so.
   - Alternative: treat musl as "not shipped" and skip. Not taken: it needs a detection rule I cannot verify
     on every distribution, and no CI leg or known developer machine is on musl.

3. **One shared helper, in `Credentials.TestSupport`.** Three test assemblies need the same answer and the
   same skip reason. `TestSupport` is the existing shared test library, and it must not reference
   `Credentials.Rdfc` (the architecture tests keep the RDF stack out of their host). So the helper asks
   NetCrypto's provider, which is already in every test project's graph through `Credentials.Core`. The
   availability test, which lives in `Credentials.Rdfc.Tests`, also asks `Bbs2023Cryptosuite`, the object the
   product asks, and requires the two answers to agree.

4. **Visible skips use `[SkippableFact]` / `[SkippableTheory]` with `Skip.IfNot`**, the style the interop
   tests and the W3C harness already use, and the one the issue names. A custom `[BbsFact]` attribute was
   considered and not taken: it would be a second convention for the same thing.

5. **A second test pins which platforms NetCrypto declares the library for: exactly the five.** It reads the
   test project's `.deps.json`, so it runs on any host and never skips.
   - It catches a release that drops a binary for a platform CI does not run (`linux-arm64`, `osx-x64`).
   - It keeps the list in `docs/conformance.md` true: when crypto-dotnet#34 ships more platforms, the PR that
     takes that release fails this test until the list and the docs are updated.
   - Alternative: "at least the five", which never fails on an addition and lets the docs fall behind.

6. **The sample loses its "unavailable" branch.** A sample that could not show its subject should not exit 0.
   Without the branch, the first BBS call throws NetCrypto's `BbsUnavailableException`, whose message names
   the five platforms, and the process exits non-zero. That is how every sample reports a failure (they throw).
   The smoke test asks the shared helper first and skips visibly, so the three assemblies behave alike.
   - Alternative: keep a branch that prints its own message and exits with a non-zero code, without a stack
     trace. Not taken: it changes the entry point every sample shares, for one sample.

7. **CI gets a macOS leg: `macos-latest` in the `build-test` matrix.**
   - Development happens on macOS. A failure seen locally should be reproducible in CI, and a macOS-only
     break should not wait for the owner's machine to find it.
   - NetCrypto ships two macOS binaries and CI loads neither. Loading has macOS-specific failure modes that
     only a macOS host shows: the code signature Apple Silicon requires, and the minimum OS version the
     binary was built for.
   - Cost: the repository is public (checked with `gh repo view`), and GitHub's billing documentation says
     standard hosted runners are free in public repositories (read today from the `github/docs` source). The
     label must stay `macos-latest`; the `-large` and `-xlarge` labels are billed even there. I expect a run
     time of a minute or two, since the Ubuntu and Windows legs take 33 s and 92 s; it is not measured yet.
   - `macos-latest` is macOS 26 on arm64 according to the `actions/runner-images` README (read today), so
     this leg exercises `osx-arm64`, the development platform. The suite passes there locally.
   - `main` has no branch protection and no rulesets (checked), so a new check changes no merge rule.
   - The three gate jobs (`no-newtonsoft`, `semver`, `api-coverage`) wait for every `build-test` leg. A slow
     macOS queue would delay them. If that becomes a problem, the leg can move to its own job.
   - Alternative: no macOS leg, and the docs say macOS is shipped but not exercised in CI.

8. **No `linux-arm64` or `osx-x64` leg in this PR.** Both have a standard runner that is free for a public
   repository (`ubuntu-24.04-arm`, `macos-26-intel`; read today from GitHub's runner table), so all five
   platforms could be exercised. The issue asks about macOS only, and which platforms CI covers for the whole
   library is a wider question than `bbs-2023`. The docs will list these two as shipped and not exercised in
   CI. Whether to add either leg is a question for the owner.

9. **The proof that the availability test can fail is a one-off, recorded in the Review**, as every earlier
   mutation check in this repo is. It will be a real hidden-library run on `osx-arm64` and on `linux-arm64`
   (the .NET SDK container is on this machine: SDK 10.0.404, glibc 2.39), and on `linux-x64` under emulation
   if that container runs. Windows cannot be run locally. There the claim rests on the failure path being the
   same managed code on every OS, and on a test that pins the platform mapping for all five platforms.
   - Alternative: a standing CI step on every leg that hides the library and requires the availability test
     to fail (about 20 s per leg, one more script to maintain). It would give the Windows proof.

10. **`FrCoverageGateTests` does not change.** It stays a static scan. What changes is that it can no longer
    be read as coverage in a run that tested nothing: the same `dotnet test` run that executes the gate also
    executes the availability test on that leg.

11. **No change under `src/`, no PRD change.** No public API moves, so the ApiCompat and PublicAPI gates are
    untouched. None of the epic's open PRD decisions (5 to 12) is reached by this issue.

Considered and not taken:

- **CI declares the expected platform per leg in an environment variable, and the test checks it.** It would
  catch a runner label that silently changes architecture. Decision 2 already makes the mapping fixed.
- **An architecture test that forbids hand-written availability guards in test sources.** The guarantee that
  matters, a green CI run means the tests ran, comes from the availability test and does not depend on how a
  later test is written.

## Changes, file by file

| File | Change |
|---|---|
| `tests/Credentials.TestSupport/Credentials.TestSupport.csproj` | Add a versionless `NetCrypto` package reference (the version is already pinned centrally). |
| `tests/Credentials.TestSupport/BbsNativeLibrary.cs` (new) | The helper: `IsAvailable`; the list of five runtime identifiers; the host's identifier, from a pure function of operating system and architecture; the skip reason, which names the host and the five. |
| `tests/Credentials.Rdfc.Tests/BbsNativeLibraryTests.cs` (new) | Three tests. (a) The availability test of decision 1. (b) The declaration test of decision 5. (c) A theory that pins the mapping: each of the five platforms maps to its identifier and is on the list; `win-arm64`, `linux-arm` and one non-Linux Unix are not. |
| `tests/Credentials.Rdfc.Tests/Credentials.Rdfc.Tests.csproj` | Add the `Xunit.SkippableFact` reference (already pinned centrally). |
| `tests/Credentials.Rdfc.Tests/Bbs2023SelectiveDisclosureTests.cs` | The 11 guards become `Skip.IfNot` on the helper; 10 `[Fact]` become `[SkippableFact]` and the theory becomes `[SkippableTheory]`. Remove the `BbsAvailable` field and the "COVERAGE NOTE"; correct the class summary. Test bodies do not change. |
| `tests/Credentials.InteropTests/Bbs2023InteropTests.cs` | Use the helper and its reason in place of the private `Available` field. Reword "IsAvailable-gated" in the summary and in the `.csproj` comment. |
| `tests/Credentials.SampleSmokeTests/SampleSmokeTests.cs` and its `.csproj` | `Bbs2023` becomes a `[SkippableFact]` that skips on the helper, then runs the sample. Add the `TestSupport` project reference and the `Xunit.SkippableFact` package reference. |
| `samples/Credentials.Sample.Bbs2023/Program.cs` | Remove the "unavailable" branch (decision 6). Correct the summary, which promises "a clear skip and exits 0". |
| `tests/Credentials.RoundTripTests/Credentials.RoundTripTests.csproj` | Comment only: it says the project exercises `bbs-2023` derivation, and it holds no such test. |
| `.github/workflows/ci.yml` | `os: [ubuntu-latest, windows-latest, macos-latest]`, with a comment that names the three platforms and points at `docs/conformance.md`. |
| `docs/conformance.md` | A new section, "bbs-2023: platforms" (below). |
| `CHANGELOG.md` | An *Unreleased* entry (below). |
| This file | Checklist ticks and the Review. |

## Checklist

- [ ] 1. Helper in `Credentials.TestSupport`
- [ ] 2. `BbsNativeLibraryTests`: availability, declaration, mapping
- [ ] 3. The 11 guards in `Bbs2023SelectiveDisclosureTests` become visible skips
- [ ] 4. `Bbs2023InteropTests` uses the helper
- [ ] 5. Sample: remove the "unavailable" branch; smoke test skips visibly
- [ ] 6. Stale comments (`RoundTripTests.csproj`, class and project summaries)
- [ ] 7. `ci.yml`: macOS leg
- [ ] 8. Local verification, including the hidden-library runs (next section)
- [ ] 9. Adversarial pass; findings handled
- [ ] 10. `docs/conformance.md`
- [ ] 11. `CHANGELOG.md`
- [ ] 12. PR opened; CI evidence from the three legs recorded in the Review
- [ ] 13. Review section written

## How each "Done when" bullet is proven

**1. The availability test exists and can fail.**

- Hidden-library run of `Credentials.Rdfc.Tests`: the availability test is reported Failed with its own
  message, and the run exits non-zero. On `main` the same run exits 0 with 29 Passed.
- Broken-library run: the library file replaced by an empty file of the same name. Same expectation.
- Both on `osx-arm64` and in the `linux-arm64` container; on `linux-x64` under emulation if it runs.
- The declaration test: in a copy, remove one platform's entry from the `.deps.json`, then add a sixth. It
  must fail both times.
- The mapping theory passes for all five platforms on every host, including the three CI platforms.
- CI on the PR: on each of the three legs, the summaries of `Credentials.Rdfc.Tests`, `Credentials.InteropTests`
  and `Credentials.SampleSmokeTests` show 0 Skipped. With a green job, that means the availability test ran
  and passed there.

**2. No silent guard is left.**

- `grep` finds no `if (!BbsAvailable)` and no `IsAvailable` under `tests/` or `samples/` outside the helper
  and the availability test.
- Hidden-library run of `Credentials.Rdfc.Tests`: exactly the 14 cases of the 11 methods are reported Skipped,
  each with the reason. The only tests of `Bbs2023SelectiveDisclosureTests` reported Passed are the three that
  never needed the library. `Credentials.InteropTests`: 2 Skipped, as today, with the shared reason.
- With the library, the list of tests (`dotnet test --list-tests`) differs from `main` only by the new tests,
  and all pass.

**3. The sample smoke test.**

- Hidden-library run of `Credentials.SampleSmokeTests`: `Bbs2023` is reported Skipped with the reason. On
  `main` it is Passed.
- The sample run directly from a hidden-library copy exits non-zero and prints NetCrypto's message. On `main`
  it exits 0.
- One local mutation, not committed: with the skip line removed from the smoke test, the hidden-library run
  reports `Bbs2023` Failed. This shows the sample has no path that returns quietly.

**4. The macOS leg.** Decision 7, and the PR's `build + test (macos-latest)` job: green, with 0 Skipped in the
three assemblies.

**5. The docs.** The diff of `docs/conformance.md`. Its list of five is the list the declaration test pins,
and its "exercised in CI" rows are the `ci.yml` matrix.

**Everything else.** Release build with 0 warnings; `dotnet test Credentials.sln -c Release --filter
"Category!=Conformance"`; `tools/check-no-newtonsoft-closure.sh` (TestSupport gains a reference),
`tools/run-api-coverage.sh` (the sample changes) and `tools/check-api-compat.sh`.

## Adversarial pass

One subagent, after the implementation passes locally and before the PR is opened. It gets the diff and this
goal, not my conclusions: **make `dotnet test` exit 0, or CI go green, while `bbs-2023` did not run; or make
any test that needs the library report Passed without it.** It reports every attempt in detail. It should at
least try:

- Hiding the library in other ways: an empty file, a binary for the wrong architecture, the whole `runtimes`
  folder gone, hidden in one test assembly only (the availability test runs in one of three).
- The filters CI and the release workflow use (`Category!=Conformance`): can any of them drop the
  availability test?
- A `Skip.IfNot` left under a plain `[Fact]`, a wrong row in the platform mapping, a failure in the helper's
  static initialisation, any test that catches the "unavailable" exception and carries on.
- The declaration test against stale files in a build output directory.
- The product on a host without the library, which nothing has run before: `IBbsDeriver.DeriveAsync` should
  throw its documented `NotSupportedException`, and `IVerifier` must not return Accepted for a `bbs-2023`
  credential, genuine or altered. By reading, it reports Indeterminate.

This PR changes no signing, binding or integrity code, so epic instruction 8 adds no new attack tests. The
existing tamper and issuer-binding tests keep their bodies; the test-list comparison shows none was lost.

A finding that would let a forged, altered, expired or revoked credential verify goes to the epic
orchestrator and into no commit, PR or issue.

## Docs and CHANGELOG

**`docs/conformance.md`, new section "bbs-2023: platforms".**

- `bbs-2023` needs NetCrypto's native BBS library. A table of the five runtime identifiers NetCrypto 1.7.1
  ships it for, and for each whether CI exercises it: `linux-x64` (`ubuntu-latest`), `win-x64`
  (`windows-latest`), `osx-arm64` (`macos-latest`); `linux-arm64` and `osx-x64` shipped, not exercised in CI.
- The Linux binaries are glibc builds and need glibc 2.34 or later. More platforms are requested in
  moisesja/crypto-dotnet#34.
- What the tests do: the three outcomes of decision 1, and which test fails. On a platform outside the five,
  `IBbsDeriver.DeriveAsync` throws `NotSupportedException`, as its documentation says.
- The interop bullet loses "`IsAvailable`-gated" and points at the new section.

**`CHANGELOG.md`, *Unreleased*, under *Changed*.** One entry for #57: the `bbs-2023` tests fail or skip
visibly without the native library; CI runs on macOS; the `Bbs2023` sample no longer exits 0 when it cannot
run; the platform list is documented.

**Not changed.** The PRD (decision 11). `README.md` (a thin router). `SECURITY.md` (no change in what the
library guarantees). Older CHANGELOG entries that say "`IsAvailable`-gated" are history and stay.

## Risks

- **First macOS run.** A test that depends on the platform could fail on the hosted runner although the suite
  passes on the development machine. It would be fixed in this PR, or reported if it is not this PR's to fix.
- **A NetCrypto release that adds platforms fails the declaration test** until the list and the docs are
  updated. That is the intent of decision 5. The epic's table says crypto-dotnet#34 needs "nothing in this
  repo"; with this test it needs one list entry and one docs line.
- **A developer on musl, or on glibc older than 2.34, gets one failing test** (decision 2).
- **The sample now fails on an unsupported host** where it used to print "skipped" and exit 0.
- **The availability test runs in one assembly.** The other two resolve the same NetCrypto package (versions
  are pinned centrally), so one load check stands for all three. The adversarial pass probes this.
- **`Credentials.TestSupport` gains a package reference.** NetCrypto is already in the graph of every project
  that references it. The architecture tests and the no-Newtonsoft script are re-run to confirm.

## Out of scope, reported to the epic orchestrator

- The API-coverage gate measures `Credentials.Core` and the DI package only. Epic instruction 10 relies on it
  for new public API, and all BBS API lands in `Credentials.Rdfc`.
- `ISecuringCapabilities` reports `bbs-2023` as supported on a host where the library is missing.
- No test covers what the product does on a host without the library.

## Review

To be written when the work is done.
