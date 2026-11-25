# Plan: issue #57, bbs-2023 tests that fail or skip visibly without the BBS native library

**Status:** in progress. The owner made the external review of the PR the approval gate for epic #25 on
2026-11-23 (issue #25, instruction 1), so this plan ships in the PR and the work did not wait for a separate
approval. The first commit on the branch (c96fd95) is this plan alone.
The plan was re-made on 2026-11-24, after three rounds of external review, by the owner's decision: see
"Re-plan" below. The record of the earlier rounds is condensed there and under "Review".
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

## Re-plan, 2026-11-24 (review round 4): a gate that runs without the library, and a scan with one job

**The owner's decision, 2026-11-24.** Asked how round 4 should close the convention check in this PR, the
owner chose "CI gate + slim scanner": on every CI leg, run the tests again with the native library removed
and require each `bbs-2023` test to fail; the source scan shrinks to one job, saying which test classes are
`bbs-2023` classes, and stops restricting how tests are written. This is the owner's decision, not a
default. It replaces the orchestrator's ruling of 2026-11-23 that the one-off runs were enough (decision 9).

**Why.** The property is about what happens at run time: a test that needs the library must not pass or
skip without it. Three review rounds and four adversarial passes read source to prove it, and each found
something new. The last, on cf28395, found a hole no source rule covers: a `[SkippableTheory]` whose rows
come up empty without the library runs no body, xUnit reports nothing for it, and the run exits 0
(reproduced on cf28395: the scan lists both forms as guarded, and neither appears in the results). By then
the scan also rejected much that a contributor would write, and fifteen more sub-issues will write
`bbs-2023` tests.

**The principle.** xUnit decides what a test is. Running without the library decides whether a test is
guarded. The source scan decides only which test classes are `bbs-2023` classes. No rule depends on
recognising a test, an attribute or a call in source.

**The gate** (`tools/check-bbs-tests-without-library.sh`, driving `tests/Credentials.BbsGate`):

1. It runs on all four `build + test` legs after the normal test step, from that step's result files, and
   locally by the same script. It works on copies under `artifacts/bbs-gate`, so the build output is not
   touched.
2. It copies everything under `tests/` but `obj` and the other outputs, and each test output folder, removes
   every `zkryptium_ffi` file from the copies, and runs the same assemblies under the same filter. Both
   runs have `GITHUB_ACTIONS=true`, so that a missing library has to fail a test on any host.
3. It compares the two runs test by test, by class and method name, not by row: rows may differ between
   the runs. For a test of a `bbs-2023` class, every result without the library must be a failure, and by
   the helper's own message; passed, skipped, failed for another reason and no result at all are each
   reported by name.
4. The named list of tests that need no native library stays, now a text file with a reason per entry, and
   checked by running: a listed test must pass without the library. One test a line.
5. The whole suite is compared, not only the `bbs-2023` classes (my choice on the orchestrator's point 5):
   a test of any other class must do the same in both runs, row for row. That reports a test that depends
   on the library through another file and fails or skips, which scope by names cannot see. It costs the
   no-library run of the other assemblies; the assemblies run side by side.
6. The run has to be a no-library run: the named availability check must pass with the library and fail
   without it, and at least one library file must have been removed. Otherwise the gate fails.
7. Test assemblies are taken from the result files of the normal run, so a new test project is covered
   without anyone editing the script, and every built test project of the solution has to be among them.
8. The gate is proven by committed coverage that runs on every leg: its comparison on made-up results (unit
   tests), and `tests/Credentials.GateFixtures`, a small project of deliberately wrong tests that is not
   in the solution. The script's `--self-test` builds it, runs the gate on it and requires exit code 1
   and exactly the findings in `expected-findings.txt`: the reviewer's case 1 (the call in a block
   comment) and case 2 (trait first, early return), both forms of the empty theory, a test that skips
   where it must fail, a listed test that fails, a test outside the `bbs-2023` classes whose outcome
   changes, and what the adversarial rounds on this design found.

**The scan, with one job** (`BbsScope`, in `tests/Credentials.BbsGate`; its tests stay in
`Credentials.ArchitectureTests`): the types declared in test source files whose code names anything of
`bbs-2023`. A class that derives from one of them inherits its tests; that is read from the test
assemblies, not from source. Kept, because that one decision needs them: the syntax tree, the choice of files, UTF-8, the
language version held to the build's, the syntax-error rule, and one reading of each file (`#if` is a
finding in any test source file; the reviewer's round 3 fixture and its variants stay).

**Removed:** every rule that tried to prove from source that a test is guarded, and its fixtures: the
first-statement rule, the lists of known attributes and base types, sealed and partial, static imports,
skips outside a test body, return types, shadowed names, duplicate tests, the category rule. `#define` and
`#undef` are no longer findings: without an `#if` they choose no code.

**Two things that stay, and why.**
- `[Trait("Category", "Bbs")]` stays on the existing tests as a convenience for `--filter`. Nothing enforces
  it any more, and the docs say so.
- The `bbs-2023` smoke test stays in a class of its own, `Bbs2023SampleSmokeTests`. Scope is by class now,
  so in one class with the other thirteen samples every one of them would be a `bbs-2023` test to list. The
  class is no longer partial-for-the-scan; it is just a second class.

**Order of work:** this plan (its own commit); the gate project and the script; the slim scan and its
tests; the fixture project and the self-test; CI; an adversarial round on the whole design; docs,
CHANGELOG, PR description, lessons.

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

This section is the design as built. Where it differs from the first version of this plan (commit c96fd95),
"What changed during the work" at the end says what changed and why.

Who decided what:

- **The owner**, on 2026-11-23: the external PR review is the approval gate, and CI also gets a `linux-arm64`
  leg (decision 8).
- **Defaults the owner can overturn**, each with its alternative: decisions 2, 5, 6, 7, 9, and leaving out
  `osx-x64` in decision 8. Decisions 2, 8 and 9 were put to the epic orchestrator, whose rulings are recorded
  with them. A ruling is the orchestrator's default, not the owner's.

1. **Without the library, a test that needs it fails or is skipped. It never passes.**

   | Host | Every test that needs the library, and the sample's smoke test |
   |---|---|
   | The library loads | Runs |
   | The library does not load, and it has to (decision 2) | **Fails**, with a message that says why |
   | The library does not load on any other host (`win-arm64`, for example) | Skipped, with a reason that names the platform |

   The rule is applied by each test, in its own test process, so it holds for every test assembly and for any
   subset of the tests. Removing the guards outright was the alternative. It would turn every `bbs-2023` test
   red on a platform upstream does not ship for, where there is nothing to fix.

2. **Where the library has to load.** Either rule is enough:
   - **On one of the five platforms NetCrypto ships it for.** The platform is the operating system and the
     process architecture, as the runtime itself reports them. It is not read from
     `RuntimeInformation.RuntimeIdentifier`, which the `DOTNET_RUNTIME_ID` environment variable overrides.
   - **On GitHub Actions, whatever the platform.** When `GITHUB_ACTIONS` is `true` no such test is skipped: a
     missing library fails it. So a green CI leg means the `bbs-2023` tests ran on it, and a leg on a platform
     outside the five cannot go green without the library. Adding such a leg takes a deliberate change to
     this rule.
   - **musl and old glibc are Linux, and fail.** NetCrypto's Linux builds are glibc builds that need glibc
     2.34 or later. A Linux host on musl, or on an older glibc, is `linux-x64` or `linux-arm64` by operating
     system and architecture, the library does not load there, and the tests fail with a message that says
     so. That is accurate: `bbs-2023` does not work on that host.
   - Ruling of the epic orchestrator: never skip on GitHub Actions; fail on old glibc; skip on musl if musl
     can be detected reliably, and otherwise keep the first plan (fail) and document it.
   - **Why musl is not skipped.** Three ways of detecting musl were built and each was run on real hosts: the
     runtime identifier, the process map, and asking the C library whether it is glibc. Each one worked on
     Alpine, and each one gave a way to turn the failure into a skip on a glibc host, off CI, by setting a
     variable or placing a file (adversarial findings below). CI was never affected, because of the GitHub
     Actions rule. But a skip that can be forced where the library is shipped is the thing this issue
     removes, and a musl host is red in any case (see "Considered and not taken", BLS keys). Without the
     exemption, no skip can be reached on a shipped operating system and architecture at all.
   - Alternative: skip on musl, detected by asking the C library (the most accurate of the three, about 25
     lines). Cost: someone who puts a file named `libc.so.6` next to the tests on a glibc host, off CI, gets
     a skip.

3. **One shared helper, `BbsNativeLibrary` in `Credentials.TestSupport`**, with one call,
   `BbsNativeLibrary.RequireOrSkip()`, that every test needing the library makes before it touches
   `bbs-2023`. Three test assemblies need the same decision, and a test author cannot get it half right.
   - The call is two public steps, so each can be tested: `OutcomeFor` is the rule as a pure function, and
     `Enforce` carries an outcome out on the calling test.
   - With the library present, which is the case on every CI leg, `RequireOrSkip()` just returns, and a
     regression in it would go unnoticed until the day the library is missing. So one test runs the real
     call where the library is missing, on every host and every CI leg: it loads a second copy of NetCrypto
     and of the helper into a load context that refuses to load `zkryptium_ffi`, and requires the call to
     fail (or, on a platform outside the five and off CI, to skip).
   - Every `bbs-2023` test class and the sample's smoke test carry `[Trait("Category", "Bbs")]`, which only
     the interop tests had. `dotnet test --filter "Category=Bbs"` now selects them all.
   - **A test that forgets the call is caught by running without the library** (since the re-plan of
     2026-11-24; before that an architecture test read the sources). See "Re-plan" above.

4. **A skip is an xUnit skip**: `[SkippableFact]` / `[SkippableTheory]`, the style the interop tests and the
   W3C harness already use. A `RequireOrSkip()` under a plain `[Fact]` fails instead of skipping, so a wrong
   attribute cannot hide anything. A custom `[BbsFact]` attribute was considered and not taken: it would be a
   second convention for the same thing.

5. **A test pins what NetCrypto declares: the library, under its file name, for exactly the five platforms.**
   It reads the test project's `.deps.json`, so it runs on any host.
   - It catches a release that drops a binary for a platform CI does not run (`osx-x64`).
   - It keeps the list in `docs/conformance.md` true: when crypto-dotnet#34 ships more platforms, the PR that
     takes that release fails this test until the list and the docs are updated.
   - It proves a declaration. Only a run on the platform shows that the binary loads.
   - A build made for one runtime (`dotnet build -r <rid>`) lists only that platform's assets. There the test
     is skipped with a reason, except on GitHub Actions, where it fails.
   - Alternative: "at least the five", which never fails on an addition and lets the docs fall behind.

6. **The sample fails when it cannot run.** Its "unavailable" branch now throws `NotSupportedException`, the
   exception `IBbsDeriver` documents for this case, and the process exits non-zero. A sample that could not
   show its subject should not exit 0. Its smoke test calls `RequireOrSkip()` first, like every other test.
   - Alternative: delete the branch and let the first BBS call throw. Tried first and not kept: NetCrypto's
     exception carries the loader's output, about forty lines of `dlopen` attempts, in front of the message.

7. **CI gets a macOS leg: `macos-latest` in the `build-test` matrix.**
   - Development happens on macOS. A failure seen locally should be reproducible in CI, and a macOS-only
     break should not wait for the owner's machine to find it.
   - NetCrypto ships two macOS binaries and CI loaded neither. Loading has macOS-specific failure modes that
     only a macOS host shows: the code signature Apple Silicon requires, and the minimum OS version the
     binary was built for.
   - Cost: the repository is public (checked with `gh repo view`), and GitHub's billing documentation says
     standard hosted runners are free in public repositories (read on 2026-11-23 from the `github/docs`
     source). The label must stay `macos-latest`; the `-large` and `-xlarge` labels are billed even there.
   - `macos-latest` is macOS 26 on arm64 according to GitHub's runner table (read the same day), so this leg
     exercises `osx-arm64`, the development platform.
   - `main` has no branch protection and no rulesets (checked), so a new check changes no merge rule.
   - The three gate jobs (`no-newtonsoft`, `semver`, `api-coverage`) wait for every `build-test` leg. A slow
     queue on a new leg would delay them. If that becomes a problem, the leg can move to its own job.
   - Alternative: no macOS leg, and the docs say macOS is shipped but not exercised in CI.

8. **CI gets a `linux-arm64` leg, `ubuntu-24.04-arm`, by the owner's decision of 2026-11-23** ("For CI
   platform, also add linux-arm64"). It is a standard runner, free for a public repository (GitHub's runner
   table, read the same day). The matrix now exercises four of the five platforms.
   - **`osx-x64` stays out.** The owner did not ask for it, and the Intel macOS label (`macos-26-intel`) is
     on a retirement path. The docs list it as shipped and not exercised. This part is a default the owner
     can overturn; the cost is one matrix entry and about a minute of free runner time per run.
   - Nothing else in the workflows assumes x64 on the new leg: its steps are checkout, `setup-dotnet` from
     `global.json`, restore, build and test, with no cache and no tool download. The three gate jobs run on
     `ubuntu-latest` and only wait for it.

9. **The proof that these tests can fail is in two parts.**
   - A one-off, recorded in the Review, as every earlier mutation check in this repo is: real runs with the
     library hidden on `osx-arm64`, `linux-arm64` and `linux-x64` (emulated), a real old-glibc host and a
     real musl host.
   - A standing one, inside the suite: the load-context test of decision 3 runs the failing path on every
     leg, Windows included. It came out of the adversarial pass, which showed that nothing else would notice
     a broken helper while the library is present.
   - Ruling of the epic orchestrator, 2026-11-23: the one-off is enough; no standing CI step.
   - **Superseded on 2026-11-24 by the owner's decision:** a standing step on every leg removes the library
     and requires each `bbs-2023` test to fail. See "Re-plan" above.

10. **`FrCoverageGateTests` does not change.** It stays a static scan of `[FrTag]` attributes. What changes
    is that a tagged `bbs-2023` test can no longer pass without running, and cannot be skipped on CI.

11. **No change under `src/`, no PRD change.** No public API moves, so the ApiCompat and PublicAPI gates are
    untouched. None of the epic's open PRD decisions (5 to 12) is reached by this issue.

Considered and not taken:

- **CI declares the expected platform per leg in an environment variable, and a test checks it.** It would
  catch a runner label that silently changes architecture. The GitHub Actions rule already keeps any leg from
  skipping, whatever its platform.
- **An architecture test that forbids hand-written availability guards in test sources.** On CI a test with
  such a guard still runs, because the library is there, and off CI the helper call that the convention test
  requires fails or skips before the guard is reached.
- **Checking the convention by behaviour, not by reading sources**, was not taken at first and is what the
  re-plan of 2026-11-24 does.
- **Treating BLS key generation like the BBS library.** `Bbs_issuance_is_gated` needs no BBS call, but it
  generates a BLS key, which needs NetCrypto's second native library (`blst`). Where that is missing the test
  fails loudly with `DllNotFoundException`. NetCrypto has no availability check for it (crypto-dotnet#34),
  and #43 replaces this test, so it is documented and left as it is.

## Changes, file by file

| File | Change |
|---|---|
| `tests/Credentials.TestSupport/BbsNativeLibrary.cs` (new) | The helper: `RequireOrSkip()`, made of `OutcomeFor` (the rule, a pure function) and `Enforce` (what an outcome does to the calling test); `IsAvailable`; the list of five runtime identifiers; the host's identifier, from a pure function of operating system and architecture. |
| `tests/Credentials.TestSupport/Credentials.TestSupport.csproj` | Versionless `NetCrypto` and `Xunit.SkippableFact` package references (both already pinned centrally). Header comment updated. |
| `tests/Credentials.Rdfc.Tests/BbsNativeLibraryTests.cs` (new) | Seven tests. (a) The named check that the library is there, with the agreement assertion of decision 3. (b) A theory that pins the rule of decisions 1 and 2, all eight cases. (c) What each outcome does to a test: return, fail, skip. (d) Where the rule's inputs come from on this host. (e) The real call against a copy of NetCrypto that is refused the library. (f) A theory that pins the platform mapping. (g) The declaration test of decision 5. |
| `tools/check-bbs-tests-without-library.sh`, `tests/Credentials.BbsGate/` (new, round 4) | The no-library gate: the script, and a console project with the scope scan (`BbsScope`), the reading of result files and the comparison of the two runs. `Directory.Packages.props` and the project file gain `Microsoft.CodeAnalysis.CSharp`, for this tool alone. |
| `tests/Credentials.GateFixtures/` (new, round 4; not in the solution) | Deliberately wrong `bbs-2023` tests, the list and the findings the gate must report for them. Run by the script's `--self-test` on every leg. |
| `tests/Credentials.ArchitectureTests/BbsScopeTests.cs`, `NoLibraryGateTests.cs`, `BbsScopeFixtures/` (new, round 4; they replace the convention test of rounds 1 to 3) | Tests of the scope scan over the real sources and over fixtures, and of the comparison over made-up results. |
| `tests/Credentials.SampleSmokeTests/Bbs2023SampleSmokeTests.cs` (new; `SampleSmokeTests.Bbs2023.cs`, a part of a partial class, in review round 2) | The `bbs-2023` smoke test, in a class and a file of its own, so that the other samples' tests stay outside the convention scan. |
| `tests/Credentials.Rdfc.Tests/Bbs2023SelectiveDisclosureTests.cs` | The 11 guards become `BbsNativeLibrary.RequireOrSkip()`; 10 `[Fact]` become `[SkippableFact]` and the theory becomes `[SkippableTheory]`. The `BbsAvailable` field and the "COVERAGE NOTE" go; the class summary is corrected; the class gains the `Bbs` category. Test bodies do not change. |
| `tests/Credentials.Rdfc.Tests/Credentials.Rdfc.Tests.csproj` | `Xunit.SkippableFact` reference. |
| `tests/Credentials.InteropTests/Bbs2023InteropTests.cs` and its `.csproj` | The two tests call `RequireOrSkip()` in place of their own `Skip.IfNot`. "IsAvailable-gated" reworded. The file now imports `Credentials.TestSupport`, so its two `[TestSupport.FrTag]` attributes are written `[FrTag]`, the form the FR gate's scan recognises. |
| `tests/Credentials.SampleSmokeTests/SampleSmokeTests.cs` and its `.csproj` | `Bbs2023` becomes a `[SkippableFact]` that calls `RequireOrSkip()`, then runs the sample. `TestSupport` project reference and `Xunit.SkippableFact` package reference. |
| `samples/Credentials.Sample.Bbs2023/Program.cs` | The "unavailable" branch throws (decision 6). The summary, which promised "a clear skip and exits 0", is corrected. |
| `tests/Credentials.RoundTripTests/Credentials.RoundTripTests.csproj` | Comment only: it said the project exercises `bbs-2023` derivation, and it holds no such test. |
| `.github/workflows/ci.yml` | `os: [ubuntu-latest, windows-latest, macos-latest, ubuntu-24.04-arm]`, with a comment that names the four platforms and points at `docs/conformance.md`. |
| `docs/conformance.md` | New section, "bbs-2023: platforms". The interop bullet loses "`IsAvailable`-gated". |
| `CHANGELOG.md` | An *Unreleased* entry under *Changed*. |
| This file | Decisions, checklist ticks and the Review. |

## Checklist

- [x] 1. Helper in `Credentials.TestSupport`
- [x] 2. `BbsNativeLibraryTests`: the named check, the rule, its enforcement, its inputs, the call without the library, the mapping, the declaration
- [x] 3. The 11 guards in `Bbs2023SelectiveDisclosureTests` call the helper
- [x] 4. `Bbs2023InteropTests` calls the helper
- [x] 5. Sample: the "unavailable" branch throws; its smoke test calls the helper
- [x] 6. Stale comments (`RoundTripTests.csproj`, class and project summaries)
- [x] 7. `ci.yml`: macOS and `linux-arm64` legs
- [x] 8. Local verification, including the hidden-library runs
- [x] 9. Adversarial pass: the gate (three rounds) and the product; findings handled
- [x] 10. `docs/conformance.md`
- [x] 11. `CHANGELOG.md`
- [x] 12. PR opened; CI evidence from the four legs recorded in the Review
- [x] 13. Review section written
- [x] 14. External review, round 1: observations 1, 2, 4 and 5 addressed; 3 left as it is
- [x] 15. External review, round 2: the convention scan rebuilt on a syntax tree, with fixtures
- [x] 16. External review, round 3: one reading for every test source file; the early exits audited; three
  adversarial rounds, with what they found closed or recorded as a limit
- [x] 17. External review, round 4 (re-plan): the no-library gate on every leg, the scan cut down to scope,
  committed coverage of what the gate must report, two adversarial rounds on the whole design

## How each "Done when" bullet is proven

The results are in the Review.

**1. A test asserts the library is available and fails when it is not.**
`BbsNativeLibraryTests.Bbs_native_library_loads_wherever_it_has_to` is the named one; every test that needs
the library applies the same rule.

- Hidden-library runs of each of the three test assemblies, with the library deleted and with it replaced by
  an empty file: the tests that need it are reported Failed and the run exits non-zero. On `main` the same
  runs exit 0.
- The same on `linux-arm64` and `linux-x64`, and on real old-glibc and musl hosts, where the shipped
  library cannot load.
- The load-context test, which runs the failing path inside the suite on every leg.
- The declaration test against altered copies of the `.deps.json`.
- CI on the PR: on each of the four legs the three assemblies show 0 Skipped under a green job.

**2. No silent guard is left.**

- `grep` finds no `if (!BbsAvailable)` and no `IsAvailable` under `tests/` or `samples/` outside the helper,
  `BbsNativeLibraryTests` and the sample's throwing branch.
- In the hidden-library runs no test that needs the library is reported Passed: the 14 cases of the 11
  methods, the 2 interop tests and the smoke test are Failed.
- The list of tests differs from `main` only by the new tests.

**3. The sample smoke test.**

- Hidden-library run of `Credentials.SampleSmokeTests`: `Bbs2023` is Failed. On `main` it is Passed.
- The sample run directly from a hidden-library copy exits non-zero. On `main` it exits 0.
- One local mutation, not committed: with the `RequireOrSkip()` line removed from the smoke test, the
  hidden-library run reports `Bbs2023` Failed with the sample's own exception. The sample has no path that
  returns quietly.

**4. The macOS leg** (and the owner's `linux-arm64` leg): decisions 7 and 8, and the PR's four `build + test`
jobs.

**5. The docs.** The diff of `docs/conformance.md`. Its list of five is the list the declaration test pins,
and its "exercised in CI" column is the `ci.yml` matrix.

**Everything else.** Release build with 0 warnings; `dotnet test Credentials.sln -c Release --filter
"Category!=Conformance"`; `tools/check-no-newtonsoft-closure.sh`, `tools/run-api-coverage.sh` and
`tools/check-api-compat.sh`.

## Adversarial pass

Two independent subagents, after the implementation passed locally and before the PR was opened. Each got the
code and a goal, not my conclusions, and worked in its own copy of the tree.

- **The test gate**, three rounds. Goal: make `dotnet test` exit 0, or CI go green, while `bbs-2023` did not
  run; make any test that needs the library report Passed without it; make it skip where it has to fail;
  make the tests of the helper pass while wrong. The second round, by a fresh subagent, attacked the rework
  that the first round caused; the third attacked the host detection and the helper's own tests. (An earlier
  attempt at the second round was lost to a network failure and produced nothing; it was run again from the
  start.)
- **The product on a host without the library**, which nothing had run before: `ISecuringCapabilities`,
  `IBbsDeriver.DeriveAsync`, and `IVerifier` on genuine, altered and forged `bbs-2023` credentials, each made
  with the library and verified without it.

This PR changes no signing, binding or integrity code, so epic instruction 8 adds no new attack tests. The
existing tamper and issuer-binding tests keep their bodies; the test-list comparison shows none was lost.

A finding that would let a forged, altered, expired or revoked credential verify goes to the epic
orchestrator and into no commit, PR or issue.

## Docs and CHANGELOG

- **`docs/conformance.md`, new section "bbs-2023: platforms".** The five runtime identifiers NetCrypto 1.7.1
  ships the library for and which of them CI exercises; the glibc 2.34 requirement of the Linux builds; what
  the tests do without the library; old glibc and musl; the sample; crypto-dotnet#34.
- **`CHANGELOG.md`, *Unreleased*, under *Changed*.** One entry for #57.
- **Not changed.** The PRD (decision 11). `README.md` (a thin router). `SECURITY.md` (no change in what the
  library guarantees). Older CHANGELOG entries that say "`IsAvailable`-gated" are history and stay.

## Risks

- **First run on two new runners.** A test that depends on the platform could fail on a hosted runner
  although the suite passes on the development machine and in the `linux-arm64` container.
- **A NetCrypto release that adds, drops or renames a platform's library fails the declaration test** until
  the list and the docs are updated. That is the intent of decision 5. The epic's table says crypto-dotnet#34
  needs "nothing in this repo"; with this test it needs a list entry and a docs line.
- **A developer on musl, or on glibc older than 2.34, gets failing `bbs-2023` tests.** That is accurate:
  `bbs-2023` does not work on that host.
- **The sample now fails on a host without the library**, where it used to print "skipped" and exit 0.
- **`Credentials.TestSupport` gains two package references.** Both are already in the graph of the test
  projects that use them. The architecture tests and the no-Newtonsoft script were re-run.

## Out of scope, reported to the epic orchestrator

- The API-coverage gate measures `Credentials.Core` and the DI package only. Epic instruction 10 relies on it
  for new public API, and all BBS API lands in `Credentials.Rdfc`. The orchestrator is filing it as its own
  sub-issue.
- What the product does on a host without the library: for #59.
- `Bbs_issuance_is_gated` fails where NetCrypto's BLS library is missing (musl): for #43 or crypto-dotnet#34.

## Review

Written on 2026-11-24. Everything but the last section was written before the PR was opened. "Run" means
I ran it and read the output. All numbers are for the code as committed (386da36); earlier revisions are
named where they matter.

### Results with the library

- Release build: 0 warnings, 0 errors.
- **477 passed, 0 skipped** on `osx-arm64`: Core 204, DI 181, Rdfc 51, SampleSmoke 14, Architecture 9,
  RoundTrip 9, Interop 5, Conformance 4 (the W3C fact is filtered out, as in CI). `main` has 455. The 22 new
  tests are all in `BbsNativeLibraryTests`: the named check, 8 cases of the rule, what an outcome does to a
  test, where the inputs come from, the call without the library, 9 cases of the mapping, and the
  declaration test. `dotnet test --list-tests` shows nothing removed.
- The same 477 and 0 skipped, with `GITHUB_ACTIONS=true`, in a `linux-arm64` container (glibc 2.39) and in a
  `linux-x64` container under emulation.
- `tools/run-api-coverage.sh`: 53 covered, 0 uncovered. `tools/check-no-newtonsoft-closure.sh`: clean.
  `tools/check-api-compat.sh`: no breaking change in the three packages.

### Results without the library

A hidden-library run copies a test project's build output, removes the host's library from the copy and runs
the copied assembly:

```sh
cp -R tests/Credentials.Rdfc.Tests/bin/Release/net10.0 "$SCRATCH/rdfc"
rm "$SCRATCH/rdfc/runtimes/osx-arm64/native/libzkryptium_ffi.dylib"   # or: truncate it to an empty file
dotnet test "$SCRATCH/rdfc/Credentials.Rdfc.Tests.dll" --logger "console;verbosity=normal"
```

On `osx-arm64`, before and after:

| Hidden-library run | `main` @ 66ab8ce | This branch |
|---|---|---|
| `Credentials.Rdfc.Tests` | 29 Passed, exit 0; 14 cases "pass" in under 1 ms | 36 Passed, **15 Failed**, exit 1 |
| `Credentials.InteropTests` | 3 Passed, 2 Skipped, exit 0 | 3 Passed, **2 Failed**, exit 1 |
| `Credentials.SampleSmokeTests` | 14 Passed, exit 0 | 13 Passed, **1 Failed**, exit 1 |
| The sample, run directly | prints "skipped", exit 0 | `NotSupportedException`, exit 134 |

- The 15 are the 14 cases of the 11 converted methods and the named check. The 36 that pass never needed
  the library, among them `Bbs_issuance_is_gated`, the two registration tests and the rest of
  `BbsNativeLibraryTests`.
- The failure reads: "NetCrypto ships the BBS native library (zkryptium_ffi) for osx-arm64, but it did not
  load in this process, so bbs-2023 cannot be tested here. Check the NetCrypto package's
  runtimes/osx-arm64/native asset. See docs/conformance.md." On Linux it adds that the Linux builds are glibc
  builds that need glibc 2.34 or later and do not load on musl.
- With the library replaced by an empty file, the outcomes are identical, test for test.

The other hosts, all run:

| Host | What it is | Result without a loadable library |
|---|---|---|
| `linux-arm64`, glibc 2.39 | `mcr.microsoft.com/dotnet/sdk:10.0` container | Library deleted: Rdfc 15 Failed, Interop 2 Failed, SampleSmoke 1 Failed, each exit 1. |
| `linux-x64`, glibc 2.39 | the same image under emulation | The same. |
| `linux-arm64`, glibc 2.28 | AlmaLinux 8 container, SDK from Microsoft's install script | Nothing removed: the shipped library cannot load. Rdfc 15 Failed, Interop 2 Failed, SampleSmoke 1 Failed. `Bbs_issuance_is_gated` passes. |
| `linux-arm64` on musl | Alpine 3.24 SDK container | Nothing removed: the glibc build cannot load. Rdfc 16 Failed (the 15 and `Bbs_issuance_is_gated`), Interop 2 Failed, SampleSmoke 1 Failed. The same with `GITHUB_ACTIONS=true`. |
| `linux-arm` (32-bit), outside the five | the same image for `linux/arm/v7` under emulation; tests built on the host, run with `--filter "Category=Bbs"` | Nothing removed: there is no library for it. Rdfc 15 Skipped, Interop 2 Skipped, SampleSmoke 1 Skipped, each with "did not load on this host (linux-arm)". With `GITHUB_ACTIONS=true` the same 15, 2 and 1 are Failed, and the inputs test fails too: a CI leg on a platform outside the five. |

On that 32-bit host two more tests fail in both settings, for reasons that are not this change:
`Bbs_issuance_is_gated` (no BLS library for the platform either) and one registration test (a
`NullReferenceException` while a cryptosuite is constructed, under the emulator). The compiler crashed the
emulator, which is why the tests were built on the host.

**`Bbs_issuance_is_gated` on musl.** It fails with `DllNotFoundException` for `libblst.so`, on `main` as well.
The test makes no BBS call, but it generates a BLS key, and NetCrypto's BLS library has no musl build either.
It is documented in `docs/conformance.md` and left as it is (see "Considered and not taken").

**Attempts to turn the failure into a skip**, on the `linux-arm64` and `linux-x64` containers with the
library deleted and `GITHUB_ACTIONS` unset. Each still gave 15 Failed and 0 Skipped:
`DOTNET_RUNTIME_ID=linux-musl-<arch>`; `DOTNET_RUNTIME_ID=win-arm64`; the test directory under a path that
contains ` /lib/ld-musl-`; a file named `libc.so.6` next to the tests, and in `runtimes/<rid>/native`; a
file named like musl's loader in `/usr/lib`, preloaded. The middle four are the ways the adversarial rounds
got past the three musl detectors; the committed code has no detector to get past.

**The same scenarios the adversarial rounds used against the gate**, on `osx-arm64`:

- Library missing from the `InteropTests` and `SampleSmokeTests` output only, the exact CI command, with
  `GITHUB_ACTIONS=true`: exit 1 (Interop 2 Failed, SampleSmoke 1 Failed, Rdfc 51 Passed).
- Library missing from the `Rdfc.Tests` and `SampleSmokeTests` output only, `--filter "Category=Bbs"`:
  exit 1 (Rdfc 15 Failed, SampleSmoke 1 Failed, Interop 2 Passed).

### Mutation checks

- **The helper**, fifteen mutants, each built in a scratch copy and run against `BbsNativeLibraryTests` with
  the library present, which is the CI situation, with `GITHUB_ACTIONS` unset and set. Thirteen are killed;
  the two that survive behave like the original on every host the tests run on.

  | Mutant | Killed by |
  |---|---|
  | `RequireOrSkip()` does nothing; treats the library as always available; computes the outcome and drops it; always skips when the library is missing | the call without the library, in both settings |
  | Passes "not shipped" to the rule | the call without the library, off GitHub Actions (on it the outcome is a failure either way) |
  | `Enforce` skips where it should fail; `Enforce` returns where it should skip | what an outcome does to a test |
  | The rule skips on a shipped platform | the rule theory |
  | `IsShippedForHost` always false; host operating system unknown; host always Linux | where the inputs come from, in both settings |
  | `IsShippedForHost` true only on GitHub Actions | where the inputs come from, off GitHub Actions |
  | The variable name misspelt | where the inputs come from, on GitHub Actions |
  | Passes "not on GitHub Actions" to the rule | **survives**: on a shipped platform the outcome is a failure either way |
  | Host identifier taken from `RuntimeInformation.RuntimeIdentifier` | **survives**: the two agree on a Microsoft build unless `DOTNET_RUNTIME_ID` is set |

- **The smoke test without its `RequireOrSkip()` line** (in a scratch copy), hidden-library run: `Bbs2023`
  Failed with the sample's own `NotSupportedException`. The sample has no path that returns quietly.
- **The declaration test** against altered copies of `Credentials.Rdfc.Tests.deps.json`. It passes unaltered
  and fails for each of: `win-x64` dropped; a `linux-musl-x64` entry added; the `win-x64` asset turned into a
  `.pdb`; the `linux-x64` asset renamed; all five entries moved under another package; an asset typed
  `runtime`; an entry's `rid` changed.
- **A build for one runtime** (`dotnet test -r osx-arm64`): the declaration test is Skipped with its reason,
  and the other 21 tests of the class pass; with `GITHUB_ACTIONS=true` it is Failed.

### What was not run

- **Windows without the library, as a real host.** No Windows host was available. On the Windows CI leg the
  load-context test runs the failing path of the helper, and the rest is the same managed code on every OS.
- **`osx-x64`** in the committed revision. An earlier revision ran under Rosetta during the second
  adversarial round (all three assemblies passed, and failed with the library deleted). It is not in CI.
- **A GitHub runner, without the library.** Everything above ran on the development machine and in
  containers. The four legs ran with the library; see "CI on the PR".

### Adversarial pass: the test gate

Three rounds, each by an independent subagent that got the code and a goal, not my conclusions. Every
finding was checked against the code and re-run before it was acted on.

**Round 1** attacked the first design, in which one availability test failed and the other tests skipped.

| # | Finding | Checked | Disposition |
|---|---|---|---|
| 1 | **Hole.** With the library missing from the `InteropTests` and `SampleSmokeTests` output only, the exact CI command exits 0 with three tests skipped. The gate ran in one assembly of three. | Real. I had listed it as a risk and argued it away. | **Fixed.** The decision moved into `BbsNativeLibrary.RequireOrSkip()`, which every test that needs the library calls. Replayed above: exit 1. |
| 2 | **Hole**, off CI only. `DOTNET_RUNTIME_ID=linux-musl-arm64` renames a glibc host to musl, and the missing library becomes a skip. | Real: `RuntimeInformation.RuntimeIdentifier` obeys that variable. | **Fixed**, finally by removing the musl exemption (round 3). |
| 3 | Weakness. The `api-coverage` job runs only the smoke tests, so a skipped `Bbs2023` there went unnoticed. | Real. | **Fixed by 1.** The smoke test now fails. |
| 4 | Weakness. `--filter "Category=Bbs"` selects the interop tests and not the gate. | Real; the trait was on the interop tests only. | **Fixed.** Every `bbs-2023` test class and the smoke test carry the trait. Replayed above. |
| 5 | Weakness. "CI" means `GITHUB_ACTIONS=true` and nothing else. | True, and intended: it is the variable this repository's build already keys on. | Kept. The code and the docs say "GitHub Actions", and that a job running the tests in its own container has to pass the variable on. |
| 6 | Weakness. The declaration test fails on a build for one runtime (`-r`). | Real. | **Fixed.** It is skipped there with a reason, and fails on GitHub Actions. |
| 7 | Weakness. The declaration test accepted any package and any file whose name contains `zkryptium_ffi`. | Real: three altered `.deps.json` files passed. | **Fixed.** It requires the NetCrypto package and the exact asset paths. |
| 8 | False comment. "`Bbs_issuance_is_gated` needs no native code": it fails on musl, where BLS key generation cannot load `libblst`. | Real, and on `main` too. | Comment corrected; documented; the test is left as it is. |
| 9 | Observation. A stub library that exports the one probed symbol makes NetCrypto report "available". | True; it is NetCrypto's probe. The 14 tests then fail loudly. | No change. |
| 10 | Note. `main` has no branch protection, so a red leg does not block a merge. | True. | Outside this PR; reported. |
| 11 | Sloppy. Docs cited before they were written; the platform list repeated in the sample; a stale project comment; "on any host" and "green means ran" too strong as written. | True at the time. | Docs and CHANGELOG written; the sample no longer lists platforms; comments corrected. |

Held in round 1, each run: the library deleted, empty, or built for the wrong architecture; the whole
`runtimes` folder gone; a stub without the symbol; `Xunit.SkippableFact.dll` removed; a skip under a plain
`[Fact]` or `[Theory]` (reported Failed); a helper whose static initialiser throws (Failed); the test list
against `main` (nothing removed).

**Round 2** attacked the rework, which then detected musl from the process map.

| # | Finding | Checked | Disposition |
|---|---|---|---|
| 1 | **Hole**, off CI only. A glibc host looks like musl when any mapped file's path contains ` /lib/ld-musl-`: a test directory or an `LD_LIBRARY_PATH` entry with that text in its name. | Real: the check matched the whole line of the map. | **Fixed**, finally by removing the musl exemption (round 3). |
| 2 | Weakness. `--filter "Category=Bbs"` still selected 2 of the 18 tests that need the library. | Real. | **Fixed** (round 1, finding 4). |
| 3 | Weakness. No test pinned the helper's own wiring: a helper that skipped where the rule says fail, a misspelt variable name and an `IsShippedForHost` that is always false all passed. | Real. | **Fixed.** Tests for what an outcome does to a test and for where the inputs come from; see the mutation table. |
| 4 | Weakness. musl was recognised on Alpine and not on Void Linux, where the tests failed instead. | Real. | Moot: musl is no longer exempt. |
| 5 | Weakness. The GitHub Actions rule holds only if the variable reaches the test process. | True. | Documented. |
| 6 | Weakness. On GitHub Actions a build for one runtime failed the declaration test with a misleading message. | Real. | **Fixed**: the message says CI has to test the portable build. |
| 7 | Weakness. A future test that expects an exception from `bbs-2023` and forgets the helper call would pass without the library. | True; no such test exists. | Said in the helper's documentation at first. **Covered** after the external review by `BbsTestConventionTests`; see "External review, round 1". |
| 8 | Ten statements in the docs, CHANGELOG and comments that were false, too strong or unverifiable. | Each checked. | Corrected, except "exercised in CI: yes" for the two new legs, which the PR's CI run settles. |

Held in round 2, each run: the library deleted, empty, of the wrong architecture or operating system; the
`runtimes` folder gone; the library missing from one or two assemblies in every combination under the exact
CI command; `DOTNET_RUNTIME_ID` set to four values; a simulated `ubuntu-24.04-arm` leg (all eight assemblies
passed, 0 skipped); AlmaLinux 8; altered `.deps.json` files; misuse of the helper under plain attributes;
`tools/run-api-coverage.sh` with the library removed (exit 1); the sample as a process; the test list
against `main`; verification without the library (nothing Accepted).

**Round 3** attacked the next rework, which detected musl by asking the C library whether it is glibc, and
the helper's own tests.

| # | Finding | Checked | Disposition |
|---|---|---|---|
| 1 | **Hole**, off CI only. A file named `libc.so.6` in the test output directory (a link to the dynamic loader is enough) makes a glibc host report musl and skip. .NET looks next to the application before it asks the loader. | Real. | **Fixed by removing the musl exemption** (decision 2). Replayed above against the committed code: 15 Failed. |
| 2 | **Hole**, off CI only. `LD_LIBRARY_PATH` pointing at a patched copy of glibc. | Real. | The same. |
| 3 | Weakness. A preloaded library that interposes `dlsym`. | True; whoever can inject code can fake anything. | The same; nothing is detected any more. |
| 4 | Surviving mutants. A `RequireOrSkip()` that does nothing passed all 25 tests of the class, with the library deleted too. The reviewer judged that it could not be pinned inside the process. | Real. | **Fixed** inside the process after all: the load-context test. It kills that mutant and the three like it; see the mutation table. |
| 5 | Surviving mutants in the inputs: `IsShippedForHost` wrong off GitHub Actions; a host always named Linux. | Real. | **Fixed**: where the library loaded the platform must be on the list, and the host's name must match its operating system and architecture. |
| 6 | Statements in the two files that were false or too strong, among them the glibc note printed on macOS. | Each checked. | Corrected or removed with the code they described. |

Held in round 3, each run: environment variables alone (`DOTNET_RUNTIME_ID`, `GLIBC_TUNABLES`, `LD_PRELOAD`
of the loader and others); a musl host made to look like glibc (it then fails, the safe direction); crashes
and unexpected exception types from the C-library call (the tests fail, none skips); macOS never making that
call. No false alarm on the hosts standing in for the CI legs.

### Adversarial pass: the product on a host without the library

Run by a separate subagent: 47 test documents made with the library, then 194 verify calls with it and 194
without, in two processes.

- **No `bbs-2023` credential or presentation was Accepted without the library**, genuine, altered or forged,
  and no exception escaped the verifier.
- `IBbsDeriver.DeriveAsync` throws the documented `NotSupportedException`.
- `ISecuringCapabilities` still lists `bbs-2023` and reports it supported.
- The full table went to the epic orchestrator for #59. Nothing under `src/` changes in this PR.

### The source scan, review rounds 1 to 3: what was tried, and why it went

The external review asked for a check that a `bbs-2023` test cannot leave the helper call out. For three
rounds that check read the test sources. Each version, what the review found in it, and what changed:

| Round | The check | What the review found | What changed |
|---|---|---|---|
| 1 (ac942a4) | A scan of the sources as text: every test in a `Bbs` class contains the call. | Case 1: the call inside a block comment counts as a call. Case 2: `[Trait("Category", "Bbs"), SkippableFact]` with an early return is not seen as a test. | Rebuilt on a Roslyn syntax tree; scope became "a file that names the suite"; what the tree cannot resolve was reported. 45 fixtures. |
| 2 (28925f2) | The syntax-tree scan. | Case 3: a file wrapped whole in `#if NET10_0` is all disabled text to a parser without symbols, so it was out of scope before any rule ran. | Conditional compilation, bytes that are not UTF-8 and a wrong language version became findings in every test source file. |
| 3 (cf28395) | The same, after three adversarial passes of my own, with rules on skips before the call, trusted names, attributes, return types, sealed and partial classes. 78 fixtures, 102 mutants of the scanner. | The orchestrator's independent pass: a theory whose rows come up empty without the library reports nothing at all; and the scan now rejected `[Collection]`, any base class, `using static`, `partial`, `ValueTask` and more. | The re-plan above. |

What the adversarial passes of round 3 found, for the record, since each is now a matter for the gate and
not for a rule: a file that names nothing of the suite; a file name with an upper-case extension on Linux;
a parser a language version ahead of the compiler; a skip in a constructor, an initializer,
`InitializeAsync`, theory data or an attribute's argument; `BeforeAfterTestAttribute` on the class or the
assembly; a string, or an alias named `global`, in the place of the helper type; an `enum Task` with its
own method builder; a test attribute on a property accessor, and under `[@method: ...]`; `async ValueTask`,
which xUnit 2 does not await; the other part of a partial class and a derived class in another file; a
global static import of `Xunit.Skip`. Twenty-odd rules later, no pass had come back empty.

Why it went: every one of those is a way for a test to pass or skip without the library, and running the
tests without the library shows each of them without a rule that names it. The scan could only ever
enumerate the ways someone had already thought of.

What survives from those rounds: the syntax tree, the choice of files (every `.cs` file in any letter
case), UTF-8, the pinned language version, and one reading of each file. They protect the one decision the
scan still makes.

### External review, round 4: the gate, as built

**Reproduced first**, on cf28395: both forms of the empty theory compile into `Credentials.Rdfc.Tests`, the
scan of that commit lists both as guarded, their four rows pass with the library, and without it neither
appears in the results.

**Built:** the "Re-plan" at the head of this file. `Credentials.ArchitectureTests` lost the convention
scanner, its tests and 63 of its 78 fixtures; 15 fixtures of the scope scan stayed and 16 were written.

**Adversarial pass: two rounds on the new design, and neither was clean.** Each was a fresh sub-agent with
the code and a goal; every case was reproduced (the script exits 0; the test passes or is skipped on a
host without the library) before it was acted on.

| Round | Found | Disposition |
|---|---|---|
| 1 | A test that fails in the gate's copy only because a file reached by `../../../` is missing there, and passes on a real host | Closed: the copy is of everything under `tests/`, and a failure has to be the helper's |
| 1 | A namespace written `@base`; the suite named only as `"BBS"`; a display name that makes the result file give the namespace as the class | Closed, in the scope scan and in how a test is matched to a class |
| 1 | Tests inherited by a class in a file that names nothing; rows of a theory that trade places outside the scope | Closed: derived classes are in scope; other tests are compared row for row |
| 1 | The same test name in a second assembly; a new test under a `Class.*` entry of the list | Closed: a finding; one test a line |
| 1 | A results folder without one assembly's file passes; the self-test did not go through the verdict the CI step uses | Closed: every test project of the solution has to have results; the self-test requires exit code 1 from the same path |
| 2 | A derived class that names its base through a `using` alias | Closed: inheritance is read from the assemblies |
| 2 | A class without a namespace, or named as its namespace, under a display name | Closed: a test is matched by the class's own name |
| 2 | NetCrypto's own exception carries the words the gate took for the helper's failure | Closed: both phrases of the helper's message are required |
| 2 | Four faults put into the gate that no test noticed | Closed: a unit test or fixture for each; the solution is a required argument |
| 2 | False alarms: rows named by a value made at run time; a file in the next project folder | Closed |
| 2 | A test that skips on `IsShippedForHost` before the call: skipped on a platform outside the five, which no run of the gate is on | **Limit**, stated in the docs and in the fixture project |
| 2 | A test that depends on a file an earlier test wrote beside the assembly: the copy has it, a fresh host does not | **Limit**, the same |

No round has run since the second round's fixes. Both rounds found less natural cases than the scanner
rounds did, and both limits need a test written to that end; but the plain statement is that the last
round was not clean.

**Proof.** All run, on `osx-arm64` unless it says otherwise.

- The suite, by the CI command: 584 passed, 0 skipped. `Credentials.ArchitectureTests` has 116 tests, 123
  before: the scanner's 114 went, and 107 came for the scope scan and the gate's comparison.
- The gate on the real suite: 8 assemblies, 584 results in each run, 35 library files removed, 40
  `bbs-2023` classes, 31 tests on the list. It passes, in about 9 seconds. With one result file taken
  away, and with the candidates of the two adversarial rounds put back, it fails as the table says.
- The self-test: on the fixture project the gate exits with 1 and reports exactly the 13 findings listed.
- 28 mutants of the gate (the comparison, the scope scan, the reading of result files and of assemblies,
  the program): each fails a unit test, the self-test, or both.
- Not run locally: Windows. CI is the first run of the gate there, and the first run anywhere of these
  tests on Windows without the library.

### What changed during the work

Against the first version of this plan (c96fd95):

- **Every test that needs the library fails where it has to load.** The first plan had one test fail and the
  others skip. Round 1 showed that one failing test in one assembly does not protect the others.
- **The rule also applies on GitHub Actions whatever the platform**: the orchestrator's ruling.
- **musl fails, as in the first plan, after two revisions that skipped it.** The orchestrator's ruling was
  to skip musl if it could be detected reliably. Three detectors were built and each was fooled (round 1
  finding 2, round 2 finding 1, round 3 findings 1 and 2), so the exemption went (decision 2).
- **The failing path of the helper is run inside the suite**, by the load-context test (round 3 finding 4).
  The first plan had only the one-off runs.
- **The sample throws its own `NotSupportedException`.** The first plan deleted the branch; the upstream
  exception that then surfaced carries about forty lines of loader output.
- **The declaration test is stricter** and is skipped on a build for one runtime (round 1 findings 6 and 7).
- **Every `bbs-2023` test carries the `Bbs` category** (round 1 finding 4).
- **CI has a `linux-arm64` leg**: the owner's decision.
- `Credentials.TestSupport` references `Xunit.SkippableFact` as well as `NetCrypto`, because the helper now
  performs the skip.
- `tasks/lessons.md` has an entry for what this taught.
- **A convention check exists at all**: asked for by the external review. It read the sources for three
  rounds and runs the tests without the library since the re-plan of 2026-11-24.
- **The smoke test of the `Bbs2023` sample is a class of its own**, `Bbs2023SampleSmokeTests`, so that the
  other thirteen samples are not `bbs-2023` tests.

### Follow-ups, none in this PR

- The API-coverage gate does not measure `Credentials.Rdfc` (the orchestrator is filing a sub-issue).
- The product's behaviour without the library, for #59.
- `Bbs_issuance_is_gated` on a host without NetCrypto's BLS library, for #43 or crypto-dotnet#34.
- When crypto-dotnet#34 ships, the declaration test fails until `BbsNativeLibrary.ShippedRuntimeIdentifiers`,
  the test's list and `docs/conformance.md` are updated.

### CI on the PR

PR #72, run 45334260764 on 386da36, the implementation commit. All eight checks passed, read from the logs:

| Check | Runner image | Platform | Tests |
|---|---|---|---|
| `build + test (ubuntu-latest)` | `ubuntu-26.04` | `linux-x64` | 477 passed, 0 skipped (48 s) |
| `build + test (windows-latest)` | `windows-2025-vs2026` | `win-x64` | 477 passed, 0 skipped (83 s) |
| `build + test (macos-latest)` | `macos-26-arm64` | `osx-arm64` | 477 passed, 0 skipped (42 s) |
| `build + test (ubuntu-24.04-arm)` | `ubuntu-24.04-arm` | `linux-arm64` | 477 passed, 0 skipped (41 s) |
| `no-Newtonsoft consumer closure` | | | passed |
| `API compatibility (semver)` | | | passed |
| `API coverage (samples exercise the surface)` | | | passed |
| `W3C VCDM 2.0 suite` (Conformance) | | | passed |

- On every leg `Credentials.Rdfc.Tests` has 51 passed, `Credentials.InteropTests` 5 and
  `Credentials.SampleSmokeTests` 14, each with 0 skipped: the `bbs-2023` tests ran on all four platforms.
  The two new legs are the first CI runs of this library on macOS and on arm64 Linux.
- Two of the 51 say more than "the library loaded". The inputs test requires a GitHub Actions leg to be on
  one of the five platforms, so each runner was identified as the table says. The load-context test ran the
  helper's failing path on each leg, Windows included, which is the Windows proof the one-off runs lack.
- The platform column is not printed by the logs; it follows from the runner image and from the inputs
  test passing.
- This section was added in a later commit, which runs CI again; the PR shows that run.
