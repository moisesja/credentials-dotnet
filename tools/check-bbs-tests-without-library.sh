#!/usr/bin/env bash
# The no-library gate for bbs-2023 tests (issue #57).
#
# bbs-2023 needs NetCrypto's native BBS library (zkryptium_ffi). A test that needs it must never pass, be
# skipped or quietly not run on a host where the library does not load. This gate proves that by running:
# it takes the result files of a normal test run, runs the same test assemblies again from copies of
# their output folders with the library removed, and compares the two runs test by test.
#
#   - A test of a bbs-2023 class has to FAIL without the library, and by the failure of the helper,
#     BbsNativeLibrary.RequireOrSkip(). Passed, skipped, "no result" and failed for another reason are each
#     reported by name. A bbs-2023 class is a type declared in a test source file whose code names anything
#     of bbs-2023, or one that derives from such a type (tests/Credentials.BbsGate/BbsScope.cs).
#   - A test on the list tests/Credentials.BbsGate/need-no-native-library.txt has to PASS without it.
#   - A test of any other class has to do the same in both runs, row for row.
#   - The run has to be a no-library run: the availability check passes with the library and fails
#     without it. If hiding the library did not work, the gate fails.
#   - Every test project of the solution has to be in the results.
#
# The build output is not touched: the second run works on copies of the test project folders under
# artifacts/bbs-gate. Both runs have GITHUB_ACTIONS=true, as on CI, so that a missing library fails a
# guarded test on any host and nothing differs between the runs but the library.
#
# Usage, after `dotnet build Credentials.sln -c Release`:
#
#   tools/check-bbs-tests-without-library.sh                     run the tests, then the gate
#   tools/check-bbs-tests-without-library.sh --results <dir>     the gate alone, on the result files (TRX)
#                                                                of a run that used the filter below
#   tools/check-bbs-tests-without-library.sh --self-test         prove that the gate reports what it has to:
#                                                                build tests/Credentials.GateFixtures,
#                                                                a project of deliberately wrong tests, and
#                                                                require exactly its expected findings
#
# Exit code: 0 when the gate passes, 1 when it has findings, 2 when it could not run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIGURATION="${CONFIGURATION:-Release}"
# The filter of the CI test step (.github/workflows/ci.yml). Both runs have to use the same one.
FILTER='Category!=Conformance'
GATE=(dotnet run --no-build -c "$CONFIGURATION" --project "$ROOT/tests/Credentials.BbsGate" --)
export GITHUB_ACTIONS=true
TEMPORARY="$(mktemp -d)"
trap 'rm -rf "$TEMPORARY"' EXIT

case "${1:-}" in
  --self-test)
    FIXTURES="$ROOT/tests/Credentials.GateFixtures"
    dotnet build "$FIXTURES/Credentials.GateFixtures.csproj" -c "$CONFIGURATION" --nologo -v q
    # The fixture tests pass with the library: what is wrong with them shows only without it.
    dotnet test "$FIXTURES/bin/$CONFIGURATION/net10.0/Credentials.GateFixtures.dll" \
      --logger "trx;LogFileName=fixtures.trx" --results-directory "$TEMPORARY/with" > "$TEMPORARY/with.log" \
      || { cat "$TEMPORARY/with.log"; echo "the fixture tests have to pass with the library" >&2; exit 2; }
    FIXTURE_GATE=("${GATE[@]}" --repo "$ROOT" --solution "$FIXTURES/GateFixtures.sln" --with-library-results "$TEMPORARY/with"
      --list "$FIXTURES/need-no-native-library.txt"
      --availability-check "Credentials.GateFixtures.GuardedTests.The_native_library_loads")
    # Twice: as CI runs the gate, where these tests have to make it fail, and against the exact list of
    # what it has to report for them.
    CODE=0; "${FIXTURE_GATE[@]}" > "$TEMPORARY/gate.log" 2>&1 || CODE=$?
    if [ "$CODE" -ne 1 ]; then
      cat "$TEMPORARY/gate.log"; echo "on a project of deliberately wrong tests the gate has to exit with 1; it exited with $CODE" >&2; exit 1
    fi
    "${FIXTURE_GATE[@]}" --expect "$FIXTURES/expected-findings.txt"
    ;;
  --results)
    "${GATE[@]}" --repo "$ROOT" --solution "$ROOT/Credentials.sln" --with-library-results "${2:?--results needs a folder}" --filter "$FILTER"
    ;;
  "")
    dotnet test "$ROOT/Credentials.sln" -c "$CONFIGURATION" --no-build --filter "$FILTER" \
      --logger trx --results-directory "$TEMPORARY/with"
    "${GATE[@]}" --repo "$ROOT" --solution "$ROOT/Credentials.sln" --with-library-results "$TEMPORARY/with" --filter "$FILTER"
    ;;
  *)
    sed -n '2,30p' "$0" >&2
    exit 2
    ;;
esac
