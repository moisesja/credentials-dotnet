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
#     of bbs-2023 (tests/Credentials.BbsGate/BbsScope.cs), or one that derives from such a type or is
#     nested in one (read from the test assemblies, tests/Credentials.BbsGate/TestClasses.cs).
#   - A test on the list tests/Credentials.BbsGate/need-no-native-library.txt has to PASS without it.
#   - A test of any other class has to do the same in both runs, row for row.
#   - The run has to be a no-library run: the availability check passes with the library and fails
#     without it. If hiding the library did not work, the gate fails.
#   - Every test project of the solution has to be in the results.
#
# The build output is not touched: the second run works on copies of the test project folders. The gate
# makes one new folder for them in artifacts/bbs-gate, writes only inside it, and deletes that folder and
# nothing else at the end. It never deletes, overwrites or truncates anything it did not create in the same
# run. A run that is killed leaves its folder behind and no later run removes it: delete artifacts/bbs-gate
# by hand when it has grown. Both runs have GITHUB_ACTIONS=true, as on CI, so that a missing library fails
# a guarded test on any host and nothing differs between the runs but the library.
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
# Exit code: 0 when the gate passes, 1 when it has findings, 2 when it could not run: a wrong call, a build
# that is not there, a temporary folder that cannot be made. In the mode without arguments, a test run
# that fails ends the script with the code of `dotnet test`, before the gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIGURATION="${CONFIGURATION:-Release}"
# The filter of the CI test step (.github/workflows/ci.yml). Both runs have to use the same one.
FILTER='Category!=Conformance'
GATE=(dotnet run --no-build -c "$CONFIGURATION" --project "$ROOT/tests/Credentials.BbsGate" --)
export GITHUB_ACTIONS=true
stop() { echo "$*" >&2; exit 2; }

# The call, before anything is made: one of three forms, and a build of the gate to run.
case "${1:-}:$#" in
  :0 | --self-test:1 | --results:2) ;;
  *) sed -n '2,36p' "$0" >&2; exit 2 ;;
esac
[ -f "$ROOT/tests/Credentials.BbsGate/bin/$CONFIGURATION/net10.0/Credentials.BbsGate.dll" ] \
  || stop "the gate is not built in $CONFIGURATION: run 'dotnet build Credentials.sln -c $CONFIGURATION' first"

# What the script makes, it makes with mktemp, and removes when it ends, however it ends. Nothing else.
TEMPORARY=""; MARKER=""; GIVEN=""
trap 'rm -rf ${TEMPORARY:+"$TEMPORARY"} ${GIVEN:+"$GIVEN"}; rm -f ${MARKER:+"$MARKER"}' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
TEMPORARY="$(mktemp -d)" || stop "a temporary folder could not be made"

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
    # What is not the gate's has to be there afterwards: a file in the folder it works in by default, and
    # a file in a folder it is given with --work. Both are made here, by mktemp, and removed here.
    mkdir -p "$ROOT/artifacts/bbs-gate" || stop "artifacts/bbs-gate could not be made"
    MARKER="$(mktemp "$ROOT/artifacts/bbs-gate/keep-me.XXXXXX")" || stop "a file could not be made in artifacts/bbs-gate"
    GIVEN="$(mktemp -d "$ROOT/artifacts/bbs-gate-self-test.XXXXXX")" || stop "a folder could not be made in artifacts"
    echo "not the gate's" > "$MARKER"; echo "not the gate's" > "$GIVEN/keep-me.txt"
    ls -A "$ROOT/artifacts/bbs-gate" | sort > "$TEMPORARY/before"

    # Twice: as CI runs the gate, where these tests have to make it fail, and against the exact list of
    # what it has to report for them. The first run works in the default folder, the second in a given one.
    CODE=0; "${FIXTURE_GATE[@]}" > "$TEMPORARY/gate.log" 2>&1 || CODE=$?
    if [ "$CODE" -ne 1 ]; then
      cat "$TEMPORARY/gate.log"; echo "on a project of deliberately wrong tests the gate has to exit with 1; it exited with $CODE" >&2; exit 1
    fi
    "${FIXTURE_GATE[@]}" --expect "$FIXTURES/expected-findings.txt" --work "$GIVEN"

    ls -A "$ROOT/artifacts/bbs-gate" | sort > "$TEMPORARY/after"
    if [ "$(cat "$MARKER")" != "not the gate's" ] || ! cmp -s "$TEMPORARY/before" "$TEMPORARY/after"; then
      echo "a run without --work has to leave artifacts/bbs-gate as it found it" >&2; exit 1
    fi
    if [ "$(cat "$GIVEN/keep-me.txt")" != "not the gate's" ] || [ "$(ls -A "$GIVEN" | wc -l | tr -d ' ')" -ne 2 ]; then
      echo "a run with --work has to leave what was in the folder, and add one folder of its own" >&2; exit 1
    fi
    echo "bbs-2023 gate self-test OK: the gate left what was not its own, in artifacts/bbs-gate and in a given folder."
    # A filter that cannot be read leaves the second run without a result. That is "could not run", not
    # a verdict about four hundred tests.
    CODE=0; "${FIXTURE_GATE[@]}" --filter '(((' > "$TEMPORARY/filter.log" 2>&1 || CODE=$?
    if [ "$CODE" -ne 2 ]; then
      cat "$TEMPORARY/filter.log"; echo "with a filter that cannot be read the gate has to exit with 2; it exited with $CODE" >&2; exit 1
    fi

    # The script's own exits: called wrongly it has to end with 2, under every bash it runs on.
    for ARGUMENTS in "--results" "--results $TEMPORARY/no-such-folder" "--no-such-mode" "--self-test one-too-many" \
                     "--results $TEMPORARY/with one-too-many" "one-too-many"; do
      CODE=0; "$0" $ARGUMENTS > /dev/null 2>&1 || CODE=$?
      if [ "$CODE" -ne 2 ]; then echo "'$0 $ARGUMENTS' has to exit with 2; it exited with $CODE" >&2; exit 1; fi
    done
    CODE=0; "$0" --results "" > /dev/null 2>&1 || CODE=$?
    if [ "$CODE" -ne 2 ]; then echo "'$0 --results \"\"' has to exit with 2; it exited with $CODE" >&2; exit 1; fi
    echo "bbs-2023 gate self-test OK: called wrongly, the script exits with 2."
    ;;
  --results)
    # Checked by hand, not by ${2:?...}: under bash 3.2 that ends the script with the status of the
    # EXIT trap, which is 0.
    if [ -z "${2:-}" ] || [ ! -d "$2" ]; then
      echo "--results needs the folder with the result files of the normal run" >&2
      exit 2
    fi
    "${GATE[@]}" --repo "$ROOT" --solution "$ROOT/Credentials.sln" --with-library-results "$2" --filter "$FILTER"
    ;;
  "")
    dotnet test "$ROOT/Credentials.sln" -c "$CONFIGURATION" --no-build --filter "$FILTER" \
      --logger trx --results-directory "$TEMPORARY/with"
    "${GATE[@]}" --repo "$ROOT" --solution "$ROOT/Credentials.sln" --with-library-results "$TEMPORARY/with" --filter "$FILTER"
    ;;
  *)
    sed -n '2,36p' "$0" >&2
    exit 2
    ;;
esac
