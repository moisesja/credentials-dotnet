#!/usr/bin/env bash
#
# The api-coverage gate: runs every sample (via Credentials.SampleSmokeTests) under coverlet scoped to
# Credentials.Core + Credentials.Extensions.DependencyInjection, then asserts every gateable public type
# is exercised by at least one sample (type-level), with documented exemptions in
# tools/api-coverage/api-coverage-exclusions.txt. Exit 0 = covered; non-zero = an uncovered public type.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS="$ROOT/artifacts/api-coverage"
rm -rf "$RESULTS"

echo ">> Building solution"
dotnet build "$ROOT/Credentials.sln" -c Debug --nologo

echo ">> Running samples under coverlet (scoped to Core + DI)"
dotnet test "$ROOT/tests/Credentials.SampleSmokeTests/Credentials.SampleSmokeTests.csproj" -c Debug --no-build \
  --collect:"XPlat Code Coverage" --settings "$ROOT/tools/coverage.runsettings" --results-directory "$RESULTS"

COB="$(find "$RESULTS" -name '*.cobertura.xml' | head -1)"
if [[ -z "$COB" ]]; then echo "no cobertura report produced" >&2; exit 2; fi
# Derive the output dir from the built assembly rather than hardcoding the TFM, so a framework bump
# can't silently break the gate (it would report a coverage gap, not crash on a missing path).
BIN="$(dirname "$(find "$ROOT/tests/Credentials.SampleSmokeTests/bin/Debug" -name 'Credentials.Core.dll' | head -1)")"
if [[ -z "$BIN" ]]; then echo "could not locate the built Credentials.Core.dll" >&2; exit 2; fi

echo ">> Diffing the public surface against sample coverage"
dotnet run --project "$ROOT/tools/api-coverage/Credentials.Tools.ApiCoverage.csproj" -c Debug --no-build -- \
  "$COB" \
  "$ROOT/tools/api-coverage/api-coverage-exclusions.txt" \
  "$BIN/Credentials.Core.dll" \
  "$BIN/Credentials.Extensions.DependencyInjection.dll"
