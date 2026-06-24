#!/usr/bin/env bash
#
# NFR-005 semver gate (package-compat half): pack each shippable library and compare it against the
# last version published to nuget.org with Microsoft.DotNet.ApiCompat.Tool. A breaking change fails
# the gate. The source-level surface is independently guarded at build time by the RS0016/RS0017
# PublicAPI analyzers; this catches binary/package-level breaks against an actually-released baseline.
#
# Pre-release honesty: when a package has no published version yet, there is nothing to compare
# against, so that package is SKIP-marked + logged (never reported as passing). Intended for
# release.yml; runnable locally.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NEW="$ROOT/artifacts/apicompat/new"
BASE="$ROOT/artifacts/apicompat/baseline"
rm -rf "$NEW" "$BASE"; mkdir -p "$NEW" "$BASE"

dotnet tool restore >/dev/null

PACKAGES=(Credentials.Core Credentials.Extensions.DependencyInjection Credentials.Rdfc)
PROJECTS=(
  "src/Credentials.Core/Credentials.Core.csproj"
  "src/Credentials.Extensions.DependencyInjection/Credentials.Extensions.DependencyInjection.csproj"
  "src/Credentials.Rdfc/Credentials.Rdfc.csproj"
)

skipped=()
checked=()
for i in "${!PACKAGES[@]}"; do
  id="${PACKAGES[$i]}"
  idl="$(echo "$id" | tr '[:upper:]' '[:lower:]')"
  dotnet pack "$ROOT/${PROJECTS[$i]}" -c Release -o "$NEW" --nologo >/dev/null

  # Newest published version, if any.
  versions="$(curl -s --max-time 20 "https://api.nuget.org/v3-flatcontainer/$idl/index.json" || true)"
  latest="$(echo "$versions" | python3 -c "import sys,json
try:
    v=[x for x in json.load(sys.stdin).get('versions',[]) if '-' not in x]
    print(v[-1] if v else '')
except Exception:
    print('')" 2>/dev/null || true)"

  if [[ -z "$latest" ]]; then
    echo "SKIP  $id — no published baseline on nuget.org (pre-release); package-compat not checked."
    skipped+=("$id")
    continue
  fi

  curl -s --max-time 60 -o "$BASE/$id.$latest.nupkg" \
    "https://api.nuget.org/v3-flatcontainer/$idl/$latest/$idl.$latest.nupkg"
  newpkg="$(ls "$NEW/$id."*.nupkg | head -1)"
  echo ">> ApiCompat $id: $latest (baseline) vs freshly packed"
  dotnet apicompat package --package "$newpkg" --baseline-package "$BASE/$id.$latest.nupkg" --run-api-compat
  checked+=("$id")
done

echo ""
echo "ApiCompat summary: checked=[${checked[*]:-}] skipped(pre-release)=[${skipped[*]:-}]"
