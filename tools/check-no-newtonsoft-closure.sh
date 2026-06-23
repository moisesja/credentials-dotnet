#!/usr/bin/env bash
#
# NFR-002 package-closure gate: pack Credentials.Core + Credentials.Extensions.DependencyInjection,
# restore the ConsumerProbe against them in an isolated package folder, and assert that no
# Newtonsoft.Json (nor dotNetRDF / AngleSharp / HtmlAgilityPack, which drag it in) appears anywhere in
# the consumer's transitive closure. The opt-in Credentials.Rdfc is the sanctioned Newtonsoft carrier
# and is deliberately NOT consumed here.
#
# Runnable locally and in CI. Exit 0 = clean closure; non-zero = a forbidden package leaked in.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FEED="$ROOT/artifacts/local-feed"
PKGS="$ROOT/artifacts/probe-packages"
PROBE="$ROOT/tests/Credentials.ConsumerProbe/Credentials.ConsumerProbe.csproj"

# CRITICAL: pack under a UNIQUE version each run. NuGet caches package *metadata* by id+version, so
# re-packing the same fixed version (0.1.0) with different dependencies serves STALE deps from a prior
# run — which would silently make this gate report the first run's closure forever (verified: a
# Newtonsoft dependency added to a re-packed 0.1.0 was invisible). A unique version guarantees a fresh
# dependency-graph resolution. It is exported as an environment variable so MSBuild reads it as the
# $(ProbePackageVersion) property consistently across restore, build, AND `dotnet list` (which does not
# accept -p:).
VER="0.0.0-probe$(date +%s)"
export ProbePackageVersion="$VER"

echo ">> Packing libraries to the local feed at version $VER: $FEED"
rm -rf "$FEED" "$PKGS"
mkdir -p "$FEED"
dotnet pack "$ROOT/src/Credentials.Core/Credentials.Core.csproj" -c Release -o "$FEED" --nologo -p:CredentialsVersion="$VER"
dotnet pack "$ROOT/src/Credentials.Extensions.DependencyInjection/Credentials.Extensions.DependencyInjection.csproj" -c Release -o "$FEED" --nologo -p:CredentialsVersion="$VER"

echo ">> Restoring the ConsumerProbe from the local feed (isolated package folder)"
rm -rf "$(dirname "$PROBE")/obj" "$(dirname "$PROBE")/bin"
# --packages isolates extraction; --no-cache skips the HTTP cache; $(ProbePackageVersion) (from the
# exported env var) forces a fresh resolve of the unique version.
dotnet restore "$PROBE" --packages "$PKGS" --no-cache

echo ">> Building the ConsumerProbe (confirms the packed public API is genuinely consumable)"
dotnet build "$PROBE" -c Release --no-restore --nologo

echo ">> Inspecting the transitive package closure"
OUT="$(dotnet list "$PROBE" package --include-transitive)"
echo "$OUT"

if echo "$OUT" | grep -iqE "newtonsoft|dotnetrdf|anglesharp|htmlagility"; then
  echo ""
  echo "NFR-002 VIOLATION: a forbidden package appears in the ConsumerProbe transitive closure." >&2
  exit 1
fi

echo ""
echo "NFR-002 OK: the default consumer closure (Credentials.Core + DI) is Newtonsoft-free."
