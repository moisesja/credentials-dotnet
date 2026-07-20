# Task — Issue #18: Upgrade AngleSharp to fix GHSA-pgww-w46g-26qg + prep 1.1.1 release

Full plan: `/Users/moises/.claude/plans/floofy-knitting-wall.md`

## Problem

Build failed under `TreatWarningsAsErrors=true` with `NU1902`: **AngleSharp 1.4.0** carries
moderate-severity advisory GHSA-pgww-w46g-26qg. AngleSharp is a transitive-only dependency arriving
via `Credentials.Rdfc → DataProofsDotnet.Rdfc → dotNetRdf.Core 3.5.1 → AngleSharp`, so the advisory
surfaced in every project downstream of `Credentials.Rdfc` (not just the 2 the issue named).

## Changes (branch `fix/anglesharp-1.5.2-issue-18`)

- [x] `Directory.Packages.props` — added `<PackageVersion Include="AngleSharp" Version="1.5.2" />`
      (central, CPM) with a security-pin comment.
- [x] `src/Credentials.Rdfc/Credentials.Rdfc.csproj` — added versionless
      `<PackageReference Include="AngleSharp" />` at the single source project; the promotion flows to
      all downstream projects.
- [x] `Directory.Build.props` — `CredentialsVersion` 1.1.0 → 1.1.1.
- [x] `CHANGELOG.md` — added `## v1.1.1 - 7/20/2026` (Security) entry.

## Pipelines

No workflow edit needed: `.github/workflows/release.yml` is tag-driven and derives the version from
the pushed tag (`version=${GITHUB_REF_NAME#v}`), overriding `CredentialsVersion`. Deploy = push tag
`v1.1.1` after merge to `main`. Tag push is an irreversible nuget.org publish — left to the user.

## Review — verification results (all green)

- `dotnet list … --vulnerable --include-transitive`: **0 vulnerable packages** across all 29 projects
  (was AngleSharp 1.4.0 in the Rdfc subtree). `Credentials.Rdfc` and `Credentials.Conformance.VcApi`
  (both named in the issue) confirmed clean.
- AngleSharp resolves to **1.5.2** in Rdfc (direct) and Conformance.VcApi (inherited).
- `dotnet build Credentials.sln -c Release`: **0 warnings, 0 errors** (NU1902 gone).
- `dotnet test … --filter "Category!=Conformance"`: all pass — Core 172, DI 161, Rdfc 21,
  RoundTrip 9, SampleSmoke 14, Interop 5, Architecture 9. The Rdfc/RoundTrip suites exercise the
  dotNetRDF canonicalization path against AngleSharp 1.5.2 → runtime-compatible.
- `tools/check-no-newtonsoft-closure.sh`: **NFR-002 OK** (default closure Newtonsoft-free; unaffected).
- `tools/check-api-compat.sh`: **no breaking changes** for Core / DI / Rdfc vs published 1.1.0
  baseline → confirms dependency-only, no public API delta.
- `dotnet pack -p:CredentialsVersion=1.1.1`: all 3 packages + snupkg pack; Rdfc nuspec declares
  `<dependency id="AngleSharp" version="1.5.2" />`. Assemblies stamped `1.1.1+<sha>`.

## Notes / lessons

- No user correction this session → no new `tasks/lessons.md` entry.
- The issue listed only 2 affected projects; the real blast radius was every downstream-of-Rdfc
  project, which is why a single pin at the source (not two per-project edits) is the correct fix.
