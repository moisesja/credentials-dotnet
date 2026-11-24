# Conformance & interoperability status

This documents how `credentials-dotnet` is measured against external test suites and vectors, and —
honestly — what passes and what does not yet.

## W3C VCDM 2.0 test suite

The [`w3c/vc-data-model-2.0-test-suite`](https://github.com/w3c/vc-data-model-2.0-test-suite) (the Node
interoperability suite) is run against a thin ASP.NET shim (`tests/Credentials.Conformance.VcApi`) that
exposes `POST /credentials/issue`, `/credentials/verify`, and `/presentations/verify` over the engine's
`IIssuer`/`IVerifier`. The shim issues with `eddsa-rdfc-2022`; the suite injects the shim's own `did:key`
as the credential issuer, so issuance satisfies the engine's issuer-binding. The full run is
`conformance.yml` (PR + nightly).

### The gate

`Credentials.Conformance.Tests` boots the shim on loopback, runs the suite, and passes only if **both**
hold:

1. **Every failing suite test is a named known failure.** The harness parses each mocha failure and matches
   it against `KnownFailures` in `W3cVcdm2SuiteTests`, keyed on the suite's own assertion message. A failure
   outside that list fails the gate however many tests pass, so a regression cannot hide behind the count.
2. **The passing count is at least the floor** (59 suite tests minus the known failures). This is a sanity
   check beside the list, so a run that executes nothing cannot pass with zero failures.

When a known failure starts passing, the run prints a notice: remove the entry, raise the floor, and update
this page. Lowering the floor without naming the failure is not how a regression is accepted.

### Current result: 58 / 59 passing

The structural / issue / verify core passes, including the v1.0 compliance hardening — identifier-URL
validation (`id`, `issuer`, `credentialStatus.id`, `credentialSchema.id`, `credentialSubject.id`,
`refreshService.id`, `relatedResource.id`), `refreshService.type`, `relatedResource` structure, and
`name`/`description` §11.1 language value objects, with and without a base direction. The 1 known failure:

| Test | Why it does not pass | Status |
|---|---|---|
| `relatedResource` digest MUST match the retrieved resource | The engine validates `relatedResource` **structure** (objects; a unique URL `id`; at least one of `digestSRI`/`digestMultibase`) but does not yet **fetch the resource and verify the digest hash**. | Deferred to a focused follow-up (a verifier-side fetch+hash on an optional resolver hook), then this gap closes. |

Two notes on what the count does and does not say:

- **Language value objects with `@direction`** (`name`, `description`, `issuer.name`, `issuer.description`)
  pass because DataProofs ≥ 2.0.0 canonicalizes RDFC with JSON-LD 1.1 `rdfDirection: i18n-datatype`, the
  representation the reference Data Integrity implementations sign with
  ([dataproofs-dotnet#40](https://github.com/moisesja/dataproofs-dotnet/issues/40)). The direction is
  inside the signature: flipping or dropping it after signing fails the proof. That is a stronger result
  than before DataProofs 1.5.0, when these cases "passed" by silently signing bytes that did not carry the
  direction, and than 1.5.0, when the RDFC suites refused `@direction` and the cases were listed here as
  known failures. A number or boolean with `@direction` is still refused as data loss. Regression coverage:
  `RdfcIssueVerifyTests` (the four positions, both RDFC and JCS, and the post-signing flip/removal).
- The `type` term-resolution test ("`type` MUST be one or more terms and/or absolute URL strings"), a
  documented gap up to v1.1.1, now **passes**: RDFC data-loss detection rejects a `type` that no
  `@context` maps. That holds for RDFC-secured input only; the JCS and enveloping forms still accept a
  well-formed-but-unmapped `type`, because an STJ-only engine does not perform JSON-LD term resolution
  (NFR-002).

This is reported as a tracked baseline rather than a "fully conformant" claim: the engine passes the
structural / issue / verify core of the suite, and the gap above is explicit, named, and individually
addressable.

## Interoperability vectors (`tests/Credentials.InteropTests`)

- **SD-JWT VC** — the disclosures the engine emits are cross-checked against the SD-JWT spec's digest
  algorithm: each disclosure's `base64url(SHA-256(ascii(disclosure)))` is recomputed independently and
  matched against the issued `_sd` array, proving cross-implementation agreement on the disclosure-digest
  algorithm. The negative cases (a tampered disclosure value; an unmatched disclosure) reject, and the
  `dc+sd-jwt` media type / `typ` are drift sentinels.
- **bbs-2023 (vc-di-bbs)** — A derived proof pins the wire-format drift sentinels
  (the `bbs-2023` cryptosuite name and a multibase-base64url `proofValue`), verifies, and a tampered
  revealed-mandatory value is rejected (the cryptographically-enforced mandatory group). DataProofs ≥ 2.0.0
  follows the reference `bbs-2023` algorithms (its own conformance tests verify the W3C
  `derivedRevealDocument.json` vector and cross-verify with the reference verifier). These tests need a
  native library; see [bbs-2023: platforms](#bbs-2023-platforms).

The no-Newtonsoft consumer-closure guarantee (NFR-002) is asserted separately by
`Credentials.ConsumerProbe` (`tools/check-no-newtonsoft-closure.sh`).

## bbs-2023: platforms

`bbs-2023` runs on native code. NetCrypto, the cryptographic foundation, carries a native BBS library
(`zkryptium_ffi`) inside its NuGet package, and every `bbs-2023` operation needs it: deriving and verifying
here, and issuing once [#43](https://github.com/moisesja/credentials-dotnet/issues/43) lands. Where the
library does not load, `IBbsDeriver.DeriveAsync` throws `NotSupportedException`.

NetCrypto 1.7.1 ships the library for five runtime identifiers. CI exercises four of them:

| Runtime identifier | Library shipped | `bbs-2023` exercised in CI |
|---|---|---|
| `linux-x64` | yes; needs glibc 2.34 or later | yes (`ubuntu-latest`) |
| `linux-arm64` | yes; needs glibc 2.34 or later | yes (`ubuntu-24.04-arm`) |
| `osx-arm64` | yes | yes (`macos-latest`) |
| `win-x64` | yes | yes (`windows-latest`) |
| `osx-x64` | yes | no |
| any other (musl Linux, `win-arm64`, mobile) | no | no |

More platforms are requested upstream in
[crypto-dotnet#34](https://github.com/moisesja/crypto-dotnet/issues/34).

### What the tests do without the library

Every test that needs the library calls `BbsNativeLibrary.RequireOrSkip()` (in
`tests/Credentials.TestSupport`) before it touches `bbs-2023`. That covers the derive and verify tests in
`Credentials.Rdfc.Tests`, the interop tests above, and the smoke test of the `Bbs2023` sample;
`dotnet test --filter "Category=Bbs"` runs them all. When the library did not load, such a test is never
reported as passed:

- It **fails** where the library has to be there: on one of the five platforms, and on GitHub Actions
  whatever the platform. GitHub sets `GITHUB_ACTIONS=true` on every runner, and the tests read it. A green CI
  leg therefore means the `bbs-2023` tests ran on it, and a leg on a platform outside the five cannot go
  green without the library. (A job that runs the tests inside a container of its own has to pass the
  variable on.)
- It is **skipped**, with a reason that names the platform, on any other host: `win-arm64`, for example.

The decision is taken in each test process, so it holds for a single test project and for a filtered run as
much as for the whole solution. On CI the library is always there, so the failing branch would never run;
`BbsNativeLibraryTests` therefore runs the call against a second copy of NetCrypto that is refused the
library, on every host and every leg, and pins the rule and where its inputs come from.

The same class pins the first column of the table against the NetCrypto package the build resolved. That
test fails when NetCrypto drops, adds or renames a platform's library, until the list in `BbsNativeLibrary`
and this page are updated. It reads what the package declares, in the portable build that CI tests. Only a
run on the platform itself shows that the binary loads, which is what the CI column records; `osx-x64` has
the declaration check alone.

The tests name a platform by its operating system and architecture. NetCrypto's Linux builds are glibc
builds, and two kinds of Linux host are on the list by that name although the library cannot load there:

- **glibc older than 2.34** (RHEL 8 and its rebuilds, for example);
- **musl** (Alpine, for example), for which NetCrypto has no build.

On both the tests fail, and the message says that the Linux builds need glibc 2.34 or later and do not load
on musl. On a stock Alpine image `Bbs_issuance_is_gated` fails as well, for a related reason: it generates a
BLS key, and BLS key generation needs NetCrypto's second native library (`blst`, through
`Nethermind.Crypto.Bls`), which ships for the same five platforms and has no availability check of its own.
Both are part of crypto-dotnet#34.

The `Credentials.Sample.Bbs2023` sample follows the same line. Run on a host where the library does not
load, it throws `NotSupportedException` and exits non-zero. It does not print a result for a path it did not
run.
