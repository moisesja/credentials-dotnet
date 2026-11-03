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
- **bbs-2023 (vc-di-bbs)** — `IsAvailable`-gated. A derived proof pins the wire-format drift sentinels
  (the `bbs-2023` cryptosuite name and a multibase-base64url `proofValue`), verifies, and a tampered
  revealed-mandatory value is rejected (the cryptographically-enforced mandatory group). DataProofs ≥ 2.0.0
  follows the reference `bbs-2023` algorithms (its own conformance tests verify the W3C
  `derivedRevealDocument.json` vector and cross-verify with the reference verifier).

The no-Newtonsoft consumer-closure guarantee (NFR-002) is asserted separately by
`Credentials.ConsumerProbe` (`tools/check-no-newtonsoft-closure.sh`).
