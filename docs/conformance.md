# Conformance & interoperability status

This documents how `credentials-dotnet` is measured against external test suites and vectors, and —
honestly — what passes and what does not yet.

## W3C VCDM 2.0 test suite

The [`w3c/vc-data-model-2.0-test-suite`](https://github.com/w3c/vc-data-model-2.0-test-suite) (the Node
interoperability suite) is run against a thin ASP.NET shim (`tests/Credentials.Conformance.VcApi`) that
exposes `POST /credentials/issue`, `/credentials/verify`, and `/presentations/verify` over the engine's
`IIssuer`/`IVerifier`. The shim issues with `eddsa-rdfc-2022`; the suite injects the shim's own `did:key`
as the credential issuer, so issuance satisfies the engine's issuer-binding. `Credentials.Conformance.Tests`
boots the shim on loopback, runs the suite, and asserts a passing **baseline of 57** so the conformance
level cannot regress; the full run is `conformance.yml` (PR + nightly).

**Current result: 57 / 59 passing.** The structural / issue / verify core passes, including the v1.0
compliance hardening — identifier-URL validation (`id`, `issuer`, `credentialStatus.id`,
`credentialSchema.id`, `credentialSubject.id`, `refreshService.id`, `relatedResource.id`),
`refreshService.type`, `relatedResource` structure, and `name`/`description` §11.1 language value objects.
The 2 not-yet-passing tests are explicit and individually named:

| Test | Why it does not pass | Status |
|---|---|---|
| `type` MUST be one or more terms and/or absolute URL strings (rejecting a `type` that is well-formed but unmapped by `@context`) | Detecting a `type` string that is neither an absolute URL nor a term mapped by `@context` requires JSON-LD context expansion / term resolution, which the System.Text.Json-only engine does not perform (NFR-002). | Documented **non-goal** for v1.0 (STJ-only design). |
| `relatedResource` digest MUST match the retrieved resource | The engine validates `relatedResource` **structure** (objects; a unique URL `id`; at least one of `digestSRI`/`digestMultibase`) but does not yet **fetch the resource and verify the digest hash**. | Deferred to a focused follow-up (a verifier-side fetch+hash on an optional resolver hook), then this gap closes. |

This is reported as a tracked baseline rather than a "fully conformant" claim: the engine passes the
structural / issue / verify core of the suite, and the 2 gaps above are explicit, named, and individually
addressable. Raising the baseline as the engine improves is expected; a drop below it fails CI.

## Interoperability vectors (`tests/Credentials.InteropTests`)

- **SD-JWT VC** — the disclosures the engine emits are cross-checked against the SD-JWT spec's digest
  algorithm: each disclosure's `base64url(SHA-256(ascii(disclosure)))` is recomputed independently and
  matched against the issued `_sd` array, proving cross-implementation agreement on the disclosure-digest
  algorithm. The negative cases (a tampered disclosure value; an unmatched disclosure) reject, and the
  `dc+sd-jwt` media type / `typ` are drift sentinels.
- **bbs-2023 (vc-di-bbs)** — `IsAvailable`-gated. A derived proof pins the wire-format drift sentinels
  (the `bbs-2023` cryptosuite name and a multibase-base64url `proofValue`), verifies, and a tampered
  revealed-mandatory value is rejected (the cryptographically-enforced mandatory group).

The no-Newtonsoft consumer-closure guarantee (NFR-002) is asserted separately by
`Credentials.ConsumerProbe` (`tools/check-no-newtonsoft-closure.sh`).
