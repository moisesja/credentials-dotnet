# Conformance & interoperability status

This documents how `credentials-dotnet` is measured against external test suites and vectors, and —
honestly — what passes and what does not yet.

## W3C VCDM 2.0 test suite

The [`w3c/vc-data-model-2.0-test-suite`](https://github.com/w3c/vc-data-model-2.0-test-suite) (the Node
interoperability suite) is run against a thin ASP.NET shim (`tests/Credentials.Conformance.VcApi`) that
exposes `POST /credentials/issue`, `/credentials/verify`, and `/presentations/verify` over the engine's
`IIssuer`/`IVerifier`. The shim issues with `eddsa-rdfc-2022`; the suite injects the shim's own `did:key`
as the credential issuer, so issuance satisfies the engine's issuer-binding. `Credentials.Conformance.Tests`
boots the shim on loopback, runs the suite, and asserts a passing **baseline of 43** so the conformance
level cannot regress; the full run is `conformance.yml` (PR + nightly).

**Current result: 43 / 59 passing.** The 16 not-yet-passing tests are not silent — they are known
limitations, grouped:

| Group | Why it does not pass | Status |
|---|---|---|
| Full JSON-LD term mapping (e.g. "unmapped type", "type mapped to a non-URL") | The engine validates VCDM **structure** with System.Text.Json; it does not perform JSON-LD expansion/term resolution, so it cannot detect a `type` that is well-formed but unmapped by `@context`. | Out of scope for the current STJ-only design (NFR-002). |
| `relatedResource` integrity (wrong/missing/duplicate digest, non-object form) | `relatedResource` digest verification is not implemented. | Future feature. |
| `name` / `description` language-value-object validation (extra properties) | The engine does not validate the §11.1 language/direction object shape of `name`/`description`. | Future hardening. |
| A few issuer/credentialSchema/credentialStatus identifier-URL negatives | The structural validator does not yet reject every non-URL identifier the suite checks. | Incremental validator hardening. |

This is reported as a tracked baseline rather than a "fully conformant" claim: the engine passes the
structural / issue / verify core of the suite, and the gaps above are explicit and individually
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
