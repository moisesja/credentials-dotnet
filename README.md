# credentials-dotnet

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)
[![Spec](https://img.shields.io/badge/spec-W3C%20VCDM%202.0-informational.svg)](https://www.w3.org/TR/vc-data-model-2.0/)

A .NET 10 implementation of the **W3C Verifiable Credentials Data Model 2.0 (VCDM 2.0)** — issuing, holding,
presenting, and verifying **Verifiable Credentials (VCs)** and **Verifiable Presentations (VPs)**. It is the
credentials capability of the `net-wallet-sdk` stack: a data-model-and-roles engine that delegates cryptography
to `NetCrypto`, proofs to `DataProofsDotnet`, and identifiers/keys to `NetDid`.

## Status

Feature-complete and on the path to **v1.0.0** (currently `0.1.0`, pre-release). The engine implements all
three roles — Issuer, Holder, Verifier — across every securing family: embedded **Data Integrity**
(EdDSA / ECDSA, JCS + RDFC), **VC-JOSE-COSE**, and **SD-JWT VC**. It also covers selective disclosure
(`bbs-2023` derived proofs and SD-JWT disclosures), **Bitstring Status List v1.0**, **JSON Schema 2020-12**
validation, the issuer-trust / status / schema policy hooks, and **VCDM 1.1 verification** (issuance is
2.0 only). It passes **57 / 59** of the W3C VCDM 2.0 test suite — the 2 remaining gaps are documented, not
hidden, in [`docs/conformance.md`](docs/conformance.md).

## Documentation

This README is a thin router. The design context lives in [`docs/`](docs/) — read in this order:

1. [`docs/architectural-path.md`](docs/architectural-path.md) — the whole `net-wallet-sdk` wallet ecosystem and the shared foundation.
2. [`docs/credentials-dotnet-concept.md`](docs/credentials-dotnet-concept.md) — what this library is and the agreed decisions (D1–D12).
3. [`docs/credentials-dotnet-prd.md`](docs/credentials-dotnet-prd.md) — the numbered functional/non-functional requirements.
4. [`docs/conformance.md`](docs/conformance.md) — the honest W3C conformance + interop status.

Runnable examples for every role × form are in [`samples/`](samples/). The original phased implementation
plan (now delivered) is in [`tasks/`](tasks/).

## License

Apache-2.0 — see [LICENSE](LICENSE).
