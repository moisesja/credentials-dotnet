# credentials-dotnet

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)
[![Spec](https://img.shields.io/badge/spec-W3C%20VCDM%202.0-informational.svg)](https://www.w3.org/TR/vc-data-model-2.0/)

A .NET 10 implementation of the **W3C Verifiable Credentials Data Model 2.0 (VCDM 2.0)** — issuing, holding,
presenting, and verifying **Verifiable Credentials (VCs)** and **Verifiable Presentations (VPs)**. It is the
credentials capability of the `net-wallet-sdk` stack: a data-model-and-roles engine that delegates cryptography
to `NetCrypto`, proofs to `DataProofsDotnet`, and identifiers/keys to `NetDid`.

## Status

Early development. Milestone **M0** (solution skeleton, document-centric core model, structural validation,
dependency-injection surface) is the current build target. See the implementation plan below for the roadmap.

## Documentation

This README is a thin router. The design context lives in [`docs/`](docs/) — read in this order:

1. [`docs/architectural-path.md`](docs/architectural-path.md) — the whole `net-wallet-sdk` wallet ecosystem and the shared foundation.
2. [`docs/credentials-dotnet-concept.md`](docs/credentials-dotnet-concept.md) — what this library is and the agreed decisions (D1–D12).
3. [`docs/credentials-dotnet-prd.md`](docs/credentials-dotnet-prd.md) — the numbered functional/non-functional requirements.

The phased implementation plan is in [`tasks/todo-2026-06-18-credentials-dotnet-implementation.md`](tasks/todo-2026-06-18-credentials-dotnet-implementation.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
