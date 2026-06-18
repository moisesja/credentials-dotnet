# credentials-dotnet — Product Requirements Document (PRD)

**Status:** Draft for review
**Date:** 2026-06-06
**Builds on:** `credentials-dotnet-concept.md` (approved). The concept document is the source of intent; this PRD turns its capabilities into numbered, testable requirements. Decisions D1–D12 from the concept document are binding here and are not re-opened.

---

## 1. Overview

`credentials-dotnet` is the .NET library implementing the W3C Verifiable Credentials Data Model 2.0 (VCDM 2.0): issuing, holding, presenting, and verifying Verifiable Credentials (VCs) and Verifiable Presentations (VPs). It is the credentials capability of the `net-wallet-sdk` stack — a data-model-and-roles engine that delegates cryptography to `crypto-dotnet`, proof formats to `dataproofs-dotnet`, and identifiers and keys to `net-did`.

This PRD covers the engine's public surface, functional and non-functional requirements, deliverables, and acceptance criteria. It does not specify implementation internals beyond what a requirement constrains.

## 2. Goals and non-goals

**Goals**

- A complete, standards-conformant VCDM 2.0 engine for the three roles (Issuer, Holder, Verifier).
- Support for all three credential forms: embedded Data Integrity, enveloping VC-JOSE-COSE, and SD-JWT VC.
- Selective disclosure on both paths (`bbs-2023` embedded; SD-JWT token).
- Credential status (Bitstring Status List v1.0) and schema validation (JSON Schema 2020-12).
- A clean, stable public API that isolates draft churn and is composable by `net-wallet-sdk`.

**Non-goals (out of scope)**

- Issuance/presentation transport protocols (OID4VCI, OID4VP, DIDComm exchange) — composed above.
- Cryptographic primitives and proof mechanics (`crypto-dotnet` / `dataproofs-dotnet`).
- DID resolution and key management (`net-did`).
- Trust frameworks and trust registries (caller-supplied policy only).
- Wallet storage, UI, and lifecycle.

## 3. Consumers

- `net-wallet-sdk`, which exposes credentials as one of its composed capabilities.
- Direct library consumers building issuer, holder, or verifier services on .NET.

## 4. Dependencies and runtime

- **Runtime:** .NET 10, latest C#.
- **Serialization:** `System.Text.Json` exclusively.
- **Direct dependencies:** `crypto-dotnet` (cryptographic operations the engine performs itself — hashing, digests, salts, holder-binding keys), `dataproofs-dotnet` (all securing mechanisms), `net-did` (DIDs and keys).
- **Composed by:** `net-wallet-sdk`. **Orthogonal to:** `zcap-dotnet`, `didcomm-dotnet`.

## 5. Public API model

Per D10, the library exposes:

- A **document-centric core** — credentials and presentations backed by a `System.Text.Json` document that is the canonical source of truth, preserving the exact structure proof verification depends on.
- A **strongly-typed object model** layered over the core for ergonomics, projecting typed views and builders over the underlying document.

The three roles are surfaced as in-process services (`IIssuer`, `IHolder`, `IVerifier` or equivalent), registered via Microsoft dependency injection. Securing mechanisms, schema resolution, status fetching, and issuer trust are injected hooks, never hard-wired.

---

## 6. Functional requirements

Requirements use MUST / SHOULD / MAY per RFC 2119. Each is testable; acceptance is covered in §9.

### 6.1 Data model (VCDM 2.0)

- **FR-001** — The library MUST represent a VCDM 2.0 credential with all standard members (`@context`, `id`, `type`, `issuer`, `validFrom`, `validUntil`, `credentialSubject`, `credentialStatus`, `credentialSchema`, `termsOfUse`, `evidence`), supporting multiple subjects and arbitrary claim shapes.
- **FR-002** — The library MUST represent a VCDM 2.0 Verifiable Presentation (`type` including `VerifiablePresentation`, `holder`, `verifiableCredential`).
- **FR-003** — Credentials and presentations MUST be backed by a document-centric core that preserves the member structure required for byte/structure-faithful proof verification and lossless round-trip.
- **FR-004** — The library MUST provide a strongly-typed object model over the document core, with typed accessors and builders for standard members, kept consistent with the underlying document.
- **FR-005** — The library MUST validate structural conformance to VCDM 2.0 (required members, `@context` ordering and inclusion, presence of the base type), reporting structured errors.

### 6.2 Issuer

- **FR-010** — The Issuer MUST build a credential from caller-supplied claims, subject(s), validity window, optional status reference, and optional schema reference.
- **FR-011** — The Issuer MUST produce an embedded Data Integrity credential using a caller-selected cryptosuite exposed by `dataproofs-dotnet` (the EdDSA and ECDSA suites, and `bbs-2023`).
- **FR-012** — The Issuer MUST produce an enveloping VC-JOSE-COSE credential in both the JOSE and COSE serializations.
- **FR-013** — The Issuer MUST produce an SD-JWT VC credential (`application/dc+sd-jwt`), marking caller-selected claims as selectively disclosable and optionally establishing a holder key-binding reference.
- **FR-014** — The Issuer MUST be able to issue a `bbs-2023` base credential that supports later holder-side selective disclosure.
- **FR-015** — The Issuer MUST sign using an issuer key obtained through `net-did`'s signer abstraction; it MUST NOT handle raw private key material directly.
- **FR-016** — The Issuer MUST be able to set `credentialStatus` referencing a Bitstring Status List entry.

### 6.3 Status (Bitstring Status List v1.0)

- **FR-020** — The library MUST create and produce a Bitstring Status List v1.0 status-list credential supporting the revocation and suspension purposes.
- **FR-021** — The library MUST set, clear, and update a credential's status (revoke, suspend, reinstate) and re-produce the status-list credential.
- **FR-022** — The Verifier MUST resolve a referenced status list (via a caller-supplied fetch hook) and evaluate the referenced status, returning the result as part of verification.

### 6.4 Holder

- **FR-030** — The Holder MUST ingest and inspect credentials in all three forms — exposing claims, validity window, status, and schema references — without altering the document core.
- **FR-031** — The Holder MUST derive a minimally disclosing credential from a `bbs-2023` base credential, producing an unlinkable derived proof revealing only chosen claims.
- **FR-032** — The Holder MUST produce an SD-JWT VC presentation revealing caller-chosen disclosures, with a Key Binding JWT.
- **FR-033** — The Holder MUST build a Verifiable Presentation from one or more credentials.
- **FR-034** — The Holder MUST bind a presentation to a holder key (VP proof or Key Binding JWT), with the key obtained through `net-did`.

### 6.5 Verifier

- **FR-040** — The Verifier MUST verify a credential end-to-end: proof (via `dataproofs-dotnet`), validity window (`validFrom`/`validUntil`, with configurable clock-skew tolerance), schema (§6.7), status (§6.3), and the issuer-trust hook (§6.8).
- **FR-041** — The Verifier MUST verify a Verifiable Presentation: each contained credential, the holder binding, and any presentation proof.
- **FR-042** — The Verifier MUST verify selectively disclosed credentials — `bbs-2023` derived proofs and SD-JWT disclosures with their Key Binding JWT.
- **FR-043** — The Verifier MUST return a structured verification result: an overall decision plus per-check outcomes and human-readable reasons. (D11)
- **FR-044** — The Verifier MUST accept and verify VCDM 1.1 credentials; issuance remains VCDM 2.0 only. (D8)
- **FR-045** — Verification MUST be side-effect free and MUST report a failed check through the structured result rather than throwing; exceptions are reserved for malformed input and programming errors.

### 6.6 Securing-mechanism integration

- **FR-050** — The library MUST delegate all proof creation and verification, and all canonicalization, to `dataproofs-dotnet`; it MUST NOT implement proof or canonicalization logic itself.
- **FR-051** — SD-JWT VC support MUST target `draft-ietf-oauth-sd-jwt-vc-16` and MUST NOT expose draft-specific types on the public API; the format is reached only through the role API, with wire mechanics owned by `dataproofs-dotnet`. (D12)
- **FR-052** — Cryptographic operations the engine performs itself (hashing and digests, salt and nonce generation, holder-binding key operations) MUST use `crypto-dotnet`. (D5)
- **FR-053** — The set of available cryptosuites and credential forms MUST be extensible: enabling a future suite surfaced by `dataproofs-dotnet` (for example `ecdsa-sd-2023`) MUST NOT require a public API change. (D3)

### 6.7 Schema validation

- **FR-070** — The library MUST validate a credential against its `credentialSchema` using JSON Schema 2020-12, fetching schema documents through a caller-supplied resolver hook. The validation seam MUST be designed to admit SHACL later without an API break. (D9)

### 6.8 Identity, keys, and policy hooks

- **FR-080** — The library MUST resolve issuer, holder, and subject DIDs and verification methods through `net-did`, and use its signer/key-store abstractions for all signing, supporting pluggable key stores.
- **FR-081** — The library MUST expose caller-supplied hooks, injected via dependency injection, for: issuer trust (`IIssuerTrustPolicy`), schema resolution, and status-list fetching.
- **FR-082** — `IIssuerTrustPolicy` MUST be invoked by the Verifier as an explicit, optional step and MUST return a structured result (decision plus reason). No built-in trust lists ship in v1; a single allowlist sample MAY be provided. (D11)

---

## 7. Non-functional requirements

- **NFR-001** — Target .NET 10 and the latest C# language version.
- **NFR-002** — Use `System.Text.Json` on the public surface and internally; the library MUST NOT introduce a `Newtonsoft.Json` dependency, and MUST NOT surface the transitive Newtonsoft that `dataproofs-dotnet` confines to its RDF canonicalization internals.
- **NFR-003** — Issuer/Holder/Verifier services MUST be safe for concurrent use; result and model types exposed across threads MUST be effectively immutable.
- **NFR-004** — I/O (DID resolution, schema and status fetching) MUST be asynchronous; the library MUST NOT block on hot paths.
- **NFR-005** — Public API MUST follow semantic versioning; `bbs-2023` and SD-JWT VC draft churn MUST stay isolated behind stable APIs (no draft-version types on the surface).
- **NFR-006** — Security: the library MUST NOT expose private key material; it MUST rely on `crypto-dotnet` for constant-time and other security-sensitive operations; canonicalization-DoS protection is delegated to `dataproofs-dotnet`.
- **NFR-007** — Conformance: the library MUST pass the official W3C VCDM 2.0 test suite, and MUST validate `bbs-2023` and SD-JWT VC behavior against published interoperability test vectors where available.
- **NFR-008** — Observability: verification results MUST carry per-check diagnostics suitable for logging without leaking secrets.
- **NFR-009** — All public API MUST carry XML documentation comments.

---

## 8. Deliverables

- **The `credentials-dotnet` NuGet package.**
- **Samples (first-class deliverable).** A `samples/` directory of runnable console projects covering each role and each credential form (issue/hold/present/verify across embedded, VC-JOSE-COSE, and SD-JWT VC; selective disclosure; status; schema validation; a trust-policy allowlist). A CI-enforced **API-coverage check** MUST verify that every public API member is exercised by at least one sample. Samples are separate from the unit-test suite.
- **Test suites.** Unit tests, the W3C VCDM 2.0 conformance suite, and interop vector tests — separate from samples.
- **API reference documentation** generated from XML comments.

---

## 9. Verification and acceptance (Definition of Done)

- Every functional requirement has corresponding automated tests.
- The W3C VCDM 2.0 conformance suite passes; `bbs-2023` and SD-JWT VC interop vectors pass where published.
- Document-core round-trip fidelity tests pass (issue → serialize → parse → verify with no structural drift).
- Samples build and run in CI; the API-coverage gate is green.
- No `Newtonsoft.Json` appears on the public surface or in the dependency closure exposed to consumers (NFR-002).
- Public API carries XML docs; semantic-versioning gate is in place.

---

## 10. Decisions carried from the concept document

D1 three securing families · D2 RDFC + JCS canonicalization · D3 `bbs-2023` embedded selective disclosure, `ecdsa-sd-2023` deferred · D4 Bitstring Status List v1.0 · D5 three substrates (`crypto-dotnet`, `dataproofs-dotnet`, `net-did`) · D6 protocol-agnostic · D7 .NET 10 / `System.Text.Json` · D8 verify VCDM 1.1, issue 2.0 only · D9 JSON Schema 2020-12, SHACL deferred · D10 document-centric core + typed layer · D11 `IIssuerTrustPolicy` (structured result, no built-in lists) · D12 SD-JWT VC pinned to `draft-ietf-oauth-sd-jwt-vc-16`.

## 11. Open questions and risks (PRD-level)

- **OQ-1** — Exact `IIssuerTrustPolicy` signature and the shape of the structured trust result.
- **OQ-2** — The precise SD-JWT VC validation surface, and the process for bumping past `draft-16` as the draft evolves.
- **OQ-3** — How the strongly-typed views project over the document core (ergonomics vs. fidelity trade-offs).
- **OQ-4** — Whether to prioritize the JOSE or COSE serialization first within VC-JOSE-COSE.
- **Risk R-1** — `bbs-2023` is a W3C Candidate Recommendation Draft (not final); interop depends on `dataproofs-dotnet`'s `bbs-2023` wiring and the zkryptium draft alignment. Track and re-verify on each draft movement.
- **Risk R-2** — SD-JWT VC is a moving Internet-Draft; pinning (D12) contains but does not eliminate churn.
- **Risk R-3** — `credentials-dotnet` now depends directly on `crypto-dotnet`; `architectural-path.md` (§5.7 and the diagram) must be updated to match, and the same direct-dependency question resolved for `zcap-dotnet`/`didcomm-dotnet`.

---

## Appendix A — Concept-to-FR traceability

Maps each concept-document capability (concept §6) to the functional requirements that realize it and the downstream consumer.

| Concept capability (role) | Functional requirements | Downstream consumer |
|---|---|---|
| Issuer — build a VCDM 2.0 credential | FR-001, FR-005, FR-010 | wallet issuer flows; direct issuers |
| Issuer — secure as embedded / enveloping / SD-JWT VC | FR-011, FR-012, FR-013, FR-050, FR-051 | wallet; issuers |
| Issuer — issue a `bbs-2023` base credential | FR-014 | holders performing selective disclosure |
| Issuer — publish/update status; set credential status | FR-016, FR-020, FR-021 | verifiers; status infrastructure |
| Issuer — sign via issuer key | FR-015, FR-080 | `net-did` key stores |
| Holder — hold and inspect credentials | FR-003, FR-030 | wallet holder storage |
| Holder — derive minimally disclosing credential | FR-031, FR-032 | verifiers receiving presentations |
| Holder — build a Verifiable Presentation | FR-002, FR-033 | verifiers |
| Holder — holder/key binding | FR-034, FR-080 | verifiers; `net-did` |
| Verifier — verify credential / presentation | FR-040, FR-041, FR-043, FR-045 | wallet verifier flows; relying parties |
| Verifier — verify selective disclosure | FR-042 | relying parties |
| Verifier — issuer-trust policy | FR-043, FR-082 | deployment trust policy |
| Cross-cutting — DID/key resolution | FR-080 | `net-did` |
| Cross-cutting — schema validation | FR-070 | issuers; verifiers |
| Cross-cutting — VCDM 1.1 on verification | FR-044 | relying parties accepting 1.1 |
| Cross-cutting — engine cryptographic operations | FR-052 | `crypto-dotnet` |
| Cross-cutting — extensible suites/forms | FR-053, FR-081 | future cryptosuites (e.g. `ecdsa-sd-2023`) |

## Appendix B — References

- `credentials-dotnet-concept.md` (approved) and `architectural-path.md`.
- W3C VCDM 2.0, VC Data Integrity 1.0, VC-JOSE-COSE 1.0, Bitstring Status List 1.0 (W3C Recommendations, 2025-05-15).
- W3C DI BBS Cryptosuites `bbs-2023` (Candidate Recommendation Draft).
- IETF SD-JWT (RFC 9901); SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc-16`).
- JSON Schema 2020-12.
