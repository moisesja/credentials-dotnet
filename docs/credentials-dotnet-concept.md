# credentials-dotnet — Concept Document

**Status:** Draft for review (concept stage — precedes the PRD)
**Date:** 2026-06-06
**Scope:** What `credentials-dotnet` is, what it does and does not cover, and the decisions already agreed. This is the concept document in the document-first sequence (concept → decisions walkthrough → PRD → implementation); it does not yet enumerate numbered functional requirements.

> This document assumes the stack described in `architectural-path.md`. It does not repeat the foundation's design; it focuses on the credentials capability. Acronyms are expanded on first use; see the glossary in `architectural-path.md` for the long tail.

---

## 1. Purpose

`credentials-dotnet` is the .NET library that implements the **W3C Verifiable Credentials Data Model 2.0 (VCDM 2.0)** — creating, issuing, holding, presenting, and verifying **Verifiable Credentials (VCs)** and **Verifiable Presentations (VPs)**. A VC is a tamper-evident, cryptographically secured set of claims made by an issuer (the digital equivalent of a diploma or licence); a VP is a holder-assembled package of one or more credentials shown to a verifier.

It is the **credentials capability** of the `net-wallet-sdk` stack. It is a *data-model-and-roles engine*: it owns the credential and presentation model and the issuer/holder/verifier orchestration, and it delegates everything beneath that —

- cryptographic operations to **`crypto-dotnet`**,
- proof formats to **`dataproofs-dotnet`**, and
- decentralized identifiers and keys to **`net-did`**.

It implements no cryptographic primitives and no DID logic of its own.

---

## 2. Where it fits

`credentials-dotnet` is a capability library in the stack's capability layer, alongside `zcap-dotnet` (authorization capabilities) and `didcomm-dotnet` (messaging). It is composed by `net-wallet-sdk`, which exposes credentials as one of its capabilities.

**Direct dependencies:**

- **`crypto-dotnet`** — for cryptographic operations the engine performs itself: hashing and digests (for example, SD-JWT disclosure digests and integrity checks), salt and nonce generation, and holder-binding key operations / proof of possession — the cryptography that is not a complete proof object and not DID resolution.
- **`dataproofs-dotnet`** — for every securing mechanism (embedded Data Integrity proofs, and enveloping JOSE/COSE/SD-JWT).
- **`net-did`** — to resolve issuer, holder, and subject identifiers and their verification keys.

It does **not** depend on `zcap-dotnet` or `didcomm-dotnet` (they are orthogonal siblings; the wallet composes them).

> Note on the original framing. The initial brief was to "leverage `net-did` for DIDs and the underlying cryptography." Since then the shared foundation was introduced: cryptography now lives in `crypto-dotnet` and proofs in `dataproofs-dotnet`. So `credentials-dotnet` leverages `net-did` for identifiers and keys, `crypto-dotnet` for cryptographic operations, and `dataproofs-dotnet` for proofs — the same intent ("DIDs and the underlying cryptography"), now expressed through the layered architecture.

---

## 3. Scope

### In scope

- The **VCDM 2.0** data model: credentials, presentations, and their members (`@context`, `type`, `issuer`, `validFrom`/`validUntil`, `credentialSubject`, `credentialStatus`, `credentialSchema`, `termsOfUse`, `evidence`; presentation `holder` and `verifiableCredential`).
- The three **roles** as library APIs: **Issuer**, **Holder**, **Verifier**.
- Three credential forms, all secured via `dataproofs-dotnet`:
  1. VCDM 2.0 with an **embedded** Data Integrity proof,
  2. VCDM 2.0 with an **enveloping** proof (VC-JOSE-COSE — JOSE or COSE), and
  3. the **SD-JWT VC** profile (IETF, media type `application/dc+sd-jwt`) for the OpenID/European-Digital-Identity ecosystem.
- **Selective disclosure and unlinkability** — the holder revealing only chosen claims: via `bbs-2023` on the embedded path, and via SD-JWT salted disclosures with a Key Binding JWT on the token path.
- **Credential status** — issuing and checking **Bitstring Status List v1.0** entries for revocation and suspension.
- **Schema validation** — validating a credential against its `credentialSchema` (JSON Schema 2020-12; SHACL deferred).
- **Presentations** — building and verifying VPs, including holder/key binding.
- **VCDM 1.1 on verification only** — the verifier accepts VCDM 1.1 credentials; issuance is VCDM 2.0 only.

### Out of scope (explicitly)

- **Issuance and presentation transport protocols** — OpenID for Verifiable Credential Issuance / Presentation (OID4VCI / OID4VP), and DIDComm-based exchange. These are protocol concerns composed *above* `credentials-dotnet`, in `net-wallet-sdk` or a dedicated protocol library. `credentials-dotnet` exposes the roles as in-process APIs, not network protocols.
- **Cryptographic primitives and proof mechanics** — owned by `dataproofs-dotnet` / `crypto-dotnet`.
- **DID resolution and key management** — owned by `net-did`.
- **Trust frameworks / trust lists** — deciding *whether* to trust a given issuer is caller-supplied policy. `credentials-dotnet` provides the verification primitives and policy hooks, not a trust registry.
- **Wallet storage, UI, and lifecycle** — the wallet's concern.

---

## 4. Conceptual model

### 4.1 Credentials and presentations

A **credential** binds claims about a subject to an issuer. A **presentation** is how a holder shares one or more credentials with a verifier, optionally proving control of the holder key. VCDM 2.0 deliberately separates the *data model* (what a credential means) from the *securing mechanism* (how it is made tamper-evident) — which is exactly the seam between `credentials-dotnet` (model + roles) and `dataproofs-dotnet` (securing).

### 4.2 The three roles

- **Issuer** — assembles a credential, then secures it in the requested form (embedded, enveloping, or SD-JWT VC) by calling `dataproofs-dotnet`, signing with an issuer key resolved through `net-did`.
- **Holder** — receives and holds credentials; derives a minimally disclosing version when needed (a `bbs-2023` derived proof, or an SD-JWT presentation with chosen disclosures); and assembles a Verifiable Presentation, binding it to a holder key.
- **Verifier** — checks a credential or presentation end to end: proof verification (via `dataproofs-dotnet`), validity window (`validFrom`/`validUntil`), status (Bitstring Status List), schema conformance, holder binding, and any caller-supplied issuer-trust policy.

### 4.3 Securing mechanisms (credential forms)

All three are produced and verified through `dataproofs-dotnet`; `credentials-dotnet` chooses the form and orchestrates:

- **Embedded (Data Integrity).** The proof lives inside the credential JSON. Used with the EdDSA/ECDSA cryptosuites for ordinary signing, and with `bbs-2023` for unlinkable selective disclosure.
- **Enveloping (VC-JOSE-COSE).** The VCDM 2.0 credential is the payload of a signed JOSE or COSE container.
- **SD-JWT VC.** A token-format credential with selective disclosure built in, aligned with the OpenID/EUDI world.

### 4.4 Selective disclosure and unlinkability

Two mechanisms, one per path: `bbs-2023` derived proofs on the embedded path (unlinkable across presentations), and SD-JWT salted-hash disclosures plus a Key Binding JWT on the token path. `ecdsa-sd-2023` (the final-standard ECDSA selective-disclosure cryptosuite) is **deferred to a later release** (see Decisions).

### 4.5 Status

Issuers publish a **Bitstring Status List v1.0** credential and reference it from each credential's `credentialStatus`; verifiers fetch the list and check the referenced bit. Supports both revocation and suspension.

### 4.6 Schema validation

A credential may carry a `credentialSchema` pointing to a JSON Schema; the verifier (and optionally the issuer at creation time) validates the credential's claims against it.

---

## 5. Specifications implemented

| Specification | Version | Status |
|---|---|---|
| Verifiable Credentials Data Model (VCDM) | 2.0 | W3C Recommendation (2025-05-15) |
| Bitstring Status List | 1.0 | W3C Recommendation (2025-05-15) |
| VC Data Integrity (embedded securing, via `dataproofs-dotnet`) | 1.0 | W3C Recommendation |
| Securing VCs using JOSE & COSE (VC-JOSE-COSE) | 1.0 | W3C Recommendation |
| DI BBS Cryptosuites (`bbs-2023`, selective disclosure) | 1.0 | W3C Candidate Recommendation Draft (not final) |
| SD-JWT | — | IETF RFC 9901 (final) |
| SD-JWT VC (`application/dc+sd-jwt`) | `draft-ietf-oauth-sd-jwt-vc-16` (pinned) | IETF Internet-Draft (not final) |
| JSON Schema (for `credentialSchema`) | 2020-12 | IETF/community standard |
| DI ECDSA Cryptosuites (`ecdsa-sd-2023`) | 1.0 | W3C Recommendation — *deferred to a later release* |

The mechanics of every securing spec above are implemented in `dataproofs-dotnet`; `credentials-dotnet` implements only VCDM 2.0, Bitstring Status List, and schema validation directly, and orchestrates the rest.

---

## 6. Capabilities (basis for the future functional requirements)

Grouped by role; these are the capability rows the PRD will expand into numbered functional requirements with a concept-to-FR traceability table.

**Issuer**

- Build a VCDM 2.0 credential from claims, subject, validity window, status reference, and schema reference.
- Secure it as embedded (Data Integrity), enveloping (VC-JOSE-COSE), or SD-JWT VC.
- Issue a `bbs-2023` base credential that supports later selective disclosure.
- Publish and update a Bitstring Status List, and set/clear a credential's status.

**Holder**

- Hold and inspect credentials in any of the three forms.
- Derive a minimally disclosing credential — a `bbs-2023` derived proof or an SD-JWT presentation with chosen disclosures.
- Build a Verifiable Presentation from one or more credentials, with holder/key binding.

**Verifier**

- Verify a credential or presentation: proof, validity window, status, schema, holder binding.
- Verify selectively disclosed credentials (derived `bbs-2023` proofs; SD-JWT disclosures + Key Binding JWT).
- Apply caller-supplied issuer-trust policy via the `IIssuerTrustPolicy` hook (not a built-in trust registry).

**Cross-cutting**

- Resolve issuer/holder/subject DIDs and keys through `net-did`.
- Validate against `credentialSchema` (JSON Schema 2020-12).
- VCDM 1.1 backward compatibility on verification (verify only; issuance is 2.0 only — D8).

---

## 7. Dependencies and integration

- **Runtime:** .NET 10, latest C#.
- **Serialization:** `System.Text.Json` throughout (consistent with the stack; the only Newtonsoft.Json in the stack is isolated inside `dataproofs-dotnet`'s RDF canonicalization and never surfaces here).
- **Depends on:** `crypto-dotnet` (cryptographic operations — hashing, digests, salts, holder-binding keys), `dataproofs-dotnet` (all securing mechanisms), `net-did` (DIDs and keys).
- **Composed by:** `net-wallet-sdk`.
- **Orthogonal to:** `zcap-dotnet`, `didcomm-dotnet`.

---

## 8. Design principles

- **Protocol-agnostic engine.** Roles are in-process APIs; transport protocols live above.
- **Delegate, don't duplicate.** It implements no cryptographic primitives of its own — calling `crypto-dotnet` for operations and `dataproofs-dotnet` for complete proofs — and no DID logic of its own (→ `net-did`). It reaches `crypto-dotnet` directly only for operations the proof layer does not expose (hashing, digests, salts, holder-binding keys).
- **Uniform `System.Text.Json`.**
- **Policy by injection.** Issuer trust (`IIssuerTrustPolicy`), schema sources, and status fetching are caller-supplied hooks, not baked-in behavior.
- **Document-centric core, typed convenience layer.** The credential-as-document is the source of truth (proofs and canonicalization need byte/structure fidelity); a strongly-typed object model is layered over it for ergonomics. Both are first-class.
- **Samples and API coverage as deliverables.** Per house style, the PRD will mandate a `samples/` directory of runnable console projects and a CI-enforced API-coverage check, separate from unit tests.

---

## 9. Decisions (agreed this session)

- **D1 — Support all three securing families.** Embedded (Data Integrity), enveloping (VC-JOSE-COSE), and SD-JWT VC.
- **D2 — Canonicalization is full RDFC + JCS.** The RDF-Dataset-Canonicalization-based and JCS-based cryptosuites are both in scope (implemented in `dataproofs-dotnet`); `bbs-2023` rides the RDFC path.
- **D3 — Selective disclosure: `bbs-2023` on the embedded path; SD-JWT disclosures on the token path.** `ecdsa-sd-2023` is deferred to a later release.
- **D4 — Status via Bitstring Status List v1.0** (revocation and suspension).
- **D5 — Three substrates: `crypto-dotnet`, `dataproofs-dotnet`, `net-did`.** `credentials-dotnet` depends on all three — `crypto-dotnet` directly for cryptographic operations it performs itself (hashing, digests, salts, holder-binding key operations), `dataproofs-dotnet` for complete proof objects, and `net-did` for identifiers and keys.
- **D6 — Protocol-agnostic.** OID4VCI/OID4VP and DIDComm exchange are out of scope, composed above.
- **D7 — .NET 10 / latest C#, `System.Text.Json` throughout.**
- **D8 — VCDM 1.1 backward compatibility: verify, do not issue.** The verifier accepts VCDM 1.1 credentials; issuance is VCDM 2.0 only.
- **D9 — Schema validation is JSON Schema 2020-12.** SHACL validation is deferred to a later release; the validation seam is designed to admit it without rework.
- **D10 — Both API shapes, layered.** The library exposes a document-centric core — the credential as a JSON document, which is the source of truth for proof and canonicalization purposes (byte/structure fidelity matters) — with a strongly-typed object model layered over it for ergonomics.
- **D11 — Issuer trust is a named interface.** Verification exposes an optional `IIssuerTrustPolicy` extension point, invoked as an explicit step, returning a structured result (decision plus reason) rather than a bare boolean. No built-in trust lists ship in v1 (a single allowlist sample only); trust frameworks stay out of scope.
- **D12 — SD-JWT VC pinned to a named draft, behind a stable surface.** The implementation targets `draft-ietf-oauth-sd-jwt-vc-16` (the current revision as of mid-2026; bumped deliberately, not chased). No draft-specific types appear on the public API — SD-JWT VC is reached only through the common Issuer/Holder/Verifier API, with the wire mechanics owned by `dataproofs-dotnet` — the same isolation discipline as `bbs-2023`.

---

## 10. Open decisions (all resolved)

All concept-stage open decisions are now resolved (OD1–OD3 as D8–D10, OD4 as D11, OD5 as D12). The remaining specifics — the exact `IIssuerTrustPolicy` signature and structured-result type, the precise SD-JWT VC validation surface, and how the strongly-typed views project over the document core — are PRD-level detail, to be settled when functional requirements are written.

---

## 11. References

- `architectural-path.md` — the stack, the foundation, and the full glossary.
- W3C VCDM 2.0, VC Data Integrity, VC-JOSE-COSE, Bitstring Status List (W3C Recommendations, 2025-05-15).
- W3C DI BBS Cryptosuites (`bbs-2023`, Candidate Recommendation Draft).
- IETF SD-JWT (RFC 9901) and SD-JWT VC (Internet-Draft).
