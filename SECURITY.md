# Security Policy

credentials-dotnet is a W3C Verifiable Credentials Data Model 2.0 engine: it issues, holds, presents, and **verifies** cryptographically secured credentials. A bug in the verification path can cause a forged or tampered credential to be accepted — so verdict correctness is a security property, not just a feature. Please read this policy before reporting.

## Supported versions

| Version | Supported |
|---|---|
| `1.x` (latest minor) | Yes — security fixes land on the most recent `1.x` minor |
| `0.x` (pre-release) | No |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### How to report

1. Use GitHub's [private vulnerability reporting](https://github.com/moisesja/credentials-dotnet/security/advisories/new), or email the maintainer privately.
2. Include:
   - A description of the vulnerability and its impact
   - Steps to reproduce (a failing test or a credential/presentation fixture is ideal)
   - The affected commit/version
   - Your name and contact info for credit, if desired

### What to expect

- Acknowledgement within **48 hours**
- A plan for remediation within **7 days**
- A coordinated-disclosure timeline agreed with the reporter
- Credit in the published security advisory unless you ask to remain anonymous

## Scope

Security issues in any of the following are in scope:

- **Verdict correctness (the core property).** Any path where a forged, tampered, expired, or revoked credential/presentation verifies as **Accepted** — or where a definitive failure is downgraded to **Indeterminate** (which a non-strict policy may soft-accept). This includes all securing families: embedded Data Integrity (eddsa/ecdsa, JCS + RDFC), VC-JOSE-COSE, SD-JWT VC, and `bbs-2023` derived proofs.
- **Issuer / holder binding.** Accepting a credential whose `issuer` is not the entity that actually signed it (binding must be to the proof's verification-method base DID / the `kid`/`iss`, never a self-asserted controller), or a presentation whose holder binding does not cover the verifier's freshness challenge — including self-consistent forgeries where two signed identity fields disagree (`iss` vs `issuer`, kid-base vs `issuer`, holder vs proof VM).
- **Trust / status / schema hooks.** A fetched, separately-signed artifact (status list, schema credential) trusted without binding it to the expected issuer; a status/validity-window/type-string check that can be bypassed; secret or subject-claim leakage into a policy hook or a diagnostic (NFR-008).
- **Untrusted-input hardening.** Bypasses of the input bounds (`MaxInputBytes`, `MaxDepth`, duplicate-key rejection), GZIP decompression bombs or multibase/integer-overflow attacks in the status-list codec, or any unbounded allocation reachable from a parse/decode entry point.
- **Egress / SSRF.** Causing the verifier's opt-in HTTP hooks to reach an internal or cleartext host the configured posture forbids (e.g. via a redirect).
- **Key material.** Any path that exposes raw private key material (the library must not export it; `bbs-2023` issuance is gated for this reason).
- **Selective-disclosure residuals.** Where this engine **issues**, a holder hiding a verification-critical claim (`validUntil`, `credentialStatus`, …) the issuer should have forced into the clear. (For credentials this engine only **verifies** but did not issue, the withheld-disclosure residual is inherent to SD-JWT/BBS and is the third-party issuer's responsibility — see `docs/conformance.md`.)

## Out of scope

- Vulnerabilities in upstream dependencies — please report these to the respective project (`NetCrypto`, `DataProofsDotnet`, `NetDid`, `NetCid`, `JsonSchema.Net`).
- The egress / SSRF posture of a **caller-supplied** status/schema fetcher hook or a caller-reconfigured named `HttpClient` — egress allow-listing is the deployment's responsibility (the engine binds every fetched artifact to its expected issuer regardless).
- Issues requiring physical access to the host.
- The two documented, non-faked W3C conformance gaps (`type` JSON-LD term resolution; `relatedResource` digest hash-verification) — these are tracked features, not vulnerabilities (`docs/conformance.md`).

## Best practices for users

- **Use a fail-closed verification policy** (`TreatIndeterminateAsFailure = true`, the default) unless you have a specific reason not to — a non-strict policy soft-accepts `Indeterminate`.
- **Set `RequireStatus` / `RequireSchema` / `RequireHolderBinding`** when your trust model needs them; an unconfigured hook reports `Skipped`, not a failure.
- **Front the opt-in HTTP fetchers with an allow-listing handler / proxy** for SSRF-sensitive deployments; prefer privacy-preserving status retrieval (proxy / Oblivious HTTP).
- **Implement `IIssuerTrustPolicy`** — no trust lists ship in the library; an unverified issuer is cryptographically valid but not necessarily trusted.
- **Sign through `net-did`'s signer/key-store abstraction** and back it with an HSM/KMS in production; never handle raw private keys.

## Cryptographic-agility commitments

Proof creation, verification, and canonicalization are delegated entirely to `DataProofsDotnet`; cryptographic operations to `NetCrypto`. The engine adds no cryptographic primitives of its own. Adding or removing a securing family or cryptosuite is a design discussion — please open an issue.

## Coordinated disclosure

If a vulnerability affects the W3C VCDM, Data Integrity, VC-JOSE-COSE, Bitstring Status List, or SD-JWT VC specifications themselves, or other implementations, the maintainer will coordinate disclosure with the relevant working groups before publishing the advisory.
