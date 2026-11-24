# Warden Quantum Authority — competition P0 (23 Nov 2026)

Feature freeze follows these two final capabilities: post-quantum protection and quantum-gated authority. The project remains synthetic, competition-only, with no production changes, credential collection, private-key transfer, paid subscription, billing upgrade, or unapproved cloud resource creation.

## Assurance and evidence boundaries

| Component | Acceptance | Scope |
|---|---|---|
| PQC signatures | 3 distinct synthetic custodians, each signing the same bounded request with ECDSA P-256 and ML-DSA-65; six signatures and pinned public keys must verify; missing, altered, or substituted evidence rejected | Node 24.6+ / OpenSSL 3.5; no independent-human or hardware-custody claim |
| PQC encryption | Real ML-KEM-768 key establishment and AES-256-GCM on a single public synthetic document; roundtrip succeeds; tampered ciphertext and wrong recipient fail | Local disposable feasibility test, not an interoperable production envelope or live cloud KMS operation |
| Native hybrid KEM | Dedicated eligible X-Wing key (ML-KEM-768 + X25519) and ML-DSA signing only after owner approves the exact software key versions and available credits | Google Cloud KMS documented support; live acceptance pending; no HSM equivalence |
| Quantum authority | Three valid dual signatures plus one fresh, exact-request-bound, provider-verified physical QPU result; unavailable/simulated, stale, replayed and wrong-request results deny | IBM Quantum Open Plan; no mathematical proof of quantumness. The operation must remain behind Warden; exporting a complete conventional key would defeat this architecture |
| Judge sandbox | Separate owner-authenticated environment with explicit disposable test object, scoped existing privileges, public redacted evidence only | No API tokens or private keys on the public site. Never change production assets, existing encryption configuration, or IAM |

## Implementation gates

1. **24 Nov — PQC:** reproduce actual ML-DSA-65 + ECDSA signatures and ML-KEM/AES-GCM trial, reject tampered data and wrong recipients. Publish only public keys, signatures and independently retained fingerprints. Local tests do not demonstrate native X-Wing, cloud signing or real custodial independence.
2. **25 Nov — quantum authority:** use one owner-approved IBM Quantum free Open Plan instance. Test a bounded synthetic circuit, retrieve job result through the authenticated provider, bind request digest, approved circuit digest, nonce, provider/backend and completion time to one permission. Never accept an uploaded JSON report as an authorizing credential. Local unit tests exercise the adapter contract; only the actual trusted adapter and live job can satisfy the hardware gate. No paid fallback. Quantum provider unavailability denies the protected operation. Use durable single-use validation for any live mediated operation; the public rehearsal cannot execute it.
3. **26 Nov — cloud and evidence:** finish existing five-VM idle/restart acceptance and native signing; add a single synthetic object workflow in a judge-owned sandbox only if resource and spend are explicitly approved. Keep source-side private keys under their original authority. Export only sanitized public report material. A QPU result is provider-observed execution, not proof that a classical computer cannot reproduce it.
4. **27 Nov — release freeze:** independently verify clean-checkout CI, read-only HTTPS console, proof validation and denial experience. Default 90-second no-account judge path; genuine hardware recording separately marked recorded, no live QPU claim without evidence. Optional own-cloud path is separate.
5. **28–29 Nov — communication:** final UI polish, Portuguese rehearsal and <=3-minute video after functionality stabilizes. Submit only with explicit final owner approval by 30 Nov 23:59 BRT.

## Reproducible starter

From `demo/` use Node 24.6+ (ML-KEM requires 24.7+) and run `node --test test_quantum_authority.mjs` and `node quantum_authority.mjs verify judge/quantum-sample.json judge/quantum-pins.json`. Only the code-generated sample public proof/pins are published; never publish private data or test-only provider fixture receipts. The read-only portal's Quantum page shows recorded cryptographic proof and a fail-closed rehearsal, with hardware/native cloud acceptance explicitly pending. Hardware authorization is not yet implemented at a provider boundary.

Official references: [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final), [Google KMS algorithms](https://docs.cloud.google.com/kms/docs/algorithms), [IBM Quantum Open Plan](https://quantum.cloud.ibm.com/docs/en/ibm-quantum-platform/plans-overview), [Hack Brasil evaluation](https://hackbrasil.com/regulamento#avaliacao).
