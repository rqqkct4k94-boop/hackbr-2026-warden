# Warden Quantum Authority — competition P0 (23 Nov 2026)

Feature freeze follows these two final capabilities: post-quantum protection and quantum-gated authority. The project remains synthetic, competition-only, with no production changes, credential collection, private-key transfer, paid subscription, billing upgrade, or unapproved cloud resource creation.

## Assurance and evidence boundaries

| Component | Acceptance | Scope |
|---|---|---|
| PQC signatures | 3 distinct synthetic custodians, each signing the same bounded request with ECDSA P-256 and ML-DSA-65; six signatures and pinned public keys must verify; missing, altered, or substituted evidence rejected | Node 24.6+ / OpenSSL 3.5; no independent-human or hardware-custody claim |
| PQC encryption | Real ML-KEM-768 key establishment and AES-256-GCM on a single public synthetic document; roundtrip succeeds; tampered ciphertext and wrong recipient fail | Local disposable feasibility test, not an interoperable production envelope or live cloud KMS operation |
| Native standard PQC | Owner-run Google Cloud KMS SOFTWARE ML-DSA-65 signature independently verified against separately supplied public fingerprints and existing audit head; signed ML-KEM-768/AES-GCM roundtrip and alteration rejection report consistent | Completed 24 Nov; report is not provider attestation or provider-enforced Warden 3/3 |
| Native hybrid KEM | Dedicated eligible X-Wing key (ML-KEM-768 + X25519) and ML-DSA signing only after owner approves the exact software key versions and available credits | Google Cloud KMS documented support; live acceptance pending; no HSM equivalence |
| Quantum authority | Three valid dual signatures plus one fresh, exact-request-bound, provider-verified physical QPU result; unavailable/simulated, stale, replayed and wrong-request results deny | IBM Quantum Open Plan; no mathematical proof of quantumness. The operation must remain behind Warden; exporting a complete conventional key would defeat this architecture |
| Judge sandbox | Separate owner-authenticated environment with explicit disposable test object, scoped existing privileges, public redacted evidence only | No API tokens or private keys on the public site. Never change production assets, existing encryption configuration, or IAM |

## Implementation gates

**Hardware smoke test completed, separate from the gate:** on 23 Nov 2026, the authenticated IBM Quantum console reported a 256-shot Bell-state workload completed on `ibm_marrakesh`, with 2 seconds displayed on QPU and 0.029489 RUs consumed. See [`judge/recorded-qpu-smoke.json`](judge/recorded-qpu-smoke.json). This does not authorize a Warden operation; the trusted request-bound adapter and live positive/negative acceptance remain pending.

1. **24 Nov — PQC:** reproduce actual ML-DSA-65 + ECDSA signatures and ML-KEM/AES-GCM trial, reject tampered data and wrong recipients. Publish only public keys, signatures and independently retained fingerprints. Local tests do not demonstrate native X-Wing, cloud signing or real custodial independence.
2. **25 Nov — quantum authority:** use one owner-approved IBM Quantum free Open Plan instance. Test a bounded synthetic circuit, retrieve job result through the authenticated provider, bind request digest, approved circuit digest, nonce, provider/backend and completion time to one permission. Never accept an uploaded JSON report as an authorizing credential. Local unit tests exercise the adapter contract; only the actual trusted adapter and live job can satisfy the hardware gate. No paid fallback. Quantum provider unavailability denies the protected operation. Use durable single-use validation for any live mediated operation; the public rehearsal cannot execute it.
3. **26 Nov — cloud and evidence:** existing five-VM idle/restart acceptance passed on 24 Nov. The owner has separately approved two dedicated SOFTWARE KMS versions; implement native ML-DSA-65 signing and standard ML-KEM-768 decapsulation with the existing `cryptography` package. X-Wing remains a distinct interoperability acceptance (not silently substituted or claimed), and no extra key version is authorized. Add a single synthetic object workflow in a judge-owned sandbox only if resource and spend are explicitly approved. Keep source-side private keys under their original authority. Export only sanitized public report material. A QPU result is provider-observed execution, not proof that a classical computer cannot reproduce it.
4. **27 Nov — release freeze:** independently verify clean-checkout CI, read-only HTTPS console, proof validation and denial experience. Default 90-second no-account judge path; genuine hardware recording separately marked recorded, no live QPU claim without evidence. Optional own-cloud path is separate.
5. **28–29 Nov — communication:** final UI polish, Portuguese rehearsal and <=3-minute video after functionality stabilizes. Submit only with explicit final owner approval by 30 Nov 23:59 BRT.

## Owner-run IBM gate (25 Nov)

The public PQC release is deployed and anonymously tested: [recorded release](judge/recorded-pqc-release.json). The next live acceptance is the isolated owner-side `ibm_quantum_gate.py`. It requires an existing IBM Cloud API key or existing saved Qiskit profile, the exact current Open Plan service CRN, and the existing prepared Warden runtime. It refuses non-Open plans and nonphysical or unavailable backends. **No credentials are ever accepted by the public portal; enter an existing key only in the private terminal's hidden prompt.** No saved credential is created by the runner.

From the existing Cloud Shell `demo/` directory with the venv active and the approved `WARDEN_DEMO_PROJECT` set:

```bash
python -m pip install -r requirements.txt -r requirements-quantum.txt
read -rp 'Existing IBM Open Plan instance CRN: ' WARDEN_IBM_INSTANCE
python ibm_quantum_gate.py plan --runtime ~/warden-hackbr-p0-private --instance "$WARDEN_IBM_INSTANCE"
```

Use the reviewed preflight branch. Proceed only if the authenticated console confirms sufficient remaining Open Plan usage, `plan` reports `ibm_marrakesh`, `local_preparation: passed` and `jobs_submitted: 0`, and the private runtime has no previous IBM gate journal or output. The offline SDK test uses IBM's labeled `FakeMarrakesh` target and the real SDK constructor, options, transpiler, and serializer. The owner plan checks the actual target, faults, options and usage before the journal is opened. It exercises one 256-shot PUB with a 60-second execution cap. A passed plan leaves server acceptance, queue timing, measured usage and the authenticated result contract to the live run. [IBM Runtime 0.49 SamplerV2](https://quantum.cloud.ibm.com/docs/en/api/qiskit-ibm-runtime/0.49/sampler-v2) · [IBM Runtime 0.49 job results and metrics](https://quantum.cloud.ibm.com/docs/en/api/qiskit-ibm-runtime/0.49/runtime-job-v2)

When those conditions hold, the owner can explicitly approve the single job.

```bash
python ibm_quantum_gate.py apply --runtime ~/warden-hackbr-p0-private --instance "$WARDEN_IBM_INSTANCE" --approve-one-open-plan-job
```

For an existing saved SDK profile add `--profile PROFILE_NAME`. A fresh local synthetic three-custodian dual-signature request is verified before submission, the 256-shot two-qubit Bell challenge carries both request and circuit digests, and a single journal reservation is committed before submission. The authenticated service re-fetches the exact submitted job and checks backend, instance, status, timestamps, tags, result circuit metadata, positive usage and bounded shot statistics. The journal atomically consumes the job and request before decrypting a fixed AES-GCM-encrypted synthetic document. It never creates or uses KMS keys. The circuit is classically simulable; quantum dependence is the owner-side policy gate, not a proof of quantum-exclusive computation or entropy. The three synthetic signers are not independent humans.

A preparation failure before the journal is opened can be corrected by rerunning `plan`. If a journal already exists, preserve it and review the prior attempt. If submission or result retrieval fails, stop. The private journal prevents repeat submissions; do not remove it to bypass this prohibition. Share only the redacted `public-ibm-gate-report.json` and, for independent signature validation, `public-ibm-gate-proof.json`. Until an actual provider result passes, tests remain local adapter-contract evidence only.

## Reproducible starter

From `demo/` use Node 24.6+ (ML-KEM requires 24.7+) and run `node --test test_quantum_authority.mjs` and `node quantum_authority.mjs verify judge/quantum-sample.json judge/quantum-pins.json`. Verify the owner-run native proof independently with `python native_pqc_gate.py verify --proof judge/recorded-native-pqc-proof.json --pin judge/recorded-native-pqc-pin.json`. Only public proof/pins are published; never publish private data or test-only provider fixture receipts. The read-only portal's Quantum page shows recorded cryptographic proof and a fail-closed rehearsal. Request-bound hardware authorization and hybrid X-Wing remain pending. Hardware authorization is not yet implemented at a provider boundary.

Official references: [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final), [Google KMS algorithms](https://docs.cloud.google.com/kms/docs/algorithms), [IBM Quantum Open Plan](https://quantum.cloud.ibm.com/docs/en/ibm-quantum-platform/plans-overview), [Hack Brasil evaluation](https://hackbrasil.com/regulamento#avaliacao).
