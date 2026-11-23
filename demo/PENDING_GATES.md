# Remaining owner-side cloud acceptance

These tools operate only in the existing prepared Warden synthetic lab. No new billing account, paid upgrade, API enablement, IAM grants, service accounts, production resources or private key transfers. Recheck the actual promotional credit balance in the authenticated GCP console. The owner runs the command in the existing authenticated Cloud Shell.

## 1. Resumable stop/restart acceptance

`lifecycle_acceptance.py` validates the exact prepared runtime and all five existing private VMs. It checks the unique persistent boot-disk resource IDs (not just disk names), obtains a valid live TLS/audit/Besu baseline, and starts the 600-second true-idle interval with a final explicit TLS operation. Close any private dashboard or IAP preview while it observes power state. It makes no manual stop request during the interval and sends no dashboard/SSH activity or heartbeat during that observation. It allows up to 900 seconds for provider reporting lag. Provider observation is not an independently measured guest trigger timestamp.

The **stop-observed checkpoint is saved before a restart command**. If Cloud Shell disconnects after that point, run the same command again to resume the post-restart verification without repeating the idle wait. If it disconnected before the durable stop checkpoint, a fresh observation requires the additional explicit `--restart-unproven` option; the previous private checkpoint is preserved. Never force or bypass the validation. Do not launch duplicate runners.

```bash
python lifecycle_acceptance.py --runtime ~/warden-hackbr-p0-private --credit-brl <CURRENT_OWNER_VERIFIED_BRL>
```

On success share only `~/warden-hackbr-p0-private/public-lifecycle-report.json`. It contains no project ID, infrastructure locators, private disk IDs, credentials, custody material or raw private logs. No other file from the private runtime should be shared. The tool does not claim success if the final file is absent.

## 2. Provider-native signing proof — no private key transfer

The proposed Google Cloud integration uses **one software-protected provider-generated P-256 signing key version** in the dedicated `hackbr-warden-p0-native` ring. It does not import any Warden key. The native provider's private signing material never passes through Warden, Cloud Shell or the judge portal. The owner authorizes a fixed, domain-separated synthetic challenge that references the existing public Warden audit head. Only the public key and signature are exported. The 3/3 Warden policy exercise is separate; the native KMS operation is an owner-operated proof of signing capability, not proof that cloud IAM enforces that policy.

Read the inventory and plan first:

```bash
python native_signing_gate.py plan --runtime ~/warden-hackbr-p0-private
```

If Cloud KMS is disabled or the ring/key has an unexpected configuration, stop. The script never enables APIs automatically, grants new access, changes billing, deletes keys, rotates keys or modifies another resource. The Google Cloud standard SOFTWARE key version list price is around US$0.06 per month, plus US$0.03 per 10,000 crypto operations; even a disabled active version remains chargeable until destroyed. Creation is optional and requires separate explicit owner approval and current verified existing credits. [Official pricing](https://cloud.google.com/kms/pricing). [Google Cloud signing documentation](https://docs.cloud.google.com/kms/docs/create-validate-signatures).

After the owner approves one dedicated new key if needed, and verifies the current credit balance, run the `apply` command with `--credit-brl` and `--approve-dedicated-new-key`. If the exact eligible key already exists, the explicit new-key approval flag is not needed. No HSM instance or HSM-certified equivalent is proposed. The command accepts only its fixed synthetic challenge, not arbitrary input files, and verifies the returned signature. If a signing call is interrupted and its result is ambiguous, the tool refuses a blind retry.

Share only `public-native-kms-proof.json` and `public-native-kms-pin.json` from the private runtime when both exist. The proof is independently checkable against the separately retained pin. Cryptographic verification is not independent attestation that the key was hosted in a particular provider or HSM; the recorded metadata is operator-supplied. Do not publish private runtime directories, key files other than the explicit public PEM embedded in this proof, GCP identifiers or credentials.
