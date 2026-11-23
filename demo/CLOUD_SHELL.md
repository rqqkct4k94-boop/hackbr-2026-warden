# Owner-run Cloud Shell deployment — Warden P0

**Read this first.** Re-check the actual remaining balance in the Google Cloud free-trial banner before applying. Nothing in this handoff charges or modifies the project unless the owner explicitly runs `apply`. No new billing account, paid upgrade, new IAM role, secret manager or service account is created. No pre-existing production or development resource is modified. The deployment script deliberately excludes account and project identifiers from source; the owner supplies the exact approved project locally.

The workflow is original competition code. Cloud commands have been designed and tested offline, not yet executed against this account. A passing local test is **not** live-cloud evidence. If `prepare`, `plan` or `apply` reports a blocker, retain the output, do not bypass checks, and give the operator the exact error. A failed apply attempts to stop only verified matching lab VMs without deleting disks; the bootstrap guard also shuts down abandoned newly provisioned guests after 600 seconds. If partial resources remain, run `status` and ask for a scoped recovery instead of rerunning blindly.

## Run as the already authenticated project owner

Open the existing Google Cloud Console at [Cloud Shell](https://console.cloud.google.com/cloudshell/editor). Choose the intended owner-approved project. Use a new clone, not any proprietary repository.

```bash
export WARDEN_DEMO_PROJECT='<owner-approved-project-id>'
gcloud config set project "$WARDEN_DEMO_PROJECT"
git clone https://github.com/rqqkct4k94-boop/hackbr-2026-warden.git warden-hackbr-cloud
cd warden-hackbr-cloud/demo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-besu.txt
python cloudshell_owner.py plan
```

The read-only plan must report active billing, the selected project, zero `lab_name_collisions`, and Compute/IAP APIs present. It lists precisely what will be created. If an API or policy is missing, stop and resolve it with the owner; the script deliberately does not modify broad project security administration. The selected user must be permitted to use IAP SSH on the new VMs. This is normal owner authorization, not an added permanent credential grant. Cloud Shell must have a functioning Docker engine for the official Besu key generator. Nothing is provisioned before this local preparation succeeds.

```bash
python cloudshell_owner.py prepare --runtime "$PWD/../../warden-hackbr-p0-private"
```

The new private runtime contains **synthetic private keys, custody shares and transfer bundles**. Do not paste or upload it to chat, GitHub or any external location. It is owned by the Cloud Shell user. The prepared files are based on Besu's official `hyperledger/besu:26.11.1` release (released 18 November 2026; [release](https://github.com/besu-eth/besu/releases/tag/26.11.1), [official Docker tags](https://hub.docker.com/r/hyperledger/besu/tags)). The script does not use a mutable `latest` tag.

When the owner has confirmed that the trial credit is still available (**replace `350` with the actual live balance, at least R$350**), execute:

```bash
python cloudshell_owner.py apply --runtime "$PWD/../../warden-hackbr-p0-private" --credit-brl 350
```

`apply` creates one private custom VPC and subnet with no peering, four separate 4 GiB `e2-medium` validators and one 2 GiB `e2-small` control/HTTPS VM. Every guest has a retained 20 GiB persistent boot disk, no attached service account or OAuth scopes, deletion protection, and **no individual public address**. Only IAP SSH is allowed from Google's IAP range; validator P2P is internal and RPC plus lease traffic is allowed only from the control host. A dedicated Cloud Router and one-address Public NAT provide outbound package/image downloads, not public service ingress. No public CA claim or external blockchain.

If a prior apply was interrupted specifically during network/subnet creation, before any VM, disk or firewall was created, the narrow `resume-network` recovery command validates the exact custom unpeered VPC and its optional matching subnet, then continues without recreating either or regenerating keys. It refuses unexpected resources, existing lab disks, VMs or firewall rules. Never use this recovery path after a later-stage failure. Progress messages appear before each cloud operation; wait for the operation to finish rather than interrupting.

```bash
python cloudshell_owner.py resume-network --runtime "$PWD/../../warden-hackbr-p0-private" --credit-brl 350
```

If a prior `apply` failed specifically during VM creation with `IN_USE_ADDRESSES` quota exceeded, **before application configuration**, `resume-quota` preserves the verified lab VPC/subnet/firewalls and all existing matching VMs/disks. It stops only scoped VMs, removes their original ephemeral public-IP configurations, validates/creates one shared NAT address and router, then creates only missing private VMs and resumes configuration. It refuses unrelated resources, orphaned disks, unexpected firewall/VM shapes or an existing successful acceptance. No quota increase is requested and no disk is deleted. Use this path only for that allocation-stage failure.

```bash
python cloudshell_owner.py resume-quota --runtime "$PWD/../../warden-hackbr-p0-private" --credit-brl 350
```

At the verified US-central list rates, compute is approximately US$0.151/hour while all five are running (about US$25.33 for seven days continuous use). Public NAT adds US$0.007/hour with five assigned VMs plus US$0.005/hour for one NAT public address, and US$0.045/GiB processed. Disk, internet egress and exchange rates are extra. Stopped persistent disk costs and the reserved egress address may continue. The owner must keep the verified credit ceiling; there is no billing-account upgrade. [Google pricing](https://cloud.google.com/products/compute/pricing/general-purpose). [Cloud NAT pricing](https://cloud.google.com/nat/pricing). [IAP SSH](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding). [Guest shutdown](https://docs.cloud.google.com/compute/docs/instances/stop-start-instance).

## Owner demo and evidence

If and only if apply succeeds, expect a JSON report with a real four-validator block, two independently verified TLS fingerprints, public audit verification, and a matching audit anchor receipt on all four validators. The initial PKI ceremony runs in the isolated Cloud Shell process with separate signing processes; distinct custody packages are also placed in three dedicated validator hosts and not copied to the control runtime. This is not independent human custody or a certified HSM. The independent hosts must later exercise the real approval workflow before making that stronger claim. The owner retains control of all VMs and the original synthetic ceremony staging directory.

For administration and viewing, run a standard IAP tunnel in Cloud Shell and use **Web Preview → Preview on port 8080**. The dashboard itself stays loopback-only on the control VM. This is owner-only, separate from the tested [public judge verifier](https://hackbr-2026-warden-p0.royalcrafter.workers.dev/).

```bash
gcloud compute ssh hackbr-warden-p0-control --project="$WARDEN_DEMO_PROJECT" --zone=us-central1-a --tunnel-through-iap -- -N -L 8080:127.0.0.1:8080
```

Close the tunnel when finished. A normal browser page visit and the explicit TLS verify button count toward genuine activity. Health checks and background validator messages do not extend the idle deadline. The control process sends each validator its own authenticated **deadline**, not a fresh ten-minute lease; the dedicated guest-level receiver expires and shuts down without any broad cloud IAM service account. An in-flight user operation temporarily retains all nodes. The control guest and validators stop themselves, retaining state. The owner can start the exact validated group through Cloud Shell.

Run the real lifecycle acceptance gate with the dashboard closed and no human activity during the wait. The 600-second guest policy is unchanged; allow up to 900 seconds for the provider to report all five guests `TERMINATED`, plus restart and acceptance time. The gate records observed power-state transitions separately from the configured guest idle deadline, checks disk identities, starts only the matching group, and confirms the same audit head, two TLS fingerprints and anchor receipt. A provider-state timestamp is not the exact guest trigger time.

```bash
python cloudshell_owner.py idle-gate --runtime "$PWD/../../warden-hackbr-p0-private"
```

For routine bounded operations:

```bash
python cloudshell_owner.py status
python cloudshell_owner.py start
python cloudshell_owner.py verify
python cloudshell_owner.py stop
```

`start` and `stop` refuse any instance with unexpected labels, network, machine type, tags, disk policy or attached service account. On stopping, disks are retained. No final deletion is performed. Do not start all five merely to perform periodic health checks. The public judge verifier is hosted separately and needs no running GCP VM; this protected IAP interface is not its public link.

After the lifecycle gate finishes (never during its ten-minute idle interval), the owner can run a separate read-only three-guest custodian presence check while the lab is running:

```bash
python custody_presence.py --runtime ~/warden-hackbr-p0-private
```

It challenges the three actual dedicated custodian guest accounts with one short-lived, domain-separated random nonce, verifies their distinct Ed25519 signatures against the original independently pinned manifest, and writes a public `custody-presence-*.json` report. It never exports private signing keys or custody shares, never renews/revokes a certificate, and cannot be used as a certificate approval. It proves deployed signer key possession, not independent human control or an actual three-guest issuance. The latter remains a distinct gate.

While the group is running, export the real cloud ceremony's **public-only** audit evidence and independent pins (separate from the local sample included with the judge portal):

```bash
python cloudshell_owner.py export-public --runtime ~/warden-hackbr-p0-private
```

This verifies the proof against the original owner ceremony manifest and current matching four-receipt audit anchor, refuses recognized secret fields, and creates only `cloud-public-proof.json` and `cloud-public-pins.json` without overwriting. Those two files may be loaded into the judge verifier. Never transfer the private runtime directory, custody packages, or staging archives. The browser independently verifies the certificate/approval evidence, not private-ledger transaction inclusion.

Share **only** these public/synthetic acceptance summaries with Codex—never the parent runtime, bundles, private keys or custody shares:

```bash
cat "$PWD/../../warden-hackbr-p0-private/live-acceptance.json"
cat "$PWD/../../warden-hackbr-p0-private/idle-acceptance.json"
```

If either file does not exist, the corresponding gate is not proven. The script deliberately refuses a duplicate ambiguous anchor transaction if its intent already exists. Report the failure and preserve its evidence for review.
