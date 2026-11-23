# Meu sandbox — optional, owner-side, read-only

The recommended path for Hack Brasil judges is the public **FAROL-26** synthetic laboratory. No account or credentials are required. The console also offers a fictional metadata example so a judge can explore the asset inventory without cloud access.

If an evaluator wants to use **their own Google Cloud test account**, the Warden console only accepts a manually selected, redacted JSON manifest from the owner's own authenticated environment. It never receives an API key, cloud token, password, service-account credential, project ID, network address, object/file contents, or private key. File processing takes place in the browser. It does not connect to or make changes in the user's account.

The separate `judge_sandbox.py` utility uses only explicit read-only description requests for assets named individually by the owner. It is intentionally not an automatic discovery or provisioning tool. Run it only on selected disposable synthetic assets in a project you control. It requires an explicit `--synthetic-only` confirmation, validates the active project, refuses unrecognized resource names, limits the manifest to 12 assets and writes to a new local file. Consult `python judge_sandbox.py --help` for the local interface. No third-party service or account needs to be authorized for this demonstration.

After reviewing the manifest, open the public console, choose **Meu sandbox**, and select the JSON. The dashboard labels the result as operator-supplied metadata, not a verified live connection. Selecting an example fixture instead labels the data as fictitious. The other views continue to show the Warden synthetic laboratory.

For a synthetic P-256 test signing key selected by its alias, the console offers an optional short-lived public challenge. The judge can independently produce a signature in their own controlled environment and choose **only** the public SPKI and signature files. The browser verifies possession of the corresponding key; it never retrieves or imports private key material and the proof is not provider attestation, HSM certification, or a guarantee of hardware origin. The live provider integration gate remains separate.

Do not use production assets or upload secrets. AWS/Azure provider integrations remain planned, not demonstrated. Public PKI and the recorded GCP acceptance have separate evidence scopes. No claim of HSM equivalence is made.
