"""One owner-approved Cloud KMS SOFTWARE signing version, dedicated synthetic proof.

No private key export/import, arbitrary payload signing, new IAM, billing changes,
API enablement or changes to unrelated resources. The public proof verifies a
signature; operator-reported KMS provenance is not hardware attestation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import cloudshell_owner as lab
from lifecycle_acceptance import check_credit, evidence_summary, verify_runtime

RING = 'hackbr-warden-p0-native'
KEY = 'synthetic-native-signing'
LOCATION = lab.REGION
ALGORITHM = 'EC_SIGN_P256_SHA256'
LABELS = {'hackbr': 'warden-p0', 'scope': 'synthetic'}
SCHEMA = 'warden-native-kms-signing-v1'
PROOF = 'public-native-kms-proof.json'
PIN = 'public-native-kms-pin.json'


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def key_path(project):
    return f'projects/{project}/locations/{LOCATION}/keyRings/{RING}/cryptoKeys/{KEY}'


def validate_key(metadata, project):
    if (metadata.get('name') != key_path(project) or metadata.get('purpose') != 'ASYMMETRIC_SIGN'
            or metadata.get('labels') != LABELS or metadata.get('importOnly', False) is not False
            or metadata.get('rotationPeriod') or metadata.get('nextRotationTime')
            or metadata.get('versionTemplate', {}).get('algorithm') != ALGORITHM
            or metadata.get('versionTemplate', {}).get('protectionLevel') != 'SOFTWARE'):
        raise RuntimeError('Existing KMS key differs from exact dedicated synthetic signing scope')


def validate_version(version, project):
    if (version.get('name') != key_path(project) + '/cryptoKeyVersions/1'
            or version.get('state') != 'ENABLED' or version.get('algorithm') != ALGORITHM
            or version.get('protectionLevel') != 'SOFTWARE' or not version.get('generateTime')
            or version.get('importJob') or version.get('importTime') or version.get('reimportEligible')):
        raise RuntimeError('Expected a single enabled provider-generated SOFTWARE key version, never imported')
    return {'provider': 'google-cloud-kms', 'algorithm': ALGORITHM, 'protection': 'SOFTWARE',
            'version': '1', 'state': 'ENABLED', 'origin': 'provider-generated',
            'source': 'owner-run-provider-metadata', 'provider_attestation_verified': False}


def options():
    return (f'--location={LOCATION}', f'--keyring={RING}')


def key_inventory():
    project = lab.owner_project()
    services = lab.gcjson('services', 'list', '--enabled') or []
    if not any(row.get('config', {}).get('name') == 'cloudkms.googleapis.com' for row in services):
        raise RuntimeError('Cloud KMS API is not enabled. Owner review required; no automatic API enablement.')
    rings = lab.gcjson('kms', 'keyrings', 'list', f'--location={LOCATION}') or []
    ring_path = f'projects/{project}/locations/{LOCATION}/keyRings/{RING}'
    matches = [r for r in rings if r.get('name') == ring_path]
    if len(matches) > 1: raise RuntimeError('Unexpected duplicate ring identity')
    if not matches: return {'ring_exists': False, 'key_exists': False}
    keys = lab.gcjson('kms', 'keys', 'list', *options()) or []
    if any(k.get('name') != key_path(project) for k in keys) or len(keys) > 1:
        raise RuntimeError('The dedicated ring contains unrelated or unexpected keys; refuse to operate')
    if not keys: return {'ring_exists': True, 'key_exists': False}
    metadata = lab.gcjson('kms', 'keys', 'describe', KEY, *options())
    validate_key(metadata, project)
    versions = lab.gcjson('kms', 'keys', 'versions', 'list', f'--key={KEY}', *options()) or []
    if len(versions) != 1 or versions[0].get('name') != key_path(project) + '/cryptoKeyVersions/1':
        raise RuntimeError('Unexpected number or identity of KMS key versions; refuse rotation or creation')
    return {'ring_exists': True, 'key_exists': True}


def plan(runtime):
    verify_runtime(runtime)
    inv = lab.inventory()
    if not inv['billing_enabled'] or not inv['project_active']:
        raise RuntimeError('Existing project and billing must remain active')
    current = key_inventory()
    return {**current, 'scope': 'one fixed synthetic SOFTWARE asymmetric signing key version',
            'location': LOCATION, 'key_ring': RING, 'key': KEY, 'algorithm': ALGORITHM,
            'new_iam': False, 'billing_changes': False, 'private_key_export_or_import': False,
            'listed_usd_per_month_one_active_version': 0.06,
            'listed_usd_per_10000_operations': 0.03,
            'ongoing_charge_note': 'An active version is charged until destroyed, including disabled versions. Owner must manage retirement separately.'}


def ensure_key(approve_new):
    checked = key_inventory()
    if not checked['key_exists'] and not approve_new:
        raise RuntimeError('A new dedicated key requires explicit owner approval after live-credit verification')
    if not checked['ring_exists']:
        lab.gc('kms', 'keyrings', 'create', RING, f'--location={LOCATION}')
        checked = key_inventory()
    if not checked['key_exists']:
        lab.gc('kms', 'keys', 'create', KEY, *options(), '--purpose=asymmetric-signing',
               '--default-algorithm=ec-sign-p256-sha256', '--protection-level=software',
               '--labels=hackbr=warden-p0,scope=synthetic')
        # Creation may be asynchronous; do not create another version on a failure.
    for _ in range(12):
        try:
            if key_inventory()['key_exists']:
                version = lab.gcjson('kms', 'keys', 'versions', 'describe', '1', f'--key={KEY}', *options())
                if version.get('state') == 'PENDING_GENERATION':
                    time.sleep(5); continue
                return validate_version(version, lab.owner_project())
        except RuntimeError as exc:
            # Never bypass an unexpected resource, label, algorithm, auth or API failure.
            raise RuntimeError('KMS key metadata validation failed. Do not recreate or retry blindly.') from exc
        time.sleep(5)
    raise RuntimeError('Dedicated version not ready; review inventory and resume without creating another key')


def audit_head(runtime):
    lifecycle = runtime / 'public-lifecycle-report.json'
    if lifecycle.exists():
        report = json.loads(lifecycle.read_text(encoding='utf8'))
        if (report.get('schema') != 'warden-lifecycle-acceptance-v1' or report.get('verified') is not True
                or report.get('restart_verified') is not True): raise ValueError('Invalid lifecycle acceptance')
        head = report.get('audit_head', '')
    else:
        head = evidence_summary(json.loads((runtime / 'live-acceptance.json').read_text(encoding='utf8')))['audit_head']
    if not re.fullmatch(r'[0-9a-f]{64}', head): raise ValueError('Invalid public audit head')
    return head


def public_fingerprint(pem):
    if not isinstance(pem, str) or 'PRIVATE KEY' in pem or not pem.startswith('-----BEGIN PUBLIC KEY-----'):
        raise ValueError('Only public SPKI PEM is accepted')
    public = serialization.load_pem_public_key(pem.encode('ascii'))
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
        raise ValueError('Expected P-256 public key')
    spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return public, hashlib.sha256(spki).hexdigest()


def verify_proof(proof, pin):
    if set(proof) != {'schema', 'scope', 'message', 'public_key_pem', 'signature_der_b64', 'provider_report'} or proof['schema'] != SCHEMA or proof['scope'] != 'synthetic-demo-only':
        raise ValueError('Unexpected proof format')
    message = proof['message']
    if (set(message) != {'schema', 'scope', 'nonce', 'audit_head', 'purpose'} or message['schema'] != SCHEMA
            or message['scope'] != 'synthetic-demo-only' or message['purpose'] != 'demonstrate-provider-native-signing'
            or not re.fullmatch(r'[a-f0-9]{64}', message['nonce']) or not re.fullmatch(r'[a-f0-9]{64}', message['audit_head'])):
        raise ValueError('Only this bounded public synthetic challenge is accepted')
    public, fp = public_fingerprint(proof['public_key_pem'])
    if pin != {'schema': SCHEMA, 'public_key_sha256': fp, 'audit_head': message['audit_head']}:
        raise ValueError('Public key and audit head must match the independently retained pin')
    metadata = {'provider': 'google-cloud-kms', 'algorithm': ALGORITHM, 'protection': 'SOFTWARE',
                'version': '1', 'state': 'ENABLED', 'origin': 'provider-generated',
                'source': 'owner-run-provider-metadata', 'provider_attestation_verified': False}
    if proof['provider_report'] != metadata: raise ValueError('Unexpected or inflated provider claim')
    signature = base64.b64decode(proof['signature_der_b64'], validate=True)
    public.verify(signature, canonical(message), ec.ECDSA(hashes.SHA256()))
    return {'signature_verified': True, 'public_key_sha256': fp, 'provider_attestation_verified': False,
            'audit_head': message['audit_head']}


def apply(runtime, credit_brl, approve_new):
    root = verify_runtime(runtime)
    check_credit(credit_brl)
    out, pinfile = root / PROOF, root / PIN
    if out.exists() and pinfile.exists():
        return {**verify_proof(json.loads(out.read_text()), json.loads(pinfile.read_text())), 'reused_existing_public_proof': True}
    head = audit_head(root)
    metadata = ensure_key(approve_new)
    stage = root / 'native-signing-stage'
    stage.mkdir(mode=0o700, exist_ok=True)
    msg, keyfile, sigfile, marker = (stage / n for n in ('challenge.json', 'public.pem', 'signature.b64', 'sign-request-started'))
    if not msg.exists():
        challenge = {'schema': SCHEMA, 'scope': 'synthetic-demo-only', 'nonce': secrets.token_hex(32),
                     'audit_head': head, 'purpose': 'demonstrate-provider-native-signing'}
        with msg.open('xb') as stream: stream.write(canonical(challenge))
    challenge = json.loads(msg.read_text(encoding='utf8'))
    if canonical(challenge) != msg.read_bytes() or challenge.get('audit_head') != head:
        raise RuntimeError('Stored challenge is inconsistent; do not send a signing request')
    # Validate the exact challenge envelope before it can ever reach the signing command.
    if (set(challenge) != {'schema', 'scope', 'nonce', 'audit_head', 'purpose'} or challenge['schema'] != SCHEMA
            or challenge['scope'] != 'synthetic-demo-only' or challenge['purpose'] != 'demonstrate-provider-native-signing'
            or not re.fullmatch(r'[0-9a-f]{64}', challenge['nonce'])):
        raise ValueError('Challenge not within the fixed synthetic signing scope')
    if not keyfile.exists():
        lab.gc('kms', 'keys', 'versions', 'get-public-key', '1', f'--key={KEY}', *options(),
               '--public-key-format=pem', f'--output-file={keyfile}')
    else:
        # A resumable stage must still match the actual provider key, rather than only its local cache.
        current = stage / ('provider-public-' + secrets.token_hex(8) + '.pem')
        lab.gc('kms', 'keys', 'versions', 'get-public-key', '1', f'--key={KEY}', *options(),
               '--public-key-format=pem', f'--output-file={current}')
        if public_fingerprint(current.read_text(encoding='ascii'))[1] != public_fingerprint(keyfile.read_text(encoding='ascii'))[1]:
            raise RuntimeError('Cached and current provider public keys differ; no signature requested')
    pem = keyfile.read_text(encoding='ascii')
    _, fingerprint = public_fingerprint(pem)
    if sigfile.exists() and not marker.exists():
        raise RuntimeError('Unexpected pre-existing signature without a recorded provider request; refuse proof')
    if not sigfile.exists():
        # A disconnected signing call may have completed at the provider. Refuse a blind second call.
        if marker.exists(): raise RuntimeError('Prior signature request outcome ambiguous; owner must review, not retry blindly')
        with marker.open('x', encoding='utf8') as stream: stream.write('One fixed synthetic challenge requested\n')
        lab.gc('kms', 'asymmetric-sign', '--version=1', f'--key={KEY}', *options(), '--digest-algorithm=sha256',
               f'--input-file={msg}', f'--signature-file={sigfile}')
    signature = sigfile.read_text(encoding='ascii').strip()
    proof = {'schema': SCHEMA, 'scope': 'synthetic-demo-only', 'message': challenge,
             'public_key_pem': pem, 'signature_der_b64': signature, 'provider_report': metadata}
    pin = {'schema': SCHEMA, 'public_key_sha256': fingerprint, 'audit_head': head}
    result = verify_proof(proof, pin)
    for path, data in ((out, proof), (pinfile, pin)):
        if path.exists():
            if json.loads(path.read_text()) != data: raise RuntimeError('Existing public record differs; no overwrite')
        else:
            with path.open('x', encoding='utf8') as stream: json.dump(data, stream, indent=2)
    return {**result, 'public_files': [PROOF, PIN]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['plan', 'apply'])
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--credit-brl', type=float)
    parser.add_argument('--approve-dedicated-new-key', action='store_true')
    args = parser.parse_args()
    if args.command == 'plan': result = plan(args.runtime)
    else:
        if args.credit_brl is None: parser.error('Apply requires current owner-verified trial credit')
        result = apply(args.runtime, args.credit_brl, args.approve_dedicated_new_key)
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
