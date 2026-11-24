"""Owner-run native PQC check for two explicitly approved synthetic SOFTWARE KMS keys.

Fixed public challenge and disposable synthetic document only. No private-key
export, key import, IAM, billing change, API enablement, production or QPU access.
The report proves a public signature; KEM acceptance is operator-reported, not
provider attestation. No shared secret or encrypted data leaves the private run.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import secrets
import tempfile
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import cloudshell_owner as lab
from lifecycle_acceptance import check_credit, verify_runtime
from native_signing_gate import audit_head, canonical

RING = 'hackbr-warden-p0-pqc'
LOCATION = lab.REGION
LABELS = {'hackbr': 'warden-p0', 'scope': 'synthetic'}
SCHEMA = 'warden-native-pqc-v1'
PROOF = 'public-native-pqc-proof.json'
PIN = 'public-native-pqc-pin.json'
SPECS = {
    'synthetic-ml-dsa-65': ('ASYMMETRIC_SIGN', 'PQ_SIGN_ML_DSA_65', 'asymmetric-signing', 'pq-sign-ml-dsa-65', 1952),
    'synthetic-ml-kem-768': ('KEY_ENCAPSULATION', 'ML_KEM_768', 'key-encapsulation', 'ml-kem-768', 1184),
}
SIGN, KEM = tuple(SPECS)
HEX = re.compile(r'[0-9a-f]{64}')


def options(name):
    if name not in SPECS: raise ValueError('Only the two exact lab keys are allowed')
    return (f'--location={LOCATION}', f'--keyring={RING}', f'--key={name}')


def ring_path(project): return f'projects/{project}/locations/{LOCATION}/keyRings/{RING}'


def key_path(project, name): return f'{ring_path(project)}/cryptoKeys/{name}'


def sha(raw): return hashlib.sha256(raw).hexdigest()


def b64(raw): return base64.b64encode(raw).decode('ascii')


def decode(value, expected):
    if not isinstance(value, str) or len(value) > 20000: raise ValueError('Invalid public byte field')
    data = base64.b64decode(value, validate=True)
    if len(data) != expected or b64(data) != value: raise ValueError('Incorrect public byte length or encoding')
    return data


def normalize_signature(raw):
    """Accept the fixed ML-DSA signature size in binary or canonical Base64 form."""
    if len(raw)==3309:return b64(raw)
    try:value=raw.decode('ascii').strip();decoded=decode(value,3309)
    except (ValueError,UnicodeDecodeError) as exc:raise ValueError('Unrecognized ML-DSA signature encoding') from exc
    return b64(decoded)


def validate_key(name, metadata, project):
    purpose, algorithm, _, _, _ = SPECS[name]
    if (metadata.get('name') != key_path(project, name) or metadata.get('purpose') != purpose
            or metadata.get('labels') != LABELS or metadata.get('importOnly', False) is not False
            or metadata.get('rotationPeriod') or metadata.get('nextRotationTime')
            or metadata.get('versionTemplate', {}).get('algorithm') != algorithm
            or metadata.get('versionTemplate', {}).get('protectionLevel') != 'SOFTWARE'):
        raise RuntimeError('Existing key differs from the exact approved PQC lab scope')


def validate_version(name, version, project, pending_ok=False):
    _, algorithm, _, _, _ = SPECS[name]
    allowed_states = ('PENDING_GENERATION', 'ENABLED') if pending_ok else ('ENABLED',)
    if (version.get('name') != key_path(project, name)+'/cryptoKeyVersions/1'
            or version.get('state') not in allowed_states or version.get('algorithm') != algorithm
            or version.get('protectionLevel') != 'SOFTWARE' or version.get('importJob')
            or version.get('importTime') or version.get('reimportEligible')
            or (version.get('state') == 'ENABLED' and not version.get('generateTime'))):
        raise RuntimeError('Expected one provider-generated SOFTWARE key version; never imported')
    return version.get('state')


def inventory():
    project=lab.owner_project()
    services=lab.gcjson('services','list','--enabled') or []
    if not any(r.get('config',{}).get('name')=='cloudkms.googleapis.com' for r in services):
        raise RuntimeError('Cloud KMS is disabled; do not enable it automatically')
    rings=lab.gcjson('kms','keyrings','list',f'--location={LOCATION}') or []
    matching=[r for r in rings if r.get('name')==ring_path(project)]
    if len(matching)>1: raise RuntimeError('Duplicate ring identity')
    if not matching:return {'ring_exists':False,'keys':{}}
    keys=lab.gcjson('kms','keys','list',f'--keyring={RING}',f'--location={LOCATION}') or []
    allowed={key_path(project,n):n for n in SPECS}
    if len(keys)>2 or len({k.get('name') for k in keys})!=len(keys) or any(k.get('name') not in allowed for k in keys):
        raise RuntimeError('Unexpected resources in dedicated PQC ring; stop without changes')
    states={}
    for item in keys:
        name=allowed[item['name']]
        meta=lab.gcjson('kms','keys','describe',name,f'--keyring={RING}',f'--location={LOCATION}')
        validate_key(name,meta,project)
        versions=lab.gcjson('kms','keys','versions','list',*options(name)) or []
        if len(versions)!=1: raise RuntimeError('Expected exactly version 1; do not create or rotate another version')
        states[name]=validate_version(name,versions[0],project,True)
    return {'ring_exists':True,'keys':states}


def preflight(runtime):
    root=verify_runtime(runtime);inv=lab.inventory()
    if not inv['billing_enabled'] or not inv['project_active']:raise RuntimeError('Existing project and billing must remain active')
    checked=inventory()
    return root,checked


def plan(runtime):
    _,state=preflight(runtime)
    return {**state,'scope':'two named provider-generated SOFTWARE key versions, synthetic only',
            'algorithms':['PQ_SIGN_ML_DSA_65','ML_KEM_768'],'hybrid_xwing_verified':False,
            'listed_usd_per_month_two_active_versions':0.12,'listed_usd_per_10000_operations':0.03,
            'private_key_transfer':False,'iam_changes':False,'billing_changes':False}


def ensure_keys(approve):
    state=inventory()
    if len(state['keys'])!=2 and not approve:raise RuntimeError('Creating the dedicated keys requires explicit approval')
    if not state['ring_exists']:
        lab.gc('kms','keyrings','create',RING,f'--location={LOCATION}')
        state=inventory()
        if not state['ring_exists']:raise RuntimeError('Created ring not visible yet; review inventory before retry')
    for name,(_,_,purpose,algorithm,_) in SPECS.items():
        if name not in state['keys']:
            lab.gc('kms','keys','create',name,f'--keyring={RING}',f'--location={LOCATION}',
                   f'--purpose={purpose}',f'--default-algorithm={algorithm}','--protection-level=software',
                   '--labels=hackbr=warden-p0,scope=synthetic')
            state=inventory()
            if name not in state['keys']:raise RuntimeError('Created key not yet visible; stop and review inventory')
    for _ in range(12):
        state=inventory()
        if state['keys']=={SIGN:'ENABLED',KEM:'ENABLED'}:return
        time.sleep(5)
    raise RuntimeError('Both exact keys are not enabled; do not rotate or create more')


def derive(secret,salt,context):
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=context).derive(secret)


def kem_trial(public_raw,decapsulate,head):
    pub=mlkem.MLKEM768PublicKey.from_public_bytes(public_raw)
    shared,ciphertext=pub.encapsulate()
    observed=decapsulate(ciphertext)
    if len(shared)!=32 or len(observed)!=32 or len(ciphertext)!=1088 or not secrets.compare_digest(shared,observed):
        raise RuntimeError('Native decapsulation did not reproduce the shared secret; no acceptance')
    salt,iv=secrets.token_bytes(32),secrets.token_bytes(12)
    context=b'warden-native-pqc-synthetic-v1:'+head.encode('ascii')
    plaintext=b'FAROL-26 synthetic document only'
    encrypted=AESGCM(derive(shared,salt,context)).encrypt(iv,plaintext,context)
    decryption=AESGCM(derive(observed,salt,context))
    if decryption.decrypt(iv,encrypted,context)!=plaintext:raise RuntimeError('Authenticated roundtrip failed')
    try:decryption.decrypt(iv,bytes([encrypted[0]^1])+encrypted[1:],context)
    except InvalidTag:pass
    else:raise RuntimeError('Tampered data was not rejected')
    return {'algorithm':'ML_KEM_768','aead':'AES-256-GCM','shared_key_match':True,'roundtrip':True,
            'tampered_ciphertext_rejected':True,'encapsulation_bytes':1088,'hybrid_xwing_verified':False}


def metadata():
    return {'provider':'google-cloud-kms','protection':'SOFTWARE','origin':'provider-generated',
            'versions':['1','1'],'source':'owner-run-provider-metadata','provider_attestation_verified':False,
            'warden_three_of_three_enforced_by_provider':False,'quantum_gate_verified':False}


def verify_proof(proof,pin):
    if not isinstance(proof,dict) or set(proof)!={'schema','scope','message','sign_public_raw_b64','kem_public_raw_b64','signature_b64','provider_report'} or proof['schema']!=SCHEMA or proof['scope']!='synthetic-demo-only' or proof['provider_report']!=metadata():raise ValueError('Unexpected report')
    message=proof['message']
    if not isinstance(message,dict) or set(message)!={'schema','scope','purpose','nonce','audit_head','kem_public_sha256','kem_trial'} or message['schema']!=SCHEMA or message['scope']!='synthetic-demo-only' or message['purpose']!='native-pqc-synthetic-acceptance':raise ValueError('Unexpected challenge')
    if not all(isinstance(message[k],str) and HEX.fullmatch(message[k]) for k in ('nonce','audit_head','kem_public_sha256')):raise ValueError('Malformed challenge binding')
    sign_raw=decode(proof['sign_public_raw_b64'],1952);kem_raw=decode(proof['kem_public_raw_b64'],1184)
    if message['kem_public_sha256']!=sha(kem_raw) or pin!={'schema':SCHEMA,'audit_head':message['audit_head'],'sign_public_sha256':sha(sign_raw),'kem_public_sha256':sha(kem_raw)}:raise ValueError('Public pin mismatch')
    expected={'algorithm':'ML_KEM_768','aead':'AES-256-GCM','shared_key_match':True,'roundtrip':True,'tampered_ciphertext_rejected':True,'encapsulation_bytes':1088,'hybrid_xwing_verified':False}
    if message['kem_trial']!=expected:raise ValueError('KEM evidence is incomplete or overclaimed')
    mldsa.MLDSA65PublicKey.from_public_bytes(sign_raw).verify(decode(proof['signature_b64'],3309),canonical(message))
    mlkem.MLKEM768PublicKey.from_public_bytes(kem_raw)
    return {'signature_verified':True,'kem_operator_report_consistent':True,'provider_attestation_verified':False,
            'hybrid_xwing_verified':False,'quantum_gate_verified':False,'audit_head':message['audit_head']}


def save_new(path,data):
    if path.exists():raise RuntimeError('Existing proof file; no overwrite')
    with path.open('x',encoding='utf8') as stream:json.dump(data,stream,indent=2)


def choose_attempt_marker(root,state,recovery):
    original=root/'native-pqc-provider-request-started'
    retry=root/'native-pqc-signature-format-recovery-started'
    if recovery:
        if not original.is_file() or original.read_text(encoding='utf8')!='One fixed synthetic native PQC acceptance started\n':
            raise RuntimeError('Recovery requires the exact original attempt marker')
        if retry.exists():raise RuntimeError('One recovery already started; review evidence, no blind retry')
        if not state['ring_exists'] or state['keys']!={SIGN:'ENABLED',KEM:'ENABLED'}:
            raise RuntimeError('Recovery can reuse only the two already-enabled dedicated versions; no creation')
        return retry
    if original.exists() or retry.exists():raise RuntimeError('Previous operation outcome ambiguous; review owner evidence rather than retry blindly')
    return original


def apply(runtime,credit,approve,recovery=False):
    root,state=preflight(runtime);check_credit(credit)
    out,pinfile=root/PROOF,root/PIN
    if out.exists() or pinfile.exists():
        if not out.exists() or not pinfile.exists():raise RuntimeError('Partial public report; owner review required')
        return {**verify_proof(json.loads(out.read_text()),json.loads(pinfile.read_text())),'reused_existing_public_proof':True}
    marker=choose_attempt_marker(root,state,recovery)
    # Check actual local crypto support before any cloud resource creation.
    mldsa.MLDSA65PrivateKey.generate();mlkem.MLKEM768PrivateKey.generate()
    # Confirm installed CLI supports the native KEM command before creating a key.
    lab.gc('kms','decapsulate','--help')
    head=audit_head(root)
    if not recovery:ensure_keys(approve)
    elif inventory()['keys']!={SIGN:'ENABLED',KEM:'ENABLED'}:raise RuntimeError('Recovery inventory changed; no operation')
    with tempfile.TemporaryDirectory(prefix='native-pqc-',dir=root) as tmp:
        path=Path(tmp);signfile,kemfile=path/'sign.pub',path/'kem.pub'
        for name,file in ((SIGN,signfile),(KEM,kemfile)):
            lab.gc('kms','keys','versions','get-public-key','1',*options(name),'--public-key-format=nist-pqc',f'--output-file={file}')
        sign_raw,kem_raw=signfile.read_bytes(),kemfile.read_bytes()
        if len(sign_raw)!=1952 or len(kem_raw)!=1184:raise RuntimeError('Provider did not return expected raw NIST public key bytes')
        mldsa.MLDSA65PublicKey.from_public_bytes(sign_raw);mlkem.MLKEM768PublicKey.from_public_bytes(kem_raw)
        with marker.open('x',encoding='utf8') as stream:stream.write('One fixed synthetic native PQC '+('signature encoding recovery' if recovery else 'acceptance')+' started\n')
        def decap(ciphertext):
            ct,secretfile=path/'kem.ct',path/'kem.private-temporary'
            ct.write_bytes(ciphertext)
            lab.gc('kms','decapsulate','--version=1',*options(KEM),f'--ciphertext-file={ct}',f'--shared-secret-file={secretfile}')
            return secretfile.read_bytes()
        trial=kem_trial(kem_raw,decap,head)
        message={'schema':SCHEMA,'scope':'synthetic-demo-only','purpose':'native-pqc-synthetic-acceptance','nonce':secrets.token_hex(32),'audit_head':head,'kem_public_sha256':sha(kem_raw),'kem_trial':trial}
        challenge,sig=path/'challenge.json',path/'signature.b64';challenge.write_bytes(canonical(message))
        # Pure ML-DSA signs raw data; do not pass a digest algorithm or disable integrity checking.
        lab.gc('kms','asymmetric-sign','--version=1',*options(SIGN),f'--input-file={challenge}',f'--signature-file={sig}')
        # Preserve only public signing artifacts after a successful provider response,
        # so a later local decode/validation failure does not require another cloud call.
        public_stage=root/('native-pqc-recovery-public-stage' if recovery else 'native-pqc-public-stage')
        public_stage.mkdir(mode=0o700,exist_ok=False)
        for name,data in (('challenge.json',canonical(message)),('sign.pub',sign_raw),('kem.pub',kem_raw),('signature.response',sig.read_bytes())):
            with (public_stage/name).open('xb') as stream:stream.write(data)
        signature=normalize_signature(sig.read_bytes())
        proof={'schema':SCHEMA,'scope':'synthetic-demo-only','message':message,'sign_public_raw_b64':b64(sign_raw),'kem_public_raw_b64':b64(kem_raw),'signature_b64':signature,'provider_report':metadata()}
        pin={'schema':SCHEMA,'audit_head':head,'sign_public_sha256':sha(sign_raw),'kem_public_sha256':sha(kem_raw)}
        result=verify_proof(proof,pin);save_new(out,proof);save_new(pinfile,pin)
    return {**result,'reused_existing_keys_only':recovery,'public_files':[PROOF,PIN]}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=['plan','apply','recover-signature-format','verify']);parser.add_argument('--runtime');parser.add_argument('--proof');parser.add_argument('--pin');parser.add_argument('--credit-brl',type=float);parser.add_argument('--approve-two-dedicated-new-keys',action='store_true');args=parser.parse_args()
    if args.command=='verify':
        if not args.proof or not args.pin:parser.error('Verify requires the two public JSON files')
        paths=[Path(args.proof),Path(args.pin)]
        if any(p.stat().st_size>65536 for p in paths):raise ValueError('Public JSON exceeds limit')
        result=verify_proof(*(json.loads(p.read_text(encoding='utf8')) for p in paths))
    elif not args.runtime:parser.error('Plan or apply requires the existing private runtime')
    elif args.command=='plan':result=plan(args.runtime)
    else:
        if args.credit_brl is None:parser.error('Apply requires current owner-verified credit')
        recovery=args.command=='recover-signature-format'
        if recovery and args.approve_two_dedicated_new_keys:parser.error('Recovery never creates keys; do not pass creation approval')
        result=apply(args.runtime,args.credit_brl,args.approve_two_dedicated_new_keys,recovery)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
