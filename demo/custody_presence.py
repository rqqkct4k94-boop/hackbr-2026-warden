"""Read-only, owner-run proof of three distinct deployed custodian signing identities.

This is NOT a certificate authorization or proof of separate human operators. The
signing keys stay inside their existing dedicated guest accounts. No storage or
CA state is changed and no release shares are read into the orchestration output.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import json
import re
import secrets
import shlex
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from warden import CUSTODIANS, canonical, digest, unb64
from cloudshell_owner import NODES, PREFIX, ZONE, IMAGE, owner_project, status, retry_live_read

SCHEMA='warden-custody-presence-only-v1'
REMOTE_SIGNER=r'''import base64, json, re, sys, time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
challenge=json.loads(sys.argv[1]); expected=sys.argv[2]
package=json.loads(Path('/var/lib/warden-custodian/custody.json').read_text())
def require(value):
    if not value:raise SystemExit('Custody presence challenge refused')
require(set(challenge)=={'schema','nonce','root_fingerprint','manifest_sha256','issued_at','expires_at','scope'})
require(challenge['schema']=='warden-custody-presence-only-v1' and challenge['scope']=='not-certificate-authorization')
require(re.fullmatch('[0-9a-f]{64}',challenge['nonce']) and re.fullmatch('[0-9a-f]{64}',challenge['manifest_sha256']))
require(expected==package['id'] and challenge['root_fingerprint']==package['root_fingerprint'])
require(challenge['issued_at']-5<=time.time()<=challenge['expires_at'] and 0<challenge['expires_at']-challenge['issued_at']<=300)
statement={'schema':challenge['schema'],'challenge':challenge,'custodian_id':expected}
key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(package['signing_key'],validate=True))
message=json.dumps(statement,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
print(json.dumps({'statement':statement,'signature':base64.b64encode(key.sign(message)).decode('ascii')}))
'''

def challenge_for(manifest,now=None):
    now=int(time.time() if now is None else now)
    return {'schema':SCHEMA,'nonce':secrets.token_hex(32),'root_fingerprint':manifest['root_fingerprint'],
            'manifest_sha256':digest(canonical(manifest)),'issued_at':now,'expires_at':now+300,'scope':'not-certificate-authorization'}


def verify_presence(manifest,challenge,proofs):
    if challenge.get('schema')!=SCHEMA or challenge.get('root_fingerprint')!=manifest.get('root_fingerprint') or challenge.get('manifest_sha256')!=digest(canonical(manifest)) or challenge.get('scope')!='not-certificate-authorization':
        raise ValueError('Presence challenge differs from the pinned authority or scope')
    public={p['id']:p['public_key'] for p in manifest['custodians']}
    if len(proofs)!=3 or set(public)!=set(CUSTODIANS) or len(set(public.values()))!=3:raise ValueError('Expected three different registered identities')
    found=set()
    for p in proofs:
        if set(p)!={'statement','signature'}:raise ValueError('Unrecognized presence evidence fields')
        statement=p['statement'];cid=statement.get('custodian_id')
        if cid not in public or cid in found or statement!={'schema':SCHEMA,'challenge':challenge,'custodian_id':cid}:
            raise ValueError('Duplicate, unknown, or mismatched presence identity')
        Ed25519PublicKey.from_public_bytes(unb64(public[cid])).verify(unb64(p['signature']),canonical(statement))
        found.add(cid)
    return {'verified':True,'registered_signing_identities':sorted(found),'signatures':3,'certificate_authorization':False,
            'independent_human_custody_proven':False}


def owner_gate(runtime):
    runtime=Path(runtime).expanduser().resolve();project=owner_project()
    meta=json.loads((runtime/'prepared.json').read_text())
    if meta!={'project':project,'zone':ZONE,'image':IMAGE,'scope':PREFIX,'prepared':True}:raise ValueError('Runtime is not exact Warden scope')
    if not all(x['status']=='RUNNING' for x in status(private_only=True)):
        raise RuntimeError('Start the dedicated lab explicitly before running this read-only gate')
    directory=runtime/'stage-control'/'runtime';manifest=json.loads((directory/'manifest.json').read_text());pins=json.loads((directory/'pins.json').read_text())
    if pins['manifest']!=digest(canonical(manifest)) or pins['root']!=manifest['root_fingerprint']:raise ValueError('Owner ceremony pins do not match')
    challenge=challenge_for(manifest)
    def attest(item):
        node,cid=item;cmd=shlex.join(['sudo','-u','warden-custodian','/opt/warden-p0/custody-venv/bin/python','-c',REMOTE_SIGNER,json.dumps(challenge),cid])
        return retry_live_read(node[0],cmd,timeout=80,attempts=3)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:proofs=list(pool.map(attest,zip(NODES[:3],CUSTODIANS)))
    if time.time()>challenge['expires_at']:raise RuntimeError('Challenge expired before all signed responses arrived')
    result=verify_presence(manifest,challenge,proofs)
    for p,cid in zip(proofs,CUSTODIANS):
        if p['statement']['custodian_id']!=cid:raise RuntimeError('Unexpected identity-to-guest assignment')
    report={'scope':'three separate deployed guest accounts; no certificate state change','result':result,'challenge':challenge,
            'proofs':proofs,'manifest':manifest,'pins':pins}
    target=runtime/f'custody-presence-{challenge["nonce"][:12]}.json'
    with target.open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
    print(json.dumps({'result':result,'public_evidence_file':target.name},indent=2));return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runtime',required=True);owner_gate(p.parse_args().runtime)
