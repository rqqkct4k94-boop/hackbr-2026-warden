"""Owner-side physical-QPU gate for one fixed synthetic document.

Only an existing IBM Open Plan instance is eligible. No arbitrary inputs, key
export, KMS operation, provider simulator, credential persistence, public
authorization endpoint or automatic job retry. The local operator is trusted.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
from dataclasses import asdict
from functools import partial
from importlib.metadata import version
import getpass
import hashlib
import json
import math
import re
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lifecycle_acceptance import verify_runtime

SCHEMA='warden-quantum-authority-proof-v1'
REPORT='warden-ibm-physical-gate-v1'
BACKEND='ibm_marrakesh'
SHOTS=256
MAX_EXECUTION_TIME=60
RUNTIME_VERSION="0.49.0"
QISKIT_VERSION="2.6.2"
MAX_AGE=900
MAX_RESULT_AGE=300
DOCUMENT=b'FAROL-26 | fixed synthetic quantum-dependent document'
HEX=re.compile(r'[0-9a-f]{64}')
ROLES=('A','B','C')


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
def sha(data):return hashlib.sha256(data).hexdigest()
def digest(value):return sha(canonical(value))
def b64(data):return base64.b64encode(data).decode('ascii')
def decode(value):
    if not isinstance(value,str) or len(value)>8192:raise ValueError('Invalid public field')
    raw=base64.b64decode(value,validate=True)
    if b64(raw)!=value:raise ValueError('Noncanonical base64')
    return raw
def spki(key):return b64(key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
def exact(value,keys):return isinstance(value,dict) and set(value)==set(keys)
def validhex(value):return isinstance(value,str) and HEX.fullmatch(value) is not None


def make_custody(now):
    request={'schema':SCHEMA,'scope':'synthetic-demo-only','operation':'verify-fixed-document','nonce':secrets.token_hex(32),'issued_at':now}
    approvals=[];manifest=[]
    for role in ROLES:
        classical=ec.generate_private_key(ec.SECP256R1());pqc=mldsa.MLDSA65PrivateKey.generate()
        public={'role':role,'classical_public_spki':spki(classical.public_key()),'pqc_public_spki':spki(pqc.public_key())}
        message=canonical({'domain':'warden-dual-custodian-approval-v1','request':request,'role':role})
        r,s=utils.decode_dss_signature(classical.sign(message,ec.ECDSA(hashes.SHA256())))
        manifest.append(public);approvals.append({**public,'classical_signature':b64(r.to_bytes(32,'big')+s.to_bytes(32,'big')),'pqc_signature':b64(pqc.sign(message))})
    return {'schema':SCHEMA,'source':'local-synthetic-ephemeral-signatures','request':request,'approvals':approvals},{'schema':SCHEMA,'manifest_sha256':digest(manifest)}


def verify_custody(proof,pins,now):
    if not exact(proof,('schema','source','request','approvals')) or proof['schema']!=SCHEMA or proof['source']!='local-synthetic-ephemeral-signatures':raise ValueError('Invalid custody proof')
    req=proof['request']
    if not exact(req,('schema','scope','operation','nonce','issued_at')) or req['schema']!=SCHEMA or req['scope']!='synthetic-demo-only' or req['operation']!='verify-fixed-document' or not validhex(req['nonce']) or type(req['issued_at']) is not int or type(now) is not int or not 0<=now-req['issued_at']<=MAX_AGE:raise ValueError('Invalid or expired request')
    if not isinstance(proof['approvals'],list) or len(proof['approvals'])!=3:raise ValueError('All three custodians required')
    manifest=[];keys=set()
    for role,a in zip(ROLES,proof['approvals']):
        if not exact(a,('role','classical_public_spki','pqc_public_spki','classical_signature','pqc_signature')) or a['role']!=role:raise ValueError('Invalid custodian')
        for name in ('classical_public_spki','pqc_public_spki'):
            if a[name] in keys:raise ValueError('Duplicate public key')
            keys.add(a[name])
        c=serialization.load_der_public_key(decode(a['classical_public_spki']));q=serialization.load_der_public_key(decode(a['pqc_public_spki']))
        if not isinstance(c,ec.EllipticCurvePublicKey) or not isinstance(c.curve,ec.SECP256R1) or not isinstance(q,mldsa.MLDSA65PublicKey):raise ValueError('Wrong algorithm')
        msg=canonical({'domain':'warden-dual-custodian-approval-v1','request':req,'role':role})
        sig=decode(a['classical_signature'])
        if len(sig)!=64:raise ValueError('Wrong ECDSA signature size')
        c.verify(utils.encode_dss_signature(int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')),msg,ec.ECDSA(hashes.SHA256()))
        q.verify(decode(a['pqc_signature']),msg)
        manifest.append({k:a[k] for k in ('role','classical_public_spki','pqc_public_spki')})
    if pins!={'schema':SCHEMA,'manifest_sha256':digest(manifest)}:raise ValueError('Custody pin mismatch')
    return digest(req)


def circuit_spec(request_sha):
    if not validhex(request_sha):raise ValueError('Invalid request digest')
    return {'schema':'warden-bell-challenge-v1','request_sha256':request_sha,'backend':BACKEND,'shots':SHOTS,'parity':int(request_sha[-1],16)%2,'logical_qubits':2}


def circuit_metadata(spec):return {'warden_request_sha256':spec['request_sha256'],'warden_circuit_sha256':digest(spec)}
def job_tags(spec):return ['warden-p0',spec['request_sha256'],digest(spec)]


def validate_counts(counts,parity):
    if not isinstance(counts,dict) or not counts or any(k not in ('00','01','10','11') or type(v) is not int or v<0 for k,v in counts.items()) or sum(counts.values())!=SHOTS:raise ValueError('Malformed shot counts')
    targets=('00','11') if parity==0 else ('01','10')
    if sum(counts.get(k,0) for k in targets)<math.ceil(SHOTS*.75) or min(counts.get(k,0) for k in targets)<math.ceil(SHOTS*.10):raise ValueError('Physical circuit statistical check failed')
    return dict(sorted(counts.items()))


def timestamp(value):
    if not isinstance(value,str):raise ValueError('Missing provider timestamp')
    parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:raise ValueError('Provider timestamp missing timezone')
    return int(parsed.timestamp())


def open_plan(service,instance):
    matches=[x for x in service.instances() if x.get('crn')==instance]
    if len(matches)!=1 or matches[0].get('plan')!='open' or service.active_instance()!=instance:raise ValueError('Exact existing Open Plan instance required')
    backend=service.backend(BACKEND,instance=instance)
    if backend.name!=BACKEND or backend.configuration().simulator is not False or not backend.status().operational or service.active_instance()!=instance:raise ValueError('Approved physical backend unavailable')
    return backend


def provider_observation(job,instance,spec,job_id,issued,now):
    # Only called with the job freshly retrieved by the authenticated service.
    if job.job_id()!=job_id or job.instance!=instance or job.status()!='DONE' or job.backend().name!=BACKEND or job.backend().configuration().simulator is not False or not set(job_tags(spec)).issubset(set(job.tags or [])):raise ValueError('Unexpected provider job')
    result=job.result(timeout=15)
    if len(result)!=1 or result[0].metadata.get('circuit_metadata')!=circuit_metadata(spec):raise ValueError('Provider result not bound to the exact request')
    counts=validate_counts(result[0].data.meas.get_counts(),spec['parity'])
    metrics=job.metrics();timestamps=metrics.get('timestamps') or {}
    created=timestamp(timestamps.get('created'));finished=timestamp(timestamps.get('finished'))
    if not issued<=created<=finished<=now or now-issued>MAX_AGE or now-finished>MAX_RESULT_AGE:raise ValueError('Stale or invalid physical result')
    usage=metrics.get('usage') or {};seconds=usage.get('qpu_charge_time_seconds',usage.get('quantum_seconds'))
    if not isinstance(seconds,(int,float)) or isinstance(seconds,bool) or not math.isfinite(seconds) or seconds<=0:raise ValueError('No positive provider QPU usage')
    return {'backend':BACKEND,'provider_status':'DONE','job_id_sha256':sha(job_id.encode('ascii')),'request_sha256':spec['request_sha256'],'circuit_sha256':digest(spec),'shots':SHOTS,'parity':spec['parity'],'counts':counts,'created_at':created,'completed_at':finished,'observed_at':now,'qpu_seconds':seconds}


class Journal:
    """One immutable attempt slot; committed state transitions resist replay/restart."""
    def __init__(self,path):
        self.db=sqlite3.connect(path,timeout=5)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS gate (slot INTEGER PRIMARY KEY CHECK(slot=1), request_sha TEXT UNIQUE NOT NULL, circuit_sha TEXT NOT NULL, job TEXT UNIQUE, state TEXT NOT NULL)')
        self.db.commit()
    def reserve(self,spec):
        with self.db:self.db.execute("INSERT INTO gate VALUES(1,?,?,NULL,'reserved')",(spec['request_sha256'],digest(spec)))
    def submitted(self,spec,job):
        if not isinstance(job,str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,100}',job):raise ValueError('Invalid provider job ID')
        with self.db:
            cursor=self.db.execute("UPDATE gate SET job=?,state='submitted' WHERE slot=1 AND request_sha=? AND circuit_sha=? AND state='reserved' AND job IS NULL",(job,spec['request_sha256'],digest(spec)))
            if cursor.rowcount!=1:raise ValueError('Not a fresh reserved attempt')
    def consume(self,spec,job):
        with self.db:
            cursor=self.db.execute("UPDATE gate SET state='consumed' WHERE slot=1 AND request_sha=? AND circuit_sha=? AND job=? AND state='submitted'",(spec['request_sha256'],digest(spec),job))
            if cursor.rowcount!=1:raise ValueError('Replay or mismatched attempt')
    def close(self):self.db.close()


def check_sdk_version():
    if (version("qiskit-ibm-runtime"), version("qiskit")) != (RUNTIME_VERSION, QISKIT_VERSION):
        raise ValueError("Install the pinned requirements-quantum.txt")


def prepare_sampler(backend,spec):
    check_sdk_version()
    from qiskit import QuantumCircuit
    from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
    from qiskit.primitives.containers.sampler_pub import SamplerPub
    from qiskit_ibm_runtime import IBMBackend, RuntimeEncoder, SamplerV2
    from qiskit_ibm_runtime.runtime_options import RuntimeOptions
    from qiskit_ibm_runtime.utils.validations import (
        validate_classical_registers, validate_isa_circuits,
        validate_no_dd_with_dynamic_circuits, validate_rzz_pubs,
    )
    circuit=QuantumCircuit(2,name='warden-bound-bell')
    circuit.metadata=circuit_metadata(spec)
    circuit.h(0);circuit.cx(0,1)
    if spec['parity']:circuit.x(1)
    circuit.measure_all()
    isa=generate_preset_pass_manager(backend=backend,optimization_level=1,seed_transpiler=26).run(circuit)
    if isa.metadata!=circuit.metadata:raise ValueError('Request binding lost during transpilation')
    sampler = SamplerV2(mode=backend, options={
        'environment': {'job_tags': job_tags(spec)}, 'max_execution_time': MAX_EXECUTION_TIME,
    })
    if sampler.mode is not None or sampler.backend() is not backend:
        raise ValueError('Backend job mode required')
    pub = SamplerPub.coerce(isa, SHOTS)
    validate_classical_registers([pub])
    validate_isa_circuits([isa], backend.target)
    validate_rzz_pubs([pub])
    validate_no_dd_with_dynamic_circuits([isa], sampler.options)
    if isinstance(backend, IBMBackend):
        backend.check_faulty(isa)
    # Validate the pinned SDK's option projection and PUB serialization locally.
    options = asdict(sampler.options)
    runtime = RuntimeOptions(**sampler.options._get_runtime_options(options))
    runtime.validate(channel='ibm_quantum_platform')
    if runtime.job_tags != job_tags(spec) or runtime.max_execution_time != MAX_EXECUTION_TIME:
        raise ValueError('Runtime options lost request binding or execution limit')
    json.dumps({'pubs': [pub], **sampler.options._get_program_inputs(options)}, cls=RuntimeEncoder)
    return partial(sampler.run, [pub])


def prepare_physical(service,instance,backend,spec):
    from qiskit_ibm_runtime import IBMBackend
    from requests.adapters import HTTPAdapter

    if (not isinstance(backend, IBMBackend) or backend.service is not service
            or backend._instance != instance or service.active_instance() != instance):
        raise ValueError('Exact authenticated backend instance required')
    submit = prepare_sampler(backend,spec)
    usage = service.usage()
    remaining = usage.get('usage_remaining_seconds')
    if (usage.get('usage_limit_reached') or
            (remaining is not None and
             (type(remaining) not in (int,float) or not math.isfinite(remaining) or remaining <= 0))):
        raise ValueError('Open Plan usage unavailable')

    class SinglePostAdapter(HTTPAdapter):
        def send(self, request, **kwargs):
            response = super().send(request, **kwargs)
            if request.method == 'POST' and 300 <= response.status_code < 400:
                response.close()
                raise ValueError('Job endpoint redirected')
            return response

    # Runtime 0.49.0 retries some POSTs by default. Scope the zero-retry
    # adapter to this client's exact HTTPS job endpoint.
    session = service._api_clients[instance]._session
    endpoint = session.base_url + '/jobs'
    if not endpoint.startswith('https://'):
        raise ValueError('HTTPS job endpoint required')
    session.mount(endpoint, SinglePostAdapter(max_retries=0))
    return submit


def prepare_request(service,instance,backend):
    issued = int(time.time())
    proof, pin = make_custody(issued)
    spec = circuit_spec(verify_custody(proof,pin,issued))
    submit = prepare_physical(service,instance,backend,spec)
    if verify_custody(proof,pin,int(time.time())) != spec['request_sha256']:
        raise ValueError('Custody changed during preparation')
    return issued, proof, pin, spec, submit


def run_gate(service,instance,root,backend):
    # This function is deliberately not a public API. The CLI supplies trusted service.
    now,proof,pin,spec,submit=prepare_request(service,instance,backend)
    local_key=AESGCM.generate_key(bit_length=256);nonce=secrets.token_bytes(12);aad=canonical(spec)
    encrypted=AESGCM(local_key).encrypt(nonce,DOCUMENT,aad)
    journal=Journal(root/'ibm-physical-gate.sqlite')
    try:
        print('[Warden] Reserving one fixed Open Plan circuit before submission.',flush=True)
        journal.reserve(spec) # Commit before a single external mutation.
        job=submit();job_id=job.job_id()
        journal.submitted(spec,job_id)
        print('[Warden] Job submitted; waiting for physical result. No protected operation has run.',flush=True)
        job.wait_for_final_state(timeout=MAX_AGE-60,poll_interval=5)
        # Re-fetch from the service, never accept a caller-supplied result or job ID.
        retrieved=service.job(job_id)
        if service.active_instance()!=instance:raise ValueError('Provider instance changed')
        observed=provider_observation(retrieved,instance,spec,job_id,now,int(time.time()))
        if verify_custody(proof,pin,int(time.time()))!=spec['request_sha256']:raise ValueError('Custody changed')
        journal.consume(spec,job_id) # Durable, atomic single use before cryptographic operation.
        plain=AESGCM(local_key).decrypt(nonce,encrypted,aad)
        if plain!=DOCUMENT:raise ValueError('Unexpected synthetic document')
        # Persist only public, redacted evidence in these export files. The raw
        # job ID remains exclusively in the private replay journal.
        report={'schema':REPORT,'scope':'synthetic-demo-only','source':'owner-run-authenticated-ibm-runtime','plan':'open','custody_proof_sha256':digest(proof),'custody_pin_sha256':digest(pin),'three_dual_signatures_verified':True,'physical_provider_observed':True,'request_bound':True,'durable_single_use':True,'fixed_document_verified':True,'document_sha256':sha(plain),'provider_attestation_verified':False,'hardware_exclusivity_proven':False,'kms_operation':False,**observed}
        with (root/'public-ibm-gate-proof.json').open('x',encoding='utf8') as f:json.dump({'report':report,'proof':proof,'pin':pin},f,indent=2)
        with (root/'public-ibm-gate-report.json').open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
        return report
    finally:journal.close()


def connect(instance,profile):
    check_sdk_version()
    # Owner may use an existing SDK profile; otherwise enter an existing API key
    # in their private terminal. It is never saved or printed by this runner.
    from qiskit_ibm_runtime import QiskitRuntimeService
    if not isinstance(instance,str) or not instance.startswith('crn:v1:') or len(instance)>512:raise ValueError('Provide the exact owner-approved Open Plan instance CRN')
    options={'channel':'ibm_quantum_platform','instance':instance,'verify':True}
    if profile:options['name']=profile
    else:options['token']=getpass.getpass('Existing IBM Cloud API key (hidden; never paste into chat): ')
    if not profile and not options['token']:raise ValueError('No existing credential supplied')
    return QiskitRuntimeService(**options)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('plan','apply'))
    parser.add_argument('--runtime',required=True)
    parser.add_argument('--instance',required=True,help='Existing Open Plan IBM service CRN')
    parser.add_argument('--profile',help='Existing saved Qiskit account profile (optional)')
    parser.add_argument('--approve-one-open-plan-job',action='store_true')
    args=parser.parse_args()
    root=verify_runtime(args.runtime)
    if args.command=='apply' and not args.approve_one_open_plan_job:raise SystemExit('Explicit one-job Open Plan approval required')
    if args.command=='apply' and any((root/p).exists() for p in ('ibm-physical-gate.sqlite','public-ibm-gate-proof.json','public-ibm-gate-report.json')):raise SystemExit('Prior attempt exists; review its state, do not resubmit')
    try:
        service=connect(args.instance,args.profile);backend=open_plan(service,args.instance)
        if args.command=='plan':
            prepare_request(service,args.instance,backend)
            result={'plan':'open','backend':backend.name,'physical':True,'shots':SHOTS,
                    'jobs':1,'jobs_submitted':0,'local_preparation':'passed',
                    'max_execution_time_seconds':MAX_EXECUTION_TIME,
                    'kms_keys_created':0,'paid_fallback':False}
        else:result=run_gate(service,args.instance,root,backend)
        print(json.dumps(result,indent=2))
    except Exception as exc:
        # SDK error strings can contain account metadata. Do not print them.
        raise SystemExit('Gate denied; no automatic retry. Error class: '+type(exc).__name__) from None


if __name__=='__main__':main()
