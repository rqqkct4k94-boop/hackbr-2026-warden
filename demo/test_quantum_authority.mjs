import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {generatePublicProof,verifyPublicProof,encryptionTrial,QuantumGate,requestDigest} from './quantum_authority.mjs';
const now=1800000000;
const load=name=>JSON.parse(readFileSync(new URL('./judge/'+name,import.meta.url),'utf8'));
const sample=generatePublicProof(now);
test('recorded public proof contains six genuine signatures and no private key',()=>{
  const proof=load('quantum-sample.json'),pins=load('quantum-pins.json');assert.equal(verifyPublicProof(proof,pins),true);assert.equal(proof.approvals.length,3);assert.doesNotMatch(JSON.stringify(proof),/private|secret|token/i);
});
test('both algorithms and all three pinned custodians are mandatory',()=>{
  const {proof,pins}=sample;assert.equal(verifyPublicProof(proof,pins),true);
  for(const field of ['classical_signature','pqc_signature']){const changed=structuredClone(proof);changed.approvals[0][field]='AAAA';assert.equal(verifyPublicProof(changed,pins),false)}
  assert.equal(verifyPublicProof({...proof,approvals:proof.approvals.slice(0,2)},pins),false);
  assert.equal(verifyPublicProof({...proof,request:{...proof.request,nonce:'0'.repeat(64)}},pins),false);
  assert.equal(verifyPublicProof(proof,{...pins,manifest_sha256:'0'.repeat(64)}),false);
  const duplicate=structuredClone(proof);duplicate.approvals[1]={...duplicate.approvals[0],role:'B'};assert.equal(verifyPublicProof(duplicate,pins),false);
});
test('ML-KEM and AES-GCM local roundtrip rejects tampering and wrong recipient',()=>{
  const r=encryptionTrial();assert.equal(r.roundtrip,true);assert.equal(r.tampered_ciphertext_rejected,true);assert.equal(r.wrong_recipient_rejected,true);assert.equal(r.encapsulation_ciphertext_bytes,1088);
});
test('no hardware adapter denies even with six valid approvals',async()=>{
  const {proof,pins}=sample;assert.deepEqual(await new QuantumGate(pins).authorize(proof,now+5),{allowed:false,reason:'physical-provider-unavailable'});
  assert.deepEqual(await new QuantumGate(pins).authorize({...proof,approvals:proof.approvals.slice(0,2)},now+5),{allowed:false,reason:'dual-custody-denied'});
  assert.equal((await new QuantumGate(pins).authorize(proof,now+901)).allowed,false);
  assert.equal((await new QuantumGate(pins).authorize(generatePublicProof(now).proof,now+5)).reason,'dual-custody-denied');
});
test('test-only adapter contract rejects replay, simulator, altered request and stale result',async()=>{
  const {proof,pins}=sample;const fixture={provider:'ibm-quantum',mode:'physical-hardware',status:'DONE',request_sha256:requestDigest(proof.request),job:'test-fixture-only',completed_at:now+1};
  // This deliberately mocked callback proves policy logic, never hardware execution.
  const gate=new QuantumGate(pins,async()=>fixture);assert.equal((await gate.authorize(proof,now+5)).allowed,true);assert.equal((await gate.authorize(proof,now+6)).reason,'replay-denied');
  for(const change of [{mode:'simulator'},{request_sha256:'0'.repeat(64)},{completed_at:now-1},{status:'QUEUED'},{job:'bad'}])assert.equal((await new QuantumGate(pins,async()=>({...fixture,...change})).authorize(proof,now+5)).allowed,false);
  assert.equal((await new QuantumGate(pins,async()=>{throw Error('offline')}).authorize(proof,now+5)).allowed,false);
});
