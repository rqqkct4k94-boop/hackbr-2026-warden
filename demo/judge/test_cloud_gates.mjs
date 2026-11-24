import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {verifyLifecycleReport,verifyNativeKmsProof} from './cloud-gates.mjs';
import worker from './dist/worker.mjs';

const ref=JSON.parse(readFileSync(new URL('./recorded-cloud.json',import.meta.url),'utf8'));
const base=ref.live_acceptance;
const canonical=x=>Array.isArray(x)?'['+x.map(canonical).join(',')+']':x!==null&&typeof x==='object'?'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}':JSON.stringify(x);

function mockLifecycle(){
  // This object is a local unit-test fixture, never shipped as live acceptance.
  return {schema:'warden-lifecycle-acceptance-v1',scope:'synthetic-warden-lab',source:'owner-run-gce-provider-observation-and-live-verification',verified:true,
    configured_guest_idle_seconds:600,provider_observation_limit_seconds:900,observed_all_terminated_seconds:720,
    provider_transition_seconds:Object.fromEntries(['control','v1','v2','v3','v4'].map(n=>['hackbr-warden-p0-'+n,615])),
    five_unique_disk_ids_preserved:true,restart_verified:true,four_validators_verified_after_restart:true,four_matching_anchor_receipts:4,
    two_distinct_tls_fingerprints:Object.fromEntries(base.tls.sites.map(s=>[s.hostname,s.fingerprint])),audit_head:base.audit.head,anchor_transaction:base.anchor.transaction_hash,
    guest_trigger_timestamp_independently_measured:false,completed_utc:1800000000,limitations:['synthetic test only','synthetic test only']};
}
function mockNative(){
  // Local signature only. The test verifies mathematical checks, not observed provider behavior.
  const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),schema='warden-native-kms-signing-v1';
  const message={schema,scope:'synthetic-demo-only',nonce:'1'.repeat(64),audit_head:base.audit.head,purpose:'demonstrate-provider-native-signing'};
  const publicPem=key.publicKey.export({format:'pem',type:'spki'}),der=key.publicKey.export({format:'der',type:'spki'});
  const proof={schema,scope:'synthetic-demo-only',message,public_key_pem:publicPem,signature_der_b64:sign('sha256',Buffer.from(canonical(message)),key.privateKey).toString('base64'),
    provider_report:{provider:'google-cloud-kms',algorithm:'EC_SIGN_P256_SHA256',protection:'SOFTWARE',version:'1',state:'ENABLED',origin:'provider-generated',source:'owner-run-provider-metadata',provider_attestation_verified:false}};
  const pin={schema,public_key_sha256:createHash('sha256').update(der).digest('hex'),audit_head:base.audit.head};
  return {proof,pin};
}

test('acceptance verifier checks fixture consistency, never claims independent provider attestation',()=>{
  const r=verifyLifecycleReport(mockLifecycle(),ref);assert.equal(r.consistent,true);assert.equal(r.providerAttestationVerified,false);assert.equal(r.disks,5);
  for(const changes of [{restart_verified:false},{observed_all_terminated_seconds:200},{audit_head:'0'.repeat(64)},{four_matching_anchor_receipts:3},{private_key:'fixture'}])assert.throws(()=>verifyLifecycleReport({...mockLifecycle(),...changes},ref));
  const omitted=mockLifecycle();delete omitted.provider_transition_seconds['hackbr-warden-p0-v2'];assert.throws(()=>verifyLifecycleReport(omitted,ref));
});

test('KMS proof verifies only public challenge signature, pinned key and reference audit head',async()=>{
  const {proof,pin}=mockNative(),r=await verifyNativeKmsProof(proof,pin,ref);assert.equal(r.signatureVerified,true);assert.equal(r.providerAttestationVerified,false);
  await assert.rejects(verifyNativeKmsProof({...proof,message:{...proof.message,nonce:'3'.repeat(64)}},pin,ref));
  await assert.rejects(verifyNativeKmsProof(proof,{...pin,public_key_sha256:'0'.repeat(64)},ref));
  await assert.rejects(verifyNativeKmsProof({...proof,provider_report:{...proof.provider_report,provider_attestation_verified:true}},pin,ref));
  await assert.rejects(verifyNativeKmsProof({...proof,public_key_pem:'-----BEGIN PRIVATE KEY-----\nplaceholder\n-----END PRIVATE KEY-----'},pin,ref));
});

test('static portal includes the recorded owner lifecycle report but no shipped mock reports or write endpoint',async()=>{
  const get=(path,method='GET')=>worker.fetch(new Request('https://synthetic.invalid'+path,{method}));
  const html=await get('/console').text();assert.match(html,/lifecycle-file/);assert.match(html,/native-kms-pin/);assert.match(html,/Aguardando prova pública/);
  assert.equal(get('/cloud-gates.mjs').status,200);assert.equal(get('/cloud-gates.mjs','POST').status,405);
  assert.equal(get('/public-lifecycle-report.json').status,404);assert.equal(get('/public-native-kms-proof.json').status,404);
  const report=await get('/lifecycle-report.json').json(),verified=verifyLifecycleReport(report,ref);assert.equal(verified.consistent,true);assert.equal(verified.observedSeconds,728.558);assert.equal(verified.providerAttestationVerified,false);assert.equal(get('/lifecycle-report.json','POST').status,405);
  assert.match(await get('/').text(),/Relatório de aceitação/);
});
