import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {verifyProof,verifyPresence,canonical} from './verify.mjs';
const read=name=>JSON.parse(readFileSync(new URL(name,import.meta.url),'utf8'));
test('independent WebCrypto verification of authentic local sample',async()=>{const p=await verifyProof(read('sample-proof.json'),read('sample-pins.json'));assert.equal(p.verified,true);assert.equal(p.authorized,2);assert.equal(p.denied,2);assert.equal(p.certificates.length,2);assert.equal(p.ledgerVerified,false);});
test('tampering and wrong independent manifest pin fail closed',async()=>{const e=read('sample-proof.json'),pins=read('sample-pins.json');e.events.at(-1).payload.result.fingerprint='0'.repeat(64);await assert.rejects(verifyProof(e,pins),/auditoria alterada/);await assert.rejects(verifyProof(read('sample-proof.json'),{...pins,manifest:'0'.repeat(64)}),/Manifesto/);});
test('recorded cloud report and local sample are explicitly different scopes',()=>{const r=read('recorded-cloud.json');assert.equal(r.live_acceptance.network.validators.length,4);assert.equal(r.live_acceptance.anchor.receipts,4);assert.notEqual(r.live_acceptance.audit.head,read('sample-pins.json').audit_head);});
test('three presence signatures check against independent pins without implying issuance',async()=>{
  const manifest=read('sample-proof.json').manifest;const pairs=manifest.custodians.map(()=>generateKeyPairSync('ed25519'));
  manifest.custodians.forEach((x,i)=>x.public_key=pairs[i].publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'));
  const pins={root:manifest.root_fingerprint,manifest:createHash('sha256').update(canonical(manifest)).digest('hex')};
  const schema='warden-custody-presence-only-v1',challenge={schema,scope:'not-certificate-authorization',nonce:'b'.repeat(64),root_fingerprint:pins.root,manifest_sha256:pins.manifest,issued_at:1800000000,expires_at:1800000300};
  const proofs=manifest.custodians.map((c,i)=>{const statement={schema,challenge,custodian_id:c.id};return {statement,signature:sign(null,Buffer.from(canonical(statement)),pairs[i].privateKey).toString('base64')};});
  const report={manifest,challenge,proofs};const v=await verifyPresence(report,pins);assert.equal(v.identities.length,3);assert.equal(v.certificateAuthorization,false);
  await assert.rejects(verifyPresence({...report,proofs:proofs.slice(0,2)},pins),/Três identidades/);
  await assert.rejects(verifyPresence({...report,proofs:[proofs[0],proofs[0],proofs[2]]},pins),/duplicada/);
  await assert.rejects(verifyPresence({...report,proofs:[{...proofs[0],signature:proofs[1].signature},...proofs.slice(1)]},pins),/Assinatura/);
});

const caseEvidence = () => read('issuance-case.json');
const casePins = read('issuance-pins.json');
function rechain(events){
  let previous = '0'.repeat(64);
  for (const [i, event] of events.entries()) {
    event.seq = i + 1;
    event.prev_hash = previous;
    previous = createHash('sha256').update(canonical({seq:event.seq, prev_hash:previous, payload:event.payload})).digest('hex');
    event.event_hash = previous;
  }
}
test('single-service case ties both decisions and leaf to the request under retained pins', async () => {
  const result = await verifyProof(caseEvidence(), casePins);
  assert.equal(result.authorized, 1);
  assert.equal(result.denied, 2); // partial approval and repeated authorization
  assert.equal(result.certificates.length, 1);
  assert.equal(result.issuance.countAfterDenial, 0);
  assert.equal(result.issuance.partial.length, 2);
  assert.equal(result.issuance.approved.length, 3);
  assert.equal(result.issuance.requestHash, caseEvidence().events[3].payload.approvals[2].request_sha256);
  await assert.rejects(verifyProof(caseEvidence(), {...casePins, audit_head:undefined}), /pin independente/);
});

test('rewritten public history still fails its signature, certificate, policy or decision checks', async () => {
  const mutations = [
    ['external anchor', e => { e.ledger_anchor = 'unverified'; }, /Formato do pacote/],
    ['policy', e => { e.manifest.issuance_policy.required = 2; }, /Manifesto/],
    ['request', e => {
      for (const i of [1, 3]) e.events[i].payload.request.id = 'a'.repeat(32);
    }, /Aprovação não corresponde/],
    ['approval', e => { const a = e.events[3].payload.approvals; a[1].signature = a[2].signature; }, /Assinatura do custodiante/],
    ['duplicate', e => { const a = e.events[3].payload.approvals; a[2] = a[0]; }, /duplicadas/],
    ['other certificate', e => { e.events[3].payload.result = read('sample-proof.json').events.at(-1).payload.result; }, /Assinatura X.509/],
    ['denial count', e => { e.events[2].payload.service_certificate_count = 1; }, /Negação 2\/3/],
    ['denial signers', e => { const a = e.events[2].payload.approvals; a[1] = a[0]; }, /Negação 2\/3/],
    ['replay', e => { e.events.push(structuredClone(e.events[3])); }, /Vínculo ou validade/],
    ['missing replay', e => { e.events.pop(); }, /Histórico incompleto/],
    ['different final timestamp', e => { e.events.at(-1).payload.at += 1; }, /pin independente/]
  ];
  for (const [label, mutate, expected] of mutations) {
    const evidence = caseEvidence();
    mutate(evidence);
    rechain(evidence.events);
    await assert.rejects(verifyProof(evidence, casePins), expected, label);
  }
});
