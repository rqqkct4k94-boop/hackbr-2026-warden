import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyProof} from './verify.mjs';
const read=name=>JSON.parse(readFileSync(new URL(name,import.meta.url),'utf8'));
test('independent WebCrypto verification of authentic local sample',async()=>{const p=await verifyProof(read('sample-proof.json'),read('sample-pins.json'));assert.equal(p.verified,true);assert.equal(p.authorized,2);assert.equal(p.denied,2);assert.equal(p.certificates.length,2);assert.equal(p.ledgerVerified,false);});
test('tampering and wrong independent manifest pin fail closed',async()=>{const e=read('sample-proof.json'),pins=read('sample-pins.json');e.events.at(-1).payload.result.fingerprint='0'.repeat(64);await assert.rejects(verifyProof(e,pins),/auditoria alterada/);await assert.rejects(verifyProof(read('sample-proof.json'),{...pins,manifest:'0'.repeat(64)}),/Manifesto/);});
test('recorded cloud report and local sample are explicitly different scopes',()=>{const r=read('recorded-cloud.json');assert.equal(r.live_acceptance.network.validators.length,4);assert.equal(r.live_acceptance.anchor.receipts,4);assert.notEqual(r.live_acceptance.audit.head,read('sample-pins.json').audit_head);});
