import {test} from 'node:test';
import assert from 'node:assert/strict';
import worker from './dist/worker.mjs';
import {browserCheck} from './quantum-ui.mjs';
const req=(path,method='GET')=>worker.fetch(new Request('https://synthetic.invalid'+path,{method}));
test('public Quantum route is linked, static and honest about pending live acceptance',async()=>{
  assert.match(await req('/console').text(),/href="\/quantum"/);
  const res=req('/quantum'),html=await res.text();assert.equal(res.status,200);
  assert.match(html,/GATE PENDENTE/);assert.match(html,/não tem acesso ao QPU/);assert.match(html,/Testar bloqueio sem QPU/);
  assert.equal(req('/quantum','POST').status,405);assert.equal(req('/quantum-ui.mjs').status,200);assert.equal(req('/quantum-hardware-report.json').status,404);
  assert.equal(req('/quantum-proof.json').status,200);assert.doesNotMatch(await req('/quantum-proof.json').text(),/private_key|secret_key|api_token/i);
  const hardware=await req('/quantum-hardware-smoke.json').json();assert.equal(hardware.status,'Completed');assert.equal(hardware.shots,256);assert.equal(hardware.bound_to_warden_custody_request,false);assert.equal(hardware.protected_key_operation_authorized,false);assert.equal(hardware.provider_attestation_verified,false);
});
test('browser verifier validates classical signatures and rejects tampered public request; ML-DSA support is detected',async()=>{
  const proof=await req('/quantum-proof.json').json(),pins=await req('/quantum-pins.json').json();
  const r=await browserCheck(proof,pins);assert.equal(r.classicalVerified,true);assert.equal(typeof r.pqcVerified,'boolean');
  await assert.rejects(browserCheck(proof,pins,true));await assert.rejects(browserCheck(proof,{...pins,manifest_sha256:'0'.repeat(64)}));
});
