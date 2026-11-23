import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {generateKeyPairSync,sign} from 'node:crypto';
import worker from './dist/worker.mjs';
import {newSource,newRehearsal,approveRehearsal,verifyRehearsal} from './console-policy.mjs';
import {checkConsoleSample} from './console-evidence.mjs';
import {validateSandbox,createPossessionChallenge,possessionChallengeBytes,verifyPossession} from './console-connect.mjs';

const read=name=>JSON.parse(readFileSync(new URL(name,import.meta.url),'utf8'));
const route=(path,method='GET')=>worker.fetch(new Request('https://synthetic.invalid'+path,{method}));

test('public console is linked from stable root and has only read-only routes and external local scripts',async()=>{
  assert.match(await route('/').text(),/href="\/console"/);
  const response=route('/console'),html=await response.text();assert.equal(response.status,200);
  assert.match(html,/FAROL-26/);assert.match(html,/console-verify-proof/);assert.match(html,/use-fixture-sandbox/);
  assert.doesNotMatch(html,/<script(?![^>]*\ssrc=)/);assert.doesNotMatch(html,/@@[A-Z_]+@@/);
  assert.match(response.headers.get('Content-Security-Policy'),/script-src 'self'/);
  assert.doesNotMatch(response.headers.get('Content-Security-Policy'),/script-src[^;]*unsafe-inline/);
  for(const script of ['console-app','console-policy','console-evidence','console-connect','console-icons'])assert.equal(route('/'+script+'.mjs').status,200);
  assert.equal(route('/console','POST').status,405);assert.equal(route('/admin').status,404);assert.equal(route('/console','HEAD').status,200);
  assert.equal(await route('/console','HEAD').text(),'');
});

test('synthetic 3/3 rehearsal enforces partial denial and binds all signatures to exact intent',async()=>{
  const fingerprint=await newSource(),r=await newRehearsal(fingerprint,'gcp');
  assert.match(fingerprint,/^[A-F0-9]{64}$/);
  assert.ok(r.custodians.every(c=>!c.privateKey.extractable));
  await approveRehearsal(r,0);await approveRehearsal(r,1);await approveRehearsal(r,1);
  assert.deepEqual(await verifyRehearsal(r),{authorized:false,count:2});
  await approveRehearsal(r,2);assert.deepEqual(await verifyRehearsal(r),{authorized:true,count:3});
  assert.deepEqual(await verifyRehearsal(r,{...r.request,destination:'aws'}),{authorized:false,count:3});
  const next=await newRehearsal(fingerprint,'aws');assert.deepEqual(await verifyRehearsal(next),{authorized:false,count:0});
});

test('console uses the authentic PKI evidence and detects alteration; cannot mistake mismatched pins for valid evidence',async()=>{
  const proof=read('sample-proof.json'),pins=read('sample-pins.json');
  const verified=await checkConsoleSample(proof,pins);assert.equal(verified.verified,true);assert.equal(verified.authorized,2);
  await assert.rejects(checkConsoleSample(proof,pins,true));await assert.rejects(checkConsoleSample(proof,{...pins,manifest:'0'.repeat(64)}));
  assert.equal((await checkConsoleSample(proof,pins)).verified,true);
});

test('own-sandbox manifest only accepts the exact redacted metadata shape',()=>{
  const data={schema:'warden-judge-sandbox-v1',provider:'gcp',environment:'judge-sandbox',source:'owner-cli-read-only',captured_at:'2026-11-23T12:00:00Z',assets:[{kind:'vm',alias:'Demo VM',region:'us-central1-a',status:'running'}]};
  assert.deepEqual(validateSandbox(data),data);
  assert.throws(()=>validateSandbox({...data,apiKey:'test-placeholder'}));
  assert.throws(()=>validateSandbox({...data,assets:[{...data.assets[0],resource:'projects/private'}]}));
  assert.throws(()=>validateSandbox({...data,assets:[data.assets[0],data.assets[0]]}));
  assert.throws(()=>validateSandbox({...data,assets:[{...data.assets[0],alias:'https://sample.invalid'}]}));
});

test('public challenge signature proves only possession, rejects wrong or expired proof and private key material',async()=>{
  const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),challenge=createPossessionChallenge('Demo signing key',1000);
  const pub=key.publicKey.export({type:'spki',format:'pem'}),sig=sign('sha256',possessionChallengeBytes(challenge),key.privateKey).toString('base64');
  const result=await verifyPossession(challenge,pub,sig,1001);
  assert.equal(result.verified,true);assert.equal(result.cloudOriginAttested,false);assert.equal(result.accountAccessGranted,false);
  await assert.rejects(verifyPossession(challenge,pub,sig,1601));
  await assert.rejects(verifyPossession({...challenge,nonce:'0'.repeat(64)},pub,sig,1001));
  await assert.rejects(verifyPossession(challenge,'-----BEGIN PRIVATE KEY-----\nplaceholder\n-----END PRIVATE KEY-----',sig,1001));
});
