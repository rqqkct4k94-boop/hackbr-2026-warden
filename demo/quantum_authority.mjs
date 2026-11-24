// Competition-only cryptographic feasibility experiment. No provider or key export.
import {createHash,createPublicKey,generateKeyPairSync,sign,verify,randomBytes,encapsulate,decapsulate,hkdfSync,createCipheriv,createDecipheriv} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const schema='warden-quantum-authority-proof-v1',roles=['A','B','C'];
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(',')===keys.slice().sort().join(',');
const canonical=o=>Array.isArray(o)?'['+o.map(canonical).join(',')+']':o!==null&&typeof o==='object'?'{'+Object.keys(o).sort().map(k=>JSON.stringify(k)+':'+canonical(o[k])).join(',')+'}':JSON.stringify(o);
const bytes=o=>Buffer.from(canonical(o),'utf8');
const hash=o=>createHash('sha256').update(bytes(o)).digest('hex');
const validHex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const decode=(x,max=8192)=>{if(typeof x!=='string'||x.length>max||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(x))throw Error('invalid base64');return Buffer.from(x,'base64')};
const validRequest=r=>exact(r,['schema','scope','operation','nonce','issued_at'])&&r.schema===schema&&r.scope==='synthetic-demo-only'&&r.operation==='verify-fixed-document'&&validHex(r.nonce)&&Number.isSafeInteger(r.issued_at)&&r.issued_at>0;
const publicSpki=key=>key.export({format:'der',type:'spki'}).toString('base64');
export const requestDigest=request=>{if(!validRequest(request))throw Error('invalid request');return hash(request)};

export function generatePublicProof(now=Math.floor(Date.now()/1000)){
  const request={schema,scope:'synthetic-demo-only',operation:'verify-fixed-document',nonce:randomBytes(32).toString('hex'),issued_at:now};
  const approvals=roles.map(role=>{
    const classical=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),pqc=generateKeyPairSync('ml-dsa-65');
    const message=bytes({domain:'warden-dual-custodian-approval-v1',request,role});
    return {role,classical_public_spki:publicSpki(classical.publicKey),pqc_public_spki:publicSpki(pqc.publicKey),classical_signature:sign('sha256',message,{key:classical.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64'),pqc_signature:sign(null,message,pqc.privateKey).toString('base64')};
  });
  const publicManifest=approvals.map(({role,classical_public_spki,pqc_public_spki})=>({role,classical_public_spki,pqc_public_spki}));
  return {proof:{schema,source:'local-synthetic-ephemeral-signatures',request,approvals},pins:{schema,manifest_sha256:hash(publicManifest)}};
}

export function verifyPublicProof(proof,pins){
  try{
    if(!exact(proof,['schema','source','request','approvals'])||proof.schema!==schema||proof.source!=='local-synthetic-ephemeral-signatures'||!validRequest(proof.request)||!Array.isArray(proof.approvals)||proof.approvals.length!==3||!exact(pins,['schema','manifest_sha256'])||pins.schema!==schema||!validHex(pins.manifest_sha256))return false;
    const keys=new Set();
    for(let i=0;i<3;i++){
      const a=proof.approvals[i];if(!exact(a,['role','classical_public_spki','pqc_public_spki','classical_signature','pqc_signature'])||a.role!==roles[i])return false;
      for(const v of [a.classical_public_spki,a.pqc_public_spki]){if(keys.has(v))return false;keys.add(v)}
      const classical=createPublicKey({key:decode(a.classical_public_spki),format:'der',type:'spki'}),pqc=createPublicKey({key:decode(a.pqc_public_spki),format:'der',type:'spki'});
      if(classical.asymmetricKeyType!=='ec'||classical.asymmetricKeyDetails?.namedCurve!=='prime256v1'||pqc.asymmetricKeyType!=='ml-dsa-65')return false;
      const message=bytes({domain:'warden-dual-custodian-approval-v1',request:proof.request,role:a.role});
      if(!verify('sha256',message,{key:classical,dsaEncoding:'ieee-p1363'},decode(a.classical_signature))||!verify(null,message,pqc,decode(a.pqc_signature)))return false;
    }
    return hash(proof.approvals.map(({role,classical_public_spki,pqc_public_spki})=>({role,classical_public_spki,pqc_public_spki})))===pins.manifest_sha256;
  }catch{return false}
}

// Fixed local feasibility trial; all shared secrets and private keys stay in memory.
export function encryptionTrial(){
  const message=Buffer.from('FAROL-26 synthetic file only'),aad=Buffer.from('warden-pqc-local-trial-v1');
  const recipient=generateKeyPairSync('ml-kem-768'),{sharedKey,ciphertext}=encapsulate(recipient.publicKey);
  const salt=randomBytes(32),iv=randomBytes(12),derive=s=>Buffer.from(hkdfSync('sha256',s,salt,aad,32));
  const key=derive(sharedKey),goodKey=derive(decapsulate(recipient.privateKey,ciphertext));
  const enc=createCipheriv('aes-256-gcm',key,iv);enc.setAAD(aad);const encrypted=Buffer.concat([enc.update(message),enc.final()]),tag=enc.getAuthTag();
  const decrypt=(raw,k)=>{const d=createDecipheriv('aes-256-gcm',k,iv);d.setAAD(aad);d.setAuthTag(tag);return Buffer.concat([d.update(raw),d.final()])};
  const reject=(raw,k)=>{try{decrypt(raw,k);return false}catch{return true}};
  const altered=Buffer.from(encrypted);altered[0]^=1;
  const wrong=generateKeyPairSync('ml-kem-768'),wrongKey=derive(decapsulate(wrong.privateKey,ciphertext));
  const result={kem:'ML-KEM-768',aead:'AES-256-GCM',roundtrip:decrypt(encrypted,goodKey).equals(message),tampered_ciphertext_rejected:reject(altered,goodKey),wrong_recipient_rejected:reject(encrypted,wrongKey),encapsulation_ciphertext_bytes:ciphertext.length};
  [key,goodKey,wrongKey,sharedKey].forEach(b=>b.fill(0));return result;
}

// Offline contract only. No production adapter is provided. A browser/file is never a trusted adapter.
export class QuantumGate {
  #verifyProvider;#trustedPins;#seen=new Set();
  constructor(trustedPins,trustedProviderAdapter=null){this.#trustedPins=structuredClone(trustedPins);this.#verifyProvider=trustedProviderAdapter}
  async authorize(proof,now=Math.floor(Date.now()/1000)){
    if(!verifyPublicProof(proof,this.#trustedPins))return {allowed:false,reason:'dual-custody-denied'};
    if(!Number.isSafeInteger(now)||now<proof.request.issued_at||now-proof.request.issued_at>900)return {allowed:false,reason:'request-expired'};
    if(typeof this.#verifyProvider!=='function')return {allowed:false,reason:'physical-provider-unavailable'};
    let result;try{result=await this.#verifyProvider(requestDigest(proof.request))}catch{return {allowed:false,reason:'physical-provider-unavailable'}}
    if(!exact(result,['provider','mode','status','request_sha256','job','completed_at'])||result.provider!=='ibm-quantum'||result.mode!=='physical-hardware'||result.status!=='DONE'||result.request_sha256!==requestDigest(proof.request)||typeof result.job!=='string'||!/^[A-Za-z0-9_-]{8,100}$/.test(result.job)||!Number.isSafeInteger(result.completed_at)||result.completed_at<proof.request.issued_at||result.completed_at>now||now-result.completed_at>300)return {allowed:false,reason:'provider-result-denied'};
    if(this.#seen.has(result.job)||this.#seen.has(result.request_sha256))return {allowed:false,reason:'replay-denied'};
    this.#seen.add(result.job);this.#seen.add(result.request_sha256);
    // This is an in-memory policy contract, never a provider attestation or key operation.
    return {allowed:true,reason:'trusted-adapter-contract-only'};
  }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const [action,proofFile,pinFile]=process.argv.slice(2);
  if(action==='generate'&&proofFile&&pinFile){const {proof,pins}=generatePublicProof();writeFileSync(proofFile,JSON.stringify(proof,null,2)+'\n',{flag:'wx'});writeFileSync(pinFile,JSON.stringify(pins,null,2)+'\n',{flag:'wx'});console.log('Generated public-only ephemeral proof and pin. No private key output.');}
  else if(action==='verify'&&proofFile&&pinFile){const read=p=>JSON.parse(readFileSync(p,'utf8'));const ok=verifyPublicProof(read(proofFile),read(pinFile));console.log(JSON.stringify({dual_signature_verified:ok,provider_attestation:false,physical_qpu_verified:false}));if(!ok)process.exitCode=1;}
  else if(action==='trial'){const r=encryptionTrial();console.log(JSON.stringify(r));if(!r.roundtrip||!r.tampered_ciphertext_rejected||!r.wrong_recipient_rejected)process.exitCode=1;}
  else{console.error('Usage: generate <new-public-proof> <new-pin> | verify <proof> <pin> | trial');process.exitCode=1;}
}
