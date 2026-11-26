// Public-only WebCrypto verification; no provider access, no key operations, no uploaded files.
const canonical=o=>Array.isArray(o)?'['+o.map(canonical).join(',')+']':o!==null&&typeof o==='object'?'{'+Object.keys(o).sort().map(k=>JSON.stringify(k)+':'+canonical(o[k])).join(',')+'}':JSON.stringify(o);
const bytes=o=>new TextEncoder().encode(canonical(o));const decode=s=>Uint8Array.from(atob(s),x=>x.charCodeAt(0));
const hex=b=>Array.from(new Uint8Array(b),v=>v.toString(16).padStart(2,'0')).join('');
export async function browserCheck(proof,pins,alter=false){
  if(proof?.schema!=='warden-quantum-authority-proof-v1'||proof?.source!=='local-synthetic-ephemeral-signatures'||proof?.approvals?.length!==3||pins?.schema!==proof.schema)throw Error('Formato inválido');
  if(alter)proof=structuredClone(proof),proof.request.nonce='0'.repeat(64);
  if(!proof.request||proof.request.scope!=='synthetic-demo-only'||proof.request.operation!=='verify-fixed-document'||!['A','B','C'].every((r,i)=>proof.approvals[i].role===r))throw Error('Escopo inválido');
  const manifest=proof.approvals.map(({role,classical_public_spki,pqc_public_spki})=>({role,classical_public_spki,pqc_public_spki}));
  if(hex(await crypto.subtle.digest('SHA-256',bytes(manifest)))!==pins.manifest_sha256)throw Error('Pin não corresponde');
  let pqc=true;
  for(const a of proof.approvals){
    const msg=bytes({domain:'warden-dual-custodian-approval-v1',request:proof.request,role:a.role});
    const key=await crypto.subtle.importKey('spki',decode(a.classical_public_spki),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
    if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,decode(a.classical_signature),msg))throw Error('Assinatura clássica inválida');
    if(pqc){try{const q=await crypto.subtle.importKey('spki',decode(a.pqc_public_spki),{name:'ML-DSA-65'},false,['verify']);if(!await crypto.subtle.verify({name:'ML-DSA-65'},q,decode(a.pqc_signature),msg))throw Error('Assinatura ML-DSA inválida')}catch(e){if(e.name==='NotSupportedError')pqc=false;else throw e}}
  }
  return {classicalVerified:true,pqcVerified:pqc};
}
export async function nativePqcInputs(proof,pin,cloud,alter=false){
  const schema='warden-native-pqc-v1',scope='synthetic-demo-only';
  const eq=(a,b)=>canonical(a)===canonical(b);
  const exact=(v,keys)=>v&&typeof v==='object'&&eq(Object.keys(v).sort(),keys.sort());
  const fingerprint=async raw=>hex(await crypto.subtle.digest('SHA-256',raw));
  const sized=(value,length)=>{const raw=decode(value);if(raw.length!==length)throw Error('Tamanho criptográfico inválido');return raw};
  if(!exact(proof,['schema','scope','message','sign_public_raw_b64','kem_public_raw_b64','signature_b64','provider_report'])||proof.schema!==schema||proof.scope!==scope)throw Error('Prova inválida');
  const expectedReport={provider:'google-cloud-kms',protection:'SOFTWARE',origin:'provider-generated',versions:['1','1'],source:'owner-run-provider-metadata',provider_attestation_verified:false,warden_three_of_three_enforced_by_provider:false,quantum_gate_verified:false};
  if(!eq(proof.provider_report,expectedReport))throw Error('Metadados do operador inconsistentes');
  const msg=structuredClone(proof.message);
  if(!exact(msg,['schema','scope','purpose','nonce','audit_head','kem_public_sha256','kem_trial'])||msg.schema!==schema||msg.scope!==scope||msg.purpose!=='native-pqc-synthetic-acceptance'||!['nonce','audit_head','kem_public_sha256'].every(k=>typeof msg[k]==='string'&&/^[0-9a-f]{64}$/.test(msg[k])))throw Error('Desafio inválido');
  if(msg.audit_head!==cloud?.live_acceptance?.audit?.head)throw Error('Histórico de auditoria não corresponde');
  const sign=sized(proof.sign_public_raw_b64,1952),kem=sized(proof.kem_public_raw_b64,1184),sig=sized(proof.signature_b64,3309);
  const sp=await fingerprint(sign),kp=await fingerprint(kem);
  if(msg.kem_public_sha256!==kp||!eq(pin,{schema,audit_head:msg.audit_head,sign_public_sha256:sp,kem_public_sha256:kp}))throw Error('Pin não corresponde');
  if(!eq(msg.kem_trial,{algorithm:'ML_KEM_768',aead:'AES-256-GCM',shared_key_match:true,roundtrip:true,tampered_ciphertext_rejected:true,encapsulation_bytes:1088,hybrid_xwing_verified:false}))throw Error('Relatório KEM inconsistente');
  if(alter)msg.nonce=msg.nonce==='0'.repeat(64)?'1'.repeat(64):'0'.repeat(64);
  return {publicKey:sign, signature:sig, message:bytes(msg)};
}
export async function checkNativePqc(proof,pin,cloud,alter=false){
  const {publicKey, signature, message} = await nativePqcInputs(proof,pin,cloud,alter);
  let key;
  try{key=await crypto.subtle.importKey('raw-public',publicKey,{name:'ML-DSA-65'},false,['verify'])}catch(e){if(e.name==='NotSupportedError')return {pinsVerified:true,signatureVerified:false,supported:false};throw e}
  if(!await crypto.subtle.verify({name:'ML-DSA-65'},key,signature,message))throw Error('Assinatura ML-DSA inválida');
  return {pinsVerified:true,signatureVerified:true,supported:true,kemOperatorReportConsistent:true,providerAttestationVerified:false};
}
if(typeof document!=='undefined' && document.getElementById('verify-native')){
  const $=id=>document.getElementById(id),show=(id,message,ok)=>{$(id).textContent=message;$(id).classList.toggle('yes',ok)};
  async function check(alter){try{const get=async path=>{const r=await fetch(path,{credentials:'omit'});if(!r.ok)throw Error('Prova indisponível');return r.json()};const result=await browserCheck(await get('/quantum-proof.json'),await get('/quantum-pins.json'),alter);show('proof-status',result.pqcVerified?'VERIFICADO · 6 assinaturas ECDSA e ML-DSA válidas.':'3 assinaturas ECDSA verificadas. ML-DSA não suportada neste navegador; execute o verificador Node para validar as seis.',result.pqcVerified)}catch(e){show('proof-status','RECUSADO · '+e.message,false)}}
  $('verify').addEventListener('click',()=>check(false));$('alter').addEventListener('click',()=>check(true));$('check-gate').addEventListener('click',()=>show('gate-status','BLOQUEADO · nenhum resultado físico autenticado está disponível. Nenhuma operação de chave ou nuvem foi executada.',false));
  async function checkNative(alter){try{const get=async path=>{const r=await fetch(path,{credentials:'omit'});if(!r.ok)throw Error('Prova indisponível');return r.json()};const result=await checkNativePqc(await get('/native-pqc-proof.json'),await get('/native-pqc-pin.json'),await get('/cloud-report.json'),alter);show('native-status',result.signatureVerified?'VERIFICADO · assinatura ML-DSA-65, pins e histórico de auditoria correspondem. Relatório KEM consistente; sem atestado do provedor.':'Pins e histórico conferidos. ML-DSA não suportada neste navegador; use o verificador Python independente.',result.signatureVerified)}catch(e){show('native-status','RECUSADO · '+e.message,false)}}
  $('verify-native').addEventListener('click',()=>checkNative(false));$('alter-native').addEventListener('click',()=>checkNative(true));
}
