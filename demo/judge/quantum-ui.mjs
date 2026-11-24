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
if(typeof document!=='undefined'){
  const $=id=>document.getElementById(id),show=(id,message,ok)=>{$(id).textContent=message;$(id).classList.toggle('yes',ok)};
  async function check(alter){try{const get=async path=>{const r=await fetch(path,{credentials:'omit'});if(!r.ok)throw Error('Prova indisponível');return r.json()};const result=await browserCheck(await get('/quantum-proof.json'),await get('/quantum-pins.json'),alter);show('proof-status',result.pqcVerified?'VERIFICADO · 6 assinaturas ECDSA e ML-DSA válidas.':'3 assinaturas ECDSA verificadas. ML-DSA não suportada neste navegador; execute o verificador Node para validar as seis.',result.pqcVerified)}catch(e){show('proof-status','RECUSADO · '+e.message,false)}}
  $('verify').addEventListener('click',()=>check(false));$('alter').addEventListener('click',()=>check(true));$('check-gate').addEventListener('click',()=>show('gate-status','BLOQUEADO · nenhum resultado físico autenticado está disponível. Nenhuma operação de chave ou nuvem foi executada.',false));
}
