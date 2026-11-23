// Evaluator-only processing of public files. No cloud account, secret or write access.
const LIFECYCLE='warden-lifecycle-acceptance-v1', NATIVE='warden-native-kms-signing-v1';
const names=['hackbr-warden-p0-control','hackbr-warden-p0-v1','hackbr-warden-p0-v2','hackbr-warden-p0-v3','hackbr-warden-p0-v4'];
const sites=['alpha.warden-demo.invalid','beta.warden-demo.invalid'];
const hex64=/^[a-f0-9]{64}$/, tx=/^0x[a-f0-9]{64}$/;
const assert=(truth,message)=>{if(!truth)throw Error(message)};
const exact=(x,keys)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).sort().join(',')===keys.slice().sort().join(',');
const canonical=x=>Array.isArray(x)?'['+x.map(canonical).join(',')+']':x!==null&&typeof x==='object'?'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}':JSON.stringify(x);
const hex=b=>Array.from(new Uint8Array(b),v=>v.toString(16).padStart(2,'0')).join('');
const bytes=new TextEncoder();
const decode64=text=>{assert(typeof text==='string'&&text.length<=8192&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text),'Base64 inválido');return Uint8Array.from(atob(text),x=>x.charCodeAt(0))};

function baselineValues(wrapper){
  const record=wrapper?.live_acceptance, tls=record?.tls, audit=record?.audit, anchor=record?.anchor;
  assert(tls?.verified===true&&audit?.verified===true&&anchor?.verified===true&&anchor.receipts===4&&audit.head===anchor.audit_head&&hex64.test(audit.head)&&tx.test(anchor.transaction_hash),'Relatório GCP de referência inválido');
  const fingerprints=Object.fromEntries(tls.sites.map(x=>[x.hostname,x.fingerprint]));
  assert(exact(fingerprints,sites)&&Object.values(fingerprints).every(x=>hex64.test(x))&&new Set(Object.values(fingerprints)).size===2,'Referência TLS inválida');
  return {head:audit.head,transaction:anchor.transaction_hash,fingerprints};
}

export function verifyLifecycleReport(report,recorded){
  const base=baselineValues(recorded);
  const fields=['schema','scope','source','verified','configured_guest_idle_seconds','provider_observation_limit_seconds','observed_all_terminated_seconds','provider_transition_seconds','five_unique_disk_ids_preserved','restart_verified','four_validators_verified_after_restart','four_matching_anchor_receipts','two_distinct_tls_fingerprints','audit_head','anchor_transaction','guest_trigger_timestamp_independently_measured','completed_utc','limitations'];
  assert(exact(report,fields)&&report.schema===LIFECYCLE&&report.scope==='synthetic-warden-lab'&&report.source==='owner-run-gce-provider-observation-and-live-verification','Formato de aceitação inválido');
  assert(report.verified===true&&report.five_unique_disk_ids_preserved===true&&report.restart_verified===true&&report.four_validators_verified_after_restart===true&&report.four_matching_anchor_receipts===4,'Aceitação incompleta');
  const elapsed=report.observed_all_terminated_seconds;
  assert(report.configured_guest_idle_seconds===600&&report.provider_observation_limit_seconds===900&&Number.isFinite(elapsed)&&elapsed>=570&&elapsed<=900,'Janela de observação inválida');
  assert(exact(report.provider_transition_seconds,names)&&Object.values(report.provider_transition_seconds).every(x=>Number.isFinite(x)&&x>=570&&x<=elapsed),'As cinco transições não foram registradas dentro da janela');
  assert(report.audit_head===base.head&&report.anchor_transaction===base.transaction&&canonical(report.two_distinct_tls_fingerprints)===canonical(base.fingerprints),'Identidade TLS, auditoria ou âncora não corresponde ao relatório de referência');
  assert(report.guest_trigger_timestamp_independently_measured===false&&Number.isSafeInteger(report.completed_utc)&&Array.isArray(report.limitations)&&report.limitations.length===2&&report.limitations.every(x=>typeof x==='string'&&x.length<400),'Limites de evidência não declarados');
  return {consistent:true,providerAttestationVerified:false,observedSeconds:elapsed,disks:5,validators:4,tlsSites:2};
}

// The KMS signer returns ASN.1 DER ECDSA; WebCrypto takes fixed-width P1363.
function derToP1363(der){
  assert(der.length>=8&&der.length<=72&&der[0]===0x30&&der[1]===der.length-2,'Assinatura DER inválida');
  let offset=2;const result=new Uint8Array(64);
  for(let i=0;i<2;i++){
    assert(der[offset++]===2,'Inteiro DER inválido');const length=der[offset++];
    assert(length>=1&&length<=33&&offset+length<=der.length,'Comprimento DER inválido');let part=der.subarray(offset,offset+length);offset+=length;
    assert(!(part[0]&128),'Inteiro DER negativo');if(part.length>1&&part[0]===0){assert(part[1]&128,'Inteiro DER não canônico');part=part.subarray(1)}
    assert(part.length<=32,'Inteiro fora de P-256');result.set(part,i*32+32-part.length);
  }
  assert(offset===der.length,'Dados extras em DER');return result;
}

export async function verifyNativeKmsProof(proof,pin,recorded){
  const base=baselineValues(recorded);
  assert(exact(proof,['schema','scope','message','public_key_pem','signature_der_b64','provider_report'])&&proof.schema===NATIVE&&proof.scope==='synthetic-demo-only','Formato de prova KMS inválido');
  const message=proof.message;
  assert(exact(message,['schema','scope','nonce','audit_head','purpose'])&&message.schema===NATIVE&&message.scope==='synthetic-demo-only'&&hex64.test(message.nonce)&&message.audit_head===base.head&&message.purpose==='demonstrate-provider-native-signing','Desafio fora do escopo ou diferente da âncora de referência');
  const provider={provider:'google-cloud-kms',algorithm:'EC_SIGN_P256_SHA256',protection:'SOFTWARE',version:'1',state:'ENABLED',origin:'provider-generated',source:'owner-run-provider-metadata',provider_attestation_verified:false};
  assert(canonical(proof.provider_report)===canonical(provider),'Relatório do provedor contém alegação não suportada');
  assert(typeof proof.public_key_pem==='string'&&proof.public_key_pem.length<8192,'PEM público inválido');
  const match=proof.public_key_pem.match(/^-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END PUBLIC KEY-----\s*$/);
  assert(match,'Somente PEM de chave pública SPKI');
  const publicDer=decode64(match[1].replace(/\s/g,''));
  const fingerprint=hex(await crypto.subtle.digest('SHA-256',publicDer));
  assert(exact(pin,['schema','public_key_sha256','audit_head'])&&pin.schema===NATIVE&&pin.public_key_sha256===fingerprint&&pin.audit_head===base.head,'Pin de chave pública ou âncora não corresponde');
  const publicKey=await crypto.subtle.importKey('spki',publicDer,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const valid=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},publicKey,derToP1363(decode64(proof.signature_der_b64)),bytes.encode(canonical(message)));
  assert(valid,'Assinatura do desafio é inválida');
  return {signatureVerified:true,providerAttestationVerified:false,publicKeySha256:fingerprint,auditHead:base.head};
}

if(typeof document!=='undefined'){
  const $=id=>document.getElementById(id);
  const getFile=async(id,max)=>{const file=$(id).files[0];assert(file&&file.size<=max,'Selecione um arquivo JSON público dentro do limite');return JSON.parse(await file.text())};
  const recorded=async()=>{const response=await fetch('/cloud-report.json',{cache:'no-store',credentials:'omit'});assert(response.ok,'Relatório de referência indisponível');return response.json()};
  const output=(id,message,ok)=>{const element=$(id);element.className='bridge-status'+(ok?' verified':' warn');element.textContent=message};
  $('verify-lifecycle-file').addEventListener('click',async()=>{
    try{const r=verifyLifecycleReport(await getFile('lifecycle-file',32768),await recorded());output('lifecycle-result',`CONSISTÊNCIA VERIFICADA · relatório do operador: ${r.disks} discos, ${r.validators} validadores, ${r.tlsSites} TLS, parada observada em ${Math.round(r.observedSeconds)} s. Não é consulta independente ao GCP nem medição exata do gatilho.`,true)}
    catch(e){output('lifecycle-result','Relatório recusado: '+e.message,false)}
  });
  $('verify-native-kms-file').addEventListener('click',async()=>{
    try{const r=await verifyNativeKmsProof(await getFile('native-kms-file',32768),await getFile('native-kms-pin',8192),await recorded());output('native-kms-result',`ASSINATURA VERIFICADA · chave pública P-256 ${r.publicKeySha256.slice(0,12)}…${r.publicKeySha256.slice(-12)}. Origem SOFTWARE informada pelo operador, sem atestado de provedor/HSM nem garantia de política 3/3 no KMS.`,true)}
    catch(e){output('native-kms-result','Prova recusada: '+e.message,false)}
  });
}
