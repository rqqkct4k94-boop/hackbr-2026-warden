// Browser-side, independent verification of synthetic, public Warden evidence.
// No keys or data are uploaded. This is not a general-purpose TLS/PKI implementation.
const te = new TextEncoder();
const HOSTS = new Set(['alpha.warden-demo.invalid','beta.warden-demo.invalid']);
const ZERO = '0'.repeat(64);
const CUSTODIANS = ['custodian-a','custodian-b','custodian-c'];
const ensure = (condition,message) => { if(!condition) throw new Error(message); };

export function canonical(value){
  if(value===null||typeof value==='boolean'||typeof value==='number'){
    ensure(typeof value!=='number'||Number.isFinite(value),'Número inválido');return JSON.stringify(value);
  }
  if(typeof value==='string')return JSON.stringify(value).replace(/[\u007f-\uffff]/g,x=>'\\u'+x.charCodeAt(0).toString(16).padStart(4,'0'));
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  ensure(typeof value==='object'&&value!==undefined,'Objeto inválido');
  return '{'+Object.keys(value).sort().map(k=>canonical(k)+':'+canonical(value[k])).join(',')+'}';
}
export const hex = bytes => [...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,'0')).join('');
const un64 = value => {ensure(typeof value==='string'&&/^[A-Za-z0-9+/]+={0,2}$/.test(value),'Base64 inválido');return Uint8Array.from(atob(value),x=>x.charCodeAt(0));};
const sha = async bytes => hex(await crypto.subtle.digest('SHA-256',bytes));
const hashObject = obj => sha(te.encode(canonical(obj)));
const equal = (a,b) => a.length===b.length&&a.every((x,i)=>x===b[i]);

function pem(value,label){
  const regex=new RegExp('^-----BEGIN '+label+'-----\\s+([A-Za-z0-9+/=\\s]+)-----END '+label+'-----\\s*$');
  const match=String(value).match(regex);ensure(match,'PEM inválido: '+label);return un64(match[1].replace(/\s/g,''));
}
function tlv(bytes,off=0){
  ensure(off+2<=bytes.length,'DER truncado');const tag=bytes[off],first=bytes[off+1];let start=off+2,length=first;
  if(first&128){const count=first&127;ensure(count>0&&count<=4&&start+count<=bytes.length,'DER length inválido');length=0;for(let i=0;i<count;i++)length=length*256+bytes[start+i];start+=count;}
  const end=start+length;ensure(end<=bytes.length,'DER fora do limite');return {tag,start,end,raw:bytes.subarray(off,end),body:bytes.subarray(start,end)};
}
function children(node){const parts=[];let offset=0;while(offset<node.body.length){const p=tlv(node.body,offset);parts.push(p);offset=p.end;}ensure(offset===node.body.length,'DER children inválidos');return parts;}
function seq(node){ensure(node.tag===0x30,'Sequência DER esperada');return children(node);}
function outer(bytes){const x=tlv(bytes);ensure(x.end===bytes.length,'DER contém dados extras');return seq(x);}
function integer(n){ensure(n.tag===2&&n.body.length>0,'Inteiro DER esperado');let v=0n;for(const b of n.body)v=(v<<8n)+BigInt(b);return v;}
function rawEcdsa(der){const parts=outer(der);ensure(parts.length===2,'Assinatura ECDSA inválida');const result=new Uint8Array(64);for(let i=0;i<2;i++){let b=parts[i].body;ensure(parts[i].tag===2,'Inteiro ECDSA inválido');while(b.length>32&&b[0]===0)b=b.subarray(1);ensure(b.length<=32,'Tamanho ECDSA inválido');result.set(b,32*i+32-b.length);}return result;}
async function importEcdsa(spki){return crypto.subtle.importKey('spki',spki,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);}
function signatureParts(der){const p=outer(der);ensure(p.length===3&&p[2].tag===3&&p[2].body[0]===0,'Estrutura assinada inválida');return {tbs:p[0],signature:rawEcdsa(p[2].body.subarray(1))};}
function certificate(der){const signed=signatureParts(der),c=seq(signed.tbs);const i=c[0]?.tag===0xa0?1:0;ensure(c.length>=i+6,'Certificado truncado');return {...signed,serial:integer(c[i]).toString(),issuer:c[i+2].raw,subject:c[i+4].raw,spki:c[i+5].raw,extensions:c.slice(i+6).find(x=>x.tag===0xa3)};}
function dnsNames(cert){
  ensure(cert.extensions,'Extensões ausentes');const list=seq(children(cert.extensions)[0]);let san=null;
  for(const extension of list){const p=seq(extension);if(p[0]?.tag===6&&hex(p[0].body)==='551d11'){ensure(!san,'SAN duplicado');const octet=p.at(-1);ensure(octet.tag===4,'SAN inválido');san=outer(octet.body).map(n=>{ensure(n.tag===0x82,'Tipo SAN fora do escopo');return new TextDecoder().decode(n.body);});}}
  ensure(san,'SAN ausente');return san;
}
async function verifySignature(key,signed){ensure(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,signed.signature,signed.tbs.raw),'Assinatura X.509 inválida');}

function revokedSerials(der){const signed=signatureParts(der),p=seq(signed.tbs);let i=p[0]?.tag===2?1:0;i+=3; // signature, issuer, thisUpdate
  if(p[i]?.tag===0x17||p[i]?.tag===0x18)i++;
  if(p[i]?.tag!==0x30)return {signed,serials:new Set()};
  return {signed,serials:new Set(seq(p[i]).map(entry=>integer(seq(entry)[0]).toString()))};
}

export async function verifyProof(evidence,pins){
  ensure(evidence&&Array.isArray(evidence.events)&&evidence.events.length>0&&evidence.events.length<=1000,'Evidência pública inválida');
  const m=evidence.manifest;ensure(m&&typeof pins.root==='string'&&typeof pins.manifest==='string','Pins independentes ausentes');
  ensure(m.root_fingerprint===pins.root&&await hashObject(m)===pins.manifest,'Manifesto ou raiz não coincide com o pin');
  const rootDer=pem(m.root_certificate,'CERTIFICATE');ensure(await sha(rootDer)===pins.root,'Fingerprint raiz inválido');
  const root=certificate(rootDer);ensure(equal(root.issuer,root.subject),'Raiz não autoemitida');const rootKey=await importEcdsa(root.spki);await verifySignature(rootKey,root);
  const cs=m.custodians;ensure(Array.isArray(cs)&&cs.length===3&&cs.map(c=>c.id).sort().join(',')===CUSTODIANS.join(',')&&new Set(cs.map(c=>c.public_key)).size===3&&new Set(cs.map(c=>c.share_sha256)).size===3,'Identidades de custódia inválidas');
  const keys=new Map(await Promise.all(cs.map(async c=>[c.id,{key:await crypto.subtle.importKey('raw',un64(c.public_key),{name:'Ed25519'},false,['verify']),share:c.share_sha256}])));
  let prev=ZERO,authorized=0,denied=0;const requests=new Map(),finished=new Set(),certs=[],active=new Map(),revoked=new Set();
  for(let i=0;i<evidence.events.length;i++){
    const e=evidence.events[i],p=e.payload;ensure(e.seq===i+1&&e.prev_hash===prev&&await hashObject({seq:i+1,prev_hash:prev,payload:p})===e.event_hash,'Cadeia de auditoria alterada no evento '+(i+1));prev=e.event_hash;
    if(i===0)ensure(p.type==='ceremony'&&p.manifest_sha256===pins.manifest,'Cerimônia não corresponde ao manifesto');
    if(p.type==='denied'){denied++;continue;}
    if(p.type==='request'){ensure(!requests.has(p.request.id),'Solicitação duplicada');requests.set(p.request.id,p.request);continue;}
    if(p.type!=='authorized')continue;
    const req=p.request,out=p.result,ap=p.approvals;
    ensure(HOSTS.has(req.hostname)&&req.root_fingerprint===pins.root&&['issue','renew','revoke'].includes(req.kind)&&!finished.has(req.id)&&requests.has(req.id)&&canonical(requests.get(req.id))===canonical(req)&&req.created_at<=p.at&&p.at<=req.expires_at,'Vínculo ou validade de solicitação inválido');
    ensure(Array.isArray(ap)&&ap.length===3&&ap.map(x=>x.custodian_id).sort().join(',')===CUSTODIANS.join(','),'Autorizações insuficientes ou duplicadas');
    const reqSha=await hashObject(req);
    for(const a of ap){const c=keys.get(a.custodian_id);const fields={schema:a.schema,request_sha256:a.request_sha256,custodian_id:a.custodian_id,share_sha256:a.share_sha256};
      ensure(a.schema===m.schema&&a.request_sha256===reqSha&&a.share_sha256===c.share,'Aprovação não corresponde à solicitação');
      ensure(await crypto.subtle.verify({name:'Ed25519'},c.key,un64(a.signature),te.encode(canonical(fields))),'Assinatura do custodiante inválida');}
    if(req.kind==='revoke'){
      ensure(certs.some(c=>c.serial===req.previous_serial&&c.hostname===req.hostname)&&out.serial===req.previous_serial&&!revoked.has(out.serial),'Revogação inválida');
      revoked.add(out.serial);const crl=revokedSerials(pem(out.crl_pem,'X509 CRL'));await verifySignature(rootKey,crl.signed);ensure([...revoked].sort().join(',')===[...crl.serials].sort().join(','),'CRL não corresponde às revogações');
      if(active.get(req.hostname)===out.serial)active.delete(req.hostname);
    }else{
      const der=pem(out.certificate_pem,'CERTIFICATE'),leaf=certificate(der);await verifySignature(rootKey,leaf);ensure(equal(root.subject,leaf.issuer),'Emissor não corresponde à raiz');
      ensure(await sha(der)===out.fingerprint&&leaf.serial===out.serial&&dnsNames(leaf).join(',')===req.hostname,'Certificado não corresponde à solicitação');
      const csr=signatureParts(pem(req.csr_pem,'CERTIFICATE REQUEST')),csrFields=seq(csr.tbs);ensure(csrFields.length>=3&&equal(csrFields[2].raw,leaf.spki),'Chave pública do CSR difere do certificado');await verifySignature(await importEcdsa(leaf.spki),csr);
      if(req.kind==='renew')ensure(active.get(req.hostname)===req.previous_serial,'Renovação sem vínculo');else ensure(!active.has(req.hostname),'Certificado ativo duplicado');
      active.set(req.hostname,out.serial);certs.push({hostname:req.hostname,serial:out.serial,fingerprint:out.fingerprint});
    }
    finished.add(req.id);authorized++;
  }
  if(pins.audit_head)ensure(prev===pins.audit_head,'Cabeça da auditoria difere do pin');
  return {verified:true,events:evidence.events.length,authorized,denied,head:prev,certificates:certs,revoked:revoked.size,ledgerVerified:false};
}
