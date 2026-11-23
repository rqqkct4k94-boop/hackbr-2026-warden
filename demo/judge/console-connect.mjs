// No fetch, SDK credential handling, localStorage, cookies, or cloud mutation.
// All user-selected files stay in the browser and are strict public-data formats.
const SANDBOX_SCHEMA='warden-judge-sandbox-v1';
const ALIAS=/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,47}$/;
const REGION=/^[a-z0-9-]{1,32}$/;
const KINDS=new Set(['vm','disk','bucket','kms']);
const STATE=new Set(['running','stopped','stopping','provisioning','suspended','ready','unknown','metadata-confirmed']);
const bytes=new TextEncoder();
const assert=(v,m)=>{if(!v)throw Error(m)};
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
const hex=b=>Array.from(new Uint8Array(b),v=>v.toString(16).padStart(2,'0')).join('');
const hash=async b=>hex(await crypto.subtle.digest('SHA-256',b));
const un64=(s,max=4096)=>{assert(typeof s==='string'&&s.length<=max&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s),'Codificação inválida');return Uint8Array.from(atob(s),c=>c.charCodeAt(0))};
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v!==null&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);

export function validateSandbox(data){
  assert(exact(data,['schema','provider','environment','source','captured_at','assets']),'Formato desconhecido ou inclui campos não permitidos');
  assert(data.schema===SANDBOX_SCHEMA&&data.provider==='gcp'&&data.environment==='judge-sandbox'&&data.source==='owner-cli-read-only','Manifesto de sandbox esperado');
  assert(typeof data.captured_at==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/.test(data.captured_at)&&Number.isFinite(Date.parse(data.captured_at)),'Data inválida');
  assert(Array.isArray(data.assets)&&data.assets.length>=1&&data.assets.length<=12,'Selecione de 1 a 12 ativos');
  const found=new Set();
  const assets=data.assets.map(a=>{
    assert(exact(a,['kind','alias','region','status']),'Campos de ativo não permitidos');
    assert(KINDS.has(a.kind)&&typeof a.alias==='string'&&ALIAS.test(a.alias)&&typeof a.region==='string'&&REGION.test(a.region)&&STATE.has(a.status),'Metadados de ativo inválidos');
    assert(!found.has(a.alias.toLowerCase()),'Alias duplicado');found.add(a.alias.toLowerCase());
    return {kind:a.kind,alias:a.alias,region:a.region,status:a.status};
  });
  return {schema:SANDBOX_SCHEMA,provider:'gcp',environment:'judge-sandbox',source:'owner-cli-read-only',captured_at:data.captured_at,assets};
}

// Strict P-256 ASN.1 DER ECDSA signature -> IEEE P1363 for WebCrypto verification.
function derSignature(der){
  assert(der.length>=8&&der.length<=72&&der[0]===0x30&&der[1]===der.length-2,'Assinatura DER inválida');
  let offset=2;const out=new Uint8Array(64);
  for(let i=0;i<2;i++){
    assert(der[offset++]===2,'Inteiro DER inválido');const n=der[offset++];
    assert(n>=1&&n<=33&&offset+n<=der.length,'Tamanho DER inválido');let b=der.subarray(offset,offset+n);offset+=n;
    assert(!(b[0]&128),'Inteiro DER negativo');if(b.length>1&&b[0]===0){assert(b[1]&128,'Inteiro DER não canônico');b=b.subarray(1)}
    assert(b.length<=32,'Inteiro DER fora de P-256');out.set(b,i*32+32-b.length);
  }
  assert(offset===der.length,'Dados extras em DER');return out;
}

export function createPossessionChallenge(alias,now=Math.floor(Date.now()/1000)){
  assert(typeof alias==='string'&&ALIAS.test(alias),'Selecione um alias de chave de teste');
  assert(Number.isSafeInteger(now)&&now>=0,'Horário inválido');
  return {schema:'warden-judge-key-possession-v1',scope:'synthetic-demo-only',asset_alias:alias,provider_hint:'gcp',nonce:hex(crypto.getRandomValues(new Uint8Array(32))),issued_at:now,expires_at:now+600};
}

export function possessionChallengeBytes(challenge){return bytes.encode(canonical(challenge))}

export async function verifyPossession(challenge,publicPem,signatureB64,now=Math.floor(Date.now()/1000)){
  assert(exact(challenge,['schema','scope','asset_alias','provider_hint','nonce','issued_at','expires_at'])&&challenge.schema==='warden-judge-key-possession-v1'&&challenge.scope==='synthetic-demo-only'&&ALIAS.test(challenge.asset_alias)&&challenge.provider_hint==='gcp'&&/^[a-f0-9]{64}$/.test(challenge.nonce)&&Number.isSafeInteger(challenge.issued_at)&&challenge.expires_at===challenge.issued_at+600&&challenge.issued_at<=now&&now<=challenge.expires_at,'Desafio fora do escopo ou expirado');
  assert(typeof publicPem==='string'&&publicPem.length<=8192,'Arquivo de chave pública inválido');
  const matched=publicPem.trim().match(/^-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\r\n]+)\s+-----END PUBLIC KEY-----$/);
  assert(matched,'Somente chave pública SPKI PEM é aceita; nunca use chave privada.');
  const publicDer=un64(matched[1].replace(/\s/g,''));const pk=await crypto.subtle.importKey('spki',publicDer,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  assert(typeof signatureB64==='string'&&signatureB64.length<=2048,'Assinatura inválida');
  assert(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pk,derSignature(un64(signatureB64.trim())),possessionChallengeBytes(challenge)),'A assinatura não corresponde ao desafio e à chave pública');
  return {verified:true,fingerprint:await hash(publicDer),cloudOriginAttested:false,accountAccessGranted:false};
}

// Browser wiring is intentionally separate from validation so it can be tested with Node.
function setup(){
  const $=id=>document.getElementById(id),label=$('tenant-label'),dialog=$('environment-dialog'),file=$('sandbox-file'),notice=$('sandbox-status');
  let localInventory=null,judgeChallenge=null,isFixture=false;
  const kinds={vm:'VM / computação',disk:'Volume em bloco',bucket:'Bucket de objetos',kms:'Chave KMS'};
  const states={running:'Em execução',stopped:'Parado',stopping:'Parando',ready:'Pronto',provisioning:'Provisionando',suspended:'Suspenso',unknown:'Estado não confirmado','metadata-confirmed':'Metadados consultados'};
  function setMode(mode){
    document.body.dataset.tenant=mode;label.textContent=mode==='judge'?(isFixture?'Meu sandbox · exemplo fictício':'Meu sandbox · metadados'):'FAROL-26 · organização fictícia';$('tenant-context').hidden=mode!=='judge';
    const panel=$('judge-asset-panel');panel.hidden=mode!=='judge';
    if(mode==='judge'){
      clearChallenge();const keys=localInventory.assets.filter(a=>a.kind==='kms');$('judge-possession').hidden=isFixture||keys.length===0;$('judge-kms-select').replaceChildren(...keys.map(a=>{const opt=document.createElement('option');opt.value=a.alias;opt.textContent=a.alias;return opt}));
      $('judge-asset-summary').textContent=isFixture?`${localInventory.assets.length} ativos de exemplo · dados fictícios · nenhuma consulta ao Google Cloud`:`${localInventory.assets.length} ativo(s) selecionado(s) · Google Cloud · captura informada: ${localInventory.captured_at}`;
      $('judge-asset-list').replaceChildren(...localInventory.assets.map(a=>{
        const card=document.createElement('article');card.className='card tile';const tag=document.createElement('span');tag.className='evidence-tag planned';tag.textContent=isFixture?'Exemplo fictício · não consultado':'Metadados informados pelo operador';const h=document.createElement('h3');h.textContent=a.alias;const p=document.createElement('p');const state=isFixture?(a.status==='metadata-confirmed'?'Não consultado (exemplo)':states[a.status]+' (exemplo)'):states[a.status];p.textContent=`${kinds[a.kind]} · ${a.region} · ${state}`;card.append(tag,h,p);return card;
      }));document.querySelector('[data-view="assets"]').click();
    }else{localInventory=null;isFixture=false;clearChallenge();$('judge-possession').hidden=true;$('judge-kms-select').replaceChildren();$('judge-asset-list').replaceChildren();file.value='';notice.textContent='Nenhum manifesto carregado.';document.querySelector('[data-view="overview"]').click();}
    dialog.close();
  }
  $('environment-open').addEventListener('click',()=>dialog.showModal());
  $('use-demo-org').addEventListener('click',()=>setMode('demo'));
  $('import-sandbox').addEventListener('click',async()=>{
    try{assert(file.files.length===1&&file.files[0].size<=32768,'Selecione um manifesto JSON pequeno, sem credenciais');localInventory=validateSandbox(JSON.parse(await file.files[0].text()));isFixture=false;notice.textContent='Manifesto validado. A conta permanece no console do proprietário.';setMode('judge')}
    catch(e){notice.textContent='Manifesto rejeitado: '+(e instanceof SyntaxError?'JSON inválido.':e.message);}
  });
  $('use-fixture-sandbox').addEventListener('click',()=>{localInventory=validateSandbox({"schema":"warden-judge-sandbox-v1","provider":"gcp","environment":"judge-sandbox","source":"owner-cli-read-only","captured_at":"2026-11-23T12:00:00Z","assets":[{"kind":"vm","alias":"VM exemplo ficticio","region":"us-central1-a","status":"running"},{"kind":"disk","alias":"Volume exemplo ficticio","region":"us-central1-a","status":"ready"},{"kind":"bucket","alias":"Objetos exemplo ficticio","region":"us","status":"metadata-confirmed"},{"kind":"kms","alias":"Chave exemplo ficticio","region":"us-central1","status":"metadata-confirmed"}]});isFixture=true;setMode('judge')});
  $('disconnect-sandbox').addEventListener('click',()=>{dialog.showModal();setMode('demo')});
  const possessionStatus=$('judge-possession-result');
  function clearChallenge(){judgeChallenge=null;$('judge-challenge-preview').textContent='Nenhum desafio ativo.';$('judge-public-key').value='';$('judge-signature').value='';$('judge-challenge-download').disabled=true;$('judge-verify-possession').disabled=true;possessionStatus.textContent='Aguardando desafio.';}
  $('judge-kms-select').addEventListener('change',clearChallenge);
  $('judge-challenge-new').addEventListener('click',()=>{clearChallenge();try{judgeChallenge=createPossessionChallenge($('judge-kms-select').value);$('judge-challenge-preview').textContent=canonical(judgeChallenge);$('judge-challenge-download').disabled=false;$('judge-verify-possession').disabled=false;possessionStatus.textContent='Desafio criado; válido por 10 minutos. Assine o arquivo exato usando uma chave de teste P-256 que permaneça no seu KMS.'}catch(e){possessionStatus.textContent=e.message}});
  $('judge-challenge-download').addEventListener('click',()=>{if(!judgeChallenge)return;const url=URL.createObjectURL(new Blob([possessionChallengeBytes(judgeChallenge)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='warden-public-challenge.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)});
  $('judge-verify-possession').addEventListener('click',async()=>{try{const pk=$('judge-public-key').files[0],sig=$('judge-signature').files[0];assert(judgeChallenge&&pk&&sig&&pk.size<=8192&&sig.size<=2048,'Selecione a chave pública PEM e a assinatura Base64');const outcome=await verifyPossession(judgeChallenge,await pk.text(),await sig.text());possessionStatus.textContent=`Assinatura do desafio verificada · SHA-256 ${outcome.fingerprint.slice(0,12)}…${outcome.fingerprint.slice(-12)}. Prova de controle da chave pública apresentada; não é atestado de origem KMS ou HSM. Nenhum acesso à conta foi concedido.`}catch(e){possessionStatus.textContent='Prova rejeitada: '+e.message}});
}
if(typeof document!=='undefined')setup();
