import {createIcons} from './console-icons.mjs';
import {newSource,newRehearsal,approveRehearsal,verifyRehearsal} from './console-policy.mjs';

const $=id=>document.getElementById(id);
const names={gcp:'Google Cloud KMS',aws:'AWS KMS',azure:'Azure Key Vault'};
const titles={overview:'Warden SDSM · Visão geral',assets:'Inventário de ativos',keys:'Governança de chaves',pki:'PKI & TLS',custody:'Custódia criptográfica',bridge:'Sovereign Cloud Key Bridge',audit:'Auditoria e evidência'};
const abbreviate=s=>`${s.slice(0,6)}…${s.slice(-6)}`;
let selected='gcp',rehearsal=null,events=[],preparing=false,generation=0;
const busy=new Set();
const fingerprintPromise=newSource().then(fingerprint=>{
  $('fingerprint').textContent=abbreviate(fingerprint);$('fingerprint').title=fingerprint;$('fingerprint-alt').textContent=abbreviate(fingerprint);return fingerprint;
}).catch(()=>{$('fingerprint').textContent='Indisponível';$('fingerprint-alt').textContent='Indisponível';return null});

function log(title,detail){
  events.unshift({title,detail,time:new Date().toLocaleTimeString('pt-BR')});
  events=events.slice(0,30);
  $('audit-list').replaceChildren(...events.map(e=>{
    const entry=document.createElement('p');entry.className='audit-entry';
    const b=document.createElement('b'),small=document.createElement('small'),span=document.createElement('span');
    b.textContent=e.title;small.textContent=e.time+' · sessão local';span.textContent=e.detail;entry.append(b,small,span);return entry;
  }));
}
function switchView(view){
  if(!Object.hasOwn(titles,view))return;
  document.querySelectorAll('.view').forEach(section=>section.hidden=section.id!=='view-'+view);
  document.querySelectorAll('.nav').forEach(button=>button.dataset.view===view?button.setAttribute('aria-current','page'):button.removeAttribute('aria-current'));
  $('page-title').textContent=titles[view];window.scrollTo({top:0,behavior:'instant'});
}
function showGate(state){
  $('gate-text').textContent={initial:'Ensaio de autorização · política 3/3 necessária',prepared:'Intenção preparada · aguardando 3 de 3 autorizações',authorized:'Autorização 3/3 verificada localmente · operação KMS pendente'}[state];
  const position={initial:1,prepared:2,authorized:3}[state];
  for(let i=1;i<=4;i++){const item=$('step-'+i);item.classList.toggle('active',i===position);item.classList.toggle('complete',i<position)}
}
function reset(){generation++;rehearsal=null;busy.clear();showGate('initial')}
function selectProvider(provider){
  if(!Object.hasOwn(names,provider)||provider===selected)return;
  selected=provider;reset();
  document.querySelectorAll('.provider').forEach(button=>{
    const current=button.dataset.provider===provider;button.setAttribute('aria-checked',String(current));
    const old=button.querySelector('.radio'),icon=document.createElement('i');
    icon.className='radio icon';icon.setAttribute('data-lucide',current?'circle-dot':'circle');old.replaceWith(icon);
  });createIcons();
}
function updateApprovals(){
  const approvals=rehearsal?.approvals??[null,null,null];
  document.querySelectorAll('[data-approve]').forEach(button=>{
    const i=Number(button.dataset.approve),done=Boolean(approvals[i]);button.dataset.approved=String(done);button.textContent=done?'Assinado':busy.has(i)?'Assinando…':'Aprovar';button.disabled=done||busy.has(i);
  });$('verify-approvals').textContent=`Verificar autorização · ${approvals.filter(Boolean).length}/3`;
}
function result(message,success){const el=$('proof-result');el.className='proof-result visible'+(success?' success':'');el.textContent=message}
async function prepare(){
  if(preparing)return;preparing=true;const token=generation,button=$('prepare');button.disabled=true;button.textContent='Preparando…';
  try{
    const fingerprint=await fingerprintPromise;if(!fingerprint)throw Error('WebCrypto indisponível');
    if(!rehearsal){const next=await newRehearsal(fingerprint,selected);if(token!==generation)return;rehearsal=next;showGate('prepared');log('Intenção sintética preparada',names[selected]+' · '+next.request.nonce.slice(0,12)+' · '+abbreviate(fingerprint));}
    if(token!==generation)return;
    $('request-destination').textContent=names[rehearsal.request.destination];$('request-key').textContent=abbreviate(rehearsal.request.key);$('request-id').textContent=rehearsal.request.nonce;
    $('proof-result').className='proof-result';updateApprovals();$('transfer-dialog').showModal();
  }catch(error){$('gate-text').textContent='Ensaio não iniciado: '+error.message;}
  finally{preparing=false;button.disabled=false;button.textContent='Preparar autorização';}
}
async function approve(i){
  if(!rehearsal||busy.has(i)||rehearsal.approvals[i])return;
  const pending=rehearsal,token=generation;busy.add(i);updateApprovals();
  try{await approveRehearsal(pending,i);if(token!==generation)return;log(`Custodiante ${'ABC'[i]} assinou`,'Assinatura ECDSA da intenção local.');$('proof-result').className='proof-result';}
  catch{if(token===generation)result('Assinatura inválida. Não autorizada.',false);}
  finally{if(token===generation){busy.delete(i);updateApprovals()}}
}
async function verify(){
  const pending=rehearsal,token=generation;if(!pending)return;
  const verification=await verifyRehearsal(pending).catch(()=>({authorized:false,count:pending.approvals.filter(Boolean).length}));
  if(token!==generation)return;
  if(!verification.authorized){result(`BLOQUEADO · ${verification.count}/3 assinaturas válidas exigidas. Nenhuma operação na nuvem.`,false);log('Autorização bloqueada',`${verification.count}/3 assinaturas presentes.`);return;}
  showGate('authorized');result('3/3 assinaturas verificadas · autorização local concluída. Operação e assinatura no KMS ainda não foram testadas.',true);log('Autorização local verificada','Três assinaturas ECDSA válidas para a mesma intenção. Nenhuma chave transferida.');
}

document.querySelectorAll('.provider').forEach(button=>button.addEventListener('click',()=>selectProvider(button.dataset.provider)));
document.querySelectorAll('.nav').forEach(button=>button.addEventListener('click',()=>switchView(button.dataset.view)));
document.querySelectorAll('[data-jump]').forEach(button=>button.addEventListener('click',()=>switchView(button.dataset.jump)));
document.querySelectorAll('[data-close]').forEach(button=>button.addEventListener('click',()=>$(button.dataset.close).close()));
document.querySelectorAll('[data-approve]').forEach(button=>button.addEventListener('click',()=>approve(Number(button.dataset.approve))));
$('prepare').addEventListener('click',prepare);
$('requirements').addEventListener('click',()=>{$('requirements-provider').textContent=names[selected]+' · aceitação em nuvem pendente';$('requirements-dialog').showModal()});
$('verify-approvals').addEventListener('click',verify);
$('reset-request').addEventListener('click',()=>{$('transfer-dialog').close();reset();prepare()});
createIcons();switchView('overview');
