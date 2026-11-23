import {verifyProof,verifyPresence} from '/verify.mjs';
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n;};
const add=(p,...n)=>{n.forEach(x=>p.append(x));return p;};
const metric=(name,value,detail='')=>add(el('article',undefined,'card'),el('p',name,'muted'),el('div',value,'metric'),el('p',detail,'small'));
const step=(n,name,value,ok)=>add(el('div',undefined,'step'),el('span',n,'step-n'),add(el('div'),el('strong',name,ok?'ok':'bad'),el('div',value,'small')));
const load=async path=>{const r=await fetch(path,{cache:'no-store'});if(!r.ok)throw new Error('Arquivo indisponível');return r.json();};

async function cloud(){try{const wrapper=await load('/cloud-report.json');const r=wrapper.live_acceptance;const all=r.network.verified&&r.network.validators.length===4&&r.tls.verified&&r.anchor.verified&&r.anchor.receipts===4;
  $('cloud-metrics').replaceChildren(metric('Validadores',r.network.validators.length+'/4','QBFT · rede privada'),metric('Peers por nó',r.network.nodes.map(n=>n.peers).join(' / '),'Conectividade registrada'),metric('Sites privados',r.tls.sites.length,'Certificados distintos'),metric('Recibos',r.anchor.receipts+'/4',all?'Âncora confirmada no teste':'Relatório incompleto'));
  $('cloud-anchor').textContent=r.anchor.transaction_hash+' · hash de auditoria '+r.anchor.audit_head;
}catch(e){$('cloud-metrics').replaceChildren(el('div','Relatório indisponível: '+e.message,'card bad'));}}
async function sample(tamper=false){const status=$('sample-status');const results=$('sample-results');results.replaceChildren();status.textContent='Verificando localmente…';status.className='status';
  try{const [evidence,pins]=await Promise.all([load('/proof.json'),load('/pins.json')]);
    const result=await verifyProof(evidence,pins);
    if(tamper){const changed=structuredClone(evidence);changed.events.at(-1).payload.result.fingerprint='0'.repeat(64);
      try{await verifyProof(changed,pins);status.textContent='FALHA DO VERIFICADOR — alteração não detectada';status.className='status bad';}
      catch(e){status.textContent='ALTERAÇÃO DETECTADA — '+e.message;status.className='status ok';}return;}
    render(result,status,results);
  }catch(e){status.textContent='Falha na verificação da amostra original — '+e.message;status.className='status bad';}}
function render(v,status,results){status.textContent='PROVA VERIFICADA — assinaturas e integridade válidas.';status.className='status ok';
  results.replaceChildren(step('01','Raiz e manifesto fixados','Fingerprint e assinatura da raiz válidos',true),step('02','Autorizações de custódia',v.authorized+' operações com três assinaturas distintas; '+v.denied+' negações registradas',true),step('03','Certificados X.509',v.certificates.length+' emitidos, '+v.revoked+' revogados; assinatura, CSR e hostname verificáveis',true),add(el('div',undefined,'card'),el('strong','Cabeça do histórico'),el('p',v.head,'hash')));}
$('verify-sample').onclick=()=>sample();$('tamper').onclick=()=>sample(true);
$('verify-file').onclick=async()=>{const status=$('file-status'),results=$('file-results');results.replaceChildren();try{const proof=$('proof-file').files[0],pins=$('pins-file').files[0];if(!proof||!pins)throw new Error('Selecione ambos os arquivos.');if(proof.size>2_000_000||pins.size>20_000)throw new Error('Arquivo maior que o limite da demonstração.');status.textContent='Verificando arquivos locais…';const document=JSON.parse(await proof.text()),trusted=JSON.parse(await pins.text());if(document.challenge?.schema==='warden-custody-presence-only-v1'){const v=await verifyPresence(document,trusted);status.textContent='TRÊS ASSINATURAS DE PRESENÇA VERIFICADAS';status.className='status ok';results.replaceChildren(step('01','Identidades registradas',v.identities.join(', '),true),step('02','Desafio separado da autorização','A mesma prova foi assinada pelas três chaves. Não autoriza emissão.',true),el('p','O verificador não estabelece o local físico da assinatura, a independência humana nem a hora real.','note'));}else{const v=await verifyProof(document,trusted);render(v,status,results);}}catch(e){status.textContent='Verificação recusada — '+e.message;status.className='status bad';}};
cloud();
