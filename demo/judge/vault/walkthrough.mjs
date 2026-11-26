import {ml_dsa65} from '@noble/post-quantum/ml-dsa.js';
import {verifyProof} from '../verify.mjs';
import {nativePqcInputs} from '../quantum-ui.mjs';
import {assetName, assetHash, validateStorage} from './storage.mjs';

const $ = id => document.getElementById(id);
const evidence = JSON.parse($('evidence').textContent);
const steps = Array.from(document.querySelectorAll('#flow li'));
const titles = ['Quem autorizou a emissão?', 'Como o pacote foi armazenado?', 'A assinatura de auditoria confere?', 'O que mudou na cópia?'];
const nextLabels = ['Conferir armazenamento', 'Verificar auditoria', 'Alterar uma cópia e verificar'];
const pauseMs = 7500;
let stage = -1, epoch = 0, automatic = false, busy = false, timer, failed = false;

function controls() {
  $('next').hidden = stage >= 3 || failed;
  $('next').disabled = busy;
  $('next').textContent = nextLabels[stage] || '';
  $('play').hidden = stage >= 3 || failed;
  $('play').textContent = automatic ? 'Pausar demonstração' : 'Demonstrar caso';
  clearTimeout(timer);
  if (automatic && !busy && !failed && stage >= 0 && stage < 3) {
    timer = setTimeout(() => advance(false), pauseMs);
  }
}

function show(result) {
  $('verdict').className = 'result ' + (result.state === 'pending' ? 'pending' : '');
  $('verdict').textContent = result.verdict;
  $('body').replaceChildren(...result.notes.map(note => {
    const p = document.createElement('p'); p.textContent = note; return p;
  }));
  $('ids').replaceChildren();
  for (const [name, value] of result.ids) {
    const label = document.createElement('dt'), detail = document.createElement('dd');
    label.textContent = name; detail.textContent = value; $('ids').append(label, detail);
  }
  $('technical').hidden = !result.ids.length;
  steps[Math.min(stage, 2)].dataset.result = result.state || 'ok';
}

async function certificate() {
  const original = new TextEncoder().encode(evidence.issuanceText);
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', original)),
    byte => byte.toString(16).padStart(2,'0')).join('');
  if (hash !== assetHash) throw Error('O pacote difere da edição fixada.');
  const result = await verifyProof(JSON.parse(evidence.issuanceText), evidence.pins);
  const {issuance} = result;
  if (!issuance || issuance.countAfterDenial !== 0 || result.certificates.length !== 1) throw Error('Emissão incompleta.');
  return {verdict:'Verificado no navegador · 2/3 recusado, 3/3 emitiu um X.509.',
    notes:[
      'Com duas assinaturas válidas, a CA registrou zero certificados. A terceira identidade assinou o mesmo pedido. A assinatura da CA cobre o hash desse pedido e a chave corresponde ao CSR.',
      'TLS registrado na execução do PR #7: o cliente validou a cadeia e o nome ' + issuance.hostname + ', recebeu HTTP 200 em loopback e conferiu a impressão digital do certificado antes da exportação. Esta página verifica o registro de emissão offline.'
    ], ids:[['Pedido',issuance.requestId],['SHA-256 do pedido na extensão X.509',issuance.requestHash],
      ['SHA-256 do certificado apresentado pelo serviço',issuance.fingerprint],['Política',issuance.policy]]};
}
function storage() {
  if (evidence.storage === null) return {state:'pending', verdict:'Não verificado · armazenamento com CMEK pendente.',
    notes:['O ativo previsto é ' + assetName + '. Esta edição não contém uma observação do objeto no GCP.',
      'Para confirmar, o operador precisa conferir a chave simétrica indicada nos metadados da geração e o SHA-256 dos bytes relidos. O quórum de emissão pertence à CA.'],
    ids:[['SHA-256 esperado do pacote local',assetHash]]};
  const r = validateStorage(evidence.storage);
  return {verdict:'Registro do operador · CMEK e releitura da mesma geração correspondem.',
    notes:['O operador observou kmsKeyName em ' + assetName + ' e releu ' + r.size_bytes + ' bytes da geração indicada. O navegador conferiu os campos públicos e o digest do relatório.',
      'A origem depende do relato do operador. O serviço de armazenamento gerencia o acesso à CMEK com suas próprias permissões.'],
    ids:[['Geração observada',r.generation],['Versão da CMEK simétrica',r.kms_key_version ?? 'Não informada pelo serviço'],
      ['SHA-256 do nome completo observado em kmsKeyName',r.kms_key_sha256],['SHA-256 do pacote e da releitura',r.readback_sha256]]};
}
async function audit(alter) {
  const proof = structuredClone(evidence.pqc);
  if (alter) proof.message.nonce = (proof.message.nonce[0] === '0' ? '1' : '0') + proof.message.nonce.slice(1);
  const cloud = {live_acceptance:{audit:{head:evidence.cloudHead}}};
  const inputs = await nativePqcInputs(proof,evidence.pqcPins,cloud);
  const valid = ml_dsa65.verify(inputs.signature,inputs.message,inputs.publicKey);
  if (alter) {
    if (valid) throw Error('A cópia modificada foi aceita.');
    return {verdict:'Cópia recusada · a assinatura deixou de corresponder à mensagem.',
      notes:['Um dígito do desafio foi trocado em uma cópia local. A mesma chave e a mesma assinatura passaram com a mensagem original e falharam com a mensagem alterada.',
        'Percurso concluído. Emissão verificada. ' + (evidence.storage ? 'Armazenamento com registro do operador.' : 'Armazenamento CMEK pendente.') + ' Auditoria pós-quântica verificada em registro separado.'],
      ids:[['Desafio original',evidence.pqc.message.nonce],['Desafio alterado',proof.message.nonce]]};
  }
  if (!valid) throw Error('Assinatura ML-DSA original inválida.');
  return {verdict:'Verificado no navegador · assinatura ML-DSA-65 válida.',
    notes:['A assinatura cobre o relatório do ensaio pós-quântico registrado pelo operador e a referência ao histórico daquele ensaio. A origem da chave no KMS foi relatada pelo operador.',
      'Esse histórico é de outra execução. A assinatura pós-quântica não cobre o certificado nem o objeto FAROL-26. Altere a cópia para testar a assinatura.'],
    ids:[['Cabeça de auditoria do ensaio PQC',proof.message.audit_head],['Cabeça da emissão FAROL-26',evidence.pins.audit_head],
      ['SHA-256 da chave pública ML-DSA',evidence.pqcPins.sign_public_sha256]]};
}

async function advance(moveFocus) {
  if (busy || failed || stage >= 3) return;
  busy = true;
  const run = ++epoch;
  stage++;
  $('title').textContent = titles[stage];
  if (moveFocus) $('title').focus();
  steps.forEach((step,i) => {
    if (i === Math.min(stage,2)) step.setAttribute('aria-current','step');
    else step.removeAttribute('aria-current');
  });
  $('verdict').textContent = 'Conferindo evidência…';
  $('verdict').className = 'result'; $('body').replaceChildren();
  $('technical').open = false; $('technical').hidden = true;
  controls();
  try {
    const result = stage === 0 ? await certificate() : stage === 1 ? storage() : await audit(stage === 3);
    if (run === epoch) show(result);
  } catch (error) {
    if (run === epoch) {
      failed = true; automatic = false; $('verdict').className = 'error';
      $('verdict').textContent = 'Verificação interrompida · ' + error.message;
    }
  } finally {
    if (run === epoch) { busy = false; controls(); }
  }
}
$('start').onclick = () => {
  automatic = $('auto').checked; $('intro').hidden = true; $('flow').hidden = false; advance(true);
};
$('next').onclick = () => advance(true);
$('play').onclick = () => { automatic = !automatic; controls(); };
$('reset').onclick = () => {
  epoch++; clearTimeout(timer); stage = -1; busy = false; failed = false; automatic = false;
  steps.forEach(step => {delete step.dataset.result; step.removeAttribute('aria-current');});
  $('flow').hidden = true; $('intro').hidden = false; $('auto').checked = false; $('start').focus();
};
