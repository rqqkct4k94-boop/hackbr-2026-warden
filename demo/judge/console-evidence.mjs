import {verifyProof} from './verify.mjs';

// Public sample only, not a call to an authority or private network.
export async function checkConsoleSample(proof,pins,altered=false){
  const sample=structuredClone(proof);
  if(altered)sample.events.at(-1).payload.result.fingerprint='0'.repeat(64);
  return verifyProof(sample,pins);
}

if(typeof document!=='undefined'){
  const $=id=>document.getElementById(id);
  async function check(altered){
    const status=$('console-proof-status'),details=$('console-proof-details');
    const buttons=[$('console-verify-proof'),$('console-tamper')];
    buttons.forEach(b=>b.disabled=true);status.className='bridge-status';status.textContent='Verificando no navegador…';details.textContent='';
    try{
      const [proof,pins]=await Promise.all(['/proof.json','/pins.json'].map(async path=>{const response=await fetch(path,{cache:'no-store',credentials:'omit'});if(!response.ok)throw Error('Registro público indisponível');return response.json()}));
      if(altered){
        // Establish that the authentic sample is valid before testing alteration. A fetch failure is not a pass.
        await checkConsoleSample(proof,pins);
        try{await checkConsoleSample(proof,pins,true);status.className='bridge-status warn';status.textContent='FALHA: alteração não detectada';}
        catch{status.className='bridge-status verified';status.textContent='ALTERAÇÃO DETECTADA · prova modificada recusada';details.textContent='A amostra original foi validada antes do ensaio.';}
        return;
      }
      const result=await checkConsoleSample(proof,pins);
      status.className='bridge-status verified';status.textContent='PROVA VERIFICADA · assinaturas e integridade válidas';
      details.textContent=`${result.authorized} operações autorizadas · ${result.denied} negações · ${result.certificates.length} certificados X.509 · SHA-256 do histórico: ${result.head.slice(0,16)}…`;
    }catch(error){status.className='bridge-status warn';status.textContent='Não foi possível verificar: '+error.message;}
    finally{buttons.forEach(b=>b.disabled=false);}
  }
  $('console-verify-proof').addEventListener('click',()=>check(false));
  $('console-tamper').addEventListener('click',()=>check(true));
}
