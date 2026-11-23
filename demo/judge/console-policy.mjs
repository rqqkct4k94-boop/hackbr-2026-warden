// Competition-only rehearsal: private keys are non-extractable, ephemeral and never leave WebCrypto.
// The three roles live in this browser; this is not independent host custody or a cloud import.
const algorithm={name:'ECDSA',namedCurve:'P-256'}, signatureAlgorithm={name:'ECDSA',hash:'SHA-256'};
const encoder=new TextEncoder();
const hex=bytes=>Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
const requestBytes=request=>encoder.encode(JSON.stringify(request));
const destinations=new Set(['gcp','aws','azure']);

export async function newSource(){
  const key=await crypto.subtle.generateKey(algorithm,false,['sign','verify']);
  const spki=await crypto.subtle.exportKey('spki',key.publicKey);
  return hex(await crypto.subtle.digest('SHA-256',spki));
}
export async function newRehearsal(fingerprint,destination){
  if(!destinations.has(destination)||!/^[A-F0-9]{64}$/.test(fingerprint))throw Error('Intenção sintética inválida');
  const request=Object.freeze({type:'warden-synthetic-authorization-rehearsal-v1',key:fingerprint,destination,nonce:hex(crypto.getRandomValues(new Uint8Array(16)))});
  const custodians=await Promise.all([0,1,2].map(()=>crypto.subtle.generateKey(algorithm,false,['sign','verify'])));
  return {request,custodians,approvals:[null,null,null]};
}
export async function approveRehearsal(rehearsal,index){
  if(!Number.isInteger(index)||index<0||index>2||!rehearsal?.custodians[index])throw Error('Identidade sintética inválida');
  const signer=rehearsal.custodians[index],data=requestBytes(rehearsal.request);
  if(rehearsal.approvals[index])return;
  const signature=await crypto.subtle.sign(signatureAlgorithm,signer.privateKey,data);
  if(!await crypto.subtle.verify(signatureAlgorithm,signer.publicKey,signature,data))throw Error('Assinatura inválida');
  rehearsal.approvals[index]=signature;
}
export async function verifyRehearsal(rehearsal,request=rehearsal?.request){
  if(!rehearsal||!request)return {authorized:false,count:0};
  const count=rehearsal.approvals.filter(Boolean).length;
  if(count!==3)return {authorized:false,count};
  const data=requestBytes(request);
  const result=await Promise.all(rehearsal.custodians.map((c,i)=>crypto.subtle.verify(signatureAlgorithm,c.publicKey,rehearsal.approvals[i],data)));
  return {authorized:result.every(Boolean),count};
}
