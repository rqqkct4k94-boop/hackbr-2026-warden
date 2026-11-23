import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import worker from './dist/worker.mjs';

test('read-only worker routes, headers and method restrictions',async()=>{
  for(const [path,method,status] of [['/','GET',200],['/proof.json','GET',200],['/','HEAD',200],['/','POST',405],['/unknown','GET',404]]){
    const r=worker.fetch(new Request('https://synthetic.invalid'+path,{method}));
    assert.equal(r.status,status);assert.ok(r.headers.get('Content-Security-Policy'));if(method==='HEAD')assert.equal(await r.text(),'');
  }
});

test('offline module loads cloud report, verifies sample and detects tampering',async()=>{
  const html=readFileSync(new URL('./dist/standalone.html',import.meta.url),'utf8');
  const code=html.split('<script type="module">')[1].split('</script>')[0];
  assert.ok(code.includes('structuredClone(embedded[path])'));
  class Element {constructor(){this.children=[];this.textContent='';}append(e){this.children.push(e);}replaceChildren(...e){this.children=e;}}
  const elements=new Map();globalThis.document={getElementById:id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);},createElement:()=>new Element()};
  try{
    await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
    await elements.get('verify-sample').onclick();assert.match(elements.get('sample-status').textContent,/PROVA VERIFICADA/);
    await elements.get('tamper').onclick();assert.match(elements.get('sample-status').textContent,/ALTERAÇÃO DETECTADA/);
    assert.equal(elements.get('cloud-metrics').children.length,4);
  }finally{delete globalThis.document;}
});
