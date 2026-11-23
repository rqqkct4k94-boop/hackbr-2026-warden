"""Run the original Warden lab locally; all identities, names and keys are synthetic."""
from __future__ import annotations
import argparse
import hashlib
import http.server
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path
from warden import Authority, ActivityLease, HOSTS, canonical, digest, verify_evidence, make_approval, PolicyError


HERE = Path(__file__).resolve().parent


def read_json(p):
    return json.loads(Path(p).read_text(encoding='utf8'))


def cli(*args):
    # Each custodian's signing command is invoked in a separate OS process.
    result = subprocess.run([sys.executable, str(HERE/'warden_cli.py'), *map(str,args)],
                            check=True, capture_output=True, text=True)
    return result.stdout


def prepare(runtime):
    runtime = Path(runtime).resolve()
    if runtime.exists() and any(runtime.iterdir()):
        raise SystemExit('Refusing to overwrite an existing Warden runtime')
    if runtime == HERE or HERE in runtime.parents:
        raise SystemExit('Choose a separate private runtime directory outside the source tree')
    runtime.mkdir(parents=True, exist_ok=True)
    db, custody, manifest_path = runtime/'authority.db', runtime/'custody', runtime/'manifest.json'
    cli('initialize', '--database', db, '--custody-dir', custody, '--manifest', manifest_path)
    manifest = read_json(manifest_path)
    (runtime/'pins.json').write_bytes(canonical({'root':manifest['root_fingerprint'], 'manifest':digest(canonical(manifest))}))
    for index, host in enumerate(HOSTS):
        site = runtime/f'site-{index+1}'
        cli('create-site','--hostname',host,'--directory',site)
        req_file = site/'request.json'
        cli('request','--database',db,'--kind','issue','--csr',site/'site.csr','--output',req_file)
        req=read_json(req_file); releases=[]
        for cid in ('custodian-a','custodian-b','custodian-c'):
            release=runtime/'releases'/f'{index+1}-{cid}-release.json'
            cli('approve','--custody',custody/cid/'custody.json','--request',req_file,'--release',release)
            releases.append(release)
        if index==0:
            authority=Authority(db)
            try:
                for count in [1,2]:
                    try: authority.authorize(req['id'],[read_json(x) for x in releases[:count]])
                    except PolicyError: pass
                    else: raise RuntimeError('Unexpected authorization')
            finally: authority.close()
        output=site/'issued.json'
        cli('authorize','--database',db,'--request-id',req['id'],'--releases',*releases,'--output',output)
        (site/'site.crt').write_text(read_json(output)['certificate_pem'],encoding='ascii')
        # The generated transfer copies are no longer needed. Custody packages remain private.
        for release in releases: release.unlink()
    # Custodian packages remain in the private runtime. Never publish them.
    # For a real deployment, three independent secured custody endpoints and a transfer/wipe policy are mandatory.
    authority=Authority(db)
    try:
        pin=read_json(runtime/'pins.json')
        print(json.dumps(verify_evidence(authority.manifest(),authority.events(),pin['root'],pin['manifest']),indent=2))
    finally: authority.close()


def check_tls(port, host, root):
    context=ssl.create_default_context(cadata=root)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    with socket.create_connection(('127.0.0.1',port),timeout=3) as raw:
        with context.wrap_socket(raw,server_hostname=host) as tls:
            fp=hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
            tls.sendall(f'GET / HTTP/1.0\r\nHost: {host}\r\n\r\n'.encode())
            chunks=[]
            while True:
                chunk=tls.recv(4096)
                if not chunk: break
                chunks.append(chunk)
            http=b''.join(chunks)
            return {'hostname':host,'port':port,'fingerprint':fp,'tls':tls.version(),'http_ok':b'200 OK' in http}


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def send_bytes(self,body,ctype='application/json; charset=utf-8',status=200):
        self.send_response(status)
        self.send_header('Content-Type',ctype)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers(); self.wfile.write(body)
    def send_json(self,body,status=200): self.send_bytes(json.dumps(body,ensure_ascii=False).encode(),status=status)


class SiteHandler(QuietHandler):
    def do_GET(self):
        if self.path == '/health': return self.send_json({'status':'ok','activity_counted':False})
        if self.path != '/': return self.send_json({'error':'not found'},404)
        self.server.lease.user_activity()
        self.send_bytes(f'<!doctype html><title>Warden · {self.server.site}</title><h1>{self.server.site}</h1><p>Endpoint HTTPS sintético com certificado privado distinto.</p>'.encode(),'text/html; charset=utf-8')


class DashboardHandler(QuietHandler):
    def do_GET(self):
        if self.path=='/health': return self.send_json({'status':'ok','activity_counted':False})
        if self.path=='/':
            self.server.lease.user_activity()
            return self.send_bytes(HTML.encode(),'text/html; charset=utf-8')
        if self.path=='/api/state':
            with self.server.read_lock:
                a=Authority(self.server.runtime/'authority.db')
                try:
                    e=a.evidence(); pin=self.server.pins
                    proof=verify_evidence(e['manifest'],e['events'],pin['root'],pin['manifest'])
                    certs=[]
                    for c in a.certificates():
                        from cryptography import x509
                        from cryptography.hazmat.primitives import hashes
                        cert=x509.load_pem_x509_certificate(c['pem'].encode())
                        certs.append({'hostname':c['hostname'],'serial':c['serial'],'status':c['status'],
                                      'fingerprint':cert.fingerprint(hashes.SHA256()).hex(),'expires':cert.not_valid_after_utc.isoformat()})
                    events=[{'seq':x['seq'],'hash':x['event_hash'],'type':x['payload']['type'],
                             'label':x['payload'].get('reason',x['payload'].get('request',{}).get('kind','trusted ceremony')),
                             'host':x['payload'].get('request',{}).get('hostname',''),
                             'approvals':len(x['payload'].get('approvals',[]))} for x in e['events']]
                    return self.send_json({'root':pin['root'],'manifest':pin['manifest'],'proof':proof,'certificates':certs,'events':events,
                                           'custodians':[x['id'] for x in e['manifest']['custodians']], 'ledger':'NOT_CONNECTED','scope':'LOCAL_SYNTHETIC'})
                finally: a.close()
        if self.path=='/api/evidence':
            with self.server.read_lock:
                a=Authority(self.server.runtime/'authority.db')
                try: return self.send_json(a.evidence())
                finally: a.close()
        return self.send_json({'error':'not found'},404)

    def do_POST(self):
        if self.path!='/api/verify': return self.send_json({'error':'not found'},404)
        origin=self.headers.get('Origin')
        if origin and origin!=f'http://127.0.0.1:{self.server.server_address[1]}':
            return self.send_json({'error':'origin not permitted'},403)
        if int(self.headers.get('Content-Length','0'))>0:
            return self.send_json({'error':'request body not accepted'},400)
        self.server.lease.begin_operation()
        try:
            root=read_json(self.server.runtime/'manifest.json')['root_certificate']
            with self.server.read_lock:
                authority=Authority(self.server.runtime/'authority.db')
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import hashes
                    approved={c['hostname']:x509.load_pem_x509_certificate(c['pem'].encode()).fingerprint(hashes.SHA256()).hex()
                              for c in authority.certificates() if c['status']=='active'}
                finally: authority.close()
            result=[]
            for host,port in zip(HOSTS,self.server.site_ports):
                try:
                    check=check_tls(port,host,root)
                    check['matches_approved_certificate']=check['fingerprint']==approved.get(host)
                    result.append(check)
                except (OSError,ssl.SSLError): result.append({'hostname':host,'port':port,'http_ok':False,'error':'TLS validation failed'})
            return self.send_json({'verified':all(r['http_ok'] and r.get('matches_approved_certificate') for r in result) and len({r.get('fingerprint') for r in result})==2,'sites':result})
        finally: self.server.lease.end_operation()


def serve(runtime, dashboard_port, site_a_port, site_b_port, idle_seconds=600):
    runtime=Path(runtime).resolve(); manifest=read_json(runtime/'manifest.json'); pins=read_json(runtime/'pins.json')
    if manifest['root_fingerprint']!=pins['root'] or digest(canonical(manifest))!=pins['manifest']:
        raise SystemExit('Runtime trust pins differ')
    if idle_seconds < 1: raise ValueError('Idle timeout must be positive')
    servers=[];threads=[];started=[];lease=ActivityLease(idle_seconds=idle_seconds)
    try:
        for i,(hostname,port) in enumerate(zip(HOSTS,(site_a_port,site_b_port))):
            s=http.server.ThreadingHTTPServer(('127.0.0.1',port),SiteHandler);s.site=hostname;s.lease=lease
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(runtime/f'site-{i+1}'/'site.crt',runtime/f'site-{i+1}'/'site.key'); s.socket=ctx.wrap_socket(s.socket,server_side=True);servers.append(s)
        dashboard=http.server.ThreadingHTTPServer(('127.0.0.1',dashboard_port),DashboardHandler)
        dashboard.runtime=runtime;dashboard.pins=pins;dashboard.lease=lease;dashboard.read_lock=threading.Lock()
        dashboard.site_ports=[s.server_address[1] for s in servers];servers.append(dashboard)
        for server in servers:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread);started.append(server)
        print(json.dumps({'dashboard':f'http://127.0.0.1:{dashboard.server_address[1]}', 'sites':dashboard.site_ports,
                          'scope':'loopback only','idle_timeout_seconds':idle_seconds,'ledger':'NOT_CONNECTED'}),flush=True)
        while not lease.eligible_for_stop(): time.sleep(0.2)
        print('All local demo listeners stopped after genuine inactivity; persistent state retained.',flush=True)
    except KeyboardInterrupt: print('Demo interrupted; persistent state retained.',flush=True)
    finally:
        for s in started: s.shutdown()
        for s in servers: s.server_close()
        for t in threads:t.join(timeout=3)


HTML='''<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Warden · Controle de Confiança</title><style>
:root{font-family:Segoe UI,system-ui,sans-serif;color:#e9f5ef;background:#071610}*{box-sizing:border-box}body{margin:0}header{border-bottom:1px solid #284637;background:#0c2016;padding:30px max(20px,calc((100vw - 1100px)/2));display:flex;justify-content:space-between;align-items:center;gap:20px}h1{margin:3px 0;font-size:37px}h2{font-size:22px;margin:0 0 14px}p{line-height:1.5}.eyebrow{font-size:12px;letter-spacing:.15em;color:#84e4aa;text-transform:uppercase}.muted{color:#9cb6a7}.badge{background:#163d29;color:#b4ffca;border:1px solid #3b7b50;padding:7px 12px;border-radius:20px;font-size:13px}.wrap{max-width:1140px;margin:auto;padding:24px}.notice{padding:14px;border:1px solid #876e38;border-radius:10px;background:#2b2616;color:#f2d890;margin-bottom:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.card{background:#10291c;border:1px solid #284637;border-radius:14px;padding:19px;margin-bottom:14px}.metric{font-size:33px;font-weight:700;color:#9ef4b5}.hash{font:12px Consolas,monospace;overflow-wrap:anywhere;color:#a9d1be}.line{display:grid;grid-template-columns:75px 115px 1fr;gap:12px;border-top:1px solid #2d473a;padding:11px 0;font-size:14px}.denied{color:#ffb79a}.allowed{color:#9ef4b5}button,a.btn{font:inherit;background:#9ef4b5;color:#0a2b18;border:0;padding:10px 14px;border-radius:8px;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}button:focus,a:focus{outline:3px solid #f6cb68;outline-offset:3px}button:disabled{opacity:.6}footer{padding:20px 0;color:#9cb6a7;font-size:13px}.break{word-break:break-word}#status{min-height:24px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}@media(max-width:650px){header{align-items:start;flex-direction:column}.line{grid-template-columns:55px 90px 1fr}}</style></head><body><header><div><span class="eyebrow">ROYALCRAFTER / HACK BRASIL 2026</span><h1>Warden</h1><p>Confiança criptográfica sob controle da organização.</p></div><span class="badge">LABORATÓRIO SINTÉTICO</span></header><main class="wrap"><div class="notice"><strong>Escopo verificado:</strong> PKI privada local, três identidades de custódia e TLS real. O consenso Besu ainda não está conectado. Não é um HSM certificado, nem uma garantia de proteção contra um host de assinatura comprometido.</div><div class="grid" id="summary"></div><section class="card"><h2>Autorização de confiança · 3 de 3</h2><div class="grid" id="custodians"></div><p class="muted">Cada aprovação Ed25519 é vinculada à solicitação exata e a uma parcela criptográfica distinta. O envelope da CA só é aberto pelo serviço após três liberações válidas.</p><h3>Raiz e manifesto fixados</h3><div id="pins" class="hash"></div></section><section class="card"><h2>Verificação HTTPS independente</h2><p>Um cliente designado verifica a cadeia privada, o nome do servidor e o certificado de cada site sem ignorar erros TLS.</p><div class="row"><button id="verify">Verificar dois endpoints</button><a class="btn" href="/api/evidence" target="_blank" rel="noopener">Evidência pública JSON</a></div><p id="status" role="status" aria-live="polite"></p><div id="sites" class="grid"></div></section><section class="card"><h2>Histórico de autorização</h2><div id="events"></div></section><footer>Seiscentos segundos de inatividade encerram os serviços locais em conjunto, preservando os registros. Health checks não renovam o prazo.</footer></main><script>
const $=id=>document.getElementById(id), el=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;};const add=(p,...c)=>{c.forEach(x=>p.append(x));return p;};function metric(label,value){return add(el('article',undefined,'card'),el('div',label,'muted'),el('div',value,'metric'));}function draw(state){$('summary').replaceChildren(metric('Custodiantes',state.custodians.length+' / 3'),metric('Certificados',state.proof.certificates),metric('Operações autorizadas',state.proof.authorized_operations),metric('Auditoria local',state.proof.verified?'Válida':'Falha'));$('custodians').replaceChildren(...state.custodians.map(c=>add(el('div',undefined,'card'),el('span','CHAVE INDEPENDENTE','eyebrow'),el('h3',c),el('p','Identidade registrada · Ed25519','muted'))));$('pins').replaceChildren(el('p','CA SHA-256: '+state.root),el('p','Manifesto SHA-256: '+state.manifest));$('sites').replaceChildren(...state.certificates.map(c=>add(el('article',undefined,'card'),el('h3',c.hostname,'break'),el('span',c.status,'badge'),el('p','Serial: '+c.serial,'hash'),el('p','SHA-256: '+c.fingerprint,'hash'))));$('events').replaceChildren(...state.events.slice().reverse().map(e=>add(el('div',undefined,'line'),el('span','#'+e.seq,'muted'),el('strong',e.type,e.type==='denied'?'denied':'allowed'),add(el('div'),el('div',e.label+' '+e.host+(e.approvals?' · '+e.approvals+'/3 assinaturas':'')),el('div',e.hash,'hash')))));}async function initial(){const r=await fetch('/api/state');if(!r.ok)throw new Error('Não foi possível ler evidências');draw(await r.json());} $('verify').onclick=async()=>{const b=$('verify');b.disabled=true;$('status').textContent='Verificando cadeia TLS real…';try{const r=await fetch('/api/verify',{method:'POST'});const v=await r.json();$('status').textContent=v.verified?'✓ Dois servidores HTTPS validados com certificados distintos.':'Falha de validação; veja os endpoints.';$('sites').replaceChildren(...v.sites.map(s=>add(el('article',undefined,'card'),el('h3',s.hostname,'break'),el('span',s.http_ok?'TLS verificado':'Falha',s.http_ok?'allowed':'denied'),el('p',(s.tls||'')+' · porta local '+s.port),el('p',s.fingerprint||s.error,'hash'))));}catch(e){$('status').textContent=e.message;}finally{b.disabled=false;}};initial().catch(e=>$('status').textContent=e.message);</script></body></html>'''


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['prepare','serve']);p.add_argument('--runtime',required=True)
    p.add_argument('--dashboard-port',type=int,default=8080);p.add_argument('--site-a-port',type=int,default=8443);p.add_argument('--site-b-port',type=int,default=8444)
    p.add_argument('--idle-seconds',type=int,default=600,help='600 for normal operation; short values only for isolated acceptance tests')
    args=p.parse_args();prepare(args.runtime) if args.mode=='prepare' else serve(args.runtime,args.dashboard_port,args.site_a_port,args.site_b_port,args.idle_seconds)

