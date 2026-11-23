"""Guest-level Warden lab lease coordination; no cloud IAM credentials needed."""
import argparse
import hashlib
import hmac
import http.server
import json
import subprocess
import threading
import time
from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler

LAB='hackbr-warden-p0'; CONTROL='10.88.24.20'; HOSTS=tuple(f'10.88.24.{n}' for n in range(11,15)); PORT=8890; IDLE=600


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def signed_lease(key, now, remaining):
    if len(key)!=32 or not 0<remaining<=IDLE: raise ValueError('Invalid lease scope or expiry')
    payload={'lab':LAB,'issued_at':now,'expires_at':now+remaining}
    return {**payload,'signature':hmac.new(key,canonical(payload),hashlib.sha256).hexdigest()}


class LeaseReceiver:
    def __init__(self,key,wall=time.time,monotonic=time.monotonic):
        if len(key)!=32:raise ValueError('Require precisely 32 bytes of validator-specific secret')
        self.key=key;self.wall=wall;self.monotonic=monotonic;self.deadline=monotonic()+IDLE;self.last_issued=0;self.lock=threading.Lock()

    def receive(self,msg):
        try:
            if set(msg)!= {'lab','issued_at','expires_at','signature'}:return False
            fields={k:msg[k] for k in ('lab','issued_at','expires_at')};now=self.wall()
            expiry=float(fields['expires_at']);issued=float(fields['issued_at'])
            if fields['lab']!=LAB or not now-45<=issued<=now+10 or not issued<expiry<=issued+IDLE+0.1 or not now<expiry<=now+IDLE+10:return False
            check=hmac.new(self.key,canonical(fields),hashlib.sha256).hexdigest()
            if not hmac.compare_digest(check,msg['signature']):return False
            with self.lock:
                if issued<=self.last_issued:return False
                self.last_issued=issued;self.deadline=self.monotonic()+min(IDLE,expiry-now)
            return True
        except (TypeError,ValueError,KeyError):return False

    def expired(self):
        with self.lock:return self.monotonic()>=self.deadline


class AgentHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        if self.path!='/lease' or self.client_address[0]!=CONTROL:
            self.send_error(403);return
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=1024: self.send_error(400);return
            self.connection.settimeout(3);msg=json.loads(self.rfile.read(size))
            okay=self.server.receiver.receive(msg)
            self.send_response(204 if okay else 403);self.end_headers()
        except (ValueError,OSError,TypeError):self.send_error(400)


def run_agent(bind,key):
    if bind not in HOSTS:raise ValueError('Bind only one designated Warden validator private address')
    receiver=LeaseReceiver(key);server=http.server.ThreadingHTTPServer((bind,PORT),AgentHandler);server.receiver=receiver
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        while not receiver.expired():time.sleep(.5)
        print('Warden lease expired; shutting down this dedicated guest.',flush=True)
    finally:server.shutdown();server.server_close();thread.join(timeout=3)
    # Fixed command, only installed as a service on the isolated validator VMs.
    subprocess.run(['/sbin/shutdown','-h','now'],check=True)


def run_control(runtime,key_dir):
    from warden import ActivityLease
    from serve_demo import serve
    keys=[(Path(key_dir)/f'validator{i}.key').read_bytes() for i in range(1,5)]
    if any(len(k)!=32 for k in keys) or len(set(keys))!=4:raise ValueError('Four separate validator lease keys are required')
    lease=ActivityLease(idle_seconds=IDLE);stop=threading.Event();opener=build_opener(ProxyHandler({}))
    def publish():
        while not stop.is_set():
            remaining=lease.remaining_seconds()
            if remaining<=0:return
            # The heartbeat carries the deadline caused by genuine activity, not a fresh idle duration.
            for host,key in zip(HOSTS,keys):
                remaining=lease.remaining_seconds()
                if remaining<=0:return
                body=canonical(signed_lease(key,time.time(),remaining))
                try:
                    with opener.open(Request(f'http://{host}:{PORT}/lease',data=body,headers={'Content-Type':'application/json'}),timeout=3) as response:pass
                except OSError:pass
            stop.wait(15)
    thread=threading.Thread(target=publish,daemon=True);thread.start()
    try:serve(runtime,8080,8443,8444,IDLE,lease)
    finally:stop.set();thread.join(timeout=15)
    # The dedicated control systemd unit shuts down the host after this service exits.


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode',required=True)
    p=sub.add_parser('agent');p.add_argument('--bind',required=True);p.add_argument('--key-file',required=True)
    p=sub.add_parser('control');p.add_argument('--runtime',required=True);p.add_argument('--key-dir',required=True)
    args=parser.parse_args()
    if args.mode=='agent':run_agent(args.bind,Path(args.key_file).read_bytes())
    else:run_control(args.runtime,args.key_dir)

