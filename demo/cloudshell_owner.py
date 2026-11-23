"""Owner-run Google Cloud Shell deployment for the isolated Warden P0 lab.

This is a staged, unexecuted cloud workflow; do not claim success until its live gate passes.
No project-wide IAM grants, service accounts, billing changes, public RPC or production edits.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import json
import math
import os
import re
import secrets
import shlex
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

PROJECT=os.environ.get('WARDEN_DEMO_PROJECT',''); ZONE='us-central1-a'; REGION='us-central1'
PREFIX='hackbr-warden-p0'; NETWORK=PREFIX+'-net'; SUBNET=PREFIX+'-subnet'; CIDR='10.88.24.0/24'
IMAGE='hyperledger/besu:26.11.1'; ROOT=Path(__file__).resolve().parent
NODES=[(f'{PREFIX}-v{i}',f'10.88.24.{10+i}','e2-medium','validator') for i in range(1,5)]
CONTROL=(PREFIX+'-control','10.88.24.20','e2-small','control'); ALL=NODES+[CONTROL]
LABELS={'hackbr':'warden-p0','scope':'synthetic'}
RUNTIME_NAME='warden-hackbr-p0-private'


def owner_project():
    if not re.fullmatch(r'[a-z][a-z0-9-]{4,28}[a-z0-9]',PROJECT):
        raise ValueError('Set WARDEN_DEMO_PROJECT to the explicit, owner-approved project ID. No source-embedded account identifiers.')
    return PROJECT


def run(args,timeout=180,check=True):
    result=subprocess.run([str(x) for x in args],text=True,capture_output=True,timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr[-750:]}')
    return result


def gc(*args,timeout=180,check=True):
    return run(['gcloud','--quiet',f'--project={owner_project()}',*args],timeout,check)


def gcjson(*args,timeout=180):return json.loads(gc(*args,'--format=json',timeout=timeout).stdout or 'null')
def ssh(name,command,timeout=180,check=True):
    if name not in {n[0] for n in ALL}:raise ValueError('Outside dedicated Warden scope')
    return gc('compute','ssh',name,f'--zone={ZONE}','--tunnel-through-iap','--ssh-key-expire-after=30m',f'--command={command}',timeout=timeout,check=check)


def scp(source,name,destination,timeout=120):
    if name not in {n[0] for n in ALL}:raise ValueError('Outside dedicated Warden scope')
    return gc('compute','scp',source,f'{name}:{destination}',f'--zone={ZONE}','--tunnel-through-iap','--ssh-key-expire-after=30m',timeout=timeout)


def inventory():
    account=gc('auth','list','--filter=status:ACTIVE','--format=value(account)').stdout.strip()
    active=gc('config','get-value','project').stdout.strip()
    if not account:raise RuntimeError('Cloud Shell has no active owner authentication')
    if active!=PROJECT:raise RuntimeError(f'Choose the confirmed project first: gcloud config set project {PROJECT}')
    project=gcjson('projects','describe',PROJECT);billing=gcjson('billing','projects','describe',PROJECT)
    if project.get('lifecycleState')!='ACTIVE' or not billing.get('billingEnabled'):
        raise RuntimeError('Project is not active with existing billing; no billing change will be made')
    instances=gcjson('compute','instances','list') or [];disks=gcjson('compute','disks','list') or []
    networks=gcjson('compute','networks','list') or [];subnets=gcjson('compute','networks','subnets','list') or []
    firewalls=gcjson('compute','firewall-rules','list') or []
    services=gcjson('services','list','--enabled') or []
    enabled={x.get('config',{}).get('name') for x in services}
    prefixed=[x.get('name') for group in (instances,disks,networks,subnets,firewalls) for x in group if str(x.get('name','')).startswith(PREFIX)]
    return {'project':PROJECT,'project_active':True,'billing_enabled':True,'active_account_present':True,
            'instance_count':len(instances),'disk_count':len(disks),'network_count':len(networks),'lab_name_collisions':prefixed,
            'required_apis_present':all(x in enabled for x in ('compute.googleapis.com','iap.googleapis.com'))}


def plan():
    inv=inventory()
    return {'inventory':inv,'scope':'new synthetic-only network; no peering, no production changes, no billing changes',
            'network':NETWORK,'subnet':CIDR,'zone':ZONE,'instances':[{'name':x[0],'internal_ip':x[1],'machine':x[2],'role':x[3],'persistent_disk_gb':20} for x in ALL],
            'estimated_compute_usd_per_hour':0.15078,'estimate_excludes_disk_egress_and_ip_charges':True,
            'billing_changes':False,'usage_against_existing_credits_only':True,'idle_shutdown':'signed deadline from real activity; no health refresh; 600 seconds; preserve disks'}


def validate_instance(node,actual):
    name,ip,machine,role=node
    nics=actual.get('networkInterfaces',[]);disks=actual.get('disks',[])
    if (actual.get('name')!=name or not actual.get('zone','').endswith('/'+ZONE)
            or actual.get('labels',{}).get('hackbr')!='warden-p0' or actual.get('labels',{}).get('scope')!='synthetic'
            or not actual.get('machineType','').endswith('/'+machine) or actual.get('serviceAccounts')
            or len(nics)!=1 or nics[0].get('networkIP')!=ip or not nics[0].get('network','').endswith('/'+NETWORK)
            or len(disks)!=1 or disks[0].get('autoDelete') is not False or disks[0].get('type')=='SCRATCH'):
        raise RuntimeError(f'Refusing to operate on {name}: exact isolated lab configuration did not match')
    tags=set(actual.get('tags',{}).get('items',[]));expected={PREFIX,PREFIX+'-'+role}
    if tags!=expected:raise RuntimeError(f'Refusing unexpected network tags on {name}')
    return {'name':name,'status':actual['status'],'disk':disks[0].get('source'),'machine':machine}


def status(require_all=True):
    existing={x['name']:x for x in gcjson('compute','instances','list') or [] if x.get('name') in {n[0] for n in ALL}}
    if require_all and len(existing)!=5:raise RuntimeError('The exact five-VM lab is incomplete; no start/stop issued')
    return [validate_instance(n,existing[n[0]]) for n in ALL if n[0] in existing]


def change_state(action,partial=False):
    if action not in ('start','stop'):raise ValueError('Only start or stop of exact lab instances is supported')
    statuses=status(require_all=not partial);names=[x['name'] for x in statuses if x['status']!=('RUNNING' if action=='start' else 'TERMINATED')]
    if names:gc('compute','instances',action,*names,f'--zone={ZONE}',timeout=300)
    return status(require_all=not partial)


def startup_script(role):
    packages='python3 python3-venv ca-certificates curl'+(' docker.io' if role=='validator' else '')
    return f'''#!/bin/bash
set -euo pipefail
if [ -f /var/lib/warden-p0-configured ]; then exit 0; fi
# Initial owner-authorized bootstrap is bounded. A failed/abandoned bootstrap powers off.
systemd-run --unit=warden-bootstrap-guard --on-active=600s /sbin/shutdown -h now || true
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq {packages}
{'systemctl enable --now docker' if role=='validator' else 'true'}
touch /var/lib/warden-p0-ready
'''


def instance_args(node,startup):
    name,ip,machine,role=node
    return ['compute','instances','create',name,f'--zone={ZONE}',f'--machine-type={machine}',f'--subnet={SUBNET}',f'--private-network-ip={ip}',
            '--network-tier=STANDARD','--image-family=ubuntu-2404-lts-amd64','--image-project=ubuntu-os-cloud',
            '--boot-disk-size=20GB','--boot-disk-type=pd-balanced','--no-boot-disk-auto-delete','--deletion-protection',
            '--no-service-account','--no-scopes','--metadata=block-project-ssh-keys=TRUE',f'--metadata-from-file=startup-script={startup}',
            f'--tags={PREFIX},{PREFIX}-{role}','--labels=hackbr=warden-p0,scope=synthetic']


def write(path,value):path.write_text(value,encoding='utf8')
def copy_sources(dst,*names):
    for name in names:shutil.copy2(ROOT/name,dst/name)


def validator_installer(index,enodes):
    name,ip,_,_=NODES[index];peers=','.join(x for i,x in enumerate(enodes) if i!=index)
    return f'''#!/bin/bash
set -euo pipefail
cd /var/lib/warden-p0-staging
test ! -e /var/lib/warden-p0-configured
systemctl restart warden-bootstrap-guard.timer
id -u warden-besu >/dev/null 2>&1 || useradd --system --home-dir /var/lib/warden-besu --shell /usr/sbin/nologin warden-besu
install -d -m 755 /opt/warden-p0
install -d -o warden-besu -g warden-besu -m 700 /var/lib/warden-besu
install -o warden-besu -g warden-besu -m 600 key /var/lib/warden-besu/key
install -m 644 genesis.json /opt/warden-p0/genesis.json
install -m 755 cloud_idle.py /opt/warden-p0/cloud_idle.py
install -m 600 lease.key /etc/warden-p0-lease.key
docker pull {IMAGE}
uid=$(id -u warden-besu); gid=$(id -g warden-besu)
cat > /etc/systemd/system/warden-besu.service <<EOF
[Unit]
Description=Dedicated Warden QBFT validator
After=network-online.target docker.service
Requires=docker.service
[Service]
Type=simple
ExecStart=/usr/bin/docker run --rm --name {name} --network host --user $uid:$gid --memory=3g --env "BESU_OPTS=-Xms512m -Xmx2048m -XX:-UseBASE64Intrinsics" --mount type=bind,src=/var/lib/warden-besu,dst=/lab/data --mount type=bind,src=/opt/warden-p0/genesis.json,dst=/lab/genesis.json,readonly {IMAGE} --data-path=/lab/data --genesis-file=/lab/genesis.json --node-private-key-file=/lab/data/key --p2p-host={ip} --p2p-port=30303 --bootnodes={peers} --rpc-http-enabled --rpc-http-host={ip} --rpc-http-port=8545 --rpc-http-api=ETH,NET,QBFT --host-allowlist=localhost,127.0.0.1,{ip}
ExecStop=/usr/bin/docker stop -t 30 {name}
TimeoutStopSec=45
Restart=no
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/warden-lease.service <<EOF
[Unit]
Description=Dedicated Warden signed activity-deadline receiver
After=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/warden-p0/cloud_idle.py agent --bind {ip} --key-file /etc/warden-p0-lease.key
ExecStopPost=/sbin/shutdown -h now
Restart=no
[Install]
WantedBy=multi-user.target
EOF
if [ -f custody.json ]; then
 id -u warden-custodian >/dev/null 2>&1 || useradd --system --home-dir /var/lib/warden-custodian --shell /usr/sbin/nologin warden-custodian
 install -d -m 700 -o warden-custodian -g warden-custodian /var/lib/warden-custodian
 install -m 600 -o warden-custodian -g warden-custodian custody.json /var/lib/warden-custodian/custody.json
 install -m 755 warden.py warden_cli.py /opt/warden-p0/
 python3 -m venv /opt/warden-p0/custody-venv
 /opt/warden-p0/custody-venv/bin/pip -q install -r requirements.txt
fi
systemctl daemon-reload
systemctl enable --now warden-lease.service warden-besu.service
systemctl is-active --quiet warden-lease.service
systemctl is-active --quiet warden-besu.service
touch /var/lib/warden-p0-configured
systemctl stop warden-bootstrap-guard.timer
'''


CONTROL_INSTALLER='''#!/bin/bash
set -euo pipefail
cd /var/lib/warden-p0-staging
test ! -e /var/lib/warden-p0-configured
systemctl restart warden-bootstrap-guard.timer
id -u warden-control >/dev/null 2>&1 || useradd --system --home-dir /var/lib/warden-control --shell /usr/sbin/nologin warden-control
install -d -m 755 /opt/warden-p0
install -d -m 700 -o warden-control -g warden-control /var/lib/warden-control
install -m 755 warden.py warden_cli.py serve_demo.py cloud_idle.py besu_lab.py /opt/warden-p0/
python3 -m venv /opt/warden-p0/venv
/opt/warden-p0/venv/bin/pip -q install -r requirements.txt -r requirements-besu.txt
cp -a runtime lease-keys besu /var/lib/warden-control/
chown -R warden-control:warden-control /var/lib/warden-control
chmod -R go-rwx /var/lib/warden-control
cat > /etc/systemd/system/warden-control.service <<EOF
[Unit]
Description=Dedicated Warden P0 dashboard and traceable activity coordinator
After=network-online.target
[Service]
Type=simple
User=warden-control
Group=warden-control
ExecStart=/opt/warden-p0/venv/bin/python /opt/warden-p0/cloud_idle.py control --runtime /var/lib/warden-control/runtime --key-dir /var/lib/warden-control/lease-keys
ExecStopPost=+/sbin/shutdown -h now
Restart=no
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now warden-control.service
systemctl is-active --quiet warden-control.service
touch /var/lib/warden-p0-configured
systemctl stop warden-bootstrap-guard.timer
'''


def archive_dir(source,target):
    with tarfile.open(target,'x:gz') as tf:
        for file in sorted(source.iterdir()):tf.add(file,arcname=file.name,recursive=True)
    target.chmod(0o600)


def prepare(runtime):
    from besu_lab import prepare as besu_prepare
    from serve_demo import prepare as pki_prepare
    owner_project();runtime=Path(runtime).resolve()
    if runtime.exists() or runtime==ROOT or ROOT in runtime.parents:
        raise ValueError('Use a NEW private directory outside this source tree; no overwrite')
    if shutil.which('docker') is None:raise RuntimeError('Docker unavailable in owner Cloud Shell; no cloud resources created')
    run(['docker','info'],timeout=30);runtime.mkdir(mode=0o700,parents=True)
    besu_prepare(runtime/'besu-generation',IMAGE);pki_prepare(runtime/'pki-generation')
    besu=runtime/'besu-generation';pki=runtime/'pki-generation';manifest=json.loads((besu/'network-manifest.json').read_text())
    key_dirs=sorted(x for x in (besu/'networkFiles'/'keys').iterdir() if x.is_dir())
    pub=[(x/'key.pub').read_text().strip().removeprefix('0x') for x in key_dirs]
    if len(pub)!=4 or any(not re.fullmatch(r'[0-9a-fA-F]{128}',x) for x in pub):raise RuntimeError('Unexpected Besu-generated public keys')
    enodes=[f'enode://{key}@{node[1]}:30303' for key,node in zip(pub,NODES)]
    keys=[secrets.token_bytes(32) for _ in range(4)];bundles=runtime/'bundles';bundles.mkdir(mode=0o700)
    for i,node in enumerate(NODES):
        stage=runtime/f'stage-v{i+1}';stage.mkdir(mode=0o700)
        copy_sources(stage,'cloud_idle.py','warden.py','warden_cli.py','requirements.txt')
        shutil.copy2(besu/'nodes'/f'validator{i+1}'/'key',stage/'key');shutil.copy2(besu/'networkFiles'/'genesis.json',stage/'genesis.json')
        (stage/'lease.key').write_bytes(keys[i]);(stage/'lease.key').chmod(0o600)
        if i<3:shutil.copy2(pki/'custody'/f'custodian-{chr(97+i)}'/'custody.json',stage/'custody.json')
        write(stage/'install.sh',validator_installer(i,enodes));archive_dir(stage,bundles/(node[0]+'.tar.gz'))
    stage=runtime/'stage-control';stage.mkdir(mode=0o700)
    copy_sources(stage,'warden.py','warden_cli.py','serve_demo.py','cloud_idle.py','besu_lab.py','requirements.txt','requirements-besu.txt')
    destination=stage/'runtime';destination.mkdir(mode=0o700)
    for file in ['authority.db','manifest.json','pins.json']:shutil.copy2(pki/file,destination/file)
    for i in (1,2):
        site=destination/f'site-{i}';site.mkdir(mode=0o700)
        for file in ['site.key','site.crt']:shutil.copy2(pki/f'site-{i}'/file,site/file)
    lease=stage/'lease-keys';lease.mkdir(mode=0o700)
    for i,key in enumerate(keys,1):(lease/f'validator{i}.key').write_bytes(key);(lease/f'validator{i}.key').chmod(0o600)
    control_besu=stage/'besu';control_besu.mkdir(mode=0o700);shutil.copy2(besu/'anchor.key',control_besu/'anchor.key')
    manifest['rpc_hosts']=[x[1] for x in NODES];write(control_besu/'network-manifest.json',json.dumps(manifest,indent=2))
    write(stage/'install.sh',CONTROL_INSTALLER);archive_dir(stage,bundles/(CONTROL[0]+'.tar.gz'))
    for role in ('validator','control'):write(runtime/f'startup-{role}.sh',startup_script(role))
    write(runtime/'prepared.json',json.dumps({'project':PROJECT,'zone':ZONE,'image':IMAGE,'scope':PREFIX,'prepared':True}))
    print('Private deployment bundles prepared. Never share this runtime, its archives or root/custody/node keys.')


def validate_network_recovery(networks,subnets,firewalls,instances,disks):
    """Resume only an interrupted network/subnet operation, before any VM or disk creation."""
    exact=[n for n in networks if n.get('name')==NETWORK]
    if len(exact)!=1 or exact[0].get('autoCreateSubnetworks') is not False or exact[0].get('peerings'):
        raise RuntimeError('Interrupted lab VPC was not uniquely found as a custom, unpeered network')
    if any(str(x.get('name','')).startswith(PREFIX) for group in (instances,disks,firewalls) for x in group):
        raise RuntimeError('Network-only recovery refuses any existing lab VM, disk or firewall')
    if any(str(x.get('network','')).endswith('/'+NETWORK) for x in firewalls):
        raise RuntimeError('Network-only recovery refuses unexpected existing firewall rules on the lab VPC')
    if any(str(nic.get('network','')).endswith('/'+NETWORK) for vm in instances for nic in vm.get('networkInterfaces',[])):
        raise RuntimeError('Network-only recovery refuses a VPC already used by a VM')
    attached=[x for x in subnets if str(x.get('network','')).endswith('/'+NETWORK)]
    if any(str(x.get('name','')).startswith(PREFIX) and x not in attached for x in subnets):
        raise RuntimeError('Unexpected lab subnet in another network')
    if len(attached)>1:raise RuntimeError('Network-only recovery refuses multiple existing lab subnets')
    if attached:
        subnet=attached[0]
        if (subnet.get('name')!=SUBNET or subnet.get('ipCidrRange')!=CIDR or
            not subnet.get('region','').endswith('/'+REGION) or subnet.get('purpose','PRIVATE')!='PRIVATE'):
            raise RuntimeError('Existing lab subnet differs from the exact authorised plan')
    return bool(attached)


def recover_network():
    return validate_network_recovery(gcjson('compute','networks','list') or [],gcjson('compute','networks','subnets','list') or [],
                                     gcjson('compute','firewall-rules','list') or [],gcjson('compute','instances','list') or [],
                                     gcjson('compute','disks','list') or [])


def progress(message):print('[Warden P0] '+message,flush=True)


def create_infrastructure(runtime,resume_network=False):
    subnet_present=False
    if resume_network:
        progress('Checking the exact interrupted custom VPC; no prior VM/disk may exist.')
        subnet_present=recover_network();progress('Existing isolated VPC verified; preserving it.')
    else:
        progress('Creating dedicated custom VPC (can take a few minutes).')
        gc('compute','networks','create',NETWORK,'--subnet-mode=custom',timeout=300)
    if not subnet_present:
        progress('Creating the private subnet (wait for Google Cloud to finish).')
        gc('compute','networks','subnets','create',SUBNET,f'--network={NETWORK}',f'--region={REGION}',f'--range={CIDR}',timeout=300)
    else:progress('Previously created subnet matches the plan; preserving it.')
    # Every rule is within the dedicated new VPC. No ingress from the public internet.
    progress('Creating the three narrowly scoped IAP/P2P/control firewall rules.')
    f=['compute','firewall-rules','create']
    common=[f'--network={NETWORK}','--direction=INGRESS','--action=ALLOW']
    gc(*f,PREFIX+'-iap',*common,'--rules=tcp:22','--source-ranges=35.235.240.0/20',f'--target-tags={PREFIX}')
    gc(*f,PREFIX+'-peer',*common,'--rules=tcp:30303,udp:30303',f'--source-tags={PREFIX}-validator',f'--target-tags={PREFIX}-validator')
    gc(*f,PREFIX+'-control',*common,'--rules=tcp:8545,tcp:8890',f'--source-tags={PREFIX}-control',f'--target-tags={PREFIX}-validator')
    progress('Creating exactly five isolated VMs and retained boot disks; allow several minutes.')
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        jobs=[pool.submit(gc,*instance_args(n,runtime/f'startup-{n[3]}.sh'),timeout=300) for n in ALL]
        for job in jobs:job.result()
    status();progress('Five exact lab VM configurations validated.')


def configure(node,runtime):
    name=node[0];deadline=time.monotonic()+240
    progress(f'Waiting for bounded startup of {name}.')
    while time.monotonic()<deadline:
        try:
            if ssh(name,'test -f /var/lib/warden-p0-ready',timeout=35,check=False).returncode==0:break
        except subprocess.TimeoutExpired:pass
        time.sleep(8)
    else:raise RuntimeError(f'{name} did not finish its bounded bootstrap')
    progress(f'Installing private bundle on {name} via IAP.')
    ssh(name,'umask 077; mkdir -m 700 -p "$HOME/warden-p0-staging"; sudo systemctl restart warden-bootstrap-guard.timer')
    scp(runtime/'bundles'/(name+'.tar.gz'),name,'~/warden-p0-staging/bundle.tar.gz')
    ssh(name,'sudo install -d -m 700 /var/lib/warden-p0-staging && sudo tar -xzf "$HOME/warden-p0-staging/bundle.tar.gz" -C /var/lib/warden-p0-staging && sudo bash /var/lib/warden-p0-staging/install.sh',timeout=420)
    # Remove only the two exact temporary transfer locations created by this workflow.
    ssh(name,'set -e; sudo test ! -L /var/lib/warden-p0-staging; test "$(sudo readlink -f /var/lib/warden-p0-staging)" = /var/lib/warden-p0-staging; sudo find /var/lib/warden-p0-staging -depth -mindepth 1 -delete; sudo rmdir /var/lib/warden-p0-staging; rm -f "$HOME/warden-p0-staging/bundle.tar.gz"',timeout=60)
    progress(f'{name} installation completed.')


def cloud_verify(anchor=False):
    status();controller=CONTROL[0];base='/var/lib/warden-control';py='/opt/warden-p0/venv/bin/python';src='/opt/warden-p0'
    cmd=f'sudo -u warden-control {py} {src}/besu_lab.py verify --runtime {base}/besu'
    for _ in range(10):
        try: network=json.loads(ssh(controller,cmd,timeout=45).stdout);break
        except (RuntimeError,ValueError):time.sleep(8)
    else:raise RuntimeError('Four-validator live verification did not pass')
    tls=json.loads(ssh(controller,'curl --max-time 10 -fsS -X POST http://127.0.0.1:8080/api/verify').stdout)
    state=json.loads(ssh(controller,'curl --max-time 10 -fsS http://127.0.0.1:8080/api/state').stdout)
    if not tls.get('verified') or not network.get('verified') or not state.get('proof',{}).get('verified'):
        raise RuntimeError('Local live TLS or audit/network acceptance did not pass')
    result={'network':network,'tls':tls,'audit':state['proof'],'anchor':None}
    head=state['proof']['head'];receipt=f'{base}/besu/anchor-{head}.json';evidence=f'{base}/evidence.json'
    if anchor:
        ssh(controller,f'sudo test -f {evidence} || sudo -u warden-control {py} {src}/warden_cli.py evidence --database {base}/runtime/authority.db --output {evidence}')
        cmd=f'sudo -u warden-control {py} {src}/besu_lab.py anchor --runtime {base}/besu --evidence {evidence} --pins {base}/runtime/pins.json'
        result['anchor']=json.loads(ssh(controller,cmd,timeout=100).stdout)
    elif ssh(controller,f'sudo test -f {receipt}',check=False).returncode==0:
        cmd=f'sudo -u warden-control {py} {src}/besu_lab.py verify-receipt --runtime {base}/besu --receipt {receipt}'
        result['anchor']=json.loads(ssh(controller,cmd,timeout=65).stdout)
    return result


def apply(runtime,credit_brl,resume_network=False):
    owner_project();runtime=Path(runtime).resolve();meta=json.loads((runtime/'prepared.json').read_text())
    if meta!={'project':PROJECT,'zone':ZONE,'image':IMAGE,'scope':PREFIX,'prepared':True}:raise ValueError('Prepared runtime does not match exact lab scope')
    inv=inventory()
    if resume_network:
        if NETWORK not in inv['lab_name_collisions'] or any(x not in (NETWORK,SUBNET) for x in inv['lab_name_collisions']):
            raise RuntimeError('Network-only recovery accepts only the exact interrupted VPC/subnet; unexpected resources require review')
        recover_network()
    elif inv['lab_name_collisions']:raise RuntimeError('Lab resource name collision; use status and inspect, never overwrite or recreate existing resources')
    if not inv['required_apis_present']:raise RuntimeError('Compute or IAP API is not enabled; owner must review before project-level changes')
    if not math.isfinite(credit_brl) or credit_brl<350:raise RuntimeError('Owner must verify at least R$350 remaining credit for this conservative bounded demo allocation')
    try:
        create_infrastructure(runtime,resume_network)
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            jobs=[pool.submit(configure,node,runtime) for node in ALL]
            for job in jobs:job.result()
        progress('Verifying actual four-node consensus, two HTTPS sites and audit anchoring now.')
        result=cloud_verify(anchor=True)
        write(runtime/'live-acceptance.json',json.dumps(result,indent=2));return result
    except BaseException:
        # On any failed provisioning/configuration, stop only validated lab instances. Preserve all disks.
        try:change_state('stop',partial=True)
        except Exception as exc:print('Scoped automatic stop could not be verified; immediately inspect lab status:',str(exc))
        raise


def idle_gate(runtime):
    before=cloud_verify();before_disks={x['name']:x['disk'] for x in status()}
    if not before['anchor'] or not before['anchor'].get('verified'):raise RuntimeError('Earn an actual ledger anchor before lifecycle acceptance')
    # No dashboard requests, SSH activity or lease refresh during this wait. Cloud status polls are read-only.
    start=time.monotonic();stopped=None
    while time.monotonic()-start<660:
        current=status()
        if all(x['status']=='TERMINATED' for x in current):stopped=current;break
        time.sleep(15)
    if stopped is None:raise RuntimeError('All five VMs did not enter TERMINATED; idle gate failed')
    elapsed=time.monotonic()-start
    if elapsed<570:raise RuntimeError('Group stopped too early to verify a 600-second idle policy')
    if {x['name']:x['disk'] for x in stopped}!=before_disks:raise RuntimeError('Persistent disk identities changed')
    change_state('start');after=cloud_verify()
    if (before['audit']['head']!=after['audit']['head'] or before['anchor']['transaction_hash']!=after['anchor']['transaction_hash']
            or sorted(x['fingerprint'] for x in before['tls']['sites'])!=sorted(x['fingerprint'] for x in after['tls']['sites'])
            or {x['name']:x['disk'] for x in status()}!=before_disks):raise RuntimeError('Restart failed to preserve required state')
    result={'verified':True,'stopped_all_after_seconds':elapsed,'disks_preserved':True,'anchor_preserved':True,'tls_and_audit_preserved':True,'before':before,'after':after}
    write(Path(runtime)/'idle-acceptance.json',json.dumps(result,indent=2));return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='cmd',required=True)
    sub.add_parser('plan');sub.add_parser('status');sub.add_parser('start');sub.add_parser('stop');sub.add_parser('verify')
    p=sub.add_parser('prepare');p.add_argument('--runtime',required=True)
    p=sub.add_parser('apply');p.add_argument('--runtime',required=True);p.add_argument('--credit-brl',type=float,required=True)
    p=sub.add_parser('resume-network');p.add_argument('--runtime',required=True);p.add_argument('--credit-brl',type=float,required=True)
    p=sub.add_parser('idle-gate');p.add_argument('--runtime',required=True)
    args=parser.parse_args()
    if args.cmd=='plan':print(json.dumps(plan(),indent=2))
    elif args.cmd=='prepare':prepare(args.runtime)
    elif args.cmd=='apply':print(json.dumps(apply(args.runtime,args.credit_brl),indent=2))
    elif args.cmd=='resume-network':print(json.dumps(apply(args.runtime,args.credit_brl,True),indent=2))
    elif args.cmd=='status':print(json.dumps(status(require_all=False),indent=2))
    elif args.cmd in ('start','stop'):print(json.dumps(change_state(args.cmd),indent=2))
    elif args.cmd=='verify':print(json.dumps(cloud_verify(),indent=2))
    else:print(json.dumps(idle_gate(args.runtime),indent=2))


if __name__=='__main__':main()

