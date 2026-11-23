"""Reproducible isolated four-validator Besu lab and hash anchoring.

Live execution requires an authorised Docker/Compose host and eth-account.
No production networks, wildcard host allowances, public RPC, or reused keys.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler
from warden import verify_evidence, digest, canonical

CHAIN_ID=20261123
PORTS=(18545,18546,18547,18548)
SUBNET=ipaddress.ip_network('172.28.231.0/24')
PREFIX=b'WARDEN-P0:'
HERE=Path(__file__).resolve().parent


def image_pin(image):
    if not re.fullmatch(r'hyperledger/besu(?::[0-9]+(?:\.[0-9]+){1,3}(?:[-.][A-Za-z0-9.-]+)?|@sha256:[0-9a-f]{64})',image):
        raise ValueError('Require an explicit official hyperledger/besu release tag or image digest; never use latest')
    return image


def genesis_input(anchor_address):
    if not re.fullmatch(r'0x[0-9a-fA-F]{40}',anchor_address): raise ValueError('Invalid public anchoring address')
    return {'genesis':{'config':{'chainId':CHAIN_ID,'berlinBlock':0,'qbft':{'blockperiodseconds':2,'epochlength':30000,'requesttimeoutseconds':4}},
                       'nonce':'0x0','timestamp':'0x0','gasLimit':'0x47b760','difficulty':'0x1',
                       'mixHash':'0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365',
                       'coinbase':'0x0000000000000000000000000000000000000000','alloc':{anchor_address[2:]:{'balance':'0xad78ebc5ac6200000'}}},
            'blockchain':{'nodes':{'generate':True,'count':4}}}


def build_compose(image, public_keys):
    image_pin(image)
    keys=[v.removeprefix('0x').lower() for v in public_keys]
    if len(keys)!=4 or len(set(keys))!=4 or any(not re.fullmatch(r'[0-9a-f]{128}',k) for k in keys):
        raise ValueError('Require exactly four distinct valid public node keys')
    ips=[str(SUBNET.network_address+i) for i in range(11,15)]
    enodes=[f'enode://{k}@{ip}:30303' for k,ip in zip(keys,ips)]
    services={}
    for i in range(4):
        name=f'validator{i+1}'
        args=['--data-path=/lab/data','--genesis-file=/lab/config/genesis.json','--node-private-key-file=/lab/data/key',
              f'--p2p-host={ips[i]}','--p2p-port=30303','--rpc-http-enabled','--rpc-http-host=0.0.0.0','--rpc-http-port=8545',
              '--rpc-http-api=ETH,NET,QBFT','--host-allowlist=localhost,127.0.0.1',
              '--bootnodes='+','.join(enodes[j] for j in range(4) if j!=i)]
        svc={'image':image,'command':args,'mem_limit':'4g','environment':{'BESU_OPTS':'-Xms512m -Xmx2048m'},
             'ports':[f'127.0.0.1:{PORTS[i]}:8545'],
             'volumes':[f'./nodes/{name}:/lab/data:rw','./networkFiles/genesis.json:/lab/config/genesis.json:ro'],
             'networks':{'warden_lab':{'ipv4_address':ips[i]}},'restart':'no'}
        if hasattr(os,'getuid'):svc['user']=f'{os.getuid()}:{os.getgid()}'
        services[name]=svc
    return {'name':'hackbr-warden-local','services':services,
            'networks':{'warden_lab':{'internal':True,'ipam':{'config':[{'subnet':str(SUBNET)}]}}}}


def write_private(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data)


def prepare(runtime,image):
    from eth_account import Account
    image_pin(image);runtime=Path(runtime).resolve()
    if runtime==HERE or HERE in runtime.parents or (runtime.exists() and any(runtime.iterdir())):
        raise ValueError('Use a new, separate private runtime outside the source tree')
    if shutil.which('docker') is None:raise RuntimeError('Docker is not installed; no network has been created')
    runtime.mkdir(parents=True,exist_ok=True)
    anchor=Account.create(); write_private(runtime/'anchor.key',bytes(anchor.key))
    (runtime/'qbftConfigFile.json').write_text(json.dumps(genesis_input(anchor.address),indent=2))
    args=['docker','run','--rm','-v',f'{runtime}:/lab']
    if hasattr(os,'getuid'):args+=['--user',f'{os.getuid()}:{os.getgid()}']
    args+=[image,'operator','generate-blockchain-config','--config-file=/lab/qbftConfigFile.json','--to=/lab/networkFiles','--private-key-file-name=key']
    subprocess.run(args,check=True,capture_output=True,text=True,timeout=300)
    key_dirs=sorted(x for x in (runtime/'networkFiles'/'keys').iterdir() if x.is_dir())
    if len(key_dirs)!=4: raise RuntimeError('Official Besu generator did not produce four distinct node key directories')
    addresses=[];pubs=[]
    for i,src in enumerate(key_dirs,1):
        address='0x'+src.name.removeprefix('0x').lower()
        if not re.fullmatch(r'0x[0-9a-f]{40}',address):raise RuntimeError('Unexpected generator address')
        addresses.append(address);pubs.append((src/'key.pub').read_text().strip())
        dest=runtime/'nodes'/f'validator{i}';dest.mkdir(parents=True)
        write_private(dest/'key',(src/'key').read_bytes())
    (runtime/'compose.json').write_text(json.dumps(build_compose(image,pubs),indent=2))
    (runtime/'network-manifest.json').write_text(json.dumps({'chain_id':CHAIN_ID,'validators':addresses,'anchor':anchor.address,'image':image},indent=2))
    print('Generated four validator identities and compose plan. Start only this lab with docker compose -f compose.json up -d.')


def rpc_at(port,method,params=None,host='127.0.0.1',remote_port=None):
    if port not in PORTS:raise ValueError('Only the four designated loopback lab RPC ports are allowed')
    if host!='127.0.0.1' and host not in tuple(f'10.88.24.{n}' for n in range(11,15)):
        raise ValueError('Only designated Warden lab private addresses are allowed')
    if host!='127.0.0.1' and remote_port!=8545:raise ValueError('Private validator RPC must use designated port 8545')
    data=canonical({'jsonrpc':'2.0','id':1,'method':method,'params':params or []})
    opener=build_opener(ProxyHandler({}))
    with opener.open(Request(f'http://{host}:{remote_port or port}',data=data,headers={'Content-Type':'application/json'}),timeout=5) as response:
        result=json.load(response)
    if 'error' in result:raise RuntimeError(f'Besu {method} failed at local node {port}')
    return result['result']


def rpc(port,method,params=None):return rpc_at(port,method,params)


def rpc_for(manifest):
    hosts=manifest.get('rpc_hosts')
    if hosts is None:return rpc
    if hosts!=[f'10.88.24.{n}' for n in range(11,15)]:raise ValueError('Unexpected private cloud lab endpoints')
    return lambda port,method,params=None:rpc_at(port,method,params,hosts[PORTS.index(port)],8545)


def verify_network(manifest,rpc_call=None,wait=time.sleep):
    rpc_call=rpc_call or rpc_for(manifest)
    expected={v.lower() for v in manifest['validators']}
    if manifest['chain_id']!=CHAIN_ID or len(expected)!=4:raise ValueError('Unexpected lab manifest')
    infos=[]
    for port in PORTS:
        chain=int(rpc_call(port,'eth_chainId'),16)
        validators={v.lower() for v in rpc_call(port,'qbft_getValidatorsByBlockNumber',['latest'])}
        initial=int(rpc_call(port,'eth_blockNumber'),16)
        peers=int(rpc_call(port,'net_peerCount'),16)
        genesis=rpc_call(port,'eth_getBlockByNumber',['0x0',False])['hash']
        if chain!=CHAIN_ID or validators!=expected or peers<1:raise RuntimeError(f'Node {port} does not match the isolated four-validator lab')
        infos.append({'port':port,'initial_height':initial,'peers':peers,'genesis':genesis})
    wait(5)
    heights=[int(rpc_call(port,'eth_blockNumber'),16) for port in PORTS]
    for row,height in zip(infos,heights):
        if height<=row['initial_height']:raise RuntimeError('A validator has no block progress')
        row['height']=height
    common=min(heights)
    hashes={rpc_call(port,'eth_getBlockByNumber',[hex(common),False])['hash'] for port in PORTS}
    if len(hashes)!=1 or len({r['genesis'] for r in infos})!=1:raise RuntimeError('Validators disagree on genesis or common block')
    return {'verified':True,'chain_id':CHAIN_ID,'validators':sorted(expected),'nodes':infos,'common_block':common,'block_hash':hashes.pop()}


def anchor(runtime,evidence_path,pins_path):
    from eth_account import Account
    runtime=Path(runtime).resolve();manifest=json.loads((runtime/'network-manifest.json').read_text()); pins=json.loads(Path(pins_path).read_text())
    evidence=json.loads(Path(evidence_path).read_text());proof=verify_evidence(evidence['manifest'],evidence['events'],pins['root'],pins['manifest'])
    out=runtime/f'anchor-{proof["head"]}.json';intent=runtime/f'anchor-intent-{proof["head"]}.json'
    if out.exists() or intent.exists():raise RuntimeError('Existing anchor evidence or intent; verify existing receipt before any retry')
    call=rpc_for(manifest);network=verify_network(manifest,call); account=Account.from_key((runtime/'anchor.key').read_bytes())
    if account.address.lower()!=manifest['anchor'].lower():raise RuntimeError('Anchor signer does not match the isolated genesis allocation')
    payload='0x'+(PREFIX+bytes.fromhex(proof['head'])).hex();nonce=int(call(PORTS[0],'eth_getTransactionCount',[account.address,'pending']),16)
    gas_price=int(call(PORTS[0],'eth_gasPrice'),16)
    tx={'chainId':CHAIN_ID,'nonce':nonce,'to':account.address,'value':0,'data':payload,'gas':40000,'gasPrice':gas_price}
    signed=account.sign_transaction(tx);expected_hash='0x'+bytes(signed.hash).hex()
    with intent.open('x',encoding='ascii') as f:json.dump({'audit_head':proof['head'],'transaction_hash':expected_hash,'chain_id':CHAIN_ID},f)
    tx_hash=call(PORTS[0],'eth_sendRawTransaction',['0x'+bytes(signed.raw_transaction).hex()])
    if tx_hash.lower()!=expected_hash.lower():raise RuntimeError('Transaction hash differed from signed intent')
    deadline=time.monotonic()+45;receipts=None
    while time.monotonic()<deadline:
        receipts=[call(port,'eth_getTransactionReceipt',[tx_hash]) for port in PORTS]
        if all(receipts):break
        time.sleep(2)
    if not receipts or not all(receipts):raise RuntimeError('Anchor was not confirmed by all four validators; do not claim success')
    if any(r['status']!='0x1' for r in receipts) or len({r['blockHash'] for r in receipts})!=1:raise RuntimeError('Anchor receipts disagree or failed')
    for port in PORTS:
        tx_found=call(port,'eth_getTransactionByHash',[tx_hash])
        if tx_found['input'].lower()!=payload.lower() or tx_found['from'].lower()!=account.address.lower():raise RuntimeError('Ledger payload or signer mismatch')
    result={'verified':True,'audit_head':proof['head'],'transaction_hash':tx_hash,'block_hash':receipts[0]['blockHash'],'network':network,'receipts':4}
    with out.open('x',encoding='ascii') as f:json.dump(result,f,indent=2)
    return result


def verify_receipt(runtime,receipt_path):
    runtime=Path(runtime).resolve();manifest=json.loads((runtime/'network-manifest.json').read_text())
    saved=json.loads(Path(receipt_path).read_text());call=rpc_for(manifest);tx_hash=saved['transaction_hash']
    expected='0x'+(PREFIX+bytes.fromhex(saved['audit_head'])).hex()
    verify_network(manifest,call)
    for port in PORTS:
        tx=call(port,'eth_getTransactionByHash',[tx_hash]);receipt=call(port,'eth_getTransactionReceipt',[tx_hash])
        if (not tx or not receipt or tx['input'].lower()!=expected.lower() or tx['from'].lower()!=manifest['anchor'].lower()
                or receipt['status']!='0x1' or receipt['blockHash']!=saved['block_hash']):
            raise RuntimeError('Persisted audit anchor was not verified on every validator')
    return {'verified':True,'audit_head':saved['audit_head'],'transaction_hash':tx_hash,'block_hash':saved['block_hash'],'receipts':4}


def main():
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('prepare');p.add_argument('--runtime',required=True);p.add_argument('--image',required=True)
    p=sub.add_parser('verify');p.add_argument('--runtime',required=True)
    p=sub.add_parser('anchor');p.add_argument('--runtime',required=True);p.add_argument('--evidence',required=True);p.add_argument('--pins',required=True)
    p=sub.add_parser('verify-receipt');p.add_argument('--runtime',required=True);p.add_argument('--receipt',required=True)
    args=parser.parse_args()
    if args.command=='prepare': prepare(args.runtime,args.image)
    elif args.command=='verify': print(json.dumps(verify_network(json.loads((Path(args.runtime)/'network-manifest.json').read_text())),indent=2))
    elif args.command=='anchor':print(json.dumps(anchor(args.runtime,args.evidence,args.pins),indent=2))
    else:print(json.dumps(verify_receipt(args.runtime,args.receipt),indent=2))


if __name__=='__main__': main()

