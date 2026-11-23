"""Owner-side, read-only export of explicitly selected synthetic Google Cloud assets.

No credential reads, IAM edits, resource creation, resource listing, or network upload.
Run inside the judge's own already-authenticated Cloud Shell. The resulting manifest
contains hand-selected aliases and narrow, normalized operational metadata only.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 'warden-judge-sandbox-v1'
NAME = re.compile(r'[a-z][a-z0-9-]{0,62}')
PROJECT = re.compile(r'[a-z][a-z0-9-]{4,28}[a-z0-9]')
ZONE = re.compile(r'[a-z]+-[a-z0-9]+[0-9]-[a-z]')
REGION = re.compile(r'[a-z]+-[a-z0-9]+[0-9]')
ALIAS = re.compile(r'[A-Za-z0-9][A-Za-z0-9 _.-]{0,47}')
BUCKET = re.compile(r'[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]')
STATES = {'RUNNING':'running','TERMINATED':'stopped','STOPPING':'stopping','PROVISIONING':'provisioning','STAGING':'provisioning','SUSPENDED':'suspended','READY':'ready','CREATING':'provisioning','RESTORING':'provisioning'}
KINDS = ('vm','disk','bucket','kms')


def validate(value,pattern,label):
    if not isinstance(value,str) or not pattern.fullmatch(value):
        raise ValueError(f'Invalid {label}; use a simple, explicitly selected test asset')
    return value


def read_gcloud(project,*args):
    # Never print raw provider JSON or stderr: metadata can contain account IDs,
    # service-account identities, customer identifiers, URLs, or configuration.
    done=subprocess.run(['gcloud',f'--project={project}','--quiet',*args,'--format=json'],capture_output=True,text=True,check=False,timeout=60)
    if done.returncode:
        raise RuntimeError('Read-only asset lookup not permitted or asset not found. Check the selected project and asset.')
    record=json.loads(done.stdout)
    if not isinstance(record,dict):raise ValueError('Unexpected cloud metadata')
    return record


def cli_active(project):
    current=subprocess.run(['gcloud','config','get-value','project'],capture_output=True,text=True,check=False,timeout=20)
    account=subprocess.run(['gcloud','auth','list','--filter=status:ACTIVE','--format=value(account)'],capture_output=True,text=True,check=False,timeout=20)
    if current.returncode or account.returncode or current.stdout.strip()!=project or not account.stdout.strip():
        raise RuntimeError('Select the exact sandbox project and sign into your own Cloud Shell before running. No credential was exported.')


def describe(project, selection, reader=read_gcloud):
    # All resources must be named individually; no wildcard, broad list, URL, or
    # untrusted option is passed to gcloud. Aliases never substitute for cloud IDs.
    kind,alias,name,location,ring=selection
    validate(alias,ALIAS,'public alias')
    if kind not in KINDS:raise ValueError('Unsupported asset category')
    if kind in ('vm','disk'):
        validate(name,NAME,'resource name');validate(location,ZONE,'zone')
        args=('compute','instances' if kind=='vm' else 'disks','describe',name,f'--zone={location}')
        obj=reader(project,*args)
        if obj.get('name')!=name or not str(obj.get('zone','')).endswith('/'+location):raise ValueError('Provider response does not match the selected asset')
        status=STATES.get(str(obj.get('status','')).upper(),'unknown')
        return {'kind':kind,'alias':alias,'region':location,'status':status}
    if kind=='bucket':
        validate(name,BUCKET,'bucket name');obj=reader(project,'storage','buckets','describe','gs://'+name)
        if obj.get('name')!=name and obj.get('id')!=name:raise ValueError('Provider response does not match selected bucket')
        owner=reader(project,'projects','describe',project)
        project_number=str(owner.get('projectNumber',''))
        bucket_number=str(obj.get('projectNumber',obj.get('project_number','')))
        if not project_number.isdigit() or project_number!=bucket_number:raise ValueError('Bucket ownership could not be confirmed in the selected sandbox project')
        # Do not imply object contents, readability or encryption were inspected.
        loc=str(obj.get('location','')).lower()
        if not re.fullmatch(r'[a-z0-9-]{1,32}',loc):loc='unknown'
        return {'kind':kind,'alias':alias,'region':loc,'status':'metadata-confirmed'}
    validate(name,NAME,'key name');validate(ring,NAME,'key ring');validate(location,REGION,'region')
    obj=reader(project,'kms','keys','describe',name,f'--keyring={ring}',f'--location={location}')
    expected=f'projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{name}'
    if obj.get('name')!=expected:raise ValueError('Provider response does not match selected key')
    return {'kind':kind,'alias':alias,'region':location,'status':'metadata-confirmed'}


def manifest(project,selections,reader=read_gcloud,check=cli_active):
    validate(project,PROJECT,'sandbox project');check(project)
    if not 1<=len(selections)<=12:raise ValueError('Select between one and twelve exact sandbox assets')
    # Explicit owner-supplied aliases, case insensitive uniqueness. No provider ID
    # or project is placed in the resulting public-safe manifest.
    aliases=[str(item[1]).casefold() for item in selections]
    if len(set(aliases))!=len(aliases):raise ValueError('Asset aliases must be unique')
    assets=[describe(project,item,reader) for item in selections]
    return {'schema':SCHEMA,'provider':'gcp','environment':'judge-sandbox','source':'owner-cli-read-only','captured_at':datetime.now(timezone.utc).isoformat(timespec='seconds'),'assets':assets}


def parse_selection(value):
    # KIND,ALIAS,NAME,LOCATION[,RING]; the CLI accepts no arbitrary operations.
    fields=value.split(',')
    if len(fields)==4:fields.append('')
    if len(fields)!=5:raise argparse.ArgumentTypeError('Use KIND,ALIAS,NAME,LOCATION[,RING]')
    return tuple(fields)


def main():
    p=argparse.ArgumentParser(description='Create a local, redacted Warden asset manifest from explicitly named sandbox resources.')
    p.add_argument('--project',required=True);p.add_argument('--asset',action='append',type=parse_selection,required=True)
    p.add_argument('--synthetic-only',action='store_true',help='Confirm that all selected assets are non-production and approved for this demo.')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if not a.synthetic_only:p.error('Explicit --synthetic-only confirmation is required. Do not select production assets.')
    result=manifest(a.project,a.asset)
    # Refuse overwrite (may be a user's existing manifest or another file).
    with a.output.open('x',encoding='utf-8') as file:json.dump(result,file,ensure_ascii=True,indent=2)
    print(f'Redacted manifest created: {len(result["assets"])} explicitly selected assets. No credentials or project ID included.')


if __name__=='__main__':main()
