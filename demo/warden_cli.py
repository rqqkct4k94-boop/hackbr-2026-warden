"""Separate custody command line for the synthetic Warden laboratory."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from warden import Authority, HOSTS, canonical, digest, create_site_csr, make_approval, verify_evidence


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def exclusive(path, data, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


def json_file(path, value, private=False):
    exclusive(path, canonical(value) + b'\n', private=private)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('initialize', help='one-time trusted lab ceremony; secure separate custody files')
    s.add_argument('--database', required=True); s.add_argument('--custody-dir', required=True); s.add_argument('--manifest', required=True)
    s = sub.add_parser('create-site', help='generate a site-owned private key and public CSR')
    s.add_argument('--hostname', required=True, choices=HOSTS); s.add_argument('--directory', required=True)
    s = sub.add_parser('request', help='create a time-bound issuance, renewal or revocation request')
    s.add_argument('--database', required=True); s.add_argument('--kind', required=True, choices=['issue','renew','revoke'])
    s.add_argument('--csr'); s.add_argument('--previous-serial'); s.add_argument('--output', required=True)
    s = sub.add_parser('approve', help='each custodian runs this independently using their own protected package')
    s.add_argument('--custody', required=True); s.add_argument('--request', required=True); s.add_argument('--release', required=True)
    s = sub.add_parser('authorize', help='require all three exact signed custody releases')
    s.add_argument('--database', required=True); s.add_argument('--request-id', required=True); s.add_argument('--releases', required=True, nargs=3); s.add_argument('--output', required=True)
    s = sub.add_parser('evidence', help='export only public certificate and signature evidence')
    s.add_argument('--database', required=True); s.add_argument('--output', required=True)
    s = sub.add_parser('verify', help='verify with independent root and manifest pins')
    s.add_argument('--evidence', required=True); s.add_argument('--root-pin', required=True); s.add_argument('--manifest-pin', required=True)
    args = p.parse_args()
    if args.command == 'create-site':
        target = Path(args.directory)
        if target.exists() and any(target.iterdir()):
            raise SystemExit('Refusing to overwrite any site runtime files')
        key, csr = create_site_csr(args.hostname)
        exclusive(target/'site.key', key, private=True); exclusive(target/'site.csr', csr.encode())
        print('Site key and CSR generated locally; only the CSR is shared.'); return
    if args.command == 'approve':
        release = make_approval(read_json(args.custody), read_json(args.request))
        json_file(args.release, release, private=True)
        print('Custodian release saved privately. Do not publish or log release material.'); return
    if args.command == 'verify':
        e = read_json(args.evidence)
        print(json.dumps(verify_evidence(e['manifest'], e['events'], args.root_pin, args.manifest_pin), indent=2)); return
    database = Path(args.database)
    if args.command == 'initialize':
        custody_dir = Path(args.custody_dir)
        if database.exists() or Path(args.manifest).exists() or (custody_dir.exists() and any(custody_dir.iterdir())):
            raise SystemExit('Refusing to overwrite any existing authority or custodian material')
        database.parent.mkdir(parents=True, exist_ok=True)
    elif not database.is_file():
        raise SystemExit('Authority database does not exist')
    auth = Authority(database)
    try:
        if args.command == 'initialize':
            packages = auth.initialize()
            # Runtime-only private files. On shared systems use separate OS accounts/hosts and ACLs.
            for package in packages:
                json_file(Path(args.custody_dir)/package['id']/'custody.json', package, private=True)
            manifest = auth.manifest(); json_file(args.manifest, manifest)
            print(json.dumps({'root_fingerprint':manifest['root_fingerprint'], 'manifest_sha256':digest(canonical(manifest)),
                              'custodians': len(packages), 'warning':'Trusted bootstrap; distribute private packages separately.'}, indent=2))
        elif args.command == 'request':
            if Path(args.output).exists(): raise SystemExit('Output already exists')
            csr = Path(args.csr).read_text(encoding='ascii') if args.csr else None
            req = auth.request(args.kind, csr, args.previous_serial); json_file(args.output, req)
            print(json.dumps({'id':req['id'],'kind':req['kind'],'hostname':req['hostname'],'request_sha256':digest(canonical(req))},indent=2))
        elif args.command == 'authorize':
            if Path(args.output).exists(): raise SystemExit('Output already exists')
            out = auth.authorize(args.request_id, [read_json(x) for x in args.releases]); json_file(args.output, out)
            print(json.dumps({k:v for k,v in out.items() if k not in ('certificate_pem','crl_pem')},indent=2))
        elif args.command == 'evidence':
            json_file(args.output, auth.evidence()); print('Public evidence exported. No custody shares or private keys included.')
    finally:
        auth.close()


if __name__ == '__main__': main()

