"""Owner-run, resumable acceptance for the existing five-VM Warden synthetic lab.

Never provisions, deletes or changes permissions. A verified stop checkpoint is
saved before restarting. Provider observation time is not guest trigger time.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import time
from pathlib import Path

import cloudshell_owner as lab

SCHEMA = 'warden-lifecycle-checkpoint-v1'
PUBLIC_SCHEMA = 'warden-lifecycle-acceptance-v1'
PUBLIC_FILE = 'public-lifecycle-report.json'
CHECKPOINT = 'lifecycle-checkpoint.json'
SITES = {'alpha.warden-demo.invalid', 'beta.warden-demo.invalid'}
NAMES = {node[0] for node in lab.ALL}


def verify_runtime(runtime):
    root = Path(runtime).expanduser().resolve(strict=True)
    expected = {'project': lab.owner_project(), 'zone': lab.ZONE, 'image': lab.IMAGE,
                'scope': lab.PREFIX, 'prepared': True}
    if json.loads((root / 'prepared.json').read_text(encoding='utf8')) != expected:
        raise ValueError('The private runtime is not the exact prepared Warden lab')
    return root


def check_credit(credit_brl):
    if not math.isfinite(credit_brl) or credit_brl < 350:
        raise ValueError('Owner must confirm at least R$350 in existing live trial credits')
    inventory = lab.inventory()
    if not (inventory['project_active'] and inventory['billing_enabled'] and inventory['required_apis_present']):
        raise RuntimeError('Existing lab project, trial billing and Compute/IAP APIs must be active')


def disk_snapshot(read_rows=None, describe=None):
    """Record exact GCE disk resource IDs as private normalized fingerprints."""
    rows = (read_rows or (lambda: lab.status(private_only=True)))()
    describe = describe or (lambda name: lab.gcjson('compute', 'disks', 'describe', name, f'--zone={lab.ZONE}'))
    if len(rows) != 5 or {row['name'] for row in rows} != NAMES:
        raise RuntimeError('The exact five-VM lab is incomplete')
    project = lab.owner_project()
    result = {}
    for row in rows:
        name = row['name']
        suffix = f'/projects/{project}/zones/{lab.ZONE}/disks/{name}'
        if not isinstance(row['disk'], str) or not row['disk'].endswith(suffix):
            raise RuntimeError('Unexpected retained boot disk')
        disk = describe(name)
        identifier = str(disk.get('id', ''))
        if (disk.get('name') != name or not str(disk.get('zone', '')).endswith('/' + lab.ZONE)
                or str(disk.get('sizeGb')) != '20' or not str(disk.get('type', '')).endswith('/pd-balanced')
                or not re.fullmatch(r'[0-9]{1,32}', identifier)
                or not str(disk.get('selfLink', '')).endswith(suffix)):
            raise RuntimeError('Persistent disk identity or allocated shape did not match')
        result[name] = hashlib.sha256((name + ':' + identifier).encode()).hexdigest()
    if len(set(result.values())) != 5:
        raise RuntimeError('Disk identities must be distinct')
    return {'identity_hashes': result, 'links': {row['name']: row['disk'] for row in rows}}


def evidence_summary(report):
    network, tls, audit, anchor = (report.get(k) for k in ('network', 'tls', 'audit', 'anchor'))
    if not all(isinstance(x, dict) and x.get('verified') is True for x in (network, tls, audit, anchor)):
        raise ValueError('Live network, TLS, audit and ledger receipts are all required')
    validators, nodes = network.get('validators', []), network.get('nodes', [])
    if (len(validators) != 4 or len(set(validators)) != 4 or len(nodes) != 4
            or any(node.get('peers') != 3 for node in nodes) or anchor.get('receipts') != 4):
        raise ValueError('Expected four connected validators and four matching receipts')
    sites = tls.get('sites', [])
    if len(sites) != 2 or {s.get('hostname') for s in sites} != SITES:
        raise ValueError('Expected the exact two synthetic TLS sites')
    fingerprints = {}
    for site in sites:
        fp = site.get('fingerprint', '')
        if not re.fullmatch(r'[0-9a-f]{64}', fp) or site.get('http_ok') is not True or site.get('matches_approved_certificate') is not True:
            raise ValueError('TLS proof does not match the approved certificate')
        fingerprints[site['hostname']] = fp
    if len(set(fingerprints.values())) != 2:
        raise ValueError('Synthetic TLS sites must use different certificates')
    head, transaction = audit.get('head', ''), anchor.get('transaction_hash', '')
    if (not re.fullmatch(r'[0-9a-f]{64}', head) or anchor.get('audit_head') != head
            or not re.fullmatch(r'0x[0-9a-f]{64}', transaction) or audit.get('certificates') != 2):
        raise ValueError('Audit head or anchored transaction did not match')
    genesis = {n.get('genesis') for n in nodes}
    if len(genesis) != 1 or not re.fullmatch(r'0x[0-9a-f]{64}', str(next(iter(genesis)))):
        raise ValueError('Validator genesis mismatch')
    return {'audit_head': head, 'anchor_transaction': transaction, 'tls_fingerprints': fingerprints,
            'validators': sorted(validators), 'genesis': next(iter(genesis)), 'receipts': 4,
            'chain_id': network['chain_id']}


def safe_same_evidence(before, after, before_disks, after_disks):
    if before != after or before_disks != after_disks:
        raise RuntimeError('Persistent disk IDs, TLS, audit or ledger evidence changed after restart')


def write_checkpoint(path, data):
    # The checkpoint is in the already validated private runtime, not a public export.
    temporary = path.with_name(path.name + '.tmp-' + str(os.getpid()))
    with temporary.open('x', encoding='utf8') as stream:
        json.dump(data, stream, indent=2); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


@contextlib.contextmanager
def single_runner(root):
    import fcntl  # Cloud Shell is Linux; lock automatically releases on disconnect/process exit.
    with (root / 'lifecycle-run.lock').open('a', encoding='utf8') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('Another lifecycle gate is running; do not start a duplicate') from None
        try: yield
        finally: fcntl.flock(lock, fcntl.LOCK_UN)


def stable_group_start():
    # A GCE operation may continue after Cloud Shell disconnect. Wait for its state before starting.
    deadline = time.monotonic() + 180
    while True:
        current = lab.status(private_only=True)
        if all(row['status'] in ('RUNNING', 'TERMINATED') for row in current): break
        if time.monotonic() >= deadline: raise RuntimeError('VM state transitions still pending; retry without changing any resources')
        time.sleep(10)
    if not all(row['status'] == 'RUNNING' for row in current):
        lab.progress('Starting only the existing, validated synthetic lab group.')
        lab.change_state('start')


def fresh_stop_checkpoint(root, path):
    disk_snapshot()  # Verify exact retained boot-disk resource identities before the first start.
    stable_group_start()
    lab.progress('Verifying the live baseline, then recording exact persistent disk IDs.')
    baseline = evidence_summary(lab.cloud_verify())
    original_disks = disk_snapshot()
    # Start the true-idle window with exactly one final explicit TLS operation, not a heartbeat.
    last = lab.retry_live_read(lab.CONTROL[0], 'curl --max-time 10 -fsS -X POST http://127.0.0.1:8080/api/verify', attempts=3)
    if last.get('verified') is not True or {s['hostname']: s['fingerprint'] for s in last['sites']} != baseline['tls_fingerprints']:
        raise RuntimeError('Final explicit TLS demonstration did not match the baseline')
    checkpoint = {'schema': SCHEMA, 'phase': 'observing', 'scope': lab.PREFIX, 'started_utc': int(time.time()),
                  'baseline': baseline, 'disks': original_disks}
    write_checkpoint(path, checkpoint)
    lab.progress('No dashboard activity or SSH requests for this idle observation. Wait up to 900 seconds.')
    elapsed, transitions = lab.observe_idle_shutdown(original_disks['links'])
    stopped_disks = disk_snapshot()
    if stopped_disks != original_disks:
        raise RuntimeError('Persistent disk identity changed during stop')
    # Persist the proven stop BEFORE issuing any restart request.
    checkpoint.update(phase='stop-observed', elapsed=elapsed, transitions=transitions,
                      stop_observed_utc=int(time.time()))
    write_checkpoint(path, checkpoint)
    lab.progress('All five provider power states reached TERMINATED; exact disk identities persisted. Stop checkpoint saved.')
    return checkpoint


def public_report(checkpoint, after):
    elapsed, transitions = checkpoint['elapsed'], checkpoint['transitions']
    if (not 570 <= elapsed <= 900 or set(transitions) != NAMES
            or any(not 570 <= value <= elapsed for value in transitions.values())):
        raise ValueError('The provider stop observation is incomplete or inconsistent')
    return {'schema': PUBLIC_SCHEMA, 'scope': 'synthetic-warden-lab',
            'source': 'owner-run-gce-provider-observation-and-live-verification', 'verified': True,
            'configured_guest_idle_seconds': 600, 'provider_observation_limit_seconds': 900,
            'observed_all_terminated_seconds': round(elapsed, 3),
            'provider_transition_seconds': {k: round(v, 3) for k, v in transitions.items()},
            'five_unique_disk_ids_preserved': True, 'restart_verified': True,
            'four_validators_verified_after_restart': True, 'four_matching_anchor_receipts': 4,
            'two_distinct_tls_fingerprints': after['tls_fingerprints'],
            'audit_head': after['audit_head'], 'anchor_transaction': after['anchor_transaction'],
            'guest_trigger_timestamp_independently_measured': False,
            'completed_utc': int(time.time()),
            'limitations': ['Provider power-state observation includes shutdown/reporting latency; not an exact guest trigger timestamp.',
                            'No manual stop was issued during the observed idle interval by this runner.']}


def execute(root, credit_brl, restart_unproven=False):
    root = verify_runtime(root)
    check_credit(credit_brl)
    public_path, path = root / PUBLIC_FILE, root / CHECKPOINT
    with single_runner(root):
        if public_path.exists():
            raise RuntimeError('Verified public lifecycle report already exists; preserve and review it, do not rerun')
        checkpoint = json.loads(path.read_text(encoding='utf8')) if path.exists() else None
        if checkpoint is not None:
            if checkpoint.get('schema') != SCHEMA or checkpoint.get('scope') != lab.PREFIX:
                raise ValueError('Unexpected prior checkpoint; no cloud mutations issued')
            if checkpoint.get('phase') == 'observing':
                if not restart_unproven:
                    raise RuntimeError('Interrupted before durable stop proof. Review the prior checkpoint; explicit --restart-unproven is required for a fresh observation.')
                archive = root / ('lifecycle-interrupted-' + str(checkpoint['started_utc']) + '.json')
                with archive.open('x', encoding='utf8') as out: json.dump(checkpoint, out, indent=2)
                checkpoint = None
            elif checkpoint.get('phase') != 'stop-observed':
                raise RuntimeError('Unknown checkpoint phase; no cloud mutations issued')
        if checkpoint is None: checkpoint = fresh_stop_checkpoint(root, path)
        # Reject incomplete stop observations before issuing a recovery start.
        public_report(checkpoint, checkpoint['baseline'])
        # Validate evidence and stored disk identity before any resume start.
        if disk_snapshot() != checkpoint['disks']:
            raise RuntimeError('Recorded disk IDs no longer match; do not restart')
        stable_group_start()
        lab.progress('Rechecking the previously recorded audit head, TLS sites and four-validator receipt after restart.')
        after = evidence_summary(lab.cloud_verify())
        safe_same_evidence(checkpoint['baseline'], after, checkpoint['disks'], disk_snapshot())
        result = public_report(checkpoint, after)
        with public_path.open('x', encoding='utf8') as out: json.dump(result, out, indent=2)
        lab.progress('Full stop/restart acceptance saved. After test activity finishes, the same idle policy stops the group again.')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--credit-brl', type=float, required=True)
    parser.add_argument('--restart-unproven', action='store_true')
    args = parser.parse_args()
    print(json.dumps(execute(args.runtime, args.credit_brl, args.restart_unproven), indent=2))


if __name__ == '__main__': main()
