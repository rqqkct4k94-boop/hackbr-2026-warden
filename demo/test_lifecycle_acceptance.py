import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import lifecycle_acceptance as a
import cloudshell_owner as lab


def report():
    return json.loads((Path(__file__).parent / 'judge' / 'recorded-cloud.json').read_text())['live_acceptance']


def disks(project='synthetic-test'):
    ids = {name: str(i + 100) for i, name in enumerate(sorted(a.NAMES))}
    urls = {name: f'https://www.googleapis.com/compute/v1/projects/{project}/zones/{lab.ZONE}/disks/{name}' for name in a.NAMES}
    rows = [{'name': name, 'disk': url, 'status': 'TERMINATED'} for name, url in urls.items()]
    def describe(name):
        return {'id': ids[name], 'name': name, 'zone': 'zones/' + lab.ZONE, 'sizeGb': '20',
                'type': 'diskTypes/pd-balanced', 'selfLink': urls[name]}
    return rows, describe, ids


class LifecycleAcceptanceTests(unittest.TestCase):
    def test_disk_ids_not_just_names_are_preserved(self):
        rows, describe, ids = disks()
        with patch.object(lab, 'owner_project', return_value='synthetic-test'):
            baseline = a.disk_snapshot(lambda: rows, describe)
            ids[rows[0]['name']] = '99999'
            modified = a.disk_snapshot(lambda: rows, describe)
            self.assertEqual(baseline['links'], modified['links'])
            self.assertNotEqual(baseline['identity_hashes'], modified['identity_hashes'])
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                a.safe_same_evidence({}, {}, baseline, modified)
            with self.assertRaisesRegex(RuntimeError, 'Unexpected retained'):
                a.disk_snapshot(lambda: [{**rows[0], 'disk': 'disks/unrelated'}, *rows[1:]], describe)

    def test_evidence_rejects_receipt_and_tls_mismatches(self):
        baseline = a.evidence_summary(report())
        self.assertEqual(baseline['receipts'], 4)
        for property_name, inner, value in [('anchor','receipts',3), ('anchor','audit_head','a'*64), ('audit','certificates',1)]:
            wrong = report(); wrong[property_name][inner] = value
            with self.subTest(property_name=property_name, inner=inner), self.assertRaises(ValueError): a.evidence_summary(wrong)
        wrong = report();wrong['tls']['sites'][1]['fingerprint'] = wrong['tls']['sites'][0]['fingerprint']
        with self.assertRaises(ValueError): a.evidence_summary(wrong)

    def test_public_report_contains_no_disk_ids_or_project_names(self):
        baseline = a.evidence_summary(report())
        checkpoint = {'elapsed': 735, 'transitions': {n: 615 for n in a.NAMES}, 'disks': {'private': 'not-public'}}
        result = a.public_report(checkpoint, baseline)
        self.assertTrue(result['restart_verified']);self.assertFalse(result['guest_trigger_timestamp_independently_measured'])
        self.assertNotIn('not-public', json.dumps(result));self.assertNotIn('projects/', json.dumps(result))
        with self.assertRaises(ValueError): a.public_report({**checkpoint, 'transitions': {n: 100 for n in a.NAMES}}, baseline)

    def test_resume_preserves_stop_checkpoint_and_does_not_repeat_idle_wait(self):
        baseline = a.evidence_summary(report()); exact_disks = {'links': {}, 'identity_hashes': {}}
        checkpoint = {'schema': a.SCHEMA, 'phase': 'stop-observed', 'scope': lab.PREFIX,
                      'baseline': baseline, 'disks': exact_disks, 'elapsed': 720, 'transitions': {n: 600 for n in a.NAMES}}
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); path = root / a.CHECKPOINT; path.write_text(json.dumps(checkpoint))
            with patch.object(a,'verify_runtime',return_value=root), patch.object(a,'check_credit'), \
                 patch.object(a,'single_runner',return_value=contextlib.nullcontext()), patch.object(a,'disk_snapshot',return_value=exact_disks), \
                 patch.object(a,'stable_group_start') as start, patch.object(a,'fresh_stop_checkpoint') as fresh, \
                 patch.object(lab,'cloud_verify',return_value=report()):
                result=a.execute(root, 999)
                self.assertTrue(result['verified']);start.assert_called_once();fresh.assert_not_called()
                self.assertEqual(json.loads((root/a.PUBLIC_FILE).read_text()),result)
                with self.assertRaisesRegex(RuntimeError,'already exists'):a.execute(root,999)

    def test_interrupted_observation_requires_explicit_new_attempt(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/a.CHECKPOINT).write_text(json.dumps({'schema':a.SCHEMA,'phase':'observing','scope':lab.PREFIX}))
            with patch.object(a,'verify_runtime',return_value=root), patch.object(a,'check_credit'), \
                 patch.object(a,'single_runner',return_value=contextlib.nullcontext()), patch.object(a,'stable_group_start') as start:
                with self.assertRaisesRegex(RuntimeError,'Interrupted before durable stop proof'):a.execute(root,999)
                start.assert_not_called()


if __name__=='__main__':unittest.main()
