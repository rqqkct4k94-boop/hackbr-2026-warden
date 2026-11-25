"""Local contract tests only; these fixtures are never public provider evidence."""
import datetime as dt
import sqlite3
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

import ibm_quantum_gate as gate


def iso(seconds):return dt.datetime.fromtimestamp(seconds,dt.timezone.utc).isoformat()


class QuantumGateTests(unittest.TestCase):
    def setUp(self):
        self.now=1795600000
        self.proof,self.pin=gate.make_custody(self.now)
        self.spec=gate.circuit_spec(gate.verify_custody(self.proof,self.pin,self.now))
        self.instance='crn:v1:synthetic-test-only'
        self.job='syntheticjob01'
        self.backend=NS(name=gate.BACKEND,configuration=lambda:NS(simulator=False),status=lambda:NS(operational=True))
        self.counts={'00':122,'11':122,'01':6,'10':6} if self.spec['parity']==0 else {'01':122,'10':122,'00':6,'11':6}

    def fixture(self,**changes):
        pub=NS(metadata={'circuit_metadata':gate.circuit_metadata(self.spec)},data=NS(meas=NS(get_counts=lambda:self.counts)))
        fields={'job_id':lambda:self.job,'instance':self.instance,'status':lambda:'DONE','backend':lambda:self.backend,'tags':gate.job_tags(self.spec),'result':lambda **_:[pub],'metrics':lambda:{'timestamps':{'created':iso(self.now+2),'finished':iso(self.now+4)},'usage':{'qpu_charge_time_seconds':2}}}
        return NS(**{**fields,**changes})

    def test_all_dual_signatures_and_pin(self):
        self.assertEqual(gate.verify_custody(self.proof,self.pin,self.now),self.spec['request_sha256'])
        altered=deepcopy(self.proof);altered['request']['nonce']='a'*64
        with self.assertRaises(Exception):gate.verify_custody(altered,self.pin,self.now)
        altered=deepcopy(self.proof);altered['approvals'].pop()
        with self.assertRaises(ValueError):gate.verify_custody(altered,self.pin,self.now)
        with self.assertRaises(ValueError):gate.verify_custody(self.proof,{**self.pin,'manifest_sha256':'0'*64},self.now)
        with self.assertRaises(ValueError):gate.verify_custody(self.proof,self.pin,self.now+901)

    def test_open_plan_and_backend_scope(self):
        service=NS(instances=lambda:[{'crn':self.instance,'plan':'open'}],active_instance=lambda:self.instance,backend=lambda *_args,**_kwargs:self.backend)
        self.assertIs(gate.open_plan(service,self.instance),self.backend)
        service.instances=lambda:[{'crn':self.instance,'plan':'pay-as-you-go'}]
        with self.assertRaises(ValueError):gate.open_plan(service,self.instance)
        service.instances=lambda:[{'crn':self.instance,'plan':'open'}];self.backend.configuration=lambda:NS(simulator=True)
        with self.assertRaises(ValueError):gate.open_plan(service,self.instance)

    def test_authenticated_adapter_contract_and_binding(self):
        result=gate.provider_observation(self.fixture(),self.instance,self.spec,self.job,self.now,self.now+5)
        self.assertEqual(result['request_sha256'],self.spec['request_sha256'])
        self.assertEqual(result['circuit_sha256'],gate.digest(self.spec))
        self.assertNotIn(self.job,str(result));self.assertNotIn(self.instance,str(result))
        for fixture in (self.fixture(tags=[]),self.fixture(status=lambda:'RUNNING'),self.fixture(instance='wrong'),self.fixture(job_id=lambda:'anotherjob'),self.fixture(result=lambda **_:[NS(metadata={})]),self.fixture(metrics=lambda:{'timestamps':{'created':iso(self.now),'finished':iso(self.now+4)},'usage':{'qpu_charge_time_seconds':0}})):
            with self.assertRaises(ValueError):gate.provider_observation(fixture,self.instance,self.spec,self.job,self.now,self.now+5)
        with self.assertRaises(ValueError):gate.provider_observation(self.fixture(),self.instance,self.spec,self.job,self.now,self.now+305)

    def test_counts_and_replay(self):
        self.assertEqual(gate.validate_counts(self.counts,self.spec['parity']),self.counts)
        for bad in ({'00':256},{'00':128,'11':127},{'bad':256}):
            with self.assertRaises(ValueError):gate.validate_counts(bad,self.spec['parity'])
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'journal.sqlite'
            journal=gate.Journal(path);journal.reserve(self.spec);journal.submitted(self.spec,self.job);journal.close()
            journal=gate.Journal(path);journal.consume(self.spec,self.job);journal.close()
            journal=gate.Journal(path)
            try:
                with self.assertRaises(ValueError):journal.consume(self.spec,self.job)
                with self.assertRaises(sqlite3.IntegrityError):journal.reserve(self.spec)
            finally:journal.close()

    def test_denied_provider_never_decrypts_or_publishes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);fake_job=NS(job_id=lambda:self.job,wait_for_final_state=lambda **_:None)
            service=NS(job=lambda _:self.fixture(status=lambda:'ERROR'),active_instance=lambda:self.instance)
            with patch.object(gate,'submit_physical',return_value=fake_job),patch.object(gate.AESGCM,'decrypt') as decrypt:
                with self.assertRaises(ValueError):gate.run_gate(service,self.instance,root,self.backend)
                decrypt.assert_not_called()
            self.assertFalse((root/'public-ibm-gate-proof.json').exists())

    def test_fixture_success_only_after_persistent_consume(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);fake_job=NS(job_id=lambda:self.job,wait_for_final_state=lambda **_:None)
            service=NS(job=lambda _:self.fixture(),active_instance=lambda:self.instance)
            with patch.object(gate,'make_custody',return_value=(self.proof,self.pin)),patch.object(gate.time,'time',side_effect=[self.now,self.now+5,self.now+5]),patch.object(gate,'submit_physical',return_value=fake_job):
                report=gate.run_gate(service,self.instance,root,self.backend)
            self.assertTrue(report['fixed_document_verified'])
            self.assertFalse(report['provider_attestation_verified']);self.assertFalse(report['kms_operation'])
            db=sqlite3.connect(root/'ibm-physical-gate.sqlite')
            try:self.assertEqual(db.execute('SELECT state FROM gate').fetchone()[0],'consumed')
            finally:db.close()
            self.assertTrue((root/'public-ibm-gate-report.json').exists())


if __name__=='__main__':unittest.main()
