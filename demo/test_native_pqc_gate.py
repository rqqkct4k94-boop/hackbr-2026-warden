import unittest
from copy import deepcopy
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

import native_pqc_gate as p


class NativePqcTests(unittest.TestCase):
    def setUp(self):
        self.head='a'*64
        self.sign=mldsa.MLDSA65PrivateKey.generate()
        self.kem=mlkem.MLKEM768PrivateKey.generate()
        sr=self.sign.public_key().public_bytes_raw();kr=self.kem.public_key().public_bytes_raw()
        trial=p.kem_trial(kr,self.kem.decapsulate,self.head)
        message={'schema':p.SCHEMA,'scope':'synthetic-demo-only','purpose':'native-pqc-synthetic-acceptance','nonce':'b'*64,'audit_head':self.head,'kem_public_sha256':p.sha(kr),'kem_trial':trial}
        self.proof={'schema':p.SCHEMA,'scope':'synthetic-demo-only','message':message,'sign_public_raw_b64':p.b64(sr),'kem_public_raw_b64':p.b64(kr),'signature_b64':p.b64(self.sign.sign(p.canonical(message))),'provider_report':p.metadata()}
        self.pin={'schema':p.SCHEMA,'audit_head':self.head,'sign_public_sha256':p.sha(sr),'kem_public_sha256':p.sha(kr)}

    def test_real_local_fixture_signature_and_kem(self):
        # Local fixture never published as evidence of provider behavior.
        result=p.verify_proof(self.proof,self.pin)
        self.assertTrue(result['signature_verified']);self.assertTrue(result['kem_operator_report_consistent']);self.assertFalse(result['provider_attestation_verified']);self.assertFalse(result['hybrid_xwing_verified']);self.assertFalse(result['quantum_gate_verified'])

    def test_wrong_kem_recipient_denied(self):
        wrong=mlkem.MLKEM768PrivateKey.generate()
        with self.assertRaises(RuntimeError):p.kem_trial(self.kem.public_key().public_bytes_raw(),wrong.decapsulate,self.head)

    def test_changed_signed_report_and_pin_denied(self):
        modified=deepcopy(self.proof);modified['message']['nonce']='c'*64
        with self.assertRaises(InvalidSignature):p.verify_proof(modified,self.pin)
        with self.assertRaises(ValueError):p.verify_proof(self.proof,{**self.pin,'sign_public_sha256':'0'*64})
        modified=deepcopy(self.proof);modified['message']['kem_trial']['hybrid_xwing_verified']=True
        with self.assertRaises(ValueError):p.verify_proof(modified,self.pin)
        modified=deepcopy(self.proof);modified['provider_report']['quantum_gate_verified']=True
        with self.assertRaises(ValueError):p.verify_proof(modified,self.pin)

    def test_exact_key_scope_guards(self):
        project='synthetic-project';name=p.SIGN;purpose,algorithm,_,_,_=p.SPECS[name]
        metadata={'name':p.key_path(project,name),'purpose':purpose,'labels':p.LABELS,'versionTemplate':{'algorithm':algorithm,'protectionLevel':'SOFTWARE'}}
        p.validate_key(name,metadata,project)
        with self.assertRaises(RuntimeError):p.validate_key(name,{**metadata,'labels':{'hackbr':'other'}},project)
        version={'name':p.key_path(project,name)+'/cryptoKeyVersions/1','state':'ENABLED','algorithm':algorithm,'protectionLevel':'SOFTWARE','generateTime':'2026-11-24T03:00:00Z'}
        self.assertEqual(p.validate_version(name,version,project),'ENABLED')
        with self.assertRaises(RuntimeError):p.validate_version(name,{**version,'importTime':'fake'},project)
        with self.assertRaises(RuntimeError):p.validate_version(name,{**version,'name':version['name'][:-1]+'2'},project)
        with self.assertRaises(ValueError):p.options('unrelated')

    def test_no_creation_without_explicit_approval(self):
        with patch.object(p,'inventory',return_value={'ring_exists':False,'keys':{}}),patch.object(p.lab,'gc') as cloud:
            with self.assertRaises(RuntimeError):p.ensure_keys(False)
            cloud.assert_not_called()


if __name__=='__main__':unittest.main()
