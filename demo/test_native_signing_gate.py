import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import native_signing_gate as k
import cloudshell_owner as lab


def provider_metadata():
    return {'provider':'google-cloud-kms','algorithm':k.ALGORITHM,'protection':'SOFTWARE','version':'1',
            'state':'ENABLED','origin':'provider-generated','source':'owner-run-provider-metadata','provider_attestation_verified':False}


def local_fixture():
    # Pure local test fixture; this is not a provider signature or report.
    private = ec.generate_private_key(ec.SECP256R1());pem = private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')
    message={'schema':k.SCHEMA,'scope':'synthetic-demo-only','nonce':'1'*64,'audit_head':'2'*64,'purpose':'demonstrate-provider-native-signing'}
    proof={'schema':k.SCHEMA,'scope':'synthetic-demo-only','message':message,'public_key_pem':pem,
           'signature_der_b64':base64.b64encode(private.sign(k.canonical(message),ec.ECDSA(hashes.SHA256()))).decode(), 'provider_report':provider_metadata()}
    pin={'schema':k.SCHEMA,'public_key_sha256':k.public_fingerprint(pem)[1],'audit_head':message['audit_head']}
    return proof,pin


class NativeSigningTests(unittest.TestCase):
    def test_exact_generated_software_version(self):
        p='synthetic-test';key={'name':k.key_path(p),'purpose':'ASYMMETRIC_SIGN','labels':k.LABELS,
                               'versionTemplate':{'algorithm':k.ALGORITHM,'protectionLevel':'SOFTWARE'}}
        k.validate_key(key,p)
        version={'name':k.key_path(p)+'/cryptoKeyVersions/1','state':'ENABLED', 'algorithm':k.ALGORITHM,
                 'protectionLevel':'SOFTWARE','generateTime':'2026-11-23T12:00:00Z'}
        self.assertEqual(k.validate_version(version,p),provider_metadata())
        for changes in ({'importJob':'test-import'}, {'state':'DISABLED'}, {'protectionLevel':'HSM'}, {'name':k.key_path(p)+'/cryptoKeyVersions/2'}):
            with self.subTest(changes=changes),self.assertRaises(RuntimeError): k.validate_version({**version,**changes},p)
        with self.assertRaises(RuntimeError):k.validate_key({**key,'labels':{'scope':'prod'}},p)

    def test_key_creation_refuses_without_explicit_authority(self):
        with patch.object(k,'key_inventory',return_value={'ring_exists':False,'key_exists':False}),patch.object(lab,'gc') as write:
            with self.assertRaisesRegex(RuntimeError,'explicit owner approval'):k.ensure_key(False)
            write.assert_not_called()

    def test_no_api_enable_and_no_unrelated_ring_write(self):
        with patch.object(lab,'owner_project',return_value='synthetic-test'),patch.object(lab,'gcjson',return_value=[]),patch.object(lab,'gc') as write:
            with self.assertRaisesRegex(RuntimeError,'API is not enabled'):k.key_inventory()
            write.assert_not_called()

    def test_local_signature_fixture_verify_and_reject_altered_proof(self):
        proof,pin=local_fixture();r=k.verify_proof(proof,pin);self.assertTrue(r['signature_verified']);self.assertFalse(r['provider_attestation_verified'])
        changed=copy.deepcopy(proof);changed['message']['nonce']='3'*64
        with self.assertRaises(Exception):k.verify_proof(changed,pin)
        with self.assertRaises(ValueError):k.verify_proof(proof,{**pin,'public_key_sha256':'0'*64})
        with self.assertRaises(ValueError):k.verify_proof({**proof,'provider_report':{**proof['provider_report'],'provider_attestation_verified':True}},pin)
        with self.assertRaises(ValueError):k.public_fingerprint('-----BEGIN PRIVATE KEY-----\nnot-a-key')

    def test_invalid_baseline_blocks_creation(self):
        with tempfile.TemporaryDirectory() as d,patch.object(k,'verify_runtime',return_value=Path(d)),patch.object(k,'check_credit'), \
             patch.object(k,'audit_head',side_effect=ValueError('bad evidence')),patch.object(k,'ensure_key') as key:
            with self.assertRaisesRegex(ValueError,'bad evidence'):k.apply(d,999,True)
            key.assert_not_called()

    def test_ambiguous_sign_call_is_not_repeated(self):
        proof,pin=local_fixture();head=proof['message']['audit_head']
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);stage=root/'native-signing-stage';stage.mkdir();(stage/'challenge.json').write_bytes(k.canonical(proof['message']));(stage/'public.pem').write_text(proof['public_key_pem']);(stage/'sign-request-started').write_text('earlier attempt')
            def gc(*args,**kw):
                self.assertIn('get-public-key',args);target=next(v.split('=',1)[1] for v in args if v.startswith('--output-file='));Path(target).write_text(proof['public_key_pem'],encoding='ascii')
            with patch.object(k,'verify_runtime',return_value=root),patch.object(k,'check_credit'),patch.object(k,'audit_head',return_value=head), \
                 patch.object(k,'ensure_key',return_value=provider_metadata()),patch.object(lab,'gc',side_effect=gc) as command:
                with self.assertRaisesRegex(RuntimeError,'outcome ambiguous'):k.apply(root,999,True)
                self.assertEqual(command.call_count,1)


if __name__=='__main__':unittest.main()
