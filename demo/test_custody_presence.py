import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from warden import Authority
from custody_presence import REMOTE_SIGNER, challenge_for, verify_presence


class CustodyPresenceTest(unittest.TestCase):
    def test_three_separate_synthetic_signers_and_no_custody_release(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);a=Authority(root/'authority.db')
            try:packages=a.initialize();manifest=a.manifest()
            finally:a.close()
            challenge=challenge_for(manifest);proofs=[]
            for package in packages:
                private=root/(package['id']+'.json');private.write_text(json.dumps(package))
                # This only changes the fixed guest path for the local synthetic fixture.
                code=REMOTE_SIGNER.replace("'/var/lib/warden-custodian/custody.json'",repr(str(private)))
                response=subprocess.run([sys.executable,'-c',code,json.dumps(challenge),package['id']],check=True,capture_output=True,text=True)
                proof=json.loads(response.stdout);proofs.append(proof)
                self.assertEqual(set(proof),{'statement','signature'});self.assertNotIn(package['share'],response.stdout);self.assertNotIn(package['signing_key'],response.stdout)
                rejected=subprocess.run([sys.executable,'-c',code,json.dumps({**challenge,'scope':'certificate-authorization'}),package['id']],capture_output=True,text=True)
                self.assertNotEqual(rejected.returncode,0);self.assertFalse(rejected.stdout)
            result=verify_presence(manifest,challenge,proofs);self.assertTrue(result['verified']);self.assertFalse(result['certificate_authorization'])
            with self.assertRaises(ValueError):verify_presence(manifest,challenge,proofs[:2])
            with self.assertRaises(ValueError):verify_presence(manifest,challenge,[proofs[0],proofs[0],proofs[2]])
            with self.assertRaises(InvalidSignature):verify_presence(manifest,challenge,[{**proofs[0],'signature':proofs[1]['signature']},*proofs[1:]])


if __name__=='__main__':unittest.main()
