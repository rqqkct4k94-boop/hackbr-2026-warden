"""Offline acceptance contract; these stand-in responses are never exported as cloud evidence."""
import hashlib
from pathlib import Path
import unittest

from vault_storage import ASSET, DIGEST, preflight, record

PROJECT = "demo-synthetic"
BUCKET = "example-test-bucket"
KEY = f"projects/{PROJECT}/locations/us/keyRings/example/cryptoKeys/example"
RAW = Path(__file__).with_name("judge").joinpath("issuance-case.json").read_bytes().replace(b"\r\n", b"\n")


class VaultStorageTests(unittest.TestCase):
    def test_preflight_scopes_project_location_and_symmetric_key(self):
        metadata = [{"projectId": PROJECT, "projectNumber": "123"},
                    {"projectNumber": "123", "name": BUCKET, "location": "US"},
                    {"name": KEY, "purpose": "ENCRYPT_DECRYPT",
                     "primary": {"state": "ENABLED", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}}]
        def run():
            data = iter(metadata)
            preflight(lambda _: next(data), PROJECT, BUCKET, KEY)
        run()
        for i, name, value in [(1, "projectNumber", "321"), (1, "location", "EU"), (2, "purpose", "ASYMMETRIC_SIGN")]:
            with self.subTest(name=name):
                previous = metadata[i][name]
                metadata[i][name] = value
                with self.assertRaises(ValueError):
                    run()
                metadata[i][name] = previous

    def test_generation_metadata_and_exact_readback(self):
        meta = {"name": ASSET, "bucket": BUCKET, "generation": "123", "size": str(len(RAW)), "kmsKeyName": KEY}
        calls = []
        def read(url, params):
            self.assertTrue(url.endswith("/o/farol-26%2Fissuance-case.json"))
            self.assertEqual(params, {"alt": "media", "generation": "123"})
            calls.append(url)
            return RAW
        def get(url, params):
            self.assertEqual(params, {"generation": "123"})
            return meta
        result = record(get, read, BUCKET, {KEY}, "123")
        self.assertEqual((result["asset_sha256"], result["readback_sha256"]), (DIGEST, DIGEST))
        self.assertIsNone(result["kms_key_version"])
        meta["kmsKeyName"] += "/cryptoKeyVersions/5"
        report = record(get, read, BUCKET, {KEY}, "123")
        self.assertEqual(report["kms_key_version"], "5")
        self.assertEqual(report["kms_key_sha256"], hashlib.sha256(meta["kmsKeyName"].encode()).hexdigest())
        self.assertNotIn(KEY, str(report))
        self.assertNotIn(BUCKET, str(report))
        for key, value in [("kmsKeyName", KEY+"-other"), ("generation", "2"), ("name", "other"),
                           ("size", "1"), ("bucket", "other"), ("contentEncoding", "gzip")]:
            with self.subTest(field=key), self.assertRaises(ValueError):
                record(lambda *_: {**meta, key:value}, read, BUCKET, {KEY}, "123")
        self.assertEqual(len(calls), 2)
        with self.assertRaisesRegex(ValueError, "Digest"):
            record(get, lambda *_: b"x" * len(RAW), BUCKET, {KEY}, "123")
