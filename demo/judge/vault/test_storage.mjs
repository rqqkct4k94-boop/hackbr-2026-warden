import test from 'node:test';
import assert from 'node:assert/strict';
import {assetName, assetHash, validateStorage} from './storage.mjs';

test('public projection accepts only the named asset and matching generation readback', () => {
  // In-memory schema example only; never passed to the preview build.
  const example = {schema:'warden-storage-cmek-v1', source:'owner-google-api-generation-readback',
    asset:assetName, generation:'17', kms_key_sha256:'1'.repeat(64), kms_key_version:null,
    asset_sha256:assetHash, readback_sha256:assetHash, size_bytes:9163};
  assert.equal(validateStorage(example),example);
  assert.equal(validateStorage({...example,kms_key_version:'3'}).kms_key_version,'3');
  for (const change of [{asset:'other'}, {generation:17}, {generation:'0'}, {kms_key_version:'primary'},
    {readback_sha256:'0'.repeat(64)}, {asset_sha256:'2'.repeat(64)}, {kms_key_sha256:'projects/example'},
    {size_bytes:0}, {source:'provider-attested'}, {bucket:'example'}]) {
    assert.throws(() => validateStorage({...example,...change}),/incompatível/);
  }
});
