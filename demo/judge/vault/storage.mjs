export const assetName = 'farol-26/issuance-case.json';
export const assetHash = '1c615b76986d07c06d7d5cef4995eae5f6a95f136062c7eb97c6c68915d6d9d2';

// Only this public projection may enter the offline HTML. The report has operator provenance.
export function validateStorage(report) {
  const expected = ['schema', 'source', 'asset', 'generation', 'kms_key_sha256',
    'kms_key_version', 'asset_sha256', 'readback_sha256', 'size_bytes'];
  const positiveId = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value);
  if (!report || Object.keys(report).sort().join('|') !== expected.sort().join('|') ||
      report.schema !== 'warden-storage-cmek-v1' || report.source !== 'owner-google-api-generation-readback' ||
      report.asset !== assetName || report.asset_sha256 !== assetHash ||
      report.readback_sha256 !== assetHash || report.size_bytes !== 9163 ||
      !positiveId(report.generation) || (report.kms_key_version !== null && !positiveId(report.kms_key_version)) ||
      typeof report.kms_key_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(report.kms_key_sha256)) {
    throw new Error('Registro CMEK incompatível com o arquivo ou com o esquema público.');
  }
  return report;
}
