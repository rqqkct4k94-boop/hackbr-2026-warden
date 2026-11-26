"""Owner-side read-only preflight and generation-specific CMEK acceptance for FAROL-26."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import quote

ASSET = "farol-26/issuance-case.json"
DIGEST = "1c615b76986d07c06d7d5cef4995eae5f6a95f136062c7eb97c6c68915d6d9d2"
SIZE = 9163
SOURCE = "owner-google-api-generation-readback"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def target(project, bucket, key):
    require(re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project), "ID do projeto inválido.")
    require(re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]", bucket), "Nome do bucket inválido.")
    match = re.fullmatch(r"projects/" + re.escape(project) +
                         r"/locations/([a-z0-9-]+)/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+", key)
    require(match, "Indique a CryptoKey existente do projeto aprovado, sem versão.")
    return match[1]


def preflight(get, project, bucket, key):
    location = target(project, bucket, key)
    project_meta = get(f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}")
    bucket_meta = get(f"https://storage.googleapis.com/storage/v1/b/{bucket}")
    key_meta = get(f"https://cloudkms.googleapis.com/v1/{key}")
    require(project_meta.get("projectId") == project and project_meta.get("projectNumber"), "Projeto divergente.")
    require(str(bucket_meta.get("projectNumber")) == str(project_meta["projectNumber"]) and
            bucket_meta.get("name") == bucket, "Bucket fora do projeto aprovado.")
    require(bucket_meta.get("location", "").lower() == location, "Localização do bucket e da CMEK divergente.")
    number_key = key.replace(f"projects/{project}/", f"projects/{project_meta['projectNumber']}/", 1)
    approved_keys = {key, number_key}
    require(key_meta.get("name") in approved_keys and key_meta.get("purpose") == "ENCRYPT_DECRYPT" and
            key_meta.get("primary", {}).get("state") == "ENABLED" and
            key_meta["primary"].get("algorithm") == "GOOGLE_SYMMETRIC_ENCRYPTION",
            "CMEK simétrica aprovada com versão primária habilitada não confirmada.")
    return approved_keys


def record(get, read_bytes, bucket, approved_keys, generation):
    require(re.fullmatch(r"[1-9][0-9]{0,19}", generation), "Geração inválida.")
    url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{quote(ASSET, safe='')}"
    meta = get(url, {"generation": generation})
    require(meta.get("bucket") == bucket and meta.get("name") == ASSET and
            str(meta.get("generation")) == generation and str(meta.get("size")) == str(SIZE)
            and not meta.get("contentEncoding"), "Objeto, versão, tamanho ou codificação divergente.")
    observed = meta.get("kmsKeyName", "")
    key, separator, version = observed.partition("/cryptoKeyVersions/")
    require(key in approved_keys and (not separator or re.fullmatch(r"[1-9][0-9]{0,19}", version)), "Metadados da geração não identificam a CMEK aprovada.")
    raw = read_bytes(url, {"alt": "media", "generation": generation})
    digest = hashlib.sha256(raw).hexdigest()
    require(len(raw) == SIZE and digest == DIGEST, "Digest da releitura divergente.")
    return {"schema": "warden-storage-cmek-v1", "source": SOURCE, "asset": ASSET, "generation": generation,
            "kms_key_sha256": hashlib.sha256(observed.encode()).hexdigest(), "kms_key_version": version or None,
            "asset_sha256": DIGEST, "readback_sha256": digest, "size_bytes": len(raw)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="mode", required=True)
    for mode in ("preflight", "record"):
        sub = subs.add_parser(mode)
        sub.add_argument("--project", required=True)
        sub.add_argument("--bucket", required=True)
        sub.add_argument("--kms-key", required=True)
        if mode == "record":
            sub.add_argument("--generation", required=True)
            sub.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    target(args.project, args.bucket, args.kms_key)
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    with AuthorizedSession(credentials) as session:
        def get(url, params=None):
            with session.get(url, params=params, timeout=20, allow_redirects=False) as response:
                require(response.status_code == 200, f"Consulta de metadados recusada (HTTP {response.status_code}).")
                return response.json()

        def read_bytes(url, params):
            with session.get(url, params=params, timeout=20, allow_redirects=False, stream=True,
                             headers={"Accept-Encoding": "identity"}) as response:
                require(response.status_code == 200, f"Releitura recusada (HTTP {response.status_code}).")
                return response.raw.read(SIZE + 1, decode_content=False)

        approved_keys = preflight(get, args.project, args.bucket, args.kms_key)
        if args.mode == "preflight":
            print("Recursos existentes conferidos. Permissão de gravação e proteção do objeto permanecem sem teste.")
            return
        report = record(get, read_bytes, args.bucket, approved_keys, args.generation)
        with args.output.open("x", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print("Registro público do operador salvo. Atestação independente do provedor permanece em aberto.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, FileExistsError) as error:
        raise SystemExit(str(error)) from None
    except Exception:
        raise SystemExit("Consulta não concluída. Confira SDK, credenciais privadas e acesso de leitura no terminal.") from None
