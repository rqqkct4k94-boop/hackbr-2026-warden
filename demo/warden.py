"""Warden competition-only trust laboratory. No production keys or identities."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


HOSTS = ("alpha.warden-demo.invalid", "beta.warden-demo.invalid")
CUSTODIANS = ("custodian-a", "custodian-b", "custodian-c")
ZERO = "0" * 64
SCHEMA = "warden-hackbr-p0-v1"


class PolicyError(ValueError):
    """A request failed the demo's explicit authorization policy."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def utc(timestamp=None):
    return datetime.now(timezone.utc) if timestamp is None else datetime.fromtimestamp(timestamp, timezone.utc)


def public_bytes(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Warden Synthetic Trust Lab"),
                      x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def xor3(a, b, c):
    if any(len(v) != 32 for v in (a, b, c)):
        raise PolicyError("Invalid custody share size")
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))


def root_certificate(key, at):
    subject = name("Warden Demo Root CA")
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(at - timedelta(minutes=2)).not_valid_after(at + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, key_cert_sign=True, crl_sign=True,
                                       encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))


def validate_csr(pem):
    if not isinstance(pem, str) or len(pem) > 8192:
        raise PolicyError("CSR is missing or too large")
    try:
        csr = x509.load_pem_x509_csr(pem.encode())
        if not csr.is_signature_valid:
            raise PolicyError("Invalid CSR signature")
        public = csr.public_key()
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
            raise PolicyError("Only P-256 demo site keys are supported")
        sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        raw_sans = list(sans)
        names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(raw_sans) != 1 or not isinstance(raw_sans[0], x509.DNSName) or len(names) != 1:
            raise PolicyError("The CSR must have exactly one synthetic DNS name")
        host = raw_sans[0].value
        if host not in HOSTS or names[0].value != host:
            raise PolicyError("The CSR name is outside the synthetic demonstration allowlist")
        return csr, host
    except PolicyError:
        raise
    except (ValueError, TypeError, x509.ExtensionNotFound) as exc:
        raise PolicyError("Malformed or unsupported CSR") from exc


def create_site_csr(host):
    if host not in HOSTS:
        raise PolicyError("Only synthetic demonstration hostnames may be issued")
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder().subject_name(name(host))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
           .sign(key, hashes.SHA256()))
    return private_pem(key), csr.public_bytes(serialization.Encoding.PEM).decode()


def make_approval(package, request, now=None):
    """Run in a custodian's separate process/storage; never publish the release file."""
    now = time.time() if now is None else now
    if (request.get("schema") != SCHEMA or request.get("hostname") not in HOSTS or
            request.get("kind") not in ("issue", "renew", "revoke") or
            request.get("root_fingerprint") != package.get("root_fingerprint") or
            not request["created_at"] <= now <= request["expires_at"]):
        raise PolicyError("Custodian refuses an out-of-scope or expired request")
    if request["expires_at"] - request["created_at"] > 600 or request["expires_at"] <= request["created_at"]:
        raise PolicyError("Custodian refuses an invalid authorization lifetime")
    if request["kind"] in ("issue", "renew"):
        _, csr_host = validate_csr(request.get("csr_pem"))
        if csr_host != request["hostname"]:
            raise PolicyError("Custodian refuses inconsistent certificate scope")
    if request["kind"] == "issue" and request.get("previous_serial") is not None:
        raise PolicyError("Issuance has an unexpected prior certificate")
    if request["kind"] in ("renew", "revoke") and not str(request.get("previous_serial", "")).isdigit():
        raise PolicyError("Custodian requires an explicit previous certificate serial")
    if request["kind"] == "revoke" and request.get("csr_pem") is not None:
        raise PolicyError("Revocation cannot introduce a CSR")
    rid = digest(canonical(request))
    share = unb64(package["share"])
    share_hash = digest(share)
    signed = {"schema": SCHEMA, "request_sha256": rid, "custodian_id": package["id"], "share_sha256": share_hash}
    private = ed25519.Ed25519PrivateKey.from_private_bytes(unb64(package["signing_key"]))
    return {**signed, "signature": b64(private.sign(canonical(signed))), "share": b64(share)}


def validate_signed_evidence(manifest, request, approvals):
    if len(approvals) != 3:
        raise PolicyError("Exactly three independent approvals are required")
    ids = [x.get("custodian_id") for x in approvals]
    if len(set(ids)) != 3 or set(ids) != set(CUSTODIANS):
        raise PolicyError("Three distinct registered custodians are mandatory")
    expected = digest(canonical(request))
    public = {p["id"]: p for p in manifest["custodians"]}
    if request.get("root_fingerprint") != manifest["root_fingerprint"]:
        raise PolicyError("Request belongs to another trust authority")
    for release in approvals:
        identity = public[release["custodian_id"]]
        if release.get("schema") != SCHEMA or release.get("request_sha256") != expected:
            raise PolicyError("Approval is not bound to this exact request")
        if not hmac.compare_digest(release.get("share_sha256", ""), identity["share_sha256"]):
            raise PolicyError("Custody commitment mismatch")
        fields = {k: release[k] for k in ("schema", "request_sha256", "custodian_id", "share_sha256")}
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(unb64(identity["public_key"])).verify(
                unb64(release["signature"]), canonical(fields))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise PolicyError("Custodian signature invalid") from exc


def verify_root_signature(root, obj):
    data = obj.tbs_certificate_bytes if isinstance(obj, x509.Certificate) else obj.tbs_certlist_bytes
    root.public_key().verify(obj.signature, data, ec.ECDSA(obj.signature_hash_algorithm))


class Authority:
    """Local demo authority. Only public metadata and an encrypted CA key are persisted here."""

    def __init__(self, database, clock=time.time):
        self.clock = clock
        self.db = sqlite3.connect(str(database), timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS authority (id INTEGER PRIMARY KEY CHECK(id=1), manifest TEXT NOT NULL, envelope TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, body TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('pending','completed')));
          CREATE TABLE IF NOT EXISTS certificates (serial TEXT PRIMARY KEY, hostname TEXT NOT NULL, pem TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL, revoked_at REAL);
          CREATE TABLE IF NOT EXISTS crl (id INTEGER PRIMARY KEY CHECK(id=1), pem TEXT NOT NULL, number INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, prev_hash TEXT NOT NULL, payload TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE);
        """)

    def close(self):
        self.db.close()

    def _row(self):
        row = self.db.execute("SELECT manifest,envelope FROM authority WHERE id=1").fetchone()
        if row is None:
            raise PolicyError("Authority not initialized")
        return row

    def manifest(self):
        return json.loads(self._row()["manifest"])

    def _append(self, payload):
        last = self.db.execute("SELECT seq,event_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq, prev = (last["seq"] + 1, last["event_hash"]) if last else (1, ZERO)
        doc = {"seq": seq, "prev_hash": prev, "payload": payload}
        final_hash = digest(canonical(doc))
        self.db.execute("INSERT INTO events VALUES(?,?,?,?)", (seq, prev, canonical(payload).decode(), final_hash))
        return final_hash

    def initialize(self):
        """Trusted one-time ceremony; separate packages must leave the authority afterward."""
        if self.db.execute("SELECT 1 FROM authority").fetchone():
            raise PolicyError("Existing authority must never be reinitialized")
        key = ec.generate_private_key(ec.SECP256R1())
        root = root_certificate(key, utc(self.clock()))
        root_fp = fingerprint(root)
        master = AESGCM.generate_key(bit_length=256)
        a, b = secrets.token_bytes(32), secrets.token_bytes(32)
        c = xor3(master, a, b)
        nonce = secrets.token_bytes(12)
        aad = canonical({"schema": SCHEMA, "root_fingerprint": root_fp})
        ciphertext = AESGCM(master).encrypt(nonce, private_pem(key), aad)
        packages, public = [], []
        for cid, share in zip(CUSTODIANS, (a, b, c)):
            signer = ed25519.Ed25519PrivateKey.generate()
            packages.append({"id": cid, "root_fingerprint": root_fp, "share": b64(share),
                             "signing_key": b64(signer.private_bytes(serialization.Encoding.Raw,
                                                   serialization.PrivateFormat.Raw, serialization.NoEncryption()))})
            public.append({"id": cid, "share_sha256": digest(share),
                           "public_key": b64(signer.public_key().public_bytes(serialization.Encoding.Raw,
                                                                serialization.PublicFormat.Raw))})
        manifest = {"schema": SCHEMA, "root_fingerprint": root_fp,
                    "root_certificate": root.public_bytes(serialization.Encoding.PEM).decode(),
                    "policy": "three-of-three-signed-custody-release", "custodians": public}
        with self.db:
            self.db.execute("INSERT INTO authority VALUES(1,?,?)", (canonical(manifest).decode(),
                canonical({"nonce": b64(nonce), "ciphertext": b64(ciphertext)}).decode()))
            self._append({"type": "ceremony", "manifest_sha256": digest(canonical(manifest)), "at": self.clock()})
        return packages

    def _certificate(self, serial):
        row = self.db.execute("SELECT * FROM certificates WHERE serial=?", (serial,)).fetchone()
        if row is None:
            raise PolicyError("Unknown demo certificate")
        return dict(row)

    def request(self, kind, csr_pem=None, previous_serial=None):
        if kind not in ("issue", "renew", "revoke"):
            raise PolicyError("Unsupported lifecycle action")
        if kind == "revoke":
            previo = self._certificate(previous_serial)
            if previo["status"] == "revoked" or csr_pem is not None:
                raise PolicyError("Invalid revocation request")
            host = previo["hostname"]
        else:
            _, host = validate_csr(csr_pem)
            if kind == "renew":
                previo = self._certificate(previous_serial)
                if previo["hostname"] != host or previo["status"] != "active":
                    raise PolicyError("Renewal must refer to an active certificate for this host")
            elif previous_serial is not None:
                raise PolicyError("Issuance cannot specify a prior certificate")
            elif self.db.execute("SELECT 1 FROM certificates WHERE hostname=? AND status='active'", (host,)).fetchone():
                raise PolicyError("An active certificate exists; use the renewal workflow")
        now = self.clock()
        req = {"schema": SCHEMA, "id": uuid.uuid4().hex, "kind": kind, "hostname": host,
               "csr_pem": csr_pem, "previous_serial": previous_serial,
               "created_at": now, "expires_at": now + 600, "root_fingerprint": self.manifest()["root_fingerprint"]}
        with self.db:
            self.db.execute("INSERT INTO requests VALUES(?,?,'pending')", (req["id"], canonical(req).decode()))
            self._append({"type": "request", "request": req, "at": now})
        return req

    def _root_key(self, request, releases):
        manifest = self.manifest()
        validate_signed_evidence(manifest, request, releases)
        shares = {}
        for item in releases:
            try:
                share = unb64(item["share"])
            except (KeyError, TypeError, ValueError) as exc:
                raise PolicyError("Missing or malformed custody release") from exc
            if not hmac.compare_digest(digest(share), item["share_sha256"]):
                raise PolicyError("Released share does not match signed commitment")
            shares[item["custodian_id"]] = share
        master = xor3(*(shares[x] for x in CUSTODIANS))
        envelope = json.loads(self._row()["envelope"])
        aad = canonical({"schema": SCHEMA, "root_fingerprint": manifest["root_fingerprint"]})
        try:
            pem = AESGCM(master).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), aad)
            key = serialization.load_pem_private_key(pem, password=None)
        except (InvalidTag, TypeError, ValueError) as exc:
            raise PolicyError("Unable to reconstruct authenticated CA envelope") from exc
        root = x509.load_pem_x509_certificate(manifest["root_certificate"].encode())
        if public_bytes(key.public_key()) != public_bytes(root.public_key()):
            raise PolicyError("Reconstructed key does not match the pinned CA")
        # Python cannot promise zeroization of immutable bytes or key objects.
        return root, key

    def _issue(self, req, root, key):
        csr, host = validate_csr(req["csr_pem"])
        at = utc(self.clock())
        if req["kind"] == "issue" and self.db.execute("SELECT 1 FROM certificates WHERE hostname=? AND status='active'", (host,)).fetchone():
            raise PolicyError("An active certificate exists; use the renewal workflow")
        if at + timedelta(days=7) >= root.not_valid_after_utc:
            raise PolicyError("Root is too close to expiry")
        cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(root.subject)
                .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(at - timedelta(minutes=1)).not_valid_after(at + timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()), critical=False)
                .sign(key, hashes.SHA256()))
        serial = str(cert.serial_number)
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        if req["kind"] == "renew":
            prior = self._certificate(req["previous_serial"])
            if prior["status"] != "active" or prior["hostname"] != host:
                raise PolicyError("Renewal target is no longer active")
            self.db.execute("UPDATE certificates SET status='superseded' WHERE serial=?", (prior["serial"],))
        self.db.execute("INSERT INTO certificates VALUES(?,?,?,'active',?,NULL)", (serial, host, pem, self.clock()))
        return {"serial": serial, "certificate_pem": pem, "fingerprint": fingerprint(cert)}

    def _revoke(self, req, root, key):
        target = self._certificate(req["previous_serial"])
        if target["status"] == "revoked" or target["hostname"] != req["hostname"]:
            raise PolicyError("Revocation target is no longer eligible")
        at = utc(self.clock())
        self.db.execute("UPDATE certificates SET status='revoked',revoked_at=? WHERE serial=?", (self.clock(), target["serial"]))
        prior = self.db.execute("SELECT number FROM crl WHERE id=1").fetchone()
        number = prior["number"] + 1 if prior else 1
        builder = (x509.CertificateRevocationListBuilder().issuer_name(root.subject)
                   .last_update(at).next_update(at + timedelta(hours=24))
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()), critical=False)
                   .add_extension(x509.CRLNumber(number), critical=False))
        for row in self.db.execute("SELECT serial,revoked_at FROM certificates WHERE status='revoked' ORDER BY serial"):
            entry = (x509.RevokedCertificateBuilder().serial_number(int(row["serial"]))
                     .revocation_date(utc(row["revoked_at"])).build())
            builder = builder.add_revoked_certificate(entry)
        crl = builder.sign(key, hashes.SHA256())
        pem = crl.public_bytes(serialization.Encoding.PEM).decode()
        self.db.execute("INSERT INTO crl VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET pem=excluded.pem,number=excluded.number", (pem, number))
        return {"serial": target["serial"], "crl_pem": pem, "crl_number": number}

    def authorize(self, request_id, releases):
        """The only signing pathway: all three valid releases, matching exact pending request."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
            if row is None or row["state"] != "pending":
                raise PolicyError("Request is unknown or already completed")
            req = json.loads(row["body"])
            if not req["created_at"] <= self.clock() <= req["expires_at"]:
                raise PolicyError("Request expired")
            root, key = self._root_key(req, releases)
            result = self._revoke(req, root, key) if req["kind"] == "revoke" else self._issue(req, root, key)
            public = [{k: item[k] for k in ("schema", "request_sha256", "custodian_id", "share_sha256", "signature")} for item in releases]
            public.sort(key=lambda x: x["custodian_id"])
            event = {"type": "authorized", "request": req, "approvals": public,
                     "result": result, "at": self.clock()}
            event_hash = self._append(event)
            self.db.execute("UPDATE requests SET state='completed' WHERE id=?", (request_id,))
            self.db.commit()
            return {**result, "audit_hash": event_hash}
        except (PolicyError, KeyError, TypeError, ValueError) as exc:
            self.db.rollback()
            message = str(exc) if isinstance(exc, PolicyError) else "Malformed authorization input"
            with self.db:
                self._append({"type": "denied", "request_id": str(request_id)[:64], "reason": message, "at": self.clock()})
            raise PolicyError(message) from exc
        except BaseException:
            self.db.rollback()
            raise

    def certificates(self):
        return [dict(r) for r in self.db.execute("SELECT serial,hostname,pem,status,created_at,revoked_at FROM certificates ORDER BY created_at,serial")]

    def events(self):
        return [{"seq": r["seq"], "prev_hash": r["prev_hash"], "payload": json.loads(r["payload"]),
                 "event_hash": r["event_hash"]} for r in self.db.execute("SELECT * FROM events ORDER BY seq")]

    def evidence(self):
        return {"manifest": self.manifest(), "events": self.events(), "ledger_anchor": None}


def verify_evidence(manifest, events, trusted_root_fingerprint, trusted_manifest_sha256):
    """Independent verifier: pinned root, chain hashes, signatures, lifecycle output.

    This is not an externally anchored ledger or protection against complete history replacement.
    """
    if (manifest["root_fingerprint"] != trusted_root_fingerprint or
            digest(canonical(manifest)) != trusted_manifest_sha256):
        raise PolicyError("Manifest differs from independently pinned root")
    custodians = manifest.get("custodians", [])
    if (len(custodians) != 3 or {c["id"] for c in custodians} != set(CUSTODIANS) or
            len({c["public_key"] for c in custodians}) != 3 or len({c["share_sha256"] for c in custodians}) != 3):
        raise PolicyError("Manifest must pin three different custodians and shares")
    root = x509.load_pem_x509_certificate(manifest["root_certificate"].encode())
    if (fingerprint(root) != trusted_root_fingerprint or root.subject != root.issuer or
            not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca):
        raise PolicyError("Root certificate fingerprint mismatch")
    verify_root_signature(root, root)
    prev, completed, requested, certificates, revoked, checked = ZERO, set(), {}, {}, set(), 0
    active, crl_number = {}, 0
    for i, event in enumerate(events, 1):
        doc = {"seq": i, "prev_hash": prev, "payload": event["payload"]}
        if event["seq"] != i or event["prev_hash"] != prev or digest(canonical(doc)) != event["event_hash"]:
            raise PolicyError("Audit chain integrity failure")
        prev = event["event_hash"]
        p = event["payload"]
        if i == 1 and (p.get("type") != "ceremony" or p.get("manifest_sha256") != digest(canonical(manifest))):
            raise PolicyError("Manifest is not bound to the recorded ceremony")
        if p["type"] == "request":
            req = p["request"]
            if req["id"] in requested:
                raise PolicyError("Duplicate request record")
            requested[req["id"]] = req
        if p["type"] != "authorized":
            continue
        req, out = p["request"], p["result"]
        if req["id"] in completed or requested.get(req["id"]) != req or not req["created_at"] <= p["at"] <= req["expires_at"]:
            raise PolicyError("Invalid authorization lifecycle")
        validate_signed_evidence(manifest, req, p["approvals"])
        if req["kind"] == "revoke":
            if req["previous_serial"] not in certificates or out["serial"] != req["previous_serial"] or out["serial"] in revoked:
                raise PolicyError("Invalid revocation lifecycle")
            crl = x509.load_pem_x509_crl(out["crl_pem"].encode())
            verify_root_signature(root, crl)
            revoked.add(out["serial"])
            crl_number += 1
            if (crl.issuer != root.subject or crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number!=crl_number or
                    out["crl_number"] != crl_number or {str(x.serial_number) for x in crl} != revoked):
                raise PolicyError("CRL does not match authorized revocations")
            if active.get(req["hostname"]) == out["serial"]: active.pop(req["hostname"])
        else:
            csr, host = validate_csr(req["csr_pem"])
            cert = x509.load_pem_x509_certificate(out["certificate_pem"].encode())
            verify_root_signature(root, cert)
            if (host != req["hostname"] or cert.issuer != root.subject or
                    cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value !=
                    x509.SubjectAlternativeName([x509.DNSName(host)]) or
                    cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or
                    public_bytes(csr.public_key()) != public_bytes(cert.public_key()) or
                    fingerprint(cert) != out["fingerprint"] or str(cert.serial_number) != out["serial"] or
                    out["serial"] in certificates):
                raise PolicyError("Certificate does not match approved scope")
            if req["kind"] == "renew" and active.get(host) != req["previous_serial"]:
                raise PolicyError("Invalid renewal linkage")
            if req["kind"] == "issue" and host in active:
                raise PolicyError("Duplicate active certificate")
            certificates[out["serial"]] = host
            active[host] = out["serial"]
        completed.add(req["id"])
        checked += 1
    if not events:
        raise PolicyError("No ceremony evidence")
    return {"verified": True, "events": len(events), "authorized_operations": checked, "head": prev,
            "certificates": len(certificates), "revoked": len(revoked), "ledger_anchored": False}


class ActivityLease:
    """Pure policy component; a cloud shutdown actuator must be tested separately."""

    def __init__(self, clock=time.monotonic, idle_seconds=600):
        self.clock = clock
        self.idle_seconds = idle_seconds
        self.last_activity = clock()
        self.active_operations = 0
        self._lock = threading.Lock()

    def user_activity(self):
        with self._lock:
            self.last_activity = self.clock()

    def health_check(self):
        return self.eligible_for_stop()  # deliberately no activity refresh

    def begin_operation(self):
        with self._lock:
            self.active_operations += 1
            self.last_activity = self.clock()

    def end_operation(self):
        with self._lock:
            if self.active_operations < 1:
                raise RuntimeError("No active operation")
            self.active_operations -= 1
            self.last_activity = self.clock()

    def eligible_for_stop(self):
        with self._lock:
            return self.active_operations == 0 and self.clock() - self.last_activity >= self.idle_seconds


