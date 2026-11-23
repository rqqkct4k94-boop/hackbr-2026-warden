import copy
import hashlib
import http.server
import json
import socket
import ssl
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from warden import (Authority, ActivityLease, HOSTS, PolicyError, canonical, digest,
                    create_site_csr, make_approval, verify_evidence, b64)


class DemoSite(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data = self.server.site.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@contextmanager
def tls_site(directory, hostname, key, cert):
    key_file, cert_file = directory / (hostname + '.key'), directory / (hostname + '.crt')
    key_file.write_bytes(key)
    cert_file.write_text(cert, encoding='ascii')
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), DemoSite)
    server.site = hostname
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request_https(port, hostname, context):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls:
            fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
            tls.sendall(f'GET / HTTP/1.0\r\nHost: {hostname}\r\n\r\n'.encode())
            chunks = []
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            return fingerprint, b''.join(chunks)


class WardenTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='warden-demo-test-')
        self.dir = Path(self.temp.name)
        self.db = self.dir / 'authority.db'
        self.authority = Authority(self.db)
        self.custodians = self.authority.initialize()
        self.manifest = self.authority.manifest()
        self.root = self.manifest['root_fingerprint']
        self.manifest_sha = digest(canonical(self.manifest))

    def tearDown(self):
        self.authority.close()
        self.temp.cleanup()

    def releases(self, request):
        return [make_approval(c, request) for c in self.custodians]

    def issue(self, host, prior=None):
        key, csr = create_site_csr(host)
        req = self.authority.request('renew' if prior else 'issue', csr, prior)
        out = self.authority.authorize(req['id'], self.releases(req))
        return key, out, req

    def verify(self):
        return verify_evidence(self.authority.manifest(), self.authority.events(), self.root, self.manifest_sha)

    def test_unanimous_signatures_and_custody_required(self):
        _, csr = create_site_csr(HOSTS[0]); req = self.authority.request('issue', csr)
        releases = self.releases(req)
        for subset in ([], releases[:1], releases[:2], [releases[0], releases[0], releases[2]]):
            with self.assertRaises(PolicyError):
                self.authority.authorize(req['id'], subset)
        self.assertEqual(len(self.authority.certificates()), 0)
        malformed = copy.deepcopy(releases); malformed[1]['share'] = b64(bytes(32))
        with self.assertRaises(PolicyError):
            self.authority.authorize(req['id'], malformed)
        malformed = copy.deepcopy(releases); malformed[1]['signature'] = b64(bytes(64))
        with self.assertRaises(PolicyError):
            self.authority.authorize(req['id'], malformed)
        self.assertEqual(len(self.authority.certificates()), 0)
        result = self.authority.authorize(req['id'], releases)
        self.assertTrue(result['fingerprint'])
        with self.assertRaises(PolicyError):
            self.authority.authorize(req['id'], releases)
        self.assertEqual(self.verify()['authorized_operations'], 1)
        evidence = json.dumps(self.authority.evidence())
        for release in releases:
            self.assertNotIn(release['share'], evidence)
        for custodian in self.custodians:
            self.assertNotIn(custodian['signing_key'], evidence)

    def test_approvals_cannot_be_reused_for_another_request(self):
        _, csr1 = create_site_csr(HOSTS[0]); _, csr2 = create_site_csr(HOSTS[1])
        req1 = self.authority.request('issue', csr1)
        req2 = self.authority.request('issue', csr2)
        with self.assertRaisesRegex(PolicyError, 'exact request'):
            self.authority.authorize(req2['id'], self.releases(req1))
        self.assertEqual(len(self.authority.certificates()), 0)
        with self.assertRaises(PolicyError):
            create_site_csr('outside-synthetic-allowlist.example')

    def test_request_expiry_fails_closed(self):
        _, csr = create_site_csr(HOSTS[0]); req = self.authority.request('issue', csr)
        releases = self.releases(req)
        self.authority.clock = lambda: req['expires_at'] + 1
        with self.assertRaisesRegex(PolicyError, 'expired'):
            self.authority.authorize(req['id'], releases)
        self.assertEqual(len(self.authority.certificates()), 0)

    def test_actual_https_sites_with_distinct_keys_and_certificates(self):
        key1, a, _ = self.issue(HOSTS[0]); key2, b, _ = self.issue(HOSTS[1])
        self.assertNotEqual(key1, key2)
        self.assertNotEqual(a['fingerprint'], b['fingerprint'])
        client = ssl.create_default_context(cadata=self.manifest['root_certificate'])
        with tls_site(self.dir, HOSTS[0], key1, a['certificate_pem']) as p1, tls_site(self.dir, HOSTS[1], key2, b['certificate_pem']) as p2:
            fa, body_a = request_https(p1, HOSTS[0], client)
            fb, body_b = request_https(p2, HOSTS[1], client)
            self.assertEqual(fa, a['fingerprint']); self.assertEqual(fb, b['fingerprint'])
            self.assertIn(b'200 OK', body_a); self.assertIn(HOSTS[0].encode(), body_a)
            self.assertIn(b'200 OK', body_b); self.assertIn(HOSTS[1].encode(), body_b)
            with self.assertRaises(ssl.SSLCertVerificationError):
                request_https(p1, HOSTS[1], client)
            with self.assertRaises(ssl.SSLCertVerificationError):
                request_https(p1, HOSTS[0], ssl.create_default_context())
        verified = self.verify()
        self.assertEqual(verified['certificates'], 2)
        self.assertFalse(verified['ledger_anchored'])

    def test_renew_revocation_crl_and_restart(self):
        key1, a, _ = self.issue(HOSTS[0]); key2, b, _ = self.issue(HOSTS[0], a['serial'])
        self.assertNotEqual(a['serial'], b['serial'])
        self.assertNotEqual(key1, key2)
        req = self.authority.request('revoke', previous_serial=a['serial'])
        with self.assertRaises(PolicyError):
            self.authority.authorize(req['id'], self.releases(req)[:2])
        revoked = self.authority.authorize(req['id'], self.releases(req))
        crl = x509.load_pem_x509_crl(revoked['crl_pem'].encode())
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(int(a['serial'])))
        pem = self.dir / 'pinned-root-and-crl.pem'
        pem.write_text(self.manifest['root_certificate'] + revoked['crl_pem'], encoding='ascii')
        client = ssl.create_default_context(cafile=str(pem)); client.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        with tls_site(self.dir, HOSTS[0], key1, a['certificate_pem']) as old_port:
            with self.assertRaises(ssl.SSLCertVerificationError):
                request_https(old_port, HOSTS[0], client)
        with tls_site(self.dir, HOSTS[0], key2, b['certificate_pem']) as new_port:
            self.assertEqual(request_https(new_port, HOSTS[0], client)[0], b['fingerprint'])
        expected = self.verify(); self.authority.close(); self.authority = Authority(self.db)
        self.assertEqual(self.verify(), expected)
        self.assertEqual({x['status'] for x in self.authority.certificates()}, {'active','revoked'})
        with self.assertRaises(PolicyError):
            self.authority.authorize(req['id'], self.releases(req))

    def test_independent_verifier_detects_audit_and_manifest_changes(self):
        self.issue(HOSTS[0]); data = self.authority.evidence()
        data['events'][-1]['payload']['result']['fingerprint'] = '0' * 64
        with self.assertRaisesRegex(PolicyError, 'integrity'):
            verify_evidence(data['manifest'], data['events'], self.root, self.manifest_sha)
        data = self.authority.evidence(); data['manifest']['custodians'][0]['public_key'] = 'fake'
        with self.assertRaises(PolicyError):
            verify_evidence(data['manifest'], data['events'], self.root, self.manifest_sha)

    def test_runtime_root_key_is_encrypted_in_authority_storage(self):
        row = self.authority.db.execute('SELECT envelope,manifest FROM authority').fetchone()
        self.assertNotIn('PRIVATE KEY', row['envelope']); self.assertNotIn('PRIVATE KEY', row['manifest'])
        for custodian in self.custodians:
            self.assertNotIn(custodian['share'], row['manifest'])
            self.assertNotIn(custodian['signing_key'], row['manifest'])


class LifecycleTests(unittest.TestCase):
    def test_ten_minute_true_idle_and_health_checks(self):
        now = [0]; lease = ActivityLease(lambda: now[0]);
        now[0] = 599; self.assertFalse(lease.health_check())
        now[0] = 600; self.assertTrue(lease.health_check())
        lease.user_activity(); self.assertFalse(lease.eligible_for_stop())
        lease.begin_operation(); now[0] = 1250
        self.assertFalse(lease.eligible_for_stop())
        lease.end_operation(); now[0] = 1849; self.assertFalse(lease.eligible_for_stop())
        now[0] = 1850; self.assertTrue(lease.eligible_for_stop())


if __name__ == '__main__':
    unittest.main(verbosity=2)

