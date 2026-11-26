"""Run the single-service ceremony and export only public evidence and its trust record."""
import argparse
from contextlib import closing
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
from threading import Thread
import time

from serve_demo import SiteHandler, check_tls
from warden import (ActivityLease, Authority, ISSUANCE_POLICY, PolicyError, QuorumDenied,
                    canonical, create_site_csr, digest, make_approval, verify_evidence)
from warden_cli import exclusive


def check_service(key, result, host, root):
    with TemporaryDirectory(prefix="warden-site-") as tmp:
        keyfile, certfile = Path(tmp, "site.key"), Path(tmp, "site.crt")
        exclusive(keyfile, key, private=True)
        certfile.write_text(result["certificate_pem"], encoding="ascii")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        with ThreadingHTTPServer(("127.0.0.1", 0), SiteHandler) as server:
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.site, server.lease = host, ActivityLease()
            thread = Thread(target=server.serve_forever)
            thread.start()
            try:
                observed = check_tls(server.server_port, host, root)
            finally:
                server.shutdown()
                thread.join()
    if not observed["http_ok"] or observed["fingerprint"] != result["fingerprint"]:
        raise RuntimeError("The loopback HTTPS service did not present the issued certificate")


def run_case():
    with closing(Authority(":memory:", clock=lambda: int(time.time()))) as ca:
        custodians = ca.initialize(single_issuance=True)
        manifest = ca.manifest()
        # Capture the trust anchors from initialization before the service has a request.
        pins = {"root": manifest["root_fingerprint"], "manifest": digest(canonical(manifest))}
        host = ISSUANCE_POLICY["hostname"]
        site_key, csr = create_site_csr(host)
        req = ca.request("issue", csr)
        releases = [make_approval(c, req) for c in custodians[:2]]
        try:
            ca.authorize(req["id"], releases)
        except QuorumDenied:
            if ca.certificates():
                raise RuntimeError("Certificate exists after denial")
        else:
            raise RuntimeError("Authority accepted partial approval")
        releases.append(make_approval(custodians[2], req))
        result = ca.authorize(req["id"], releases)
        try:
            ca.authorize(req["id"], releases)
        except PolicyError as exc:
            if str(exc) != "Request is unknown or already completed":
                raise
        else:
            raise RuntimeError("Authority accepted repeated authorization")
        if [c["pem"] for c in ca.certificates()] != [result["certificate_pem"]]:
            raise RuntimeError("Unexpected certificate inventory after replay")
        check_service(site_key, result, host, manifest["root_certificate"])
        evidence = ca.evidence()
        pins["audit_head"] = evidence["events"][-1]["event_hash"]
        verify_evidence(manifest, evidence["events"], pins["root"], pins["manifest"], pins["audit_head"])
        return evidence, pins


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="new directory for this independent ceremony")
    output = parser.parse_args().directory
    output.mkdir(parents=True, exist_ok=False)
    evidence, pins = run_case()
    for name, doc in (("issuance-case.json", evidence), ("issuance-pins.json", pins)):
        exclusive(output / name, (json.dumps(doc, indent=2) + "\n").encode())
    print("2/3 denied (0 certificates), 3/3 issued, replay denied, loopback HTTPS verified.")
    print("Retain the trust record independently:", output / "issuance-pins.json")


if __name__ == "__main__":
    main()
