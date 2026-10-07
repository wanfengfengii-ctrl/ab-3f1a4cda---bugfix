"""End-to-end HTTP tests against a live server instance."""

import base64
import hashlib
import http.client
import json
import os
import tempfile
import threading
import time
import unittest

from app import ed25519
from app.server import build_server

SEED = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1" "66d38535076f094b85ce3a2e0b4458f7")
PUB = ed25519.publickey(SEED)
KEY_ID = "http-vendor"


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class HttpCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.keys_path = os.path.join(cls.tmp.name, "keys.json")
        cls.db_path = os.path.join(cls.tmp.name, "att.db")
        with open(cls.keys_path, "w") as fh:
            json.dump({"keys": {KEY_ID: {
                "algorithm": "Ed25519",
                "publicKeyBase64": base64.b64encode(PUB).decode(),
            }}}, fh)
        cls.server = build_server("127.0.0.1", 0, cls.db_path, cls.keys_path)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def req(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json"} if body is not None else {}
        conn.request(method, path, body=json.dumps(body) if body is not None else None,
                     headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw) if raw else {}

    def attestation_body(self, att_id, device, gen, prev, config, *, bad_sig=False,
                         key_id=KEY_ID, prereqs=None):
        doc = {"deviceId": device, "generation": gen, "previousGeneration": prev,
               "configSha256": h(config)}
        if prereqs is not None:
            doc["prerequisites"] = prereqs
        payload = json.dumps(doc, separators=(",", ":")).encode()
        sig = b"\x00" * 64 if bad_sig else ed25519.sign(payload, SEED)
        return {
            "attestationId": att_id,
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload).decode(),
            "signatureBase64": base64.b64encode(sig).decode(),
        }

    def test_health(self):
        status, body = self.req("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_full_flow_and_head(self):
        body = self.attestation_body("att-1", "sat-1", 1, 0, b"config-v1")
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 201, resp)
        self.assertEqual(resp["status"], "accepted")

        status, resp = self.req("GET", "/api/devices/sat-1/head")
        self.assertEqual(status, 200)
        self.assertEqual(resp["generation"], 1)
        self.assertEqual(resp["configSha256"], h(b"config-v1"))

        # chain successor
        b2 = self.attestation_body("att-2", "sat-1", 2, 1, b"config-v2")
        status, resp = self.req("POST", "/api/attestations", b2)
        self.assertEqual(status, 201)

        status, resp = self.req("GET", "/api/devices/sat-1/head")
        self.assertEqual(resp["generation"], 2)

    def test_retry_is_idempotent(self):
        body = self.attestation_body("att-r", "sat-r", 1, 0, b"c")
        s1, r1 = self.req("POST", "/api/attestations", body)
        s2, r2 = self.req("POST", "/api/attestations", body)
        self.assertEqual((s1, r1["status"]), (201, "accepted"))
        self.assertEqual((s2, r2["status"]), (200, "duplicate"))

    def test_unknown_device_head(self):
        status, resp = self.req("GET", "/api/devices/ghost/head")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "DEVICE_NOT_FOUND")

    def test_unknown_key_error_code(self):
        body = self.attestation_body("x", "sat-x", 1, 0, b"c", key_id="missing")
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 401)
        self.assertEqual(resp["error"]["code"], "UNKNOWN_KEY_ID")

    def test_bad_signature_error_code(self):
        body = self.attestation_body("x", "sat-x", 1, 0, b"c", bad_sig=True)
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 401)
        self.assertEqual(resp["error"]["code"], "INVALID_SIGNATURE")

    def test_conflict_error_codes(self):
        self.req("POST", "/api/attestations",
                 self.attestation_body("c1", "sat-c", 1, 0, b"v1"))
        # stale predecessor: head is 1 but request claims predecessor 0
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("c2", "sat-c", 3, 0, b"v3"))
        self.assertEqual(s, 409)
        self.assertEqual(r["error"]["code"], "STALE_PREDECESSOR")
        # same id, different content
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("c1", "sat-c", 2, 1, b"v2"))
        self.assertEqual(r["error"]["code"], "ATTESTATION_ID_CONTENT_MISMATCH")
        # head not advanced
        s, head = self.req("GET", "/api/devices/sat-c/head")
        self.assertEqual(head["generation"], 1)
        self.assertEqual(head["configSha256"], h(b"v1"))

    def test_malformed_request(self):
        s, r = self.req("POST", "/api/attestations", {"attestationId": "z"})
        self.assertEqual(s, 400)
        self.assertEqual(r["error"]["code"], "MALFORMED_REQUEST")

    def test_unknown_route(self):
        s, _ = self.req("GET", "/nope")
        self.assertEqual(s, 404)

    # ------------------------------------------------------- prerequisites
    def _seed_dependency(self, device="dep", config=b"dep-v1", gen=1, att_id=None):
        att_id = att_id or f"dep-{device}-{gen}-{h(config)[:12]}"
        body = self.attestation_body(att_id, device, gen, gen - 1, config)
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertIn(status, (200, 201), resp)

    def _prereq_body(self, att_id, device, gen, prev, config, prereqs):
        return self.attestation_body(att_id, device, gen, prev, config, prereqs=prereqs)

    def test_prerequisite_accepted_over_http(self):
        self._seed_dependency(config=b"dep-v1")
        body = self._prereq_body("t-1", "tgt", 1, 0, b"tgt-v1", [
            {"deviceId": "dep", "generation": 1, "configSha256": h(b"dep-v1")}])
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 201, resp)
        status, head = self.req("GET", "/api/devices/tgt/head")
        self.assertEqual(head["generation"], 1)

    def test_prerequisite_missing_device_over_http(self):
        body = self._prereq_body("t-miss", "tgt-miss", 1, 0, b"c", [
            {"deviceId": "ghost-dev", "generation": 1, "configSha256": h(b"x")}])
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 409)
        self.assertEqual(resp["error"]["code"], "PREREQUISITE_NOT_SATISFIED")
        status, resp = self.req("GET", "/api/devices/tgt-miss/head")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "DEVICE_NOT_FOUND")

    def test_prerequisite_version_and_digest_mismatch_over_http(self):
        self._seed_dependency(device="dep-vm", config=b"dep-v1",
                              att_id="dep-vm-1")
        status, resp = self.req("POST", "/api/attestations",
                                self.attestation_body(
                                    "dep-vm-2", "dep-vm", 2, 1, b"dep-v2"))
        self.assertEqual(status, 201, resp)
        # stale generation pinned
        body = self._prereq_body("t-stale", "tgt-stale", 1, 0, b"c", [
            {"deviceId": "dep-vm", "generation": 1, "configSha256": h(b"dep-v1")}])
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 409)
        self.assertEqual(resp["error"]["code"], "PREREQUISITE_NOT_SATISFIED")
        # correct generation but wrong digest
        body = self._prereq_body("t-digest", "tgt-digest", 1, 0, b"c", [
            {"deviceId": "dep-vm", "generation": 2, "configSha256": h(b"wrong")}])
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(resp["error"]["code"], "PREREQUISITE_NOT_SATISFIED")
        # neither target exists
        for device in ("tgt-stale", "tgt-digest"):
            status, _ = self.req("GET", f"/api/devices/{device}/head")
            self.assertEqual(status, 404)

    def test_prerequisite_retry_replays_after_dependency_advances(self):
        self._seed_dependency(device="dep-r", config=b"r1")
        prereq = [{"deviceId": "dep-r", "generation": 1, "configSha256": h(b"r1")}]
        body = self._prereq_body("t-r", "tgt-r", 1, 0, b"c", prereq)
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 201, resp)
        # dependency moves on, then the identical target request is retried
        self.req("POST", "/api/attestations",
                 self.attestation_body("dep-r-2", "dep-r", 2, 1, b"r2"))
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "duplicate")
        status, head = self.req("GET", "/api/devices/tgt-r/head")
        self.assertEqual(head["generation"], 1)

    def test_prerequisite_payload_validation_over_http(self):
        self._seed_dependency(device="dep-v", config=b"v1")
        good = {"deviceId": "dep-v", "generation": 1, "configSha256": h(b"v1")}

        def malformed(att_id, device, entry):
            return self._prereq_body(att_id, device, 1, 0, b"c", [entry])

        cases = [
            ("m-self", "dep-v", dict(good, deviceId="dep-v")),       # self reference
            ("m-badgen", "bg-t", dict(good, generation=0)),
            ("m-badsha", "bs-t", dict(good, configSha256=h(b"v1").upper())),
        ]
        for att_id, device, entry in cases:
            status, resp = self.req("POST", "/api/attestations",
                                    malformed(att_id, device, entry))
            self.assertEqual(status, 400, (att_id, resp))
            self.assertEqual(resp["error"]["code"], "INVALID_JSON_PAYLOAD", att_id)
        # duplicate deviceIds
        status, resp = self.req(
            "POST", "/api/attestations",
            self._prereq_body("m-dup2", "dup-t2", 1, 0, b"c", [good, dict(good)]))
        self.assertEqual(resp["error"]["code"], "INVALID_JSON_PAYLOAD")
        # empty list
        status, resp = self.req(
            "POST", "/api/attestations",
            self._prereq_body("m-empty", "empty-t", 1, 0, b"c", []))
        self.assertEqual(resp["error"]["code"], "INVALID_JSON_PAYLOAD")
        # nothing admitted for any malformed target
        for device in ("bg-t", "bs-t", "dup-t2", "empty-t"):
            status, _ = self.req("GET", f"/api/devices/{device}/head")
            self.assertEqual(status, 404, device)


if __name__ == "__main__":
    unittest.main()
