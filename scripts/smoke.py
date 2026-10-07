"""Signature-admission smoke test run inside the one-shot ``verify`` service.

It generates a fresh keypair, declares the public key, starts the real HTTP
server on an ephemeral port, exercises accept/retry/reject paths, then restarts
a second server against the same database to prove head persistence.

Exit code is non-zero (count of failures) if any check fails.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import ed25519
from app.server import build_server

FAILURES = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    print(f"[smoke:{mark}] {name}{(' - ' + detail) if detail and not condition else ''}")
    global FAILURES
    if not condition:
        FAILURES += 1


def request(port: int, method: str, path: str, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, body=json.dumps(body) if body is not None else None,
                 headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, (json.loads(raw) if raw else {})


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="smoke-")
    db_path = os.path.join(tmp, "att.db")
    keys_path = os.path.join(tmp, "keys.json")

    seed = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1" "66d38535076f094b85ce3a2e0b4458f7")
    public = ed25519.publickey(seed)
    key_id = "smoke-vendor"
    device = "smoke-sat-1"
    # The key is deliberately left unbound so it can sign for every device in
    # the multi-device formation scenarios below.
    with open(keys_path, "w", encoding="utf-8") as fh:
        json.dump({"keys": {key_id: {
            "algorithm": "Ed25519",
            "publicKeyBase64": base64.b64encode(public).decode(),
        }}}, fh)

    server = build_server("127.0.0.1", 0, db_path, keys_path)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    try:
        status, body = request(port, "GET", "/healthz")
        check("healthz", status == 200 and body.get("status") == "ok", f"{status} {body}")

        config1 = b"smoke-config-v1"
        doc1 = {
            "deviceId": device,
            "generation": 1,
            "previousGeneration": 0,
            "configSha256": hashlib.sha256(config1).hexdigest(),
        }
        payload1 = json.dumps(doc1, separators=(",", ":")).encode()
        envelope = {
            "attestationId": "smoke-att-1",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload1).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(payload1, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", envelope)
        check("first attestation accepted (201)", status == 201, f"{status} {body}")

        # exact retry -> original result, no state change
        status, body = request(port, "POST", "/api/attestations", envelope)
        check("identical retry is duplicate (200)",
              status == 200 and body.get("status") == "duplicate", f"{status} {body}")

        # wrong signature rejected, state untouched
        bad = dict(envelope)
        bad["signatureBase64"] = base64.b64encode(b"\x00" * 64).decode()
        status, body = request(port, "POST", "/api/attestations", bad)
        check("bad signature rejected",
              status == 401 and body["error"]["code"] == "INVALID_SIGNATURE", f"{status} {body}")

        # unknown key rejected
        bad_key = dict(envelope)
        bad_key["attestationId"] = "smoke-att-x"
        bad_key["keyId"] = "does-not-exist"
        status, body = request(port, "POST", "/api/attestations", bad_key)
        check("unknown key rejected",
              status == 401 and body["error"]["code"] == "UNKNOWN_KEY_ID", f"{status} {body}")

        # successor chaining
        config2 = b"smoke-config-v2"
        doc2 = {"deviceId": device, "generation": 2, "previousGeneration": 1,
                "configSha256": hashlib.sha256(config2).hexdigest()}
        payload2 = json.dumps(doc2, separators=(",", ":")).encode()
        env2 = {
            "attestationId": "smoke-att-2",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload2).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(payload2, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", env2)
        check("successor accepted (201)", status == 201, f"{status} {body}")

        # stale predecessor conflict (claims 0 while head is 2)
        doc_stale = {"deviceId": device, "generation": 9, "previousGeneration": 0,
                     "configSha256": hashlib.sha256(b"x").hexdigest()}
        p_stale = json.dumps(doc_stale, separators=(",", ":")).encode()
        env_stale = {
            "attestationId": "smoke-att-stale",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(p_stale).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(p_stale, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", env_stale)
        check("stale predecessor conflict",
              status == 409 and body["error"]["code"] == "STALE_PREDECESSOR",
              f"{status} {body}")

        status, body = request(port, "GET", f"/api/devices/{device}/head")
        check("head is generation 2 with v2 digest",
              status == 200 and body.get("generation") == 2
              and body.get("configSha256") == hashlib.sha256(config2).hexdigest(),
              f"{status} {body}")

        # ===============================================================
        # Formation prerequisites (optional signed-payload field):
        # success / missing / version mismatch / concurrent race, all from
        # this clean data volume.
        # ===============================================================
        def envelope(att_id, dev, gen, prev, cfg_bytes, prereqs=None):
            doc = {
                "deviceId": dev,
                "generation": gen,
                "previousGeneration": prev,
                "configSha256": hashlib.sha256(cfg_bytes).hexdigest(),
            }
            if prereqs is not None:
                doc["prerequisites"] = prereqs
            raw = json.dumps(doc, separators=(",", ":")).encode()
            return {
                "attestationId": att_id,
                "keyId": key_id,
                "payloadBase64": base64.b64encode(raw).decode(),
                "signatureBase64": base64.b64encode(ed25519.sign(raw, seed)).decode(),
            }

        dep_device = "smoke-dep"
        dep_cfg = b"dep-config-v1"

        # --- prerequisite success --------------------------------------
        status, body = request(
            port, "POST", "/api/attestations",
            envelope("dep-att-1", dep_device, 1, 0, dep_cfg))
        check("dependency admitted (201)", status == 201, f"{status} {body}")

        prereq_v1 = [{"deviceId": dep_device, "generation": 1,
                      "configSha256": hashlib.sha256(dep_cfg).hexdigest()}]
        target_ok = "smoke-target-ok"
        env_target = envelope("target-att-ok", target_ok, 1, 0, b"payload-v1", prereq_v1)
        status, body = request(port, "POST", "/api/attestations", env_target)
        check("prerequisite satisfied -> target accepted (201)",
              status == 201, f"{status} {body}")

        # identical retry replays the original acceptance even though the
        # dependency will have advanced by the time it is replayed below
        # (checked after the race section).

        # --- prerequisite missing --------------------------------------
        env_missing = envelope(
            "target-att-missing", "smoke-target-missing", 1, 0, b"m",
            [{"deviceId": "smoke-ghost", "generation": 1,
              "configSha256": hashlib.sha256(b"g").hexdigest()}])
        status, body = request(port, "POST", "/api/attestations", env_missing)
        check("missing dependency -> PREREQUISITE_NOT_SATISFIED",
              status == 409 and body["error"]["code"] == "PREREQUISITE_NOT_SATISFIED",
              f"{status} {body}")
        status, body = request(port, "GET", "/api/devices/smoke-target-missing/head")
        check("missing-dependency target left no head",
              status == 404 and body["error"]["code"] == "DEVICE_NOT_FOUND",
              f"{status} {body}")

        # --- prerequisite version/digest mismatch ----------------------
        # concurrent race first (below) advances the dependency to gen 2;
        # both the stale-generation and wrong-digest pins must then fail.
        race_results = {}
        barrier = threading.Barrier(2)

        def post_result(name, env):
            barrier.wait()
            race_results[name] = request(port, "POST", "/api/attestations", env)

        dep_env2 = envelope("dep-att-2", dep_device, 2, 1, b"dep-config-v2")
        race_target = "smoke-target-race"
        race_env = envelope(
            "target-att-race", race_target, 1, 0, b"r", prereq_v1)
        threads = [
            threading.Thread(target=post_result, args=("target", race_env)),
            threading.Thread(target=post_result, args=("dep", dep_env2)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        dep_status, dep_body = race_results["dep"]
        tgt_status, tgt_body = race_results["target"]
        check("race: dependency successor accepted",
              dep_status == 201, f"{dep_status} {dep_body}")
        if tgt_status == 201:
            check("race: target committed before dependency advanced", True)
        else:
            check("race: target lost commit order (stable code, no head)",
                  tgt_status == 409 and tgt_body["error"]["code"] in
                  ("PREREQUISITE_NOT_SATISFIED", "CONCURRENT_UPDATE"),
                  f"{tgt_status} {tgt_body}")
            s, h = request(port, "GET", f"/api/devices/{race_target}/head")
            check("race loser left no target head", s == 404, f"{s} {h}")

        # dependency is now at generation 2 regardless of the race order
        s, h = request(port, "GET", f"/api/devices/{dep_device}/head")
        check("dependency head is generation 2", s == 200 and h.get("generation") == 2,
              f"{s} {h}")

        env_stale = envelope(
            "target-att-stale", "smoke-target-stale", 1, 0, b"s", prereq_v1)
        status, body = request(port, "POST", "/api/attestations", env_stale)
        check("stale prerequisite generation -> PREREQUISITE_NOT_SATISFIED",
              status == 409 and body["error"]["code"] == "PREREQUISITE_NOT_SATISFIED",
              f"{status} {body}")

        env_wrong_digest = envelope(
            "target-att-wrongdigest", "smoke-target-wrongdigest", 1, 0, b"w",
            [{"deviceId": dep_device, "generation": 2,
              "configSha256": hashlib.sha256(b"dep-config-v2-tampered").hexdigest()}])
        status, body = request(port, "POST", "/api/attestations", env_wrong_digest)
        check("prerequisite digest mismatch -> PREREQUISITE_NOT_SATISFIED",
              status == 409 and body["error"]["code"] == "PREREQUISITE_NOT_SATISFIED",
              f"{status} {body}")

        for failed_target in ("smoke-target-stale", "smoke-target-wrongdigest"):
            s, h = request(port, "GET", f"/api/devices/{failed_target}/head")
            check(f"failed target {failed_target} left no generation", s == 404, f"{s} {h}")

        # the target accepted against the gen-1 baseline replays as the
        # original verdict despite the dependency now being at gen 2
        status, body = request(port, "POST", "/api/attestations", env_target)
        check("accepted prerequisite target retries as duplicate",
              status == 200 and body.get("status") == "duplicate", f"{status} {body}")
    finally:
        server.shutdown()
        server.server_close()

    # ---- restart: brand new server process against the same database -------
    server2 = build_server("127.0.0.1", 0, db_path, keys_path)
    port2 = server2.server_address[1]
    t2 = threading.Thread(target=server2.serve_forever, daemon=True)
    t2.start()
    time.sleep(0.1)
    try:
        status, body = request(port2, "GET", f"/api/devices/{device}/head")
        check("head survives restart",
              status == 200 and body.get("generation") == 2
              and body.get("configSha256") == hashlib.sha256(config2).hexdigest()
              and body.get("attestationId") == "smoke-att-2",
              f"{status} {body}")

        # accepted formation baseline survives restart: the target admitted
        # against the dependency is still queryable at its unique generation,
        # while the dependency itself has advanced to 2
        status, body = request(port2, "GET", f"/api/devices/{target_ok}/head")
        check("accepted prerequisite target survives restart",
              status == 200 and body.get("generation") == 1
              and body.get("attestationId") == "target-att-ok",
              f"{status} {body}")
        status, body = request(port2, "GET", f"/api/devices/{dep_device}/head")
        check("dependency generation 2 survives restart",
              status == 200 and body.get("generation") == 2
              and body.get("configSha256") == hashlib.sha256(b"dep-config-v2").hexdigest(),
              f"{status} {body}")

        # failed prerequisites never left any generation, even after restart
        for failed_target in (
            "smoke-target-missing",
            "smoke-target-stale",
            "smoke-target-wrongdigest",
        ):
            status, body = request(port2, "GET", f"/api/devices/{failed_target}/head")
            check(f"failed target {failed_target} still absent after restart",
                  status == 404, f"{status} {body}")

        # unknown device
        status, body = request(port2, "GET", "/api/devices/unknown/head")
        check("unknown device 404", status == 404
              and body["error"]["code"] == "DEVICE_NOT_FOUND", f"{status} {body}")
    finally:
        server2.shutdown()
        server2.server_close()

    print(f"[smoke] {FAILURES} failure(s)")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
