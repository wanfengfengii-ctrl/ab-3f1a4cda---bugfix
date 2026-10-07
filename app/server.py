"""HTTP API for the attestation guard (stdlib only).

Endpoints
---------
GET  /healthz                         liveness/readiness probe
POST /api/attestations                submit a signed attestation
GET  /api/devices/{deviceId}/head     current accepted generation + digest

All errors return JSON ``{"error": {"code", "message"}}`` with a stable
machine-readable ``code``.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from .admit import (
    Admitter,
    ERR_INTERNAL,
    ERR_MALFORMED,
)
from .config import KeyConfigError, load_key_bindings, load_keys
from .store import Store

MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB is ample for one attestation


def create_app(store: Store, keys_path: str) -> Admitter:
    keys = load_keys(keys_path)
    bindings = load_key_bindings(keys_path)
    return Admitter(keys=keys, bindings=bindings, store=store)


class Handler(BaseHTTPRequestHandler):
    server_version = "AttestationGuard/1.0"

    def log_message(self, fmt: str, *args) -> None:
        if os.environ.get("QUIET_LOGS") != "1":
            super().log_message(fmt, *args)

    @property
    def admitter(self) -> Admitter:
        return self.server.admitter  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ utils
    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status: int, code: str, message: str) -> None:
        self._send_json(status, {"error": {"code": code, "message": message}})

    def _read_json_body(self) -> dict | None:
        length = self.headers.get("Content-Length")
        if length is None:
            self._error(400, ERR_MALFORMED, "missing Content-Length header")
            return None
        try:
            n = int(length)
        except ValueError:
            self._error(400, ERR_MALFORMED, "invalid Content-Length header")
            return None
        if n < 0 or n > MAX_BODY_BYTES:
            self._error(413, "PAYLOAD_TOO_LARGE", "request body exceeds 1 MiB")
            return None
        raw = self.rfile.read(n)
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(400, ERR_MALFORMED, "request body must be UTF-8 JSON")
            return None
        if not isinstance(doc, dict):
            self._error(400, ERR_MALFORMED, "request body must be a JSON object")
            return None
        return doc

    # ------------------------------------------------------------------ GET
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        prefix = "/api/devices/"
        suffix = "/head"
        if path.startswith(prefix) and path.endswith(suffix):
            device_id = unquote(path[len(prefix) : -len(suffix)])
            if not device_id or "/" in device_id:
                self._error(404, "NOT_FOUND", "unknown path")
                return
            head = self.admitter.head(device_id)
            if head is None:
                self._error(404, "DEVICE_NOT_FOUND", f"no accepted attestation for device {device_id!r}")
                return
            self._send_json(
                200,
                {
                    "deviceId": head["deviceId"],
                    "generation": head["generation"],
                    "previousGeneration": head["previousGeneration"],
                    "configSha256": head["configSha256"],
                    "attestationId": head["attestationId"],
                    "acceptedAt": head["acceptedAt"],
                },
            )
            return
        self._error(404, "NOT_FOUND", "unknown path")

    # ------------------------------------------------------------------ POST
    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path != "/api/attestations":
            self._error(404, "NOT_FOUND", "unknown path")
            return
        body = self._read_json_body()
        if body is None:
            return
        decision = self.admitter.admit(
            attestation_id=body.get("attestationId"),
            key_id=body.get("keyId"),
            payload_b64=body.get("payloadBase64"),
            signature_b64=body.get("signatureBase64"),
        )
        if decision.accepted:
            rec = decision.record or {}
            self._send_json(
                decision.status,
                {
                    "status": "duplicate" if decision.duplicate else "accepted",
                    "deviceId": rec.get("deviceId"),
                    "generation": rec.get("generation"),
                    "previousGeneration": rec.get("previousGeneration"),
                    "configSha256": rec.get("configSha256"),
                    "attestationId": rec.get("attestationId"),
                    "acceptedAt": rec.get("acceptedAt"),
                },
            )
        else:
            self._error(decision.status, decision.code, decision.message)


def build_server(host: str, port: int, db_path: str, keys_path: str) -> ThreadingHTTPServer:
    store = Store(db_path)
    admitter = create_app(store, keys_path)
    server = ThreadingHTTPServer((host, port), Handler)
    server.admitter = admitter
    server.daemon_threads = True
    return server


def main() -> int:
    host = os.environ.get("APP_HOST", "0.0.0.0")
    port = int(os.environ.get("APP_PORT", "8080"))
    db_path = os.environ.get("DB_PATH", "/data/attestations.db")
    keys_path = os.environ.get("KEYS_PATH", "/app/deploy/keys.json")
    try:
        server = build_server(host, port, db_path, keys_path)
    except KeyConfigError as exc:
        print(f"fatal: {exc}", flush=True)
        return 2
    actual_port = server.server_address[1]
    print(f"attestation guard listening on {host}:{actual_port} (db={db_path})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
