"""Deployment-declared device public keys.

Keys are declared with the deployment (never provisioned through the API) in a
JSON file::

    {
      "keys": {
        "sat-alpha-1": {
          "algorithm": "Ed25519",
          "publicKeyBase64": "BASE64_32_BYTE_KEY",
          "deviceId": "sat-alpha"
        }
      }
    }

``deviceId`` is optional; when present a key is bound to that device.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Optional


class KeyConfigError(Exception):
    pass


def load_keys(path: str) -> dict[str, bytes]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError as exc:
        raise KeyConfigError(f"key declaration file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise KeyConfigError(f"key declaration {path} is not valid JSON: {exc.msg}") from exc

    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), dict):
        raise KeyConfigError("key declaration must be an object with a 'keys' object")

    keys: dict[str, bytes] = {}
    for key_id, entry in doc["keys"].items():
        if not isinstance(entry, dict):
            raise KeyConfigError(f"key {key_id!r}: entry must be an object")
        alg = entry.get("algorithm")
        if alg != "Ed25519":
            raise KeyConfigError(
                f"key {key_id!r}: unsupported algorithm {alg!r} (expected 'Ed25519')"
            )
        b64 = entry.get("publicKeyBase64")
        if not isinstance(b64, str):
            raise KeyConfigError(f"key {key_id!r}: publicKeyBase64 must be a string")
        try:
            raw = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise KeyConfigError(f"key {key_id!r}: invalid base64 public key") from exc
        if len(raw) != 32:
            raise KeyConfigError(
                f"key {key_id!r}: Ed25519 public key must be 32 bytes (got {len(raw)})"
            )
        keys[key_id] = raw
    return keys


def load_key_bindings(path: str) -> dict[str, Optional[str]]:
    """Return keyId -> deviceId binding (None when the key is unbound)."""
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    bindings: dict[str, Optional[str]] = {}
    for key_id, entry in doc.get("keys", {}).items():
        device = entry.get("deviceId") if isinstance(entry, dict) else None
        bindings[key_id] = device if isinstance(device, str) and device else None
    return bindings
