"""Generate Ed25519 key declarations for deploy/keys.json.

Examples
--------
Fresh random key::

    python -m scripts.keytool generate --key-id sat-alpha-1 --device-id sat-alpha

Deterministic (test) key from a 32-byte hex seed::

    python -m scripts.keytool generate --key-id test --seed-hex 9d61... --pretty
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import ed25519


def generate(key_id: str, seed_hex: str | None, device_id: str | None) -> dict:
    if seed_hex is not None:
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError as exc:
            raise SystemExit(f"invalid --seed-hex: {exc}") from exc
        if len(seed) != 32:
            raise SystemExit("--seed-hex must decode to exactly 32 bytes")
    else:
        seed = os.urandom(32)
    public = ed25519.publickey(seed)
    entry = {
        "algorithm": "Ed25519",
        "publicKeyBase64": base64.b64encode(public).decode("ascii"),
    }
    if device_id:
        entry["deviceId"] = device_id
    print(f"# keyId={key_id}", file=sys.stderr)
    print(f"# seedHex (KEEP SECRET, do not deploy)={seed.hex()}", file=sys.stderr)
    return {"keys": {key_id: entry}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("--key-id", required=True)
    gen.add_argument("--device-id", default=None)
    gen.add_argument("--seed-hex", default=None)
    gen.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    doc = generate(args.key_id, args.seed_hex, args.device_id)
    print(json.dumps(doc, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
