"""Attestation admission: payload validation, signature verification, chain rules.

Chain rule
----------
For each device the accepted attestations form a strictly increasing chain of
generations:

* the first attestation ever accepted for a device MUST carry
  ``previousGeneration == 0``;
* every later attestation MUST carry ``previousGeneration`` equal to the
  currently accepted generation and a ``generation`` strictly greater than it.

Formation prerequisites
-----------------------
A signed payload MAY additionally carry ``prerequisites``: one to eight other
devices whose current heads must, at the exact instant of admission, each be at
a precisely stated generation with a precisely stated config digest. Every
prerequisite is read inside the same ``BEGIN IMMEDIATE`` write transaction that
inserts the target attestation, so the verdict is indivisible: a concurrent
update to a dependency device either commits before the target's verdict (the
target then fails with ``PREREQUISITE_NOT_SATISFIED``) or after it (the target
was admitted against a still-valid formation baseline). A failed prerequisite
never advances the target device.

Stable verdicts
---------------
The first verdict rendered for an ``attestationId`` is durably recorded,
whether it is an acceptance or a rejection. A later byte-identical request
replays that first verdict forever: an accepted proof replays as ``200``
without re-evaluating anything, and a rejected proof (e.g. one whose
prerequisite was missing) keeps returning the same HTTP status and stable
error code even after the dependency device, the target device, or any other
external state has changed, and after a service restart. A reused id with
different signed content is always ``ATTESTATION_ID_CONTENT_MISMATCH``. A
stale predecessor or a generation that does not advance likewise leaves state
untouched.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from . import ed25519
from .store import Store

# Stable error codes (part of the API contract).
ERR_MALFORMED = "MALFORMED_REQUEST"
ERR_INVALID_JSON = "INVALID_JSON_PAYLOAD"
ERR_INVALID_BASE64 = "INVALID_BASE64"
ERR_UNKNOWN_KEY = "UNKNOWN_KEY_ID"
ERR_KEY_DEVICE_MISMATCH = "KEY_NOT_BOUND_TO_DEVICE"
ERR_BAD_SIGNATURE = "INVALID_SIGNATURE"
ERR_UNSUPPORTED_ALG = "UNSUPPORTED_KEY"
ERR_GEN_ZERO = "GENERATION_ZERO"
ERR_GEN_NOT_GREATER = "GENERATION_NOT_GREATER"
ERR_BAD_PREDECESSOR_FIRST = "FIRST_PREDECESSOR_NOT_ZERO"
ERR_STALE_PREDECESSOR = "STALE_PREDECESSOR"
ERR_ID_CONTENT_MISMATCH = "ATTESTATION_ID_CONTENT_MISMATCH"
ERR_GENERATION_CONTENT_MISMATCH = "GENERATION_CONTENT_CONFLICT"
ERR_RACE_LOST = "CONCURRENT_UPDATE"
ERR_PREREQUISITE = "PREREQUISITE_NOT_SATISFIED"
ERR_INTERNAL = "INTERNAL_ERROR"

MAX_PREREQUISITES = 8


@dataclass(frozen=True)
class AdmissionDecision:
    accepted: bool
    status: int
    code: str
    message: str
    record: Optional[dict] = None
    duplicate: bool = False


def _b64decode(data: str) -> bytes:
    # urlsafe or standard alphabet both accepted; padding optional.
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        pass
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(str(exc)) from exc


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_payload(raw: bytes) -> dict:
    """Decode payload bytes as UTF-8 JSON and enforce required fields."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"payload is not valid UTF-8: {exc}") from exc
    if text and text[0] == "﻿":
        raise ValueError("payload must not contain a UTF-8 BOM")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"payload is not valid JSON: {exc.msg}") from exc
    if not isinstance(doc, dict):
        raise ValueError("payload JSON must be an object")

    required = ("deviceId", "generation", "previousGeneration", "configSha256")
    for field in required:
        if field not in doc:
            raise ValueError(f"payload missing required field: {field}")

    if not isinstance(doc["deviceId"], str) or not doc["deviceId"]:
        raise ValueError("payload field deviceId must be a non-empty string")
    # bool is a subclass of int: reject it explicitly for both generations.
    for field in ("generation", "previousGeneration"):
        value = doc[field]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"payload field {field} must be an integer")
    if doc["generation"] < 0 or doc["previousGeneration"] < 0:
        raise ValueError("generation values must be non-negative")
    if not isinstance(doc["configSha256"], str) or not doc["configSha256"]:
        raise ValueError("payload field configSha256 must be a non-empty string")
    if not _HEX64.fullmatch(doc["configSha256"]):
        raise ValueError("payload field configSha256 must be 64 lowercase hex characters")

    if "prerequisites" in doc:
        doc["prerequisites"] = _validate_prerequisites(doc["prerequisites"], doc["deviceId"])
    return doc


def _validate_prerequisites(value: object, target_device: str) -> list[dict]:
    """Validate the optional ``prerequisites`` array from a signed payload."""
    if not isinstance(value, list):
        raise ValueError("payload field prerequisites must be an array")
    if not 1 <= len(value) <= MAX_PREREQUISITES:
        raise ValueError(
            f"payload must declare between 1 and {MAX_PREREQUISITES} prerequisites "
            f"(got {len(value)})"
        )
    seen: set[str] = set()
    normalised: list[dict] = []
    for index, entry in enumerate(value):
        where = f"prerequisites[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"payload field {where} must be an object")
        for field in ("deviceId", "generation", "configSha256"):
            if field not in entry:
                raise ValueError(f"payload field {where} missing required field: {field}")
        device_id = entry["deviceId"]
        if not isinstance(device_id, str) or not device_id:
            raise ValueError(f"payload field {where}.deviceId must be a non-empty string")
        if device_id == target_device:
            raise ValueError(f"payload field {where}.deviceId must not be the target device")
        if device_id in seen:
            raise ValueError(f"payload field prerequisites contains duplicate deviceId {device_id!r}")
        seen.add(device_id)
        generation = entry["generation"]
        # bool is a subclass of int: reject it explicitly.
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise ValueError(f"payload field {where}.generation must be an integer")
        if generation <= 0:
            raise ValueError(f"payload field {where}.generation must be greater than 0")
        digest_value = entry["configSha256"]
        if not isinstance(digest_value, str) or not _HEX64.fullmatch(digest_value):
            raise ValueError(
                f"payload field {where}.configSha256 must be 64 lowercase hex characters"
            )
        normalised.append(
            {"deviceId": device_id, "generation": generation, "configSha256": digest_value}
        )
    return normalised


_HEX64 = re.compile(r"[0-9a-f]{64}")


class Admitter:
    def __init__(self, store: Store, keys: dict[str, bytes], bindings: dict[str, Optional[str]] | None = None):
        self.store = store
        # keyId -> raw 32-byte Ed25519 public key
        self.keys = keys
        # keyId -> bound deviceId (None or missing means unbound)
        self.bindings = bindings or {}

    def head(self, device_id: str) -> Optional[dict]:
        rec = self.store.head(device_id)
        return rec.to_dict() if rec is not None else None

    def admit(
        self,
        attestation_id: object,
        key_id: object,
        payload_b64: object,
        signature_b64: object,
    ) -> AdmissionDecision:
        # ---- request shape -------------------------------------------------
        if not all(isinstance(v, str) for v in (attestation_id, key_id, payload_b64, signature_b64)):
            return AdmissionDecision(
                False, 400, ERR_MALFORMED,
                "attestationId, keyId, payloadBase64 and signatureBase64 "
                "must all be strings",
            )
        if not attestation_id:
            return AdmissionDecision(False, 400, ERR_MALFORMED, "attestationId must be non-empty")

        try:
            payload = _b64decode(payload_b64)
        except ValueError:
            return AdmissionDecision(False, 400, ERR_INVALID_BASE64, "payloadBase64 is not valid base64")
        try:
            signature = _b64decode(signature_b64)
        except ValueError:
            return AdmissionDecision(False, 400, ERR_INVALID_BASE64, "signatureBase64 is not valid base64")

        # ---- signature / key ----------------------------------------------
        public_key = self.keys.get(key_id)
        if public_key is None:
            return AdmissionDecision(
                False, 401, ERR_UNKNOWN_KEY,
                f"no public key is registered for keyId {key_id!r}",
            )
        try:
            ed25519.verify(signature, payload, public_key)
        except ValueError:
            return AdmissionDecision(False, 401, ERR_BAD_SIGNATURE, "Ed25519 signature verification failed")

        # ---- payload -------------------------------------------------------
        try:
            doc = validate_payload(payload)
        except ValueError as exc:
            return AdmissionDecision(False, 400, ERR_INVALID_JSON, str(exc))

        bound_device = self.bindings.get(key_id)
        if bound_device is not None and bound_device != doc["deviceId"]:
            return AdmissionDecision(
                False, 403, ERR_KEY_DEVICE_MISMATCH,
                f"keyId {key_id!r} is not bound to device {doc['deviceId']!r}",
            )

        # The signature is valid, so attestation id reuse can be checked
        # against the exact signed bytes rather than trusting the client.
        payload_sha = hashlib.sha256(payload).hexdigest()
        return self._persist(
            attestation_id=attestation_id,
            payload_sha=payload_sha,
            device_id=doc["deviceId"],
            generation=doc["generation"],
            previous_generation=doc["previousGeneration"],
            config_sha256=doc["configSha256"],
            prerequisites=doc.get("prerequisites") or [],
        )

    def _record_rejection(
        self,
        conn,
        *,
        attestation_id: str,
        payload_sha: str,
        device_id: str,
        generation: int,
        previous_generation: int,
        config_sha256: str,
        status: int,
        code: str,
        message: str,
    ) -> AdmissionDecision:
        """Persist a freshly rendered rejection so identical retries replay it."""
        self.store.insert_verdict(
            conn,
            attestation_id=attestation_id,
            payload_sha256=payload_sha,
            accepted=False,
            status=status,
            code=code,
            message=message,
            device_id=device_id,
            generation=generation,
            previous_generation=previous_generation,
            config_sha256=config_sha256,
            accepted_at=None,
        )
        return AdmissionDecision(False, status, code, message)

    def _persist(
        self,
        *,
        attestation_id: str,
        payload_sha: str,
        device_id: str,
        generation: int,
        previous_generation: int,
        config_sha256: str,
        prerequisites: list[dict],
    ) -> AdmissionDecision:
        from .store import ConcurrentUpdateError

        try:
            with self.store.transaction() as conn:
                verdict = self.store.find_verdict(conn, attestation_id)

                # 1) This id already has a recorded verdict. Byte-identical
                #    requests replay that verdict forever without
                #    re-evaluating signatures' downstream state (chain, heads,
                #    prerequisites); a different signed payload conflicts.
                if verdict is not None:
                    if verdict.payload_sha256 != payload_sha:
                        return AdmissionDecision(
                            False, 409, ERR_ID_CONTENT_MISMATCH,
                            "attestationId was already used with different content",
                        )
                    if verdict.accepted:
                        return AdmissionDecision(
                            True, 200, "",
                            "attestation already accepted",
                            record=verdict.replay_record(), duplicate=True,
                        )
                    return AdmissionDecision(
                        False, verdict.status, verdict.code, verdict.message
                    )

                # Legacy databases may hold an accepted row written before the
                # verdict registry existed: treat it as a recorded acceptance
                # (backfilling the registry) or as an id/content conflict.
                legacy = self.store.find_by_id(conn, attestation_id)
                if legacy is not None:
                    if legacy.payload_sha256 != payload_sha:
                        return AdmissionDecision(
                            False, 409, ERR_ID_CONTENT_MISMATCH,
                            "attestationId was already used with different content",
                        )
                    self.store.insert_verdict(
                        conn,
                        attestation_id=attestation_id,
                        payload_sha256=payload_sha,
                        accepted=True,
                        status=201,
                        code="",
                        message="attestation accepted",
                        device_id=legacy.device_id,
                        generation=legacy.generation,
                        previous_generation=legacy.previous_generation,
                        config_sha256=legacy.config_sha256,
                        accepted_at=legacy.accepted_at,
                    )
                    return AdmissionDecision(
                        True, 200, "",
                        "attestation already accepted",
                        record=legacy.to_dict(), duplicate=True,
                    )

                # 2) Same generation number already accepted -> content must match.
                prior = self.store.find(conn, device_id, generation)
                if prior is not None:
                    return self._record_rejection(
                        conn,
                        attestation_id=attestation_id, payload_sha=payload_sha,
                        device_id=device_id, generation=generation,
                        previous_generation=previous_generation,
                        config_sha256=config_sha256,
                        status=409, code=ERR_GENERATION_CONTENT_MISMATCH,
                        message=(
                            f"generation {generation} for device {device_id!r} is "
                            "already accepted with different content"
                        ),
                    )

                # 3) Chain / predecessor rules evaluated against the locked head.
                head = self.store.head_unlocked(conn, device_id)
                if head is None:
                    if previous_generation != 0:
                        return self._record_rejection(
                            conn,
                            attestation_id=attestation_id, payload_sha=payload_sha,
                            device_id=device_id, generation=generation,
                            previous_generation=previous_generation,
                            config_sha256=config_sha256,
                            status=409, code=ERR_BAD_PREDECESSOR_FIRST,
                            message=(
                                f"first attestation for device {device_id!r} must "
                                f"have previousGeneration 0 (got {previous_generation})"
                            ),
                        )
                    if generation == 0:
                        return self._record_rejection(
                            conn,
                            attestation_id=attestation_id, payload_sha=payload_sha,
                            device_id=device_id, generation=generation,
                            previous_generation=previous_generation,
                            config_sha256=config_sha256,
                            status=409, code=ERR_GEN_ZERO,
                            message="generation must be greater than 0",
                        )
                else:
                    if previous_generation != head.generation:
                        return self._record_rejection(
                            conn,
                            attestation_id=attestation_id, payload_sha=payload_sha,
                            device_id=device_id, generation=generation,
                            previous_generation=previous_generation,
                            config_sha256=config_sha256,
                            status=409, code=ERR_STALE_PREDECESSOR,
                            message=(
                                f"previousGeneration {previous_generation} does not "
                                f"match current head generation {head.generation}"
                            ),
                        )
                    if generation <= head.generation:
                        return self._record_rejection(
                            conn,
                            attestation_id=attestation_id, payload_sha=payload_sha,
                            device_id=device_id, generation=generation,
                            previous_generation=previous_generation,
                            config_sha256=config_sha256,
                            status=409, code=ERR_GEN_NOT_GREATER,
                            message=(
                                f"generation {generation} must be greater than "
                                f"current head {head.generation}"
                            ),
                        )

                # 4) Formation prerequisites, evaluated against the locked
                #    heads of the dependency devices *inside this same write
                #    transaction*. Each dependency must exist and its current
                #    head must match both the stated generation and the stated
                #    config digest exactly. Failure aborts the chain insert
                #    but records the rejection verdict, so the target row is
                #    never written, no state advances, and an identical retry
                #    replays this same failure even if the baseline later
                #    becomes satisfiable.
                for prereq in prerequisites:
                    dep_head = self.store.head_unlocked(conn, prereq["deviceId"])
                    expected_gen = prereq["generation"]
                    expected_sha = prereq["configSha256"]
                    if (
                        dep_head is None
                        or dep_head.generation != expected_gen
                        or dep_head.config_sha256 != expected_sha
                    ):
                        if dep_head is None:
                            detail = "device has no accepted attestation"
                        elif dep_head.generation != expected_gen:
                            detail = (
                                f"head generation is {dep_head.generation}, "
                                f"expected {expected_gen}"
                            )
                        else:
                            detail = "head config digest differs from the prerequisite"
                        return self._record_rejection(
                            conn,
                            attestation_id=attestation_id, payload_sha=payload_sha,
                            device_id=device_id, generation=generation,
                            previous_generation=previous_generation,
                            config_sha256=config_sha256,
                            status=409, code=ERR_PREREQUISITE,
                            message=(
                                f"prerequisite on device {prereq['deviceId']!r} is not "
                                f"satisfied: {detail}"
                            ),
                        )

                accepted_at = _now()
                self.store.insert(
                    conn,
                    device_id=device_id,
                    generation=generation,
                    previous_generation=previous_generation,
                    config_sha256=config_sha256,
                    attestation_id=attestation_id,
                    payload_sha256=payload_sha,
                    accepted_at=accepted_at,
                )
                self.store.insert_verdict(
                    conn,
                    attestation_id=attestation_id,
                    payload_sha256=payload_sha,
                    accepted=True,
                    status=201,
                    code="",
                    message="attestation accepted",
                    device_id=device_id,
                    generation=generation,
                    previous_generation=previous_generation,
                    config_sha256=config_sha256,
                    accepted_at=accepted_at,
                )
                rec = self.store.find(conn, device_id, generation)
                return AdmissionDecision(
                    True, 201, "", "attestation accepted", record=rec.to_dict()
                )
        except ConcurrentUpdateError:
            return AdmissionDecision(
                False, 409, ERR_RACE_LOST,
                "lost the concurrency race; reload the current head and retry",
            )
