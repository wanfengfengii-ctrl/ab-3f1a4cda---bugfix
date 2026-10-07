"""Admission-rule, persistence, retry and concurrency tests."""

import base64
import hashlib
import json
import os
import tempfile
import threading
import unittest

from app import ed25519
from app.admit import Admitter
from app.config import load_key_bindings, load_keys
from app.store import Store

SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PUB = ed25519.publickey(SEED)
KEY_ID = "vendor-1"

SEED2 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4" "4449c5697b326919703bac031cae7f60")
PUB2 = ed25519.publickey(SEED2)
KEY_ID2 = "vendor-2"


def digest(config: bytes) -> str:
    return hashlib.sha256(config).hexdigest()


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "att.db")
        self.store = Store(self.db)
        self.admitter = Admitter(
            self.store,
            {KEY_ID: PUB, KEY_ID2: PUB2},
            {KEY_ID: None, KEY_ID2: None},
        )

    def tearDown(self):
        self.tmp.cleanup()

    def submit(self, att_id, device, gen, prev, config, *, key_id=KEY_ID, seed=SEED, extra=None):
        doc = {
            "deviceId": device,
            "generation": gen,
            "previousGeneration": prev,
            "configSha256": digest(config),
        }
        if extra:
            doc.update(extra)
        payload = json.dumps(doc, separators=(",", ":")).encode("utf-8")
        sig = ed25519.sign(payload, seed)
        return self.admitter.admit(
            attestation_id=att_id,
            key_id=key_id,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        ), payload, sig

    def prereq_submit(self, att_id, device, gen, prev, config, prerequisites, **kw):
        return self.submit(
            att_id, device, gen, prev, config,
            extra={"prerequisites": prerequisites}, **kw
        )

    def test_first_must_have_zero_predecessor(self):
        d, _, _ = self.submit("a1", "dev", 1, 1, b"cfg-1")
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "FIRST_PREDECESSOR_NOT_ZERO")
        self.assertIsNone(self.admitter.head("dev"))

    def test_generation_zero_rejected(self):
        d, _, _ = self.submit("a0", "dev", 0, 0, b"cfg-0")
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "GENERATION_ZERO")

    def test_happy_path_chain(self):
        d1, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertTrue(d1.accepted)
        self.assertEqual(d1.status, 201)
        self.assertEqual(d1.record["generation"], 1)

        d2, _, _ = self.submit("a2", "dev", 2, 1, b"cfg-2")
        self.assertTrue(d2.accepted)
        self.assertEqual(d2.status, 201)

        head = self.admitter.head("dev")
        self.assertEqual(head["generation"], 2)
        self.assertEqual(head["configSha256"], digest(b"cfg-2"))

    def test_exact_retry_returns_original(self):
        d1, payload, sig = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertEqual(d1.status, 201)
        before = self.store.accepted_generations("dev")
        # identical request bytes -> replay, no new row
        r = self.admitter.admit(
            attestation_id="a1",
            key_id=KEY_ID,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        )
        self.assertTrue(r.accepted)
        self.assertEqual(r.status, 200)
        self.assertTrue(r.duplicate)
        self.assertEqual(self.store.accepted_generations("dev"), before)

    def test_same_id_different_content_conflicts(self):
        d1, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertTrue(d1.accepted)
        d2, _, _ = self.submit("a1", "dev", 2, 1, b"cfg-2")
        self.assertFalse(d2.accepted)
        self.assertEqual(d2.code, "ATTESTATION_ID_CONTENT_MISMATCH")
        # state unchanged
        self.assertEqual(self.admitter.head("dev")["generation"], 1)

    def test_same_generation_different_content_conflicts(self):
        d1, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertTrue(d1.accepted)
        # new id but same generation, different config
        d2, _, _ = self.submit("a2", "dev", 1, 0, b"cfg-OTHER")
        self.assertFalse(d2.accepted)
        self.assertEqual(d2.code, "GENERATION_CONTENT_CONFLICT")
        self.assertEqual(self.admitter.head("dev")["configSha256"], digest(b"cfg-1"))

    def test_stale_predecessor_is_conflict(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        # replay an old attestation against head 2
        d3, _, _ = self.submit("a3", "dev", 3, 1, b"cfg-3")
        self.assertFalse(d3.accepted)
        self.assertEqual(d3.code, "STALE_PREDECESSOR")
        self.assertEqual(self.admitter.head("dev")["generation"], 2)

    def test_generation_must_increase(self):
        self.submit("a1", "dev", 5, 0, b"cfg-1")
        d, _, _ = self.submit("a2", "dev", 5, 5, b"cfg-2")
        self.assertEqual(d.code, "GENERATION_CONTENT_CONFLICT")  # gen exists
        d2, _, _ = self.submit("a3", "dev", 4, 5, b"cfg-x")
        self.assertEqual(d2.code, "GENERATION_NOT_GREATER")
        self.assertEqual(self.admitter.head("dev")["generation"], 5)

    def test_non_increasing_gaps_allowed(self):
        # generations need not be consecutive
        d, _, _ = self.submit("a1", "dev", 10, 0, b"cfg-1")
        self.assertTrue(d.accepted)
        d2, _, _ = self.submit("a2", "dev", 25, 10, b"cfg-2")
        self.assertTrue(d2.accepted)

    def test_unknown_key(self):
        d, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1", key_id="nope", seed=SEED)
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "UNKNOWN_KEY_ID")
        self.assertEqual(d.status, 401)
        self.assertIsNone(self.admitter.head("dev"))

    def test_bad_signature(self):
        doc = {"deviceId": "dev", "generation": 1, "previousGeneration": 0,
               "configSha256": digest(b"cfg-1")}
        payload = json.dumps(doc).encode()
        d = self.admitter.admit("a1", KEY_ID,
                                base64.b64encode(payload).decode(),
                                base64.b64encode(b"\x00" * 64).decode())
        self.assertEqual(d.code, "INVALID_SIGNATURE")
        # flip one payload byte but reuse signature -> invalid signature
        tampered = payload.replace(b"cfg-1", b"cfg-2", 1) if b"cfg-1" in payload else payload
        sig = ed25519.sign(payload, SEED)
        # build a distinct payload signed for a different message
        other = json.dumps({**doc, "generation": 2}).encode()
        d2 = self.admitter.admit("a1", KEY_ID,
                                 base64.b64encode(other).decode(),
                                 base64.b64encode(sig).decode())
        self.assertEqual(d2.code, "INVALID_SIGNATURE")

    def test_wrong_device_key_binding(self):
        adm = Admitter(self.store, {KEY_ID: PUB}, {KEY_ID: "bound-dev"})
        doc = {"deviceId": "other-dev", "generation": 1, "previousGeneration": 0,
               "configSha256": digest(b"c")}
        payload = json.dumps(doc).encode()
        sig = ed25519.sign(payload, SEED)
        d = adm.admit("a1", KEY_ID, base64.b64encode(payload).decode(),
                      base64.b64encode(sig).decode())
        self.assertEqual(d.code, "KEY_NOT_BOUND_TO_DEVICE")

    def test_malformed_payload_encoding(self):
        sig = ed25519.sign(b"\xff\xfe not utf8", SEED)
        d = self.admitter.admit(
            "a1", KEY_ID,
            base64.b64encode(b"\xff\xfe not utf8").decode(),
            base64.b64encode(sig).decode(),
        )
        self.assertEqual(d.code, "INVALID_JSON_PAYLOAD")

        good = {"deviceId": "dev", "generation": 1, "previousGeneration": 0,
                "configSha256": digest(b"c")}
        payload = json.dumps(good).encode()
        sig2 = ed25519.sign(payload, SEED)
        # uppercase hash must be rejected
        bad = json.dumps({**good, "configSha256": digest(b"c").upper()}).encode()
        d3 = self.admitter.admit("a1", KEY_ID, base64.b64encode(bad).decode(),
                                 base64.b64encode(ed25519.sign(bad, SEED)).decode())
        self.assertEqual(d3.code, "INVALID_JSON_PAYLOAD")

    def test_devices_are_independent_chains(self):
        self.assertTrue(self.submit("a1", "dev-A", 1, 0, b"c1")[0].accepted)
        self.assertTrue(self.submit("b1", "dev-B", 1, 0, b"d1")[0].accepted)
        self.assertTrue(self.submit("a2", "dev-A", 2, 1, b"c2")[0].accepted)
        self.assertEqual(self.admitter.head("dev-A")["generation"], 2)
        self.assertEqual(self.admitter.head("dev-B")["generation"], 1)

    def test_persistence_survives_reopen(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        store2 = Store(self.db)
        adm2 = Admitter(store2, {KEY_ID: PUB}, {KEY_ID: None})
        head = adm2.head("dev")
        self.assertEqual(head["generation"], 2)
        self.assertEqual(head["configSha256"], digest(b"cfg-2"))
        # after "restart" a stale predecessor still fails
        d, _, _ = self.submit("a3", "dev", 3, 1, b"cfg-3")
        self.assertEqual(d.code, "STALE_PREDECESSOR")
        # and the true successor succeeds
        d2, _, _ = self.submit("a4", "dev", 3, 2, b"cfg-3")
        self.assertTrue(d2.accepted)

    def test_concurrent_competing_successors_only_one_wins(self):
        self.submit("root", "dev", 1, 0, b"cfg-1")
        results = []

        def worker(att_id, config):
            d, _, _ = self.submit(att_id, "dev", 2, 1, config)
            results.append((att_id, d.accepted, d.code))

        # three different-config competitors for the same successor generation
        threads = [threading.Thread(target=worker, args=(f"g2-{i}", f"cfg-{i}".encode()))
                   for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wins = [r for r in results if r[1]]
        self.assertEqual(len(wins), 1, results)
        self.assertEqual(len(self.store.accepted_generations("dev")), 2)
        self.assertEqual(self.admitter.head("dev")["generation"], 2)

    def test_concurrent_identical_retry_single_acceptance(self):
        results = []

        def worker():
            d, _, _ = self.submit("same-id", "dev", 1, 0, b"cfg-1")
            results.append((d.accepted, d.status, d.code, d.duplicate))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        accepted_201 = [r for r in results if r[1] and not r[3]]
        self.assertEqual(len(accepted_201), 1, results)
        self.assertTrue(all(r[1] for r in results), results)
        self.assertEqual(len(self.store.accepted_generations("dev")), 1)


class PrerequisiteCase(Case):
    """Formation prerequisite: dependency heads gate target admission."""

    def dep(self, att_id="dep-1", device="dep", config=b"dep-cfg-1"):
        d, _, _ = self.submit(att_id, device, 1, 0, config)
        self.assertTrue(d.accepted, d)
        return config

    def target(self, att_id, gen, prev, config=b"tgt-cfg", prereqs=None, device="tgt"):
        return self.prereq_submit(att_id, device, gen, prev, config, prereqs)[0]

    # ------------------------------------------------------------- happy path
    def test_prerequisite_satisfied_accepted(self):
        cfg = self.dep()
        d = self.target("tgt-1", 1, 0, prereqs=[
            {"deviceId": "dep", "generation": 1, "configSha256": digest(cfg)}])
        self.assertTrue(d.accepted, d)
        self.assertEqual(d.status, 201)
        self.assertEqual(self.admitter.head("tgt")["generation"], 1)

    def test_multiple_prerequisites_must_all_match(self):
        c1 = self.dep("d1", "dep-1", b"dep-one")
        c2 = self.dep("d2", "dep-2", b"dep-two")
        # one dependency missing -> rejected
        d = self.target("t-1", 1, 0, prereqs=[
            {"deviceId": "dep-1", "generation": 1, "configSha256": digest(c1)},
            {"deviceId": "ghost", "generation": 1, "configSha256": digest(b"?")}])
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "PREREQUISITE_NOT_SATISFIED")
        self.assertIsNone(self.admitter.head("tgt"))
        # both present and matching -> accepted (a fresh attestation id; the
        # rejected id t-1 retains its verdict and must replay as rejected)
        d = self.target("t-2", 1, 0, prereqs=[
            {"deviceId": "dep-1", "generation": 1, "configSha256": digest(c1)},
            {"deviceId": "dep-2", "generation": 1, "configSha256": digest(c2)}])
        self.assertTrue(d.accepted, d)

    # --------------------------------------------------------------- failures
    def test_prerequisite_missing_device(self):
        self.dep()
        d = self.target("t-1", 1, 0, prereqs=[
            {"deviceId": "ghost", "generation": 1, "configSha256": digest(b"x")}])
        self.assertFalse(d.accepted)
        self.assertEqual(d.status, 409)
        self.assertEqual(d.code, "PREREQUISITE_NOT_SATISFIED")
        # no target generation is ever written on failure
        self.assertIsNone(self.admitter.head("tgt"))
        self.assertEqual(self.store.accepted_generations("tgt"), [])

    def test_prerequisite_generation_mismatch(self):
        self.dep(config=b"dep-cfg-1")
        self.submit("dep-2", "dep", 2, 1, b"dep-cfg-2")
        # expects the old generation while head is already 2
        d = self.target("t-1", 1, 0, prereqs=[
            {"deviceId": "dep", "generation": 1, "configSha256": digest(b"dep-cfg-1")}])
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "PREREQUISITE_NOT_SATISFIED")
        self.assertIsNone(self.admitter.head("tgt"))
        # expects a generation the dependency has not reached yet
        d = self.target("t-2", 1, 0, prereqs=[
            {"deviceId": "dep", "generation": 3, "configSha256": digest(b"dep-cfg-2")}])
        self.assertEqual(d.code, "PREREQUISITE_NOT_SATISFIED")
        self.assertIsNone(self.admitter.head("tgt"))

    def test_prerequisite_digest_mismatch(self):
        self.dep(config=b"dep-cfg-1")
        d = self.target("t-1", 1, 0, prereqs=[
            {"deviceId": "dep", "generation": 1, "configSha256": digest(b"different-bytes")}])
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "PREREQUISITE_NOT_SATISFIED")
        self.assertIsNone(self.admitter.head("tgt"))
        # dependency untouched as well
        self.assertEqual(self.admitter.head("dep")["configSha256"], digest(b"dep-cfg-1"))

    def test_rejected_prerequisite_same_id_replays_even_after_fixed(self):
        # dependency absent: the rejected verdict stores no target row ...
        prereq = [{"deviceId": "dep", "generation": 1,
                   "configSha256": digest(b"dep-cfg-1")}]
        d = self.target("t-1", 1, 0, prereqs=prereq)
        self.assertEqual(d.status, 409)
        self.assertEqual(d.code, "PREREQUISITE_NOT_SATISFIED")
        self.assertIsNone(self.admitter.head("tgt"))
        # ... but the verdict is durable: once the formation baseline exists,
        # the byte-identical request replays the original rejection instead of
        # being re-adjudicated.
        self.dep()
        d = self.target("t-1", 1, 0, prereqs=prereq)
        self.assertFalse(d.accepted)
        self.assertEqual(d.status, 409)
        self.assertEqual(d.code, "PREREQUISITE_NOT_SATISFIED")
        # the rejected proof never created or advanced the target head
        self.assertIsNone(self.admitter.head("tgt"))
        self.assertEqual(self.store.accepted_generations("tgt"), [])
        # a *different* proof under a fresh attestation id is admitted normally
        d = self.target("t-2", 1, 0, prereqs=prereq)
        self.assertTrue(d.accepted, d)
        self.assertEqual(d.status, 201)
        self.assertEqual(self.admitter.head("tgt")["generation"], 1)

    def test_rejected_prerequisite_same_id_still_replays_after_restart(self):
        prereq = [{"deviceId": "dep", "generation": 1,
                   "configSha256": digest(b"dep-cfg-1")}]
        d = self.target("t-1", 1, 0, prereqs=prereq)
        self.assertEqual(d.code, "PREREQUISITE_NOT_SATISFIED")
        self.dep()
        # brand new Store/Admitter over the same database, i.e. a restart
        store2 = Store(self.db)
        adm2 = Admitter(store2, {KEY_ID: PUB, KEY_ID2: PUB2},
                        {KEY_ID: None, KEY_ID2: None})
        payload = json.dumps({
            "deviceId": "tgt",
            "generation": 1,
            "previousGeneration": 0,
            "configSha256": digest(b"tgt-cfg"),
            "prerequisites": prereq,
        }, separators=(",", ":")).encode("utf-8")
        sig = ed25519.sign(payload, SEED)
        r = adm2.admit(
            attestation_id="t-1",
            key_id=KEY_ID,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        )
        self.assertFalse(r.accepted)
        self.assertEqual(r.status, 409)
        self.assertEqual(r.code, "PREREQUISITE_NOT_SATISFIED")
        self.assertIsNone(adm2.head("tgt"))

    # ----------------------------------------------------------------- replay
    def test_accepted_prerequisite_retry_replays_original(self):
        cfg = self.dep()
        prereq = [{"deviceId": "dep", "generation": 1, "configSha256": digest(cfg)}]
        d1 = self.target("t-1", 1, 0, prereqs=prereq)
        self.assertEqual(d1.status, 201)
        # dependency advances after the target was admitted
        self.submit("dep-2", "dep", 2, 1, b"dep-cfg-2")
        # exact retry replays the original acceptance and does not re-evaluate
        d2 = self.target("t-1", 1, 0, prereqs=prereq)
        self.assertTrue(d2.accepted)
        self.assertEqual(d2.status, 200)
        self.assertTrue(d2.duplicate)
        self.assertEqual(self.store.accepted_generations("tgt"), [1])

    # --------------------------------------------- atomicity / commit ordering
    def test_dependency_commits_first_concurrent_target_loses(self):
        """Held IMMEDIATE lock: the target verdict waits, then sees dep gen 2."""
        import sqlite3
        import time as _time

        self.dep(config=b"dep-cfg-1")

        # The holding connection is created and used solely inside this thread.
        def hold_then_commit():
            conn = sqlite3.connect(self.db, isolation_level=None)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO attestations "
                "(device_id, generation, previous_generation, config_sha256, "
                " attestation_id, payload_sha256, accepted_at) "
                "VALUES ('dep', 2, 1, ?, 'dep-2-locked', 'locked', 'now')",
                (digest(b"dep-cfg-2"),),
            )
            _time.sleep(0.5)
            conn.commit()
            conn.close()

        t = threading.Thread(target=hold_then_commit)
        t.start()
        _time.sleep(0.1)  # let the dependency transaction take the write lock
        start = _time.monotonic()
        d = self.target("t-1", 1, 0, prereqs=[
            {"deviceId": "dep", "generation": 1,
             "configSha256": digest(b"dep-cfg-1")}])
        elapsed = _time.monotonic() - start
        t.join()

        # the target really waited for the dependency commit, then rejected
        self.assertGreaterEqual(elapsed, 0.3)
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "PREREQUISITE_NOT_SATISFIED")
        self.assertIsNone(self.admitter.head("tgt"))
        self.assertEqual(self.admitter.head("dep")["generation"], 2)

    def test_concurrent_target_vs_dependency_update_serializable(self):
        self.dep(config=b"dep-cfg-1")
        prereq = [{"deviceId": "dep", "generation": 1,
                   "configSha256": digest(b"dep-cfg-1")}]
        results = []
        barrier = threading.Barrier(2)

        def target_worker():
            barrier.wait()
            results.append(("target", self.target("t-1", 1, 0, prereqs=prereq)))

        def dependency_worker():
            barrier.wait()
            d, _, _ = self.submit("dep-2", "dep", 2, 1, b"dep-cfg-2")
            results.append(("dep", d))

        threads = [threading.Thread(target=target_worker),
                   threading.Thread(target=dependency_worker)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        dep_d = next(d for name, d in results if name == "dep")
        tgt_d = next(d for name, d in results if name == "target")
        # dependency successor is valid under either serialization order
        self.assertTrue(dep_d.accepted, results)
        self.assertEqual(self.admitter.head("dep")["generation"], 2)
        if tgt_d.accepted:
            # target verdict committed before dep gen 2: row must exist
            self.assertEqual(self.admitter.head("tgt")["generation"], 1)
        else:
            # dep gen 2 committed first (or lock lost): no target generation
            self.assertIn(tgt_d.code,
                          {"PREREQUISITE_NOT_SATISFIED", "CONCURRENT_UPDATE"}, results)
            self.assertIsNone(self.admitter.head("tgt"))

    # ------------------------------------------------------------- validation
    def _malformed(self, prereqs, device="tgt"):
        return self.target("m-1", 1, 0, prereqs=prereqs, device=device)

    def test_prerequisite_self_reference_rejected(self):
        self.dep()
        d = self._malformed(
            [{"deviceId": "tgt", "generation": 1, "configSha256": digest(b"x")}])
        self.assertEqual(d.code, "INVALID_JSON_PAYLOAD")
        self.assertIsNone(self.admitter.head("tgt"))

    def test_prerequisite_empty_and_oversized_rejected(self):
        self.dep()
        entry = {"deviceId": "dep", "generation": 1, "configSha256": digest(b"dep-cfg-1")}
        self.assertEqual(self._malformed([]).code, "INVALID_JSON_PAYLOAD")
        self.assertEqual(self._malformed([dict(entry, deviceId=f"d{i}") for i in range(9)]).code,
                         "INVALID_JSON_PAYLOAD")
        # exactly eight is permitted structurally (devices are missing at
        # admission time, so it fails on the prerequisite check instead)
        d = self._malformed([dict(entry, deviceId=f"d{i}") for i in range(8)])
        self.assertEqual(d.code, "PREREQUISITE_NOT_SATISFIED")

    def test_prerequisite_duplicate_device_rejected(self):
        self.dep()
        entry = {"deviceId": "dep", "generation": 1, "configSha256": digest(b"dep-cfg-1")}
        d = self._malformed([entry, dict(entry)])
        self.assertEqual(d.code, "INVALID_JSON_PAYLOAD")

    def test_prerequisite_field_shapes_rejected(self):
        self.dep()
        good_sha = digest(b"dep-cfg-1")
        bad_shapes = [
            "not-an-array",
            [{"generation": 1, "configSha256": good_sha}],                       # missing deviceId
            [{"deviceId": "dep", "configSha256": good_sha}],                    # missing generation
            [{"deviceId": "dep", "generation": 1}],                             # missing digest
            [{"deviceId": "", "generation": 1, "configSha256": good_sha}],      # empty device
            [{"deviceId": "dep", "generation": 0, "configSha256": good_sha}],   # zero generation
            [{"deviceId": "dep", "generation": True, "configSha256": good_sha}],# bool generation
            [{"deviceId": "dep", "generation": 1, "configSha256": good_sha.upper()}],  # uppercase
            [{"deviceId": "dep", "generation": 1, "configSha256": "abc"}],      # short digest
        ]
        for prereqs in bad_shapes:
            d = self._malformed(prereqs)
            self.assertEqual(d.code, "INVALID_JSON_PAYLOAD", prereqs)
        self.assertIsNone(self.admitter.head("tgt"))

    def test_omitting_prerequisites_keeps_legacy_contract(self):
        # a dependency device may well exist; without prerequisites it is ignored
        self.dep()
        d, _, _ = self.submit("t-1", "lonely", 1, 0, b"solo")
        self.assertTrue(d.accepted)
        self.assertEqual(d.status, 201)


def _mp_submit(db_path, key_id, pub, seed, doc, att_id):
    import base64 as _b64
    import json as _json

    store = Store(db_path)
    adm = Admitter(store, {key_id: pub}, {key_id: None})
    payload = _json.dumps(doc, separators=(",", ":")).encode()
    sig = ed25519.sign(payload, seed)
    d = adm.admit(
        attestation_id=att_id,
        key_id=key_id,
        payload_b64=_b64.b64encode(payload).decode(),
        signature_b64=_b64.b64encode(sig).decode(),
    )
    return d.accepted, d.code


def _multiprocess_worker(db_path, att_id, config_byte):
    """Independent Store/Admitter instance, as in a separate process."""
    doc = {
        "deviceId": "mp-dev",
        "generation": 2,
        "previousGeneration": 1,
        "configSha256": digest(bytes([config_byte]) * 8),
    }
    return _mp_submit(db_path, KEY_ID, PUB, SEED, doc, att_id)


def _mp_target_worker(db_path):
    """Target whose prerequisite pins the dependency at generation 1."""
    doc = {
        "deviceId": "mp-tgt",
        "generation": 1,
        "previousGeneration": 0,
        "configSha256": digest(b"target"),
        "prerequisites": [
            {"deviceId": "mp-dep", "generation": 1, "configSha256": digest(b"dep-root")}
        ],
    }
    return _mp_submit(db_path, KEY_ID, PUB, SEED, doc, "mp-tgt-1")


def _mp_dependency_worker(db_path):
    """Dependency advancing from generation 1 to 2 concurrently."""
    doc = {
        "deviceId": "mp-dep",
        "generation": 2,
        "previousGeneration": 1,
        "configSha256": digest(b"dep-next"),
    }
    return _mp_submit(db_path, KEY_ID, PUB, SEED, doc, "mp-dep-2")


class MultiprocessConcurrencyTests(unittest.TestCase):
    """Separate processes hammering the same SQLite file must not fork."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "att.db")
        store = Store(self.db)
        adm = Admitter(store, {KEY_ID: PUB}, {KEY_ID: None})
        doc = {"deviceId": "mp-dev", "generation": 1, "previousGeneration": 0,
               "configSha256": digest(b"root")}
        payload = __import__("json").dumps(doc, separators=(",", ":")).encode()
        import base64 as _b64
        d = adm.admit(
            "mp-root", KEY_ID,
            _b64.b64encode(payload).decode(),
            _b64.b64encode(ed25519.sign(payload, SEED)).decode(),
        )
        self.assertTrue(d.accepted)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cross_process_competitors(self):
        import multiprocessing as mp

        ctx = mp.get_context("spawn")
        with ctx.Pool(processes=4) as pool:
            futures = [
                pool.apply_async(_multiprocess_worker, (self.db, f"mp-g2-{i}", 0x40 + i))
                for i in range(4)
            ]
            outcomes = [f.get(timeout=30) for f in futures]
        wins = [o for o in outcomes if o[0]]
        self.assertEqual(len(wins), 1, outcomes)
        # every loser must carry a stable conflict/race code
        for accepted, code in outcomes:
            if not accepted:
                self.assertIn(code, {"GENERATION_CONTENT_CONFLICT", "CONCURRENT_UPDATE"})
        store = Store(self.db)
        gens = store.accepted_generations("mp-dev")
        self.assertEqual(gens, [1, 2], gens)
        self.assertEqual(store.head("mp-dev").generation, 2)


class MultiprocessPrerequisiteTests(unittest.TestCase):
    """Target verdict vs dependency update in separate processes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "att.db")
        store = Store(self.db)
        adm = Admitter(store, {KEY_ID: PUB}, {KEY_ID: None})
        doc = {"deviceId": "mp-dep", "generation": 1, "previousGeneration": 0,
               "configSha256": digest(b"dep-root")}
        payload = __import__("json").dumps(doc, separators=(",", ":")).encode()
        import base64 as _b64
        d = adm.admit(
            "mp-dep-1", KEY_ID,
            _b64.b64encode(payload).decode(),
            _b64.b64encode(ed25519.sign(payload, SEED)).decode(),
        )
        self.assertTrue(d.accepted)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cross_process_prerequisite_race(self):
        import multiprocessing as mp

        ctx = mp.get_context("spawn")
        with ctx.Pool(processes=2) as pool:
            futures = [
                pool.apply_async(_mp_target_worker, (self.db,)),
                pool.apply_async(_mp_dependency_worker, (self.db,)),
            ]
            target_outcome, dep_outcome = [f.get(timeout=30) for f in futures]

        store = Store(self.db)
        dep_head = store.head("mp-dep")
        tgt_gens = store.accepted_generations("mp-tgt")

        # The dependency's own chain successor is valid in either commit order.
        self.assertTrue(dep_outcome[0], dep_outcome)
        self.assertEqual(dep_head.generation, 2)

        tgt_accepted, tgt_code = target_outcome
        if tgt_accepted:
            # Target verdict committed while the dependency head was still 1.
            self.assertEqual(tgt_gens, [1], tgt_gens)
        else:
            # The dependency committed first (or the write lock was lost):
            # the target must not exist in any generation.
            self.assertIn(tgt_code,
                          {"PREREQUISITE_NOT_SATISFIED", "CONCURRENT_UPDATE"},
                          target_outcome)
            self.assertEqual(tgt_gens, [], tgt_gens)
            self.assertIsNone(store.head("mp-tgt"))


if __name__ == "__main__":
    unittest.main()
