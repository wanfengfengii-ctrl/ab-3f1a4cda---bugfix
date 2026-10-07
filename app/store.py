"""SQLite-backed persistence for accepted attestations.

Write transactions use ``BEGIN IMMEDIATE`` so that concurrent submitters
(threads or processes) are serialised by the database itself: the loser of a
race re-reads the new head and is rejected as stale instead of forking the
accepted chain.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS attestations (
    device_id         TEXT    NOT NULL,
    generation        INTEGER NOT NULL,
    previous_generation INTEGER NOT NULL,
    config_sha256     TEXT    NOT NULL,
    attestation_id    TEXT    NOT NULL,
    payload_sha256    TEXT    NOT NULL,
    accepted_at       TEXT    NOT NULL,
    PRIMARY KEY (device_id, generation),
    UNIQUE (attestation_id)
);
"""


class StoredAttestation:
    __slots__ = (
        "device_id",
        "generation",
        "previous_generation",
        "config_sha256",
        "attestation_id",
        "payload_sha256",
        "accepted_at",
    )

    def __init__(self, row: sqlite3.Row):
        self.device_id = row["device_id"]
        self.generation = row["generation"]
        self.previous_generation = row["previous_generation"]
        self.config_sha256 = row["config_sha256"]
        self.attestation_id = row["attestation_id"]
        self.payload_sha256 = row["payload_sha256"]
        self.accepted_at = row["accepted_at"]

    def to_dict(self) -> dict:
        return {
            "deviceId": self.device_id,
            "generation": self.generation,
            "previousGeneration": self.previous_generation,
            "configSha256": self.config_sha256,
            "attestationId": self.attestation_id,
            "acceptedAt": self.accepted_at,
        }


class ConcurrentUpdateError(Exception):
    """Raised when the database cannot acquire the write lock in time."""


class Store:
    def __init__(self, db_path: str, busy_timeout_ms: int = 5000):
        self.db_path = db_path
        directory = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()
        self._busy_timeout = busy_timeout_ms
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=self._busy_timeout / 1000.0,
            isolation_level=None,  # manual transaction control
        )
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {int(self._busy_timeout)}")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    @contextmanager
    def transaction(self):
        """Serialise in-process writers, then take the DB write lock."""
        acquired = False
        with self._lock:
            conn = self._connect()
            try:
                waited = 0.0
                while True:
                    try:
                        conn.execute("BEGIN IMMEDIATE")
                        acquired = True
                        break
                    except sqlite3.OperationalError as exc:
                        if "locked" in str(exc).lower() and waited < self._busy_timeout / 1000.0:
                            time.sleep(0.02)
                            waited += 0.02
                            continue
                        raise ConcurrentUpdateError(str(exc)) from exc
                yield conn
                conn.commit()
            except Exception:
                if acquired:
                    conn.rollback()
                raise
            finally:
                conn.close()

    def head(self, device_id: str) -> Optional[StoredAttestation]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM attestations WHERE device_id = ? "
                "ORDER BY generation DESC LIMIT 1",
                (device_id,),
            ).fetchone()
        return StoredAttestation(row) if row is not None else None

    def insert(
        self,
        conn: sqlite3.Connection,
        *,
        device_id: str,
        generation: int,
        previous_generation: int,
        config_sha256: str,
        attestation_id: str,
        payload_sha256: str,
        accepted_at: str,
    ) -> None:
        conn.execute(
            "INSERT INTO attestations "
            "(device_id, generation, previous_generation, config_sha256, "
            " attestation_id, payload_sha256, accepted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                device_id,
                generation,
                previous_generation,
                config_sha256,
                attestation_id,
                payload_sha256,
                accepted_at,
            ),
        )

    def find(
        self, conn: sqlite3.Connection, device_id: str, generation: int
    ) -> Optional[StoredAttestation]:
        row = conn.execute(
            "SELECT * FROM attestations WHERE device_id = ? AND generation = ?",
            (device_id, generation),
        ).fetchone()
        return StoredAttestation(row) if row is not None else None

    def find_by_id(
        self, conn: sqlite3.Connection, attestation_id: str
    ) -> Optional[StoredAttestation]:
        row = conn.execute(
            "SELECT * FROM attestations WHERE attestation_id = ?",
            (attestation_id,),
        ).fetchone()
        return StoredAttestation(row) if row is not None else None

    def head_unlocked(
        self, conn: sqlite3.Connection, device_id: str
    ) -> Optional[StoredAttestation]:
        """Read the head on a connection that already holds the write lock."""
        row = conn.execute(
            "SELECT * FROM attestations WHERE device_id = ? "
            "ORDER BY generation DESC LIMIT 1",
            (device_id,),
        ).fetchone()
        return StoredAttestation(row) if row is not None else None

    def accepted_generations(self, device_id: str) -> list[int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT generation FROM attestations WHERE device_id = ? ORDER BY generation",
                (device_id,),
            ).fetchall()
        return [r["generation"] for r in rows]
