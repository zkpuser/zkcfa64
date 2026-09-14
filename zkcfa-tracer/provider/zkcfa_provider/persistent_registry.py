"""SQLite-backed one-time challenges for the reference raw registry.

The database and its directory are trusted registry state. Transactions survive
ordinary service restarts; this module does not protect against storage rollback.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from .protocol import RawRegistryService, _require_regular


class PersistentRawRegistryService(RawRegistryService):
    def __init__(self, signed_registry: dict[str, object], authority_public: Path,
                 *, state_path: Path) -> None:
        super().__init__(signed_registry, authority_public)
        self.state_path = state_path
        state_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if state_path.parent.is_symlink():
            raise ValueError("registry state parent must not be a symlink")
        try:
            descriptor = os.open(state_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            _require_regular(state_path, "registry state", private=True)
        else:
            os.close(descriptor)
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS raw_challenges ("
                "challenge_id TEXT PRIMARY KEY, registry_id TEXT NOT NULL, "
                "payload TEXT NOT NULL, used INTEGER NOT NULL CHECK (used IN (0,1)))"
            )

    def _connect(self) -> sqlite3.Connection:
        _require_regular(self.state_path, "registry state", private=True)
        connection = sqlite3.connect(self.state_path, timeout=30)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def issue_challenge(self, device_id: str, raw_registry_id_value: str,
                        *, ttl_seconds: int = 300) -> dict[str, object]:
        challenge = super().issue_challenge(
            device_id, raw_registry_id_value, ttl_seconds=ttl_seconds
        )
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT INTO raw_challenges VALUES (?, ?, ?, 0)",
                (challenge["challenge_id"], raw_registry_id_value,
                 json.dumps(challenge, sort_keys=True)),
            )
        # The authoritative copy is the committed database row.
        with self._lock:
            self._challenges.pop(challenge["challenge_id"], None)
        return challenge

    def _consume_challenge(self, payload: dict[str, object]) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload, used FROM raw_challenges "
                "WHERE challenge_id=? AND registry_id=?",
                (payload["challenge_id"], self.registry["raw_registry_id"]),
            ).fetchone()
            challenge = None if row is None else {**json.loads(row[0]), "used": bool(row[1])}
            self._validate_challenge(payload, challenge)
            connection.execute(
                "UPDATE raw_challenges SET used=1 WHERE challenge_id=?",
                (payload["challenge_id"],),
            )
