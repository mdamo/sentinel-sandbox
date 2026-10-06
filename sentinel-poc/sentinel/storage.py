"""Single-writer durable state and redacted hash-chained audit (stdlib only)."""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import sqlite3
import time


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Store:
    def __init__(self, path: str):
        # Parent must be controlled by the service account. Reject symlink files.
        self.lock_fd = os.open(path + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise ValueError("database must be owned by service user with mode 0600")
            finally:
                os.close(fd)
            self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                  seq INTEGER PRIMARY KEY, body TEXT NOT NULL, previous TEXT NOT NULL, digest TEXT NOT NULL);
            """)
            self.verify()
        except BaseException:
            if hasattr(self, "db"):
                self.db.close()
            os.close(self.lock_fd)
            raise

    def load(self):
        row = self.db.execute("SELECT body FROM state WHERE id=1").fetchone()
        return json.loads(row[0]) if row else None

    def commit(self, state: dict, event: dict) -> int:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            last = self.db.execute("SELECT seq,digest FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            seq, previous = (last[0] + 1, last[1]) if last else (1, "0" * 64)
            snapshot = canonical(state)
            body = canonical(dict(event, seq=seq, timestamp=time.time(),
                                  state_digest=hashlib.sha256(snapshot.encode()).hexdigest()))
            digest = hashlib.sha256((previous + body).encode()).hexdigest()
            self.db.execute("INSERT INTO audit VALUES (?,?,?,?)", (seq, body, previous, digest))
            self.db.execute("INSERT OR REPLACE INTO state VALUES (1,?)", (snapshot,))
            self.db.execute("COMMIT")
            return seq
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def verify(self):
        previous, count = "0" * 64, 0
        for seq, body, prev, digest in self.db.execute("SELECT * FROM audit ORDER BY seq"):
            count += 1
            if seq != count or prev != previous or hashlib.sha256((prev + body).encode()).hexdigest() != digest:
                raise ValueError("audit chain invalid")
            previous = digest
        row = self.db.execute("SELECT body FROM state WHERE id=1").fetchone()
        if count:
            if row is None or hashlib.sha256(row[0].encode()).hexdigest() != json.loads(body)["state_digest"]:
                raise ValueError("security state does not match audit")
        elif row is not None:
            raise ValueError("state without audit")
        return count, previous

    def checkpoint(self, key: bytes) -> dict:
        count, digest = self.verify()
        record = dict(seq=count, digest=digest)
        return dict(record, signature=hmac.new(key, canonical(record).encode(), hashlib.sha256).hexdigest())

    def verify_checkpoint(self, checkpoint: dict, key: bytes) -> None:
        record = {k: checkpoint[k] for k in ("seq", "digest")}
        signature = hmac.new(key, canonical(record).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, checkpoint["signature"]):
            raise ValueError("checkpoint signature invalid")
        self.verify()
        state = self.load()
        if state is not None:
            state_signature = state.pop("signature", "")
            expected_state = hmac.new(key, canonical(state).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(state_signature, expected_state):
                raise ValueError("security state signature invalid")
        row = self.db.execute("SELECT digest FROM audit WHERE seq=?", (record["seq"],)).fetchone()
        if record["seq"] == 0:
            if record["digest"] != "0" * 64:
                raise ValueError("invalid genesis checkpoint")
        elif row is None or row[0] != record["digest"]:
            raise ValueError("checkpoint missing or changed")

    def close(self):
        self.db.close()
        os.close(self.lock_fd)
