"""Context Tracker: per-session security state that the PDP decides on.

`tainted` and `pii_accessed` are sticky: once true they can never be reset for that session.
`user_named_recipients` are the e-mail addresses written in the user's own request. They are set once,
when the session starts and before any tool runs, so tool output (where injected text lives) can never
add to them.
"""
import json
import re
import sqlite3
import threading
from pathlib import Path

# Which tool results change the session state. Trust labels live here, not in the LLM.
UNTRUSTED_SOURCES = {"read_inbox"}
PII_SOURCES = {"query_customer"}

# Same pattern as bench/agentdojo/gateway_defense.py.
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def named_recipients(user_request: str) -> list[str]:
    """E-mail addresses the user wrote in the request, lower-cased and de-duplicated."""
    return sorted({m.lower() for m in EMAIL.findall(user_request)})


class ContextTracker:
    def __init__(self, db_path: Path | str):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS session ("
            " session_id TEXT PRIMARY KEY,"
            " tainted INTEGER NOT NULL DEFAULT 0,"
            " pii_accessed INTEGER NOT NULL DEFAULT 0,"
            " call_count INTEGER NOT NULL DEFAULT 0,"
            " user_named_recipients TEXT NOT NULL DEFAULT '[]')"
        )
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(session)")}
        if "user_named_recipients" not in cols:  # database created by an older version
            self._db.execute("ALTER TABLE session ADD COLUMN user_named_recipients TEXT NOT NULL DEFAULT '[]'")
        # Keyed fingerprints (HMAC) of PII values the session has seen; never the values themselves.
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS pii_fingerprint ("
            " session_id TEXT NOT NULL, field TEXT NOT NULL, length INTEGER NOT NULL, digest TEXT NOT NULL,"
            " ref TEXT NOT NULL, pos INTEGER NOT NULL,"
            " UNIQUE (session_id, field, digest, ref, pos))"
        )
        self._db.commit()

    def get(self, session_id: str) -> dict:
        row = self._db.execute(
            "SELECT tainted, pii_accessed, call_count, user_named_recipients FROM session WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        tainted, pii, count, named = row if row else (0, 0, 0, "[]")
        return {"session_id": session_id, "tainted": bool(tainted), "pii_accessed": bool(pii), "call_count": count,
                "user_named_recipients": json.loads(named)}

    def start(self, session_id: str, user_request: str) -> dict | None:
        """Open a session with the user's request. Only possible once, before the session's first tool call;
        returns None if the session already exists (so a later request cannot add recipients)."""
        named = json.dumps(named_recipients(user_request))
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO session (session_id, user_named_recipients) VALUES (?, ?) "
                "ON CONFLICT(session_id) DO NOTHING", (session_id, named))
            self._db.commit()
        return self.get(session_id) if cur.rowcount == 1 else None

    def register_call(self, session_id: str) -> dict:
        """Count a call attempt (allowed or not) and return the state the PDP should see."""
        with self._lock:
            self._db.execute(
                "INSERT INTO session (session_id, call_count) VALUES (?, 1) "
                "ON CONFLICT(session_id) DO UPDATE SET call_count = call_count + 1",
                (session_id,),
            )
            self._db.commit()
        return self.get(session_id)

    def record_result(self, session_id: str, tool: str) -> dict:
        """Update state after a tool result reached the agent. Flags only ever go 0 -> 1."""
        with self._lock:
            if tool in UNTRUSTED_SOURCES:
                self._db.execute("UPDATE session SET tainted = 1 WHERE session_id = ?", (session_id,))
            if tool in PII_SOURCES:
                self._db.execute("UPDATE session SET pii_accessed = 1 WHERE session_id = ?", (session_id,))
            self._db.commit()
        return self.get(session_id)

    def add_fingerprints(self, session_id: str, fps: list[tuple]) -> None:
        """Store DLP fingerprints (field, length, hmac, ref, pos); see gateway/dlp.py."""
        with self._lock:
            self._db.executemany("INSERT OR IGNORE INTO pii_fingerprint VALUES (?, ?, ?, ?, ?, ?)",
                                 [(session_id, *fp) for fp in fps])
            self._db.commit()

    def fingerprints(self, session_id: str) -> list[tuple]:
        return [tuple(r) for r in self._db.execute(
            "SELECT field, length, digest, ref, pos FROM pii_fingerprint WHERE session_id = ?", (session_id,))]
