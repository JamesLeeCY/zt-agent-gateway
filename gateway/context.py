"""Context Tracker: per-session security state that the PDP decides on.

`tainted` and `pii_accessed` are sticky: once true they can never be reset for that session.
"""
import sqlite3
import threading
from pathlib import Path

# Which tool results change the session state. Trust labels live here, not in the LLM.
UNTRUSTED_SOURCES = {"read_inbox"}
PII_SOURCES = {"query_customer"}


class ContextTracker:
    def __init__(self, db_path: Path | str):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS session ("
            " session_id TEXT PRIMARY KEY,"
            " tainted INTEGER NOT NULL DEFAULT 0,"
            " pii_accessed INTEGER NOT NULL DEFAULT 0,"
            " call_count INTEGER NOT NULL DEFAULT 0)"
        )
        self._db.commit()

    def get(self, session_id: str) -> dict:
        row = self._db.execute(
            "SELECT tainted, pii_accessed, call_count FROM session WHERE session_id = ?", (session_id,)
        ).fetchone()
        tainted, pii, count = row if row else (0, 0, 0)
        return {"session_id": session_id, "tainted": bool(tainted), "pii_accessed": bool(pii), "call_count": count}

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
