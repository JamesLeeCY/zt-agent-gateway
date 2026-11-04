"""Append-only JSON Lines audit log.

Arguments are stored only as a SHA-256 hash so the log never becomes a PII leak itself.
Each entry carries the hash of the previous entry, so editing or deleting a line breaks the chain.
"""
import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def args_hash(args: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(args).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = None
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        return json.loads(last)["hash"] if last else GENESIS

    def write(self, *, event: str, session_id: str, subject: dict, tool: str, args: dict,
              context: dict, decision: str, reason: list[str], policy_version: str, **extra) -> dict:
        with self._lock:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "session_id": session_id,
                "agent_id": subject.get("agent_id"),
                "on_behalf_of": subject.get("on_behalf_of"),
                "tool": tool,
                "args_hash": args_hash(args),
                "context": {k: context[k] for k in ("tainted", "pii_accessed", "call_count") if k in context},
                "decision": decision,
                "reason": reason,
                "policy_version": policy_version,
                **extra,
                "prev_hash": self._prev,
            }
            entry["hash"] = hashlib.sha256(canonical(entry).encode()).hexdigest()
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._prev = entry["hash"]
            return entry


def verify_chain(path: Path | str) -> tuple[bool, int]:
    """Return (ok, number_of_entries). ok is False if any line was altered, removed or reordered."""
    prev, n = GENESIS, 0
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            claimed = entry.pop("hash")
            if entry["prev_hash"] != prev or hashlib.sha256(canonical(entry).encode()).hexdigest() != claimed:
                return False, n
            prev, n = claimed, n + 1
    return True, n
