"""Shared filesystem locations for the mock tools (overridable for tests/containers)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("ZT_DATA_DIR", ROOT / "data"))
VAR_DIR = Path(os.environ.get("ZT_VAR_DIR", ROOT / "var"))
OUTBOX = VAR_DIR / "outbox.jsonl"
