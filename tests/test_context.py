from gateway.context import ContextTracker


def test_flags_are_sticky_and_calls_counted(tmp_path):
    t = ContextTracker(tmp_path / "c.db")
    assert t.register_call("s1") == {"session_id": "s1", "tainted": False, "pii_accessed": False, "call_count": 1}
    t.record_result("s1", "read_inbox")
    t.record_result("s1", "query_customer")
    t.record_result("s1", "send_email")  # nothing can clear the flags
    ctx = t.register_call("s1")
    assert ctx["tainted"] and ctx["pii_accessed"] and ctx["call_count"] == 2


def test_sessions_are_isolated(tmp_path):
    t = ContextTracker(tmp_path / "c.db")
    t.register_call("a")
    t.record_result("a", "read_inbox")
    assert not t.get("b")["tainted"]
