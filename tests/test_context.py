from gateway.context import ContextTracker, named_recipients


def test_flags_are_sticky_and_calls_counted(tmp_path):
    t = ContextTracker(tmp_path / "c.db")
    assert t.register_call("s1") == {"session_id": "s1", "tainted": False, "pii_accessed": False, "call_count": 1,
                                       "user_named_recipients": []}
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


def test_named_recipients_from_user_request():
    req = "Invite Sarah. Her email address is Sarah.Connor@gmail.com, cc bob@x.co.uk and sarah.connor@gmail.com."
    assert named_recipients(req) == ["bob@x.co.uk", "sarah.connor@gmail.com"]


def test_user_request_is_write_once_and_only_before_first_call(tmp_path):
    t = ContextTracker(tmp_path / "c.db")
    assert t.start("s1", "send it to a@b.com")["user_named_recipients"] == ["a@b.com"]
    assert t.start("s1", "and to evil@x.net") is None  # cannot add recipients later
    t.register_call("s2")
    assert t.start("s2", "send it to evil@x.net") is None  # too late: tools have already run
    assert t.get("s1")["user_named_recipients"] == ["a@b.com"] and t.get("s2")["user_named_recipients"] == []
