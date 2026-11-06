"""R8 semantic layer logic, with the model replaced by a stub (no Ollama needed)."""
import asyncio
import json

from gateway import dlp, semantic

FPS = dlp.fingerprints(json.dumps({"national_id": "Z298765431", "phone": "+886-912-000-101",
                                   "accounts": [{"number": "0042-118-500101"}]}))


def check_with(candidates, monkeypatch):
    async def fake_decode(text, **kw):
        if isinstance(candidates, Exception):
            raise candidates
        return candidates
    monkeypatch.setattr(semantic, "decode", fake_decode)
    return asyncio.run(semantic.check("draft", FPS))


def test_confirmed_only_when_candidate_matches_session_pii(monkeypatch):
    r = check_with(["Z298765431", "0800000123", "0101"], monkeypatch)
    assert r["status"] == "ok" and r["discloses"] and r["fields"] == ["national_id"] and r["candidates"] == 3


def test_model_over_extraction_is_not_a_false_alarm(monkeypatch):
    r = check_with(["0101", "2026", "A123456789", "Taipei"], monkeypatch)
    assert r["status"] == "ok" and r["discloses"] is False and r["fields"] == []


def test_candidates_are_not_returned(monkeypatch):
    r = check_with(["Z298765431"], monkeypatch)
    assert "Z298765431" not in json.dumps(r)


def test_model_failure_is_reported_not_raised(monkeypatch):
    r = check_with(TimeoutError("slow"), monkeypatch)
    assert r["status"] == "error" and r["discloses"] is None and "TimeoutError" in r["error"]
