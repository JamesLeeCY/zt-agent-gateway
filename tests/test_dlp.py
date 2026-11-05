import json

from gateway import dlp

RECORD = json.dumps({"customer_id": "C-1001", "name": "Lin Mei-Hua", "national_id": "Z298765431",
                     "phone": "+886-912-000-101", "email": "meihua.lin@mail-example.com",
                     "accounts": [{"type": "TWD savings", "number": "0042-118-500101", "balance": 12850000}]})


def test_fingerprints_hold_no_plaintext():
    fps = dlp.fingerprints(RECORD)
    assert {f for f, _, _ in fps} == {"national_id", "phone", "account_number"}
    assert "Z298765431" not in repr(fps).upper() and "0042118500101" not in repr(fps)


def test_obfuscated_values_are_found_and_redacted():
    text = "身分證 Z 2 9 8 7 6 5 4 3 1，電話 0912-000-101，帳號 0042118500101。Dear Lin Mei-Hua"
    spans = dlp.scan(text, dlp.fingerprints(RECORD))
    assert sorted({f for _, _, f in spans}) == ["account_number", "national_id", "phone"]
    out = dlp.redact(text, spans)
    for secret in ("Z 2 9 8", "0912-000-101", "0042118500101"):
        assert secret not in out
    assert out.count("[REDACTED:") == 3 and "Lin Mei-Hua" in out


def test_clean_text_untouched_and_bad_result_ignored():
    assert dlp.scan("Dear customer, we will reply shortly.", dlp.fingerprints(RECORD)) == []
    assert dlp.fingerprints("not json") == []


def test_rewritten_forms_are_found():
    fps = dlp.fingerprints(RECORD)
    for text, field in [("身分證 Z二九八七六五四三一", "national_id"),  # Chinese numerals
                        ("ID：Ｚ２９８７６５４３１", "national_id"),  # full-width
                        ("帳號（倒序）101005-811-2400", "account_number"),  # reversed
                        ("電話 壹零壹-零零零-貳壹玖零", "phone")]:  # formal numerals, reversed local form
        spans = dlp.scan(text, fps)
        assert [f for _, _, f in spans] == [field], text
        assert "[REDACTED:" in dlp.redact(text, spans)
