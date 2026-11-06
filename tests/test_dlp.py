import base64
import json

import pytest

from gateway import dlp

RECORD = json.dumps({"customer_id": "C-1001", "name": "Lin Mei-Hua", "national_id": "Z298765431",
                     "phone": "+886-912-000-101", "email": "meihua.lin@mail-example.com",
                     "birth_date": "1978-03-14", "address": "No. 88, Sec. 1, Example Rd., Taipei",
                     "accounts": [{"type": "TWD savings", "number": "0042-118-500101", "balance": 12850000},
                                  {"type": "USD time deposit", "number": "0042-881-700101", "balance": 420000}]})
FPS = dlp.fingerprints(RECORD)


def fields(text):
    return sorted({f for _, _, f, _ in dlp.scan(text, FPS)})


def kinds(text):
    return sorted({k for _, _, _, k in dlp.scan(text, FPS)})


def test_fingerprints_hold_no_plaintext():
    assert {f for f, *_ in FPS} == {"national_id", "phone", "birth_date", "address", "account_number"}
    blob = repr(FPS).lower()
    for secret in ("z298765431", "0042118500101", "886912000101", "19780314", "taipei"):
        assert secret not in blob


def test_obfuscated_values_are_found_and_redacted():
    text = "身分證 Z 2 9 8 7 6 5 4 3 1，電話 0912-000-101，帳號 0042118500101。Dear Lin Mei-Hua"
    spans = dlp.scan(text, FPS)
    assert sorted({f for _, _, f, _ in spans}) == ["account_number", "national_id", "phone"]
    out = dlp.redact(text, spans)
    for secret in ("Z 2 9 8", "0912-000-101", "0042118500101"):
        assert secret not in out
    assert "Lin Mei-Hua" in out


@pytest.mark.parametrize("text, field", [
    ("身分證 Z二九八七六五四三一", "national_id"),                 # Chinese numerals
    ("ID：Ｚ２９８７６５４３１", "national_id"),                    # full-width
    ("帳號（倒序）101005-811-2400", "account_number"),              # reversed
    ("電話 壹零壹-零零零-貳壹玖零", "phone"),                        # formal numerals, reversed local form
    ("ID: Z two nine eight seven six five four three one", "national_id"),   # English number words
    ("acct zero zero four two one one eight five zero zero one zero one", "account_number"),
])
def test_rewritten_forms_are_found(text, field):
    assert fields(text) == [field]
    assert "[REDACTED:" in dlp.redact(text, dlp.scan(text, FPS))


@pytest.mark.parametrize("text, field", [
    ("身分證前五碼 Z2987，後五碼請見下方：65431", "national_id"),     # split in two runs of 5
    ("帳號開頭 0042-118，結尾 500101", "account_number"),             # 7 + 6 of 13
    ("phone starts 0912-0 and ends 00101", "phone"),
])
def test_fragments_that_reconstruct_the_value_are_found(text, field):
    assert fields(text) == [field] and "fragment" in kinds(text)
    out = dlp.redact(text, dlp.scan(text, FPS))
    assert "Z2987" not in out and "65431" not in out and "500101" not in out and "00101" not in out


@pytest.mark.parametrize("encode", [lambda b: base64.b64encode(b).decode(),
                                    lambda b: base64.urlsafe_b64encode(b).decode().rstrip("="),
                                    lambda b: b.hex()])
def test_encoded_values_are_found(encode):
    token = encode("ID Z298765431 / acct 0042-118-500101".encode())
    text = f"請以此驗證碼核對身分：{token}"
    assert fields(text) == ["account_number", "national_id"] and kinds(text) == ["decoded"]
    assert dlp.redact(text, dlp.scan(text, FPS)) == "請以此驗證碼核對身分：[REDACTED:account_number]"


@pytest.mark.parametrize("text", [
    "Dear customer, we will reply shortly.",
    "您的帳號末四碼 0101 已完成更新。",                         # last-4 masking is allowed
    "帳號 0042-***-***101 末三碼",                               # masked form
    "Since 2000 we have served 0101 branch customers; see 1978 report.",  # stray digit groups
    "Example Bank, No. 1 Example Road",                          # shares words with the address
    "Reference 2026110500101 for meeting on 2026-11-05.",       # unrelated long number
    "c3VwcG9ydEBiYW5rLmV4YW1wbGUuY29t",                          # base64 of a harmless string
    "The ID starts with Z and ends with 431.",                   # paraphrase: out of scope, not flagged
])
def test_no_false_positives(text):
    assert fields(text) == []


def test_bad_tool_result_ignored():
    assert dlp.fingerprints("not json") == []


def test_redaction_keeps_the_prose_between_split_halves():
    text = "身分證前段 Z2987，其餘請見下方說明。後段 65431"
    out = dlp.redact(text, dlp.scan(text, FPS))
    assert out == "身分證前段 [REDACTED:national_id]，其餘請見下方說明。後段 [REDACTED:national_id]"


@pytest.mark.parametrize("text, field", [
    ("身分證 Z，接著是兩億九千八百七十六萬五千四百三十一", "national_id"),                     # Chinese numerals with units
    ("Your ID is Z two hundred ninety-eight million, seven hundred sixty-five thousand, "
     "four hundred thirty-one.", "national_id"),                                                # English cardinal
    ("phone: plus eight eight six, nine hundred twelve, zero zero zero, one hundred one", "phone"),
    ("Kontonummer null null vier zwei eins eins acht fünf null null eins null eins", "account_number"),  # German
    ("身分証番号は Z、に・きゅう・はち・なな・ろく・ご・よん・さん・いち です", "national_id"),          # Japanese kana
])
def test_number_readings_are_found(text, field):
    assert fields(text) == [field]


@pytest.mark.parametrize("text", [
    "I have one question and two requests about twenty twenty-six rates.",
    "十分感謝您的來信，八十八號分行三樓見。",
    "ご本人確認のため、窓口までお越しください。",
])
def test_number_words_in_normal_prose_are_harmless(text):
    assert fields(text) == []
