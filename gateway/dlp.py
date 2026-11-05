"""Output-side DLP: catch PII that leaves through the agent's own text, not through a tool.

When a PII tool returns a record, the gateway keeps only keyed fingerprints (HMAC) of its sensitive
values, never the values. Before the agent's final answer reaches anyone, the gateway scans it for those
fingerprints. Matching is done on a canonical form that ignores case, spaces and punctuation, folds
full-width characters (NFKC) and Chinese numerals to ASCII digits, and also covers values written
backwards, so "Z 298 765 431", "Ｚ２９８…", "Z二九八七六五四三一" and "134567892Z" all match.
Paraphrase, partial disclosure (e.g. last four digits) and real encodings (base64, ciphers) do not.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import unicodedata

# Fields worth protecting. Name and e-mail are left out on purpose: a reply to the customer
# legitimately contains them.
SENSITIVE_KEYS = {"national_id", "phone", "birth_date", "address", "number"}
MIN_LEN = 6  # shorter values would match by accident

_KEY = os.environ.get("ZT_DLP_KEY", "").encode() or secrets.token_bytes(32)

_ZH_DIGITS = str.maketrans("零〇一二三四五六七八九壹貳參肆伍陸柒捌玖", "00123456789123456789")


def _canon_char(ch: str) -> str:
    return re.sub(r"[^0-9a-z]", "", unicodedata.normalize("NFKC", ch).lower().translate(_ZH_DIGITS))


def _norm(s: str) -> str:
    return "".join(_canon_char(ch) for ch in s)


def _digest(s: str) -> str:
    return hmac.new(_KEY, s.encode(), hashlib.sha256).hexdigest()


def _variants(field: str, value: str) -> set[str]:
    v = _norm(value)
    out = {v}
    if field == "phone" and v.startswith("886"):  # +886-912-... is also written 0912-...
        out.add("0" + v[3:])
    out |= {x[::-1] for x in out}  # written backwards is still the same secret
    return {x for x in out if len(x) >= MIN_LEN}


def fingerprints(tool_result: str) -> list[tuple[str, int, str]]:
    """(field, length, hmac) for every sensitive value in a JSON tool result."""
    try:
        doc = json.loads(tool_result)
    except (TypeError, ValueError):
        return []
    found = []

    def walk(node, key=None):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, k)
        elif isinstance(node, list):
            for v in node:
                walk(v, key)
        elif key in SENSITIVE_KEYS and isinstance(node, (str, int)):
            field = "account_number" if key == "number" else key
            found.extend((field, len(x), _digest(x)) for x in _variants(field, str(node)))

    walk(doc)
    return found


def scan(text: str, fps: list[tuple[str, int, str]]) -> list[tuple[int, int, str]]:
    """Spans (start, end, field) in the ORIGINAL text whose normalised form matches a fingerprint."""
    chars, index = [], []
    for i, ch in enumerate(text):
        for c in _canon_char(ch):
            chars.append(c)
            index.append(i)
    norm = "".join(chars)
    by_len: dict[int, dict[str, str]] = {}
    for field, n, d in fps:
        by_len.setdefault(n, {})[d] = field
    spans = []
    for n, table in by_len.items():
        for i in range(len(norm) - n + 1):
            field = table.get(_digest(norm[i:i + n]))
            if field:
                spans.append((index[i], index[i + n - 1] + 1, field))
    return spans


def redact(text: str, spans: list[tuple[int, int, str]]) -> str:
    merged = []
    for s, e, f in sorted(spans):
        if merged and s <= merged[-1][1]:
            ps, pe, pf = merged[-1]
            merged[-1] = (ps, max(pe, e), pf)
        else:
            merged.append((s, e, f))
    for s, e, f in reversed(merged):
        text = text[:s] + f"[REDACTED:{f}]" + text[e:]
    return text
