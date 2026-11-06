"""Output-side DLP: catch PII that leaves through the agent's own text, not through a tool.

When a PII tool returns a record, the gateway keeps only keyed fingerprints (HMAC) of its sensitive
values, never the values. Before the agent's final answer reaches anyone, the gateway scans it for those
fingerprints. Everything here is deterministic; no model is involved.

What is caught
  exact     the whole value, after canonicalisation: case, spaces and punctuation ignored, full-width
            folded (NFKC), Chinese numerals (零一二… / 壹貳參…) and English number words
            ("zero zero four two") read as digits, and the value written backwards.
            "Z 298 765 431", "Ｚ２９８…", "Z二九八七六五四三一", "134567892Z" all match.
  fragment  enough pieces of a mostly-numeric value to reconstruct most of it: "前五碼 Z2987，後五碼 65431".
            Only runs of >= 5 characters count, and together they must cover >= 60% of the value, so the
            usual "last four digits" masking (and stray years such as "2000") is still allowed.
  decoded   base64 / hex tokens are decoded and the result is scanned again.

What is not caught: paraphrase that never writes the characters ("starts with Z, ends with 431"
is a fragment run of 3 and is allowed), arithmetic, ciphers, translation into other number words.
That needs semantic detection (a model), which is a separate, later layer.
"""
import base64
import binascii
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
MIN_LEN = 6        # shorter values would match by accident
GRAM = 4           # fragment fingerprints are 4-grams of the value
MIN_RUN = 5        # a fragment run shorter than this is ignored ("last 4 digits" stays allowed)
MIN_COVER = 0.6    # fragments must cover this share of the value to count as disclosure

_KEY = os.environ.get("ZT_DLP_KEY", "").encode() or secrets.token_bytes(32)

_ZH_DIGITS = str.maketrans("零〇一二三四五六七八九壹貳參肆伍陸柒捌玖", "00123456789123456789")
_WORDS = {"zero": "0", "oh": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5",
          "six": "6", "seven": "7", "eight": "8", "nine": "9"}
_B64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")

# A fingerprint: (field, length, hmac, ref, pos).
#   exact:    ref == "", pos == -1, length = length of the canonical value
#   fragment: ref = "<value id>:<value length>", pos = offset of this 4-gram in the value, length = GRAM
Fingerprint = tuple[str, int, str, str, int]
# A finding: (start, end, field, kind) in the ORIGINAL text.
Span = tuple[int, int, str, str]


def _digest(s: str) -> str:
    return hmac.new(_KEY, s.encode(), hashlib.sha256).hexdigest()


def _canon_char(ch: str) -> str:
    return re.sub(r"[^0-9a-z]", "", unicodedata.normalize("NFKC", ch).lower().translate(_ZH_DIGITS))


def _canonical(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Canonical string plus, for each canonical character, its (start, end) in the original text."""
    chars, where = [], []
    for m in re.finditer(r"[A-Za-z]+|.", text, re.S):
        tok = m.group()
        if tok.lower() in _WORDS:
            chars.append(_WORDS[tok.lower()])
            where.append((m.start(), m.end()))
            continue
        for k, ch in enumerate(tok):
            for c in _canon_char(ch):
                chars.append(c)
                where.append((m.start() + k, m.start() + k + 1))
    return "".join(chars), where


def _norm(s: str) -> str:
    return _canonical(s)[0]


def _variants(field: str, value: str) -> set[str]:
    v = _norm(value)
    out = {v}
    if field == "phone" and v.startswith("886"):  # +886-912-... is also written 0912-...
        out.add("0" + v[3:])
    out |= {x[::-1] for x in out}  # written backwards is still the same secret
    return {x for x in out if len(x) >= MIN_LEN}


def _fragment_values(field: str, value: str) -> list[str]:
    """Forward forms of a mostly-numeric value, for fragment fingerprints."""
    v = _norm(value)
    if len(v) < 8 or sum(c.isdigit() for c in v) < 0.7 * len(v):
        return []  # addresses and short values: exact matching only
    out = [v]
    if field == "phone" and v.startswith("886"):
        out.append("0" + v[3:])
    return out


def fingerprints(tool_result: str) -> list[Fingerprint]:
    """Fingerprints for every sensitive value in a JSON tool result. No plaintext is returned."""
    try:
        doc = json.loads(tool_result)
    except (TypeError, ValueError):
        return []
    found: list[Fingerprint] = []

    def walk(node, key=None):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, k)
        elif isinstance(node, list):
            for v in node:
                walk(v, key)
        elif key in SENSITIVE_KEYS and isinstance(node, (str, int)):
            field = "account_number" if key == "number" else key
            found.extend((field, len(x), _digest(x), "", -1) for x in _variants(field, str(node)))
            for v in _fragment_values(field, str(node)):
                ref = f"{secrets.token_hex(4)}:{len(v)}"
                found.extend((field, GRAM, _digest(v[p:p + GRAM]), ref, p) for p in range(len(v) - GRAM + 1))

    walk(doc)
    return found


def _pieces(text: str, where: list[tuple[int, int]], field: str, kind: str) -> list[Span]:
    """Turn the original positions of a match into spans, split wherever real prose sits in between.

    The canonical form drops CJK text, so "前段 Z2987 ……後段 65431" matches the whole value; only the
    characters that make up the value are redacted, not the sentence between the two halves."""
    spans: list[Span] = []
    for s, e in where:
        gap = text[spans[-1][1]:s] if spans else ""
        if spans and len(gap) <= 3 and re.fullmatch(r"[\W_]*", gap):  # only separators ("-", " ", "，") between
            spans[-1] = (spans[-1][0], e, field, kind)
        else:
            spans.append((s, e, field, kind))
    return spans


def _scan_plain(text: str, fps: list[Fingerprint]) -> list[Span]:
    norm, where = _canonical(text)
    spans: list[Span] = []

    # exact matches
    exact: dict[int, dict[str, str]] = {}
    for field, n, d, ref, _ in fps:
        if not ref:
            exact.setdefault(n, {})[d] = field
    for n, table in exact.items():
        for i in range(len(norm) - n + 1):
            field = table.get(_digest(norm[i:i + n]))
            if field:
                spans.extend(_pieces(text, where[i:i + n], field, "exact"))

    # fragments: chain consecutive 4-gram hits into runs, then check how much of each value they cover
    grams: dict[str, list[tuple[str, str, int]]] = {}
    for field, _, d, ref, pos in fps:
        if ref:
            grams.setdefault(d, []).append((field, ref, pos))
    if grams:
        hits: dict[tuple[str, int], set[int]] = {}  # (ref, value pos) -> text positions where that 4-gram starts
        fields = {}
        for i in range(len(norm) - GRAM + 1):
            for field, ref, pos in grams.get(_digest(norm[i:i + GRAM]), []):
                hits.setdefault((ref, pos), set()).add(i)
                fields[ref] = field
        runs: dict[str, list[tuple[int, int, int]]] = {}  # ref -> (text start, value start, run length)
        for (ref, pos), starts in hits.items():
            for i in starts:
                if i - 1 in hits.get((ref, pos - 1), ()):
                    continue  # not the beginning of a run
                length = GRAM
                while i + length - GRAM + 1 in hits.get((ref, pos + length - GRAM + 1), ()):
                    length += 1
                runs.setdefault(ref, []).append((i, pos, length))
        for ref, rs in runs.items():
            value_len = int(ref.split(":")[1])
            covered = set()
            for _, p, length in rs:
                if length >= MIN_RUN:
                    covered.update(range(p, p + length))
            if len(covered) >= max(MIN_RUN, MIN_COVER * value_len):
                for i, _, length in rs:
                    spans.extend(_pieces(text, where[i:i + length], fields[ref], "fragment"))
    return spans


def _decoded_tokens(text: str):
    """(start, end, decoded text) for base64 / hex tokens that decode to readable text."""
    for rx, decode in ((_B64, lambda t: base64.b64decode(t + "=" * (-len(t) % 4), altchars=b"-_")),
                       (_HEX, bytes.fromhex)):
        for m in rx.finditer(text):
            try:
                raw = decode(m.group().rstrip("=") if rx is _B64 else m.group())
                out = raw.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if out and sum(ch.isprintable() or ch.isspace() for ch in out) >= 0.9 * len(out):
                yield m.start(), m.end(), out


def scan(text: str, fps: list[Fingerprint]) -> list[Span]:
    """All findings in the original text: exact, fragment, and inside decodable base64/hex tokens."""
    spans = _scan_plain(text, fps)
    for start, end, decoded in _decoded_tokens(text):
        for _, _, field, _ in _scan_plain(decoded, fps):
            spans.append((start, end, field, "decoded"))
    return spans


def redact(text: str, spans: list[Span]) -> str:
    merged = []
    for s, e, f, _ in sorted(spans):
        if merged and s < merged[-1][1]:
            ps, pe, pf = merged[-1]
            merged[-1] = (ps, max(pe, e), pf)
        else:
            merged.append((s, e, f))
    for s, e, f in reversed(merged):
        text = text[:s] + f"[REDACTED:{f}]" + text[e:]
    return text
