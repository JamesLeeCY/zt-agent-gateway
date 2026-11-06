"""Output-side DLP: catch PII that leaves through the agent's own text, not through a tool.

When a PII tool returns a record, the gateway keeps only keyed fingerprints (HMAC) of its sensitive
values, never the values. Before the agent's final answer reaches anyone, the gateway scans it for those
fingerprints. Everything here is deterministic; no model is involved.

What is caught
  exact     the whole value, after canonicalisation: case, spaces and punctuation ignored, full-width
            folded (NFKC), Chinese numerals (零一二… / 壹貳參…) and English number words
            ("zero zero four two") read as digits, and the value written backwards.
            "Z 298 765 431", "Ｚ２９８…", "Z二九八七六五四三一", "134567892Z" all match.
            A birth date also matches as day-month-year, month-day-year, unpadded and ROC (民國) year.
  fragment  enough pieces of a mostly-numeric value to reconstruct most of it: "前五碼 Z2987，後五碼 65431".
            Only runs of >= 5 characters written in one piece count (prose in between ends a run), and
            together they must cover >= 60% of the value, so the usual "last four digits" masking (and
            stray years such as "2000") is still allowed; only the counted runs are redacted.
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


_ZH_DIGITS = str.maketrans("零〇一二兩三四五六七八九壹貳參肆伍陸柒捌玖", "001223456789123456789")
_ZH_VAL = {c: int(d) for c, d in zip("零〇一二兩三四五六七八九壹貳參肆伍陸柒捌玖", "001223456789123456789")}
_ZH_UNIT = {"十": 10, "拾": 10, "百": 100, "佰": 100, "千": 1000, "仟": 1000}
_ZH_RUN = re.compile("[" + "".join(_ZH_VAL) + "".join(_ZH_UNIT) + "萬億]+")

# Digit words read one by one, in the languages a bank's mail is likely to see. Kana only as whole tokens.
_DIGIT_WORDS = {
    **{w: str(i) for i, w in enumerate("zero one two three four five six seven eight nine".split())}, "oh": "0",
    **{w: str(i) for i, w in enumerate("null eins zwei drei vier fünf sechs sieben acht neun".split())},
    **{w: str(i) for i, w in enumerate("zéro un deux trois quatre cinq six sept huit neuf".split())},
    **{w: str(i) for i, w in enumerate("cero uno dos tres cuatro cinco seis siete ocho nueve".split())},
    **{w: str(i) for i, w in enumerate("ぜろ いち に さん よん ご ろく なな はち きゅう".split())},
    "れい": "0", "しち": "7", "zwo": "2",
}
_EN_SMALL = {w: i for i, w in enumerate("zero one two three four five six seven eight nine ten eleven twelve "
                                        "thirteen fourteen fifteen sixteen seventeen eighteen nineteen".split())}
_EN_TENS = {w: 10 * i for i, w in enumerate("_ _ twenty thirty forty fifty sixty seventy eighty ninety".split()) if w != "_"}
_EN_SCALE = {"hundred": 100, "thousand": 1000, "million": 10 ** 6, "billion": 10 ** 9}
_EN_ALL = set(_EN_SMALL) | set(_EN_TENS) | set(_EN_SCALE) | {"oh"}


def _zh_number(run: str) -> str:
    """'兩億九千八百七十六萬五千四百三十一' -> '298765431'; runs without units are read digit by digit."""
    if not any(c in _ZH_UNIT or c in "萬億" for c in run):
        return run.translate(_ZH_DIGITS)
    total = section = num = 0
    for c in run:
        if c in _ZH_VAL:
            num = _ZH_VAL[c]
        elif c in _ZH_UNIT:
            section += (num or 1) * _ZH_UNIT[c]
            num = 0
        elif c == "萬":
            total += (section + num) * 10 ** 4
            section = num = 0
        else:  # 億
            total = (total + section + num) * 10 ** 8
            section = num = 0
    return str(total + section + num)


def _en_number(words: list[str]) -> str:
    """'nine hundred twelve' -> '912'; a run of plain digit words is read digit by digit."""
    if all(w in _DIGIT_WORDS for w in words):
        return "".join(_DIGIT_WORDS[w] for w in words)
    out, total, current = [], 0, 0
    for w in words:
        v = _EN_SMALL.get(w, _EN_TENS.get(w))
        if v is not None:
            # "forty-two one hundred one" is two numbers: a new one starts when the slot is already taken.
            if (v < 10 and current % 10) or (v >= 10 and current % 100):
                out.append(str(total + current))
                total = current = 0
            current += v
        elif w == "hundred":
            current = (current or 1) * 100
        elif w in _EN_SCALE:
            total += (current or 1) * _EN_SCALE[w]
            current = 0
    out.append(str(total + current))
    return "".join(out)


_TOKEN = re.compile(r"[^\W\d_]+|.", re.S)


def _canonical(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Canonical string plus, for each canonical character, its (start, end) in the original text.

    Number words are read as digits: digit words in several languages ("zero zero four two", "null vier",
    "に・きゅう"), English cardinals ("nine hundred twelve"), Chinese numerals with units ("八十八").
    """
    chars: list[str] = []
    where: list[tuple[int, int]] = []

    def emit(digits: str, start: int, end: int):
        for d in digits:
            chars.append(d)
            where.append((start, end))

    tokens = [(m.start(), m.end(), m.group()) for m in _TOKEN.finditer(text)]
    i = 0
    while i < len(tokens):
        s, e, tok = tokens[i]
        low = unicodedata.normalize("NFKC", tok).lower()
        if low in _EN_ALL or low in _DIGIT_WORDS and low.isascii():
            # Group an English number phrase: number words joined by spaces / hyphens / "and".
            words, j, end = [], i, e
            while j < len(tokens):
                w = unicodedata.normalize("NFKC", tokens[j][2]).lower()
                if w in _EN_ALL or (w in _DIGIT_WORDS and w.isascii()):
                    words.append(w)
                    end = tokens[j][1]
                    j += 1
                elif w in {" ", "-"} or (w == "and" and words and words[-1] in _EN_SCALE) or (
                        w == "," and words and words[-1] in {"thousand", "million", "billion"}):
                    j += 1
                else:
                    break
            while j > i and unicodedata.normalize("NFKC", tokens[j - 1][2]).lower() in {" ", "-", "and", ","}:
                j -= 1
            emit(_en_number(words), s, end)
            i = j
            continue
        if low in _DIGIT_WORDS:  # non-English digit word, whole token
            emit(_DIGIT_WORDS[low], s, e)
        else:
            for k, ch in enumerate(tok):
                zh = _ZH_RUN.match(text, s + k)
                if zh and zh.start() == s + k and (k == 0 or not _ZH_RUN.match(text, s + k - 1)):
                    emit(_zh_number(zh.group()), zh.start(), zh.end())
                    continue
                if ch in _ZH_VAL or ch in _ZH_UNIT or ch in "萬億":
                    continue  # already emitted as part of a numeral run
                for c in re.sub(r"[^0-9a-z]", "", unicodedata.normalize("NFKC", ch).lower()):
                    chars.append(c)
                    where.append((s + k, s + k + 1))
        i += 1
    return "".join(chars), where


def _norm(s: str) -> str:
    return _canonical(s)[0]


def _date_forms(ymd: str) -> set[str]:
    """Other ways the same date is written: day-month-year, month-day-year, unpadded, ROC (民國) year.

    Forms shorter than MIN_LEN are dropped later ("民國67年3月14日" reads as 67314 and is left to the
    semantic layer)."""
    y, m, d = ymd[:4], ymd[4:6], ymd[6:]
    out = set()
    for mm, dd in {(m, d), (m.lstrip("0"), d.lstrip("0"))}:
        out |= {y + mm + dd, dd + mm + y, mm + dd + y}
        if int(y) > 1911:
            roc = int(y) - 1911
            out |= {f"{roc:03d}{mm}{dd}", f"{roc}{mm}{dd}"}
    return out


def _variants(field: str, value: str) -> set[str]:
    v = _norm(value)
    out = {v}
    if field == "phone" and v.startswith("886"):  # +886-912-... is also written 0912-...
        out.add("0" + v[3:])
    if field == "birth_date" and len(v) == 8 and v.isdigit():
        out |= _date_forms(v)
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
        # A fragment must be written in one piece: the canonical form drops prose, so without this "余额
        # 12,850,000" or the "一" in "进一步" can join digits from elsewhere into an accidental 4-gram.
        seg = [0] * len(norm)
        for j in range(1, len(norm)):
            gap = text[where[j - 1][1]:where[j][0]]
            seg[j] = seg[j - 1] + (len(gap) > 3 or not re.fullmatch(r"[\W_]*", gap))
        hits: dict[tuple[str, int], set[int]] = {}  # (ref, value pos) -> text positions where that 4-gram starts
        fields = {}
        for i in range(len(norm) - GRAM + 1):
            if seg[i] != seg[i + GRAM - 1]:
                continue
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
                    if length < MIN_RUN:
                        continue  # a stray 4-gram elsewhere ("2000" in a balance) is not part of the leak
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
