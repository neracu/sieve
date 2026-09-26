"""L2 composite detector — deterministic four-signal risk score.

This layer replaces a remote LLM call with an explainable heuristic engine.
Every score is a pure function of the input text and a fixed malicious corpus,
so the same string always produces the same result.

Signals (each normalised to ``[0.0, 1.0]``)
-------------------------------------------
1. **POS imperative ratio** — share of sentences that are imperative
   (base-form verbs with no explicit subject). Uses spaCy ``en_core_web_sm``
   when the model loads, and a regex verb lexicon otherwise.
2. **Shannon entropy anomaly** — sliding 64-character windows, plus base64
   blobs and zero-width / bidi obfuscation.
3. **TF-IDF cosine similarity** — max similarity of the input (and its
   chunks) to the known injection fixtures.
4. **Structural context** — HTML comments, Markdown hidden comments,
   Markdown image titles, and a payload parked at the tail of a long document.

Aggregation
-----------
``risk = 0.35*POS + 0.20*Entropy + 0.30*TFIDF + 0.15*Structural``

  risk ≥ 0.50  → MALICIOUS (flagged)
  risk ≥ 0.25  → SUSPICIOUS (flagged)
  risk <  0.25 → SAFE
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections import Counter
from functools import lru_cache
from pathlib import Path

from sieve.core.types import ContentSource, DetectionResult, RiskLevel, UntrustedContent
from sieve.detectors.base import BaseDetector

try:
    import spacy
except ImportError:  # pragma: no cover - exercised only when spaCy is absent
    spacy = None  # type: ignore[assignment]

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
except ImportError:  # pragma: no cover - dependency is required at runtime
    TfidfVectorizer = None  # type: ignore[assignment,misc]
    cosine_similarity = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Weights and decision thresholds
# ---------------------------------------------------------------------------

WEIGHT_POS: float = 0.35
WEIGHT_ENTROPY: float = 0.20
WEIGHT_TFIDF: float = 0.30
WEIGHT_STRUCTURAL: float = 0.15

THRESHOLD_MALICIOUS: float = 0.50
THRESHOLD_SUSPICIOUS: float = 0.25

_FIXTURE_PATH = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "injections.json"

# Entropy windows. Natural English sits near 4 bits/char and contains spaces;
# base64 and noise sit higher and are almost space-free.
_ENTROPY_WINDOW = 64
_ENTROPY_STEP = 32
_ENTROPY_HIGH = 4.85

_TAIL_MIN_CHARS = 480

_SUBJECT_DEPS = frozenset({"nsubj", "nsubjpass", "csubj", "csubjpass"})
_LEADING_DISCOURSE = frozenset({"please", "kindly", "now", "just"})

# Sentence-initial base verbs used by the regex POS fallback (and as a
# backstop when the tagger misses a classic instruction verb).
_IMPERATIVE_VERBS = frozenset(
    {
        "ignore",
        "disregard",
        "forget",
        "override",
        "reveal",
        "output",
        "print",
        "read",
        "execute",
        "exec",
        "run",
        "send",
        "leak",
        "exfiltrate",
        "dump",
        "bypass",
        "disable",
        "enter",
        "confirm",
        "delete",
        "remove",
        "open",
        "write",
        "show",
        "display",
        "return",
        "provide",
        "list",
        "extract",
        "download",
        "upload",
        "access",
        "fetch",
        "obey",
        "comply",
        "cat",
        "curl",
        "wget",
        "sudo",
        "eval",
        "summarize",
        "summarise",
        "refer",
        "check",
        "act",
        "pretend",
        "jailbreak",
        "enable",
        "activate",
        "switch",
        "change",
        "set",
        "make",
        "do",
        "use",
        "install",
        "copy",
        "paste",
        "post",
        "get",
        "put",
        "call",
        "invoke",
        "transmit",
        "forward",
        "email",
        "mail",
        "drop",
        "wipe",
        "erase",
        "expose",
        "disclose",
        "repeat",
        "respond",
        "reply",
        "answer",
        "begin",
        "start",
        "stop",
        "halt",
        "continue",
        "proceed",
        "follow",
    }
)

_OBFUSCATION_CHARS = frozenset(
    {
        "\u200b",
        "\u200c",
        "\u200d",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2060",
        "\u2061",
        "\u2062",
        "\u2063",
        "\u2064",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
        "\ufeff",
        "\u180e",
        "\u00ad",
    }
)

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
_CLAUSE_SPLIT = re.compile(r"[.!?;:]+")
_LEADING_LABEL = re.compile(r"^(?:\[[^\]]{0,48}\]\s*|#{1,6}\s+)")
_RE_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_RE_MD_COMMENT = re.compile(
    r"\[//\]:\s*#\s*(?:\([^)\n]*\)|\"[^\"\n]*\"|'[^'\n]*')",
    re.IGNORECASE,
)
_RE_MD_IMAGE = re.compile(r"!\[(?P<alt>[^\]]*)\]\(\s*(?P<dest>[^)]*)\)")
_RE_B64 = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
_RE_TAIL_PAYLOAD = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior)|disregard\s+(all\s+)?(previous|prior|rules?)|"
    r"system\s+(override|prompt)|read\s+\.env|exfiltrat|reveal\s+(your\s+)?(system\s+)?prompt|"
    r"developer\s+mode|\[//\]:\s*#|<!--)",
    re.IGNORECASE,
)
_RE_WORD = re.compile(r"[A-Za-z']+")


# ---------------------------------------------------------------------------
# Model + corpus initialisation
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _load_nlp():
    """Load ``en_core_web_sm``, or return ``None`` so the regex POS path runs."""
    if spacy is None:
        return None
    try:
        return spacy.load("en_core_web_sm", disable=["ner", "lemmatizer"])
    except Exception:
        return None


@lru_cache(maxsize=1)
def _load_injection_corpus() -> tuple[str, ...]:
    data = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    payloads: list[str] = []
    for item in data:
        text = item.get("payload") or item.get("text") or ""
        if str(text).strip():
            payloads.append(str(text))
    if not payloads:
        raise ValueError(f"No injection payloads found in {_FIXTURE_PATH}")
    return tuple(payloads)


@lru_cache(maxsize=1)
def _load_tfidf():
    """Fit a TF-IDF vectorizer on the known injection fixtures."""
    if TfidfVectorizer is None or cosine_similarity is None:
        raise RuntimeError("scikit-learn is required for L2CompositeDetector")
    corpus = list(_load_injection_corpus())
    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        ngram_range=(1, 2),
        min_df=1,
        norm="l2",
    )
    matrix = vectorizer.fit_transform(corpus)
    return vectorizer, matrix


# ---------------------------------------------------------------------------
# Signal 1 — POS imperative ratio
# ---------------------------------------------------------------------------


def _is_infinitive(verb) -> bool:
    return any(tok.lower_ == "to" and tok.dep_ == "aux" for tok in verb.lefts)


def _verb_has_subject(verb) -> bool:
    if any(child.dep_ in _SUBJECT_DEPS for child in verb.children):
        return True
    for ancestor in verb.ancestors:
        if any(child.dep_ in _SUBJECT_DEPS for child in ancestor.children):
            return True
        if ancestor.pos_ not in {"VERB", "AUX"}:
            break
    return False


def _spacy_sentence_imperative(sent) -> bool:
    """True when *sent* contains a bare base-form verb with no subject."""
    tokens = [tok for tok in sent if not tok.is_space and tok.pos_ not in {"PUNCT", "SYM", "SPACE"}]
    if not tokens:
        return False

    for tok in sent:
        if tok.pos_ != "VERB":
            continue
        if tok.tag_ not in {"VB", "VBP"}:
            continue
        if _is_infinitive(tok) or _verb_has_subject(tok):
            continue
        return True
    return False


def _fallback_sentence_imperative(sentence: str) -> bool:
    """Regex stand-in: a clause opens with a base-form instruction verb."""
    for clause in _CLAUSE_SPLIT.split(sentence):
        clause = clause.strip(" \t\"'`[](){}<>")
        if not clause:
            continue
        previous = None
        while previous != clause:
            previous = clause
            clause = _LEADING_LABEL.sub("", clause).strip(" \t\"'`[](){}<>")
        words = _RE_WORD.findall(clause)
        if not words:
            continue
        first = words[0].lower()
        if first in _LEADING_DISCOURSE and len(words) > 1:
            first = words[1].lower()
        if first in _IMPERATIVE_VERBS:
            return True
    return False


def _pos_score(text: str, nlp) -> float:
    stripped = text.strip()
    if not stripped:
        return 0.0

    if nlp is not None:
        doc = nlp(stripped)
        sentences = [sent for sent in doc.sents if sent.text.strip()]
        if sentences:
            hits = sum(
                1
                for sent in sentences
                if _spacy_sentence_imperative(sent) or _fallback_sentence_imperative(sent.text)
            )
            return hits / len(sentences)

    sentences = [part.strip() for part in _SENT_SPLIT.split(stripped) if part.strip()]
    if not sentences:
        return 0.0
    hits = sum(1 for sentence in sentences if _fallback_sentence_imperative(sentence))
    return hits / len(sentences)


# ---------------------------------------------------------------------------
# Signal 2 — Shannon entropy anomaly
# ---------------------------------------------------------------------------


def _shannon(sample: str) -> float:
    if not sample:
        return 0.0
    total = len(sample)
    return -sum((count / total) * math.log2(count / total) for count in Counter(sample).values())


def _looks_like_base64(token: str) -> bool:
    if len(token) < 32 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", token):
        return False
    has_upper = any(ch.isupper() for ch in token)
    has_lower = any(ch.islower() for ch in token)
    has_digit = any(ch.isdigit() for ch in token)
    has_symbol = any(ch in "+/=" for ch in token)
    case_flips = 0
    for index in range(len(token) - 1):
        left, right = token[index], token[index + 1]
        if left.isalpha() and right.isalpha() and left.isupper() != right.isupper():
            case_flips += 1
    return has_upper and has_lower and (has_digit or has_symbol or case_flips > len(token) * 0.12)


def _base64_score(text: str) -> float:
    best = 0.0
    for match in _RE_B64.finditer(text):
        token = match.group(0)
        if _looks_like_base64(token):
            best = max(best, min(1.0, len(token) / 48.0))
    return best


def _unicode_obfuscation_score(text: str) -> float:
    if not text:
        return 0.0
    odd = 0
    for ch in text:
        if ch in _OBFUSCATION_CHARS or unicodedata.category(ch) == "Cf":
            odd += 1
    if odd == 0:
        return 0.0
    # A few inserted format characters are enough; natural prose has none.
    return min(1.0, odd / 3.0)


def _window_entropy_score(text: str) -> float:
    if len(text) < _ENTROPY_WINDOW:
        return 0.0
    anomalies: list[float] = []
    last = len(text) - _ENTROPY_WINDOW
    for start in range(0, last + 1, _ENTROPY_STEP):
        window = text[start : start + _ENTROPY_WINDOW]
        entropy = _shannon(window)
        spaces = window.count(" ") / _ENTROPY_WINDOW
        if entropy >= _ENTROPY_HIGH and spaces < 0.08:
            anomalies.append(min(1.0, (entropy - (_ENTROPY_HIGH - 0.4)) / 1.3))
        else:
            anomalies.append(0.0)
    if not anomalies:
        return 0.0
    return sum(anomalies) / len(anomalies)


def _entropy_score(text: str) -> float:
    if not text:
        return 0.0
    return min(
        1.0,
        max(_window_entropy_score(text), _base64_score(text), _unicode_obfuscation_score(text)),
    )


# ---------------------------------------------------------------------------
# Signal 3 — TF-IDF cosine similarity
# ---------------------------------------------------------------------------


def _text_chunks(text: str, size: int = 480, step: int = 240) -> list[str]:
    stripped = text.strip()
    if not stripped:
        return []
    if len(stripped) <= size:
        return [stripped]
    chunks: list[str] = []
    for start in range(0, len(stripped), step):
        piece = stripped[start : start + size].strip()
        if piece:
            chunks.append(piece)
        if start + size >= len(stripped):
            break
    return chunks or [stripped]


def _tfidf_score(text: str) -> float:
    if not text.strip():
        return 0.0
    vectorizer, matrix = _load_tfidf()
    chunks = _text_chunks(text)
    vectors = vectorizer.transform(chunks)
    similarities = cosine_similarity(vectors, matrix)
    if similarities.size == 0:
        return 0.0
    score = float(similarities.max())
    if math.isnan(score) or score < 0.0:
        return 0.0
    return min(1.0, score)


# ---------------------------------------------------------------------------
# Signal 4 — structural context
# ---------------------------------------------------------------------------


def _has_html_comment(text: str) -> bool:
    return any(body.strip() for body in _RE_HTML_COMMENT.findall(text))


def _has_image_payload(text: str) -> bool:
    for match in _RE_MD_IMAGE.finditer(text):
        alt = match.group("alt").strip()
        dest = match.group("dest")
        title_match = re.search(r"""["']([^"']+)["']\s*$""", dest)
        title = title_match.group(1).strip() if title_match else ""
        if title:
            return True
        if len(alt) >= 48 or _fallback_sentence_imperative(alt):
            return True
    return False


def _tail_payload(text: str) -> bool:
    if len(text) < _TAIL_MIN_CHARS:
        return False
    tail_len = max(100, len(text) // 8)
    tail = text[-tail_len:]
    head = text[:-tail_len]
    if not _RE_TAIL_PAYLOAD.search(tail):
        return False
    return _RE_TAIL_PAYLOAD.search(head) is None


def _structural_score(text: str) -> float:
    if not text:
        return 0.0
    flags = (
        _has_html_comment(text),
        bool(_RE_MD_COMMENT.search(text)),
        _has_image_payload(text),
        _tail_payload(text),
    )
    if not any(flags):
        return 0.0
    # One hiding channel is a full structural hit; extra channels stay at 1.0.
    return 1.0


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _risk_level(score: float) -> tuple[bool, RiskLevel]:
    if score >= THRESHOLD_MALICIOUS:
        return True, RiskLevel.MALICIOUS
    if score >= THRESHOLD_SUSPICIOUS:
        return True, RiskLevel.SUSPICIOUS
    return False, RiskLevel.SAFE


def _coerce_source(source: str) -> ContentSource:
    try:
        return ContentSource(source.strip().upper())
    except ValueError:
        return ContentSource.WEB_FETCH


def _explanation(pos: float, tfidf: float, entropy: float, structural: float, level: RiskLevel) -> str:
    return (
        f"[Composite L2] POS: {pos:.2f}, TFIDF: {tfidf:.2f}, "
        f"Entropy: {entropy:.2f}, Structural: {structural:.2f} -> {level.value}"
    )


def _patterns(pos: float, entropy: float, tfidf: float, structural: float) -> list[str]:
    fired: list[str] = []
    if pos >= 0.25:
        fired.append("pos_imperative")
    if entropy >= 0.25:
        fired.append("entropy_anomaly")
    if tfidf >= 0.25:
        fired.append("tfidf_similarity")
    if structural >= 0.25:
        fired.append("structural_context")
    return fired


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class L2CompositeDetector(BaseDetector):
    """Deterministic composite L2 detector.

    ``scan`` is async and accepts raw text so MCP handlers can call it
    without building an :class:`~sieve.core.types.UntrustedContent` first.
    The spaCy pipeline and the TF-IDF matrix are fitted once, at
    initialisation, and are not mutated during scoring.
    """

    name = "l2_composite"

    def __init__(self) -> None:
        self._nlp = _load_nlp()
        _load_tfidf()

    async def scan(self, text: str, source: str = "unknown") -> DetectionResult:
        """Score *text* and return a :class:`~sieve.core.types.DetectionResult`.

        Args:
            text: Raw untrusted text.
            source: Origin label. Stored on the result; it does not affect the score.
        """
        pos = _pos_score(text, self._nlp)
        entropy = _entropy_score(text)
        tfidf = _tfidf_score(text)
        structural = _structural_score(text)

        risk = (
            WEIGHT_POS * pos
            + WEIGHT_ENTROPY * entropy
            + WEIGHT_TFIDF * tfidf
            + WEIGHT_STRUCTURAL * structural
        )
        risk = round(min(1.0, max(0.0, risk)), 4)
        is_flagged, level = _risk_level(risk)

        content = UntrustedContent(
            source=_coerce_source(source),
            raw_text=text,
            metadata={"source_label": source},
        )
        return self._make_result(
            content,
            is_flagged=is_flagged,
            risk_level=level,
            detected_patterns=_patterns(pos, entropy, tfidf, structural),
            raw_score=risk,
            explanation=_explanation(pos, tfidf, entropy, structural, level),
        )
