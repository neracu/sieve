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
``risk = 0.30*POS + 0.05*Entropy + 0.60*TFIDF + 0.05*Structural``

  risk ≥ 0.50  → MALICIOUS (flagged)
  risk ≥ 0.30  → SUSPICIOUS (flagged)
  risk <  0.30 → SAFE
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections import Counter
from functools import lru_cache
from pathlib import Path

from sieve.core.logger import get_logger
from sieve.core.types import DetectionResult, RiskLevel, UntrustedContent
from sieve.detectors.base import BaseDetector

log = get_logger(__name__)

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
# Calibrated 2026-09-26 against tests/fixtures/calibration.json
# (9 injection fixtures, malicious=1, and 26 legitimate maintainer
# sentences and paragraphs, malicious=0).
# Sweep: each weight is a multiple of 0.05, the four weights sum to 1.0,
# and none is below 0.05. Chosen to put every injection fixture at or
# above the MALICIOUS threshold and to minimise false positives on the
# legitimate set.
# False-positive rate on that legitimate set: 0/26 (0.00).
# POS is not simply down-weighted. Unless the text matches the L1
# injection-phrase vocabulary, POS cannot contribute more than
# POS_CONTRIBUTION_CAP. At these weights the three audit sentences
# ("Please review this PR", "Run the tests before merging",
# "Check the changelog and update the docs.") score 0.30 without that
# cap and 0.25 with it.

WEIGHT_POS: float = 0.30
WEIGHT_ENTROPY: float = 0.05
WEIGHT_TFIDF: float = 0.60
WEIGHT_STRUCTURAL: float = 0.05

# Without an L1 injection-phrase match, WEIGHT_POS * POS stays at or below this.
POS_CONTRIBUTION_CAP: float = 0.25

THRESHOLD_MALICIOUS: float = 0.50
THRESHOLD_SUSPICIOUS: float = 0.30

# A saturated window-entropy hit is a payload by itself. WEIGHT_ENTROPY stays
# at the calibrated 0.05; this floor is what keeps a pure-entropy blob from
# scoring SAFE. It sits above SUSPICIOUS (0.30) and below MALICIOUS (0.50).
ENTROPY_SIGNAL_FLOOR: float = 0.35

_FIXTURE_PATH = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "injections.json"

# Entropy windows. Natural English sits near 4 bits/char and contains spaces.
# A 276-character base64 blob of ordinary prose measures about 4.77–4.92
# bits/char on 64-character windows (measured 2026-09-26). The same-length
# English prose tops out near 4.23. The cutoff is the gap between those bands.
# The score uses the hottest window. The ramp reaches 1.0 at 4.85 so a
# base64 blob (measured max about 4.92) is a full hit, while badge URLs
# in ordinary READMEs (measured max about 4.79) stay below that.
_ENTROPY_WINDOW = 64
_ENTROPY_STEP = 32
_ENTROPY_HIGH = 4.60
_ENTROPY_RAMP = 0.65

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
        "review",
        "reset",
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
_RE_MD_LINK = re.compile(r"(?<!!)\[(?P<text>[^\]]*)\]\(\s*(?P<dest>[^)]*)\)")
_RE_MD_TITLE = re.compile(r"""["']([^"']+)["']\s*$""")
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


_POS_FALLBACK_REASON = ""


def _use_pos_fallback(reason: str) -> None:
    """Record that POS tagging is on the regex verb list, and say so."""
    global _POS_FALLBACK_REASON
    _POS_FALLBACK_REASON = f"{reason} L2 POS is using the regex verb list."
    log.error(_POS_FALLBACK_REASON)


@lru_cache(maxsize=1)
def _load_nlp():
    """Load ``en_core_web_sm``.

    A missing library or model is logged and the regex verb list is used.
    The failure is recorded on ``_POS_FALLBACK_REASON`` so a scan cannot
    drop to that list without saying so.
    """
    global _POS_FALLBACK_REASON
    if spacy is None:
        _use_pos_fallback("spaCy is not installed.")
        return None
    try:
        nlp = spacy.load("en_core_web_sm", disable=["ner", "lemmatizer"])
    except Exception as exc:
        _use_pos_fallback(f"spaCy model en_core_web_sm failed to load ({exc}).")
        return None
    _POS_FALLBACK_REASON = ""
    return nlp


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
    # Bigrams only. Unigrams such as "run" and "mode" are shared with
    # ordinary maintainer text and were inflating cosine similarity.
    # The corpus itself remains the nine injection fixtures.
    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        ngram_range=(2, 2),
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


def _matches_injection_lexicon(text: str) -> bool:
    """True when *text* hits the L1 injection-phrase vocabulary.

    The check uses :data:`sieve.detectors.l1_heuristics.INJECTION_PATTERNS`,
    the same phrase list L1 scores. A lone imperative verb is not enough.
    """
    from sieve.detectors.l1_heuristics import INJECTION_PATTERNS

    return any(pattern.search(text) for pattern, _label, _malicious in INJECTION_PATTERNS)


def _cap_pos_contribution(pos: float, text: str) -> float:
    """Keep an unmatched imperative from adding more than ``POS_CONTRIBUTION_CAP``.

    Real injections that match the L1 phrase vocabulary keep their full POS
    ratio. Benign orders such as "Please review this PR" do not.
    """
    if pos <= 0.0 or _matches_injection_lexicon(text) or WEIGHT_POS <= 0.0:
        return pos
    return min(pos, POS_CONTRIBUTION_CAP / WEIGHT_POS)


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


def _window_entropy_details(text: str) -> tuple[float, bool, float]:
    """Return ``(normalized score, anomaly flagged, max Shannon bits)``.

    ``anomaly`` is true when a low-space, base64-alphabet window reaches
    :data:`_ENTROPY_HIGH` (4.60). The normalized score is a ramp that only
    hits 1.0 near 4.85, so the anomaly flag is the floor condition.
    """
    if len(text) < _ENTROPY_WINDOW:
        return 0.0, False, 0.0
    hottest = 0.0
    max_bits = 0.0
    anomaly = False
    last = len(text) - _ENTROPY_WINDOW
    for start in range(0, last + 1, _ENTROPY_STEP):
        window = text[start : start + _ENTROPY_WINDOW]
        entropy = _shannon(window)
        max_bits = max(max_bits, entropy)
        spaces = window.count(" ") / _ENTROPY_WINDOW
        alphabet = sum(ch.isalnum() or ch in "+/=" for ch in window) / _ENTROPY_WINDOW
        # Badge URLs are high-entropy too, but they are full of ":", "/", and
        # brackets. A base64 window is almost entirely the base64 alphabet.
        if entropy >= _ENTROPY_HIGH and spaces < 0.08 and alphabet >= 0.95:
            anomaly = True
            hottest = max(hottest, min(1.0, (entropy - (_ENTROPY_HIGH - 0.4)) / _ENTROPY_RAMP))
    return hottest, anomaly, max_bits


def _window_entropy_score(text: str) -> float:
    """Score the highest-entropy low-space window in *text*.

    Aggregation is the maximum window, not the mean. A short base64 blob
    surrounded by ordinary sentences used to be diluted to zero.
    """
    return _window_entropy_details(text)[0]


def _entropy_anomaly(text: str) -> bool:
    """True when max-window entropy crossed the existing 4.60 cutoff."""
    return _window_entropy_details(text)[1]


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


def _markdown_title(dest: str) -> str:
    match = _RE_MD_TITLE.search(dest)
    return match.group(1).strip() if match else ""


def _instruction_text(text: str) -> bool:
    """True when *text* matches an injection phrase or an instruction verb."""
    cleaned = "".join(ch for ch in text if ch not in _OBFUSCATION_CHARS)
    if _matches_injection_lexicon(cleaned):
        return True
    return bool(_RE_TAIL_PAYLOAD.search(cleaned)) or _fallback_sentence_imperative(cleaned)


def _has_html_comment(text: str) -> bool:
    """A comment scores only when its body matches an injection phrase."""
    for body in _RE_HTML_COMMENT.findall(text):
        if body.strip() and _instruction_text(body):
            return True
    return False


def _has_image_payload(text: str) -> bool:
    for match in _RE_MD_IMAGE.finditer(text):
        alt = match.group("alt").strip()
        title = _markdown_title(match.group("dest"))
        if title and _instruction_text(title):
            return True
        if _instruction_text(alt) or len(alt) >= 48 or _fallback_sentence_imperative(alt):
            return True
    return False


def _has_link_payload(text: str) -> bool:
    """Scan Markdown link titles the same way image titles are scanned."""
    for match in _RE_MD_LINK.finditer(text):
        title = _markdown_title(match.group("dest"))
        if title and _instruction_text(title):
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
        _has_link_payload(text),
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

    ``scan`` matches :meth:`L1HeuristicDetector.scan`: it is synchronous and
    takes :class:`~sieve.core.types.UntrustedContent`. spaCy and the TF-IDF
    matrix are loaded on the first call and then reused.
    """

    name = "l2_composite"

    def __init__(self) -> None:
        self._nlp = None
        self._models_ready = False

    def _ensure_ready(self) -> None:
        """Load spaCy and fit TF-IDF once, synchronously, on first use."""
        if self._models_ready:
            return
        self._nlp = _load_nlp()
        _load_tfidf()
        self._models_ready = True

    def scan(self, content: UntrustedContent) -> DetectionResult:
        """Score *content* and return a :class:`~sieve.core.types.DetectionResult`."""
        self._ensure_ready()
        text = content.raw_text
        pos = _cap_pos_contribution(_pos_score(text, self._nlp), text)
        window_entropy, entropy_anomaly, _max_bits = _window_entropy_details(text)
        entropy = 0.0 if not text else min(
            1.0,
            max(window_entropy, _base64_score(text), _unicode_obfuscation_score(text)),
        )
        tfidf = _tfidf_score(text)
        structural = _structural_score(text)

        risk = (
            WEIGHT_POS * pos
            + WEIGHT_ENTROPY * entropy
            + WEIGHT_TFIDF * tfidf
            + WEIGHT_STRUCTURAL * structural
        )
        # The ramp reaches 1.0 only near 4.85 bits. Real base64 clears the
        # 4.60 anomaly cutoff and still lands just under 1.0, so the floor
        # follows the anomaly flag, not an exact score of 1.0.
        if entropy_anomaly:
            risk = max(risk, ENTROPY_SIGNAL_FLOOR)
        # A confirmed tail payload is a hiding channel. Structural weight alone
        # is too small to move a long document off SAFE.
        if _tail_payload(text):
            risk = max(risk, THRESHOLD_MALICIOUS)
        risk = round(min(1.0, max(0.0, risk)), 4)
        is_flagged, level = _risk_level(risk)
        explanation = _explanation(pos, tfidf, entropy, structural, level)
        if _POS_FALLBACK_REASON:
            explanation = f"{explanation} [{_POS_FALLBACK_REASON}]"

        return self._make_result(
            content,
            is_flagged=is_flagged,
            risk_level=level,
            detected_patterns=_patterns(pos, entropy, tfidf, structural),
            raw_score=risk,
            explanation=explanation,
        )
