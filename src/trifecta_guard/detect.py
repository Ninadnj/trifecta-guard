"""Injection detectors.

:class:`HeuristicDetector` is dependency-free and fast (well under a millisecond per KB). It is
the default. :class:`TransformersDetector` wraps a local Hugging Face classifier (optional extra
``[ml]``); :class:`Ensemble` combines detectors. Every detector returns a :class:`Verdict` whose
``findings`` say *why*, so decisions can be audited and explained to the user.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import asdict, dataclass, field
from typing import Iterable, Protocol

from . import normalize
from .rules import ACTION_CATEGORIES, DISCUSSION_MARKERS, NEGATABLE, NEGATION, QUOTE_CHARS, RULES, Rule

DEFAULT_THRESHOLD = 1.0

DISCUSSION_DAMPING = 0.35
NEGATION_DAMPING = 0.2
SAME_CATEGORY_BONUS = 0.15
CATEGORY_CAP = 1.2
CHANNEL_ACTION_SYNERGY = 0.3
# "Channel" signals: the text talks *to the model* or hides itself. With an action they are damning.
CHANNEL_CATEGORIES = frozenset({"addressing", "fake_delimiter", "hidden", "encoded"})
SECRECY_ACTION_SYNERGY = 0.3
HIDDEN_PAYLOAD_WEIGHT = 0.8
INVISIBLE_RUN_WEIGHT = 0.3
ENCODED_PAYLOAD_WEIGHT = 0.3

_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass
class Finding:
    rule: str
    category: str
    weight: float
    start: int | None
    end: int | None
    excerpt: str
    layer: str = "text"  # text | folded | hidden | encoded | model
    damped: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    score: float
    flagged: bool
    threshold: float
    findings: list[Finding] = field(default_factory=list)
    categories: dict[str, float] = field(default_factory=dict)
    hidden_payloads: list[str] = field(default_factory=list)
    invisible_removed: int = 0
    detector: str = "heuristic"

    @property
    def rules(self) -> list[str]:
        return sorted({f.rule for f in self.findings})

    def summary(self) -> str:
        if not self.findings and not self.invisible_removed:
            return f"clean (score {self.score:.2f})"
        top = sorted(self.findings, key=lambda f: -f.weight)[:4]
        parts = ", ".join(f"{f.rule}" for f in top)
        extra = f"; {self.invisible_removed} invisible chars" if self.invisible_removed else ""
        return f"score {self.score:.2f}/{self.threshold:.2f} [{parts}{extra}]"

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 3),
            "flagged": self.flagged,
            "threshold": self.threshold,
            "detector": self.detector,
            "categories": {k: round(v, 3) for k, v in self.categories.items()},
            "rules": self.rules,
            "findings": [f.to_dict() for f in self.findings],
            "hidden_payloads": self.hidden_payloads,
            "invisible_removed": self.invisible_removed,
        }


class Detector(Protocol):
    name: str

    def scan(self, text: str) -> Verdict: ...


def _excerpt(text: str, start: int, end: int, pad: int = 30) -> str:
    a, b = max(0, start - pad), min(len(text), end + pad)
    s = text[a:b].replace("\n", " ")
    return ("…" if a else "") + s + ("…" if b < len(text) else "")


def _damping(text: str, start: int, category: str) -> tuple[float, str | None]:
    before = text[max(0, start - 100):start]
    # Only look within the current sentence-ish window for discussion markers.
    window = re.split(r"(?<=[.!?])\s+|\n\s*\n", before)[-1] if before else ""
    if category in NEGATABLE and NEGATION.search(text[max(0, start - 30):start]):
        return NEGATION_DAMPING, "negated"
    if DISCUSSION_MARKERS.search(window):
        return DISCUSSION_DAMPING, "discussion"
    if start > 0 and text[start - 1] in QUOTE_CHARS or (start > 1 and text[start - 2] in QUOTE_CHARS and text[start - 1] == " "):
        return DISCUSSION_DAMPING, "quoted"
    return 1.0, None


def _match_rules(text: str, rules: Iterable[Rule], layer: str, keep_spans: bool) -> list[Finding]:
    out: list[Finding] = []
    for rule in rules:
        for m in rule.pattern.finditer(text):
            factor, why = _damping(text, m.start(), rule.category)
            out.append(
                Finding(
                    rule=rule.id,
                    category=rule.category,
                    weight=round(rule.weight * factor, 4),
                    start=m.start() if keep_spans else None,
                    end=m.end() if keep_spans else None,
                    excerpt=_excerpt(text, m.start(), m.end()),
                    layer=layer,
                    damped=why,
                )
            )
    return out


def score_findings(findings: list[Finding]) -> tuple[float, dict[str, float]]:
    """Category-max scoring with small bonuses for breadth and for dangerous combinations."""
    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)
    cats: dict[str, float] = {}
    for cat, fs in by_cat.items():
        best = max(f.weight for f in fs)
        distinct = {f.rule for f in fs if f.weight >= 0.2}
        cats[cat] = min(CATEGORY_CAP, best + SAME_CATEGORY_BONUS * max(0, len(distinct) - 1))
    score = sum(cats.values())
    strong = {c for c, v in cats.items() if v >= 0.3}
    action = strong & ACTION_CATEGORIES
    if (strong & CHANNEL_CATEGORIES) and action:
        score += CHANNEL_ACTION_SYNERGY
    if "secrecy" in strong and (action - {"secrecy"}):
        score += SECRECY_ACTION_SYNERGY
    return score, cats


def _decode_b64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        s = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in s)
    if not s or printable / len(s) < 0.95 or len(re.findall(r"[A-Za-z]{2,}", s)) < 3:
        return None
    return s


class HeuristicDetector:
    """Rule-based detector. Scans the cleaned text, its NFKC fold, hidden tag payloads and
    base64 blobs that decode to natural language."""

    name = "heuristic"

    def __init__(self, threshold: float = DEFAULT_THRESHOLD, rules: Iterable[Rule] = RULES):
        self.threshold = threshold
        self.rules = tuple(rules)

    def scan(self, text: str, _depth: int = 0) -> Verdict:
        norm = normalize.clean(text or "")
        cleaned = norm.text
        findings = _match_rules(cleaned, self.rules, "text", keep_spans=True)

        folded = normalize.fold(cleaned)
        if folded != cleaned:
            seen = {f.rule for f in findings}
            for f in _match_rules(folded, self.rules, "folded", keep_spans=False):
                if f.rule not in seen:
                    findings.append(f)
                    seen.add(f.rule)

        for payload in norm.hidden_payloads:
            findings.append(
                Finding("hidden.unicode_tags", "hidden", HIDDEN_PAYLOAD_WEIGHT, None, None,
                        payload[:120], layer="hidden")
            )
            if _depth == 0:
                inner = self.scan(payload, _depth=1)
                for f in inner.findings:
                    f.layer, f.start, f.end = "hidden", None, None
                    findings.append(f)
        zw = norm.removed_by_kind.get("zero_width", 0) + norm.removed_by_kind.get("bidi", 0)
        if zw >= 3:
            findings.append(
                Finding("hidden.invisible_chars", "hidden", INVISIBLE_RUN_WEIGHT, None, None,
                        f"{zw} zero-width/bidi characters", layer="hidden")
            )

        if _depth == 0:
            for m in _B64.finditer(cleaned):
                decoded = _decode_b64(m.group(0))
                if not decoded:
                    continue
                inner = self.scan(decoded, _depth=1)
                if inner.findings:
                    findings.append(
                        Finding("encoded.base64_payload", "encoded", ENCODED_PAYLOAD_WEIGHT, m.start(), m.end(),
                                decoded[:120], layer="encoded")
                    )
                    for f in inner.findings:
                        f.layer, f.start, f.end = "encoded", m.start(), m.end()
                        findings.append(f)

        score, cats = score_findings(findings)
        return Verdict(
            score=round(score, 4),
            flagged=score >= self.threshold,
            threshold=self.threshold,
            findings=findings,
            categories=cats,
            hidden_payloads=list(norm.hidden_payloads),
            invisible_removed=norm.removed,
            detector=self.name,
        )


class TransformersDetector:
    """Local Hugging Face text classifier (``pip install trifecta-guard[ml]``).

    Defaults to ``protectai/deberta-v3-base-prompt-injection-v2``. The model is downloaded on
    first use. Long inputs are scanned in overlapping windows and the max score is kept. Not run
    in CI; benchmark it on your own traffic before relying on it.
    """

    name = "transformers"

    def __init__(self, model: str = "protectai/deberta-v3-base-prompt-injection-v2", threshold: float = 0.9,
                 injection_label: str = "INJECTION", pipeline=None, window_chars: int = 1500):
        if pipeline is None:  # pragma: no cover - exercised only with the optional extra
            from transformers import pipeline as hf_pipeline

            pipeline = hf_pipeline("text-classification", model=model, truncation=True, max_length=512)
        self._pipe = pipeline
        self.threshold = threshold
        self.injection_label = injection_label
        self.window = window_chars

    def scan(self, text: str) -> Verdict:
        cleaned = normalize.clean(text or "").text
        chunks = [cleaned[i:i + self.window] for i in range(0, max(len(cleaned), 1), self.window * 3 // 4)] or [""]
        best = 0.0
        for res in self._pipe(chunks):
            res = res[0] if isinstance(res, list) else res
            if res.get("label") == self.injection_label:
                best = max(best, float(res.get("score", 0.0)))
        flagged = best >= self.threshold
        findings = [Finding("model.classifier", "model", best, None, None, f"p(injection)={best:.3f}", layer="model")]
        return Verdict(score=best, flagged=flagged, threshold=self.threshold,
                       findings=findings if best > 0 else [], categories={"model": best}, detector=self.name)


class Ensemble:
    """Flag when any member flags (``mode='any'``) or all members flag (``mode='all'``)."""

    name = "ensemble"

    def __init__(self, detectors: list, mode: str = "any"):
        if mode not in {"any", "all"}:
            raise ValueError("mode must be 'any' or 'all'")
        self.detectors = detectors
        self.mode = mode

    def scan(self, text: str) -> Verdict:
        verdicts = [d.scan(text) for d in self.detectors]
        flags = [v.flagged for v in verdicts]
        flagged = any(flags) if self.mode == "any" else all(flags)
        primary = verdicts[0]
        findings = [f for v in verdicts for f in v.findings]
        cats: dict[str, float] = {}
        for v in verdicts:
            cats.update(v.categories)
        return Verdict(
            score=max(v.score / v.threshold for v in verdicts),
            flagged=flagged,
            threshold=1.0,
            findings=findings,
            categories=cats,
            hidden_payloads=primary.hidden_payloads,
            invisible_removed=primary.invisible_removed,
            detector="+".join(d.name for d in self.detectors),
        )


_default = HeuristicDetector()


def scan(text: str, threshold: float | None = None) -> Verdict:
    """Scan ``text`` with the default heuristic detector."""
    if threshold is None:
        return _default.scan(text)
    return HeuristicDetector(threshold=threshold).scan(text)
