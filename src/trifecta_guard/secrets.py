"""Recognise credentials and private data inside outgoing tool arguments."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from urllib.parse import unquote_plus

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("assignment", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
        r"\s*[=:]\s*['\"]?[^\s'\"&]{8,}")),
)

_B64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
# Same tokenizer on both sides (private text and outgoing payload), so separators like = / : ? &
# never glue a secret to its neighbours differently.
_SECRETISH = re.compile(r"[A-Za-z0-9_\-+.]{16,}")
_WORD = re.compile(r"[a-z0-9]+")
SHINGLE = 8


def payload_variants(text: str) -> list[str]:
    """The text plus decodings an exfiltrating agent might use (URL-encoding, base64)."""
    variants = [text]
    un = unquote_plus(text)
    if un != text:
        variants.append(un)
    for blob in _B64_BLOB.findall(un):
        try:
            raw = base64.b64decode(blob.replace("-", "+").replace("_", "/") + "=" * (-len(blob) % 4), validate=True)
            dec = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if dec and sum(c.isprintable() or c.isspace() for c in dec) / len(dec) > 0.9:
            variants.append(dec)
    return variants


def find_secrets(text: str) -> list[str]:
    """Names of credential patterns present in ``text`` or its decodings."""
    found: set[str] = set()
    for v in payload_variants(text):
        for name, pat in SECRET_PATTERNS:
            if pat.search(v):
                found.add(name)
    return sorted(found)


def _h(salt: str, s: str) -> str:
    return hashlib.sha256((salt + "\x00" + s).encode("utf-8")).hexdigest()[:20]


def _is_secretish(tok: str) -> bool:
    has_digit = any(c.isdigit() for c in tok)
    mixed_case = any(c.islower() for c in tok) and any(c.isupper() for c in tok)
    return has_digit or mixed_case


_ASSIGN = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*[=:]\s*[\"']?([^\s\"'#]{6,})", re.MULTILINE)
_PIECE = re.compile(r"[A-Za-z0-9_\-+.]{6,}")


def _value_piece(tok: str) -> bool:
    return any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok)


def fingerprints(text: str, salt: str, side: str = "private") -> set[str]:
    """Salted hashes of what could identify private data in ``text``. Only hashes are stored.

    * ``t``: secret-looking tokens (16+ chars, digits or mixed case);
    * ``s``: 8-word shingles, for prose (emails, documents);
    * ``v``: short credential values. On the private side only values of ``KEY=value`` lines
      (and their ``user:pass@host`` pieces) are hashed; on the payload side every letter+digit
      piece of 6+ chars is, so a short database password in a URL still matches.
    """
    fps: set[str] = set()
    for tok in _SECRETISH.findall(text):
        tok = tok.strip(".")
        if len(tok) >= 16 and _is_secretish(tok):
            fps.add("t" + _h(salt, tok))
    words = _WORD.findall(text.lower())
    for i in range(0, max(0, len(words) - SHINGLE + 1)):
        fps.add("s" + _h(salt, " ".join(words[i:i + SHINGLE])))
    if side == "private":
        for value in _ASSIGN.findall(text):
            for piece in _PIECE.findall(value):
                if _value_piece(piece):
                    fps.add("v" + _h(salt, piece.strip(".")))
    else:
        for piece in _PIECE.findall(text):
            if _value_piece(piece):
                fps.add("v" + _h(salt, piece.strip(".")))
    return fps


def matches_private(payload: str, salt: str, known: set[str]) -> bool:
    if not known:
        return False
    for v in payload_variants(payload):
        if fingerprints(v, salt, side="payload") & known:
            return True
    return False
