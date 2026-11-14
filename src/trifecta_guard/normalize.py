"""Unicode hygiene: find and remove characters a human cannot see but a model can read.

Three families matter for agents:

* Unicode *tag* characters (U+E0000-U+E007F). Each one mirrors an ASCII character, so a whole
  sentence can ride invisibly inside an innocent paragraph ("ASCII smuggling"). The only
  legitimate use is emoji flag sequences that start with U+1F3F4 (e.g. the Scottish flag).
* Zero-width and formatting characters (ZWSP, ZWJ, word joiner, soft hyphen, BOM...). Used to
  split trigger words ("ig​nore") so keyword filters miss them.
* Bidirectional overrides (U+202A-U+202E, U+2066-U+2069), which reorder what a reviewer sees.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

_TAG_START, _TAG_END = 0xE0000, 0xE007F
_BLACK_FLAG = "\U0001f3f4"

_ZERO_WIDTH = {
    0x00AD,  # soft hyphen
    0x180E,  # mongolian vowel separator
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,  # zwsp, zwnj, zwj, lrm, rlm
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064,  # word joiner, invisible operators
    0xFEFF,  # bom / zwnbsp
}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_VARIATION = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))

_ZWJ = 0x200D
_VS16 = 0xFE0F


def _is_emoji(ch: str) -> bool:
    cp = ord(ch)
    return cp >= 0x2190 and unicodedata.category(ch) in ("So", "Sk")


@dataclass
class Normalized:
    """Result of :func:`clean`."""

    text: str
    """Input with invisible characters removed (positions refer to this string)."""
    hidden_payloads: list[str] = field(default_factory=list)
    """ASCII text decoded from runs of Unicode tag characters."""
    removed: int = 0
    """How many invisible characters were removed in total."""
    removed_by_kind: dict[str, int] = field(default_factory=dict)


def clean(text: str) -> Normalized:
    """Remove invisible characters and decode tag-character payloads.

    Emoji glue is preserved where it is plausibly legitimate: ZWJ between two emoji, VS16 after an
    emoji, and tag runs that follow the black-flag emoji (subdivision flags).
    """
    out: list[str] = []
    payloads: list[str] = []
    kinds: dict[str, int] = {}
    run: list[str] = []
    run_is_flag = False

    def flush_run() -> None:
        nonlocal run, run_is_flag
        if run:
            decoded = "".join(run).strip()
            if decoded and not run_is_flag:
                payloads.append(decoded)
        run = []
        run_is_flag = False

    chars = text
    n = len(chars)
    for i, ch in enumerate(chars):
        cp = ord(ch)
        if _TAG_START <= cp <= _TAG_END:
            if not run:
                run_is_flag = bool(out) and out[-1] == _BLACK_FLAG
            if run_is_flag:
                out.append(ch)  # keep flag sequences intact
            else:
                kinds["tag"] = kinds.get("tag", 0) + 1
            if 0xE0020 <= cp <= 0xE007E:
                run.append(chr(cp - 0xE0000))
            continue
        flush_run()
        if cp == _ZWJ:
            prev_e = bool(out) and _is_emoji(out[-1])
            next_e = i + 1 < n and _is_emoji(chars[i + 1])
            if prev_e and next_e:
                out.append(ch)
                continue
            kinds["zero_width"] = kinds.get("zero_width", 0) + 1
            continue
        if cp == _VS16 and out and _is_emoji(out[-1]):
            out.append(ch)
            continue
        if cp in _ZERO_WIDTH:
            kinds["zero_width"] = kinds.get("zero_width", 0) + 1
            continue
        if cp in _BIDI:
            kinds["bidi"] = kinds.get("bidi", 0) + 1
            continue
        if cp in _VARIATION:
            kinds["variation_selector"] = kinds.get("variation_selector", 0) + 1
            continue
        out.append(ch)
    flush_run()
    return Normalized(
        text="".join(out),
        hidden_payloads=payloads,
        removed=sum(kinds.values()),
        removed_by_kind=kinds,
    )


_WS = re.compile(r"[ \t  -   　]+")


def fold(text: str) -> str:
    """NFKC-fold (fullwidth letters, ligatures, math alphanumerics) and squeeze spaces.

    Used for a second detection pass only: positions are not preserved.
    """
    return _WS.sub(" ", unicodedata.normalize("NFKC", text))
