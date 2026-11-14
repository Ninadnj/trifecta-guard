"""Load eval datasets, building evasive payloads from the readable `hidden` + `transform` fields."""

from __future__ import annotations

import base64
import json
from pathlib import Path

DATASETS = Path(__file__).parent / "datasets"


def to_tags(s: str) -> str:
    """Encode ASCII as invisible Unicode tag characters."""
    return "".join(chr(0xE0000 + ord(c)) for c in s if 0x20 <= ord(c) <= 0x7E)


def to_zero_width(s: str) -> str:
    return "​".join(s)


TRANSFORMS = {
    "tags": to_tags,
    "zw": to_zero_width,
    "b64": lambda s: base64.b64encode(s.encode()).decode(),
}


def load(name: str) -> list[dict]:
    rows = []
    for line in (DATASETS / f"{name}.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if "hidden" in row:
            row["text"] = row["text"].replace("{hidden}", TRANSFORMS[row["transform"]](row["hidden"]))
        rows.append(row)
    return rows
