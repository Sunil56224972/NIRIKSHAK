"""Near-duplicate detection for scam templates (same script, different links / numbers)."""
from __future__ import annotations

import re
import zlib

MAX_SHINGLES = 256


def normalise(text: str) -> str:
    t = text.lower()
    t = re.sub(r"(?:https?://|www\.)\S+", " url ", t)
    t = re.sub(r"\b[\w.\-]+@[\w.\-]+\b", " handle ", t)
    t = re.sub(r"\d+", "0", t)
    t = re.sub(r"[^\w\u0900-\u097f]+", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def shingles(text: str, k: int = 4) -> list[int]:
    words = normalise(text).split()
    if len(words) < k:
        grams = {" ".join(words)} if words else set()
    else:
        grams = {" ".join(words[i:i + k]) for i in range(len(words) - k + 1)}
    hashes = sorted({zlib.crc32(g.encode()) for g in grams})
    return hashes[:MAX_SHINGLES]   # bottom-k sketch keeps the estimate unbiased


def jaccard(a: list[int], b: list[int]) -> float:
    if not a or not b:
        return 0.0
    sa, sb = set(a), set(b)
    # compare on the union's bottom-k to stay consistent with the sketch
    union = sorted(sa | sb)[:MAX_SHINGLES]
    if not union:
        return 0.0
    inter = sum(1 for h in union if h in sa and h in sb)
    return inter / len(union)
