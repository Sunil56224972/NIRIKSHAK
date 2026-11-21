"""Explainable scoring. Every point on the score is backed by a named indicator."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

HIGH_AT = 60
MEDIUM_AT = 30


@dataclass
class Indicator:
    code: str
    title: str
    detail: str
    weight: int
    group: str            # content | domain | network | app | intel | correlation
    evidence: str = ""


@dataclass
class Findings:
    items: list[Indicator] = field(default_factory=list)
    floor: int = 0        # minimum score forced by decisive intel (blocklist hit etc.)
    floor_reason: str = ""

    def add(self, code: str, title: str, detail: str, weight: int, group: str, evidence: str = "") -> None:
        if any(i.code == code and i.evidence == evidence for i in self.items):
            return
        self.items.append(Indicator(code, title, detail, weight, group, evidence[:300]))

    def force_floor(self, value: int, reason: str) -> None:
        if value > self.floor:
            self.floor, self.floor_reason = value, reason

    def merge(self, other: "Findings", prefix: str = "") -> None:
        for i in other.items:
            self.add(i.code, (prefix + i.title) if prefix else i.title, i.detail, i.weight, i.group, i.evidence)
        self.force_floor(other.floor, other.floor_reason)

    @property
    def score(self) -> int:
        positive = sum(i.weight for i in self.items if i.weight > 0)
        negative = sum(i.weight for i in self.items if i.weight < 0)
        raw = max(0, min(100, positive + negative))
        return max(raw, self.floor)

    @property
    def level(self) -> str:
        s = self.score
        return "HIGH" if s >= HIGH_AT else "MEDIUM" if s >= MEDIUM_AT else "LOW"

    def to_list(self) -> list[dict]:
        return [asdict(i) for i in sorted(self.items, key=lambda x: -x.weight)]
