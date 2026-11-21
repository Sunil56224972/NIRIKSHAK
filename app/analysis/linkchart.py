"""Minimal link-analysis chart (pure SVG, no JS, no inline styles — CSP-safe).

Draws the focal identifier at the centre, connected cases on the left column,
and co-occurring identifiers on the right column, like a printed i2 / link chart.
"""
from __future__ import annotations

from html import escape

from .iocs import ETYPE_LABELS
from ..service import KIND_LABEL


def _trim(s: str, n: int) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def render_identifier_svg(entity: dict, cases: list[dict], co: list[dict]) -> str:
    left = cases[:10]
    right = co[:10]
    rows = max(len(left), len(right), 1)
    row_h = 46
    pad_y = 26
    h = max(170, rows * row_h + pad_y * 2)
    w = 820

    cx, cy = 410, h // 2
    cw, ch = 204, 54

    parts = [
        f'<svg class="linkchart" viewBox="0 0 {w} {h}" role="img" '
        f'aria-label="Entity correlation diagram for {escape(entity.get("display", ""))}">',
        '<text class="lc-col" x="14" y="16">CASES (' + str(len(cases)) + ')</text>',
        f'<text class="lc-col" x="{cx - cw // 2}" y="16">FOCAL IDENTIFIER</text>',
        '<text class="lc-col" x="580" y="16">CO-OCCURRING (' + str(len(co)) + ')</text>',
    ]

    # edges first so nodes sit cleanly on top
    left_positions = []
    if left:
        step = (h - pad_y * 2) / len(left)
        for idx, c in enumerate(left):
            y = int(pad_y + step * idx + step / 2)
            left_positions.append((c, y))
            cls = "lc-edge high" if c.get("risk_level") == "HIGH" else "lc-edge"
            parts.append(
                f'<path class="{cls}" d="M 244 {y} C 278 {y}, 278 {cy}, {cx - cw // 2} {cy}" />'
            )

    right_positions = []
    if right:
        step = (h - pad_y * 2) / len(right)
        for idx, a in enumerate(right):
            y = int(pad_y + step * idx + step / 2)
            right_positions.append((a, y))
            cls = "lc-edge linked" if a.get("case_count", 0) > 1 else "lc-edge"
            parts.append(
                f'<path class="{cls}" d="M {cx + cw // 2} {cy} C 542 {cy}, 542 {y}, 576 {y}" />'
            )

    # left column: cases
    for c, y in left_positions:
        bh = 36
        by = y - bh // 2
        lvl = escape(str(c.get("risk_level", "LOW")))
        kind_lbl = KIND_LABEL.get(c.get("kind", ""), c.get("kind", ""))
        parts.append(f'<a href="/cases/{c["id"]}">')
        parts.append(f'<rect class="lc-node case {lvl}" x="14" y="{by}" width="230" height="{bh}" />')
        parts.append(
            f'<text class="lc-title" x="22" y="{by + 14}">{escape(c["case_no"])} · {escape(kind_lbl)}</text>'
        )
        parts.append(
            f'<text class="lc-sub" x="22" y="{by + 28}">{lvl} ({c.get("risk_score", 0)}) · '
            f'{escape(_trim(c.get("title", ""), 26))}</text>'
        )
        parts.append("</a>")

    # center focal node
    parts.append(
        f'<rect class="lc-node focal" x="{cx - cw // 2}" y="{cy - ch // 2}" width="{cw}" height="{ch}" />'
    )
    parts.append(
        f'<text class="lc-kicker" x="{cx}" y="{cy - 9}" text-anchor="middle">'
        f'{escape(ETYPE_LABELS.get(entity["etype"], entity["etype"]).upper())}</text>'
    )
    parts.append(
        f'<text class="lc-focal-val" x="{cx}" y="{cy + 9}" text-anchor="middle">'
        f'{escape(_trim(entity.get("display", ""), 26))}</text>'
    )
    parts.append(
        f'<text class="lc-sub" x="{cx}" y="{cy + 21}" text-anchor="middle">'
        f'{entity.get("case_count", 0)} linked case(s)</text>'
    )

    # right column: co-occurring identifiers
    for a, y in right_positions:
        bh = 36
        by = y - bh // 2
        et = ETYPE_LABELS.get(a.get("etype", ""), a.get("etype", ""))
        parts.append(f'<a href="/identifiers/{a["id"]}">')
        parts.append(f'<rect class="lc-node ent" x="576" y="{by}" width="230" height="{bh}" />')
        parts.append(
            f'<text class="lc-title" x="584" y="{by + 14}">{escape(_trim(a.get("display", ""), 28))}</text>'
        )
        parts.append(
            f'<text class="lc-sub" x="584" y="{by + 28}">{escape(et)} · {a.get("together", 1)} shared · '
            f'{a.get("case_count", 1)} total</text>'
        )
        parts.append("</a>")

    parts.append("</svg>")
    return "\n".join(parts)
