"""Generate synthetic screenshot sample(s) for PS01 website OCR testing.

Run:
    python tools/make_demo_samples.py
"""
from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent.parent / "samples" / "demo_ponzi_screenshot.png"


def _font(size: int, bold: bool = False):
    candidates = [
        r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def build_screenshot(dest: Path = OUT) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    im = Image.new("RGB", (1100, 680), "#ffffff")
    draw = ImageDraw.Draw(im)

    # Top synthetic address bar / header band
    draw.rectangle([0, 0, 1100, 86], fill="#14293d")
    draw.text((40, 22), "WealthBoost VIP - Official Investment Plan", fill="#ffffff", font=_font(34, bold=True))

    lines = [
        (40, 120, "Website: https://wealthboost-vip-demo.top", "#1d232b", 28, True),
        (40, 180, "GUARANTEED 15% DAILY RETURN - 100% RISK FREE PROFIT", "#a3201b", 30, True),
        (40, 240, "Double your investment in 7 days with AI trading!", "#1d232b", 26, False),
        (40, 295, "Level 1-3 MLM Referral Commission: 18% joining bonus", "#1d232b", 26, False),
        (40, 350, "Registered by RBI & SEBI (Synthetic Demo Sample)", "#1d232b", 26, False),
        (40, 420, "UPI ID: fastprofit99@ybl", "#0f3d5e", 28, True),
        (40, 475, "WhatsApp Desk: +91 90000 11223", "#0f3d5e", 28, True),
        (40, 530, "Telegram VIP: t.me/wealthboost_demo_vip", "#0f3d5e", 28, True),
        (40, 595, "Pay 18% tax before withdraw | Minimum withdrawal Rs 500", "#555555", 24, False),
    ]
    for x, y, text, color, sz, bold in lines:
        draw.text((x, y), text, fill=color, font=_font(sz, bold=bold))

    im.save(dest, format="PNG")
    return dest


if __name__ == "__main__":
    p = build_screenshot()
    print(f"Wrote {p} ({p.stat().st_size} bytes)")
