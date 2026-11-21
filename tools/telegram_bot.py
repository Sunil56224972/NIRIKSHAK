"""Citizen Telegram Bot for NIRIKSHAK (PS01).

Lets citizens forward suspicious SMS / WhatsApp messages or paste links to a
Cyber Crime Cell Telegram bot. Every submission runs the live NIRIKSHAK
analysis engine, logs a citizen case in Supabase, and replies with the risk
level, triggered reasons, case reference number and 1930 helpline guidance.

Usage:
    Set TELEGRAM_BOT_TOKEN in .env (from @BotFather), then:
    python tools/telegram_bot.py
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import auth, config, service  # noqa: E402
from app.db import DBError, get_db  # noqa: E402

URL_ONLY_RE = re.compile(r"^\s*(?:https?|hxxps?)://\S+\s*$", re.I)


def api_url(method: str) -> str:
    return f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/{method}"


def send(chat_id: int, text: str) -> None:
    try:
        requests.post(api_url("sendMessage"), json={"chat_id": chat_id, "text": text[:4000]}, timeout=15)
    except requests.RequestException:
        pass


def format_reply(case: dict, findings: list[dict]) -> str:
    lvl = case["risk_level"]
    score = case["risk_score"]
    lines = [
        f"NIRIKSHAK · {config.UNIT_NAME}",
        f"Reference: {case['case_no']}",
        f"Assessment: {lvl} RISK ({score}/100)",
    ]
    if case.get("category"):
        lines.append(f"Category: {case['category']}")
    reasons = [i for i in findings if i["weight"] > 0][:6]
    if reasons:
        lines.append("")
        lines.append("Indicators:")
        for i in reasons:
            lines.append(f"  [{i['weight']:+d}] {i['title']} — {i['detail'][:110]}")
    lines.append("")
    if lvl == "HIGH":
        lines.append("ADVICE: Do not open the link, install any APK, or send money.")
        lines.append("If defrauded, call 1930 immediately or report at cybercrime.gov.in.")
    elif lvl == "MEDIUM":
        lines.append("ADVICE: Warning signs detected. Verify via the official website/branch first.")
    else:
        lines.append("ADVICE: Low automated risk. Never share OTP, UPI PIN, CVV or install remote-access apps.")
    return "\n".join(lines)


def handle_message(msg: dict) -> None:
    chat_id = msg.get("chat", {}).get("id")
    text = (msg.get("text") or msg.get("caption") or "").strip()
    if not chat_id or not text:
        return
    if text.startswith("/start") or text.startswith("/help"):
        send(
            chat_id,
            f"NIRIKSHAK Citizen Check ({config.UNIT_NAME})\n\n"
            "Forward or paste any suspicious SMS, WhatsApp message, or URL here.\n"
            "You will receive an instant risk assessment with reasons and a police case reference.\n\n"
            "Emergency financial fraud helpline: 1930 | cybercrime.gov.in",
        )
        return

    user_info = msg.get("from") or {}
    reporter_name = " ".join(filter(None, [user_info.get("first_name"), user_info.get("last_name")]))
    reporter_contact = f"tg:@{user_info['username']}" if user_info.get("username") else f"tg_id:{user_info.get('id', '')}"

    try:
        kind = "url" if URL_ONLY_RE.match(text) else "message"
        if kind == "url":
            result = service.analyse("url", url=text)
        else:
            result = service.analyse("message", text=text, channel="telegram")
        db = get_db()
        case = service.create_case(
            db,
            kind,
            result,
            input_text=text,
            source="citizen",
            user=None,
            reporter_name=reporter_name,
            reporter_contact=reporter_contact,
            channel="telegram" if kind == "message" else "",
        )
        auth.audit(None, "telegram_report", case["case_no"], f"{kind} -> {case['risk_level']} {case['risk_score']}")
        send(chat_id, format_reply(case, result["findings"].to_list()))
    except (ValueError, DBError) as exc:
        send(chat_id, f"Could not process submission: {exc}")


def run() -> None:
    if not config.TELEGRAM_BOT_TOKEN:
        print("Error: set TELEGRAM_BOT_TOKEN in .env before starting the bot.", file=sys.stderr)
        sys.exit(1)
    if config.config_problems():
        print("Error:", "; ".join(config.config_problems()), file=sys.stderr)
        sys.exit(1)

    print("NIRIKSHAK Telegram bot polling started...")
    offset = 0
    while True:
        try:
            r = requests.get(api_url("getUpdates"), params={"timeout": 25, "offset": offset}, timeout=35)
            r.raise_for_status()
            for upd in r.json().get("result", []):
                offset = upd["update_id"] + 1
                if "message" in upd:
                    handle_message(upd["message"])
        except KeyboardInterrupt:
            print("Stopped.")
            break
        except Exception as exc:
            print("Poll error:", exc, file=sys.stderr)
            time.sleep(5)


if __name__ == "__main__":
    run()
