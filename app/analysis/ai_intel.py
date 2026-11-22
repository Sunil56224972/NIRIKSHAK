"""Groq AI forensic intelligence & multimodal Vision OCR for NIRIKSHAK.

Supports:
  - Vision OCR on uploaded fraud/website screenshots (using config.GROQ_VISION_MODEL)
  - Structured cyber-forensic reasoning across Message, URL, Website, and APK inputs
    (using config.GROQ_MODEL with resilient fallback models)

Guardrails:
  - Zero fabricated IOCs: summarises and contextualises observed inputs & indicators only.
  - Official allowlisted domains with zero deterministic flags never receive positive risk.
  - Any risk adjustment is recorded as an explainable Indicator in Findings.
"""
from __future__ import annotations

import base64
import io
import json
import re
from typing import Any

import requests

from .. import config
from . import iocs as ioc_mod
from . import urlscan
from .scoring import Findings

GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {config.GROQ_API_KEY}",
        "Content-Type": "application/json",
    }


def _timeout() -> float:
    return max(15.0, config.NET_TIMEOUT * 2.0)


def _strip_code_fence(text: str) -> str:
    s = (text or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    return s.strip()


def _prepare_image_data_uri(data: bytes) -> str:
    mime = "image/png"
    payload = data
    try:
        from PIL import Image

        im = Image.open(io.BytesIO(data))
        if max(im.size) > 1800 or len(data) > 2_000_000:
            im = im.convert("RGB")
            im.thumbnail((1600, 1600), Image.Resampling.LANCZOS)
            buf = io.BytesIO()
            im.save(buf, format="JPEG", quality=88, optimize=True)
            payload = buf.getvalue()
            mime = "image/jpeg"
        elif im.format == "JPEG":
            mime = "image/jpeg"
        elif im.format == "WEBP":
            mime = "image/webp"
    except Exception:
        pass
    b64 = base64.b64encode(payload).decode("ascii")
    return f"data:{mime};base64,{b64}"


def vision_ocr(data: bytes) -> str | None:
    """Transcribe all visible text from a screenshot using Groq's multimodal vision model."""
    if not (config.LIVE_CHECKS and config.GROQ_ENABLED):
        return None
    try:
        data_uri = _prepare_image_data_uri(data)
        models: list[str] = []
        for m in (config.GROQ_VISION_MODEL, "qwen/qwen3.8-27b"):
            if m and m not in models:
                models.append(m)

        prompt = (
            "You are an OCR transcription engine for cybercrime evidence. "
            "Transcribe ALL visible text in this screenshot verbatim, line by line. "
            "Include URLs, UPI IDs, phone numbers, bank accounts, IFSC codes, headings, buttons, "
            "and brand names exactly as shown (English, Hindi, Hinglish, or regional scripts). "
            "Do not add commentary or markdown explanations — output only the extracted text."
        )
        for model in models:
            r = requests.post(
                GROQ_CHAT_URL,
                headers=_headers(),
                json={
                    "model": model,
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": prompt},
                                {"type": "image_url", "image_url": {"url": data_uri}},
                            ],
                        }
                    ],
                    "temperature": 0.0,
                    "max_completion_tokens": 1600,
                },
                timeout=_timeout(),
            )
            if not r.ok:
                continue
            content = (
                ((r.json().get("choices") or [{}])[0].get("message") or {}).get("content") or ""
            ).strip()
            if content:
                return _strip_code_fence(content)
    except Exception:
        return None
    return None


def _build_evidence_summary(
    kind: str,
    *,
    text: str,
    findings: Findings,
    details: dict[str, Any],
    iocs: list[dict],
    category: str,
) -> dict[str, Any]:
    indicators_brief = [
        {"code": i.code, "weight": i.weight, "title": i.title, "evidence": i.evidence}
        for i in sorted(findings.items, key=lambda x: -abs(x.weight))[:12]
    ]
    iocs_brief = [
        {"type": it.get("etype"), "value": it.get("display"), "context": it.get("context", "")}
        for it in (iocs or [])[:15]
    ]

    summary: dict[str, Any] = {
        "kind": kind,
        "deterministic_score": findings.score,
        "deterministic_level": findings.level,
        "initial_category": category,
        "submitted_text_excerpt": (text or "")[:1800],
        "triggered_rules": indicators_brief,
        "extracted_iocs": iocs_brief,
    }

    if kind in ("url", "website"):
        info = details.get("info") or (details.get("url_report") or {}).get("info") or {}
        net = details.get("net") or (details.get("url_report") or {}).get("net") or {}
        page = details.get("page") or {}
        summary["network"] = {
            "url": details.get("url") or info.get("url") or "",
            "registrable": info.get("registrable", ""),
            "tld": info.get("tld", ""),
            "whois": net.get("whois") or {},
            "hosting": net.get("hosting") or {},
            "final_url": net.get("final_url", ""),
        }
        if page:
            summary["page"] = {
                "title": page.get("title", ""),
                "forms": page.get("forms", [])[:5],
                "script_flags": page.get("script_flags", []),
                "apk_links": page.get("apk_links", [])[:5],
                "excerpt": (page.get("excerpt") or "")[:1500],
            }
    elif kind == "apk":
        a = details.get("apk") or {}
        s = details.get("store") or {}
        if a:
            summary["apk"] = {
                "package": a.get("package"),
                "label": a.get("label"),
                "version": a.get("version_name"),
                "risky_permissions": [p.get("permission") for p in a.get("risky_permissions", [])[:15]],
                "api_markers": [m.get("marker") for m in a.get("api_markers", [])[:10]],
                "certificates": [
                    {"scheme": c.get("scheme"), "subject": c.get("subject"), "self_signed": c.get("self_signed")}
                    for c in a.get("certificates", [])[:3]
                ],
                "store": a.get("store") or {},
            }
        elif s:
            summary["store"] = s

    return summary


def _is_clean_official(kind: str, text: str, details: dict, iocs: list[dict], findings: Findings) -> bool:
    if findings.score > 0:
        return False
    hosts: list[str] = []
    if kind in ("url", "website"):
        info = details.get("info") or (details.get("url_report") or {}).get("info") or {}
        net = details.get("net") or (details.get("url_report") or {}).get("net") or {}
        for h in (info.get("host"), info.get("registrable"), ioc_mod.host_of(net.get("final_url") or "")):
            if h:
                hosts.append(h)
    for it in iocs or []:
        if it.get("etype") == "domain" and it.get("value"):
            hosts.append(it["value"])
        elif it.get("etype") == "url" and it.get("value"):
            h = ioc_mod.host_of(it["value"])
            if h:
                hosts.append(h)
    if hosts and all(urlscan.is_official(h) for h in hosts):
        return True
    return False


def analyze_forensics(
    kind: str,
    *,
    text: str,
    findings: Findings,
    details: dict[str, Any],
    iocs: list[dict],
    category: str,
) -> dict[str, Any] | None:
    """Run Groq LLM cyber-forensic triage and enrich Findings + Officer Action Brief."""
    if not (config.LIVE_CHECKS and config.GROQ_ENABLED):
        return None

    clean_official = _is_clean_official(kind, text, details, iocs, findings)
    evidence_summary = _build_evidence_summary(
        kind, text=text, findings=findings, details=details, iocs=iocs, category=category
    )
    evidence_summary["verified_official_allowlist"] = clean_official

    system_prompt = (
        "You are an expert Senior Cyber Crime Forensic Analyst assisting Indian State Cyber Crime Cell officers "
        "(PS01: Scam Message, Phishing Link, Fake Loan/Investment App & Website Analysis).\n"
        "Analyze ONLY the evidence provided in the JSON payload. Do not invent URLs, IOCs, or facts not present in the payload.\n"
        "IMPORTANT: Official Indian banks legitimately redirect `.sbi`, `.co.in`, `.com` domains to official `.bank.in` / `.sbi.bank.in` domains. "
        "If verified_official_allowlist is true and deterministic_score is 0, classify it as 'Legitimate Official Service', "
        "set risk_delta=0, tactics=[], legal_provisions=[], state clearly in modus_operandi that the destination belongs to the verified official institution, "
        "and recommend closing without enforcement action.\n"
        "Return a valid JSON object with EXACT keys:\n"
        "  - threat_category (string): short classification (e.g. 'KYC Phishing', 'Digital Arrest Extortion', "
        "'Predatory Loan App', 'Ponzi / MLM Scam', 'Illegal Betting', 'Legitimate Official Service')\n"
        "  - modus_operandi (string): concise 2-3 sentence technical & behavioural explanation grounded strictly in the observed evidence\n"
        "  - tactics (array of 0-4 short strings): psychological or technical evasion tactics observed ([] if benign)\n"
        "  - legal_provisions (array of 0-4 short strings): prima facie Indian statutory sections if suspicious/malicious using "
        "IT Act 2000 & BNS/BNSS 2023 (e.g. 'Sec 66C / 66D IT Act 2000', 'Sec 318(4) BNS cheating', 'Sec 308 BNS extortion', "
        "'Sec 319(2) BNS impersonation', 'Sec 94 BNSS preservation notice'), empty list [] if benign\n"
        "  - officer_actions (array of 1-4 concise, actionable strings): next investigative steps referencing only observed IOCs\n"
        "  - risk_delta (integer between -10 and +25): signed adjustment to deterministic rule score ONLY if semantic/Hinglish/contextual evidence clearly raises or lowers risk beyond deterministic keywords. Use 0 when deterministic score already reflects the evidence or verified_official_allowlist is true.\n"
        "  - indicator_title (string): concise 4-8 word indicator title if risk_delta != 0, else ''\n"
        "  - indicator_detail (string): 1-sentence reason grounded in the evidence if risk_delta != 0, else ''\n"
    )

    models: list[str] = []
    for m in (config.GROQ_MODEL, "qwen/qwen3.8-27b", "openai/gpt-oss-20b"):
        if m and m not in models:
            models.append(m)

    raw_data: dict[str, Any] | None = None
    used_model = ""
    for model in models:
        body: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(evidence_summary, ensure_ascii=False, default=str)},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
            "max_completion_tokens": 1400,
        }
        if "gpt-oss" in model:
            body["reasoning_effort"] = "low"

        try:
            r = requests.post(GROQ_CHAT_URL, headers=_headers(), json=body, timeout=_timeout())
            if not r.ok:
                continue
            content = (
                ((r.json().get("choices") or [{}])[0].get("message") or {}).get("content") or ""
            ).strip()
            parsed = json.loads(_strip_code_fence(content))
            if isinstance(parsed, dict) and parsed.get("modus_operandi"):
                raw_data = parsed
                used_model = model
                break
        except Exception:
            continue

    if not raw_data:
        return None

    def _str_list(val: Any, limit: int = 5) -> list[str]:
        if not isinstance(val, list):
            return []
        return [str(x).strip()[:240] for x in val if str(x).strip()][:limit]

    try:
        risk_delta = int(raw_data.get("risk_delta") or 0)
    except (TypeError, ValueError):
        risk_delta = 0
    risk_delta = max(-10, min(25, risk_delta))

    threat_category = str(raw_data.get("threat_category") or "").strip()[:80]
    modus_operandi = str(raw_data.get("modus_operandi") or "").strip()[:900]
    tactics = _str_list(raw_data.get("tactics"), 5)
    legal_provisions = _str_list(raw_data.get("legal_provisions"), 5)
    officer_actions = _str_list(raw_data.get("officer_actions"), 5)
    ind_title = str(raw_data.get("indicator_title") or "").strip()[:120]
    ind_detail = str(raw_data.get("indicator_detail") or "").strip()[:300]

    # Guardrail: never add positive risk or criminal legal sections to clean official domains
    if clean_official:
        if risk_delta > 0:
            risk_delta = 0
        legal_provisions = []
        tactics = []
        threat_category = "Legitimate Official Service"
        if any(w in modus_operandi.lower() for w in ("malicious", "harvest", "impersonat", "takedown", "phishing")):
            modus_operandi = (
                "All resolved domains belong to verified official allowlisted institutions "
                "(including RBI-mandated .bank.in / official portals) with zero deterministic fraud indicators."
            )
            officer_actions = ["Verify user context if needed and close case as benign official domain."]

    if risk_delta != 0:
        findings.add(
            "ai.forensic_review",
            ind_title or ("AI forensic contextual risk" if risk_delta > 0 else "AI benign context adjustment"),
            ind_detail or modus_operandi[:240],
            risk_delta,
            "intel",
            f"Groq {used_model}",
        )

    return {
        "provider": "Groq",
        "model": used_model,
        "threat_category": threat_category,
        "modus_operandi": modus_operandi,
        "tactics": tactics,
        "legal_provisions": legal_provisions,
        "officer_actions": officer_actions,
        "risk_delta": risk_delta,
    }
