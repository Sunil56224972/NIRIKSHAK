"""Section 94 BNSS / Section 91 CrPC Nodal Request & Actionable Identifiers export."""
from __future__ import annotations

from datetime import datetime, timezone

from . import config, report
from .analysis.iocs import ETYPE_LABELS, IFSC_BANKS, upi_bank


def _net_blocks(case: dict) -> list[dict]:
    details = (case.get("result") or {}).get("details") or {}
    blocks = []
    if isinstance(details.get("net"), dict) and details["net"]:
        blocks.append(details["net"])
    ur = details.get("url_report") or {}
    if isinstance(ur.get("net"), dict) and ur["net"]:
        blocks.append(ur["net"])
    for lnk in details.get("links") or []:
        if isinstance(lnk.get("net"), dict) and lnk["net"]:
            blocks.append(lnk["net"])
    return blocks


def _by_type(entities: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for e in entities:
        grouped.setdefault(e.get("etype", ""), []).append(e)
    return grouped


def _fmt_entity_line(e: dict, extra: str = "") -> str:
    ctx = e.get("context") or ""
    count = e.get("case_count", 1)
    parts = [f"- {e.get('display') or e.get('value', '')}"]
    if extra:
        parts.append(f"[{extra}]")
    if ctx:
        parts.append(f"(source: {ctx})")
    parts.append(f"— seen in {count} case(s)")
    return " ".join(parts)


def build_notice(case: dict, entities: list[dict], officer: dict) -> str:
    r = case.get("result") or {}
    details = r.get("details") or {}
    by_type = _by_type(entities)
    now_ist = report.ist(datetime.now(timezone.utc).isoformat())

    rank_name = " ".join(filter(None, [officer.get("rank"), officer.get("full_name")])).strip() or officer.get("username", "")
    badge = officer.get("badge_no") or "N/A"
    unit = officer.get("unit") or config.UNIT_NAME

    lines = [
        "=" * 78,
        f"{config.APP_NAME} — SECTION 94 BNSS / SECTION 91 CrPC NODAL REQUEST SUMMARY",
        f"Unit: {unit}",
        "=" * 78,
        f"Case Reference      : {case.get('case_no', '')}",
        f"Generated At        : {now_ist}",
        f"Preparing Officer   : {rank_name} (Badge: {badge}, User: {officer.get('username', '')})",
        f"Item Type / Channel : {str(case.get('kind', '')).upper()}" + (f" / {case['channel']}" if case.get("channel") else ""),
        f"Assessment          : {case.get('risk_level', '')} RISK ({case.get('risk_score', 0)}/100)",
        f"Category            : {case.get('category') or 'Unclassified'}",
        f"Subject             : {case.get('title', '')}",
        f"Input SHA-256       : {case.get('content_sha256', '')}",
        "",
    ]

    lo = details.get("live_osint") or {}
    ifsc_map = {b["ifsc"]: b for b in (lo.get("ifsc") or []) if b.get("ifsc")}
    crypto_map = {w["address"].lower(): w for w in (lo.get("crypto") or []) if w.get("address")}

    # Section A: Payment / Banking Nodal Action
    lines.append("SECTION A — PAYMENT / BANKING NODAL ACTION (UPI, BANK ACCOUNTS, IFSC, CRYPTO)")
    lines.append("-" * 78)
    sec_a = []
    for e in by_type.get("upi", []):
        val = e.get("value", "")
        handle = val.split("@", 1)[1] if "@" in val else ""
        bank = upi_bank(handle) or "Unlisted PSP handle"
        sec_a.append(_fmt_entity_line(e, f"UPI · PSP: {bank}"))
    for e in by_type.get("bank_account", []):
        sec_a.append(_fmt_entity_line(e, "Bank Account"))
    for e in by_type.get("ifsc", []):
        code = (e.get("value") or "").upper()
        binfo = ifsc_map.get(code)
        if binfo and binfo.get("valid"):
            extra = f"IFSC · {binfo.get('bank', '')} · Branch: {binfo.get('branch', '')}, {binfo.get('city', '')}, {binfo.get('state', '')}"
            sec_a.append(_fmt_entity_line(e, extra))
            if binfo.get("address"):
                sec_a.append(f"  RBI Branch Address -> {binfo['address']}" + (f" | Tel: {binfo['contact']}" if binfo.get("contact") else ""))
        elif binfo and binfo.get("valid") is False:
            sec_a.append(_fmt_entity_line(e, "IFSC · INVALID / NON-EXISTENT IN RBI DIRECTORY"))
        else:
            bank = IFSC_BANKS.get(code[:4], f"Bank code {code[:4]}")
            sec_a.append(_fmt_entity_line(e, f"IFSC · {bank}"))
    for e in by_type.get("crypto", []):
        sec_a.append(_fmt_entity_line(e, ETYPE_LABELS.get("crypto", "Crypto wallet")))
        winfo = crypto_map.get((e.get("value") or "").lower()) or crypto_map.get(e.get("display") or "")
        if winfo:
            if "usdt_trc20_balance" in winfo:
                sec_a.append(f"  On-Chain (TRON) -> {winfo['usdt_trc20_balance']:,.2f} USDT | {winfo['trx_balance']:,.2f} TRX | Last op: {winfo.get('last_activity') or 'n/a'}")
            elif "balance_btc" in winfo:
                sec_a.append(f"  On-Chain (BTC)  -> {winfo['tx_count']} tx | Total received: {winfo['total_received_btc']} BTC | Current bal: {winfo['balance_btc']} BTC")
            elif "eth_balance" in winfo:
                sec_a.append(f"  On-Chain (ETH)  -> {winfo['outgoing_tx_count']} outgoing tx | Current bal: {winfo['eth_balance']} ETH")
    lines.extend(sec_a if sec_a else ["(none extracted for this case)"])
    lines.append("")

    # Section B: Telecom / Messaging Nodal Action
    lines.append("SECTION B — TELECOM / MESSAGING NODAL ACTION (PHONES, DLT HEADERS, TELEGRAM, WHATSAPP, EMAIL)")
    lines.append("-" * 78)
    sec_b = []
    trai = (details.get("sender") or {}).get("trai")
    if trai:
        sec_b.append(f"- SMS Sender Header: {trai['header']} [TSP: {trai['operator']} | Circle: {trai['circle']} | Stream: {trai['stream']}]")
        sec_b.append(f"  Nodal Action -> {trai['nodal_hint']}")
    for t in ("phone", "telegram", "whatsapp_group", "email"):
        lbl = ETYPE_LABELS.get(t, t)
        for e in by_type.get(t, []):
            sec_b.append(_fmt_entity_line(e, lbl))
    lines.extend(sec_b if sec_b else ["(none extracted for this case)"])
    lines.append("")

    # Section C: Domain Registrar & Hosting Action
    lines.append("SECTION C — DOMAIN REGISTRAR & HOSTING ACTION")
    lines.append("-" * 78)
    sec_c = []
    for t in ("domain", "url", "ip"):
        lbl = ETYPE_LABELS.get(t, t)
        for e in by_type.get(t, []):
            sec_c.append(_fmt_entity_line(e, lbl))
    for nb in _net_blocks(case):
        w = nb.get("whois") or {}
        if w.get("found"):
            reg_parts = [p for p in [
                f"Registrar: {w['registrar']}" if w.get("registrar") else "",
                f"Created: {w['created'][:10]}" if w.get("created") else "",
                f"Age: {w['age_days']}d" if w.get("age_days") is not None else "",
                f"Abuse Email: {w['registrar_abuse_email']}" if w.get("registrar_abuse_email") else "",
                f"Abuse Tel: {w['registrar_abuse_phone']}" if w.get("registrar_abuse_phone") else "",
            ] if p]
            if reg_parts:
                sec_c.append("  RDAP -> " + " | ".join(reg_parts))
        h = nb.get("hosting") or {}
        if h.get("ip") or h.get("org") or h.get("network"):
            host_parts = [p for p in [
                f"IP: {h['ip']}" if h.get("ip") else "",
                f"ASN: {h['asn']}" if h.get("asn") else "",
                f"Network: {h['network']}" if h.get("network") else "",
                f"Org: {h['org']}" if h.get("org") else "",
                f"Location: {h.get('location') or h.get('country', '')}" if (h.get("location") or h.get("country")) else "",
                f"RIR Abuse Email: {', '.join(h['abuse_contacts'])}" if h.get("abuse_contacts") else "",
            ] if p]
            sec_c.append("  Hosting -> " + " | ".join(host_parts))
    for c2 in (details.get("live_osint") or {}).get("apk_c2") or []:
        h = c2.get("hosting") or {}
        w = c2.get("whois") or {}
        c2_parts = [p for p in [
            f"APK C2: {c2['target']}",
            f"IP: {h['ip']}" if h.get("ip") else "",
            f"ASN/Org: {h.get('asn', '')} {h.get('org', '')}".strip() if (h.get("asn") or h.get("org")) else "",
            f"Abuse Email: {', '.join(h['abuse_contacts'])}" if h.get("abuse_contacts") else "",
            f"Registrar: {w['registrar']} ({w.get('registrar_abuse_email', '')})" if w.get("registrar") else "",
        ] if p]
        sec_c.append("  " + " | ".join(c2_parts))
    lines.extend(sec_c if sec_c else ["(none extracted for this case)"])
    lines.append("")

    # Section D: Mobile Application Action
    lines.append("SECTION D — MOBILE APPLICATION ACTION (PLAY STORE / CERT / HASH)")
    lines.append("-" * 78)
    sec_d = []
    for t in ("apk_package", "apk_sha256", "apk_cert"):
        lbl = ETYPE_LABELS.get(t, t)
        for e in by_type.get(t, []):
            sec_d.append(_fmt_entity_line(e, lbl))
    apk_meta = details.get("apk") or {}
    for cert in apk_meta.get("certificates") or []:
        sec_d.append(
            f"  Cert ({cert.get('scheme', '')}) -> Subject: {cert.get('subject', '')} | "
            f"SHA-256: {cert.get('sha256', '')}"
        )
    lines.extend(sec_d if sec_d else ["(none extracted for this case)"])
    lines.append("")

    # Section E: Triggered Risk Indicators Summary
    lines.append("SECTION E — TRIGGERED RISK INDICATORS SUMMARY")
    lines.append("-" * 78)
    pos = [i for i in (r.get("indicators") or []) if i.get("weight", 0) > 0]
    if pos:
        for i in pos:
            ev = f" | Evidence: {i['evidence']}" if i.get("evidence") else ""
            lines.append(f"  [{i['weight']:+d}] {i.get('title', '')} — {i.get('detail', '')}{ev}")
    else:
        lines.append("(no positive risk indicators triggered)")
    lines.append("")
    lines.append("Note: Automated static/OSINT observation record; verify subscriber KYC via formal statutory notice.")
    return "\n".join(lines) + "\n"
