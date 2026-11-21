"""Investigation report (PDF) for a case: findings, identifiers, links, evidence hashes, custody trail."""
from __future__ import annotations

import io
from datetime import datetime, timezone, timedelta

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from . import config
from .analysis.iocs import ETYPE_LABELS

IST = timezone(timedelta(hours=5, minutes=30))
INK = colors.HexColor("#1d232b")
RULE = colors.HexColor("#9aa4ae")
SHADE = colors.HexColor("#eef0f2")
LEVEL_COLOR = {"HIGH": colors.HexColor("#a3201b"), "MEDIUM": colors.HexColor("#8a5a00"), "LOW": colors.HexColor("#2f6b2f")}


def ist(ts: str | None) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(IST).strftime("%d-%m-%Y %H:%M:%S IST")
    except ValueError:
        return ts


def _esc(s) -> str:
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build(case: dict, evidence: list[dict], audit: list[dict], officer: dict | None, generated_by: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=18 * mm,
                            bottomMargin=16 * mm, title=f"Case report {case['case_no']}", author=config.UNIT_NAME)
    ss = getSampleStyleSheet()
    base = ParagraphStyle("b", parent=ss["Normal"], fontName="Helvetica", fontSize=8.6, leading=11, textColor=INK)
    small = ParagraphStyle("s", parent=base, fontSize=7.4, leading=9.2)
    mono = ParagraphStyle("m", parent=base, fontName="Courier", fontSize=7.6, leading=9.4)
    h1 = ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=13, leading=16)
    h2 = ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=9.5, leading=12, spaceBefore=9, spaceAfter=4)

    r = case["result"]
    story = []
    story.append(Paragraph(_esc(config.UNIT_NAME.upper()), small))
    story.append(Paragraph("Cyber Fraud Analysis Report", h1))
    story.append(Paragraph(f"Case No. <b>{_esc(case['case_no'])}</b> &nbsp;&nbsp; Generated {ist(datetime.now(timezone.utc).isoformat())} "
                           f"by {_esc(generated_by['full_name'])} ({_esc(generated_by['username'])})", small))
    story.append(Spacer(1, 5))

    lvl = case["risk_level"]
    head = [
        ["Assessment", Paragraph(f"<font color='{LEVEL_COLOR[lvl].hexval()}'><b>{lvl} RISK</b></font> &nbsp; score {case['risk_score']}/100"
                                 + (f" &nbsp;(minimum applied: {_esc(r.get('floor_reason'))})" if r.get("floor_reason") else ""), base)],
        ["Category", Paragraph(_esc(case["category"] or "—"), base)],
        ["Item type", Paragraph(_esc(case["kind"].upper()) + (f" / {_esc(case['channel'])}" if case.get("channel") else ""), base)],
        ["Subject", Paragraph(_esc(case["title"]), base)],
        ["Status", Paragraph(_esc(case["status"].replace("_", " ")), base)],
        ["Received", Paragraph(ist(case["created_at"]) + f" via {'citizen portal' if case['source'] == 'citizen' else 'officer console'}", base)],
        ["Submitted by", Paragraph(_esc(f"{officer['rank']} {officer['full_name']} ({officer['badge_no']})" if officer else
                                        (case.get("reporter_name") or "Anonymous citizen") +
                                        (f", {case['reporter_contact']}" if case.get("reporter_contact") else "")), base)],
        ["Input SHA-256", Paragraph(_esc(case["content_sha256"]), mono)],
    ]
    t = Table(head, colWidths=[32 * mm, None])
    t.setStyle(TableStyle([("FONT", (0, 0), (0, -1), "Helvetica-Bold", 8), ("TEXTCOLOR", (0, 0), (-1, -1), INK),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 3)]))
    story.append(t)

    story.append(Paragraph("1. Indicators that produced this assessment", h2))
    rows = [["Wt", "Indicator", "Explanation / evidence"]]
    for i in r.get("indicators", []):
        rows.append([f"{i['weight']:+d}", Paragraph(f"<b>{_esc(i['title'])}</b><br/><font size=6.8>{_esc(i['group'])}</font>", base),
                     Paragraph(_esc(i["detail"]) + (f"<br/><font face='Courier' size=7>{_esc(i['evidence'])}</font>" if i.get("evidence") else ""), base)])
    story.append(_grid(rows, [12 * mm, 52 * mm, None]))

    story.append(Paragraph("2. Extracted identifiers (actionable)", h2))
    ids = r.get("identifiers", [])
    if ids:
        rows = [["Type", "Value", "Where found"]]
        order = ["upi", "bank_account", "ifsc", "phone", "crypto", "domain", "url", "ip", "telegram", "whatsapp_group",
                 "email", "apk_package", "apk_cert", "apk_sha256"]
        for it in sorted(ids, key=lambda x: order.index(x["etype"]) if x["etype"] in order else 99):
            rows.append([ETYPE_LABELS.get(it["etype"], it["etype"]), Paragraph(_esc(it["display"]), mono),
                         Paragraph(_esc(it.get("context", "")), small)])
        story.append(_grid(rows, [28 * mm, 82 * mm, None]))
    else:
        story.append(Paragraph("No identifiers extracted.", base))

    intel = r.get("intel", {})
    story.append(Paragraph("3. Correlation with other records", h2))
    linked = intel.get("linked", [])
    if linked:
        rows = [["Identifier", "Linked case", "Type", "Risk", "Status"]]
        for l in linked[:40]:
            rows.append([Paragraph(_esc(l["display"]), mono), l["case_no"], l["kind"], l["risk_level"], l["status"].replace("_", " ")])
        story.append(_grid(rows, [62 * mm, 34 * mm, 20 * mm, 18 * mm, None]))
    else:
        story.append(Paragraph("No identifier from this item appears in earlier cases at the time of analysis.", base))
    if intel.get("similar"):
        story.append(Spacer(1, 3))
        rows = [["Similar content", "Overlap", "Risk", "Status"]]
        for s in intel["similar"]:
            rows.append([Paragraph(f"{_esc(s['case_no'])} — {_esc(s['title'][:90])}", small), f"{s['similarity']}%", s["risk_level"],
                         s["status"].replace("_", " ")])
        story.append(_grid(rows, [None, 18 * mm, 18 * mm, 28 * mm]))
    if intel.get("blocklist"):
        story.append(Spacer(1, 3))
        rows = [["Blocklisted value", "Source"]]
        for b in intel["blocklist"]:
            rows.append([Paragraph(_esc(b["value"]), mono), Paragraph(_esc(b["source"]), small)])
        story.append(_grid(rows, [100 * mm, None]))

    story.append(Paragraph("4. Technical details", h2))
    for label, value in _technical(case):
        story.append(KeepTogether([Paragraph(f"<b>{_esc(label)}</b>", base), Paragraph(_esc(value), mono), Spacer(1, 3)]))

    story.append(Paragraph("5. Evidence items", h2))
    if evidence:
        rows = [["#", "Item", "File", "Size", "SHA-256"]]
        for n, e in enumerate(evidence, 1):
            rows.append([str(n), Paragraph(_esc(e["label"]), small), Paragraph(_esc(e["filename"]), small),
                         f"{e['size_bytes']:,}", Paragraph(_esc(e["sha256"]), mono)])
        story.append(_grid(rows, [7 * mm, 38 * mm, 34 * mm, 16 * mm, None]))
    else:
        story.append(Paragraph("No file evidence attached.", base))

    if case.get("input_text") and case["kind"] == "message":
        story.append(Paragraph("6. Original message as received", h2))
        story.append(Paragraph(_esc(case["input_text"][:6000]).replace("\n", "<br/>"), mono))

    story.append(Paragraph("7. Handling record", h2))
    rows = [["Time", "User", "Action", "Detail"]]
    for a in audit:
        rows.append([ist(a["at"]), a["username"], a["action"], Paragraph(_esc(a["detail"][:200]), small)])
    story.append(_grid(rows, [36 * mm, 26 * mm, 30 * mm, None]))
    if case.get("notes"):
        story.append(Paragraph("Officer notes", h2))
        story.append(Paragraph(_esc(case["notes"]).replace("\n", "<br/>"), base))

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "This report records automated static and network observations made at the time stated. Risk scores are "
        "indicative and support, but do not replace, investigative judgement. Live infrastructure (DNS, hosting, page "
        "content) can change after capture; rely on the evidence hashes above for integrity of captured material.", small))

    def page(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#5b6670"))
        canvas.drawString(16 * mm, 9 * mm, f"{case['case_no']}  ·  {config.APP_NAME}  ·  RESTRICTED — for law-enforcement use")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=page, onLaterPages=page)
    return buf.getvalue()


def _grid(rows, widths):
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 7.6), ("FONT", (0, 1), (-1, -1), "Helvetica", 7.8),
        ("BACKGROUND", (0, 0), (-1, 0), SHADE), ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("GRID", (0, 0), (-1, -1), 0.25, RULE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _technical(case: dict) -> list[tuple[str, str]]:
    d = case["result"].get("details", {})
    out = []
    net = d.get("net") or (d.get("url_report") or {}).get("net") or {}
    info = d.get("info") or (d.get("url_report") or {}).get("info") or {}
    if info:
        out.append(("URL", f"{info.get('url', '')}\nregistrable domain: {info.get('registrable', '')}   tld: .{info.get('tld', '')}"))
    if net.get("whois"):
        w = net["whois"]
        out.append(("Registration (RDAP)", f"registrar: {w.get('registrar', '')}\ncreated: {w.get('created', '')}   "
                                            f"age: {w.get('age_days', '')} days   expires: {w.get('expires', '')}\n"
                                            f"abuse contact: {w.get('registrar_abuse_email', '')} {w.get('registrar_abuse_phone', '')}\n"
                                            f"nameservers: {', '.join(w.get('nameservers', []))}"))
    if net.get("dns"):
        h = net.get("hosting") or {}
        out.append(("DNS / hosting", f"A/AAAA: {', '.join(net['dns'])}\nnetwork: {h.get('network', '')}  org: {h.get('org', '')}  "
                                      f"country: {h.get('country', '')}"))
    if net.get("http"):
        chain = net["http"].get("chain", [])
        out.append(("HTTP redirect chain", "\n".join(f"{c['status']}  {c['url']}" for c in chain) +
                    f"\nfinal: {net.get('final_url', '')}"))
    if net.get("tls"):
        t = net["tls"]
        out.append(("TLS certificate", f"subject: {t['subject']}\nissuer: {t['issuer']}\nvalid: {t['not_before']} to {t['not_after']}\n"
                                        f"verified: {t['verified']} {t.get('verify_error', '')}\nsha256: {t['sha256']}"))
    if net.get("errors"):
        out.append(("Checks that could not complete", "\n".join(f"{k}: {v}" for k, v in net["errors"].items())))
    if d.get("apk"):
        a = d["apk"]
        out.append(("Application", f"package: {a.get('package')}\nlabel: {a.get('label')}\nversion: {a.get('version_name')} "
                                    f"({a.get('version_code')})  minSdk {a.get('min_sdk')}  targetSdk {a.get('target_sdk')}\n"
                                    f"file: {a.get('filename')}  {a.get('size', 0):,} bytes\nsha256: {a.get('sha256')}\nmd5: {a.get('md5')}"))
        out.append(("Requested permissions", "\n".join(a.get("permissions", [])) or "none"))
        for c in a.get("certificates", []):
            out.append((f"Signing certificate ({c['scheme']})", f"subject: {c['subject']}\nissuer: {c['issuer']}\n"
                                                                 f"valid from {c['not_before']} to {c['not_after']}\nsha256: {c['sha256']}"))
    if d.get("store"):
        s = d["store"]
        out.append(("Play Store listing", "\n".join(f"{k}: {v}" for k, v in s.items())))
    if d.get("page"):
        p = d["page"]
        out.append(("Page", f"title: {p.get('title', '')}\nforms: {len(p.get('forms', []))}   script flags: "
                            f"{', '.join(p.get('script_flags', [])) or 'none'}\nAPK links: {', '.join(p.get('apk_links', [])) or 'none'}"))
    if d.get("email_headers"):
        out.append(("E-mail headers", "\n".join(f"{k}: {v}" for k, v in d["email_headers"].items() if v)))
    if d.get("sender", {}).get("value"):
        s = d["sender"]
        out.append(("Sender", f"{s['value']}  ({s.get('type', 'unclassified')})"))
    for l in d.get("links", []):
        out.append((f"Embedded link — {l['level']} ({l['score']})", l["url"] + "\n" + "\n".join(
            f"{i['weight']:+d} {i['title']}" for i in l["findings"])))
    return out
