"""Scam message analysis for SMS / WhatsApp / e-mail / social media text.

Rules are deliberately transparent regexes so every verdict can be explained in a
report and defended in court. English, Hinglish and common Hindi phrasing are covered.
"""
from __future__ import annotations

import email
import email.policy
import re

from .. import config
from . import iocs as ioc_mod
from . import osint
from . import urlscan
from .brands import BRANDS
from .scoring import Findings

# (code, category, title, weight, patterns)
RULES: list[tuple[str, str, str, int, list[str]]] = [
    ("msg.kyc", "Fake KYC / account block", "KYC / PAN / account-block threat", 22, [
        r"\b(?:e-?)?kyc\b.{0,40}(?:update|pending|expire|verify|complete|suspend|block)",
        r"(?:update|complete|verify)\s+(?:your\s+)?(?:e-?)?kyc",
        r"pan\s*(?:card)?\s*(?:not\s+)?(?:link|update|verify|block)",
        r"(?:account|a/c|khata|yono|net\s*banking|card)\s.{0,30}(?:block|suspend|deactivat|freez|band|closed|hold)",
        r"(?:खाता|अकाउंट).{0,20}(?:बंद|ब्लॉक)", r"केवाईसी",
    ]),
    ("msg.electricity", "Electricity bill disconnection", "Electricity disconnection threat", 24, [
        r"(?:electricity|power|bijli|light)\s.{0,40}(?:disconnect|cut|kat|band)",
        r"(?:previous|last)\s+month\s+bill\s+(?:was\s+)?not\s+update",
        r"(?:tonight|today|aaj\s+raat)\s.{0,30}(?:9|9:30|10)[.:]?(?:30)?\s*(?:pm|baje)",
        r"बिजली.{0,30}(?:कट|काट|बंद)", r"electricity\s+officer",
    ]),
    ("msg.parcel", "Parcel / courier / customs", "Undelivered parcel or customs-fee lure", 18, [
        r"(?:parcel|package|shipment|courier|consignment)\s.{0,50}(?:held|hold|pending|undeliver|failed|return|address|custom|redeliver)",
        r"(?:address|pin\s*code)\s+(?:is\s+)?(?:incomplete|incorrect|invalid)",
        r"(?:custom|clearance)\s+(?:duty|fee|charge)", r"india\s*post.{0,40}(?:warehouse|redeliver|address)",
    ]),
    ("msg.digital_arrest", "Digital arrest / impersonation of police", "Police / CBI / customs intimidation", 30, [
        r"digital\s+arrest", r"(?:cbi|ncb|ed\b|enforcement\s+directorate|narcotics|customs|cyber\s*cell|mumbai\s+police|trai)\s.{0,60}(?:case|fir|warrant|arrest|illegal|drugs|money\s+laundering|suspend)",
        r"(?:money\s+laundering|drugs?\s+(?:parcel|found))", r"(?:aadhaar|sim)\s.{0,30}(?:misused|illegal\s+activit|blocked\s+in\s+2\s+hours)",
        r"arrest\s+warrant",
    ]),
    ("msg.job", "Job / task / part-time scam", "Part-time job or task-earning offer", 22, [
        r"(?:part[\s\-]?time|work\s+from\s+home|wfh|home\s+based)\s.{0,40}(?:job|work|earn|income)",
        r"(?:earn|income|salary|kamai)\s.{0,20}(?:rs\.?|₹|inr)?\s?\d[\d,]{2,}\s*(?:/|per|a|daily|per\s+day|daily|rozana)",
        r"(?:like|subscribe|rate|review)\s.{0,30}(?:youtube|video|hotel|google\s+map|product).{0,40}(?:earn|paid|rs|₹)",
        r"(?:prepaid|merchant|task)\s+tasks?", r"hr\s+(?:manager|team)\s.{0,30}(?:whatsapp|telegram)",
    ]),
    ("msg.investment", "Investment / trading scam", "Unrealistic investment or trading returns", 24, [
        r"(?:guaranteed|assured|fixed|sure[\s\-]?shot)\s.{0,20}(?:return|profit|income)",
        r"\d{1,3}\s?%\s*(?:daily|per\s+day|weekly|monthly|return|profit)",
        r"double\s+(?:your\s+)?(?:money|investment)", r"(?:ipo|stock|share|crypto|forex)\s.{0,40}(?:tips|vip|group|allotment|institutional)",
        r"(?:vip|premium)\s+(?:group|channel|signals?)", r"(?:block|otc)\s+trading",
    ]),
    ("msg.loan", "Fake instant loan", "Instant loan without verification", 20, [
        r"(?:instant|pre[\s\-]?approved|personal)\s+loan", r"loan\s.{0,30}(?:without|no)\s+(?:cibil|document|income\s+proof|verification)",
        r"(?:loan|credit)\s.{0,30}(?:approved|sanctioned)\s.{0,30}(?:₹|rs|inr)", r"(?:processing|file|insurance)\s+(?:fee|charge)",
    ]),
    ("msg.prize", "Lottery / prize / reward", "Prize, lottery or reward claim", 20, [
        r"(?:won|winner|selected|lucky)\s.{0,40}(?:prize|lottery|lucky\s+draw|reward|car|iphone|kbc)",
        r"(?:reward|cashback|redeem)\s+points?\s.{0,40}(?:expire|today|claim|redeem)",
        r"\bkbc\b", r"(?:claim|collect)\s+(?:your\s+)?(?:prize|reward|gift)",
    ]),
    ("msg.refund", "Refund / tax / subsidy lure", "Refund or government benefit lure", 18, [
        r"(?:income\s+tax|itr|gst|tds)\s+refund", r"refund\s.{0,30}(?:approved|initiated|pending)\s.{0,40}(?:click|link|verify)",
        r"(?:pm[\s\-]?kisan|yojana|subsidy|scholarship)\s.{0,40}(?:click|apply|link|credited|pending)",
    ]),
    ("msg.sextortion", "Sextortion / blackmail", "Blackmail / morphed-content threat", 25, [
        r"(?:video|photo|pic)s?\s.{0,40}(?:viral|leak|upload|share)\s.{0,40}(?:contacts|family|friends|youtube)",
        r"(?:morphed|nude|obscene)", r"pay\s.{0,20}(?:or|otherwise)\s.{0,30}(?:viral|leak|share|police)",
    ]),
    ("msg.betting", "Betting / gaming", "Betting or gaming promotion", 18, [
        r"(?:cricket|ipl|casino|aviator|colou?r\s+prediction|teen\s*patti|satta|matka|rummy)\s.{0,40}(?:bet|win|earn|id|deposit|bonus)",
        r"(?:first|1st)\s+deposit\s+bonus", r"(?:betting|bet)\s+id",
    ]),
]

URGENCY = [
    r"\b(?:urgent|immediately|turant|jaldi|asap)\b", r"within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)",
    r"\b(?:today|tonight|aaj)\b.{0,30}(?:last|expire|block|disconnect|before)",
    r"(?:last|final)\s+(?:date|chance|reminder|warning|notice)", r"(?:will\s+be|shall\s+be)\s+(?:blocked|suspended|disconnected|deactivated|closed|cancell?ed)",
    r"तुरंत", r"आज\s+रात",
]
CREDENTIAL_ASK = [
    r"(?:share|send|tell|provide|enter)\s.{0,20}(?:otp|pin|cvv|password|mpin|upi\s+pin)",
    r"(?:otp|upi\s+pin|mpin)\s.{0,20}(?:share|send|bataye|batao|confirm)", r"anydesk|teamviewer|rustdesk|quick\s*support|airdroid",
    r"screen\s+shar", r"(?:collect|payment)\s+request\s.{0,30}(?:accept|approve)",
]
CALL_TO_ACTION = [
    r"(?:click|tap|open|visit)\s.{0,20}(?:link|below|here|url)", r"(?:call|contact|whatsapp)\s.{0,20}(?:immediately|now|on|at|this\s+number)",
    r"(?:download|install)\s.{0,30}(?:app|apk|application)", r"\.apk\b",
]

TRAI_HEADER = re.compile(r"^[A-Z]{2}-[A-Z0-9]{6}(?:-[SPTG])?$")


def _hits(patterns: list[str], text: str) -> list[str]:
    out = []
    for p in patterns:
        m = re.search(p, text, re.I | re.S)
        if m:
            out.append(m.group(0).strip()[:90])
    return out


def _brand_mentions(text: str) -> list[str]:
    low = text.lower()
    out = []
    for b in BRANDS:
        if b["name"] in ("WhatsApp", "Telegram"):   # delivery platforms, not impersonation targets
            continue
        names = [b["name"].lower()] + [k for k in b["keywords"] if len(k) >= 3]
        for n in names:
            if re.search(rf"(?<![a-z]){re.escape(n)}(?![a-z])", low):
                out.append(b["name"])
                break
    return out


def _email_headers(text: str, f: Findings, *, run_live: bool = True) -> dict:
    """If raw e-mail source is pasted, inspect From / Reply-To / authentication results & live DNS SPF/DMARC."""
    if not re.search(r"^(?:From|Received|Return-Path|Message-ID):", text, re.M | re.I):
        return {}
    msg = email.message_from_string(text, policy=email.policy.default)
    info = {k: str(msg.get(k, "")) for k in ("From", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID")}
    from_addr = email.utils.parseaddr(info["From"])
    reply_addr = email.utils.parseaddr(info["Reply-To"])
    from_dom = from_addr[1].split("@")[-1].lower() if "@" in from_addr[1] else ""
    if reply_addr[1] and from_dom and reply_addr[1].split("@")[-1].lower() != from_dom:
        f.add("mail.replyto", "Reply-To differs from sender domain",
              f"From {from_addr[1]} but replies go to {reply_addr[1]}.", 15, "content", reply_addr[1])
    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []) or []).lower()
    info["Authentication-Results"] = auth[:500]
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        if m and m.group(1) in ("fail", "softfail", "none", "permerror"):
            f.add(f"mail.{mech}", f"{mech.upper()} check: {m.group(1)}",
                  f"The sending server is not authorised for {from_dom or 'the sender domain'}.", 12, "network", m.group(0))
    freemail_doms = ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com")
    if run_live and config.LIVE_CHECKS and from_dom and from_dom not in freemail_doms:
        dns_info = osint.dns_forensics(from_dom)
        if dns_info:
            info["Live-DNS-MX"] = ", ".join(dns_info.get("mx") or []) or "none"
            info["Live-DNS-SPF"] = dns_info.get("spf") or "missing"
            info["Live-DNS-DMARC"] = dns_info.get("dmarc") or "missing"
            if not dns_info.get("mx") and not dns_info.get("a"):
                f.add("mail.dead_domain", "Sender domain has no live MX or A record",
                      f"{from_dom} cannot receive mail in live DNS — likely spoofed or taken down.", 16, "network", from_dom)
            elif not dns_info.get("dmarc") and not urlscan.is_official(from_dom):
                f.add("mail.no_dmarc", "Sender domain publishes no DMARC policy",
                      f"Live DNS lookup found no _dmarc.{dns_info.get('registrable', from_dom)} TXT policy.", 8, "network", from_dom)
    display = from_addr[0].lower()
    for b in BRANDS:
        if any(k in display for k in [b["name"].lower()] + [k for k in b["keywords"] if len(k) > 3]):
            if from_dom and not urlscan.is_official(from_dom):
                f.add("mail.display_spoof", f"Sender name claims {b['name']}",
                      f"Display name '{from_addr[0]}' but address is {from_addr[1]}.", 20, "content", from_addr[1])
            break
    if from_dom in freemail_doms and _brand_mentions(info["Subject"] + text[:2000]):
        f.add("mail.freemail", "Official-looking message from a free mailbox",
              f"Sent from {from_dom}; banks and departments use their own domains.", 12, "content", from_addr[1])
    body = msg.get_body(preferencelist=("plain", "html"))
    info["_body"] = body.get_content() if body else ""
    return info


def analyze(text: str, channel: str = "sms", sender: str = "", run_live: bool = True) -> dict:
    f = Findings()
    raw = text.strip()
    header_info = _email_headers(raw, f, run_live=run_live) if channel == "email" else {}
    body = header_info.pop("_body", "") or raw
    norm = re.sub(r"[ \t]+", " ", body)

    categories: dict[str, int] = {}
    for code, category, title, weight, patterns in RULES:
        hits = _hits(patterns, norm)
        if hits:
            w = weight + min(8, 4 * (len(hits) - 1))
            f.add(code, title, f"Matched phrasing typical of '{category}' scams.", w, "content", " | ".join(hits[:3]))
            categories[category] = categories.get(category, 0) + w

    urg = _hits(URGENCY, norm)
    if urg:
        f.add("msg.urgency", "Urgency / deadline pressure", "Artificial deadlines push victims to act before verifying.",
              min(18, 10 + 4 * (len(urg) - 1)), "content", " | ".join(urg[:3]))
    cred = _hits(CREDENTIAL_ASK, norm)
    if cred:
        f.add("msg.credentials", "Asks for OTP / PIN / remote access",
              "No bank, wallet or government office asks for OTP, UPI PIN or screen-sharing apps.", 30, "content",
              " | ".join(cred[:3]))
    cta = _hits(CALL_TO_ACTION, norm)

    brands = _brand_mentions(norm)
    extracted = ioc_mod.extract(body, "message body")
    groups = ioc_mod.group(extracted)

    # sender analysis
    sender = sender.strip()
    sender_info = {"value": sender}
    if sender:
        s_phone = ioc_mod.normalise_phone(sender)
        if s_phone:
            sender_info["type"] = "personal mobile number"
            extracted.append({"etype": "phone", "value": s_phone, "display": f"+91 {s_phone[3:8]} {s_phone[8:]}",
                              "context": "sender"})
            if brands or any(k in categories for k in ("Fake KYC / account block", "Electricity bill disconnection",
                                                       "Refund / tax / subsidy lure", "Digital arrest / impersonation of police")):
                f.add("msg.sender_mobile", "Official-sounding message sent from a personal mobile number",
                      f"Banks, DISCOMs and government send bulk SMS from registered headers (e.g. AX-SBIINB), not from {sender}.",
                      22, "content", sender)
        elif TRAI_HEADER.match(sender.upper()) or osint.decode_trai_header(sender):
            trai = osint.decode_trai_header(sender)
            if trai and trai["valid_dlt_prefix"]:
                sender_info["type"] = f"TRAI DLT header ({trai['operator']} · {trai['circle']} · {trai['stream']})"
                sender_info["trai"] = trai
                sender_info["note"] = trai["nodal_hint"]
                if (trai["stream_code"] == "P" or trai["is_promotional_numeric"]) and (
                    brands or any(k in categories for k in ("Fake KYC / account block", "Electricity bill disconnection",
                                                           "Digital arrest / impersonation of police"))
                ):
                    f.add("msg.promo_header_mismatch", "Promotional SMS header used for official / banking alert",
                          f"Header {trai['header']} is a promotional route ({trai['operator']}, {trai['circle']}) — real banks and agencies use Service/Transactional (-S/-T/-G) headers.",
                          16, "content", trai["header"])
            elif trai:
                sender_info["type"] = "Invalid / spoofed SMS header prefix"
                sender_info["trai"] = trai
                f.add("msg.fake_dlt_header", "Sender header uses unrecognised TRAI TSP / circle prefix",
                      trai["nodal_hint"], 16, "content", trai["header"])
            else:
                sender_info["type"] = "TRAI DLT registered header"
                sender_info["note"] = "Registered headers can still be abused by compromised telemarketers; verify against the entity."
        elif sender.startswith("+") and not sender.startswith("+91"):
            sender_info["type"] = "international number"
            f.add("msg.sender_foreign", "Sent from an international number",
                  f"{sender}: job and investment scams routinely use foreign WhatsApp numbers.", 15, "content", sender)

    if brands and (f.items or groups.get("url")):
        f.add("msg.brand_claim", "Claims to be from " + ", ".join(brands[:3]),
              "Brand names are combined with risk indicators above.", 8, "content", ", ".join(brands[:3]))

    # embedded links
    link_reports = []
    urls = [u["display"] for u in groups.get("url", [])]
    bare = [d["value"] for d in groups.get("domain", []) if not any(d["value"] in u.lower() for u in urls)]
    for target in (urls + bare)[:6]:
        rep = urlscan.analyze(target, run_live=run_live)
        link_reports.append({"url": rep["url"], "score": rep["findings"].score, "level": rep["findings"].level,
                             "findings": rep["findings"].to_list(), "info": rep["info"],
                             "net": {k: v for k, v in rep["net"].items() if k != "_body"}})
        for it in rep["findings"].items:
            if it.weight > 0:
                f.add("link." + it.code, "Link: " + it.title, it.detail, it.weight, it.group, it.evidence or rep["url"])
            elif it.code == "domain.official":
                f.add("link.official", "Link points to an official domain", it.detail, -10, "domain", rep["url"])
        if rep["net"].get("final_url"):
            for e in ioc_mod.extract(rep["net"]["final_url"], "link landing URL"):
                extracted.append(e)
        hosting = rep["net"].get("hosting") or {}
        if hosting.get("ip"):
            extracted.append({
                "etype": "ip",
                "value": hosting["ip"],
                "display": hosting["ip"],
                "context": f"link hosting · {hosting.get('org', '')} {hosting.get('country', '')}".strip(),
            })

    if cta and (urls or bare or groups.get("phone")):
        f.add("msg.cta", "Pushes the reader to click, call or install", " | ".join(cta[:3]), 6, "content", " | ".join(cta[:2]))
    if groups.get("upi") or groups.get("bank_account"):
        f.add("msg.payment_id", "Contains payment identifiers",
              "UPI IDs / bank accounts in unsolicited messages usually point to mule accounts.", 12, "content",
              ", ".join(x["display"] for x in (groups.get("upi", []) + groups.get("bank_account", []))[:3]))
    if not f.items and len(norm) > 0:
        f.add("msg.no_signal", "No scam indicators matched",
              "Rule set did not match. Absence of indicators is not proof of safety.", 0, "content")

    category = max(categories, key=categories.get) if categories else ("Suspicious link" if link_reports and f.score >= 30 else "")
    return {"findings": f, "category": category, "channel": channel, "sender": sender_info, "brands": brands,
            "email_headers": header_info, "links": link_reports, "iocs": extracted, "body": body}
