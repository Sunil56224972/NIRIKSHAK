"""Live OSINT, financial, telecom, DNS, IP/Shodan, and blockchain enrichment.

Every lookup in this module queries real public authorities / registries / explorers
without requiring paid API keys, enforces tight network timeouts so serverless
requests stay fast, and degrades gracefully to partial/empty dicts on network errors.

Live sources used:
  * Google DNS-over-HTTPS (dns.google/resolve) — A, AAAA, CNAME, MX, NS, TXT (SPF & DMARC)
  * Shodan InternetDB (internetdb.shodan.io) — open ports, CPEs, hostnames, tags, CVEs
  * ipwho.is + RIPEstat (stat.ripe.net) — BGP ASN, ISP/org, geolocation, RIR abuse e-mail
  * Certificate Transparency (crt.sh) — issued TLS certificates & sibling subdomains
  * Razorpay RBI IFSC Directory (ifsc.razorpay.com) — live bank, branch, address, city, state
  * Mempool.space (BTC), TronGrid (TRON + USDT TRC-20), PublicNode ETH JSON-RPC — live wallet stats
  * CIRCL hashlookup (hashlookup.circl.lu) — NIST NSRL / known-reference SHA-256 lookup
  * TRAI DLT header structure — Indian TSP operator, telecom circle & message stream decoder
"""
from __future__ import annotations

import html as html_mod
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import requests

from .. import config
from . import iocs as ioc_mod
from . import netintel

USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

# Official TRAI DLT two-character prefix mapping: <Access Provider><Service Area / Circle>
TRAI_OPERATORS = {
    "A": "Bharti Airtel",
    "B": "BSNL",
    "J": "Reliance Jio",
    "V": "Vodafone Idea (Vi)",
    "M": "MTNL",
    "T": "Tata Teleservices",
    "Q": "Quadrant Televentures",
    "R": "Reliance Communications",
}

TRAI_CIRCLES = {
    "A": "Andhra Pradesh",
    "B": "Bihar & Jharkhand",
    "C": "Chennai",
    "D": "Delhi NCR",
    "E": "Kerala",
    "G": "Gujarat",
    "H": "Haryana",
    "I": "Himachal Pradesh",
    "J": "Jammu & Kashmir",
    "K": "Kolkata",
    "L": "Kerala / Karnataka",
    "M": "Mumbai",
    "N": "North East",
    "O": "Odisha",
    "P": "Punjab",
    "R": "Rajasthan",
    "S": "Assam",
    "T": "Tamil Nadu",
    "U": "Uttar Pradesh (East)",
    "W": "Uttar Pradesh (West)",
    "X": "Karnataka",
    "Y": "Madhya Pradesh & Chhattisgarh",
    "Z": "West Bengal",
}

TRAI_STREAMS = {
    "S": "Service Implicit (banking/OTP/alerts)",
    "T": "Transactional (OTP)",
    "P": "Promotional (marketing)",
    "G": "Government (exempted official alerts)",
}

DISPOSABLE_CNAME_SUFFIXES = (
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "pages.dev", "workers.dev",
    "vercel.app", "netlify.app", "github.io", "onrender.com", "railway.app",
    "herokuapp.com", "glitch.me", "surge.sh", "000webhostapp.com", "duckdns.org",
)


def _tmo(seconds: float = 4.5) -> float:
    return min(seconds, max(2.5, config.NET_TIMEOUT))


# ----------------------------------------------------------------------------- TRAI DLT & Telecom
def decode_trai_header(raw: str) -> dict[str, Any] | None:
    """Decode an Indian SMS sender header (e.g. VM-SBIINB-S, AX-HDFCBK, JD-612345-P)."""
    s = (raw or "").strip().upper()
    m = re.match(r"^([A-Z])([A-Z])-([A-Z0-9]{3,9})(?:-([A-Z]))?$", s)
    if not m:
        return None
    op_code, cir_code, principal, stream_code = m.group(1), m.group(2), m.group(3), m.group(4) or ""
    op = TRAI_OPERATORS.get(op_code)
    circle = TRAI_CIRCLES.get(cir_code)
    stream = TRAI_STREAMS.get(stream_code, "Unspecified (legacy / pre-suffix format)" if not stream_code else f"Unknown (-{stream_code})")
    valid_codes = bool(op and circle)
    numeric_promo = principal.isdigit()
    return {
        "header": s,
        "operator_code": op_code,
        "operator": op or f"Unrecognised TSP code ({op_code})",
        "circle_code": cir_code,
        "circle": circle or f"Unrecognised circle code ({cir_code})",
        "entity_id_tag": principal,
        "stream_code": stream_code,
        "stream": stream,
        "is_promotional_numeric": numeric_promo,
        "valid_dlt_prefix": valid_codes,
        "nodal_hint": (
            f"Serve Sec 94 BNSS DLT Entity KYC request to {op} Nodal Officer ({circle} circle) for header '{principal}'."
            if valid_codes else "Prefix does not match standard TRAI TSP/circle codes — likely spoofed SMS gateway / grey route."
        ),
    }


def inspect_phone(raw: str) -> dict[str, Any]:
    """Classify an Indian/international phone number and provide nodal action guidance."""
    s = (raw or "").strip()
    norm = ioc_mod.normalise_phone(s)
    digits = re.sub(r"\D", "", s)
    if norm:
        ten = norm[3:]
        return {
            "normalized": norm,
            "country": "India (+91)",
            "type": "Indian 10-digit mobile (E.164)",
            "series_prefix": ten[:4],
            "mnp_note": "Exact TSP/circle requires DoT/TSP HLR or SDR lookup due to Mobile Number Portability (MNP).",
            "nodal_action": (
                "Request Subscriber Details Record (SDR), CAF/e-KYC, IMEI history & CDR under Sec 94 BNSS; "
                "report on Sanchar Saathi (Chakshu / DoT ASTR) for fraudulent connection blocking."
            ),
        }
    if digits.startswith(("1800", "1860")) and len(digits) == 11:
        return {
            "normalized": digits,
            "country": "India",
            "type": "Toll-free / shared-cost number (1800/1860)",
            "nodal_action": "Verify enterprise toll-free subscriber allocation with the routing Access Provider.",
        }
    if s.startswith("+") and not s.startswith("+91"):
        cc = digits[:3]
        return {
            "normalized": "+" + digits,
            "country": f"International (+{cc}…)",
            "type": "Foreign / virtual VoIP number (commonly used for WhatsApp/Telegram scam accounts)",
            "nodal_action": "Send WhatsApp / Telegram Law Enforcement Request (IP logs, registration timestamp, linked device info).",
        }
    return {"normalized": s, "type": "Unclassified telephone identifier"}


# ----------------------------------------------------------------------------- DNS-over-HTTPS (DoH)
def _doh_query(name: str, rrtype: str) -> list[dict]:
    r = netintel.get_session().get(
        "https://dns.google/resolve",
        params={"name": name, "type": rrtype},
        headers={"Accept": "application/dns-json"},
        timeout=_tmo(4.0),
    )
    if not r.ok:
        return []
    body = r.json()
    if body.get("Status") != 0:
        return []
    return body.get("Answer") or []


def dns_forensics(domain: str) -> dict[str, Any]:
    """Query live DNS records (A, AAAA, CNAME, MX, NS, SPF, DMARC) via Google DoH."""
    host = (domain or "").strip().lower().strip(".")
    if not host or ioc_mod.IPV4_RE.fullmatch(host):
        return {}
    reg = host
    try:
        from . import urlscan
        reg = urlscan.registrable(host)
    except Exception:
        pass

    out: dict[str, Any] = {
        "host": host,
        "registrable": reg,
        "a": [],
        "aaaa": [],
        "cname": [],
        "mx": [],
        "ns": [],
        "spf": "",
        "dmarc": "",
        "dmarc_policy": "",
    }

    jobs = {
        "A": (host, "A"),
        "AAAA": (host, "AAAA"),
        "CNAME": (host, "CNAME"),
        "MX": (reg, "MX"),
        "NS": (reg, "NS"),
        "TXT": (reg, "TXT"),
        "DMARC": (f"_dmarc.{reg}", "TXT"),
    }
    with ThreadPoolExecutor(max_workers=5) as pool:
        futs = {k: pool.submit(_doh_query, qn, qt) for k, (qn, qt) in jobs.items()}
        ans = {}
        for k, fut in futs.items():
            try:
                ans[k] = fut.result(timeout=_tmo(4.5))
            except Exception:
                ans[k] = []

    for rec in ans.get("A", []):
        if rec.get("type") == 1 and rec.get("data"):
            out["a"].append(str(rec["data"]).strip())
        elif rec.get("type") == 5 and rec.get("data"):
            out["cname"].append(str(rec["data"]).strip().rstrip(".").lower())
    for rec in ans.get("AAAA", []):
        if rec.get("type") == 28 and rec.get("data"):
            out["aaaa"].append(str(rec["data"]).strip())
    for rec in ans.get("CNAME", []):
        if rec.get("type") == 5 and rec.get("data"):
            cn = str(rec["data"]).strip().rstrip(".").lower()
            if cn not in out["cname"]:
                out["cname"].append(cn)
    for rec in ans.get("MX", []):
        if rec.get("type") == 15 and rec.get("data"):
            mx = str(rec["data"]).strip().rstrip(".").lower()
            if mx and mx != "0 .":
                out["mx"].append(mx)
    for rec in ans.get("NS", []):
        if rec.get("type") == 2 and rec.get("data"):
            out["ns"].append(str(rec["data"]).strip().rstrip(".").lower())
    for rec in ans.get("TXT", []):
        txt = str(rec.get("data") or "").strip().strip('"')
        if txt.lower().startswith("v=spf1"):
            out["spf"] = txt[:240]
            break
    for rec in ans.get("DMARC", []):
        txt = str(rec.get("data") or "").strip().strip('"')
        if "v=dmarc1" in txt.lower():
            out["dmarc"] = txt[:240]
            pm = re.search(r"\bp\s*=\s*([a-zA-Z]+)", txt, re.I)
            if pm:
                out["dmarc_policy"] = pm.group(1).lower()
            break

    out["a"] = sorted(set(out["a"]))[:10]
    out["aaaa"] = sorted(set(out["aaaa"]))[:6]
    out["mx"] = sorted(set(out["mx"]))[:8]
    out["ns"] = sorted(set(out["ns"]))[:8]
    for cn in out["cname"]:
        for suf in DISPOSABLE_CNAME_SUFFIXES:
            if cn == suf or cn.endswith("." + suf):
                out["disposable_cname"] = cn
                break
    return out


# ----------------------------------------------------------------------------- IP / ASN / Abuse / Shodan InternetDB
def _ipwhois(ip: str) -> dict[str, Any]:
    r = netintel.get_session().get(f"https://ipwho.is/{ip}", timeout=_tmo(4.5))
    if not r.ok:
        return {}
    d = r.json()
    if not d.get("success", True):
        return {}
    conn = d.get("connection") or {}
    return {
        "asn": f"AS{conn['asn']}" if conn.get("asn") else "",
        "isp": conn.get("isp") or "",
        "org": conn.get("org") or "",
        "isp_domain": conn.get("domain") or "",
        "country": d.get("country") or "",
        "country_code": d.get("country_code") or "",
        "region": d.get("region") or "",
        "city": d.get("city") or "",
    }


def _ripe_abuse(ip: str) -> list[str]:
    r = netintel.get_session().get(
        "https://stat.ripe.net/data/abuse-contact-finder/data.json",
        params={"resource": ip},
        timeout=_tmo(4.5),
    )
    if not r.ok:
        return []
    contacts = (r.json().get("data") or {}).get("abuse_contacts") or []
    return [str(c).strip() for c in contacts if c and "@" in str(c)][:4]


def _shodan_internetdb(ip: str) -> dict[str, Any]:
    r = netintel.get_session().get(f"https://internetdb.shodan.io/{ip}", timeout=_tmo(4.0))
    if not r.ok:
        return {}
    d = r.json()
    if not isinstance(d, dict) or not d.get("ip"):
        return {}
    return {
        "ports": sorted(int(p) for p in (d.get("ports") or []) if isinstance(p, int))[:25],
        "hostnames": [str(h) for h in (d.get("hostnames") or [])[:8]],
        "cpes": [str(c) for c in (d.get("cpes") or [])[:8]],
        "tags": [str(t) for t in (d.get("tags") or [])[:10]],
        "vulns": [str(v) for v in (d.get("vulns") or [])[:12]],
        "vuln_count": len(d.get("vulns") or []),
    }


def _reverse_ptr(ip: str) -> str:
    try:
        old_tmo = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(2.0)
            host, _, _ = socket.gethostbyaddr(ip)
            return (host or "").rstrip(".").lower()
        finally:
            socket.setdefaulttimeout(old_tmo)
    except Exception:
        return ""


def inspect_ip(ip: str) -> dict[str, Any]:
    """Comprehensive live IP attribution: ASN/ISP, geolocation, RIR abuse e-mail, PTR, and Shodan InternetDB."""
    ip = (ip or "").strip()
    if not netintel.is_public_ip(ip):
        return {"ip": ip, "public": False}

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_who = pool.submit(_ipwhois, ip)
        f_ab = pool.submit(_ripe_abuse, ip)
        f_sh = pool.submit(_shodan_internetdb, ip)
        f_ptr = pool.submit(_reverse_ptr, ip)
        f_rdap = pool.submit(netintel.rdap_ip, ip)

        who, abuse, shodan, ptr, rdap = {}, [], {}, "", {}
        try:
            who = f_who.result(timeout=_tmo(5.0))
        except Exception:
            pass
        try:
            abuse = f_ab.result(timeout=_tmo(5.0))
        except Exception:
            pass
        try:
            shodan = f_sh.result(timeout=_tmo(4.5))
        except Exception:
            pass
        try:
            ptr = f_ptr.result(timeout=2.5)
        except Exception:
            pass
        try:
            rdap = f_rdap.result(timeout=_tmo(5.0))
        except Exception:
            pass

    org = who.get("org") or who.get("isp") or rdap.get("org") or ""
    country = who.get("country") or rdap.get("country") or ""
    loc_parts = [p for p in (who.get("city"), who.get("region"), country) if p]
    return {
        "ip": ip,
        "public": True,
        "ptr": ptr,
        "asn": who.get("asn", ""),
        "isp": who.get("isp", ""),
        "org": org,
        "network": rdap.get("network", ""),
        "range": rdap.get("range", ""),
        "country": country,
        "country_code": who.get("country_code", ""),
        "region": who.get("region", ""),
        "city": who.get("city", ""),
        "location": ", ".join(dict.fromkeys(loc_parts)),
        "abuse_contacts": abuse,
        "ports": shodan.get("ports", []),
        "shodan_tags": shodan.get("tags", []),
        "shodan_hostnames": shodan.get("hostnames", []),
        "cpes": shodan.get("cpes", []),
        "vulns": shodan.get("vulns", []),
        "vuln_count": shodan.get("vuln_count", 0),
    }


# ----------------------------------------------------------------------------- Certificate Transparency (crt.sh)
def ct_subdomains(domain: str) -> dict[str, Any]:
    """Query Certificate Transparency logs via crt.sh for certificate history & sibling subdomains."""
    reg = (domain or "").strip().lower().strip(".")
    if not reg or ioc_mod.IPV4_RE.fullmatch(reg):
        return {}
    try:
        r = netintel.get_session().get(
            "https://crt.sh/",
            params={"q": reg, "output": "json"},
            timeout=_tmo(4.0),
        )
        if not r.ok:
            return {}
        rows = r.json()
        if not isinstance(rows, list):
            return {}
        subs: set[str] = set()
        issuers: set[str] = set()
        earliest = ""
        for entry in rows[:250]:
            nv = str(entry.get("name_value") or "")
            for ln in nv.splitlines():
                h = ln.strip().lower().lstrip("*.")
                if h and (h == reg or h.endswith("." + reg)):
                    subs.add(h)
            iss = str(entry.get("issuer_name") or "")
            m_cn = re.search(r"O=([^,]+)", iss)
            if m_cn:
                issuers.add(m_cn.group(1).strip().strip('"'))
            nb = str(entry.get("not_before") or "")[:10]
            if nb and (not earliest or nb < earliest):
                earliest = nb
        sibling_hosts = sorted(s for s in subs if s != reg)[:15]
        return {
            "cert_count": len(rows),
            "earliest_cert": earliest,
            "subdomains": sibling_hosts,
            "issuers": sorted(issuers)[:5],
        }
    except Exception:
        return {}


# ----------------------------------------------------------------------------- Live Banking / RBI IFSC Directory
def lookup_ifsc(code: str) -> dict[str, Any] | None:
    """Resolve an Indian 11-character IFSC code against the live Razorpay RBI IFSC directory."""
    ifsc = (code or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", ifsc):
        return None
    try:
        r = netintel.get_session().get(f"https://ifsc.razorpay.com/{ifsc}", timeout=_tmo(4.0))
        if r.status_code == 404:
            return {"ifsc": ifsc, "valid": False}
        if not r.ok:
            return None
        d = r.json()
        return {
            "ifsc": ifsc,
            "valid": True,
            "bank": d.get("BANK") or ioc_mod.IFSC_BANKS.get(ifsc[:4], ""),
            "branch": d.get("BRANCH") or "",
            "address": d.get("ADDRESS") or "",
            "city": d.get("CITY") or "",
            "district": d.get("DISTRICT") or "",
            "state": d.get("STATE") or "",
            "micr": d.get("MICR") or "",
            "contact": d.get("CONTACT") or "",
            "upi": bool(d.get("UPI")),
            "rtgs": bool(d.get("RTGS")),
            "neft": bool(d.get("NEFT")),
            "imps": bool(d.get("IMPS")),
        }
    except Exception:
        return None


def inspect_upi(vpa: str) -> dict[str, Any]:
    """Decode a UPI Virtual Payment Address into PSP bank, handle, and NPCI/bank nodal guidance."""
    s = (vpa or "").strip().lower()
    if "@" not in s:
        return {"vpa": s}
    user, handle = s.split("@", 1)
    psp_bank = ioc_mod.upi_bank(handle)
    likely_mobile = ioc_mod.normalise_phone(user)
    return {
        "vpa": s,
        "user_part": user,
        "handle": "@" + handle,
        "psp_bank": psp_bank or "Unlisted / custom NPCI PSP handle",
        "embedded_mobile": likely_mobile or "",
        "nodal_action": (
            f"Serve Sec 94 BNSS notice to {psp_bank or ('PSP for @' + handle)} / NPCI to obtain linked "
            "savings/current account number, IFSC, beneficiary KYC, device IP, and onward money-trail layers."
        ),
    }


# ----------------------------------------------------------------------------- Live Blockchain / Crypto Wallet Forensics
def inspect_crypto(address: str) -> dict[str, Any] | None:
    """Query live public blockchain explorers for BTC, TRON (TRX + USDT TRC-20), and ETH/EVM wallets."""
    addr = (address or "").strip()
    if not addr:
        return None

    # 1. TRON (T... — primary rail for USDT TRC-20 task/investment scams)
    if addr.startswith("T") and 33 <= len(addr) <= 35:
        try:
            r = netintel.get_session().get(f"https://api.trongrid.io/v1/accounts/{addr}", timeout=_tmo(5.0))
            if not r.ok:
                return None
            rows = r.json().get("data") or []
            if not rows:
                return {
                    "network": "TRON (TRX / TRC-20)",
                    "address": addr,
                    "active": False,
                    "trx_balance": 0.0,
                    "usdt_trc20_balance": 0.0,
                    "note": "Address valid (Base58Check) but has no on-chain activation yet.",
                }
            acc = rows[0]
            trx = round(int(acc.get("balance") or 0) / 1_000_000, 6)
            usdt = 0.0
            trc20_list = acc.get("trc20") or []
            for tok in trc20_list:
                if isinstance(tok, dict) and USDT_TRC20_CONTRACT in tok:
                    usdt = round(int(tok[USDT_TRC20_CONTRACT]) / 1_000_000, 2)
                    break
            ct = acc.get("create_time")
            lt = acc.get("latest_opration_time")
            created_iso = datetime.fromtimestamp(ct / 1000, tz=timezone.utc).strftime("%Y-%m-%d") if ct else ""
            last_iso = datetime.fromtimestamp(lt / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if lt else ""
            return {
                "network": "TRON (TRX / USDT TRC-20)",
                "address": addr,
                "active": True,
                "trx_balance": trx,
                "usdt_trc20_balance": usdt,
                "trc20_token_count": len(trc20_list),
                "created": created_iso,
                "last_activity": last_iso,
                "explorer": f"https://tronscan.org/#/address/{addr}",
            }
        except Exception:
            return None

    # 2. Bitcoin (legacy 1.../3... or native SegWit bc1...)
    if addr.lower().startswith("bc1") or (addr[0] in "13" and 26 <= len(addr) <= 35):
        q_addr = addr.lower() if addr.lower().startswith("bc1") else addr
        try:
            r = netintel.get_session().get(f"https://mempool.space/api/address/{q_addr}", timeout=_tmo(5.0))
            if not r.ok:
                return None
            cs = r.json().get("chain_stats") or {}
            funded = int(cs.get("funded_txo_sum") or 0)
            spent = int(cs.get("spent_txo_sum") or 0)
            txs = int(cs.get("tx_count") or 0)
            return {
                "network": "Bitcoin (BTC)",
                "address": q_addr,
                "active": txs > 0,
                "tx_count": txs,
                "total_received_btc": round(funded / 100_000_000, 8),
                "total_sent_btc": round(spent / 100_000_000, 8),
                "balance_btc": round((funded - spent) / 100_000_000, 8),
                "explorer": f"https://mempool.space/address/{q_addr}",
            }
        except Exception:
            return None

    # 3. Ethereum / EVM (0x...)
    if re.fullmatch(r"0x[a-fA-F0-9]{40}", addr):
        try:
            rpc = "https://ethereum-rpc.publicnode.com"
            r_bal = netintel.get_session().post(
                rpc,
                json={"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [addr, "latest"]},
                timeout=_tmo(4.5),
            )
            r_tx = netintel.get_session().post(
                rpc,
                json={"jsonrpc": "2.0", "id": 2, "method": "eth_getTransactionCount", "params": [addr, "latest"]},
                timeout=_tmo(4.5),
            )
            if not (r_bal.ok and r_tx.ok):
                return None
            wei = int(r_bal.json().get("result") or "0x0", 16)
            nonce = int(r_tx.json().get("result") or "0x0", 16)
            eth_val = round(wei / 10**18, 6)
            return {
                "network": "Ethereum / EVM",
                "address": addr,
                "active": nonce > 0 or wei > 0,
                "eth_balance": eth_val,
                "outgoing_tx_count": nonce,
                "explorer": f"https://etherscan.io/address/{addr}",
            }
        except Exception:
            return None

    return None


# ----------------------------------------------------------------------------- CIRCL Hashlookup & Telegram Preview
def hashlookup_sha256(sha256: str) -> dict[str, Any] | None:
    """Query CIRCL Luxembourg NSRL / reference hash database for a SHA-256 digest."""
    h = (sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", h):
        return None
    try:
        r = netintel.get_session().get(f"https://hashlookup.circl.lu/lookup/sha256/{h}", timeout=_tmo(4.0))
        if r.status_code == 404:
            return {"sha256": h, "known_reference": False}
        if not r.ok:
            return None
        d = r.json()
        return {
            "sha256": h,
            "known_reference": True,
            "file_name": d.get("FileName") or "",
            "product_name": (d.get("ProductCode") or {}).get("ProductName", "") if isinstance(d.get("ProductCode"), dict) else "",
            "source": d.get("db") or "CIRCL NSRL",
        }
    except Exception:
        return None


def inspect_telegram(handle_or_url: str) -> dict[str, Any]:
    """Fetch public Telegram t.me preview metadata (title, subscriber count, bio, bot flag) when reachable."""
    s = (handle_or_url or "").strip()
    h = re.sub(r"^(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/", "", s, flags=re.I).strip("/@ ")
    is_bot = h.lower().endswith("bot")
    out: dict[str, Any] = {
        "handle": "@" + h if h and not h.startswith("+") else h,
        "url": f"https://t.me/{h}" if h else s,
        "likely_bot": is_bot,
    }
    if not h or h.startswith("+"):
        out["kind"] = "Private invite link"
        return out
    try:
        r = netintel.get_session().get(f"https://t.me/{h}", timeout=_tmo(3.5))
        if r.ok and "tgme_page" in r.text:
            m_title = re.search(r'<div class="tgme_page_title"[^>]*>\s*<span[^>]*>([^<]+)</span>', r.text)
            m_extra = re.search(r'<div class="tgme_page_extra"[^>]*>([^<]+)</div>', r.text)
            m_desc = re.search(r'<div class="tgme_page_description"[^>]*>(.*?)</div>', r.text, re.S)
            if m_title:
                out["title"] = html_mod.unescape(m_title.group(1).strip())[:160]
            if m_extra:
                out["members_or_status"] = html_mod.unescape(m_extra.group(1).strip())[:120]
            if m_desc:
                clean_desc = re.sub(r"<[^>]+>", " ", m_desc.group(1))
                out["description"] = html_mod.unescape(re.sub(r"\s+", " ", clean_desc).strip())[:300]
            extra_low = (out.get("members_or_status") or "").lower()
            if "subscribers" in extra_low:
                out["kind"] = "Public channel"
            elif "members" in extra_low:
                out["kind"] = "Public group"
            elif is_bot:
                out["kind"] = "Telegram bot"
            else:
                out["kind"] = "Telegram user / handle"
    except Exception:
        pass
    return out


# ----------------------------------------------------------------------------- Unified Identifier Live Enrichment
def enrich_identifier(etype: str, value: str) -> dict[str, Any]:
    """Run live OSINT enrichment for any NIRIKSHAK identifier type."""
    etype = (etype or "").strip()
    val = (value or "").strip()
    if not val:
        return {}

    if etype == "ifsc":
        res = lookup_ifsc(val)
        return {"kind": "ifsc", "data": res} if res else {}

    if etype == "upi":
        return {"kind": "upi", "data": inspect_upi(val)}

    if etype == "phone":
        return {"kind": "phone", "data": inspect_phone(val)}

    if etype == "ip":
        return {"kind": "ip", "data": inspect_ip(val)}

    if etype == "crypto":
        res = inspect_crypto(val)
        return {"kind": "crypto", "data": res} if res else {}

    if etype == "telegram":
        return {"kind": "telegram", "data": inspect_telegram(val)}

    if etype == "apk_sha256":
        res = hashlookup_sha256(val)
        return {"kind": "apk_sha256", "data": res} if res else {}

    if etype in ("domain", "url", "email"):
        from . import urlscan
        host = val
        if etype == "url":
            host = ioc_mod.host_of(val)
        elif etype == "email" and "@" in val:
            host = val.split("@", 1)[1].lower().strip()
        if not host:
            return {}
        reg = urlscan.registrable(host)
        official = urlscan.is_official(host)
        with ThreadPoolExecutor(max_workers=4) as pool:
            f_dns = pool.submit(dns_forensics, host)
            f_who = pool.submit(netintel.rdap_domain, reg) if not ioc_mod.IPV4_RE.fullmatch(host) else None
            f_ct = pool.submit(ct_subdomains, reg) if (not official and not ioc_mod.IPV4_RE.fullmatch(host)) else None
            dns_d = f_dns.result(timeout=_tmo(5.0)) if f_dns else {}
            who_d = {}
            if f_who:
                try:
                    who_d = f_who.result(timeout=_tmo(5.5)) or {}
                except Exception:
                    who_d = {}
            ct_d = f_ct.result(timeout=_tmo(4.5)) if f_ct else {}
        ip_intel = {}
        ips = dns_d.get("a") or netintel.resolve(host)
        if ips and netintel.is_public_ip(ips[0]):
            ip_intel = inspect_ip(ips[0])
        return {
            "kind": "domain_infra",
            "data": {
                "host": host,
                "registrable": reg,
                "official": official or "",
                "dns": dns_d,
                "whois": who_d,
                "hosting": ip_intel,
                "ct": ct_d,
            },
        }

    return {}
