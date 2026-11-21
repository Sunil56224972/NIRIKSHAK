"""Website analysis for Ponzi / MLM / betting / fake-loan / phishing pages.

Accepts a live URL (fetched through the SSRF-safe fetcher), a saved page
(.html / .htm / .mhtml / .txt), or a webpage screenshot (.png / .jpg / .webp / .bmp)
analysed via Tesseract (Linux/Docker) or Windows OCR.
"""
from __future__ import annotations

import email
import email.policy
import html as html_mod
import os
import re
import subprocess
import sys
import tempfile
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from . import iocs as ioc_mod
from . import urlscan
from .scoring import Findings

CONTENT_RULES: list[tuple[str, str, str, int, list[str]]] = [
    ("web.guaranteed", "Ponzi / investment", "Guaranteed or fixed high returns", 25, [
        r"(?:guaranteed|assured|fixed|risk[\s\-]?free|100\s?%\s*safe)\s.{0,25}(?:return|profit|income|interest)",
        r"\d{1,3}(?:\.\d+)?\s?%\s*(?:daily|per\s+day|/\s*day|a\s+day|weekly|per\s+week)",
        r"double\s+(?:your\s+)?(?:money|investment|capital)", r"(?:earn|get|profit)\s.{0,20}(?:₹|rs\.?|inr)\s?\d[\d,]*\s*(?:daily|every\s+day|per\s+day)",
    ]),
    ("web.mlm", "MLM / referral chain", "Referral-chain / MLM income structure", 22, [
        r"(?:level|team|matrix|binary|referral|sponsor|direct)\s+(?:income|bonus|commission|plan)",
        r"(?:downline|upline|joining\s+bonus|invite\s+(?:friends|members)\s.{0,20}(?:earn|commission))",
        r"(?:level|lv\.?)\s?\d+\s.{0,20}(?:commission|rebate|%)", r"invitation\s+code", r"(?:agent|promoter)\s+rebate",
    ]),
    ("web.betting", "Betting / gambling", "Betting / gambling indicators", 22, [
        r"(?:cricket|ipl|football|sports)\s+(?:betting|exchange|id)", r"\b(?:satta|matka|teen\s?patti|andar\s+bahar|aviator|dragon\s+tiger)\b",
        r"colou?r\s+(?:prediction|trading)", r"(?:first|1st)\s+deposit\s+bonus", r"\b(?:casino|roulette|baccarat|jackpot)\b",
        r"(?:wingo|win\s?go|big\s?small|k3\s+lottery|5d\s+lottery)", r"\bodds\b.{0,30}\b(?:back|lay)\b",
    ]),
    ("web.task_scam", "Task / recharge scam", "Task-earning / recharge-to-unlock scheme", 22, [
        r"(?:vip|level)\s?\d\s.{0,30}(?:recharge|deposit|unlock)", r"(?:grab|rob)\s+(?:order|task)s?",
        r"(?:daily|today'?s)\s+tasks?\s.{0,30}(?:earn|commission|complete)", r"(?:recharge|deposit)\s+(?:now|first)\s.{0,40}(?:withdraw|earn)",
        r"(?:like|rating|review)\s.{0,20}tasks?",
    ]),
    ("web.loan", "Fake loan", "Instant loan without checks", 20, [
        r"loan\s.{0,30}(?:in|within)\s+\d+\s*(?:minutes?|mins?)", r"(?:no|without)\s+(?:cibil|credit\s+score|documents?|income\s+proof)",
        r"(?:instant|quick)\s+(?:personal\s+)?loan", r"(?:approval|disbursal)\s+(?:in|within)\s+\d+\s*(?:minutes?|mins?|hours?)",
    ]),
    ("web.crypto", "Crypto / trading", "Crypto mining / trading platform claims", 16, [
        r"(?:cloud|crypto|bitcoin|usdt)\s+mining", r"(?:usdt|trc-?20)\s.{0,30}(?:deposit|recharge|withdraw)",
        r"(?:quant(?:itative)?|ai|robot)\s+trading", r"(?:institutional|block|otc)\s+(?:account|trading|ipo)",
    ]),
    ("web.withdraw", "Ponzi / investment", "Withdrawal restrictions / pay-to-withdraw", 15, [
        r"(?:minimum|min\.?)\s+withdraw(?:al)?\s.{0,20}(?:₹|rs|inr|\$)?\s?\d", r"withdraw(?:al)?\s+(?:fee|tax|charge)",
        r"(?:pay|deposit)\s.{0,20}(?:tax|fee)\s.{0,20}(?:to|before)\s+withdraw",
    ]),
    ("web.kyc_phish", "Credential phishing", "Banking / KYC credential harvesting text", 20, [
        r"(?:update|verify|complete)\s+(?:your\s+)?(?:e-?)?kyc", r"(?:net\s*banking|internet\s+banking)\s+(?:login|user\s*id)",
        r"(?:card\s+number|cvv|expiry\s+date|atm\s+pin|mpin)", r"(?:reward|redeem)\s+points?\s.{0,30}(?:expire|redeem)",
    ]),
    ("web.trust_bait", "Ponzi / investment", "Fake registration / trust claims", 8, [
        r"(?:registered|approved|certified)\s+(?:by|with)\s+(?:rbi|sebi|government|mca|iso)", r"(?:sebi|rbi)\s+(?:approved|registered|certified)",
        r"(?:company\s+)?registration\s+(?:no|number|certificate)", r"\bmsme\s+registered\b",
    ]),
]

SENSITIVE_INPUTS = {
    "password": r"pass(?:word)?|pwd|mpin|\bpin\b", "otp": r"\botp\b|one.?time", "card": r"card.?n(?:o|umber)|cvv|cvc|expir",
    "aadhaar": r"aadh?aar|uid", "pan": r"\bpan\b", "account": r"account.?n(?:o|umber)|ifsc", "upi_pin": r"upi.?pin",
}


def _from_mhtml(data: bytes) -> str:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            return part.get_content()
    return data.decode("utf-8", "replace")


_WIN_OCR_PS = (
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
    "Add-Type -AssemblyName System.Runtime.WindowsRuntime; "
    "$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { "
    "$_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and "
    "$_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]; "
    "function Await($t, $r) { $m = $asTaskGeneric.MakeGenericMethod($r); $nt = $m.Invoke($null, @($t)); $nt.Wait(-1) | Out-Null; $nt.Result }; "
    "[Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime] | Out-Null; "
    "[Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null; "
    "[Windows.Foundation.IAsyncOperation`1,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null; "
    "[Windows.Graphics.Imaging.BitmapDecoder,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null; "
    "$eng = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages(); "
    "if (-not $eng) { exit 2 }; "
    "$f = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($env:NK_OCR_FILE)) ([Windows.Storage.StorageFile]); "
    "$s = Await ($f.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream]); "
    "$d = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($s)) ([Windows.Graphics.Imaging.BitmapDecoder]); "
    "$b = Await ($d.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap]); "
    "$res = Await ($eng.RecognizeAsync($b)) ([Windows.Media.Ocr.OcrResult]); "
    "Write-Output $res.Text"
)


def _ocr(data: bytes) -> str | None:
    try:
        import io
        import pytesseract
        from PIL import Image
        return pytesseract.image_to_string(Image.open(io.BytesIO(data)), lang="eng")
    except Exception:
        pass

    if sys.platform == "win32":
        tmp_path = None
        try:
            import io
            from PIL import Image
            img = Image.open(io.BytesIO(data)).convert("RGB")
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
                tmp_path = tf.name
            img.save(tmp_path, format="PNG")
            env = os.environ.copy()
            env["NK_OCR_FILE"] = tmp_path
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _WIN_OCR_PS],
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            pass
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
    return None


def load_upload(filename: str, data: bytes) -> tuple[str, str]:
    """Return (html_or_text, kind) for an uploaded saved page."""
    name = filename.lower()
    if name.endswith((".mhtml", ".mht")):
        return _from_mhtml(data), "html"
    if name.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp")):
        text = _ocr(data)
        if text is None:
            raise ValueError("Screenshot OCR is unavailable on this host (install Tesseract OCR or upload the saved .html / .mhtml page).")
        return text, "text"
    if name.endswith((".html", ".htm", ".xhtml", ".php", ".asp", ".aspx")):
        return data.decode("utf-8", "replace"), "html"
    if name.endswith(".txt"):
        return data.decode("utf-8", "replace"), "text"
    raise ValueError("Unsupported file. Accepted: .html .htm .mhtml .txt (.png/.jpg with OCR installed).")


def inspect_html(html: str, base_url: str = "") -> tuple[Findings, dict, list[dict]]:
    f = Findings()
    soup = BeautifulSoup(html, "lxml")
    for t in soup(["script", "style", "noscript", "template"]):
        t.extract() if t.name in ("style", "template") else None
    scripts = soup.find_all("script")
    script_text = "\n".join(s.get_text(" ", strip=False) for s in scripts)[:400000]
    for s in scripts:
        s.extract()
    title = (soup.title.get_text(strip=True) if soup.title else "")[:200]
    text = soup.get_text(" ", strip=True)
    norm = re.sub(r"\s+", " ", text)

    page: dict = {"title": title, "text_chars": len(norm), "excerpt": norm[:1500]}
    meta_desc = soup.find("meta", attrs={"name": re.compile("description", re.I)})
    page["description"] = (meta_desc.get("content", "") if meta_desc else "")[:300]

    categories: dict[str, int] = {}
    for code, category, label, weight, patterns in CONTENT_RULES:
        hits = []
        for p in patterns:
            for m in re.finditer(p, norm, re.I):
                hits.append(m.group(0)[:80])
                if len(hits) >= 4:
                    break
        if hits:
            w = weight + min(10, 3 * (len(set(hits)) - 1))
            f.add(code, label, f"Page text matches '{category}' patterns ({len(set(hits))} distinct phrases).", w,
                  "content", " | ".join(list(dict.fromkeys(hits))[:3]))
            categories[category] = categories.get(category, 0) + w

    # forms harvesting sensitive data
    base_host = (urlsplit(base_url).hostname or "").lower()
    forms = []
    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action") or "") if base_url else (form.get("action") or "")
        fields = []
        for inp in form.find_all(["input", "select", "textarea"]):
            desc = " ".join(filter(None, [inp.get("name"), inp.get("id"), inp.get("placeholder"), inp.get("type"),
                                          inp.get("aria-label")])).lower()
            for kind, rx in SENSITIVE_INPUTS.items():
                if re.search(rx, desc):
                    fields.append(kind)
        fields = sorted(set(fields))
        forms.append({"action": action[:200], "method": (form.get("method") or "get").upper(), "sensitive": fields})
        if fields:
            f.add("web.form_sensitive", "Form collects " + ", ".join(fields),
                  f"Form submits to {action[:120] or '(same page)'}.", 18 if {"otp", "card", "upi_pin", "password"} & set(fields) else 10,
                  "content", ", ".join(fields))
            ah = (urlsplit(action).hostname or "").lower()
            if ah and base_host and urlscan.registrable(ah) != urlscan.registrable(base_host):
                f.add("web.form_offsite", "Form posts data to another domain",
                      f"Data entered on {base_host} is sent to {ah}.", 15, "network", ah)
    page["forms"] = forms

    # client-side tricks
    tricks = []
    for label, rx in [("eval/atob obfuscation", r"eval\s*\(\s*(?:atob|unescape|function\s*\(p,a,c,k,e)"),
                      ("right-click disabled", r"oncontextmenu\s*=|contextmenu.{0,40}preventDefault"),
                      ("devtools detection", r"devtools|debugger;\s*}"),
                      ("telegram bot exfiltration", r"api\.telegram\.org/bot"),
                      ("forced APK download", r"\.apk[\"']"),
                      ("copy-to-clipboard UPI", r"clipboard\.writeText\([^)]*@")]:
        if re.search(rx, script_text + html[:200000], re.I):
            tricks.append(label)
    if tricks:
        weight = 20 if "telegram bot exfiltration" in tricks else 8
        f.add("web.js_tricks", "Suspicious client-side code", ", ".join(tricks), weight, "content", ", ".join(tricks))
    page["script_flags"] = tricks

    # outbound links + identifiers from hrefs
    hrefs = []
    for a in soup.find_all(["a", "iframe", "link", "img", "form"], href=True) + soup.find_all(["iframe", "img"], src=True):
        v = a.get("href") or a.get("src")
        if v and not v.startswith(("#", "javascript:", "data:")):
            hrefs.append(urljoin(base_url, v) if base_url and not v.startswith(("tel:", "upi:", "mailto:", "whatsapp:")) else v)
    iframes = [i.get("src", "") for i in soup.find_all("iframe") if i.get("src")]
    page["iframes"] = iframes[:10]
    apk_links = sorted({h for h in hrefs if h.lower().split("?")[0].endswith(".apk")})
    if apk_links:
        f.add("web.apk_link", "Page distributes an Android APK", ", ".join(apk_links[:3]), 25, "app", apk_links[0])
    page["apk_links"] = apk_links[:10]
    tel = [h for h in hrefs if h.startswith("tel:")]

    blob = "\n".join([norm, "\n".join(hrefs), "\n".join(tel), script_text[:200000]])
    extracted = ioc_mod.extract(blob, "page content")
    # outbound links are noisy; keep only those leaving the site that are not common CDNs
    cdn = ("googleapis.com", "gstatic.com", "cloudflare.com", "jsdelivr.net", "bootstrapcdn.com", "jquery.com",
           "fontawesome.com", "google-analytics.com", "googletagmanager.com", "facebook.net", "unpkg.com", "w3.org")
    filtered = []
    for e in extracted:
        if e["etype"] in ("url", "domain"):
            h = ioc_mod.host_of(e["value"]) if e["etype"] == "url" else e["value"]
            if h.endswith(cdn) or (base_host and urlscan.registrable(h) == urlscan.registrable(base_host) and e["etype"] == "url"):
                continue
        filtered.append(e)
    groups = ioc_mod.group(filtered)
    if groups.get("upi") or groups.get("bank_account") or groups.get("crypto"):
        f.add("web.payment_ids", "Page exposes payment collection identifiers",
              "UPI IDs / bank accounts / crypto wallets published on scheme sites are typically mule or collection accounts.",
              12, "content", ", ".join(x["display"] for x in (groups.get("upi", []) + groups.get("bank_account", []) + groups.get("crypto", []))[:4]))
    if groups.get("telegram") or groups.get("whatsapp_group"):
        f.add("web.chat_funnel", "Funnels visitors to Telegram / WhatsApp",
              "Off-platform chat groups are where victims are groomed and paid out initially.", 8, "content",
              ", ".join(x["display"] for x in (groups.get("telegram", []) + groups.get("whatsapp_group", []))[:4]))

    if norm and len(norm) < 80 and not forms:
        page["note"] = "Very little static text; content may be rendered by JavaScript."

    page["category"] = max(categories, key=categories.get) if categories else ""
    return f, page, filtered


def analyze(url: str | None = None, upload: tuple[str, bytes] | None = None, run_live: bool = True) -> dict:
    if not url and not upload:
        raise ValueError("Enter a website address or upload a saved page or screenshot.")
    f = Findings()
    result: dict = {"source": "url" if url else "upload"}
    html, kind, base = "", "html", ""
    evidence: list[tuple[str, str, bytes, str]] = []
    is_img = False

    if url:
        rep = urlscan.analyze(url, run_live=run_live)
        f.merge(rep["findings"])
        result["url_report"] = {"url": rep["url"], "info": rep["info"],
                                "net": {k: v for k, v in rep["net"].items() if k != "_body"}}
        body = rep["net"].get("_body", b"")
        base = rep["net"].get("final_url") or rep["url"]
        if body:
            html = body.decode("utf-8", "replace")
            evidence.append(("Page snapshot (HTML as served)", "snapshot.html", body, "text/html"))
        else:
            result["fetch_note"] = rep["net"].get("errors", {}).get("http") or "Page could not be fetched (live checks disabled or site down)."
    elif upload:
        name, data = upload
        is_img = name.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp"))
        html, kind = load_upload(name, data)
        ev_label = "Uploaded website screenshot (OCR analysed)" if is_img else "Uploaded saved page"
        evidence.append((ev_label, name, data, "application/octet-stream"))
        m = re.search(r"<!--\s*saved from url=\(\d+\)(\S+)\s*-->", html[:2000]) or \
            re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)', html[:20000], re.I) or \
            re.search(r'<meta[^>]+property=["\']og:url["\'][^>]+content=["\']([^"\']+)', html[:20000], re.I)
        if m:
            base = m.group(1)
            result["original_url"] = base
            lex, info = urlscan.lexical(urlscan.normalise_url(base))
            f.merge(lex)
            result["url_report"] = {"url": base, "info": info, "net": {}}

    extracted: list[dict] = []
    if html:
        if kind == "html":
            cf, page, extracted = inspect_html(html, base)
        else:
            cf, page, extracted = inspect_html(f"<html><body><pre>{html_mod.escape(html)}</pre></body></html>", base)
            if is_img:
                page["ocr"] = True
        f.merge(cf)
        result["page"] = page
    if base:
        extracted += [e for e in ioc_mod.extract(base, "site URL")]
    result["category"] = result.get("page", {}).get("category", "")
    result["findings"] = f
    result["iocs"] = extracted
    result["_evidence"] = evidence
    return result
