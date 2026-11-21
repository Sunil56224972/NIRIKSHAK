"""Extraction of actionable identifiers (IOCs) from free text, HTML and APK strings.

Each identifier is returned as {"etype", "value" (normalised key), "display", "context"}.
`value` is what gets linked across cases, so normalisation must be stable.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qs, unquote, urlsplit

# NPCI-published PSP handles (partial list of the most common). Unknown dot-less handles are
# still treated as UPI because e-mail domains always contain a dot.
UPI_HANDLES = {
    "ybl": "Yes Bank (PhonePe)", "ibl": "ICICI Bank (PhonePe)", "axl": "Axis Bank (PhonePe)",
    "okaxis": "Axis Bank (Google Pay)", "okhdfcbank": "HDFC Bank (Google Pay)",
    "okicici": "ICICI Bank (Google Pay)", "oksbi": "SBI (Google Pay)",
    "paytm": "Paytm", "ptyes": "Yes Bank (Paytm)", "ptaxis": "Axis Bank (Paytm)",
    "pthdfc": "HDFC Bank (Paytm)", "ptsbi": "SBI (Paytm)", "upi": "BHIM", "apl": "Axis Bank (Amazon Pay)",
    "yapl": "Yes Bank (Amazon Pay)", "rapl": "RBL Bank (Amazon Pay)", "icici": "ICICI Bank",
    "sbi": "State Bank of India", "hdfcbank": "HDFC Bank", "axisbank": "Axis Bank", "axisb": "Axis Bank",
    "kotak": "Kotak Mahindra Bank", "kmbl": "Kotak Mahindra Bank", "barodampay": "Bank of Baroda",
    "fbl": "Federal Bank", "federal": "Federal Bank", "indus": "IndusInd Bank", "pnb": "Punjab National Bank",
    "cnrb": "Canara Bank", "aubank": "AU Small Finance Bank", "jio": "Jio Payments Bank",
    "freecharge": "Freecharge (Axis)", "ikwik": "MobiKwik", "airtel": "Airtel Payments Bank",
    "postbank": "India Post Payments Bank", "dbs": "DBS Bank", "rbl": "RBL Bank", "yesbank": "Yes Bank",
    "yescred": "Yes Bank (CRED)", "idfcfirst": "IDFC First Bank", "idfcbank": "IDFC First Bank",
    "unionbank": "Union Bank of India", "uboi": "Union Bank of India", "indianbank": "Indian Bank",
    "boi": "Bank of India", "cbin": "Central Bank of India", "mahb": "Bank of Maharashtra", "uco": "UCO Bank",
    "waicici": "ICICI (WhatsApp Pay)", "wahdfcbank": "HDFC (WhatsApp Pay)", "wasbi": "SBI (WhatsApp Pay)",
    "waaxis": "Axis (WhatsApp Pay)", "naviaxis": "Axis (Navi)", "superyes": "Yes Bank (super.money)",
    "jupiteraxis": "Axis (Jupiter)", "fam": "IDFC (FamPay)", "slc": "Slice", "kbl": "Karnataka Bank",
    "sib": "South Indian Bank", "equitas": "Equitas SFB", "idbi": "IDBI Bank", "iob": "Indian Overseas Bank",
    "psb": "Punjab & Sind Bank", "hsbc": "HSBC", "sc": "Standard Chartered", "citi": "Citibank",
    "ezeepay": "Ezeepay", "pingpay": "Ping Pay", "abfspay": "Aditya Birla", "tapicici": "ICICI (Tap)",
}

IFSC_BANKS = {
    "SBIN": "State Bank of India", "HDFC": "HDFC Bank", "ICIC": "ICICI Bank", "UTIB": "Axis Bank",
    "PUNB": "Punjab National Bank", "BARB": "Bank of Baroda", "CNRB": "Canara Bank", "UBIN": "Union Bank of India",
    "KKBK": "Kotak Mahindra Bank", "INDB": "IndusInd Bank", "YESB": "Yes Bank", "IDFB": "IDFC First Bank",
    "FDRL": "Federal Bank", "IDIB": "Indian Bank", "BKID": "Bank of India", "CBIN": "Central Bank of India",
    "MAHB": "Bank of Maharashtra", "UCBA": "UCO Bank", "IOBA": "Indian Overseas Bank", "PSIB": "Punjab & Sind Bank",
    "RATN": "RBL Bank", "AUBL": "AU Small Finance Bank", "ESFB": "Equitas SFB", "AIRP": "Airtel Payments Bank",
    "PYTM": "Paytm Payments Bank", "IPOS": "India Post Payments Bank", "JIOP": "Jio Payments Bank",
    "SIBL": "South Indian Bank", "KARB": "Karnataka Bank", "KVBL": "Karur Vysya Bank", "IBKL": "IDBI Bank",
    "TMBL": "Tamilnad Mercantile Bank", "DBSS": "DBS Bank", "FINO": "Fino Payments Bank", "NSPB": "NSDL Payments Bank",
    "UJVN": "Ujjivan SFB", "ESMF": "ESAF SFB", "SURY": "Suryoday SFB", "JAKA": "J&K Bank", "CSBK": "CSB Bank",
    "DLXB": "Dhanlaxmi Bank", "CITI": "Citibank", "HSBC": "HSBC", "SCBL": "Standard Chartered",
}

_TLDS = (
    "com|in|net|org|co|info|biz|xyz|top|online|site|club|shop|store|live|icu|buzz|vip|app|io|me|cc|tk|ml|ga|cf|gq|"
    "pw|ly|link|click|win|bet|loan|tech|space|fun|cyou|sbs|cfd|bond|lat|rest|today|world|us|uk|ru|cn|asia|pro|"
    "life|work|website|digital|finance|money|cash|trade|market|games|casino|cloud|dev|page|ai|gg|to|su|ws|sbi|bank"
)
URL_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s<>\"'`{}|\\^\[\]]+", re.I)
BARE_DOMAIN_RE = re.compile(
    rf"(?<![@\w.\-/])((?:[a-z0-9](?:[a-z0-9\-]{{0,61}}[a-z0-9])?\.)+(?:{_TLDS}))(?![\w\-])(/[^\s<>\"'`]*)?",
    re.I,
)
DEFANG_RE = [(re.compile(r"\[\.\]|\(\.\)|\{\.\}", re.I), "."), (re.compile(r"hxxp", re.I), "http"),
             (re.compile(r"\[:\]"), ":")]
AT_TOKEN_RE = re.compile(r"(?<![\w.\-])([a-zA-Z0-9][a-zA-Z0-9._\-]{1,63})@([a-zA-Z][a-zA-Z0-9.\-]{1,63})(?![\w@])")
PHONE_RE = re.compile(r"(?<![\d+])(?:(?:\+|00)\s?91[\s\-.]?|91[\s\-]|0)?([6-9]\d{2}[\s\-.]?\d{2}[\s\-.]?\d{5}|[6-9]\d{4}[\s\-.]?\d{5})(?!\d)")
TOLLFREE_RE = re.compile(r"(?<!\d)(1800[\s\-]?\d{3}[\s\-]?\d{4}|1860[\s\-]?\d{3}[\s\-]?\d{4})(?!\d)")
IFSC_RE = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
ACCOUNT_RE = re.compile(
    r"(?:a/?c|acc(?:ount)?|acct|khata)\s*(?:no\.?|number|num|#)?\s*[:\-=]?\s*((?:\d[\s\-]?){9,18})(?!\d)", re.I)
IPV4_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\d.])")
TG_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/(?:joinchat/|\+)?([A-Za-z0-9_\-]{4,64})", re.I)
TG_HANDLE_RE = re.compile(r"(?:telegram|tg|टेलीग्राम)\s*(?:id|handle|channel|group)?\s*[:\-]?\s*@([A-Za-z][A-Za-z0-9_]{4,31})\b", re.I)
WA_RE = re.compile(r"(?:https?://)?(?:wa\.me/|api\.whatsapp\.com/send/?\?(?:[^\s\"']*&)?phone=)(\+?\d{8,15})", re.I)
WA_GROUP_RE = re.compile(r"(?:https?://)?chat\.whatsapp\.com/(?:invite/)?([A-Za-z0-9]{10,40})", re.I)
ETH_RE = re.compile(r"(?<![0-9a-fA-Fx])(0x[a-fA-F0-9]{40})(?![0-9a-fA-F])")
TRON_RE = re.compile(r"(?<![1-9A-Za-z])(T[1-9A-HJ-NP-Za-km-z]{33})(?![1-9A-Za-z])")
BTC_LEGACY_RE = re.compile(r"(?<![1-9A-Za-z])([13][1-9A-HJ-NP-Za-km-z]{25,34})(?![1-9A-Za-z])")
BTC_BECH_RE = re.compile(r"\b(bc1[ac-hj-np-z02-9]{25,62})\b")
UPI_URI_RE = re.compile(r"upi://pay\?[^\s\"'<>]+", re.I)

_ASSET_EXT = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "json", "xml", "woff", "woff2", "ttf",
              "ico", "map", "mp4", "mp3", "html", "htm", "php", "aspx", "jsp", "kt", "java", "so", "dex", "txt"}
_CODE_PREFIXES = ("android.", "androidx.", "java.", "javax.", "kotlin.", "dalvik.", "com.android.", "com.google.android.",
                  "org.apache.", "org.json.", "okhttp3.", "retrofit2.", "io.reactivex.", "com.facebook.", "sun.")

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58check(addr: str) -> bool:
    n = 0
    for ch in addr:
        idx = _B58.find(ch)
        if idx < 0:
            return False
        n = n * 58 + idx
    raw = n.to_bytes(25, "big") if n.bit_length() <= 200 else b""
    if len(raw) != 25:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def refang(text: str) -> str:
    for rx, rep in DEFANG_RE:
        text = rx.sub(rep, text)
    return text


def upi_bank(handle: str) -> str:
    return UPI_HANDLES.get(handle.lower(), "")


class Collector:
    def __init__(self, context: str):
        self.context = context
        self.items: dict[tuple[str, str], dict] = {}

    def add(self, etype: str, value: str, display: str | None = None, extra: str = "") -> None:
        value = value.strip()
        if not value:
            return
        key = (etype, value)
        if key not in self.items:
            self.items[key] = {"etype": etype, "value": value, "display": display or value,
                               "context": self.context + (f" · {extra}" if extra else "")}

    def result(self) -> list[dict]:
        return list(self.items.values())


def _clean_url(u: str) -> str:
    u = u.rstrip(".,;:!?'\")]}>")
    # balance a trailing ")" that belongs to the surrounding text
    if u.count("(") < u.count(")"):
        u = u.rstrip(")")
    return u


def host_of(url: str) -> str:
    try:
        h = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        return ""
    return h.lower().strip(".")


def normalise_phone(raw: str) -> str | None:
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    if len(digits) == 10 and digits[0] in "6789" and len(set(digits)) > 2:
        return "+91" + digits
    return None


def extract(text: str, context: str = "content", *, bare_domains: bool = True, code_strings: bool = False) -> list[dict]:
    """Extract identifiers. `code_strings=True` tightens rules for APK/DEX string tables."""
    items = _extract(text, context, bare_domains=bare_domains, code_strings=code_strings)
    # chat deep-links are captured as phone / telegram / group identifiers, not as web targets
    out = []
    for it in items:
        if it["etype"] in ("url", "domain"):
            h = host_of(it["value"]) if it["etype"] == "url" else it["value"]
            if h in CHAT_HOSTS:
                continue
        out.append(it)
    return out


CHAT_HOSTS = {"wa.me", "api.whatsapp.com", "chat.whatsapp.com", "t.me", "telegram.me", "telegram.dog"}


def _extract(text: str, context: str = "content", *, bare_domains: bool = True, code_strings: bool = False) -> list[dict]:
    if not text:
        return []
    text = refang(text)
    c = Collector(context)

    # URLs with scheme
    url_spans = []
    for m in URL_RE.finditer(text):
        u = _clean_url(m.group(0))
        h = host_of(u)
        if not h or ("." not in h and not IPV4_RE.fullmatch(h)):
            continue
        if code_strings and (h.endswith(("schemas.android.com", "w3.org", "apache.org", "xmlpull.org",
                                         "ns.adobe.com", "purl.org", "xml.org"))):
            continue
        url_spans.append(m.span())
        c.add("url", u.lower() if len(u) < 400 else u[:400].lower(), u[:400])
        if IPV4_RE.fullmatch(h):
            c.add("ip", h, h, "URL host")
        else:
            c.add("domain", h, h)

    # bare domains (messages / pages only)
    if bare_domains and not code_strings:
        for m in BARE_DOMAIN_RE.finditer(text):
            if any(s <= m.start() < e for s, e in url_spans):
                continue
            host = m.group(1).lower()
            tld = host.rsplit(".", 1)[-1]
            if tld in _ASSET_EXT or host.startswith(_CODE_PREFIXES):
                continue
            if re.fullmatch(r"[\d.]+", host):
                continue
            c.add("domain", host, host)
            if m.group(2):
                full = _clean_url(m.group(0))
                c.add("url", "http://" + full.lower(), full)

    # UPI deep links: upi://pay?pa=xxx@bank&pn=Name
    for m in UPI_URI_RE.finditer(text):
        q = parse_qs(urlsplit(m.group(0)).query)
        pa = unquote((q.get("pa") or [""])[0]).strip().lower()
        pn = unquote((q.get("pn") or [""])[0]).strip()
        if "@" in pa:
            bank = upi_bank(pa.split("@")[1])
            c.add("upi", pa, pa, f"upi:// payment link{' · payee ' + pn if pn else ''}{' · ' + bank if bank else ''}")

    # UPI VPAs vs e-mail addresses
    for m in AT_TOKEN_RE.finditer(text):
        user, host = m.group(1), m.group(2).rstrip(".")
        hl = host.lower()
        if "." in hl:
            tld = hl.rsplit(".", 1)[-1]
            if tld in _ASSET_EXT or not tld.isalpha() or len(tld) < 2:
                continue
            if code_strings and user.lower() in ("android", "string", "drawable", "style", "id", "color", "layout"):
                continue
            c.add("email", f"{user}@{hl}".lower())
        else:
            if user.lower() in ("android", "string", "drawable", "style", "id", "color", "layout", "dimen", "mipmap", "anim",
                                "raw", "xml", "font", "attr", "null", "media", "keyframes", "import", "charset"):
                continue
            bank = upi_bank(hl)
            if not bank and (code_strings or len(hl) > 15 or not hl.isalpha()):
                continue
            vpa = f"{user}@{hl}".lower()
            c.add("upi", vpa, vpa, bank or "unlisted PSP handle")

    # phone numbers
    for m in PHONE_RE.finditer(text):
        if code_strings:
            # inside code only accept numbers formatted with country code
            if not re.match(r"(?:\+|00)\s?91", m.group(0)):
                continue
        p = normalise_phone(m.group(0))
        if p:
            c.add("phone", p, f"+91 {p[3:8]} {p[8:]}")
    for m in TOLLFREE_RE.finditer(text):
        d = re.sub(r"\D", "", m.group(1))
        c.add("phone", d, f"{d[:4]} {d[4:7]} {d[7:]}", "toll-free")

    # bank details
    for m in IFSC_RE.finditer(text):
        code = m.group(1)
        bank = IFSC_BANKS.get(code[:4])
        if bank or not code_strings:
            c.add("ifsc", code, code, bank or "bank code " + code[:4])
    for m in ACCOUNT_RE.finditer(text):
        acct = re.sub(r"\D", "", m.group(1))
        if 9 <= len(acct) <= 18 and not normalise_phone(acct):
            c.add("bank_account", acct, acct)

    # IPs
    for m in IPV4_RE.finditer(text):
        ip = m.group(1)
        first = int(ip.split(".")[0])
        if first in (0, 127, 255) or ip.startswith(("10.", "192.168.", "169.254.")):
            continue
        if code_strings and ip.count(".") == 3 and ip.split(".")[2:] == ["0", "0"]:
            continue
        c.add("ip", ip)

    # messaging
    for m in TG_RE.finditer(text):
        h = m.group(1)
        if h.lower() in ("share", "addstickers", "iv", "s", "proxy", "socks", "setlanguage"):
            continue
        c.add("telegram", "t.me/" + h.lower(), "t.me/" + h)
    for m in TG_HANDLE_RE.finditer(text):
        c.add("telegram", "t.me/" + m.group(1).lower(), "@" + m.group(1))
    for m in WA_RE.finditer(text):
        p = normalise_phone(m.group(1))
        if p:
            c.add("phone", p, f"+91 {p[3:8]} {p[8:]}", "WhatsApp click-to-chat")
        else:
            d = re.sub(r"\D", "", m.group(1))
            c.add("phone", "+" + d, "+" + d, "WhatsApp click-to-chat (foreign)")
    for m in WA_GROUP_RE.finditer(text):
        c.add("whatsapp_group", "chat.whatsapp.com/" + m.group(1), "chat.whatsapp.com/" + m.group(1))

    # crypto
    for m in ETH_RE.finditer(text):
        a = m.group(1)
        if len(set(a[2:].lower())) > 4:
            c.add("crypto", a.lower(), a, "EVM (ETH/BSC/Polygon) address")
    for m in TRON_RE.finditer(text):
        if _b58check(m.group(1)):
            c.add("crypto", m.group(1), m.group(1), "TRON address (USDT TRC-20)")
    for m in BTC_LEGACY_RE.finditer(text):
        if _b58check(m.group(1)):
            c.add("crypto", m.group(1), m.group(1), "Bitcoin address")
    for m in BTC_BECH_RE.finditer(text):
        c.add("crypto", m.group(1).lower(), m.group(1), "Bitcoin bech32 address")

    return c.result()


def group(items: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for it in items:
        out.setdefault(it["etype"], []).append(it)
    return out


ETYPE_LABELS = {
    "url": "URL", "domain": "Domain", "ip": "IP address", "phone": "Phone number", "upi": "UPI ID",
    "email": "E-mail", "ifsc": "IFSC", "bank_account": "Bank account", "telegram": "Telegram",
    "whatsapp_group": "WhatsApp group", "crypto": "Crypto wallet", "apk_package": "App package",
    "apk_cert": "Signing certificate", "apk_sha256": "APK SHA-256",
}
