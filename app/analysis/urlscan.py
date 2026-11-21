"""URL / domain analysis: lexical checks, brand impersonation, and live infrastructure checks."""
from __future__ import annotations

import re
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, unquote

from .. import config
from . import netintel
from .brands import BRANDS, FREE_HOSTING, MULTI_SUFFIXES, RISKY_TLDS, SHORTENERS, TRUSTED_SUFFIXES
from .iocs import IPV4_RE, refang
from .scoring import Findings

SENSITIVE_WORDS = [
    "kyc", "ekyc", "verify", "verification", "update", "login", "signin", "secure", "account", "unblock",
    "blocked", "suspend", "refund", "reward", "cashback", "redeem", "bonus", "gift", "prize", "lottery",
    "bill", "electricity", "bijli", "payment", "pay", "otp", "pan", "aadhaar", "aadhar", "customs",
    "parcel", "delivery", "track", "courier", "loan", "invest", "earning", "task", "recharge", "claim",
    "pm-kisan", "pmkisan", "yojana", "subsidy", "fastag", "challan", "echallan", "traffic", "police",
]

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a",
                            "$": "s", "|": "l", "!": "i"})


def normalise_url(raw: str) -> str:
    s = refang(raw.strip()).strip("<>\"' ")
    s = re.sub(r"\s+", "", s)
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", s, re.I):
        s = "http://" + s
    return s


def registrable(host: str) -> str:
    host = host.lower().strip(".")
    if IPV4_RE.fullmatch(host):
        return host
    labels = host.split(".")
    for n in (3, 2):
        if len(labels) > n and ".".join(labels[-n:]) in MULTI_SUFFIXES:
            return ".".join(labels[-(n + 1):])
    if len(labels) >= 2 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return host
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def is_official(host: str) -> str | None:
    host = host.lower()
    for b in BRANDS:
        for d in b["domains"]:
            if host == d or host.endswith("." + d):
                return b["name"]
    for suf in TRUSTED_SUFFIXES:
        if host.endswith("." + suf):
            return "Government / regulated Indian registry (." + suf + ")"
    return None


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def skeleton(label: str) -> str:
    s = unicodedata.normalize("NFKD", label)
    s = "".join(ch for ch in s if not unicodedata.combining(ch)).lower()
    s = s.translate(HOMOGLYPHS)
    return s.replace("rn", "m").replace("vv", "w").replace("cl", "d")


def _tokens(host: str) -> list[str]:
    return [t for t in re.split(r"[.\-_\d]+", host.lower()) if t]


def brand_hits(host: str) -> list[tuple[str, str, str]]:
    """Return (brand, matched keyword / official domain, technique) for look-alike hostnames."""
    if is_official(host):
        return []
    hits = []
    reg = registrable(host)
    reg_label = reg.split(".")[0]
    toks = _tokens(host)
    for b in BRANDS:
        for kw in b["keywords"]:
            if len(kw) <= 4:
                ok = any(t == kw or t.startswith(kw) or t.endswith(kw) for t in toks) and \
                     any(len(t) >= len(kw) for t in toks)
                # short keywords need a whole token or a compound like "sbiyono" / "onlinesbi"
                ok = ok and any(t == kw or (len(t) - len(kw) >= 3) for t in toks if kw in t)
            else:
                ok = kw in host.replace("-", "").replace(".", "")
            if ok:
                hits.append((b["name"], kw, "brand keyword in hostname"))
                break
        else:
            for d in b["domains"]:
                off_label = d.split(".")[0]
                if len(off_label) < 5:
                    continue
                dist = levenshtein(reg_label, off_label)
                if 0 < dist <= (1 if len(off_label) < 7 else 2):
                    hits.append((b["name"], d, f"typosquat of {d} (edit distance {dist})"))
                    break
                if skeleton(reg_label) == skeleton(off_label) and reg_label != off_label:
                    hits.append((b["name"], d, f"homoglyph of {d}"))
                    break
    return hits


def lexical(url: str) -> tuple[Findings, dict]:
    f = Findings()
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    info: dict = {"url": url, "scheme": parts.scheme, "host": host, "port": parts.port,
                  "path": parts.path, "query": parts.query}
    if not host:
        f.add("url.invalid", "Unparseable URL", "No hostname could be read from the input.", 0, "domain")
        return f, info

    try:
        unicode_host = host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        unicode_host = host
    info["unicode_host"] = unicode_host
    reg = registrable(host)
    info["registrable"] = reg
    tld = host.rsplit(".", 1)[-1]
    info["tld"] = tld

    official = is_official(host)
    info["official_brand"] = official
    if official:
        f.add("domain.official", "Domain belongs to a verified official entity",
              f"{reg} is a documented domain of {official}.", -35, "domain", host)

    if IPV4_RE.fullmatch(host):
        f.add("url.ip_host", "Raw IP address used instead of a domain",
              "Legitimate banks and government services never send links to bare IP addresses.", 25, "domain", host)

    if "xn--" in host:
        f.add("url.punycode", "Internationalised (punycode) domain",
              f"Displayed as '{unicode_host}'. Punycode is used to mimic Latin letters with look-alike characters.",
              25, "domain", host)

    for brand, matched, technique in brand_hits(unicode_host if unicode_host != host else host):
        lookalike = technique.startswith(("typosquat", "homoglyph"))
        f.add("domain.impersonation", f"Impersonates {brand}",
              f"Hostname uses '{matched}' ({technique}) but {reg} is not an official {brand} domain.",
              55 if lookalike else 40, "domain", host)

    if reg in SHORTENERS or host in SHORTENERS:
        f.add("url.shortener", "Link shortener hides the real destination",
              f"{host} is a public URL shortener; the final landing page is traced separately.", 15, "domain", host)

    hosting = next((h for h in FREE_HOSTING if host == h or host.endswith("." + h)), None)
    if hosting:
        f.add("url.free_hosting", "Hosted on a free / disposable platform",
              f"Page is served from a sub-domain of {hosting}, which anyone can create in minutes.", 15, "domain", host)

    if tld in RISKY_TLDS and not official:
        f.add("domain.risky_tld", f"High-abuse top-level domain .{tld}",
              f".{tld} domains are cheap and disproportionately used in phishing and scam campaigns.", 12, "domain", host)

    if parts.scheme == "http" and not IPV4_RE.fullmatch(host):
        f.add("url.no_tls", "Link does not use HTTPS",
              "Any page asking for banking or identity details over plain HTTP is unsafe.", 8, "network", url[:120])

    if "@" in (parts.netloc or ""):
        f.add("url.userinfo", "Credential-style '@' trick in URL",
              "Everything before '@' is ignored by the browser; used to make a link appear to point elsewhere.",
              20, "domain", parts.netloc)

    sub_labels = host[: -len(reg)].strip(".").split(".") if host != reg and host.endswith(reg) else []
    if len([s for s in sub_labels if s]) >= 3:
        f.add("url.deep_subdomain", "Unusually deep sub-domain chain",
              f"{len(sub_labels)} sub-domain levels in front of {reg}; often used to push the real domain off-screen.",
              8, "domain", host)
    if host.replace("xn--", "").count("-") >= 3 or len(host) > 45:
        f.add("url.long_host", "Long or hyphen-heavy hostname",
              "Machine-generated or keyword-stuffed hostnames are typical of throw-away scam domains.", 6, "domain", host)

    if parts.port and parts.port not in (80, 443):
        f.add("url.port", f"Non-standard port {parts.port}", "Legitimate public services rarely use custom ports.",
              8, "network", str(parts.port))

    lowered = unquote(host + parts.path + "?" + parts.query).lower()
    words = [w for w in SENSITIVE_WORDS if re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", lowered)]
    if words and not official:
        f.add("url.lure_words", "Lure keywords in the link",
              "Words such as " + ", ".join(sorted(set(words))[:6]) + " are used to create urgency or trust.",
              min(12, 5 + 3 * len(words)), "content", ", ".join(sorted(set(words))[:6]))

    if parts.path.lower().endswith(".apk") or "apk" in parts.query.lower().split("="):
        f.add("url.apk_download", "Direct Android APK download link",
              "Sideloaded APKs shared through messages are the main delivery route for SMS-stealing and fake loan apps.",
              30, "app", url[:160])

    if len(url) > 200:
        f.add("url.very_long", "Very long URL", f"{len(url)} characters; tracking/obfuscation parameters.", 4, "domain")

    return f, info


def live(url: str, info: dict) -> tuple[Findings, dict]:
    """Infrastructure checks. Every failure is recorded rather than silently ignored."""
    f = Findings()
    host = info.get("host", "")
    reg = info.get("registrable", host)
    net: dict = {"errors": {}}
    if not host:
        return f, net

    is_ip = bool(IPV4_RE.fullmatch(host))

    def job_dns():
        return netintel.resolve(host)

    def job_rdap():
        return None if is_ip else netintel.rdap_domain(reg)

    def job_fetch():
        return netintel.fetch(url)

    def job_tls():
        return netintel.tls_info(host)

    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = {"dns": pool.submit(job_dns), "rdap": pool.submit(job_rdap),
                "http": pool.submit(job_fetch), "tls": pool.submit(job_tls)}
        results = {}
        for k, fut in futs.items():
            try:
                results[k] = fut.result(timeout=config.NET_TIMEOUT * 4)
            except netintel.BlockedTarget as exc:
                net["errors"][k] = str(exc)
            except Exception as exc:  # network failures are evidence too
                net["errors"][k] = f"{exc.__class__.__name__}: {str(exc)[:160]}"

    ips = results.get("dns") or []
    net["dns"] = ips
    if not ips and "dns" in results:
        f.add("net.nxdomain", "Domain does not resolve",
              "No DNS A/AAAA record. The site may already be taken down, or is only live during a campaign.",
              10, "network", host)

    if ips:
        try:
            net["hosting"] = netintel.rdap_ip(ips[0]) if netintel.is_public_ip(ips[0]) else {"ip": ips[0]}
        except Exception as exc:
            net["errors"]["hosting"] = f"{exc.__class__.__name__}"

    rd = results.get("rdap")
    if rd is not None:
        net["whois"] = rd
        age = rd.get("age_days") if rd.get("found") else None
        if rd.get("found") is False:
            f.add("domain.unregistered", "Registry has no record of this domain",
                  "Either never registered or already deleted after abuse reports.", 10, "domain", reg)
        elif age is not None and not info.get("official_brand"):
            if age < 30:
                f.add("domain.age_new", f"Domain registered {age} day(s) ago",
                      f"Created {rd.get('created', '')[:10]}. Most phishing domains are used within their first month.",
                      30, "domain", reg)
            elif age < 90:
                f.add("domain.age_young", f"Domain only {age} days old",
                      f"Created {rd.get('created', '')[:10]}.", 18, "domain", reg)
            elif age < 365:
                f.add("domain.age_lt_year", f"Domain under a year old ({age} days)",
                      f"Created {rd.get('created', '')[:10]}.", 6, "domain", reg)
            elif age > 1825:
                f.add("domain.age_established", f"Long-established domain ({age // 365} years)",
                      "Age alone does not prove legitimacy (compromised sites exist) but lowers likelihood.", -8, "domain", reg)
        statuses = " ".join(rd.get("status", [])).lower()
        if "hold" in statuses:
            f.add("domain.on_hold", "Registry has placed the domain on hold",
                  "clientHold / serverHold is usually applied after abuse complaints.", 15, "domain", statuses[:120])

    tl = results.get("tls")
    if tl:
        net["tls"] = tl
        if not tl["verified"]:
            f.add("net.tls_invalid", "TLS certificate failed validation", tl["verify_error"][:200], 15, "network", host)
        elif tl["issued_days_ago"] <= 7 and not info.get("official_brand"):
            f.add("net.tls_fresh", f"TLS certificate issued {tl['issued_days_ago']} day(s) ago",
                  f"Issuer: {tl['issuer']}. Fresh certificates accompany freshly deployed scam pages.", 5, "network", host)

    ht = results.get("http")
    if ht:
        body = ht.pop("body", b"")
        net["http"] = {k: v for k, v in ht.items() if k != "headers"}
        net["http"]["server"] = ht["headers"].get("Server", "")
        net["http"]["powered_by"] = ht["headers"].get("X-Powered-By", "")
        net["_body"] = body
        chain = ht["chain"]
        final = ht["final_url"]
        net["final_url"] = final
        final_host = (urlsplit(final).hostname or "").lower()
        if len(chain) > 1 and registrable(final_host) != reg:
            f.add("net.cross_redirect", "Redirects to a different domain",
                  " -> ".join(c["url"][:80] for c in chain[:5]), 12, "network", final_host)
        if ht.get("soft_redirect"):
            f.add("net.soft_redirect", "Page forwards via meta-refresh / JavaScript",
                  f"Client-side redirect to {ht['soft_redirect'][:150]}; often used to evade link scanners.",
                  10, "network", ht["soft_redirect"][:150])
        if final.lower().split("?")[0].endswith(".apk") or "android.package-archive" in ht["content_type"]:
            f.add("net.serves_apk", "Link downloads an Android APK",
                  f"Content-Type {ht['content_type'] or 'n/a'} from {final[:120]}", 30, "app", final[:160])
        if ht.get("tls_error"):
            f.add("net.https_broken", "HTTPS connection error", ht["tls_error"], 10, "network", host)

    if config.GSB_API_KEY:
        try:
            matches = netintel.safe_browsing([url] + ([net["final_url"]] if net.get("final_url") else []))
            net["safe_browsing"] = matches
            if matches:
                kinds = ", ".join(sorted({m.get("threatType", "") for m in matches}))
                f.add("intel.gsb", "Listed by Google Safe Browsing", kinds, 45, "intel", url[:160])
                f.force_floor(80, "Google Safe Browsing match")
        except Exception as exc:
            net["errors"]["safe_browsing"] = exc.__class__.__name__
    return f, net


def analyze(raw: str, run_live: bool = True) -> dict:
    url = normalise_url(raw)
    f, info = lexical(url)
    net = {}
    if run_live and config.LIVE_CHECKS and info.get("host"):
        lf, net = live(url, info)
        f.merge(lf)
        final = net.get("final_url")
        if final and registrable((urlsplit(final).hostname or "")) != info.get("registrable"):
            ff, finfo = lexical(final)
            info["final"] = finfo
            for it in ff.items:
                if it.weight > 0:
                    f.add(it.code + ".final", "Landing page: " + it.title, it.detail, it.weight, it.group, it.evidence)
    return {"url": url, "findings": f, "info": info, "net": net}
