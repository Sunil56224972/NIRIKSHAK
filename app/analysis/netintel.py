"""Network intelligence helpers: DNS, RDAP (registration data), TLS, and an SSRF-safe fetcher.

The fetcher refuses to connect to private, loopback, link-local or reserved address space,
because URLs submitted by the public must never be able to reach the police LAN or cloud
metadata endpoints.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import threading
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .. import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = ("Mozilla/5.0 (Linux; Android 13; SM-A536E) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0.0.0 Mobile Safari/537.36")
_tls_local = threading.local()


def get_session() -> requests.Session:
    s = getattr(_tls_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": UA, "Accept-Language": "en-IN,en;q=0.9,hi;q=0.8"})
        _tls_local.session = s
    return s


class BlockedTarget(Exception):
    pass


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    seen = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    return seen


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
                or a.is_unspecified or (a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10")))


def _check_target(url: str) -> list[str]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BlockedTarget(f"scheme '{parts.scheme}' not fetched")
    host = parts.hostname or ""
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        ips = resolve(host)
    if not ips:
        raise BlockedTarget("host does not resolve")
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:
        raise BlockedTarget(f"resolves to non-public address {bad[0]}; refused")
    return ips


META_REFRESH_RE = re.compile(r"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]*content=[\"']?\s*\d+\s*;\s*url=([^\"'>\s]+)", re.I)
JS_REDIRECT_RE = re.compile(r"(?:window\.|document\.|top\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*[\"']([^\"']{4,300})[\"']", re.I)


def fetch(url: str, max_hops: int = 8) -> dict:
    """Follow redirects hop by hop, recording the chain. Returns body bytes of the final page."""
    chain = []
    current = url
    tls_error = None
    resp = None
    for _ in range(max_hops):
        _check_target(current)
        verify = True
        try:
            resp = get_session().get(current, allow_redirects=False, timeout=config.NET_TIMEOUT, stream=True, verify=True)
        except requests.exceptions.SSLError as exc:
            tls_error = str(exc.__class__.__name__) + ": " + str(exc)[:160]
            verify = False
            resp = get_session().get(current, allow_redirects=False, timeout=config.NET_TIMEOUT, stream=True, verify=False)
        chain.append({"url": current, "status": resp.status_code, "server": resp.headers.get("Server", ""),
                      "tls_verified": verify})
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            resp.close()
            if not loc:
                break
            current = urljoin(current, loc)
            continue
        break

    body = b""
    if resp is not None:
        for chunk in resp.iter_content(65536):
            body += chunk
            if len(body) > config.MAX_FETCH_BYTES:
                break
        resp.close()

    soft = None
    head = body[:200000].decode("utf-8", "replace")
    m = META_REFRESH_RE.search(head) or JS_REDIRECT_RE.search(head)
    if m:
        target = urljoin(current, m.group(1))
        if target.startswith("http") and target != current:
            soft = target

    return {
        "chain": chain,
        "final_url": current,
        "status": resp.status_code if resp is not None else None,
        "headers": dict(resp.headers) if resp is not None else {},
        "content_type": resp.headers.get("Content-Type", "") if resp is not None else "",
        "body": body,
        "tls_error": tls_error,
        "soft_redirect": soft,
    }


# ---------------------------------------------------------------------------- RDAP
def _vcard_name(entity: dict) -> str:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] in ("fn", "org") and item[3]:
            return str(item[3])
    return ""


def _date(s: str | None):
    if not s:
        return None
    s = s.strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y %H:%M:%S", "%d-%b-%Y", "%Y/%m/%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(s[:20].strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _whois_query(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("ascii", "ignore"))
        chunks = []
        total = 0
        while total < 262_144:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def _parse_whois(raw: str) -> dict:
    def _first(rx: str) -> str:
        m = re.search(rx, raw, re.I | re.M)
        return m.group(1).strip() if m else ""

    created_raw = _first(r"^\s*(?:Creation Date|Created On|Registered On|Registration Time|Domain Registration Date)\s*:\s*(.+)$")
    expires_raw = _first(r"^\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|Expires On)\s*:\s*(.+)$")
    updated_raw = _first(r"^\s*(?:Updated Date|Last Updated On)\s*:\s*(.+)$")
    registrar = _first(r"^\s*(?:Sponsoring Registrar|Registrar)\s*:\s*(.+)$")
    abuse_email = _first(r"^\s*(?:Registrar Abuse Contact Email|Abuse Email)\s*:\s*(\S+)")
    abuse_phone = _first(r"^\s*(?:Registrar Abuse Contact Phone|Abuse Phone)\s*:\s*(.+)$")
    ns = sorted({m.group(1).strip().rstrip(".").lower()
                 for m in re.finditer(r"^\s*(?:Name Server|nserver)\s*:\s*(\S+)", raw, re.I | re.M)})
    not_found = bool(re.search(r"^(?:No match for|NOT FOUND|No Data Found|Domain not found|No entries found)", raw, re.I | re.M))
    dt = _date(created_raw)
    age = (datetime.now(timezone.utc) - dt).days if dt else None
    return {
        "found": not not_found and bool(created_raw or registrar or ns),
        "registrar": registrar,
        "registrar_abuse_email": abuse_email,
        "registrar_abuse_phone": abuse_phone,
        "created": created_raw or None,
        "expires": expires_raw or None,
        "updated": updated_raw or None,
        "age_days": age,
        "status": [],
        "nameservers": ns,
        "_not_found_msg": not_found,
    }


def whois_domain(domain: str) -> dict | None:
    timeout = min(5.0, config.NET_TIMEOUT)
    try:
        iana = _whois_query("whois.iana.org", domain, timeout)
    except OSError:
        return None
    m = re.search(r"^\s*refer\s*:\s*(\S+)", iana, re.I | re.M)
    if not m:
        return None
    srv = m.group(1).strip()
    try:
        raw = _whois_query(srv, domain, timeout)
    except OSError:
        return None
    parsed = _parse_whois(raw)
    reg_srv = re.search(r"^\s*Registrar WHOIS Server\s*:\s*(\S+)", raw, re.I | re.M)
    if reg_srv and reg_srv.group(1).strip().lower() != srv.lower():
        try:
            extra = _parse_whois(_whois_query(reg_srv.group(1).strip(), domain, timeout))
            for k in ("registrar", "registrar_abuse_email", "registrar_abuse_phone", "created", "expires", "updated", "age_days"):
                if not parsed.get(k) and extra.get(k):
                    parsed[k] = extra[k]
            if extra.get("nameservers") and not parsed.get("nameservers"):
                parsed["nameservers"] = extra["nameservers"]
            parsed["found"] = parsed["found"] or extra["found"]
        except OSError:
            pass
    if parsed.pop("_not_found_msg", False) and not parsed["found"]:
        return {"found": False}
    return parsed if parsed["found"] else None


def rdap_domain(domain: str) -> dict:
    rdap_err = None
    data = None
    try:
        r = get_session().get(f"https://rdap.org/domain/{domain}", timeout=config.NET_TIMEOUT,
                              headers={"Accept": "application/rdap+json"})
        if r.status_code == 404:
            data = {"found": False}
        else:
            r.raise_for_status()
            d = r.json()
            events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
            registrar, abuse_email, abuse_phone = "", "", ""
            for ent in d.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    registrar = _vcard_name(ent) or registrar
                    for sub in ent.get("entities", []):
                        if "abuse" in sub.get("roles", []):
                            for item in (sub.get("vcardArray") or [None, []])[1]:
                                if item[0] == "email":
                                    abuse_email = item[3]
                                if item[0] == "tel":
                                    abuse_phone = str(item[3]).replace("tel:", "")
            created = _date(events.get("registration"))
            age = (datetime.now(timezone.utc) - created).days if created else None
            data = {
                "found": True,
                "registrar": registrar,
                "registrar_abuse_email": abuse_email,
                "registrar_abuse_phone": abuse_phone,
                "created": events.get("registration"),
                "expires": events.get("expiration"),
                "updated": events.get("last changed"),
                "age_days": age,
                "status": d.get("status", []),
                "nameservers": [ns.get("ldhName", "").lower() for ns in d.get("nameservers", [])],
            }
    except (requests.RequestException, ValueError) as exc:
        rdap_err = exc

    if data is None or not data.get("created"):
        wh = whois_domain(domain)
        if wh:
            if data is None or not data.get("found"):
                return wh
            for k in ("created", "age_days", "registrar", "expires", "updated",
                      "registrar_abuse_email", "registrar_abuse_phone"):
                if not data.get(k) and wh.get(k) is not None:
                    data[k] = wh[k]
            if not data.get("nameservers") and wh.get("nameservers"):
                data["nameservers"] = wh["nameservers"]
    if data is not None:
        return data
    raise rdap_err  # surface failure in net["errors"]


def rdap_ip(ip: str) -> dict:
    r = get_session().get(f"https://rdap.org/ip/{ip}", timeout=config.NET_TIMEOUT, headers={"Accept": "application/rdap+json"})
    r.raise_for_status()
    d = r.json()
    org = ""
    for ent in d.get("entities", []):
        if {"registrant", "administrative"} & set(ent.get("roles", [])):
            org = _vcard_name(ent) or org
    if not org:
        for ent in d.get("entities", []):
            org = _vcard_name(ent) or org
            if org:
                break
    return {"ip": ip, "network": d.get("name", ""), "org": org, "country": d.get("country", ""),
            "range": f"{d.get('startAddress', '')} - {d.get('endAddress', '')}"}


# ---------------------------------------------------------------------------- TLS
def tls_info(host: str, port: int = 443) -> dict:
    tmo = min(5.0, config.NET_TIMEOUT)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=tmo) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            der = s.getpeercert(binary_form=True)
            proto = s.version()
    cert = x509.load_der_x509_certificate(der)

    def name(n):
        parts = []
        for oid_name in ("commonName", "organizationName"):
            for attr in n:
                if attr.oid._name == oid_name:
                    parts.append(attr.value)
        return ", ".join(parts)

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []

    verified, verify_error = True, ""
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=tmo) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as exc:
        verified, verify_error = False, exc.verify_message or str(exc)
    except (ssl.SSLError, OSError) as exc:
        verified, verify_error = False, str(exc)[:160]

    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    return {
        "subject": name(cert.subject), "issuer": name(cert.issuer), "san": san[:20],
        "not_before": nb.isoformat(), "not_after": na.isoformat(),
        "issued_days_ago": (datetime.now(timezone.utc) - nb).days,
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "protocol": proto, "verified": verified, "verify_error": verify_error,
    }


def safe_browsing(urls: list[str]) -> list[dict]:
    """Google Safe Browsing v4 lookup. Only used when GOOGLE_SAFE_BROWSING_KEY is configured."""
    if not config.GSB_API_KEY or not urls:
        return []
    body = {
        "client": {"clientId": "nirikshak", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:50]],
        },
    }
    r = get_session().post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={config.GSB_API_KEY}",
                           json=body, timeout=config.NET_TIMEOUT)
    r.raise_for_status()
    return r.json().get("matches", [])
