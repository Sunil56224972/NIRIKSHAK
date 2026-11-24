"""Public threat-feed import into the blocklist (phishing URLs, domains, and botnet/trojan C2 IPs)."""
from __future__ import annotations

import re

import requests

from . import config
from .analysis import iocs as ioc_mod
from .analysis import netintel
from .analysis import urlscan
from .db import Supabase
from .service import _shared_hosts

FEEDS = {
    "openphish": ("OpenPhish community feed (active phishing URLs)", "https://openphish.com/feed.txt", "url"),
    "phishdb": (
        "Phishing.Database active links (verified live phishing)",
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt",
        "url",
    ),
    "phishing_army": (
        "Phishing Army active blocklist (phishing domains)",
        "https://phishing.army/download/phishing_army_blocklist.txt",
        "domain",
    ),
    "feodo_c2": (
        "abuse.ch Feodo Tracker (banking trojan C2 IPs)",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "ip",
    ),
    "sslbl_c2": (
        "abuse.ch SSLBL (botnet & malware C2 IPs)",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "ip",
    ),
}

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9\-]+)+$")
MAX_PER_SYNC = 2500


def parse_feed(feed: str, text: str, user: str) -> tuple[list[dict], int, int, int]:
    name, _url, kind = FEEDS[feed]
    shared = _shared_hosts()
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    url_count = 0
    dom_count = 0
    ip_count = 0

    for line in text.splitlines():
        if len(rows) >= MAX_PER_SYNC:
            break
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if kind == "url":
            if not line.lower().startswith(("http://", "https://")):
                continue
            val = line.lower()[:400]
            if ("url", val) not in seen:
                seen.add(("url", val))
                rows.append({"etype": "url", "value": val, "source": name, "added_by": user})
                url_count += 1
            h = ioc_mod.host_of(line)
            if h and urlscan.registrable(h) not in shared and not urlscan.is_official(h) and ("domain", h) not in seen:
                seen.add(("domain", h))
                rows.append({"etype": "domain", "value": h, "source": name, "added_by": user})
                dom_count += 1
        elif kind == "domain":
            h = line.lower().strip(".")
            if not _HOST_RE.fullmatch(h):
                continue
            if urlscan.registrable(h) not in shared and not urlscan.is_official(h) and ("domain", h) not in seen:
                seen.add(("domain", h))
                rows.append({"etype": "domain", "value": h, "source": name, "added_by": user})
                dom_count += 1
        elif kind == "ip":
            token = line.split()[0].split(",")[0].strip()
            if ioc_mod.IPV4_RE.fullmatch(token) and netintel.is_public_ip(token) and ("ip", token) not in seen:
                seen.add(("ip", token))
                rows.append({"etype": "ip", "value": token, "source": name, "note": "C2 blocklist feed", "added_by": user})
                ip_count += 1

    return rows, url_count, dom_count, ip_count


def sync(db: Supabase, feed: str, user: str) -> dict:
    name, url, _kind = FEEDS[feed]
    r = requests.get(url, timeout=max(30, config.NET_TIMEOUT * 3), headers={"User-Agent": "nirikshak-feed-sync/2.0"})
    r.raise_for_status()
    rows, url_count, dom_count, ip_count = parse_feed(feed, r.text, user)
    for i in range(0, len(rows), 500):
        db.insert("nk_blocklist", rows[i:i + 500], on_conflict="etype,value", ignore_duplicates=True, returning=False)
    return {"feed": name, "urls": url_count, "domains": dom_count, "ips": ip_count}
