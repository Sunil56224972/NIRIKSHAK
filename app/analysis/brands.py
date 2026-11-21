"""Reference data: brands commonly impersonated in Indian fraud campaigns.

Only official, publicly documented domains and Play Store package names are listed.
`keywords` are tokens fraudsters put in look-alike hostnames or sender text.
Maintain this list as new campaigns are observed.
"""
from __future__ import annotations

BRANDS: list[dict] = [
    {"name": "State Bank of India", "keywords": ["sbi", "onlinesbi", "yonosbi", "yono"],
     "domains": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbi", "sbicard.com", "sbilife.co.in", "yonobusiness.sbi"],
     "packages": ["com.sbi.lotusintouch", "com.sbi.SBIFreedomPlus", "com.sbi.upi", "com.sbi.SBAnywhereCorporate"]},
    {"name": "HDFC Bank", "keywords": ["hdfc", "hdfcbank", "payzapp"],
     "domains": ["hdfcbank.com", "hdfc.bank.in", "hdfc.com", "hdfclife.com", "hdfcergo.com"],
     "packages": ["com.snapwork.hdfc", "com.enstage.wibmo.hdfc", "com.hdfcbank.smartbuy"]},
    {"name": "ICICI Bank", "keywords": ["icici", "icicibank", "imobile"],
     "domains": ["icicibank.com", "icici.bank.in", "icicidirect.com", "iciciprulife.com", "icicilombard.com"],
     "packages": ["com.csam.icici.bank.imobile", "com.icicibank.pockets"]},
    {"name": "Axis Bank", "keywords": ["axisbank", "axis"],
     "domains": ["axisbank.com", "axis.bank.in", "axisbank.co.in"],
     "packages": ["com.axis.mobile"]},
    {"name": "Kotak Mahindra Bank", "keywords": ["kotak", "kotak811"],
     "domains": ["kotak.com", "kotak.bank.in", "kotaksecurities.com"],
     "packages": ["com.msf.kbank.mobile"]},
    {"name": "Punjab National Bank", "keywords": ["pnb", "pnbindia", "pnbone"],
     "domains": ["pnbindia.in", "pnb.bank.in", "netpnb.com"],
     "packages": ["com.Version1"]},
    {"name": "Bank of Baroda", "keywords": ["bankofbaroda", "bob", "bobworld"],
     "domains": ["bankofbaroda.in", "bankofbaroda.bank.in", "bobibanking.com"],
     "packages": ["com.bankofbaroda.mconnect"]},
    {"name": "Canara Bank", "keywords": ["canara", "canarabank"],
     "domains": ["canarabank.com", "canarabank.bank.in"], "packages": ["com.canarabank.mobility"]},
    {"name": "Union Bank of India", "keywords": ["unionbank", "unionbankofindia"],
     "domains": ["unionbankofindia.co.in", "unionbankofindia.bank.in"], "packages": ["com.infrasoft.uboi"]},
    {"name": "Paytm", "keywords": ["paytm"], "domains": ["paytm.com", "paytm.in", "paytmbank.com"],
     "packages": ["net.one97.paytm"]},
    {"name": "PhonePe", "keywords": ["phonepe"], "domains": ["phonepe.com"], "packages": ["com.phonepe.app"]},
    {"name": "Google Pay", "keywords": ["gpay", "googlepay"], "domains": ["google.com", "pay.google.com"],
     "packages": ["com.google.android.apps.nbu.paisa.user"]},
    {"name": "NPCI / BHIM UPI", "keywords": ["npci", "bhim", "bhimupi"],
     "domains": ["npci.org.in", "bhimupi.org.in"], "packages": ["in.org.npci.upiapp"]},
    {"name": "Reserve Bank of India", "keywords": ["rbi", "reservebank"], "domains": ["rbi.org.in"], "packages": []},
    {"name": "Income Tax Department", "keywords": ["incometax", "itr", "itrefund"],
     "domains": ["incometax.gov.in", "incometaxindia.gov.in"], "packages": ["in.gov.incometax.aaykar"]},
    {"name": "UIDAI / Aadhaar", "keywords": ["aadhaar", "aadhar", "uidai", "maadhaar"],
     "domains": ["uidai.gov.in"], "packages": ["in.gov.uidai.mAadhaarPlus"]},
    {"name": "EPFO", "keywords": ["epfo", "epf", "uan"], "domains": ["epfindia.gov.in"], "packages": []},
    {"name": "India Post / IPPB", "keywords": ["indiapost", "ippb", "speedpost"],
     "domains": ["indiapost.gov.in", "ippbonline.com"], "packages": ["com.ippb.ippbmobile"]},
    {"name": "Amazon", "keywords": ["amazon"], "domains": ["amazon.in", "amazon.com", "amazonpay.in"],
     "packages": ["in.amazon.mShop.android.shopping"]},
    {"name": "Flipkart", "keywords": ["flipkart"], "domains": ["flipkart.com"], "packages": ["com.flipkart.android"]},
    {"name": "Blue Dart", "keywords": ["bluedart"], "domains": ["bluedart.com"], "packages": []},
    {"name": "Delhivery", "keywords": ["delhivery"], "domains": ["delhivery.com"], "packages": []},
    {"name": "DTDC", "keywords": ["dtdc"], "domains": ["dtdc.in", "dtdc.com"], "packages": []},
    {"name": "FedEx", "keywords": ["fedex"], "domains": ["fedex.com"], "packages": []},
    {"name": "DHL", "keywords": ["dhl"], "domains": ["dhl.com", "dhl.co.in"], "packages": []},
    {"name": "Jio", "keywords": ["jio", "myjio"], "domains": ["jio.com"], "packages": ["com.jio.myjio"]},
    {"name": "Airtel", "keywords": ["airtel"], "domains": ["airtel.in", "airtel.com"], "packages": ["com.myairtelapp"]},
    {"name": "Vi (Vodafone Idea)", "keywords": ["myvi", "vodafone", "vodafoneidea"], "domains": ["myvi.in"], "packages": []},
    {"name": "IRCTC", "keywords": ["irctc"], "domains": ["irctc.co.in", "irctc.com"], "packages": ["cris.org.in.prs.ima"]},
    {"name": "Tata Power", "keywords": ["tatapower"], "domains": ["tatapower.com", "tatapower-ddl.com"], "packages": []},
    {"name": "Adani Electricity", "keywords": ["adanielectricity"], "domains": ["adanielectricity.com"], "packages": []},
    {"name": "BSES", "keywords": ["bses", "bsesdelhi"], "domains": ["bsesdelhi.com"], "packages": []},
    {"name": "MSEDCL (Mahavitaran)", "keywords": ["mahadiscom", "msedcl", "mahavitaran"],
     "domains": ["mahadiscom.in"], "packages": []},
    {"name": "BESCOM", "keywords": ["bescom"], "domains": ["bescom.co.in", "bescom.karnataka.gov.in"], "packages": []},
    {"name": "WhatsApp", "keywords": ["whatsapp"], "domains": ["whatsapp.com", "wa.me"], "packages": ["com.whatsapp"]},
    {"name": "Telegram", "keywords": ["telegram"], "domains": ["telegram.org", "t.me"], "packages": ["org.telegram.messenger"]},
    {"name": "CBI", "keywords": ["cbi"], "domains": ["cbi.gov.in"], "packages": []},
    {"name": "TRAI", "keywords": ["trai"], "domains": ["trai.gov.in"], "packages": []},
    {"name": "Customs (CBIC)", "keywords": ["cbic", "icegate"], "domains": ["cbic.gov.in", "icegate.gov.in"], "packages": []},
    {"name": "Zerodha", "keywords": ["zerodha", "kite"], "domains": ["zerodha.com"], "packages": ["com.zerodha.kite3"]},
    {"name": "Groww", "keywords": ["groww"], "domains": ["groww.in"], "packages": ["com.nextbillion.groww"]},
]

# Second-level suffixes we treat as one public suffix when computing the registrable domain.
MULTI_SUFFIXES = {
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "res.in", "gov.in",
    "nic.in", "mil.in", "bank.in", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "com.sg", "com.my", "com.br", "com.cn", "com.hk", "co.jp", "co.za", "com.pk", "com.bd",
    "com.np", "com.lk", "co.id", "com.ph", "com.vn", "com.tr", "com.mx", "com.ar", "co.kr", "github.io",
    "blogspot.com", "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "glitch.me", "000webhostapp.com", "weebly.com", "wixsite.com", "carrd.co",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "repl.co", "onrender.com", "azurewebsites.net",
    "appspot.com", "translate.goog", "duckdns.org", "sites.google.com",
}

# Platforms where anybody can host a page under the platform's domain.
FREE_HOSTING = {
    "github.io", "blogspot.com", "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "netlify.app",
    "vercel.app", "herokuapp.com", "glitch.me", "000webhostapp.com", "weebly.com", "wixsite.com",
    "carrd.co", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "repl.co", "onrender.com",
    "azurewebsites.net", "appspot.com", "duckdns.org", "sites.google.com", "godaddysites.com",
    "webflow.io", "framer.website", "my.canva.site", "forms.gle", "docs.google.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "t.ly", "shorturl.at",
    "ow.ly", "rebrand.ly", "tiny.cc", "s.id", "bitly.ws", "v.gd", "shorte.st", "adf.ly", "short.gy",
    "lnkd.in", "surl.li", "u.to", "clck.ru", "qr.ae", "bl.ink", "tny.im", "inx.lv", "shrtco.de",
    "urlzs.com", "1url.com", "x.gd", "ii.ad", "dub.sh", "bit.do", "linktr.ee",
}

# TLDs heavily abused for throw-away fraud domains (Spamhaus / Interisle reports).
RISKY_TLDS = {
    "xyz", "top", "icu", "buzz", "click", "link", "online", "site", "shop", "store", "live", "vip", "win",
    "bet", "loan", "cyou", "sbs", "cfd", "bond", "lat", "rest", "fun", "monster", "quest", "work", "tk",
    "ml", "ga", "cf", "gq", "pw", "cc", "ws", "su", "rest", "hair", "beauty", "skin", "makeup", "autos",
    "boats", "homes", "mom", "lol", "today", "life", "space", "website", "club", "asia", "pro", "zip", "mov",
}

TRUSTED_SUFFIXES = ("gov.in", "nic.in", "bank.in", "mil.in", "ac.in", "edu.in", "res.in")


def official_domains() -> set[str]:
    out = set()
    for b in BRANDS:
        out.update(b["domains"])
    return out


def legit_packages() -> dict[str, str]:
    return {p: b["name"] for b in BRANDS for p in b["packages"]}
