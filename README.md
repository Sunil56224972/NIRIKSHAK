# NIRIKSHAK

**Cyber Fraud Analysis & Investigation Platform (PS01)**

NIRIKSHAK is a unified operational triage and digital investigation system built for cybercrime units and investigating officers. It ingests suspicious **SMS/WhatsApp/e-mail messages**, **URLs**, **fraudulent investment/Ponzi/betting websites & screenshots**, and **Android APK packages / app-store links**; produces transparent, weight-backed risk verdicts (`LOW` / `MEDIUM` / `HIGH`); extracts actionable financial and infrastructure identifiers; correlates shared indicators across cases; and exports investigation-ready PDF reports and Section 94 BNSS / Section 91 CrPC nodal action summaries.

---

## Problem Statement & Scope

Fraud campaigns regularly reuse the same mule UPI IDs, bank accounts, phone numbers, domains, hosting IPs, and app signing certificates across separate phishing links, scam messages, loan apps, and Ponzi portals. Reviewing these artifacts in isolation misses operational links.

**In scope**
- Multi-modal static and live infrastructure triage for messages, URLs, websites, saved pages/screenshots, and Android APKs.
- Explainable indicator scoring (every point on the 0–100 scale maps to an explicit rule, network observation, or intelligence match).
- Automatic cross-case entity correlation, near-duplicate template clustering, 30-day heat-lists, and fraud-confirmation blocklist promotion.
- Public citizen reporting portal (`/report`), pre-click link warning page (`/check`), Chrome extension, and citizen Telegram bot.
- Evidence preservation (SHA-256 verification on download) and formal police investigation outputs (PDF dossier, plain-text nodal notice, CSV, JSON).

**Explicitly out of scope**
- Dynamic / runtime malware detonation in an emulator or sandbox.
- Automated takedowns of external websites, apps, or accounts.
- Accessing private accounts or non-public subscriber data.

---

## Architecture

```text
  [ Officer Console ]          [ Citizen Portal ]        [ Chrome Extension ]       [ Telegram Bot ]
  / , /analyze, /cases         /report , /check          context menu & popup       tools/telegram_bot.py
          |                            |                          |                          |
          +----------------------------+--------------------------+--------------------------+
                                       |
                                       v
                     FastAPI + Jinja2 Application (app/main.py)
                     - Signed session cookies & double-submit CSRF
                     - Strict CSP (no inline scripts/styles), RBAC, Audit Log
                                       |
                                       v
                       Case Orchestrator (app/service.py)
          +---------------+------------+------------+---------------+---------------+
          |               |                         |               |               |
          v               v                         v               v               v
     message.py       urlscan.py               website.py        apk.py         iocs.py /
     Scam rules,      Brand impersonation,     HTML/MHTML/OCR    AXML/ARSC/     similarity.py /
     SPF/DKIM/DMARC,  DNS, RDAP + WHOIS:43,    forms, JS flags,  DEX strings,   linkchart.py
     sender checks    redirects, TLS, GSB      UPI/crypto        v1/v2/v3 certs
                                       |
                                       v
             Supabase PostgreSQL + Private Storage (nk-evidence) + Local Evidence Cache
             Tables: nk_users, nk_cases, nk_entities, nk_case_entities,
                     nk_evidence, nk_blocklist, nk_audit
             RPCs:   nk_link_entities, nk_heatlist, nk_stats, nk_is_server
```

---

## Analysis Engines

### 1. Message Analysis (`app/analysis/message.py`)
- Detects scam taxonomies across English, Hinglish, and Hindi phrasing: fake KYC / PAN / account block, electricity disconnection threats, parcel/customs lures, digital arrest / law-enforcement impersonation, task/part-time job scams, guaranteed-return investments, instant loans, lottery/rewards, tax/subsidy refunds, sextortion, and betting promotions.
- Checks urgency pressure, OTP / UPI PIN / CVV / remote-access requests (`AnyDesk`, `TeamViewer`, `RustDesk`), and calls to action.
- Inspects sender attribution (TRAI DLT header format vs. personal Indian mobile number vs. international prefix).
- Parses raw e-mail source headers (`From`, `Reply-To` mismatch, `Authentication-Results` SPF/DKIM/DMARC failures, free-mail impersonation).
- Extracts and analyses every embedded URL/domain (propagating resolved hosting IPs into the case's identifier graph).

### 2. URL & Infrastructure Analysis (`app/analysis/urlscan.py`, `app/analysis/netintel.py`, `app/analysis/brands.py`)
- Lexical & look-alike detection against documented official domains of major Indian banks, UPI/wallet providers, government agencies, couriers, telecoms, and DISCOMs using token matching, Levenshtein edit distance, homoglyph skeletons, and IDNA/punycode decoding (`xn--`).
- Flags raw IP hosts, public link shorteners, free/disposable hosting platforms, high-abuse TLDs, `@` userinfo tricks, non-standard ports, lure keywords, and direct `.apk` download links.
- Live server-side checks (SSRF-safe: refuses loopback, private, link-local, CGNAT, and reserved IPs):
  - DNS A/AAAA resolution and IP network ownership via RDAP.
  - Domain registration age, registrar, nameservers, and registrar abuse contacts via RDAP with pure-socket port-43 WHOIS fallback (`whois.iana.org` -> registry/registrar WHOIS).
  - Hop-by-hop HTTP redirect chain tracing plus HTML `<meta refresh>` and JavaScript `location` redirect detection.
  - TLS certificate verification, issuer, and issuance recency.
  - Optional Google Safe Browsing v4 lookup (`GOOGLE_SAFE_BROWSING_KEY`).

### 3. Website & Screenshot Analysis (`app/analysis/website.py`)
- Accepts live URLs, uploaded `.html`/`.htm`/`.mhtml`/`.txt` snapshots, or website screenshots (`.png`, `.jpg`, `.jpeg`, `.webp`, `.bmp`).
- Automatically runs OCR on uploaded screenshots via `pytesseract` + Tesseract OCR (Linux/Docker) or native Windows OCR (`Windows.Media.Ocr.OcrEngine` on Windows 10/11).
- Inspects visible text and client-side scripts for guaranteed returns, MLM referral/level structures, betting/colour-prediction terminology, task/recharge traps, fake loan offers, fake RBI/SEBI claims, sensitive forms (`otp`, `card`, `upi_pin`, `aadhaar`, `pan`, `password`), off-site form POST targets, obfuscated `eval(atob(...))`, Telegram bot exfiltration (`api.telegram.org/bot`), and `.apk` download links.
- Preserves fetched HTML or uploaded snapshots as SHA-256-indexed evidence.

### 4. Static Android APK & App-Store Analysis (`app/analysis/apk.py`)
- Pure-Python static parsers with no external Android SDK required (never executes the APK):
  - Binary `AndroidManifest.xml` (`AXML`) decoder for package name, SDK levels, debuggable/cleartext flags, permissions, launcher visibility, deep links, and SMS/boot/device-admin receivers.
  - `resources.arsc` (`ARSC`) lookup for app labels and launcher icons.
  - `classes*.dex` string table scanner for embedded URLs, IPs, UPI IDs, and sensitive API markers (`content://sms`, `sendTextMessage`, `ContactsContract`, `performGlobalAction`, `DexClassLoader`, `api.telegram.org/bot`).
  - APK signing certificate extractor supporting v1 JAR (`META-INF/*.RSA|DSA|EC`), v2, and v3/v3.1 signature schemes.
  - Detects predatory loan permission profiles, accessibility/notification/overlay abuse, native packer libraries, embedded secondary APK/DEX payloads, and Android debug/AOSP test keys.
  - Computes 8x8 perceptual average hash (`ahash`) of the launcher icon and correlates against previously flagged APKs for icon cloning, signing certificate reuse, app name clones, and package-family similarity.
- Supports app-store URLs on Google Play (`play.google.com`, `market://`), Apple App Store (`apps.apple.com`), and third-party APK portals (`apkpure`, `uptodown`, `apkcombo`, `apkmirror`).

### 5. Actionable Identifier Extraction (`app/analysis/iocs.py`)
Normalises and extracts identifiers into `nk_entities` for cross-case correlation:
- **Payment:** UPI VPAs & `upi://pay` links (attributed to NPCI PSP sponsor banks), bank account numbers, RBI IFSC codes (mapped to bank names), and checksum-validated crypto wallets (TRON USDT TRC-20, EVM/ETH/BSC, Bitcoin legacy & bech32).
- **Telecom & Messaging:** Indian mobile numbers (`+91`), toll-free numbers, Telegram handles/channels, WhatsApp click-to-chat numbers & group invites, and e-mail addresses.
- **Infrastructure & Apps:** URLs, registrable/full domains, IPv4 addresses, Android package names, APK SHA-256 digests, and signing certificate SHA-256 fingerprints.

---

## Explainable Scoring, Correlation & Exports

- **Additive Risk Scoring (`app/analysis/scoring.py`):** Indicators carry explicit positive or negative weights summed into `0–100` (`LOW < 30`, `MEDIUM 30–59`, `HIGH >= 60`). Decisive intelligence enforces score floors: local blocklist match (`>= 75`), identifier linked to a case closed as confirmed fraud (`>= 65`), Google Safe Browsing hit (`>= 80`).
- **Cross-Case Correlation & Clustering (`app/service.py`, `app/analysis/similarity.py`):** Links every extracted identifier across messages, URLs, websites, and APKs; detects repeat scam scripts using 4-word shingle Jaccard similarity; renders clickable 3-column SVG link diagrams (`app/analysis/linkchart.py`).
- **Blocklist & Live Threat Feeds (`app/feeds.py`):** Closing a case as *fraud confirmed* promotes its non-shared malicious indicators to `nk_blocklist`. Administrators can also sync active threat feeds from **OpenPhish** and **Phishing Army**.
- **Investigation Exports:**
  - **PDF Case Report (`app/report.py`):** ReportLab dossier with case metadata, weighted indicator breakdown, attributed IOCs, linked cases, technical telemetry, evidence SHA-256 manifest, and audit trail.
  - **Nodal Notice (`app/notice.py`):** Plain-text Section 94 BNSS / Section 91 CrPC action summary grouped by Payment/Banking, Telecom/Messaging, Domain Registrar/Hosting, and Mobile App identifiers.
  - **CSV & JSON:** Formula-injection-safe CSV exports for `/cases/export.csv` and `/heatlist/export.csv`, plus structured case JSON.

---

## Security Controls

- **Authentication & Sessions (`app/auth.py`):** PBKDF2-SHA256 (`310,000` iterations, per-user random salt), constant-time dummy verification on unknown usernames to prevent timing enumeration, dual IP and `IP:username` brute-force lockout, password complexity checks, signed `HttpOnly` `SameSite=Strict` session cookies invalidated on password rotation.
- **CSRF & Origin Guard (`app/main.py`):** Signed double-submit CSRF cookie (`nk_csrf`) paired with hidden `csrf_token` validation on every POST form, plus `Sec-Fetch-Site: cross-site` and `Origin`/`Referer` enforcement.
- **HTTP Hardening:** Strict Content-Security-Policy (`default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Permissions-Policy`, `COOP`, and `CORP`.
- **Upload & Download Safety:** Chunked bounded file reads, non-inline attachment downloads (`application/octet-stream`), sanitized `Content-Disposition` filenames, and mandatory SHA-256 verification before serving stored evidence.
- **Database Isolation (`supabase/schema.sql`, `app/db.py`):** Row-Level Security enabled on all `nk_*` tables and functions (`nk_is_server()`), blocking unauthenticated public/anon requests while authenticating the backend via `service_role` or server-side `x-nk-server-secret`.

---

## Routes Reference

| Path | Access | Purpose |
|---|---|---|
| `/setup` | Public (first run) | Create initial administrator account when `nk_users` is empty |
| `/login`, `/logout` | Public / Officer | Officer sign-in and session termination |
| `/` | Officer | Operational dashboard, recent cases, citizen queue, 30-day heat-list |
| `/analyze` | Officer | Submit message, URL/store link, website/screenshot, or APK |
| `/cases` | Officer | Searchable/filterable case register across text & extracted IOCs |
| `/cases/export.csv` | Officer | Export filtered case register as CSV |
| `/cases/{id}` | Officer | Case dossier, indicators, IOCs, linked cases, technical telemetry, status |
| `/cases/{id}/report.pdf` | Officer | Download investigation-ready PDF report |
| `/cases/{id}/notice.txt` | Officer | Download Section 94 BNSS / Section 91 CrPC nodal summary |
| `/cases/{id}/export.json` | Officer | Export full structured case record as JSON |
| `/evidence/{id}` | Officer | SHA-256-verified download of preserved evidence artifact |
| `/identifiers` | Officer | Searchable index of all extracted IOCs |
| `/identifiers/{id}` | Officer | Identifier dossier with SVG link diagram & co-occurring entities |
| `/heatlist` | Officer | Trending domains, phones, UPI IDs, apps, wallets (`1/7/30/90/365` days) |
| `/heatlist/export.csv` | Officer | Export heat-list rankings as CSV |
| `/blocklist` | Officer / Admin | View/add blocklist entries; sync OpenPhish & Phishing Army feeds (admin) |
| `/users`, `/audit` | Admin | Manage officer accounts and inspect audit log |
| `/account` | Officer | View profile and change password |
| `/report` | Public | Citizen submission portal with immediate explainable risk verdict |
| `/check?u=` | Public | Pre-click link inspection & warning page |
| `/api/check?u=` | Public | JSON risk verdict endpoint (used by Chrome extension) |
| `/health` | Public | Database ping & live-check status |

---

## Repository Structure

```text
.
├── app/
│   ├── analysis/
│   │   ├── apk.py          # AXML, ARSC, DEX strings, v1/v2/v3 certs, store links
│   │   ├── brands.py       # Impersonation reference domains/packages, free hosts, shorteners
│   │   ├── iocs.py         # IOC extraction & UPI PSP / RBI IFSC / crypto attribution
│   │   ├── linkchart.py    # CSP-safe SVG entity correlation diagram
│   │   ├── message.py      # SMS/WhatsApp/email scam & header analyzer
│   │   ├── netintel.py     # SSRF-safe HTTP fetcher, RDAP, port-43 WHOIS, TLS, GSB
│   │   ├── scoring.py      # Explainable weighted Indicator & Findings model
│   │   ├── similarity.py   # 4-word shingle bottom-k Jaccard template matching
│   │   ├── urlscan.py      # Lexical, homoglyph/punycode & live infrastructure checks
│   │   └── website.py      # Live/HTML/MHTML/OCR website & form analyzer
│   ├── static/
│   │   ├── app.js          # Minimal progressive enhancements
│   │   └── style.css       # Dense console stylesheet
│   ├── templates/          # Jinja2 officer console & public citizen templates
│   ├── auth.py             # PBKDF2 auth, session cookies, CSRF tokens, lockout, audit
│   ├── config.py           # Environment configuration & validation
│   ├── db.py               # Thread-safe Supabase PostgREST & Storage client
│   ├── feeds.py            # OpenPhish & Phishing Army blocklist sync
│   ├── main.py             # FastAPI routes, security middleware, CSV/PDF/notice endpoints
│   ├── notice.py           # Section 94 BNSS / Section 91 CrPC nodal notice generator
│   ├── report.py           # ReportLab PDF report builder
│   └── service.py          # Analysis orchestration, correlation & persistence
├── extension/              # Chrome MV3 extension ("Inspect link with NIRIKSHAK")
├── samples/                # Inert synthetic test APKs generated by tools/make_test_apk.py
├── supabase/schema.sql     # PostgreSQL tables, indexes, RLS & RPC functions
├── tools/
│   ├── make_test_apk.py    # Generates inert synthetic APKs for offline testing
│   └── telegram_bot.py     # Citizen Telegram reporting bot
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── run.py
```

---

## Setup & Running

### 1. Database Initialization (Supabase)
Apply [`supabase/schema.sql`](supabase/schema.sql) to your Supabase project (creates `nk_users`, `nk_cases`, `nk_entities`, `nk_case_entities`, `nk_evidence`, `nk_blocklist`, `nk_audit`, sequence `nk_case_no_seq`, bucket `nk-evidence`, and functions `nk_link_entities`, `nk_heatlist`, `nk_stats`).

### 2. Local Python Run
```bash
pip install -r requirements.txt
copy .env.example .env      # configure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_API_KEY + NK_DB_SECRET)
python run.py               # http://127.0.0.1:8000
```
Open `http://127.0.0.1:8000` — first visit routes to `/setup` to create the initial administrator account.

### 3. Docker Run (includes Tesseract OCR)
```bash
copy .env.example .env      # fill Supabase credentials
docker compose up --build   # listens on 127.0.0.1:8000
```

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SUPABASE_URL` | Yes | — | Supabase project URL (`https://<ref>.supabase.co`) |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes* | — | Supabase `service_role` secret key (server-side only) |
| `SUPABASE_API_KEY` + `NK_DB_SECRET` | Alt* | — | Publishable key paired with RLS `x-nk-server-secret` header |
| `NK_UNIT_NAME` | No | `Cyber Crime Cell` | Police unit header shown in UI, PDFs, and nodal notices |
| `NK_LIVE_CHECKS` | No | `1` | Set `0` on air-gapped terminals to disable outbound DNS/RDAP/HTTP/TLS checks |
| `NK_NET_TIMEOUT` | No | `8` | Network lookup timeout in seconds |
| `NK_MAX_APK_MB` | No | `150` | Maximum APK upload size in MB for officers |
| `GOOGLE_SAFE_BROWSING_KEY` | No | — | Enables Google Safe Browsing v4 URL lookups |
| `TELEGRAM_BOT_TOKEN` | No | — | Bot token for `python tools/telegram_bot.py` |

---

## Companion Citizen Tools & Test Samples

- **Chrome Extension (`extension/`):** Load `extension/` as an unpacked MV3 extension in Chrome/Edge to right-click any link (*Inspect link with NIRIKSHAK*) or check the active tab URL via `/api/check` and `/check`.
- **Citizen Telegram Bot:** Set `TELEGRAM_BOT_TOKEN` in `.env` and run `python tools/telegram_bot.py` to accept forwarded scam messages/URLs, create citizen cases in Supabase, and return reference numbers + `1930` helpline advice.
- **Inert APK Samples (`tools/make_test_apk.py`):** Run `python tools/make_test_apk.py` to regenerate three inert synthetic `.apk` files in `samples/` (`test_fake_loan.apk`, `test_sbi_reward_clone.apk`, `test_benign_notes.apk`) containing valid AXML manifests, DEX string tables, icons, and v1 JAR signatures with zero executable code.
