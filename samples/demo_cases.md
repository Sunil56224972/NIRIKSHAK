# NIRIKSHAK (PS01) — Synthetic Demo Dataset

All entries below are **100% synthetic test fixtures** (no real personal data).
Use them in `/analyze` (officer console), `/report` (citizen portal), `/check`, or `tools/telegram_bot.py`.

---

## 1. Sample Scam & Genuine Messages (SMS / WhatsApp / E-mail)

### A. Fake KYC + Urgency + Typosquat Domain (High Risk — SMS)
- **Channel:** `SMS`
- **Sender:** `+91 90000 11223`
- **Message:**
```text
Dear Customer, Your SBI YONO A/C will be BLOCKED today due to pending PAN eKYC update! Complete verification within 2 hours at https://sbi-kyc-update.top/login or call +91 90000 11223 immediately.
```

### B. Digital Arrest / Law-Enforcement Impersonation + Mule UPI (High Risk — WhatsApp)
- **Channel:** `WhatsApp`
- **Sender:** `+44 7900 123456`
- **Message:**
```text
URGENT NOTICE: CBI & Narcotics Dept intercepted an illegal parcel in your Aadhaar name for money laundering. Your SIM will be blocked in 2 hours under Digital Arrest warrant. Transfer refundable verification deposit immediately to fastprofit99@ybl or install https://wealthboost-vip-demo.top/support.apk to join officer video verification.
```

### C. E-mail with Spoofed Headers & Auth Failures (High Risk — E-mail)
- **Channel:** `E-mail`
- **Message (full raw source):**
```email
From: "SBI Cards Verification" <alert-security-demo@gmail.com>
Reply-To: support@sbi-kyc-update.top
Subject: Final Warning: Update your PAN e-KYC today
Authentication-Results: mx.demo.local; spf=fail smtp.mailfrom=evil-demo.top; dkim=fail; dmarc=fail

Your net banking account will be suspended tonight. Update KYC and share OTP at https://sbi-kyc-update.top/verify or pay verification Rs 10 to fastprofit99@ybl.
```

### D. Legitimate Official Message (Low Risk — Baseline Control)
- **Channel:** `SMS`
- **Sender:** `AX-SBIINB-S`
- **Message:**
```text
Rs 1,250.00 debited from A/c XX4821 on 21-Nov-26 via UPI Ref 632109876543. If not done by you, report at https://www.sbi.co.in or call 1800 11 2211.
```

---

## 2. Suspicious & Legitimate URLs (`/analyze?type=url` or `/check`)

| Label | Sample URL | Expected Signals |
|---|---|---|
| Phishing typosquat + risky TLD | `https://sbi-kyc-update.top/login` | Brand impersonation (`SBI`), `.top` TLD, lure words |
| Credential homoglyph / defanged | `hxxps://hdfc-netb4nk[.]xyz/ekyc` | Defang normalization, brand keyword, `.xyz` TLD |
| Direct sideload APK link | `https://wealthboost-vip-demo.top/app/wealthboost-vip.apk` | Direct APK download (+30), scam domain |
| Legitimate official bank | `https://www.sbi.co.in/` | Verified official entity (`State Bank of India`) |
| Legitimate govt cyber portal | `https://cybercrime.gov.in/` | Regulated `.gov.in` registry |

---

## 3. Sample Android APKs & App-Store Links (`/analyze?type=apk`)

All APKs in `samples/` are safe synthetic test packages built by [tools/make_test_apk.py](../tools/make_test_apk.py) (static analysis only):
- [test_fake_loan.apk](test_fake_loan.apk) — Predatory loan profile (SMS, Contacts, Call Log, Camera, AOSP test key, embedded HTTP IP & UPI) → **HIGH RISK**
- [test_sbi_reward_clone.apk](test_sbi_reward_clone.apk) — SBI reward clone (`com.sbi.reward.claim.clone`, Accessibility + Overlay + SMS + C2 endpoint `sbi-kyc-update.top`) → **HIGH RISK**
- [test_benign_notes.apk](test_benign_notes.apk) — Clean minimal notes app → **LOW RISK**
- **Store link (removed/suspicious):** `https://play.google.com/store/apps/details?id=com.instantcash.demo.loan`
- **Store link (official control):** `https://play.google.com/store/apps/details?id=com.sbi.lotusintouch`

---

## 4. Saved Fraudulent Websites & Screenshot PNG (`/analyze?type=website`)

- [demo_ponzi_mlm_site.html](demo_ponzi_mlm_site.html) — Synthetic Ponzi + MLM investment site (`WealthBoost VIP`: 15% daily return, Level 1–3 referrals, UPI `fastprofit99@ybl`, IFSC `SBIN0000123`, bank A/C `11002233445566`, phone `+91 90000 11223`, Telegram, `.apk` link, offsite OTP form)
- [demo_betting_loan_site.html](demo_betting_loan_site.html) — Synthetic betting + instant no-CIBIL loan site (`LuckyWin365`: IPL/colour prediction, 200% bonus, `upi://pay?pa=luckywin365@okaxis`, WhatsApp `+91 90000 44556`, `.apk` link)
- [demo_ponzi_screenshot.png](demo_ponzi_screenshot.png) — Synthetic PNG screenshot of `WealthBoost VIP` for testing automatic Screenshot OCR extraction (Tesseract / WinRT / Cloud OCR)

---

## 5. Cross-Channel Correlation Demo Flow (2-Minute Judging Script)

1. Submit **Message A** (`SMS` with `+91 90000 11223` & `sbi-kyc-update.top`).
2. Upload **`demo_ponzi_mlm_site.html`** (`Website` sharing `+91 90000 11223` & `fastprofit99@ybl`).
3. Upload **`demo_ponzi_screenshot.png`** (`Website` screenshot) or **`Message B`** (`WhatsApp` sharing `fastprofit99@ybl` & `wealthboost-vip-demo.top`).
4. Open the newest case → see **"Links to other records"** & `intel.cross_channel` (`Same identifier reused across channels`), open **Identifiers** / **Heat-list**, generate **Nodal Notice (.txt)** and **Case Report (PDF)**.
