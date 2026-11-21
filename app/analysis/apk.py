"""Static Android APK analysis (no execution, per PS01 scope).

Implements, without third-party Android tooling:
  * Android binary XML (AXML) decoding of AndroidManifest.xml
  * resources.arsc lookup for the app label and launcher icon
  * DEX string-table extraction (URLs, IPs, UPI IDs, API usage)
  * APK signing certificate extraction (v1 JAR / v2 / v3 signature schemes)
"""
from __future__ import annotations

import hashlib
import html as html_mod
import io
import re
import struct
import zipfile
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from . import iocs as ioc_mod
from .brands import BRANDS, legit_packages
from .scoring import Findings

# ----------------------------------------------------------------------------- AXML
RES_NAMES = {
    0x01010001: "label", 0x01010002: "icon", 0x01010003: "name", 0x01010006: "permission",
    0x0101000E: "enabled", 0x01010010: "exported", 0x0101000F: "debuggable", 0x01010020: "description",
    0x0101021B: "versionCode", 0x0101021C: "versionName", 0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion", 0x01010271: "maxSdkVersion", 0x01010280: "allowBackup",
    0x010104EC: "usesCleartextTraffic", 0x01010027: "scheme", 0x01010028: "host", 0x0101002A: "path",
    0x01010024: "value", 0x01010025: "resource", 0x0101001F: "process", 0x01010018: "authorities",
    0x0101020D: "priority", 0x01010026: "mimeType", 0x01010009: "targetActivity",
}


def _string_pool(d: bytes, off: int) -> list[str]:
    _t, hsz, _size, count, _styles, flags, sstart, _ss = struct.unpack_from("<HHIIIIII", d, off)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", d, off + hsz)
    base = off + sstart
    out = []
    for o in offsets:
        p = base + o
        try:
            if utf8:
                n = d[p]; p += 1
                if n & 0x80:
                    p += 1
                n = d[p]; p += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | d[p]; p += 1
                out.append(d[p:p + n].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", d, p)[0]; p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, p)[0]; p += 2
                out.append(d[p:p + n * 2].decode("utf-16-le", "replace"))
        except (IndexError, struct.error):
            out.append("")
    return out


class AXML:
    """Decode a compiled Android XML document into (depth, tag, attrs) elements."""

    def __init__(self, data: bytes):
        self.d = data
        self.strings: list[str] = []
        self.resids: list[int] = []
        self.elements: list[tuple[int, str, dict]] = []
        self._parse()

    def _s(self, i: int) -> str:
        return self.strings[i] if 0 <= i < len(self.strings) else ""

    def _typed(self, vtype: int, data: int) -> str:
        if vtype == 0x03:
            return self._s(data)
        if vtype == 0x10:
            return str(struct.unpack("<i", struct.pack("<I", data))[0])
        if vtype == 0x11:
            return hex(data)
        if vtype == 0x12:
            return "true" if data else "false"
        if vtype in (0x01, 0x02):
            return f"@0x{data:08X}"
        if vtype == 0x04:
            return str(struct.unpack("<f", struct.pack("<I", data))[0])
        return str(data)

    def _parse(self) -> None:
        d = self.d
        if len(d) < 8:
            raise ValueError("manifest too short")
        _t, hsz, _size = struct.unpack_from("<HHI", d, 0)
        off, depth = hsz or 8, 0
        while off + 8 <= len(d):
            ctype, chsz, csize = struct.unpack_from("<HHI", d, off)
            if csize < 8 or off + csize > len(d):
                break
            if ctype == 0x0001:
                self.strings = _string_pool(d, off)
            elif ctype == 0x0180:
                n = (csize - chsz) // 4
                self.resids = list(struct.unpack_from(f"<{n}I", d, off + chsz))
            elif ctype == 0x0102:
                ext = off + chsz
                _ns, name_i, a_start, a_size, a_count = struct.unpack_from("<IIHHH", d, ext)
                tag = self._s(name_i)
                attrs = {}
                a_size = a_size or 20
                for i in range(a_count):
                    p = ext + a_start + i * a_size
                    if p + 20 > len(d):
                        break
                    _ans, aname, araw, _vs, _r0, vtype, vdata = struct.unpack_from("<IIIHBBI", d, p)
                    name = self._s(aname)
                    if aname < len(self.resids) and self.resids[aname] in RES_NAMES:
                        name = RES_NAMES[self.resids[aname]]
                    elif not name:
                        name = f"attr_{aname}"
                    attrs[name] = self._s(araw) if araw != 0xFFFFFFFF else self._typed(vtype, vdata)
                self.elements.append((depth, tag, attrs))
                depth += 1
            elif ctype == 0x0103:
                depth = max(0, depth - 1)
            off += csize


# ----------------------------------------------------------------------------- ARSC
class ARSC:
    """Minimal resources.arsc reader: resolves resource IDs to strings / file paths."""

    def __init__(self, data: bytes):
        self.d = data
        self.global_strings: list[str] = []
        self.entries: dict[int, list[tuple[bool, int, int]]] = {}  # resid -> [(default_cfg, dtype, data)]
        self._parse()

    def _parse(self) -> None:
        d = self.d
        _t, hsz, _size, _pkgs = struct.unpack_from("<HHII", d, 0)
        off = hsz
        while off + 8 <= len(d):
            ctype, chsz, csize = struct.unpack_from("<HHI", d, off)
            if csize < 8:
                break
            if ctype == 0x0001 and not self.global_strings:
                self.global_strings = _string_pool(d, off)
            elif ctype == 0x0200:
                self._package(off, chsz, csize)
            off += csize

    def _package(self, off: int, hsz: int, size: int) -> None:
        d = self.d
        pkg_id = struct.unpack_from("<I", d, off + 8)[0]
        p, end = off + hsz, off + size
        while p + 8 <= end:
            ctype, chsz, csize = struct.unpack_from("<HHI", d, p)
            if csize < 8:
                break
            if ctype == 0x0201:
                self._type_chunk(pkg_id, p, chsz)
            p += csize

    def _type_chunk(self, pkg_id: int, off: int, hsz: int) -> None:
        d = self.d
        type_id, flags, _res, count, entries_start = struct.unpack_from("<BBHII", d, off + 8)
        cfg_off = off + 20
        language = struct.unpack_from("<H", d, cfg_off + 8)[0] if cfg_off + 10 <= len(d) else 0
        density = struct.unpack_from("<H", d, cfg_off + 14)[0] if cfg_off + 16 <= len(d) else 0
        default_cfg = language == 0
        idx_off = off + hsz
        pairs: list[tuple[int, int]] = []
        if flags & 0x01:  # sparse
            for i in range(count):
                eidx, eoff = struct.unpack_from("<HH", d, idx_off + i * 4)
                pairs.append((eidx, eoff * 4))
        elif flags & 0x02:  # offset16
            for i in range(count):
                v = struct.unpack_from("<H", d, idx_off + i * 2)[0]
                if v != 0xFFFF:
                    pairs.append((i, v * 4))
        else:
            for i in range(count):
                v = struct.unpack_from("<I", d, idx_off + i * 4)[0]
                if v != 0xFFFFFFFF:
                    pairs.append((i, v))
        base = off + entries_start
        for eidx, eoff in pairs:
            e = base + eoff
            if e + 8 > len(d):
                continue
            esize, eflags, key = struct.unpack_from("<HHI", d, e)
            if eflags & 0x0008:   # compact entry
                dtype, data = eflags >> 8, key
            elif eflags & 0x0001:  # complex/map entry
                continue
            else:
                if e + esize + 8 > len(d):
                    continue
                _vs, _r0, dtype, data = struct.unpack_from("<HBBI", d, e + esize)
            resid = (pkg_id << 24) | (type_id << 16) | eidx
            self.entries.setdefault(resid, []).append((default_cfg, dtype, data, density))

    def resolve(self, resid: int, depth: int = 0) -> list[str]:
        vals = self.entries.get(resid, [])
        vals = sorted(vals, key=lambda v: (not v[0], -v[3]))
        out = []
        for _default, dtype, data, _dens in vals:
            if dtype == 0x03 and data < len(self.global_strings):
                out.append(self.global_strings[data])
            elif dtype == 0x01 and depth < 3:
                out.extend(self.resolve(data, depth + 1))
        return out


# ----------------------------------------------------------------------------- DEX
def dex_strings(d: bytes, limit: int = 400_000) -> list[str]:
    if len(d) < 0x70 or not d.startswith(b"dex\n"):
        return []
    size, off = struct.unpack_from("<II", d, 0x38)
    out = []
    for i in range(min(size, limit)):
        try:
            p = struct.unpack_from("<I", d, off + i * 4)[0]
            shift = 0
            while True:
                b = d[p]; p += 1
                if b < 0x80:
                    break
                shift += 7
                if shift > 35:
                    break
            end = d.index(b"\x00", p, p + 65536)
            out.append(d[p:end].decode("utf-8", "replace"))
        except (struct.error, IndexError, ValueError):
            continue
    return out


# ----------------------------------------------------------------------------- Signatures
def _lp(buf: bytes, pos: int) -> tuple[bytes, int]:
    n = struct.unpack_from("<I", buf, pos)[0]
    return buf[pos + 4:pos + 4 + n], pos + 4 + n


def _v2v3_certs(raw: bytes) -> dict[str, list[bytes]]:
    out: dict[str, list[bytes]] = {}
    tail = raw[-65557:]
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        return out
    eocd = len(raw) - len(tail) + i
    cd_off = struct.unpack_from("<I", raw, eocd + 16)[0]
    if cd_off < 32 or raw[cd_off - 16:cd_off] != b"APK Sig Block 42":
        return out
    block_size = struct.unpack_from("<Q", raw, cd_off - 24)[0]
    start = cd_off - block_size - 8
    if start < 0:
        return out
    pos, end = start + 8, cd_off - 24
    schemes = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1"}
    while pos + 12 <= end:
        ln = struct.unpack_from("<Q", raw, pos)[0]
        pid = struct.unpack_from("<I", raw, pos + 8)[0]
        val = raw[pos + 12:pos + 8 + ln]
        if pid in schemes:
            certs = []
            try:
                signers, _ = _lp(val, 0)
                sp = 0
                while sp < len(signers):
                    signer, sp = _lp(signers, sp)
                    signed_data, _ = _lp(signer, 0)
                    _digests, q = _lp(signed_data, 0)
                    cert_seq, _ = _lp(signed_data, q)
                    cp = 0
                    while cp < len(cert_seq):
                        c, cp = _lp(cert_seq, cp)
                        certs.append(c)
            except struct.error:
                pass
            out[schemes[pid]] = certs
        pos += 8 + ln
    return out


def _cert_info(der: bytes, scheme: str) -> dict:
    try:
        c = x509.load_der_x509_certificate(der)
        _ = c.subject, c.not_valid_before_utc
    except Exception:
        # Some signing tools emit non-DER-compliant certs (e.g. negative serials). Keep the fingerprint.
        return {"scheme": scheme, "subject": "(certificate not strictly DER-encoded; fingerprint only)",
                "issuer": "", "serial": "", "not_before": "", "not_after": "", "age_days": 99999,
                "validity_years": 0, "sha256": hashlib.sha256(der).hexdigest(), "sha1": hashlib.sha1(der).hexdigest(),
                "self_signed": False, "key": "unknown"}
    pub = c.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key = f"RSA {pub.key_size}"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key = f"EC {pub.curve.name}"
    elif isinstance(pub, dsa.DSAPublicKey):
        key = f"DSA {pub.key_size}"
    else:
        key = type(pub).__name__
    nb, na = c.not_valid_before_utc, c.not_valid_after_utc
    return {
        "scheme": scheme, "subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
        "serial": format(c.serial_number, "x"), "not_before": nb.isoformat(), "not_after": na.isoformat(),
        "age_days": (datetime.now(timezone.utc) - nb).days, "validity_years": round((na - nb).days / 365.25, 1),
        "sha256": c.fingerprint(hashes.SHA256()).hex(), "sha1": c.fingerprint(hashes.SHA1()).hex(),
        "self_signed": c.subject == c.issuer, "key": key,
    }


def signing_certs(raw: bytes, zf: zipfile.ZipFile) -> list[dict]:
    certs: dict[str, dict] = {}
    try:
        for scheme, ders in _v2v3_certs(raw).items():
            for der in ders:
                info = _cert_info(der, scheme)
                certs.setdefault(info["sha256"], info)["scheme"] = ", ".join(
                    sorted(set(certs[info["sha256"]]["scheme"].split(", ") + [scheme])))
    except Exception:
        pass
    for name in zf.namelist():
        u = name.upper()
        if u.startswith("META-INF/") and u.endswith((".RSA", ".DSA", ".EC")):
            try:
                for c in pkcs7.load_der_pkcs7_certificates(zf.read(name)):
                    der = c.public_bytes(Encoding.DER)
                    info = _cert_info(der, "v1")
                    if info["sha256"] in certs:
                        if "v1" not in certs[info["sha256"]]["scheme"]:
                            certs[info["sha256"]]["scheme"] = "v1, " + certs[info["sha256"]]["scheme"]
                    else:
                        certs[info["sha256"]] = info
            except Exception:
                continue
    return list(certs.values())


# ----------------------------------------------------------------------------- Analysis
PERMISSIONS = {
    "READ_SMS": ("Read SMS inbox", 20), "RECEIVE_SMS": ("Intercept incoming SMS (OTP theft)", 20),
    "SEND_SMS": ("Send SMS silently", 12), "RECEIVE_MMS": ("Intercept MMS", 6), "RECEIVE_WAP_PUSH": ("Intercept WAP push", 6),
    "READ_CONTACTS": ("Read contact list", 10), "WRITE_CONTACTS": ("Modify contacts", 4),
    "READ_CALL_LOG": ("Read call history", 10), "PROCESS_OUTGOING_CALLS": ("Intercept outgoing calls", 10),
    "CALL_PHONE": ("Place calls without dialler", 6), "ANSWER_PHONE_CALLS": ("Answer calls programmatically", 8),
    "READ_PHONE_STATE": ("Read device identifiers / SIM", 4), "READ_PHONE_NUMBERS": ("Read own phone number", 4),
    "CAMERA": ("Use the camera", 5), "RECORD_AUDIO": ("Record audio", 8),
    "ACCESS_FINE_LOCATION": ("Precise location", 4), "ACCESS_BACKGROUND_LOCATION": ("Location in background", 6),
    "READ_EXTERNAL_STORAGE": ("Read shared storage / gallery", 4), "READ_MEDIA_IMAGES": ("Read photos", 5),
    "MANAGE_EXTERNAL_STORAGE": ("Full file-system access", 8),
    "SYSTEM_ALERT_WINDOW": ("Draw over other apps (overlay attacks)", 10),
    "REQUEST_INSTALL_PACKAGES": ("Install other APKs (dropper)", 10),
    "QUERY_ALL_PACKAGES": ("Enumerate installed apps (target banking apps)", 5),
    "RECEIVE_BOOT_COMPLETED": ("Start automatically at boot", 3),
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": ("Avoid being killed in background", 4),
    "GET_ACCOUNTS": ("List device accounts", 4), "READ_CALENDAR": ("Read calendar", 3),
    "USE_FULL_SCREEN_INTENT": ("Full-screen pop-ups", 3), "WRITE_SETTINGS": ("Change system settings", 5),
    "BIND_ACCESSIBILITY_SERVICE": ("Accessibility service (screen reading, auto-clicks)", 25),
    "BIND_NOTIFICATION_LISTENER_SERVICE": ("Read all notifications (OTP capture)", 15),
    "BIND_DEVICE_ADMIN": ("Device administrator (prevents uninstall)", 15),
    "FOREGROUND_SERVICE": ("Persistent foreground service", 1),
}

API_MARKERS = [
    ("content://sms", "Queries the SMS content provider", 12),
    ("sendTextMessage", "Calls SmsManager.sendTextMessage", 8),
    ("android.provider.Telephony.SMS_RECEIVED", "Listens for incoming SMS broadcast", 10),
    ("getMessageBody", "Reads SMS message bodies", 8),
    ("ContactsContract", "Reads the contacts database", 4),
    ("CallLog$Calls", "Reads call log", 4),
    ("api.telegram.org/bot", "Exfiltrates data through a Telegram bot", 25),
    ("Ldalvik/system/DexClassLoader;", "Loads code dynamically at runtime", 6),
    ("Ldalvik/system/InMemoryDexClassLoader;", "Loads code from memory", 8),
    ("getInstalledPackages", "Lists installed applications", 3),
    ("setComponentEnabledSetting", "Can toggle its own components (icon hiding when combined with no launcher)", 3),
    ("performGlobalAction", "Automates UI via accessibility", 10),
    ("TYPE_APPLICATION_OVERLAY", "Creates overlay windows", 6),
    ("lockNow", "Can lock the device", 8),
    ("anydesk", "References AnyDesk remote-access", 10),
    ("firebaseio.com", "Uses Firebase Realtime DB endpoint", 2),
]

PACKERS = {
    "libjiagu": "Qihoo 360 Jiagu", "libjiagu_x86": "Qihoo 360 Jiagu", "libshella": "Tencent Legu",
    "libshell": "Tencent / generic shell", "libsecexe": "Bangcle", "libsecmain": "Bangcle",
    "libDexHelper": "SecNeo DexHelper", "libprotectClass": "Unknown protector", "libnqshield": "NQ Shield",
    "libtup": "Tencent", "libexec": "Ijiami", "libexecmain": "Ijiami", "libddog": "Ijiami", "libapkprotect": "APKProtect",
}

FINANCE_THEME = re.compile(r"loan|lend|cash|credit|rupee|rupay|paisa|kredit|emi\b|money|finance|fund|wallet|invest|"
                           r"earn|profit|trade|trading|stock|crypto|bet|rummy|lottery|recharge", re.I)


def _ahash(img_bytes: bytes) -> str | None:
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(img_bytes)).convert("L").resize((8, 8), Image.Resampling.LANCZOS)
        px = list(im.getdata())
        avg = sum(px) / 64
        bits = "".join("1" if p >= avg else "0" for p in px)
        return f"{int(bits, 2):016x}"
    except Exception:
        return None


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def _brand_in(text: str) -> list[str]:
    low = text.lower()
    out = []
    for b in BRANDS:
        for kw in [b["name"].lower()] + b["keywords"]:
            if len(kw) >= 4 and kw in low:
                out.append(b["name"])
                break
            if len(kw) < 4 and re.search(rf"(?<![a-z]){kw}(?![a-z])", low):
                out.append(b["name"])
                break
    return out


def analyze_apk(filename: str, raw: bytes) -> dict:
    f = Findings()
    meta = {"filename": filename, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "md5": hashlib.md5(raw).hexdigest(), "sha1": hashlib.sha1(raw).hexdigest()}
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        names = zf.namelist()
    except zipfile.BadZipFile:
        raise ValueError("File is not a valid APK (ZIP container could not be opened).")
    if "AndroidManifest.xml" not in names:
        if any(n.endswith(".apk") for n in names):
            raise ValueError("This looks like an XAPK / APKS bundle. Extract the base APK and upload that.")
        raise ValueError("AndroidManifest.xml missing — not an Android APK.")

    ax = AXML(zf.read("AndroidManifest.xml"))
    arsc = None
    if "resources.arsc" in names:
        try:
            arsc = ARSC(zf.read("resources.arsc"))
        except Exception:
            arsc = None

    def res(v: str) -> list[str]:
        if v and v.startswith("@0x") and arsc:
            return arsc.resolve(int(v[1:], 16))
        return [v] if v else []

    manifest, application = {}, {}
    perms, components = [], []
    launcher, current = False, None
    intents: list[dict] = []
    for depth, tag, attrs in ax.elements:
        if tag == "manifest":
            manifest = attrs
        elif tag == "uses-sdk":
            manifest.update({k: v for k, v in attrs.items() if k.endswith("SdkVersion")})
        elif tag in ("uses-permission", "uses-permission-sdk-23"):
            if attrs.get("name"):
                perms.append(attrs["name"])
        elif tag == "application":
            application = attrs
        elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            current = {"type": tag, "name": attrs.get("name", ""), "exported": attrs.get("exported", ""),
                       "permission": attrs.get("permission", ""), "actions": [], "depth": depth}
            components.append(current)
        elif tag == "action" and current is not None:
            current["actions"].append(attrs.get("name", ""))
        elif tag == "category" and current is not None and attrs.get("name") == "android.intent.category.LAUNCHER":
            launcher = True
        elif tag == "data" and current is not None and (attrs.get("scheme") or attrs.get("host")):
            intents.append({"component": current["name"], "scheme": attrs.get("scheme", ""), "host": attrs.get("host", "")})

    package = manifest.get("package", "")
    label_vals = res(application.get("label", ""))
    label = next((v for v in label_vals if v), "") or package
    meta.update({
        "package": package, "label": label, "version_name": (res(manifest.get("versionName", "")) or [""])[0],
        "version_code": manifest.get("versionCode", ""), "min_sdk": manifest.get("minSdkVersion", ""),
        "target_sdk": manifest.get("targetSdkVersion", ""), "debuggable": application.get("debuggable") == "true",
        "cleartext": application.get("usesCleartextTraffic") == "true", "allow_backup": application.get("allowBackup", ""),
        "application_class": application.get("name", ""), "launcher_activity": launcher,
    })

    # ---- permissions
    short_perms = sorted({p.split(".")[-1] for p in perms})
    service_perms = {c["permission"].split(".")[-1] for c in components if c["permission"]}
    all_perm = set(short_perms) | service_perms
    perm_rows = []
    for p in sorted(all_perm):
        if p in PERMISSIONS:
            perm_rows.append({"permission": p, "meaning": PERMISSIONS[p][0], "weight": PERMISSIONS[p][1],
                              "via": "component" if p in service_perms and p not in short_perms else "uses-permission"})
    meta["permissions"] = [p for p in perms]
    meta["risky_permissions"] = perm_rows

    sms = {"READ_SMS", "RECEIVE_SMS"} & all_perm
    if sms:
        f.add("apk.sms", "Can read / intercept SMS", "Permissions: " + ", ".join(sorted(sms)) +
              ". Gives access to bank OTPs and transaction alerts.", 22, "app", ", ".join(sorted(sms)))
    if "SEND_SMS" in all_perm:
        f.add("apk.send_sms", "Can send SMS", "Used to forward OTPs or register the victim's SIM for UPI.", 10, "app", "SEND_SMS")
    if "BIND_ACCESSIBILITY_SERVICE" in all_perm:
        f.add("apk.accessibility", "Registers an accessibility service",
              "Banking trojans abuse accessibility to read the screen and auto-approve transactions.", 25, "app",
              "BIND_ACCESSIBILITY_SERVICE")
    if "BIND_NOTIFICATION_LISTENER_SERVICE" in all_perm:
        f.add("apk.notif", "Reads all notifications", "Captures OTPs and UPI alerts from notifications.", 15, "app",
              "BIND_NOTIFICATION_LISTENER_SERVICE")
    if "BIND_DEVICE_ADMIN" in all_perm:
        f.add("apk.device_admin", "Requests device-administrator rights", "Blocks uninstallation and can lock the device.",
              15, "app", "BIND_DEVICE_ADMIN")
    if "SYSTEM_ALERT_WINDOW" in all_perm:
        f.add("apk.overlay", "Can draw over other apps", "Enables fake login overlays on top of real banking apps.", 10, "app",
              "SYSTEM_ALERT_WINDOW")
    if "REQUEST_INSTALL_PACKAGES" in all_perm:
        f.add("apk.dropper", "Can install other APKs", "Typical of droppers that fetch the real payload later.", 10, "app",
              "REQUEST_INSTALL_PACKAGES")
    harvest = {"READ_CONTACTS", "READ_CALL_LOG", "CAMERA", "READ_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES",
               "ACCESS_FINE_LOCATION", "RECORD_AUDIO", "GET_ACCOUNTS"} & all_perm
    if len(harvest) >= 3:
        f.add("apk.harvest", f"Requests {len(harvest)} personal-data permissions", ", ".join(sorted(harvest)),
              6 + 3 * len(harvest), "app", ", ".join(sorted(harvest)))

    # ---- DEX strings
    strings: list[str] = []
    dex_names = [n for n in names if re.fullmatch(r"classes\d*\.dex", n)]
    for n in dex_names:
        try:
            strings.extend(dex_strings(zf.read(n)))
        except Exception:
            continue
    meta["dex_files"] = len(dex_names)
    meta["dex_strings"] = len(strings)
    blob_api = "\n".join(s for s in strings if 3 < len(s) < 300)
    api_hits = []
    for marker, desc, w in API_MARKERS:
        if marker.lower() in blob_api.lower():
            api_hits.append({"marker": marker, "meaning": desc, "weight": w})
    meta["api_markers"] = api_hits
    for h in api_hits:
        if h["weight"] >= 6:
            f.add("apk.api." + h["marker"][:24], h["meaning"], f"String '{h['marker']}' present in DEX code.",
                  h["weight"], "app", h["marker"])

    # ---- theme & predatory-loan profile
    theme_src = " ".join([label, package] + label_vals[:3])
    finance = bool(FINANCE_THEME.search(theme_src))
    meta["finance_theme"] = finance
    if finance and "READ_CONTACTS" in all_perm and ({"READ_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "CAMERA",
                                                     "READ_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES"} & all_perm):
        f.add("apk.loan_profile", "Matches predatory loan / investment app profile",
              f"Finance-themed app ('{label}') that harvests contacts plus SMS/photos/call-log; the pattern used to "
              "shame and extort borrowers.", 25, "app", label)
    if sms and "INTERNET" in set(short_perms) and any(h["marker"] in ("content://sms", "getMessageBody",
                                                                     "android.provider.Telephony.SMS_RECEIVED") for h in api_hits):
        f.add("apk.sms_forwarder", "SMS-forwarding behaviour", "Reads SMS content and has network access: OTP stealer pattern.",
              15, "app", "SMS + INTERNET")

    # ---- impersonation
    brands = _brand_in(label + " " + package)
    legit = legit_packages()
    meta["claimed_brands"] = brands
    if package in legit:
        f.add("apk.official_package", f"Package name of official {legit[package]} app",
              "A sideloaded copy may be repackaged; compare the signing certificate with the Play Store build.",
              8, "app", package)
    elif brands:
        f.add("apk.impersonation", "Impersonates " + ", ".join(brands[:2]),
              f"Name/package '{label}' / {package} uses the brand but is not the official package "
              f"({', '.join(p for p, n in legit.items() if n in brands) or 'no official app listed'}).", 40, "app", package)
        if re.search(r"spoof|mod|hack|crack|clone|fake|patch|premium|pro\b", package, re.I):
            f.add("apk.tamper_name", "Package name signals a modified / spoofed build", package, 15, "app", package)

    # ---- manifest hygiene
    try:
        tsdk = int(meta["target_sdk"] or 0)
    except ValueError:
        tsdk = 0
    if 0 < tsdk < 23:
        f.add("apk.old_target", f"targetSdkVersion {tsdk} (pre-Android 6)",
              "Targets an old API so all dangerous permissions are granted at install without prompts.", 12, "app", str(tsdk))
    if not launcher:
        f.add("apk.no_launcher", "No launcher icon declared",
              "App runs without a visible icon, so the victim cannot find or remove it easily.", 15, "app", package)
    if meta["debuggable"]:
        f.add("apk.debuggable", "Built as debuggable", "Not a store release build.", 6, "app", "android:debuggable=true")

    # ---- packers / native libs
    libs = sorted({n.split("/")[-1] for n in names if n.startswith("lib/") and n.endswith(".so")})
    meta["native_libs"] = libs[:40]
    packers = sorted({PACKERS[l[:-3]] for l in libs if l[:-3] in PACKERS})
    if packers:
        f.add("apk.packer", "Protected by a commercial packer", ", ".join(packers) +
              ". Packing hides the real code from static analysis.", 10, "app", ", ".join(packers))
    embedded_apks = [n for n in names if n.lower().endswith((".apk", ".dex", ".jar")) and not re.fullmatch(r"classes\d*\.dex", n)]
    if embedded_apks:
        f.add("apk.embedded", "Contains embedded APK / DEX / JAR payloads", ", ".join(embedded_apks[:5]), 12, "app",
              embedded_apks[0])
    meta["embedded_payloads"] = embedded_apks[:20]

    # ---- certificates
    certs = []
    try:
        certs = signing_certs(raw, zf)
    except Exception:
        certs = []
    meta["certificates"] = certs
    if not certs:
        f.add("apk.unsigned", "No signing certificate found", "Unsigned APKs cannot be installed normally; may be a tampered file.",
              10, "app")
    for c in certs:
        subj = c["subject"].lower()
        if brands and package not in legit and c["key"] != "unknown" and not any(
                k in subj for b in BRANDS if b["name"] in brands for k in [b["name"].lower()] + b["keywords"]):
            f.add("apk.cert_mismatch", "Signer is unrelated to the claimed brand",
                  f"Claims {', '.join(brands[:2])} but is signed by '{c['subject']}'.", 15, "app", c["sha256"][:16])
        if "android debug" in subj:
            f.add("apk.debug_cert", "Signed with the Android debug key", c["subject"], 15, "app", c["sha256"][:16])
        elif "o=android" in subj and ("ou=android" in subj or "android@android.com" in subj):
            f.add("apk.test_cert", "Signed with the public AOSP test key", c["subject"], 15, "app", c["sha256"][:16])
        if c["age_days"] < 60:
            f.add("apk.fresh_cert", f"Signing certificate created {c['age_days']} days ago",
                  "Short-lived signing keys are typical of disposable fraud apps.", 8, "app", c["sha256"][:16])
        if len([p for p in c["subject"].split(",") if p.strip()]) <= 1:
            f.add("apk.thin_cert", "Signing certificate carries no organisation details", c["subject"], 4, "app",
                  c["sha256"][:16])

    # ---- icon
    icon_hash = None
    icon_path = None
    for v in res(application.get("icon", "")):
        if v.lower().endswith((".png", ".webp", ".jpg")) and v in names:
            icon_path = v
            break
    if not icon_path:
        cands = sorted([n for n in names if re.search(r"res/mipmap[^/]*/ic_launcher[^/]*\.(png|webp)$", n)],
                       key=lambda n: ("xxxhdpi" not in n, "xxhdpi" not in n, "xhdpi" not in n))
        icon_path = cands[0] if cands else None
    if icon_path:
        icon_hash = _ahash(zf.read(icon_path))
    meta["icon_path"] = icon_path
    meta["icon_ahash"] = icon_hash

    # ---- identifiers from code strings
    ioc_blob = "\n".join(s for s in strings if 6 <= len(s) <= 1500 and re.search(r"://|@|\d{3}|\.[a-z]{2,}", s))
    extracted = ioc_mod.extract(ioc_blob, "DEX strings", code_strings=True)
    groups = ioc_mod.group(extracted)
    noisy = ("google.com", "googleapis.com", "gstatic.com", "android.com", "facebook.com", "fb.com", "crashlytics.com",
             "firebase.google.com", "apple.com", "mozilla.org", "github.com", "jquery.com", "w3.org", "example.com",
             "schema.org", "xmlpull.org", "apache.org", "whatsapp.com", "youtube.com", "goo.gl", "app-measurement.com",
             "googleadservices.com", "doubleclick.net", "googlesyndication.com", "unity3d.com", "applovin.com",
             "appsflyer.com", "adjust.com", "branch.io", "onesignal.com", "sentry.io", "bugsnag.com", "amazonaws.com")
    extracted = [e for e in extracted if not (
        e["etype"] in ("url", "domain") and (ioc_mod.host_of(e["value"]) if e["etype"] == "url" else e["value"]).endswith(noisy))]
    groups = ioc_mod.group(extracted)
    ip_urls = [u for u in groups.get("url", []) if re.match(r"https?://\d+\.\d+\.\d+\.\d+", u["value"])]
    http_urls = [u for u in groups.get("url", []) if u["value"].startswith("http://") and u not in ip_urls]
    if ip_urls:
        f.add("apk.ip_endpoint", "Hard-coded IP address endpoints", ", ".join(u["display"] for u in ip_urls[:4]), 12, "app",
              ip_urls[0]["display"])
    if http_urls:
        f.add("apk.cleartext_endpoint", "Unencrypted HTTP endpoints in code", ", ".join(u["display"] for u in http_urls[:4]),
              5, "network", http_urls[0]["display"])
    if groups.get("upi") or groups.get("crypto"):
        f.add("apk.payment_ids", "Payment identifiers embedded in the app",
              ", ".join(x["display"] for x in (groups.get("upi", []) + groups.get("crypto", []))[:4]), 12, "app")

    extracted.append({"etype": "apk_package", "value": package, "display": package, "context": "manifest"})
    extracted.append({"etype": "apk_sha256", "value": meta["sha256"], "display": meta["sha256"], "context": "file hash"})
    for c in certs:
        extracted.append({"etype": "apk_cert", "value": c["sha256"], "display": c["sha256"],
                          "context": f"signing cert ({c['scheme']}) {c['subject'][:60]}"})

    meta["components"] = {
        k: len([c for c in components if c["type"] == k]) for k in ("activity", "service", "receiver", "provider")}
    meta["receivers_of_interest"] = [
        {"name": c["name"], "actions": c["actions"]} for c in components
        if c["type"] == "receiver" and any(a.endswith(("SMS_RECEIVED", "BOOT_COMPLETED", "NEW_OUTGOING_CALL", "PHONE_STATE",
                                                        "DEVICE_ADMIN_ENABLED")) for a in c["actions"])][:15]
    meta["deep_links"] = intents[:15]
    category = "Fake loan / investment app" if finance and f.score >= 30 else \
        ("Impersonation app" if brands and package not in legit else ("Malicious app (SMS / banking trojan)" if sms or
                                                                      "BIND_ACCESSIBILITY_SERVICE" in all_perm else ""))
    return {"findings": f, "meta": meta, "iocs": extracted, "category": category}


THIRD_PARTY_APK_STORES = ("apkpure.com", "apkpure.net", "uptodown.com", "apkcombo.com", "apkmirror.com")


def is_store_link(url: str) -> bool:
    u = ioc_mod.refang(url.strip()).lower()
    if "play.google.com/store/apps" in u or u.startswith("market://") or "apps.apple.com/" in u:
        return True
    try:
        host = (urlsplit(u if "://" in u else "http://" + u).hostname or "").lower()
    except ValueError:
        return False
    return any(host == d or host.endswith("." + d) for d in THIRD_PARTY_APK_STORES)


def analyze_store_link(url: str, run_live: bool = True) -> dict:
    """App-store / third-party APK portal link: parse package/app id, optionally fetch listing, check impersonation."""
    from . import netintel
    f = Findings()
    url = ioc_mod.refang(url.strip())
    parts = urlsplit(url if "://" in url else "https://" + url)
    host = (parts.hostname or "").lower()
    q = parse_qs(parts.query)
    third_party_host = next((d for d in THIRD_PARTY_APK_STORES if host == d or host.endswith("." + d)), None)

    package = ""
    platform = "Google Play"
    store_url = url

    if "play.google.com" in host or url.lower().startswith("market://"):
        package = (q.get("id") or [""])[0].strip()
        if not package:
            m = re.search(r"market://details\?id=([\w.]+)", url, re.I)
            package = m.group(1) if m else ""
        if not package:
            raise ValueError("No package id found. Expected https://play.google.com/store/apps/details?id=<package>")
        store_url = f"https://play.google.com/store/apps/details?id={package}&hl=en_IN"
    elif "apps.apple.com" in host:
        platform = "Apple App Store"
        m = re.search(r"/id(\d{5,15})\b", parts.path)
        if not m:
            raise ValueError("No Apple App ID found. Expected https://apps.apple.com/.../id<digits>")
        package = f"ios:{m.group(1)}"
        store_url = url if "://" in url else "https://" + url
    elif third_party_host:
        platform = f"Third-party APK store ({third_party_host})"
        m = re.search(r"\b([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,})\b", parts.path + "?" + parts.query)
        package = m.group(1) if m else ""
        store_url = url if "://" in url else "https://" + url
        f.add("store.third_party", f"Hosted on third-party APK store ({third_party_host})",
              "Distributing apps outside official stores bypasses Play Protect and store review.", 15, "app", host)
    else:
        raise ValueError("Unsupported app-store link. Expected Google Play, Apple App Store, or a known APK portal URL.")

    meta: dict = {"platform": platform, "package": package or parts.path.strip("/"), "store_url": store_url}
    if run_live:
        try:
            r = netintel.get_session().get(store_url, timeout=10)
            meta["store_status"] = r.status_code
            if platform == "Google Play" and r.status_code == 404:
                f.add("store.removed", "Listing not found on Google Play",
                      "The app was removed (often after policy violations) or never existed; links to it in messages are a red flag.",
                      30, "app", package)
            elif r.ok:
                t = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.I)
                raw_t = html_mod.unescape(t.group(1).strip()) if t else ""
                for suf in (
                    " - Apps on Google Play",
                    " \u2013 Apps on Google Play",
                    " \u2014 Apps on Google Play",
                    " on the App\u00a0Store",
                    " on the App Store",
                ):
                    raw_t = raw_t.replace(suf, "")
                meta["title"] = raw_t.strip()
                if platform == "Google Play":
                    dev = re.search(r'href="/store/apps/dev(?:eloper)?\?id=[^"]+"[^>]*>(?:<span[^>]*>)?([^<]{2,80})<', r.text)
                    meta["developer"] = dev.group(1).strip() if dev else ""
                    inst = re.search(r">([\d.,]+[KMB+]*\+?)</div><div[^>]*>Downloads<", r.text)
                    meta["downloads"] = inst.group(1) if inst else ""
                    mail = re.search(r"mailto:([^\"'?]+)", r.text)
                    meta["developer_email"] = mail.group(1) if mail else ""
        except Exception as exc:
            meta["store_error"] = exc.__class__.__name__

    legit = legit_packages()
    probe = " ".join(filter(None, [meta.get("title", ""), package, parts.path]))
    brands = _brand_in(probe)
    if package in legit:
        f.add("store.official", f"Official {legit[package]} package", "Listed as the documented package for this brand.", -20,
              "app", package)
    elif brands:
        f.add("store.impersonation", "Impersonates " + ", ".join(brands[:2]),
              f"Listing '{meta.get('title') or meta['package']}' uses the brand name but is not the official package.",
              35, "app", meta["package"])
    if FINANCE_THEME.search(probe) and package not in legit:
        f.add("store.finance_theme", "Finance / loan / earning themed listing",
              "Verify the lender against RBI's list of regulated entities and the app's NBFC partner disclosure.",
              8, "app", meta["package"])

    iocs = []
    if package and ("." in package or package.startswith("ios:")):
        iocs.append({"etype": "apk_package", "value": package, "display": package, "context": f"{platform} link"})
    if third_party_host:
        iocs.extend(ioc_mod.extract(store_url, "third-party store link"))
    if meta.get("developer_email"):
        iocs.append({"etype": "email", "value": meta["developer_email"].lower(), "display": meta["developer_email"],
                     "context": "developer contact"})
    cat = "Impersonation app" if brands and package not in legit else ("Third-party APK distribution" if third_party_host else "")
    return {"findings": f, "meta": meta, "iocs": iocs, "category": cat}
