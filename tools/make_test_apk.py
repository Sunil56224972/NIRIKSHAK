"""Build SAFE synthetic APK samples for testing / demo of the static analyser.

The output files contain no executable code: the DEX holds only a string table and the
app cannot run. They exercise the real binary formats (AXML manifest, DEX string table,
v1 JAR signature) so the analyser can be verified end-to-end.

    python tools/make_test_apk.py            -> samples/test_fake_loan.apk, samples/test_benign_notes.apk
"""
from __future__ import annotations

import datetime
import hashlib
import io
import struct
import sys
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ATTR_IDS = {"name": 0x01010003, "label": 0x01010001, "icon": 0x01010002, "versionCode": 0x0101021B,
            "versionName": 0x0101021C, "minSdkVersion": 0x0101020C, "targetSdkVersion": 0x01010270,
            "exported": 0x01010010, "permission": 0x01010006}


class AxmlWriter:
    def __init__(self):
        self.strings: list[str] = list(ATTR_IDS)       # android attribute names first (resource map order)
        self.chunks: list[bytes] = []

    def s(self, v: str) -> int:
        if v not in self.strings:
            self.strings.append(v)
        return self.strings.index(v)

    def start(self, tag: str, attrs: list[tuple[str, str | int | bool]]):
        body = b""
        for name, val in attrs:
            ns = self.s(ANDROID_NS) if name in ATTR_IDS else 0xFFFFFFFF
            if isinstance(val, bool):
                raw, dtype, data = 0xFFFFFFFF, 0x12, 0xFFFFFFFF if val else 0
            elif isinstance(val, int):
                raw, dtype, data = 0xFFFFFFFF, 0x10, val
            else:
                idx = self.s(val)
                raw, dtype, data = idx, 0x03, idx
            body += struct.pack("<IIIHBBI", ns, self.s(name), raw, 8, 0, dtype, data)
        ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, self.s(tag), 20, 20, len(attrs), 0, 0, 0)
        payload = struct.pack("<II", 1, 0xFFFFFFFF) + ext + body
        self.chunks.append(struct.pack("<HHI", 0x0102, 16, 8 + len(payload)) + payload)

    def end(self, tag: str):
        payload = struct.pack("<IIII", 1, 0xFFFFFFFF, 0xFFFFFFFF, self.s(tag))
        self.chunks.append(struct.pack("<HHI", 0x0103, 16, 24) + payload)

    def build(self) -> bytes:
        ns_start = struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, self.s("android"), self.s(ANDROID_NS))
        ns_end = struct.pack("<HHIIIII", 0x0101, 16, 24, 1, 0xFFFFFFFF, self.s("android"), self.s(ANDROID_NS))
        data = b""
        offsets = []
        for st in self.strings:
            offsets.append(len(data))
            enc = st.encode("utf-16-le")
            data += struct.pack("<H", len(st)) + enc + b"\x00\x00"
        while len(data) % 4:
            data += b"\x00"
        hdr = 28
        start = hdr + 4 * len(offsets)
        pool = struct.pack("<HHIIIIII", 0x0001, hdr, start + len(data), len(self.strings), 0, 0, start, 0)
        pool += struct.pack(f"<{len(offsets)}I", *offsets) + data
        resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(ATTR_IDS)) + struct.pack(f"<{len(ATTR_IDS)}I", *ATTR_IDS.values())
        body = pool + resmap + ns_start + b"".join(self.chunks) + ns_end
        return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def uleb(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def dex_with_strings(strings: list[str]) -> bytes:
    strings = sorted(set(strings))
    header_size = 0x70
    ids_off = header_size
    data_off = ids_off + 4 * len(strings)
    data = b""
    ids = []
    for st in strings:
        ids.append(data_off + len(data))
        b = st.encode("utf-8")
        data += uleb(len(st)) + b + b"\x00"
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, header_size + 4 * len(strings) + len(data))
    struct.pack_into("<I", header, 0x24, header_size)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<II", header, 0x38, len(strings), ids_off)
    return bytes(header) + struct.pack(f"<{len(ids)}I", *ids) + data


def icon(color: tuple[int, int, int], mark: tuple[int, int, int]) -> bytes:
    from PIL import Image, ImageDraw
    im = Image.new("RGB", (192, 192), color)
    d = ImageDraw.Draw(im)
    d.rectangle([40, 40, 152, 152], fill=mark)
    d.ellipse([70, 70, 122, 122], fill=color)
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def sign_v1(files: dict[str, bytes], cn: str, days_old: int) -> dict[str, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_old)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365 * 25)).sign(key, hashes.SHA256()))
    import base64
    mf = "Manifest-Version: 1.0\r\nCreated-By: nirikshak-test\r\n\r\n"
    for n, b in files.items():
        mf += f"Name: {n}\r\nSHA-256-Digest: {base64.b64encode(hashlib.sha256(b).digest()).decode()}\r\n\r\n"
    sf = ("Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: "
          f"{base64.b64encode(hashlib.sha256(mf.encode()).digest()).decode()}\r\n\r\n")
    sig = pkcs7.PKCS7SignatureBuilder().set_data(sf.encode()).add_signer(cert, key, hashes.SHA256()) \
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.NoAttributes])
    return {"META-INF/MANIFEST.MF": mf.encode(), "META-INF/CERT.SF": sf.encode(), "META-INF/CERT.RSA": sig}


def build(path: Path, *, package: str, label: str, perms: list[str], services: list[tuple[str, str]],
          receivers: list[tuple[str, list[str]]], launcher: bool, target_sdk: int, dex_strings: list[str],
          cn: str, cert_age: int, colors) -> None:
    w = AxmlWriter()
    w.start("manifest", [("versionCode", 7), ("versionName", "2.1.0"), ("package", package)])
    w.start("uses-sdk", [("minSdkVersion", 21), ("targetSdkVersion", target_sdk)])
    w.end("uses-sdk")
    for p in perms:
        w.start("uses-permission", [("name", p)])
        w.end("uses-permission")
    w.start("application", [("label", label), ("icon", "res/mipmap-xxhdpi/ic_launcher.png")])
    w.start("activity", [("name", package + ".MainActivity"), ("exported", True)])
    if launcher:
        w.start("intent-filter", [])
        w.start("action", [("name", "android.intent.action.MAIN")]); w.end("action")
        w.start("category", [("name", "android.intent.category.LAUNCHER")]); w.end("category")
        w.end("intent-filter")
    w.end("activity")
    for name, perm in services:
        w.start("service", [("name", name), ("permission", perm), ("exported", False)])
        w.end("service")
    for name, actions in receivers:
        w.start("receiver", [("name", name), ("exported", True)])
        w.start("intent-filter", [])
        for a in actions:
            w.start("action", [("name", a)]); w.end("action")
        w.end("intent-filter")
        w.end("receiver")
    w.end("application")
    w.end("manifest")
    files = {"AndroidManifest.xml": w.build(), "classes.dex": dex_with_strings(dex_strings),
             "res/mipmap-xxhdpi/ic_launcher.png": icon(*colors)}
    files.update(sign_v1(files, cn, cert_age))
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in files.items():
            z.writestr(n, b)
    print("wrote", path, path.stat().st_size, "bytes")


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "samples"
    P = "android.permission."
    build(out / "test_fake_loan.apk", package="com.rupee.instantcash.loan", label="Rupee Instant Loan",
          perms=[P + x for x in ("INTERNET", "READ_CONTACTS", "READ_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "CAMERA",
                                 "READ_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION", "RECEIVE_BOOT_COMPLETED")],
          services=[], receivers=[("com.rupee.instantcash.loan.SmsReceiver", ["android.provider.Telephony.SMS_RECEIVED"])],
          launcher=True, target_sdk=22,
          dex_strings=["content://sms/inbox", "getMessageBody", "android.provider.Telephony.SMS_RECEIVED",
                       "ContactsContract", "https://api.rupee-cash-loan.top/v1/upload_contacts",
                       "http://45.137.21.9:8080/collect", "repay to recovery.agent77@ybl", "Lcom/rupee/Main;",
                       "Call recovery desk +91 9123456780"],
          cn="Rupee", cert_age=12, colors=((200, 40, 40), (250, 220, 60)))
    build(out / "test_sbi_reward_clone.apk", package="com.sbi.reward.points.update", label="SBI Reward Points",
          perms=[P + x for x in ("INTERNET", "RECEIVE_SMS", "READ_SMS", "SEND_SMS", "SYSTEM_ALERT_WINDOW")],
          services=[("com.sbi.reward.points.update.Acc", P + "BIND_ACCESSIBILITY_SERVICE")],
          receivers=[("com.sbi.reward.points.update.Boot", ["android.intent.action.BOOT_COMPLETED"])],
          launcher=False, target_sdk=30,
          dex_strings=["https://api.telegram.org/bot6511122233:AAH/sendMessage", "content://sms", "performGlobalAction",
                       "setComponentEnabledSetting", "https://sbi-rewards-kyc.online/panel"],
          cn="Android Debug", cert_age=3, colors=((20, 60, 160), (255, 255, 255)))
    build(out / "test_benign_notes.apk", package="org.example.simplenotes", label="Simple Notes",
          perms=[P + "INTERNET"], services=[], receivers=[], launcher=True, target_sdk=34,
          dex_strings=["Lorg/example/simplenotes/Note;", "https://simplenotes.example.org/help"],
          cn="Example Org, O=Example Org, C=IN", cert_age=900, colors=((240, 240, 230), (60, 120, 60)))
