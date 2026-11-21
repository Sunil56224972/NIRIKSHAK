"""Runtime configuration. Everything sensitive comes from .env, never from source."""
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_SERVICE_KEY = (
    os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    or os.getenv("SUPABASE_API_KEY")
    or ""
).strip()
NK_DB_SECRET = os.getenv("NK_DB_SECRET", "").strip()
STORAGE_BUCKET = os.getenv("NK_STORAGE_BUCKET", "nk-evidence")

UNIT_NAME = os.getenv("NK_UNIT_NAME", "Cyber Crime Cell")
APP_NAME = "NIRIKSHAK"

# Live network checks (DNS, RDAP/WHOIS, HTTP redirect trace, TLS). Disable on air-gapped terminals.
LIVE_CHECKS = os.getenv("NK_LIVE_CHECKS", "1") == "1"
NET_TIMEOUT = float(os.getenv("NK_NET_TIMEOUT", "8"))
MAX_FETCH_BYTES = 3 * 1024 * 1024
MAX_APK_BYTES = int(os.getenv("NK_MAX_APK_MB", "150")) * 1024 * 1024

GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "").strip()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()


def _load_secret() -> str:
    env = os.getenv("NK_SECRET_KEY", "").strip()
    if env:
        return env
    path = DATA_DIR / "secret.key"
    if path.exists():
        return path.read_text().strip()
    value = secrets.token_urlsafe(48)
    path.write_text(value)
    return value


SECRET_KEY = _load_secret()
SESSION_HOURS = 10


def config_problems() -> list[str]:
    problems = []
    if not SUPABASE_URL:
        problems.append("SUPABASE_URL is not set in .env")
    if not SUPABASE_SERVICE_KEY:
        problems.append("SUPABASE_SERVICE_ROLE_KEY or SUPABASE_API_KEY is not set in .env")
    elif not NK_DB_SECRET and (
        SUPABASE_SERVICE_KEY.startswith("sb_publishable_")
        or '"role":"anon"' in _jwt_payload(SUPABASE_SERVICE_KEY)
    ):
        problems.append("SUPABASE_SERVICE_ROLE_KEY contains the public anon/publishable key without NK_DB_SECRET. "
                        "Use the service_role (secret) key or set NK_DB_SECRET.")
    return problems


def _jwt_payload(token: str) -> str:
    import base64
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return base64.urlsafe_b64decode(part).decode("utf-8", "replace").replace(" ", "")
    except Exception:
        return ""
