"""Runtime configuration. Everything sensitive comes from .env, never from source."""
import hashlib
import hmac
import os
import secrets
import tempfile
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

IS_SERVERLESS = bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
TRUST_PROXY = IS_SERVERLESS or os.getenv("NK_TRUST_PROXY", "0") == "1"


def _resolve_data_dir() -> Path:
    custom = os.getenv("NK_DATA_DIR", "").strip()
    if custom:
        candidates = [Path(custom)]
    elif IS_SERVERLESS:
        candidates = [Path(tempfile.gettempdir()) / "nirikshak"]
    else:
        candidates = [BASE_DIR / "data", Path(tempfile.gettempdir()) / "nirikshak"]
    for cand in candidates:
        try:
            (cand / "evidence").mkdir(parents=True, exist_ok=True)
            return cand
        except OSError:
            continue
    return Path(tempfile.gettempdir()) / "nirikshak"


DATA_DIR = _resolve_data_dir()
EVIDENCE_DIR = DATA_DIR / "evidence"

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
OCR_SPACE_API_KEY = os.getenv("OCR_SPACE_API_KEY", "").strip()
CLOUD_OCR = os.getenv("NK_CLOUD_OCR", "1" if IS_SERVERLESS else "0") == "1"
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.getenv("NK_GROQ_MODEL", "openai/gpt-oss-120b").strip() or "openai/gpt-oss-120b"
GROQ_VISION_MODEL = os.getenv("NK_GROQ_VISION_MODEL", "qwen/qwen3.8-27b").strip() or "qwen/qwen3.8-27b"
GROQ_ENABLED = bool(GROQ_API_KEY) and os.getenv("NK_GROQ_ENABLED", "1") == "1"


def _load_secret() -> str:
    env = os.getenv("NK_SECRET_KEY", "").strip()
    if env:
        return env
    if not IS_SERVERLESS:
        path = DATA_DIR / "secret.key"
        try:
            if path.exists():
                val = path.read_text().strip()
                if val:
                    return val
            value = secrets.token_urlsafe(48)
            path.write_text(value)
            return value
        except OSError:
            pass
    seed = "|".join(p for p in (SUPABASE_URL, SUPABASE_SERVICE_KEY, NK_DB_SECRET) if p)
    if seed:
        return hmac.new(b"nirikshak-session-secret-v1", seed.encode("utf-8"), hashlib.sha256).hexdigest()
    return secrets.token_urlsafe(48)


SECRET_KEY = _load_secret()
SESSION_HOURS = 10


def config_problems() -> list[str]:
    problems = []
    if not SUPABASE_URL:
        problems.append("SUPABASE_URL is not set in environment / .env")
    if not SUPABASE_SERVICE_KEY:
        problems.append("SUPABASE_SERVICE_ROLE_KEY or SUPABASE_API_KEY is not set in environment / .env")
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
