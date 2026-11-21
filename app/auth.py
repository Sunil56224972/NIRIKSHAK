"""Officer accounts, password hashing, signed session cookies and audit trail."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from . import config
from .db import DBError, get_db

COOKIE = "nk_session"
CSRF_COOKIE = "nk_csrf"
_serializer = URLSafeTimedSerializer(config.SECRET_KEY, salt="nk-session-v1")
_csrf_ser = URLSafeTimedSerializer(config.SECRET_KEY, salt="nk-csrf-v1")
_ITER = 310_000
_lock = threading.Lock()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _ITER)
    return f"pbkdf2_sha256${_ITER}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), digest)
    except (ValueError, TypeError):
        return False


def password_problem(pw: str) -> str | None:
    if len(pw) < 10:
        return "Password must be at least 10 characters."
    classes = sum([any(c.islower() for c in pw), any(c.isupper() for c in pw),
                   any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)])
    if classes < 3:
        return "Use at least three of: lowercase, uppercase, digits, symbols."
    return None


_DUMMY_HASH = hash_password("dummy-timing-guard-placeholder")


def verify_dummy(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def make_csrf() -> str:
    return _csrf_ser.dumps(secrets.token_hex(16))


def valid_csrf_cookie(token: str) -> bool:
    if not token:
        return False
    try:
        _csrf_ser.loads(token, max_age=config.SESSION_HOURS * 3600)
        return True
    except (BadSignature, SignatureExpired):
        return False


def verify_csrf_pair(cookie_token: str, submitted_token: str) -> bool:
    return bool(
        cookie_token
        and submitted_token
        and hmac.compare_digest(cookie_token, submitted_token)
        and valid_csrf_cookie(cookie_token)
    )


def make_session(user: dict) -> str:
    # pw fingerprint invalidates sessions after a password change
    fp = hashlib.sha256(user["pw_hash"].encode()).hexdigest()[:16]
    return _serializer.dumps({"uid": user["id"], "fp": fp})


def current_user(request: Request) -> dict | None:
    if hasattr(request.state, "user"):
        return request.state.user
    user = None
    token = request.cookies.get(COOKIE)
    if token:
        try:
            data = _serializer.loads(token, max_age=config.SESSION_HOURS * 3600)
            row = get_db().one("nk_users", {"id": f"eq.{int(data['uid'])}"})
            if row and row["active"]:
                fp = hashlib.sha256(row["pw_hash"].encode()).hexdigest()[:16]
                if hmac.compare_digest(fp, data.get("fp", "")):
                    user = row
        except (BadSignature, SignatureExpired, KeyError, ValueError, DBError):
            user = None
    request.state.user = user
    return user


# ---- brute force throttle (per IP, in-memory) -----------------------------
_failures: dict[str, deque] = defaultdict(deque)
WINDOW, MAX_FAIL = 900, 6


def throttled(ip: str) -> bool:
    with _lock:
        q = _failures[ip]
        now = time.time()
        while q and now - q[0] > WINDOW:
            q.popleft()
        return len(q) >= MAX_FAIL


def record_failure(ip: str) -> None:
    with _lock:
        _failures[ip].append(time.time())


def clear_failures(ip: str) -> None:
    with _lock:
        _failures.pop(ip, None)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def audit(request: Request | None, action: str, target: str = "", detail: str = "",
          user: dict | None = None) -> None:
    if user is None and request is not None:
        user = getattr(request.state, "user", None)
    try:
        get_db().insert("nk_audit", {
            "user_id": user["id"] if user else None,
            "username": user["username"] if user else "public",
            "action": action,
            "target": target[:200],
            "detail": detail[:1000],
            "ip": client_ip(request) if request else "",
        }, returning=False)
    except DBError:
        pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
