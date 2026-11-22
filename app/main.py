"""NIRIKSHAK web application: officer console + citizen reporting portal."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

APP_DIR = Path(__file__).resolve().parent
_ROOT_DIR = str(APP_DIR.parent)
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from app import auth, config, feeds, notice, report, service
from app.analysis import ai_intel, linkchart
from app.analysis.iocs import ETYPE_LABELS
from app.analysis.scoring import Findings, Indicator
from app.db import DBError, get_db, ilike_term, in_list

app = FastAPI(title="NIRIKSHAK", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
IST = timezone(timedelta(hours=5, minutes=30))

STATUS_LABEL = {"open": "Open", "investigating": "Under investigation", "closed_fraud": "Closed — fraud confirmed",
                "closed_benign": "Closed — not fraud"}
KIND_LABEL = service.KIND_LABEL


def _ist(ts, fmt="%d %b %Y, %H:%M"):
    if not ts:
        return ""
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(IST).strftime(fmt)
    except ValueError:
        return str(ts)


templates.env.filters["ist"] = _ist
templates.env.filters["etype"] = lambda t: ETYPE_LABELS.get(t, t)
templates.env.filters["status"] = lambda s: STATUS_LABEL.get(s, s)
templates.env.filters["kind"] = lambda k: KIND_LABEL.get(k, k)
templates.env.filters["urlq"] = lambda s: quote(str(s), safe="")
templates.env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=2, ensure_ascii=False, default=str)
templates.env.globals.update(APP_NAME=config.APP_NAME, UNIT_NAME=config.UNIT_NAME, STATUS_LABEL=STATUS_LABEL,
                             KIND_LABEL=KIND_LABEL, ETYPE_LABELS=ETYPE_LABELS,
                             GROQ_ENABLED=config.GROQ_ENABLED, GROQ_MODEL=config.GROQ_MODEL,
                             GROQ_VISION_MODEL=config.GROQ_VISION_MODEL)


def _is_https(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    if config.TRUST_PROXY:
        proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
        return proto == "https"
    return False


def _expected_hosts(request: Request) -> set[str]:
    hosts: set[str] = set()
    raw = [request.url.netloc, request.headers.get("host", "")]
    if config.TRUST_PROXY:
        raw.append(request.headers.get("x-forwarded-host", "").split(",")[0].strip())
    for h in raw:
        h = h.strip().lower()
        if not h:
            continue
        hosts.add(h)
        if h.endswith(":443") or h.endswith(":80"):
            hosts.add(h.rsplit(":", 1)[0])
    return hosts


# ----------------------------------------------------------------------------- middleware
class Guard(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if config.config_problems() and not path.startswith("/static") and path != "/health":
            return templates.TemplateResponse(request, "config_error.html",
                                              {"problems": config.config_problems()}, status_code=503)
        csrf = request.cookies.get(auth.CSRF_COOKIE, "")
        need_csrf_cookie = not auth.valid_csrf_cookie(csrf)
        if need_csrf_cookie:
            csrf = auth.make_csrf()
        request.state.csrf_token = csrf

        # CSRF & cross-site origin check on state-changing requests
        if request.method == "POST" and not path.startswith("/api/"):
            if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
                return Response("Cross-site request refused", status_code=403)
            origin = request.headers.get("origin") or request.headers.get("referer") or ""
            if origin and urlsplit(origin).netloc.lower() not in _expected_hosts(request):
                return Response("Cross-site request refused", status_code=403)
        resp = await call_next(request)
        https = _is_https(request)
        if need_csrf_cookie:
            resp.set_cookie(
                auth.CSRF_COOKIE,
                csrf,
                httponly=True,
                samesite="strict",
                secure=https,
                path="/",
                max_age=config.SESSION_HOURS * 3600,
            )
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
        )
        if https:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if not path.startswith("/static"):
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            resp.headers["Pragma"] = "no-cache"
        return resp


app.add_middleware(Guard)


class NeedLogin(Exception):
    pass


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


@app.exception_handler(NeedLogin)
async def _need_login(request: Request, exc: NeedLogin):
    return RedirectResponse(f"/login?next={quote(request.url.path)}", status_code=303)


@app.exception_handler(Forbidden)
async def _forbidden(request: Request, exc: Forbidden):
    return page(request, "message.html", {"heading": "Not permitted",
                                          "text": "Your account does not have access to this page."}, 403)


@app.exception_handler(NotFound)
async def _not_found(request: Request, exc: NotFound):
    return page(request, "message.html", {"heading": "Record not found",
                                          "text": "The requested case, identifier, or evidence record does not exist."}, 404)


@app.exception_handler(DBError)
async def _dberror(request: Request, exc: DBError):
    u = getattr(request.state, "user", None)
    msg = str(exc) if u and u.get("role") == "admin" else "A database error occurred while processing the request."
    return page(request, "message.html", {"heading": "Database error", "text": msg}, 502)


def officer(request: Request) -> dict:
    u = auth.current_user(request)
    if not u:
        raise NeedLogin()
    return u


def admin(request: Request) -> dict:
    u = officer(request)
    if u["role"] != "admin":
        raise Forbidden()
    return u


def check_csrf(request: Request, csrf_token: str) -> None:
    if not auth.verify_csrf_pair(request.cookies.get(auth.CSRF_COOKIE, ""), csrf_token):
        raise Forbidden()


async def _read_upload(file: UploadFile, max_bytes: int) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"Uploaded file exceeds {max_bytes // (1024 * 1024)} MB limit.")
        chunks.append(chunk)
    return b"".join(chunks)


CHUNK_MAX_BYTES = 3 * 1024 * 1024
_UPLOAD_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _staging_key(scope: str, upload_id: str, idx: int) -> str:
    return f"_staging/{scope}/{upload_id}/{idx:04d}.part"


def _save_staged_chunk(db, scope: str, upload_id: str, idx: int, data: bytes) -> None:
    key = _staging_key(scope, upload_id, idx)
    try:
        db.upload(key, data, "application/octet-stream")
        return
    except DBError:
        if config.IS_SERVERLESS:
            raise
    d = config.EVIDENCE_DIR / "_staging" / scope / upload_id
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{idx:04d}.part").write_bytes(data)


def _assemble_staged_upload(db, scope: str, upload_id: str, total_chunks: int, max_bytes: int) -> bytes:
    if not _UPLOAD_ID_RE.fullmatch(upload_id) or not (1 <= total_chunks <= 64):
        raise ValueError("Invalid staged upload reference.")
    local_dir = config.EVIDENCE_DIR / "_staging" / scope / upload_id
    keys = [_staging_key(scope, upload_id, idx) for idx in range(total_chunks)]
    parts: list[bytes] = []
    total = 0
    try:
        for idx, key in enumerate(keys):
            lp = local_dir / f"{idx:04d}.part"
            if lp.exists():
                chunk = lp.read_bytes()
            else:
                chunk = db.download(key)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"Uploaded file exceeds {max_bytes // (1024 * 1024)} MB limit.")
            parts.append(chunk)
        return b"".join(parts)
    finally:
        for idx, key in enumerate(keys):
            lp = local_dir / f"{idx:04d}.part"
            try:
                lp.unlink(missing_ok=True)
            except OSError:
                pass
            try:
                db.delete_object(key)
            except DBError:
                pass
        try:
            local_dir.rmdir()
        except OSError:
            pass


def page(request: Request, tpl: str, ctx: dict | None = None, status: int = 200):
    ctx = dict(ctx or {})
    ctx.setdefault("user", getattr(request.state, "user", None))
    ctx.setdefault("csrf_token", getattr(request.state, "csrf_token", ""))
    ctx.setdefault("nav", "")
    return templates.TemplateResponse(request, tpl, ctx, status_code=status)


# ---- public rate limit -------------------------------------------------------
_public_hits: dict[str, deque] = defaultdict(deque)
_rate_lock = threading.Lock()


def public_limited(request: Request, per_hour: int = 30) -> bool:
    ip = auth.client_ip(request)
    with _rate_lock:
        q = _public_hits[ip]
        now = time.time()
        while q and now - q[0] > 3600:
            q.popleft()
        if len(q) >= per_hour:
            return True
        q.append(now)
        return False


# ----------------------------------------------------------------------------- setup / login
def _no_users() -> bool:
    return not get_db().select("nk_users", limit=1, columns="id")


@app.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request):
    if not _no_users():
        return RedirectResponse("/login", 303)
    return page(request, "setup.html", {"form": {}})


@app.post("/setup")
def setup_submit(request: Request, username: str = Form(...), full_name: str = Form(...), rank: str = Form(""),
                 badge_no: str = Form(""), unit: str = Form(""), password: str = Form(...), password2: str = Form(...),
                 csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    if not _no_users():
        return RedirectResponse("/login", 303)
    form = {"username": username, "full_name": full_name, "rank": rank, "badge_no": badge_no, "unit": unit}
    err = auth.password_problem(password) or (None if password == password2 else "Passwords do not match.")
    if not username.strip().isalnum() and not all(c.isalnum() or c in "._-" for c in username.strip()):
        err = "Username may contain letters, digits, dot, dash and underscore only."
    if err:
        return page(request, "setup.html", {"form": form, "error": err}, 400)
    row = get_db().insert("nk_users", {"username": username.strip().lower(), "full_name": full_name.strip(),
                                       "rank": rank.strip(), "badge_no": badge_no.strip(), "unit": unit.strip(),
                                       "role": "admin", "pw_hash": auth.hash_password(password)})[0]
    auth.audit(request, "setup", row["username"], "first administrator account created", user=row)
    return RedirectResponse("/login?created=1", 303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", created: int = 0):
    if _no_users():
        return RedirectResponse("/setup", 303)
    return page(request, "login.html", {"next": next, "created": created})


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"),
                 csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    if len(password) > 256:
        return page(request, "login.html", {"next": next, "error": "Password exceeds maximum length."}, 400)
    ip = auth.client_ip(request)
    uname = username.strip().lower()
    if auth.throttled(ip) or auth.throttled(f"{ip}:{uname}"):
        return page(request, "login.html", {"next": next, "error": "Too many failed attempts. Try again in 15 minutes."}, 429)
    u = get_db().one("nk_users", {"username": f"eq.{uname}"})
    if not u:
        auth.verify_dummy(password)
        ok_pw = False
    else:
        ok_pw = u["active"] and auth.verify_password(password, u["pw_hash"])
    if not ok_pw:
        auth.record_failure(ip)
        auth.record_failure(f"{ip}:{uname}")
        auth.audit(request, "login_failed", uname[:60], user=None)
        return page(request, "login.html", {"next": next, "error": "Invalid username or password."}, 401)
    auth.clear_failures(ip)
    auth.clear_failures(f"{ip}:{uname}")
    get_db().update("nk_users", {"id": f"eq.{u['id']}"}, {"last_login": auth.now_iso()})
    auth.audit(request, "login", u["username"], user=u)
    dest = next if next.startswith("/") and not next.startswith("//") else "/"
    resp = RedirectResponse(dest, 303)
    resp.set_cookie(auth.COOKIE, auth.make_session(u), httponly=True, samesite="strict",
                    secure=_is_https(request), path="/", max_age=config.SESSION_HOURS * 3600)
    return resp


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    u = auth.current_user(request)
    if u:
        auth.audit(request, "logout", u["username"])
    resp = RedirectResponse("/login", 303)
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


# ----------------------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    u = officer(request)
    db = get_db()
    stats = db.rpc("nk_stats") or {}
    recent = db.select("nk_cases", columns="id,case_no,kind,title,risk_level,risk_score,status,source,category,created_at",
                       order="created_at.desc", limit=12)
    queue = db.select("nk_cases", {"source": "eq.citizen", "status": "eq.open"},
                      columns="id,case_no,kind,title,risk_level,risk_score,created_at", order="risk_score.desc,created_at.desc",
                      limit=8)
    heat = db.rpc("nk_heatlist", {"p_days": 30, "p_limit": 10, "p_etype": None}) or []
    return page(request, "dashboard.html", {"nav": "dash", "stats": stats, "recent": recent, "queue": queue, "heat": heat})


# ----------------------------------------------------------------------------- analysis
@app.get("/analyze", response_class=HTMLResponse)
def analyze_form(request: Request, type: str = "message"):
    officer(request)
    if type not in KIND_LABEL:
        type = "message"
    return page(request, "analyze.html", {"nav": "new", "kind": type, "form": {}})


@app.post("/api/upload/chunk")
async def upload_chunk(
    request: Request,
    scope: str = Form(...),
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    csrf_token: str = Form(""),
    chunk: UploadFile = File(...),
):
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return JSONResponse({"error": "Cross-site request refused"}, 403)
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if origin and urlsplit(origin).netloc.lower() not in _expected_hosts(request):
        return JSONResponse({"error": "Cross-site request refused"}, 403)
    try:
        check_csrf(request, csrf_token)
    except Forbidden:
        return JSONResponse({"error": "Invalid or expired security token. Reload and try again."}, 403)

    if scope == "officer":
        if not auth.current_user(request):
            return JSONResponse({"error": "Authentication required."}, 401)
        max_chunks = min(64, max(1, (config.MAX_APK_BYTES // (2 * 1024 * 1024)) + 4))
    elif scope == "citizen":
        if public_limited(request, 80):
            return JSONResponse({"error": "Too many upload requests from this connection."}, 429)
        max_chunks = 16
    else:
        return JSONResponse({"error": "Invalid upload scope."}, 400)

    if not _UPLOAD_ID_RE.fullmatch(upload_id) or not (0 <= chunk_index < total_chunks <= max_chunks):
        return JSONResponse({"error": "Invalid chunk metadata."}, 400)
    try:
        data = await _read_upload(chunk, CHUNK_MAX_BYTES)
        if not data:
            return JSONResponse({"error": "Empty upload chunk."}, 400)
        _save_staged_chunk(get_db(), scope, upload_id, chunk_index, data)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, 400)
    except DBError as exc:
        return JSONResponse({"error": f"Staging storage error: {exc}"}, 502)
    return JSONResponse({"ok": True, "chunk_index": chunk_index, "size": len(data)})


@app.post("/analyze/{kind}")
async def analyze_submit(request: Request, kind: str, text: str = Form(""), channel: str = Form("sms"),
                         sender: str = Form(""), url: str = Form(""), file: UploadFile | None = File(None),
                         staged_upload_id: str = Form(""), staged_chunks: int = Form(0),
                         staged_filename: str = Form(""), live: str = Form("0"), csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    u = officer(request)
    if kind not in KIND_LABEL:
        return RedirectResponse("/analyze", 303)
    form = {"text": text, "channel": channel, "sender": sender, "url": url}
    upload = None
    limit = config.MAX_APK_BYTES if kind == "apk" else 15 * 1024 * 1024
    if file is not None and file.filename:
        try:
            data = await _read_upload(file, limit)
        except ValueError as exc:
            return page(request, "analyze.html", {"nav": "new", "kind": kind, "form": form, "error": str(exc)}, 400)
        if data:
            upload = (file.filename, data)
    elif staged_upload_id and staged_chunks > 0:
        try:
            data = _assemble_staged_upload(get_db(), "officer", staged_upload_id, staged_chunks, limit)
        except (ValueError, DBError) as exc:
            return page(request, "analyze.html", {"nav": "new", "kind": kind, "form": form, "error": str(exc)}, 400)
        if data:
            upload = (Path(staged_filename or "upload.apk").name, data)
    try:
        result = service.analyse(kind, text=text, channel=channel, sender=sender, url=url, upload=upload,
                                 run_live=live == "1")
    except ValueError as exc:
        return page(request, "analyze.html", {"nav": "new", "kind": kind, "form": form, "error": str(exc)}, 400)
    input_text = text if kind == "message" else (url or (upload[0] if upload else ""))
    case = service.create_case(get_db(), kind, result, input_text=input_text, source="officer", user=u,
                               channel=channel if kind == "message" else "")
    auth.audit(request, "analyse", case["case_no"], f"{kind}: {case['title'][:120]} -> {case['risk_level']} {case['risk_score']}")
    return RedirectResponse(f"/cases/{case['id']}", 303)


# ----------------------------------------------------------------------------- cases
def _csv_safe(val) -> str:
    s = "" if val is None else str(val)
    return "'" + s if s.startswith(("=", "+", "-", "@", "\t", "\r")) else s


def _case_filter_params(db, q: str, kind: str, risk: str, status: str, source: str, days: str) -> dict:
    params: dict = {}
    if kind in KIND_LABEL:
        params["kind"] = f"eq.{kind}"
    if risk in ("LOW", "MEDIUM", "HIGH"):
        params["risk_level"] = f"eq.{risk}"
    if status in STATUS_LABEL:
        params["status"] = f"eq.{status}"
    if source in ("officer", "citizen"):
        params["source"] = f"eq.{source}"
    if days.isdigit():
        params["created_at"] = f"gte.{(datetime.now(timezone.utc) - timedelta(days=int(days))).isoformat()}"
    term = ilike_term(q)
    if term:
        ors = [f"case_no.ilike.*{term}*", f"title.ilike.*{term}*", f"input_text.ilike.*{term}*", f"category.ilike.*{term}*"]
        ents = db.select("nk_entities", {"value": f"ilike.*{term.lower()}*"}, columns="id", limit=200)
        if ents:
            links = db.select("nk_case_entities", {"entity_id": in_list([e["id"] for e in ents])}, columns="case_id", limit=1000)
            ids = sorted({l["case_id"] for l in links})
            if ids:
                ors.append(f"id.in.({','.join(str(i) for i in ids[:300])})")
        params["or"] = f"({','.join(ors)})"
    return params


@app.get("/cases", response_class=HTMLResponse)
def cases(request: Request, q: str = "", kind: str = "", risk: str = "", status: str = "", source: str = "",
          days: str = "", page_no: int = 1):
    officer(request)
    db = get_db()
    params = _case_filter_params(db, q, kind, risk, status, source, days)
    per = 40
    page_no = max(1, page_no)
    rows, total = db.select_count("nk_cases", params, limit=per, offset=(page_no - 1) * per, order="created_at.desc",
                                  columns="id,case_no,kind,title,risk_level,risk_score,status,source,category,created_at")
    filters = {"q": q, "kind": kind, "risk": risk, "status": status, "source": source, "days": days}
    qs = "&".join(f"{k}={quote(v)}" for k, v in filters.items() if v)
    return page(request, "cases.html", {"nav": "cases", "rows": rows, "total": total, "filters": filters, "page_no": page_no,
                                        "pages": max(1, (total + per - 1) // per), "qs": qs})


@app.get("/cases/export.csv")
def cases_export_csv(request: Request, q: str = "", kind: str = "", risk: str = "", status: str = "",
                     source: str = "", days: str = ""):
    officer(request)
    db = get_db()
    params = _case_filter_params(db, q, kind, risk, status, source, days)
    rows = db.select(
        "nk_cases",
        params,
        limit=2000,
        order="created_at.desc",
        columns="case_no,kind,source,title,category,risk_level,risk_score,status,channel,content_sha256,created_at",
    )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["case_no", "type", "source", "subject", "category", "risk_level", "risk_score", "status",
                "channel", "content_sha256", "received_ist"])
    for r in rows:
        w.writerow([
            r.get("case_no", ""),
            KIND_LABEL.get(r.get("kind", ""), r.get("kind", "")),
            r.get("source", ""),
            _csv_safe(r.get("title", "")),
            _csv_safe(r.get("category", "")),
            r.get("risk_level", ""),
            r.get("risk_score", 0),
            STATUS_LABEL.get(r.get("status", ""), r.get("status", "")),
            r.get("channel", ""),
            r.get("content_sha256", ""),
            _ist(r.get("created_at"), "%Y-%m-%d %H:%M:%S"),
        ])
    auth.audit(request, "export_csv", "cases", f"rows={len(rows)}")
    return Response(
        buf.getvalue().encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="nirikshak-cases.csv"'},
    )


def _load_case(case_id: int) -> dict:
    c = get_db().one("nk_cases", {"id": f"eq.{case_id}"})
    if not c:
        raise NotFound()
    return c


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_view(request: Request, case_id: int):
    officer(request)
    db = get_db()
    c = _load_case(case_id)
    ev = db.select("nk_evidence", {"case_id": f"eq.{case_id}"}, order="id.asc")
    ents = db.select("nk_case_entities", {"case_id": f"eq.{case_id}"},
                     columns="context,nk_entities(id,etype,value,display,case_count,first_seen)", limit=500)
    entities = sorted([dict(e["nk_entities"], context=e["context"]) for e in ents if e.get("nk_entities")],
                      key=lambda x: (-x["case_count"], x["etype"]))
    # live view of links: other cases sharing identifiers (may have grown since analysis)
    linked = []
    shared = [e["id"] for e in entities if e["case_count"] > 1]
    if shared:
        rows = db.select("nk_case_entities", {"entity_id": in_list(shared), "case_id": f"neq.{case_id}"},
                         columns="entity_id,nk_cases(id,case_no,kind,title,risk_level,status,created_at)", limit=300)
        by_id = {e["id"]: e for e in entities}
        for r in rows:
            if r.get("nk_cases"):
                linked.append({"entity": by_id[r["entity_id"]], "case": r["nk_cases"]})
    submitter = db.one("nk_users", {"id": f"eq.{c['submitted_by']}"}, columns="full_name,rank,badge_no,username") \
        if c.get("submitted_by") else None
    trail = db.select("nk_audit", {"target": f"eq.{c['case_no']}"}, order="at.asc", limit=100)
    auth.audit(request, "view_case", c["case_no"])
    return page(request, "case.html", {"nav": "cases", "c": c, "r": c["result"], "evidence": ev, "entities": entities,
                                       "linked": linked, "submitter": submitter, "trail": trail})


@app.post("/cases/{case_id}/status")
def case_status(request: Request, case_id: int, status: str = Form(...), notes: str = Form(""),
                csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    u = officer(request)
    db = get_db()
    c = _load_case(case_id)
    if status not in STATUS_LABEL:
        return RedirectResponse(f"/cases/{case_id}", 303)
    values = {"status": status, "updated_at": auth.now_iso()}
    if notes.strip():
        stamp = datetime.now(IST).strftime("%d-%m-%Y %H:%M")
        values["notes"] = (c["notes"] + "\n\n" if c["notes"] else "") + f"[{stamp} {u['username']}] {notes.strip()}"
    db.update("nk_cases", {"id": f"eq.{case_id}"}, values)
    detail = f"{c['status']} -> {status}" + (f"; note: {notes.strip()[:200]}" if notes.strip() else "")
    if status == "closed_fraud" and c["status"] != "closed_fraud":
        n = service.confirm_fraud(db, c, u)
        detail += f"; {n} identifier(s) added to blocklist"
    auth.audit(request, "update_case", c["case_no"], detail)
    return RedirectResponse(f"/cases/{case_id}", 303)


@app.post("/cases/{case_id}/ai-brief")
def case_ai_brief(request: Request, case_id: int, csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    officer(request)
    db = get_db()
    c = _load_case(case_id)
    if not config.GROQ_ENABLED:
        return RedirectResponse(f"/cases/{case_id}#ai-panel", 303)

    res = dict(c.get("result") or {})
    f = Findings()
    for it in res.get("indicators") or []:
        f.items.append(Indicator(
            it.get("code", "rule"),
            it.get("title", ""),
            it.get("detail", ""),
            int(it.get("weight") or 0),
            it.get("group", "content"),
            it.get("evidence", ""),
        ))
    ai = ai_intel.analyze_forensics(
        c["kind"],
        text=c.get("input_text") or c.get("title") or "",
        findings=f,
        details=res.get("details") or {},
        iocs=res.get("identifiers") or [],
        category=c.get("category") or "",
    )
    if ai:
        det = dict(res.get("details") or {})
        det["ai"] = ai
        res["details"] = det
        eng = dict(res.get("engine") or {})
        eng["groq_ai"] = True
        eng["groq_model"] = ai.get("model", "")
        res["engine"] = eng
        upd = {"result": res, "updated_at": auth.now_iso()}
        if not c.get("category") and ai.get("threat_category") and c.get("risk_score", 0) >= 30:
            upd["category"] = ai["threat_category"]
        db.update("nk_cases", {"id": f"eq.{case_id}"}, upd)
        auth.audit(request, "ai_brief", c["case_no"], ai.get("model", "Groq"))
    return RedirectResponse(f"/cases/{case_id}#ai-panel", 303)


@app.post("/cases/{case_id}/ai-ask")
def case_ai_ask(request: Request, case_id: int, question: str = Form(...), csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    officer(request)
    db = get_db()
    c = _load_case(case_id)
    if config.GROQ_ENABLED and question.strip():
        qa = ai_intel.ask_case_question(c, question)
        if qa:
            res = dict(c.get("result") or {})
            det = dict(res.get("details") or {})
            hist = list(det.get("ai_qa") or [])
            hist.insert(0, qa)
            det["ai_qa"] = hist[:10]
            res["details"] = det
            db.update("nk_cases", {"id": f"eq.{case_id}"}, {"result": res, "updated_at": auth.now_iso()})
            auth.audit(request, "ai_ask", c["case_no"], question.strip()[:160])
    return RedirectResponse(f"/cases/{case_id}#ai-panel", 303)


@app.get("/cases/{case_id}/report.pdf")
def case_pdf(request: Request, case_id: int):
    u = officer(request)
    db = get_db()
    c = _load_case(case_id)
    ev = db.select("nk_evidence", {"case_id": f"eq.{case_id}"}, order="id.asc")
    auth.audit(request, "export_pdf", c["case_no"])
    trail = db.select("nk_audit", {"target": f"eq.{c['case_no']}"}, order="at.asc", limit=200)
    submitter = db.one("nk_users", {"id": f"eq.{c['submitted_by']}"}) if c.get("submitted_by") else None
    pdf = report.build(c, ev, trail, submitter, u)
    name = c["case_no"].replace("/", "-") + ".pdf"
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/cases/{case_id}/export.json")
def case_json(request: Request, case_id: int):
    officer(request)
    db = get_db()
    c = _load_case(case_id)
    c["evidence"] = db.select("nk_evidence", {"case_id": f"eq.{case_id}"}, order="id.asc")
    c.pop("shingles", None)
    auth.audit(request, "export_json", c["case_no"])
    name = c["case_no"].replace("/", "-") + ".json"
    return Response(json.dumps(c, indent=2, ensure_ascii=False, default=str), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/cases/{case_id}/notice.txt")
def case_notice(request: Request, case_id: int):
    u = officer(request)
    db = get_db()
    c = _load_case(case_id)
    ents = db.select("nk_case_entities", {"case_id": f"eq.{case_id}"},
                     columns="context,nk_entities(id,etype,value,display,case_count)", limit=500)
    entities = [dict(e["nk_entities"], context=e["context"]) for e in ents if e.get("nk_entities")]
    txt = notice.build_notice(c, entities, u)
    auth.audit(request, "export_notice", c["case_no"])
    name = c["case_no"].replace("/", "-") + "-nodal-notice.txt"
    return Response(txt.encode("utf-8"), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/evidence/{ev_id}")
def evidence_download(request: Request, ev_id: int):
    officer(request)
    db = get_db()
    e = db.one("nk_evidence", {"id": f"eq.{ev_id}"})
    if not e:
        raise NotFound()
    c = db.one("nk_cases", {"id": f"eq.{e['case_id']}"}, columns="case_no")
    local = config.EVIDENCE_DIR / str(e["case_id"])
    data = None
    if local.exists():
        for p in local.iterdir():
            if p.name.startswith(e["sha256"][:12]):
                data = p.read_bytes()
                break
    if data is None and e["storage_path"]:
        try:
            data = db.download(e["storage_path"])
        except DBError:
            data = None
    if data is None:
        return page(request, "message.html", {"heading": "Evidence unavailable", "text": "File not found in storage."}, 404)
    if hashlib.sha256(data).hexdigest() != e["sha256"]:
        auth.audit(request, "evidence_integrity_fail", c["case_no"] if c else "", e["filename"])
        return page(request, "message.html", {"heading": "Integrity check failed",
                                              "text": "Stored file no longer matches its recorded SHA-256. Download blocked."}, 409)
    auth.audit(request, "download_evidence", c["case_no"] if c else "", f"{e['filename']} sha256={e['sha256']}")
    safe_fname = re.sub(r"[^A-Za-z0-9._-]", "_", Path(e["filename"]).name)[-80:] or "evidence.bin"
    # served as attachment, never rendered inline: captured pages may contain hostile script
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{e["sha256"][:12]}_{safe_fname}"'})


# ----------------------------------------------------------------------------- identifiers
@app.get("/identifiers", response_class=HTMLResponse)
def identifiers(request: Request, q: str = "", type: str = "", linked: str = ""):
    officer(request)
    params: dict = {}
    term = ilike_term(q)
    if term:
        params["or"] = f"(value.ilike.*{term.lower()}*,display.ilike.*{term}*)"
    if type in ETYPE_LABELS:
        params["etype"] = f"eq.{type}"
    if linked == "1":
        params["case_count"] = "gt.1"
    rows, total = get_db().select_count("nk_entities", params, limit=200, order="case_count.desc,last_seen.desc")
    return page(request, "identifiers.html", {"nav": "ids", "rows": rows, "total": total,
                                              "filters": {"q": q, "type": type, "linked": linked}})


@app.get("/identifiers/{ent_id}", response_class=HTMLResponse)
def identifier_view(request: Request, ent_id: int):
    officer(request)
    db = get_db()
    e = db.one("nk_entities", {"id": f"eq.{ent_id}"})
    if not e:
        raise NotFound()
    rows = db.select("nk_case_entities", {"entity_id": f"eq.{ent_id}"},
                     columns="context,nk_cases(id,case_no,kind,title,risk_level,risk_score,status,source,created_at)", limit=500)
    cases_ = sorted([dict(r["nk_cases"], context=r["context"]) for r in rows if r.get("nk_cases")],
                    key=lambda x: x["created_at"], reverse=True)
    # co-occurring identifiers: what else appears alongside this one
    co = []
    if cases_:
        ce = db.select("nk_case_entities", {"case_id": in_list([c["id"] for c in cases_]), "entity_id": f"neq.{ent_id}"},
                       columns="case_id,nk_entities(id,etype,value,display,case_count)", limit=2000)
        agg: dict[int, dict] = {}
        for r in ce:
            en = r.get("nk_entities")
            if not en:
                continue
            a = agg.setdefault(en["id"], dict(en, together=set()))
            a["together"].add(r["case_id"])
        co = sorted(agg.values(), key=lambda x: (-len(x["together"]), -x["case_count"]))[:40]
        for a in co:
            a["together"] = len(a["together"])
    bl = db.select("nk_blocklist", {"etype": f"eq.{e['etype']}", "value": f"eq.{e['value']}"})
    chart_svg = linkchart.render_identifier_svg(e, cases_, co)
    return page(request, "identifier.html", {"nav": "ids", "e": e, "cases": cases_, "co": co,
                                            "blocklisted": bl, "chart_svg": chart_svg})


@app.get("/heatlist", response_class=HTMLResponse)
def heatlist(request: Request, days: int = 30, type: str = ""):
    officer(request)
    days = days if days in (1, 7, 30, 90, 365) else 30
    db = get_db()
    sections = []
    types = [type] if type in ETYPE_LABELS else ["domain", "phone", "upi", "apk_package", "bank_account", "telegram", "crypto"]
    for t in types:
        rows = db.rpc("nk_heatlist", {"p_days": days, "p_limit": 25 if type else 10, "p_etype": t}) or []
        sections.append((t, rows))
    return page(request, "heatlist.html", {"nav": "heat", "sections": sections, "days": days, "type": type})


@app.get("/heatlist/export.csv")
def heatlist_export_csv(request: Request, days: int = 30, type: str = ""):
    officer(request)
    days = days if days in (1, 7, 30, 90, 365) else 30
    etype = type if type in ETYPE_LABELS else None
    rows = get_db().rpc("nk_heatlist", {"p_days": days, "p_limit": 200, "p_etype": etype}) or []
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["rank", "type", "identifier", "normalized_value", "cases", "high_risk_cases",
                "first_seen_ist", "last_seen_ist"])
    for idx, r in enumerate(rows, 1):
        w.writerow([
            idx,
            ETYPE_LABELS.get(r.get("etype", ""), r.get("etype", "")),
            _csv_safe(r.get("display", "")),
            _csv_safe(r.get("value", "")),
            r.get("reports", 0),
            r.get("high_risk", 0),
            _ist(r.get("first_seen"), "%Y-%m-%d %H:%M:%S"),
            _ist(r.get("last_seen"), "%Y-%m-%d %H:%M:%S"),
        ])
    auth.audit(request, "export_heatlist_csv", f"days={days}", f"type={etype or 'all'}; rows={len(rows)}")
    return Response(
        buf.getvalue().encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="nirikshak-heatlist-{days}d.csv"'},
    )


# ----------------------------------------------------------------------------- blocklist
@app.get("/blocklist", response_class=HTMLResponse)
def blocklist(request: Request, q: str = "", type: str = "", msg: str = ""):
    officer(request)
    params: dict = {}
    term = ilike_term(q)
    if term:
        params["value"] = f"ilike.*{term.lower()}*"
    if type:
        params["etype"] = f"eq.{type}"
    rows, total = get_db().select_count("nk_blocklist", params, limit=200, order="added_at.desc")
    return page(request, "blocklist.html", {"nav": "block", "rows": rows, "total": total, "q": q, "type": type, "msg": msg,
                                            "feeds": feeds.FEEDS})


@app.post("/blocklist/add")
def blocklist_add(request: Request, etype: str = Form(...), value: str = Form(...), note: str = Form(""),
                  csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    u = officer(request)
    from .analysis import iocs as ioc_mod
    v = value.strip()
    if etype == "phone":
        v = ioc_mod.normalise_phone(v) or v
    elif etype in ("domain", "upi", "email", "url", "telegram"):
        v = v.lower()
    if etype not in ETYPE_LABELS or not v:
        return RedirectResponse("/blocklist?msg=Invalid+entry", 303)
    get_db().insert("nk_blocklist", {"etype": etype, "value": v, "source": f"Manual — {u['username']}", "note": note.strip()[:300],
                                     "added_by": u["username"]}, on_conflict="etype,value", ignore_duplicates=True,
                    returning=False)
    auth.audit(request, "blocklist_add", v, f"{etype}; {note[:200]}")
    return RedirectResponse("/blocklist?msg=Added", 303)


@app.post("/blocklist/{bid}/delete")
def blocklist_delete(request: Request, bid: int, csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    admin(request)
    db = get_db()
    row = db.one("nk_blocklist", {"id": f"eq.{bid}"})
    if row:
        db.delete("nk_blocklist", {"id": f"eq.{bid}"})
        auth.audit(request, "blocklist_remove", row["value"], row["source"])
    return RedirectResponse("/blocklist?msg=Removed", 303)


@app.post("/blocklist/sync/{feed}")
def blocklist_sync(request: Request, feed: str, csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    u = admin(request)
    if feed not in feeds.FEEDS:
        return RedirectResponse("/blocklist", 303)
    try:
        res = feeds.sync(get_db(), feed, u["username"])
        msg = f"{res['feed']}: {res['urls']} URLs, {res['domains']} domains processed"
    except Exception as exc:
        msg = f"Feed sync failed: {exc.__class__.__name__}: {str(exc)[:120]}"
    auth.audit(request, "feed_sync", feed, msg)
    return RedirectResponse(f"/blocklist?msg={quote(msg)}", 303)


# ----------------------------------------------------------------------------- users / audit
@app.get("/users", response_class=HTMLResponse)
def users(request: Request, msg: str = ""):
    admin(request)
    rows = get_db().select("nk_users", columns="id,username,full_name,rank,badge_no,unit,role,active,created_at,last_login",
                           order="id.asc")
    return page(request, "users.html", {"nav": "users", "rows": rows, "msg": msg})


@app.post("/users")
def users_add(request: Request, username: str = Form(...), full_name: str = Form(...), rank: str = Form(""),
              badge_no: str = Form(""), unit: str = Form(""), role: str = Form("officer"), password: str = Form(...),
              csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    admin(request)
    err = auth.password_problem(password)
    uname = username.strip().lower()
    if not uname or not all(c.isalnum() or c in "._-" for c in uname):
        err = "Invalid username."
    if err:
        return RedirectResponse(f"/users?msg={quote(err)}", 303)
    try:
        get_db().insert("nk_users", {"username": uname, "full_name": full_name.strip(), "rank": rank.strip(),
                                     "badge_no": badge_no.strip(), "unit": unit.strip(),
                                     "role": role if role in ("admin", "officer") else "officer",
                                     "pw_hash": auth.hash_password(password)})
    except DBError as exc:
        return RedirectResponse(f"/users?msg={quote('Could not create user: ' + str(exc)[:100])}", 303)
    auth.audit(request, "user_create", uname, role)
    return RedirectResponse(f"/users?msg={quote('Account created: ' + uname)}", 303)


@app.post("/users/{uid}/toggle")
def users_toggle(request: Request, uid: int, csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    me = admin(request)
    if uid == me["id"]:
        return RedirectResponse("/users?msg=You+cannot+disable+your+own+account", 303)
    db = get_db()
    u = db.one("nk_users", {"id": f"eq.{uid}"})
    if u:
        db.update("nk_users", {"id": f"eq.{uid}"}, {"active": not u["active"]})
        auth.audit(request, "user_disable" if u["active"] else "user_enable", u["username"])
    return RedirectResponse("/users", 303)


@app.get("/account", response_class=HTMLResponse)
def account(request: Request, msg: str = ""):
    officer(request)
    return page(request, "account.html", {"nav": "", "msg": msg})


@app.post("/account")
def account_pw(request: Request, current: str = Form(...), password: str = Form(...), password2: str = Form(...),
               csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    u = officer(request)
    if not auth.verify_password(current, u["pw_hash"]):
        return RedirectResponse("/account?msg=Current+password+is+wrong", 303)
    err = auth.password_problem(password) or (None if password == password2 else "Passwords do not match.")
    if err:
        return RedirectResponse(f"/account?msg={quote(err)}", 303)
    get_db().update("nk_users", {"id": f"eq.{u['id']}"}, {"pw_hash": auth.hash_password(password)})
    auth.audit(request, "password_change", u["username"])
    resp = RedirectResponse("/login", 303)
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


@app.get("/audit", response_class=HTMLResponse)
def audit_log(request: Request, q: str = "", page_no: int = 1):
    admin(request)
    params = {}
    term = ilike_term(q)
    if term:
        params["or"] = f"(username.ilike.*{term}*,action.ilike.*{term}*,target.ilike.*{term}*,detail.ilike.*{term}*)"
    rows, total = get_db().select_count("nk_audit", params, limit=100, offset=(max(1, page_no) - 1) * 100, order="at.desc")
    return page(request, "audit.html", {"nav": "audit", "rows": rows, "total": total, "q": q, "page_no": max(1, page_no),
                                        "pages": max(1, (total + 99) // 100)})


# ----------------------------------------------------------------------------- citizen portal
@app.get("/report", response_class=HTMLResponse)
def citizen_form(request: Request, kind: str = "", url: str = ""):
    form = {"kind": kind if kind in KIND_LABEL else "message", "url": url.strip()}
    return page(request, "citizen.html", {"public": True, "form": form})


@app.post("/report")
async def citizen_submit(request: Request, kind: str = Form("message"), text: str = Form(""), url: str = Form(""),
                         channel: str = Form("sms"), sender: str = Form(""), name: str = Form(""), contact: str = Form(""),
                         file: UploadFile | None = File(None), staged_upload_id: str = Form(""),
                         staged_chunks: int = Form(0), staged_filename: str = Form(""),
                         consent: str = Form(""), csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    form = {"kind": kind, "text": text, "url": url, "channel": channel, "sender": sender, "name": name, "contact": contact}
    if public_limited(request, 15):
        return page(request, "citizen.html", {"public": True, "form": form,
                                              "error": "Too many reports from this connection. Please try later."}, 429)
    if kind not in ("message", "url", "website", "apk"):
        kind = "message"
    if not consent:
        return page(request, "citizen.html", {"public": True, "form": form,
                                              "error": "Please confirm the declaration before submitting."}, 400)
    upload = None
    limit = 25 * 1024 * 1024 if kind == "apk" else 15 * 1024 * 1024
    if file is not None and file.filename:
        try:
            data = await _read_upload(file, limit)
        except ValueError as exc:
            return page(request, "citizen.html", {"public": True, "form": form, "error": str(exc)}, 400)
        if data:
            upload = (file.filename, data)
    elif staged_upload_id and staged_chunks > 0:
        try:
            data = _assemble_staged_upload(get_db(), "citizen", staged_upload_id, staged_chunks, limit)
        except (ValueError, DBError) as exc:
            return page(request, "citizen.html", {"public": True, "form": form, "error": str(exc)}, 400)
        if data:
            upload = (Path(staged_filename or "upload.apk").name, data)
    try:
        result = service.analyse(kind, text=text, channel=channel, sender=sender, url=url, upload=upload)
    except ValueError as exc:
        return page(request, "citizen.html", {"public": True, "form": form, "error": str(exc)}, 400)
    case = service.create_case(get_db(), kind, result, input_text=text if kind == "message" else (url or (upload[0] if upload else "")),
                               source="citizen", user=None, reporter_name=name, reporter_contact=contact,
                               channel=channel if kind == "message" else "")
    auth.audit(request, "citizen_report", case["case_no"], f"{kind} -> {case['risk_level']}", user=None)
    f: Findings = result["findings"]
    return page(request, "citizen_result.html", {"public": True, "case": case, "findings": f.to_list(), "level": f.level,
                                                 "score": f.score})


def _quick_check(u: str) -> tuple[dict, Findings]:
    result = service.analyse("url", url=u)
    f: Findings = result["findings"]
    items = service.dedupe(result.get("iocs", []))
    intel = service.correlate(get_db(), f, items, "url", "", result)
    return {"url": result["details"].get("url") or u, "intel": intel, "details": result["details"]}, f


@app.get("/check", response_class=HTMLResponse)
def check_link(request: Request, u: str = ""):
    """Interstitial shown before opening a link (used by the browser extension and bot)."""
    if not u.strip():
        return page(request, "check.html", {"public": True})
    if public_limited(request, 40):
        return page(request, "check.html", {"public": True, "u": u, "error": "Rate limit reached. Try again later."}, 429)
    try:
        info, f = _quick_check(u)
    except ValueError as exc:
        return page(request, "check.html", {"public": True, "u": u, "error": str(exc)}, 400)
    auth.audit(request, "link_check", u[:200], f"{f.level} {f.score}", user=None)
    return page(request, "check.html", {"public": True, "u": u, "info": info, "findings": f.to_list(), "level": f.level,
                                        "score": f.score})


@app.get("/api/check")
def api_check(request: Request, u: str = ""):
    if not u.strip():
        return JSONResponse({"error": "missing u"}, 400)
    if public_limited(request, 120):
        return JSONResponse({"error": "rate limited"}, 429)
    try:
        info, f = _quick_check(u)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, 400)
    return JSONResponse({"url": info["url"], "level": f.level, "score": f.score,
                         "reasons": [{"title": i["title"], "detail": i["detail"], "weight": i["weight"]}
                                     for i in f.to_list() if i["weight"] > 0][:8],
                         "linked_cases": len({l["case_no"] for l in info["intel"]["linked"]})},
                        headers={"Access-Control-Allow-Origin": "*"})


@app.get("/health")
def health():
    try:
        get_db().ping()
        return {
            "status": "ok",
            "database": "ok",
            "live_checks": config.LIVE_CHECKS,
            "groq_ai": config.GROQ_ENABLED,
            "groq_model": config.GROQ_MODEL if config.GROQ_ENABLED else "",
        }
    except DBError as exc:
        return JSONResponse({"status": "degraded", "database": str(exc)}, 503)
