"""Thin PostgREST + Storage client for Supabase.

Uses the service_role key server-side only. All tables have RLS enabled with
no policies, so nothing is reachable with the public anon key.
"""
from __future__ import annotations

import json
import threading
from typing import Any
from urllib.parse import quote

import requests

from . import config


class DBError(RuntimeError):
    pass


class Supabase:
    def __init__(self, url: str, key: str, db_secret: str = ""):
        self.url = url
        self.rest = f"{url}/rest/v1"
        self.storage = f"{url}/storage/v1"
        headers = {"apikey": key}
        if not key.startswith("sb_"):
            headers["Authorization"] = f"Bearer {key}"
        if db_secret:
            headers["x-nk-server-secret"] = db_secret
        self._headers = headers
        self._local = threading.local()

    def _session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update(self._headers)
            self._local.session = s
        return s

    # ---- low level -------------------------------------------------------
    def _call(self, method: str, url: str, *, params=None, body=None, headers=None, raw=None,
              timeout: float = 20) -> requests.Response:
        h = {"Content-Type": "application/json"}
        if headers:
            h.update(headers)
        data = raw if raw is not None else (json.dumps(body, default=str) if body is not None else None)
        try:
            r = self._session().request(method, url, params=params, data=data, headers=h, timeout=timeout)
        except requests.RequestException as exc:
            raise DBError(f"Database unreachable: {exc.__class__.__name__}") from exc
        if r.status_code >= 400:
            try:
                err = r.json()
                msg = err.get("message") or err.get("error") or r.text
                if err.get("details"):
                    msg += f" ({err['details']})"
            except ValueError:
                msg = r.text[:300]
            raise DBError(f"{r.status_code}: {msg}")
        return r

    # ---- tables ----------------------------------------------------------
    def select(self, table: str, params: dict | None = None, *, limit: int | None = None,
               offset: int | None = None, order: str | None = None, columns: str = "*") -> list[dict]:
        p = {"select": columns}
        if params:
            p.update(params)
        if order:
            p["order"] = order
        if limit is not None:
            p["limit"] = str(limit)
        if offset:
            p["offset"] = str(offset)
        return self._call("GET", f"{self.rest}/{table}", params=p).json()

    def select_count(self, table: str, params: dict | None = None, *, limit: int = 50,
                     offset: int = 0, order: str | None = None, columns: str = "*") -> tuple[list[dict], int]:
        p = {"select": columns, "limit": str(limit), "offset": str(offset)}
        if params:
            p.update(params)
        if order:
            p["order"] = order
        r = self._call("GET", f"{self.rest}/{table}", params=p, headers={"Prefer": "count=exact"})
        total = 0
        cr = r.headers.get("Content-Range", "")
        if "/" in cr:
            tail = cr.split("/")[-1]
            total = int(tail) if tail.isdigit() else 0
        return r.json(), total

    def one(self, table: str, params: dict, columns: str = "*") -> dict | None:
        rows = self.select(table, params, limit=1, columns=columns)
        return rows[0] if rows else None

    def insert(self, table: str, rows: dict | list[dict], *, on_conflict: str | None = None,
               ignore_duplicates: bool = False, returning: bool = True) -> list[dict]:
        prefer = ["return=representation" if returning else "return=minimal"]
        params = {}
        if on_conflict:
            params["on_conflict"] = on_conflict
            prefer.append("resolution=ignore-duplicates" if ignore_duplicates else "resolution=merge-duplicates")
        r = self._call("POST", f"{self.rest}/{table}", params=params, body=rows,
                       headers={"Prefer": ",".join(prefer)})
        return r.json() if returning and r.content else []

    def update(self, table: str, match: dict, values: dict) -> list[dict]:
        r = self._call("PATCH", f"{self.rest}/{table}", params=match, body=values,
                       headers={"Prefer": "return=representation"})
        return r.json() if r.content else []

    def delete(self, table: str, match: dict) -> None:
        if not match:
            raise DBError("Refusing unfiltered delete")
        self._call("DELETE", f"{self.rest}/{table}", params=match)

    def rpc(self, fn: str, args: dict | None = None) -> Any:
        r = self._call("POST", f"{self.rest}/rpc/{fn}", body=args or {})
        return r.json() if r.content else None

    # ---- storage ---------------------------------------------------------
    def upload(self, path: str, data: bytes, mime: str) -> str:
        url = f"{self.storage}/object/{config.STORAGE_BUCKET}/{quote(path)}"
        self._call("POST", url, raw=data, headers={"Content-Type": mime, "x-upsert": "true"}, timeout=120)
        return path

    def download(self, path: str) -> bytes:
        url = f"{self.storage}/object/{config.STORAGE_BUCKET}/{quote(path)}"
        return self._call("GET", url, timeout=120).content

    def ping(self) -> None:
        self.select("nk_users", limit=1, columns="id")


def in_list(values) -> str:
    """Build a PostgREST in.(...) filter with every value double-quoted."""
    out = []
    for v in values:
        s = str(v).replace("\\", "\\\\").replace('"', '\\"')
        out.append(f'"{s}"')
    return f"in.({','.join(out)})"


def ilike_term(term: str) -> str:
    """Sanitise free text for use inside a PostgREST or=() ilike filter."""
    cleaned = "".join(ch for ch in term if ch not in ',()*"\\:')
    return cleaned.strip()[:120]


_db: Supabase | None = None


def get_db() -> Supabase:
    global _db
    if _db is None:
        if config.config_problems():
            raise DBError("; ".join(config.config_problems()))
        _db = Supabase(config.SUPABASE_URL, config.SUPABASE_SERVICE_KEY, config.NK_DB_SECRET)
    return _db
