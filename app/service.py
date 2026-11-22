"""Case orchestration: run analysers, correlate with the intelligence store, persist to Supabase."""
from __future__ import annotations

import hashlib
import json
import mimetypes
import re
from datetime import datetime, timezone

from . import config
from .analysis import ai_intel
from .analysis import apk as apk_mod
from .analysis import iocs as ioc_mod
from .analysis import message as msg_mod
from .analysis import similarity
from .analysis import website as web_mod
from .analysis import urlscan
from .analysis.scoring import Findings
from .db import DBError, Supabase, in_list

KIND_LABEL = {"message": "Message", "url": "URL", "website": "Website", "apk": "Android app"}


def _apply_ai(kind: str, result: dict, *, text_hint: str, run_live: bool) -> dict:
    if not (run_live and config.GROQ_ENABLED):
        return result
    ai = ai_intel.analyze_forensics(
        kind,
        text=text_hint,
        findings=result["findings"],
        details=result.get("details", {}),
        iocs=result.get("iocs", []),
        category=result.get("category") or "",
    )
    if ai:
        result.setdefault("details", {})["ai"] = ai
        if not result.get("category") and ai.get("threat_category") and result["findings"].score >= 30:
            result["category"] = ai["threat_category"]
    return result


# ----------------------------------------------------------------------------- analysis
def analyse(kind: str, *, text: str = "", channel: str = "sms", sender: str = "", url: str = "",
            upload: tuple[str, bytes] | None = None, run_live: bool = True) -> dict:
    """Pure analysis, no persistence. Returns a dict with a Findings object under 'findings'."""
    if kind == "message":
        if not text.strip():
            raise ValueError("Paste the message text.")
        r = msg_mod.analyze(text, channel=channel, sender=sender, run_live=run_live)
        r["details"] = {"channel": channel, "sender": r["sender"], "brands": r["brands"],
                        "email_headers": r["email_headers"], "links": r["links"]}
        r["fingerprint_text"] = r["body"]
        r["evidence"] = [("Original message text", "message.txt", text.encode("utf-8"), "text/plain; charset=utf-8")]
        return _apply_ai(kind, r, text_hint=text, run_live=run_live)
    if kind == "url":
        if not url.strip():
            raise ValueError("Enter a URL.")
        if apk_mod.is_store_link(url):
            r = apk_mod.analyze_store_link(url, run_live=run_live)
            r["details"] = {"store": r["meta"]}
            r["evidence"] = []
            return _apply_ai("apk", r, text_hint=url, run_live=run_live)
        rep = urlscan.analyze(url, run_live=run_live)
        found = ioc_mod.extract(rep["url"], "submitted URL")
        if rep["net"].get("final_url"):
            found += ioc_mod.extract(rep["net"]["final_url"], "final landing URL")
        hosting = rep["net"].get("hosting") or {}
        if hosting.get("ip"):
            found.append({"etype": "ip", "value": hosting["ip"], "display": hosting["ip"],
                          "context": f"hosting · {hosting.get('org', '')} {hosting.get('country', '')}".strip()})
        body = rep["net"].pop("_body", b"")
        ev = [("Landing page snapshot (HTML)", "landing.html", body, "text/html")] if body else []
        r = {"findings": rep["findings"], "iocs": found, "category": _url_category(rep["findings"]),
             "details": {"url": rep["url"], "info": rep["info"], "net": rep["net"]}, "evidence": ev}
        return _apply_ai(kind, r, text_hint=url, run_live=run_live)
    if kind == "website":
        r = web_mod.analyze(url=url.strip() or None, upload=upload, run_live=run_live)
        r["details"] = {k: v for k, v in r.items() if k in ("source", "url_report", "page", "original_url", "fetch_note")}
        r["fingerprint_text"] = r.get("page", {}).get("excerpt", "")
        r["evidence"] = r.pop("_evidence", [])
        hint = url.strip() or r["fingerprint_text"] or (upload[0] if upload else "")
        return _apply_ai(kind, r, text_hint=hint, run_live=run_live)
    if kind == "apk":
        if upload:
            name, data = upload
            if len(data) > config.MAX_APK_BYTES:
                raise ValueError(f"APK larger than {config.MAX_APK_BYTES // 1048576} MB limit.")
            r = apk_mod.analyze_apk(name, data)
            r["details"] = {"apk": r["meta"]}
            r["evidence"] = [("Submitted APK", name, data, "application/vnd.android.package-archive")]
            return _apply_ai(kind, r, text_hint=name, run_live=run_live)
        if url.strip():
            r = apk_mod.analyze_store_link(url.strip(), run_live=run_live)
            r["details"] = {"store": r["meta"]}
            r["evidence"] = []
            return _apply_ai(kind, r, text_hint=url, run_live=run_live)
        raise ValueError("Upload an APK file or enter an app-store link.")
    raise ValueError("Unknown analysis type")


def _url_category(f: Findings) -> str:
    codes = {i.code.split(".final")[0] for i in f.items}
    if "url.apk_download" in codes or "net.serves_apk" in codes:
        return "Malicious APK distribution"
    if "domain.impersonation" in codes:
        return "Phishing / brand impersonation"
    return "Suspicious link" if f.score >= 30 else ""


# ----------------------------------------------------------------------------- correlation
def dedupe(items: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for it in items:
        if not it.get("value"):
            continue
        key = (it["etype"], it["value"])
        if key in seen:
            if it.get("context") and it["context"] not in seen[key]["context"]:
                seen[key]["context"] = (seen[key]["context"] + "; " + it["context"])[:300]
        else:
            seen[key] = dict(it)
    return list(seen.values())


def correlate(db: Supabase, f: Findings, items: list[dict], kind: str, fp_text: str, result: dict) -> dict:
    """Blocklist hits, identifiers already seen in other cases, and near-duplicate content."""
    intel: dict = {"blocklist": [], "linked": [], "similar": []}
    if not items:
        items = []
    values = sorted({i["value"] for i in items})

    # blocklist (feeds + confirmed cases)
    hosts = sorted({i["value"] for i in items if i["etype"] == "domain"})
    regs = sorted({urlscan.registrable(h) for h in hosts})
    lookup = sorted(set(values) | set(regs))
    for chunk in [lookup[i:i + 80] for i in range(0, len(lookup), 80)]:
        for row in db.select("nk_blocklist", {"value": in_list(chunk)}, limit=200):
            intel["blocklist"].append(row)
    for row in intel["blocklist"]:
        f.add("intel.blocklist", f"On blocklist: {row['value']}",
              f"Listed by {row['source']}" + (f" — {row['note']}" if row.get("note") else ""), 40, "intel", row["value"])
    if intel["blocklist"]:
        f.force_floor(75, "Identifier present on blocklist")

    # identifiers seen in earlier cases
    ents = []
    for chunk in [values[i:i + 80] for i in range(0, len(values), 80)]:
        ents += db.select("nk_entities", {"value": in_list(chunk), "case_count": "gt.0"}, limit=500)
    wanted = {(i["etype"], i["value"]) for i in items}
    ents = [e for e in ents if (e["etype"], e["value"]) in wanted]
    if ents:
        links = db.select("nk_case_entities", {"entity_id": in_list([e["id"] for e in ents])},
                          columns="entity_id,case_id,nk_cases(id,case_no,kind,risk_level,status,title,created_at)",
                          limit=500, order="created_at.desc")
        by_ent = {e["id"]: e for e in ents}
        for ln in links:
            c = ln.get("nk_cases")
            if not c:
                continue
            e = by_ent[ln["entity_id"]]
            intel["linked"].append({"etype": e["etype"], "value": e["value"], "display": e["display"],
                                    "case_id": c["id"], "case_no": c["case_no"], "kind": c["kind"],
                                    "risk_level": c["risk_level"], "status": c["status"], "title": c["title"]})
        confirmed = [l for l in intel["linked"] if l["status"] == "closed_fraud"]
        high = [l for l in intel["linked"] if l["risk_level"] == "HIGH" and l["status"] != "closed_benign"]
        other_kinds = sorted({l["kind"] for l in intel["linked"] if l["kind"] != kind})
        if confirmed:
            vals = sorted({l["display"] for l in confirmed})
            f.add("intel.confirmed_link", "Shares identifiers with confirmed fraud cases",
                  f"{', '.join(vals[:4])} appear in {len({l['case_no'] for l in confirmed})} case(s) closed as fraud: "
                  + ", ".join(sorted({l['case_no'] for l in confirmed})[:4]), 35, "correlation", vals[0])
            f.force_floor(65, "Linked to confirmed fraud case")
        elif high:
            vals = sorted({l["display"] for l in high})
            f.add("intel.high_link", "Shares identifiers with other high-risk reports",
                  f"{', '.join(vals[:4])} seen in " + ", ".join(sorted({l['case_no'] for l in high})[:4]), 15, "correlation",
                  vals[0])
        if other_kinds:
            f.add("intel.cross_channel", "Same identifier reused across channels",
                  "Also observed in " + ", ".join(KIND_LABEL[k].lower() + " cases" for k in other_kinds) +
                  ": indicates one operation running messages, sites and apps together.", 8, "correlation")

    # near-duplicate content
    sh = similarity.shingles(fp_text) if fp_text and len(fp_text) > 40 else []
    if sh:
        rows = db.select("nk_cases", {"kind": f"eq.{kind}", "shingles": "neq.{}"},
                         columns="id,case_no,risk_level,status,title,shingles", limit=2000, order="created_at.desc")
        scored = []
        for r in rows:
            j = similarity.jaccard(sh, r["shingles"])
            if j >= 0.45:
                scored.append({"case_id": r["id"], "case_no": r["case_no"], "similarity": round(j * 100),
                               "risk_level": r["risk_level"], "status": r["status"], "title": r["title"]})
        scored.sort(key=lambda x: -x["similarity"])
        intel["similar"] = scored[:8]
        if scored:
            top = scored[0]
            if any(s["status"] == "closed_fraud" for s in scored):
                fr = next(s for s in scored if s["status"] == "closed_fraud")
                f.add("intel.similar_fraud", "Content matches a confirmed scam template",
                      f"{fr['similarity']}% textual overlap with {fr['case_no']} (closed as fraud).", 25, "correlation",
                      fr["case_no"])
            else:
                f.add("intel.similar", f"Repeat content: {len(scored)} similar report(s)",
                      f"Closest: {top['case_no']} at {top['similarity']}% overlap. Same template, different identifiers.",
                      8 if top["risk_level"] == "HIGH" else 3, "correlation", top["case_no"])

    # APK comparison against known suspicious apps: icon, name, package family & certificate reuse
    if kind == "apk":
        meta = result.get("details", {}).get("apk") or result.get("details", {}).get("store") or {}
        cur_pkg = (meta.get("package") or "").strip()
        cur_label = (meta.get("label") or meta.get("title") or "").strip()
        cur_ih = meta.get("icon_ahash")
        cur_certs = {c.get("sha256") for c in meta.get("certificates", []) if c.get("sha256")}
        cur_toks = re.findall(r"[a-z0-9]+", cur_label.lower()) if cur_label and cur_label != cur_pkg else []
        cur_comp = "".join(cur_toks)
        parts_cur = cur_pkg.lower().split(".") if cur_pkg else []
        generic_prefixes = {"com.app", "com.android", "com.example", "org.example", "com.my", "in.co"}
        seen_sim = {s["case_no"] for s in intel["similar"]}

        def _add_sim(r: dict, pct: int, note: str) -> None:
            if r["case_no"] not in seen_sim:
                seen_sim.add(r["case_no"])
                intel["similar"].append({"case_id": r["id"], "case_no": r["case_no"], "similarity": pct,
                                         "risk_level": r["risk_level"], "status": r["status"],
                                         "title": f"{r['title']} ({note})"})

        rows = db.select("nk_cases", {"kind": "eq.apk"},
                         columns="id,case_no,risk_level,status,title,result", limit=500, order="created_at.desc")
        for r in rows:
            prev_det = (r.get("result") or {}).get("details") or {}
            prev_meta = prev_det.get("apk") or prev_det.get("store") or {}
            prev_pkg = (prev_meta.get("package") or "").strip()
            if cur_pkg and prev_pkg == cur_pkg:
                continue

            # 1. Icon visual hash match
            prev_ih = prev_meta.get("icon_ahash")
            if cur_ih and prev_ih:
                try:
                    d = apk_mod.hamming(cur_ih, prev_ih)
                    if d <= 5:
                        _add_sim(r, round((64 - d) / 64 * 100), f"icon match, {prev_pkg}")
                        f.add("intel.icon_reuse", "Launcher icon matches a different app",
                              f"Icon is visually identical to {r['case_no']} ({prev_pkg}): re-skinned clone.",
                              15, "correlation", r["case_no"])
                except ValueError:
                    pass

            # 2. Signing certificate reuse across different packages
            prev_certs = {c.get("sha256") for c in prev_meta.get("certificates", []) if c.get("sha256")}
            shared_certs = cur_certs & prev_certs
            if shared_certs:
                _add_sim(r, 95, f"same cert, {prev_pkg}")
                f.add("intel.cert_reuse", "Signed with the same certificate as a previously reported app",
                      f"Signing certificate {next(iter(shared_certs))[:16]}… also signed {r['case_no']} ({prev_pkg}).",
                      20, "correlation", r["case_no"])

            # 3 & 4. App name and package family comparison against suspicious prior APKs
            if r.get("status") != "closed_benign" and (r.get("risk_level") == "HIGH" or r.get("status") == "closed_fraud"):
                prev_label = (prev_meta.get("label") or prev_meta.get("title") or "").strip()
                prev_toks = re.findall(r"[a-z0-9]+", prev_label.lower()) if prev_label and prev_label != prev_pkg else []
                prev_comp = "".join(prev_toks)
                if cur_comp and prev_comp:
                    jac = (len(set(cur_toks) & set(prev_toks)) / len(set(cur_toks) | set(prev_toks))) \
                        if len(cur_toks) >= 2 and len(prev_toks) >= 2 else 0.0
                    exact_or_typo = cur_comp == prev_comp or (
                        min(len(cur_comp), len(prev_comp)) >= 6 and urlscan.levenshtein(cur_comp, prev_comp) <= 2)
                    if exact_or_typo or jac >= 0.75:
                        _add_sim(r, round(max(jac, 0.85 if exact_or_typo else 0.0) * 100), f"app name match, {prev_pkg}")
                        f.add("intel.app_name_clone", "App name matches a previously flagged suspicious app",
                              f"Name '{cur_label}' resembles {r['case_no']} ('{prev_label}' / {prev_pkg}).",
                              15, "correlation", r["case_no"])

                if cur_pkg and prev_pkg and not cur_pkg.startswith("ios:") and not prev_pkg.startswith("ios:"):
                    parts_prev = prev_pkg.lower().split(".")
                    same_prefix = len(parts_cur) >= 3 and len(parts_prev) >= 3 and parts_cur[:2] == parts_prev[:2] \
                        and ".".join(parts_cur[:2]) not in generic_prefixes
                    close_pkg = min(len(cur_pkg), len(prev_pkg)) >= 10 and \
                        urlscan.levenshtein(cur_pkg.lower(), prev_pkg.lower()) <= 3
                    if same_prefix or close_pkg:
                        _add_sim(r, 85, f"package family, {prev_pkg}")
                        f.add("intel.package_family", "Package identifier resembles a flagged app family",
                              f"Package {cur_pkg} closely matches {r['case_no']} ({prev_pkg}).",
                              15, "correlation", r["case_no"])
    return intel


# ----------------------------------------------------------------------------- persistence
def _evidence_local(case_id: int, name: str, data: bytes) -> str:
    folder = config.EVIDENCE_DIR / str(case_id)
    folder.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[-80:] or "file.bin"
    path = folder / safe
    path.write_bytes(data)
    return str(path.relative_to(config.DATA_DIR))


def store_evidence(db: Supabase, case_id: int, label: str, name: str, data: bytes, mime: str) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    try:
        _evidence_local(case_id, f"{sha[:12]}_{name}", data)
    except OSError:
        pass
    storage_path = ""
    try:
        storage_path = db.upload(f"case-{case_id}/{sha[:12]}_{re.sub(r'[^A-Za-z0-9._-]', '_', name)[-80:]}", data,
                                 mime.split(";")[0] or "application/octet-stream")
    except DBError:
        storage_path = ""
    row = db.insert("nk_evidence", {"case_id": case_id, "label": label, "filename": name, "mime": mime,
                                    "size_bytes": len(data), "sha256": sha, "storage_path": storage_path})
    return row[0] if row else {}


def build_title(kind: str, payload_text: str, result: dict) -> str:
    if kind == "apk":
        if "apk" in result["details"]:
            m = result["details"]["apk"]
            return f"{m.get('label') or m.get('package')} ({m.get('package')})"[:160]
        s = result["details"].get("store", {})
        return f"App store: {s.get('title') or s.get('package', payload_text)}"[:160]
    if kind == "url" and "store" in result["details"]:
        s = result["details"]["store"]
        return f"Play Store: {s.get('title') or s['package']}"[:160]
    if kind in ("url", "website"):
        page = result["details"].get("page", {})
        u = result["details"].get("url") or (result["details"].get("url_report") or {}).get("url") or payload_text
        t = page.get("title")
        return (f"{u} — {t}" if t else u)[:160]
    first = re.sub(r"\s+", " ", payload_text).strip()
    return (first[:110] + "…") if len(first) > 110 else first or "Message"


def create_case(db: Supabase, kind: str, result: dict, *, input_text: str, source: str, user: dict | None,
                reporter_name: str = "", reporter_contact: str = "", channel: str = "") -> dict:
    f: Findings = result["findings"]
    items = dedupe(result.get("iocs", []))
    fp_text = result.get("fingerprint_text", "")
    intel = correlate(db, f, items, kind, fp_text, result)

    payload = {
        "score": f.score, "level": f.level, "floor_reason": f.floor_reason,
        "indicators": f.to_list(), "details": result.get("details", {}),
        "intel": intel, "identifiers": items,
        "engine": {"live_checks": config.LIVE_CHECKS, "gsb": bool(config.GSB_API_KEY),
                   "groq_ai": bool(result.get("details", {}).get("ai")),
                   "groq_model": (result.get("details", {}).get("ai") or {}).get("model", ""),
                   "analysed_at": datetime.now(timezone.utc).isoformat()},
    }
    payload = json.loads(json.dumps(payload, default=str))
    content_sha = hashlib.sha256((input_text or "").encode("utf-8")).hexdigest()
    for _label, _name, data, _mime in result.get("evidence", []):
        if _name.endswith(".apk") or kind == "apk":
            content_sha = hashlib.sha256(data).hexdigest()
            break
    row = db.insert("nk_cases", {
        "kind": kind, "title": build_title(kind, input_text, result), "source": source,
        "submitted_by": user["id"] if user else None, "reporter_name": reporter_name[:120],
        "reporter_contact": reporter_contact[:120], "channel": channel[:40], "input_text": input_text[:20000],
        "risk_score": f.score, "risk_level": f.level, "category": result.get("category") or "",
        "result": payload, "shingles": similarity.shingles(fp_text) if fp_text and len(fp_text) > 40 else [],
        "content_sha256": content_sha,
    })[0]
    if items:
        db.rpc("nk_link_entities", {"p_case_id": row["id"], "p_items": items})
    for label, name, data, mime in result.get("evidence", []):
        if data:
            store_evidence(db, row["id"], label, name, data, mime or mimetypes.guess_type(name)[0] or "application/octet-stream")
    return row


def confirm_fraud(db: Supabase, case: dict, user: dict) -> int:
    """Closing a case as fraud promotes its high-value identifiers to the blocklist."""
    keep = {"domain", "url", "phone", "upi", "bank_account", "crypto", "apk_package", "apk_cert", "apk_sha256",
            "telegram", "whatsapp_group", "email", "ip"}
    rows = []
    for it in case["result"].get("identifiers", []):
        if it["etype"] not in keep:
            continue
        if it["etype"] in ("domain", "url"):
            host = it["value"] if it["etype"] == "domain" else ioc_mod.host_of(it["value"])
            if urlscan.is_official(host) or urlscan.registrable(host) in _shared_hosts():
                continue
        if it["etype"] == "phone" and it["value"].startswith("1800"):
            continue
        if it["etype"] == "apk_package" and it["value"] in apk_mod.legit_packages():
            continue
        rows.append({"etype": it["etype"], "value": it["value"], "source": f"Confirmed fraud {case['case_no']}",
                     "note": it.get("context", "")[:200], "added_by": user["username"]})
    if rows:
        db.insert("nk_blocklist", rows, on_conflict="etype,value", ignore_duplicates=True, returning=False)
    return len(rows)


def _shared_hosts() -> set[str]:
    from .analysis.brands import FREE_HOSTING, SHORTENERS
    return FREE_HOSTING | SHORTENERS | {"google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
                                        "t.me", "wa.me", "telegram.org", "github.com", "amazonaws.com"}
