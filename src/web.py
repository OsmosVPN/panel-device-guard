"""Web interface for device-guard."""

from __future__ import annotations

import asyncio
import hmac
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .config import Config
from .note_marker import extract_guard_meta, remove_guard_marker
from .node_kick import collect_ips_by_node, kick_ips
from .panel_api import PanelClient
from .webhook import fire_webhook

if TYPE_CHECKING:
    from .guard import DeviceGuard

logger = logging.getLogger("panel_device_guard.web")


def create_app(cfg: Config, guard: "DeviceGuard") -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=cfg.web_secret_key,
        session_cookie="dguard_session",
        same_site="strict",
        https_only=False,
    )

    import os
    tmpl = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

    # Separate API client so its requests.Session doesn't race with the guard's client.
    web_api = PanelClient(cfg)

    # ------------------------------------------------------------------ #
    # Auth helpers                                                         #
    # ------------------------------------------------------------------ #

    def _authed(request: Request) -> bool:
        return bool(request.session.get("authenticated"))

    def _redirect_login() -> RedirectResponse:
        return RedirectResponse("/login", status_code=302)

    # ------------------------------------------------------------------ #
    # Routes                                                               #
    # ------------------------------------------------------------------ #

    @app.get("/", include_in_schema=False)
    async def root(request: Request):
        return RedirectResponse("/active" if _authed(request) else "/login", status_code=302)

    @app.get("/login", response_class=HTMLResponse)
    async def login_get(request: Request):
        if _authed(request):
            return RedirectResponse("/active", status_code=302)
        return tmpl.TemplateResponse("login.html", {"request": request, "error": None})

    @app.post("/login", response_class=HTMLResponse)
    async def login_post(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ):
        if _verify_credentials(username, password, cfg):
            request.session["authenticated"] = True
            return RedirectResponse("/active", status_code=303)
        return tmpl.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверный логин или пароль"},
            status_code=401,
        )

    @app.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", status_code=302)

    @app.get("/active", response_class=HTMLResponse)
    async def dashboard(request: Request):
        if not _authed(request):
            return _redirect_login()
        try:
            active, banned = await _fetch_user_data(guard, web_api)
        except Exception as exc:
            logger.error("dashboard fetch error: %s", exc)
            return tmpl.TemplateResponse("active.html", {
                "request": request,
                "active_users": [],
                "banned_users": [],
                "fetch_error": str(exc),
            })
        return tmpl.TemplateResponse("active.html", {
            "request": request,
            "active_users": active,
            "banned_users": banned,
        })

    @app.get("/nodes", response_class=HTMLResponse)
    async def nodes_page(request: Request):
        if not _authed(request):
            return _redirect_login()
        nodes = dict(guard.node_names)
        addresses = dict(guard.node_addresses)
        return tmpl.TemplateResponse("nodes.html", {
            "request": request,
            "nodes": nodes,
            "addresses": addresses,
        })

    # HTMX partial: replaces only the tables on auto-refresh
    @app.get("/users-partial", response_class=HTMLResponse)
    async def users_partial(request: Request):
        if not _authed(request):
            return HTMLResponse("", status_code=401)
        try:
            active, banned = await _fetch_user_data(guard, web_api)
        except Exception as exc:
            logger.error("users-partial fetch error: %s", exc)
            return HTMLResponse(
                f'<div class="alert alert-warning m-3">Ошибка связи с панелью: {exc}</div>',
                status_code=200,
            )
        return tmpl.TemplateResponse("_users_table.html", {
            "request": request,
            "active_users": active,
        })

    @app.get("/banned", response_class=HTMLResponse)
    async def banned_page(request: Request):
        if not _authed(request):
            return _redirect_login()
        try:
            active, banned = await _fetch_user_data(guard, web_api)
        except Exception as exc:
            logger.error("banned fetch error: %s", exc)
            return tmpl.TemplateResponse("banned.html", {
                "request": request,
                "banned_users": [],
                "fetch_error": str(exc),
            })
        return tmpl.TemplateResponse("banned.html", {
            "request": request,
            "banned_users": banned,
        })

    @app.get("/banned-partial", response_class=HTMLResponse)
    async def banned_partial(request: Request):
        if not _authed(request):
            return HTMLResponse("", status_code=401)
        try:
            active, banned = await _fetch_user_data(guard, web_api)
        except Exception as exc:
            logger.error("banned-partial fetch error: %s", exc)
            return HTMLResponse(
                f'<div class="alert alert-warning m-3">Ошибка связи с панелью: {exc}</div>',
                status_code=200,
            )
        return tmpl.TemplateResponse("_banned_table.html", {
            "request": request,
            "banned_users": banned,
        })

    @app.get("/user/{username}", response_class=HTMLResponse)
    async def user_detail(request: Request, username: str):
        if not _authed(request):
            return _redirect_login()
        try:
            info = await _fetch_one_user(guard, web_api, username)
        except Exception as exc:
            logger.error("user_detail fetch error user=%s: %s", username, exc)
            return HTMLResponse(
                f'<div class="alert alert-warning m-3">Ошибка связи с панелью: {exc}</div>',
                status_code=200,
            )
        return tmpl.TemplateResponse("user_detail.html", {
            "request": request,
            "user": info,
        })

    @app.get("/user/{username}/partial", response_class=HTMLResponse)
    async def user_detail_partial(request: Request, username: str):
        if not _authed(request):
            return HTMLResponse("", status_code=401)
        try:
            info = await _fetch_one_user(guard, web_api, username)
        except Exception as exc:
            logger.error("user_detail_partial fetch error user=%s: %s", username, exc)
            return HTMLResponse(
                f'<div class="alert alert-warning m-3">Ошибка связи с панелью: {exc}</div>',
                status_code=200,
            )
        return tmpl.TemplateResponse("_user_detail_partial.html", {
            "request": request,
            "user": info,
        })

    @app.post("/user/{username}/ban")
    async def ban_user(request: Request, username: str):
        if not _authed(request):
            return _redirect_login()
        await _do_ban(cfg, guard, web_api, username)
        return RedirectResponse(f"/user/{username}", status_code=303)

    @app.post("/user/{username}/unban")
    async def unban_user(request: Request, username: str):
        if not _authed(request):
            return _redirect_login()
        await _do_unban(cfg, guard, web_api, username)
        return RedirectResponse(f"/user/{username}", status_code=303)

    @app.get("/logs/{node_id}", response_class=HTMLResponse)
    async def log_node_page(request: Request, node_id: int):
        if not _authed(request):
            return _redirect_login()
        lines = list(guard.node_logs.get(node_id, []))
        node_name = guard.node_names.get(node_id, f"Node #{node_id}")
        return tmpl.TemplateResponse("log_node.html", {
            "request": request,
            "node_id": node_id,
            "node_name": node_name,
            "lines": lines,
        })

    @app.get("/logs/{node_id}/partial", response_class=HTMLResponse)
    async def log_node_partial(request: Request, node_id: int):
        if not _authed(request):
            return HTMLResponse("", status_code=401)
        lines = list(guard.node_logs.get(node_id, []))
        node_name = guard.node_names.get(node_id, f"Node #{node_id}")
        return tmpl.TemplateResponse("_log_node_partial.html", {
            "request": request,
            "node_id": node_id,
            "node_name": node_name,
            "lines": lines,
        })

    return app


# ------------------------------------------------------------------ #
# Auth                                                                #
# ------------------------------------------------------------------ #

def _verify_credentials(username: str, password: str, cfg: Config) -> bool:
    # Constant-time comparison to avoid timing attacks.
    ok_user = hmac.compare_digest(username.encode(), cfg.web_username.encode())
    ok_pass = hmac.compare_digest(password.encode(), cfg.web_password.encode())
    return ok_user and ok_pass


# ------------------------------------------------------------------ #
# Data fetching                                                        #
# ------------------------------------------------------------------ #

async def _fetch_user_data(guard: "DeviceGuard", api: PanelClient):
    """Return (active_users, banned_users) lists.

    Active users = status active AND have at least one IP in the active window.
    Banned users  = status disabled AND have a guard marker in their note.
    """
    users = await asyncio.to_thread(api.list_all_users)
    now_ts = time.time()
    now_dt = datetime.now(timezone.utc)

    # Snapshot in-memory IP state and violation counts under the lock.
    ip_snapshot: dict[str, list[str]] = {}
    violation_snapshot: dict[str, int] = {}
    async with guard._state_lock:
        for uname in list(guard.last_seen):
            guard._prune_ips(uname, now_ts)
        for uname, recs in guard.last_seen.items():
            ip_snapshot[uname] = list(recs.keys())
        violation_snapshot = dict(guard.violation_count)

    active: list[dict] = []
    banned: list[dict] = []

    for user in users:
        uname = user.get("username")
        if not uname:
            continue
        status = user.get("status", "")
        note = user.get("note")
        meta = extract_guard_meta(note, guard.cfg.note_marker_prefix)

        if meta and status == "disabled":
            try:
                until_dt = datetime.fromisoformat(meta["until"])
            except (KeyError, ValueError):
                until_dt = None
            banned.append({
                "username": uname,
                "until": until_dt,
                "until_expired": until_dt is not None and until_dt <= now_dt,
                "device_limit": user.get("device_limit"),
                "trigger": meta.get("trigger", "auto"),
            })
        elif status == "active":
            ips = ip_snapshot.get(uname, [])
            if ips:
                active.append({
                    "username": uname,
                    "device_limit": user.get("device_limit"),
                    "ip_count": len(ips),
                    "violations": violation_snapshot.get(uname, 0),
                })

    active.sort(key=lambda u: -u["ip_count"])
    return active, banned


async def _fetch_one_user(guard: "DeviceGuard", api: PanelClient, username: str) -> dict:
    user = await asyncio.to_thread(api.get_user, username)
    now_ts = time.time()
    now_dt = datetime.now(timezone.utc)
    status = user.get("status", "")
    note = user.get("note")
    meta = extract_guard_meta(note, guard.cfg.note_marker_prefix)

    async with guard._state_lock:
        guard._prune_ips(username, now_ts)
        ip_records = dict(guard.last_seen.get(username, {}))
        violations = guard.violation_count.get(username, 0)
    node_names = dict(guard.node_names)

    # Build list of (ip, node_name) sorted by ip
    ip_entries = sorted(
        [
            {
                "ip": ip,
                "node_name": node_names.get(int(rec["node_id"])) if rec.get("node_id") is not None else None,
            }
            for ip, rec in ip_records.items()
        ],
        key=lambda e: e["ip"],
    )

    until_dt: datetime | None = None
    if meta and "until" in meta:
        try:
            until_dt = datetime.fromisoformat(meta["until"])
        except ValueError:
            pass

    return {
        "username": username,
        "status": status,
        "device_limit": user.get("device_limit"),
        "ips": [e["ip"] for e in ip_entries],
        "ip_entries": ip_entries,
        "is_banned": bool(meta and status == "disabled"),
        "until": until_dt,
        "until_expired": until_dt is not None and until_dt <= now_dt,
        "trigger": meta.get("trigger", "auto") if meta else None,
        "violations": violations,
    }


# ------------------------------------------------------------------ #
# Mutations (ban / unban)                                             #
# ------------------------------------------------------------------ #

async def _do_ban(cfg: Config, guard: "DeviceGuard", api: PanelClient, username: str) -> None:
    user = await asyncio.to_thread(api.get_user, username)
    prev_status = user.get("status", "active")
    note = user.get("note")
    now_dt = datetime.now(timezone.utc)
    until_iso = (now_dt + timedelta(seconds=cfg.manual_block_ttl_seconds)).isoformat()
    clean_note = remove_guard_marker(note, cfg.note_marker_prefix)
    marker = f"{cfg.note_marker_prefix} until={until_iso} prev={prev_status} trigger=manual"
    new_note = (f"{clean_note}\n{marker}" if clean_note else marker)[:500]
    payload = {"status": "disabled", "note": new_note}
    ips_by_node = collect_ips_by_node(guard.last_seen, username)
    async with guard._state_lock:
        await asyncio.to_thread(api.modify_user, username, payload)
        guard._clear_user_state(username)
    logger.info("web manual ban user=%s until=%s", username, until_iso)
    guard.fire_ban_side_effects(username, ips_by_node, trigger="manual")


async def _do_unban(cfg: Config, guard: "DeviceGuard", api: PanelClient, username: str) -> None:
    user = await asyncio.to_thread(api.get_user, username)
    note = user.get("note")
    meta = extract_guard_meta(note, cfg.note_marker_prefix)
    prev = (meta.get("prev", "active") if meta else "active")
    restore_status = prev if prev in {"active", "disabled"} else "active"
    payload = {
        "status": restore_status,
        "note": remove_guard_marker(note, cfg.note_marker_prefix),
    }
    async with guard._state_lock:
        await asyncio.to_thread(api.modify_user, username, payload)
        guard._clear_user_state(username)
    logger.info("web manual unban user=%s -> status=%s", username, restore_status)
    guard.fire_unban_side_effects(username, trigger="manual")
