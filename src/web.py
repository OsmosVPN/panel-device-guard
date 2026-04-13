import asyncio
import secrets
from pathlib import Path

from aiohttp import web
from jinja2 import Environment, FileSystemLoader

from .config import Config
from .guard import DeviceGuard
from .web_routes import register_routes


class WebUI:
    def __init__(self, cfg: Config, guard: DeviceGuard):
        self.cfg = cfg
        self.guard = guard
        self.sessions: set[str] = set()
        templates_dir = Path(__file__).parent.parent / "templates"
        self.jinja = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)

    def is_authenticated(self, request: web.Request) -> bool:
        sid = request.cookies.get("dg_session")
        return bool(sid and sid in self.sessions)

    @web.middleware
    async def auth_middleware(self, request: web.Request, handler):
        if request.path in {"/login", "/healthz"}:
            return await handler(request)
        if not self.is_authenticated(request):
            raise web.HTTPFound("/login")
        return await handler(request)

    async def healthz(self, request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    async def login_page(self, request: web.Request) -> web.Response:
        error = request.query.get("error", "")
        html = self.jinja.get_template("login.html").render(error=error)
        return web.Response(text=html, content_type="text/html")

    async def login_submit(self, request: web.Request) -> web.Response:
        form = await request.post()
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", "")).strip()

        if username != self.cfg.web_username or password != self.cfg.web_password:
            raise web.HTTPFound("/login?error=Invalid+username+or+password")

        sid = secrets.token_urlsafe(24)
        self.sessions.add(sid)
        resp = web.HTTPFound("/")
        resp.set_cookie("dg_session", sid, httponly=True, samesite="Lax")
        return resp

    async def logout(self, request: web.Request) -> web.Response:
        sid = request.cookies.get("dg_session")
        if sid:
            self.sessions.discard(sid)
        resp = web.HTTPFound("/login")
        resp.del_cookie("dg_session")
        return resp

    async def index(self, request: web.Request) -> web.Response:
        tab = request.query.get("tab", "active")
        snapshot = await self.guard.snapshot_users()
        active = snapshot.get("active", [])
        banned = snapshot.get("banned", [])

        if tab == "banned":
            html = self.jinja.get_template("banned.html").render(
                tab=tab, users=banned, dry_run=self.cfg.dry_run
            )
        elif tab == "info":
            config_items = [
                ("PANEL_BASE_URL", self.cfg.panel_base_url),
                ("EXTRA_DEVICES", self.cfg.extra_devices),
                ("ACTIVE_WINDOW_SECONDS", self.cfg.active_window_seconds),
                ("VIOLATION_THRESHOLD", self.cfg.violation_threshold),
                ("BLOCK_TTL_SECONDS", self.cfg.block_ttl_seconds),
                ("CHECK_INTERVAL_SECONDS", self.cfg.check_interval_seconds),
                ("DRY_RUN", self.cfg.dry_run),
                ("WEB_HOST", self.cfg.web_host),
                ("WEB_PORT", self.cfg.web_port),
            ]
            stats = {
                "active_users": len(active),
                "banned_users": len(banned),
                "whitelisted_users": sum(1 for u in active if u.get("whitelisted")),
            }
            html = self.jinja.get_template("info.html").render(
                tab=tab,
                config_items=config_items,
                sensitive_keys={},
                stats=stats,
                dry_run=self.cfg.dry_run,
            )
        elif tab == "logs":
            logs_by_node = self.guard.snapshot_logs()
            html = self.jinja.get_template("logs.html").render(
                tab=tab, logs_by_node=logs_by_node,
                dry_run=self.cfg.dry_run,
                max_lines=self.guard._node_logs_maxlen,
            )
        else:
            tab = "active"
            html = self.jinja.get_template("active.html").render(
                tab=tab, users=active, dry_run=self.cfg.dry_run
            )

        return web.Response(text=html, content_type="text/html")

    async def api_logs(self, request: web.Request) -> web.Response:
        logs_by_node = self.guard.snapshot_logs()
        return web.json_response({str(k): v for k, v in logs_by_node.items()})

    async def api_users(self, request: web.Request) -> web.Response:
        snapshot = await self.guard.snapshot_users()
        return web.json_response({
            "active": snapshot.get("active", []),
            "banned": snapshot.get("banned", []),
            "dry_run": self.cfg.dry_run,
            "node_names": {str(k): v for k, v in self.guard.node_names.items()},
        })

    async def api_ban(self, request: web.Request) -> web.Response:
        data = await request.json()
        username = str(data.get("username", "")).strip()
        ttl_raw = data.get("ttl_seconds")
        ttl_seconds = None
        if ttl_raw not in (None, ""):
            try:
                ttl_seconds = int(ttl_raw)
            except Exception:
                return web.json_response({"error": "ttl_seconds must be integer"}, status=400)

        if not username:
            return web.json_response({"error": "username is required"}, status=400)
        try:
            await self.guard.manual_ban(username, ttl_seconds=ttl_seconds)
        except ValueError as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response({"ok": True})

    async def api_unban(self, request: web.Request) -> web.Response:
        data = await request.json()
        username = str(data.get("username", "")).strip()
        if not username:
            return web.json_response({"error": "username is required"}, status=400)
        await self.guard.manual_unban(username)
        return web.json_response({"ok": True})

    def build_app(self) -> web.Application:
        app = web.Application(middlewares=[self.auth_middleware])
        register_routes(app, self)
        return app

    async def run(self) -> None:
        app = self.build_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host=self.cfg.web_host, port=self.cfg.web_port)
        await site.start()
        while True:
            await asyncio.sleep(3600)
