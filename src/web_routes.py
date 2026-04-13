from aiohttp import web


def register_routes(app: web.Application, ui) -> None:
    app.router.add_get("/healthz", ui.healthz)
    app.router.add_get("/login", ui.login_page)
    app.router.add_post("/login", ui.login_submit)
    app.router.add_get("/logout", ui.logout)
    app.router.add_get("/", ui.index)
    app.router.add_get("/api/users", ui.api_users)
    app.router.add_get("/api/logs", ui.api_logs)
    app.router.add_post("/api/ban", ui.api_ban)
    app.router.add_post("/api/unban", ui.api_unban)
