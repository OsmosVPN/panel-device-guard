"""WebSocket log monitor for panel nodes."""

import asyncio
import logging
import socket
import ssl
from collections.abc import Callable
from typing import Any

import aiohttp

from .config import Config
from .panel_api import PanelClient

logger = logging.getLogger("panel_device_guard")
_WS_USER_AGENT = "PANEL-DEVICE-GUARD"


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def monitor_node(
    node_id: int,
    cfg: Config,
    api: PanelClient,
    on_line: Callable[[int, str], None],
) -> None:
    """Continuously stream logs from a node and call on_line(node_id, line) for each."""
    base = cfg.panel_base_url.rstrip("/")
    ws_scheme = "wss" if base.startswith("https://") else "ws"
    ws_base = f"{ws_scheme}://{base.split('://', 1)[1]}"
    ssl_ctx = _make_ssl_context() if ws_scheme == "wss" else None
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=20, sock_read=None)
    connect_kwargs: dict[str, Any] = {
        "heartbeat": 20,
        "compress": 0,
        "headers": {
            "User-Agent": _WS_USER_AGENT,
            "Origin": cfg.panel_base_url,
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    }

    while True:
        ws_url: str | None = None
        try:
            await asyncio.to_thread(api.login)
            interval = cfg.node_logs_interval
            interval_param = str(int(interval)) if float(interval).is_integer() else str(interval)
            ws_url = f"{ws_base}/api/node/{node_id}/logs?interval={interval_param}&token={api._token}"

            logger.info("connect ws node_id=%s", node_id)
            last_exc: Exception | None = None
            for attempt, family in (("default", socket.AF_UNSPEC), ("ipv4", socket.AF_INET)):
                try:
                    connector = aiohttp.TCPConnector(
                        family=family, ssl=ssl_ctx if ssl_ctx is not None else False
                    )
                    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                        async with session.ws_connect(ws_url, **connect_kwargs) as ws:
                            async for msg in ws:
                                if msg.type == aiohttp.WSMsgType.TEXT:
                                    for line in str(msg.data).splitlines():
                                        on_line(node_id, line)
                                elif msg.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED}:
                                    break
                                elif msg.type == aiohttp.WSMsgType.ERROR:
                                    raise RuntimeError(f"ws error: {ws.exception()}")
                    last_exc = None
                    break
                except Exception as exc:
                    last_exc = exc
                    logger.warning("ws node_id=%s attempt=%s failed: %r", node_id, attempt, exc)

            if last_exc is not None:
                raise last_exc

        except Exception as exc:
            safe_url = ws_url
            if safe_url and "token=" in safe_url:
                safe_url = safe_url.split("token=", 1)[0] + "token=***"
            logger.error("ws node_id=%s %s url=%s", node_id, exc, safe_url)
            await asyncio.sleep(3)
