"""Webhook notifications."""

import hashlib
import hmac
import json
import logging
import ssl
import time
from typing import Any

import aiohttp

logger = logging.getLogger("panel_device_guard")


async def fire_webhook(url: str, secret: str | None, payload: dict[str, Any]) -> None:
    payload = {"timestamp": int(time.time()), **payload}
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if secret:
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Signature"] = f"sha256={sig}"
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=ssl_ctx),
        ) as session:
            async with session.post(url, data=body, headers=headers) as resp:
                if resp.status >= 400:
                    logger.warning("webhook action=%s user=%s status=%s",
                                   payload.get("action"), payload.get("username"), resp.status)
                else:
                    logger.info("webhook action=%s user=%s status=%s",
                                payload.get("action"), payload.get("username"), resp.status)
    except Exception as exc:
        logger.warning("webhook failed action=%s user=%s: %r",
                       payload.get("action"), payload.get("username"), exc)
