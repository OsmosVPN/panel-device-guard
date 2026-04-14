"""Node-agent IP kick helpers."""

import asyncio
import json
import logging
from collections import defaultdict
from typing import Any

import aiohttp

from .config import Config

logger = logging.getLogger("panel_device_guard")

IpRecord = dict[str, Any]


def collect_ips_by_node(
    last_seen: dict[str, dict[str, IpRecord]], username: str
) -> dict[int, list[str]]:
    """Snapshot IP→node mapping synchronously before user state is cleared."""
    result: dict[int, list[str]] = defaultdict(list)
    for ip, rec in last_seen.get(username, {}).items():
        if (nid := rec.get("node_id")) is not None:
            result[nid].append(ip)
    return dict(result)


async def _kick_node(address: str, port: int, token: str | None, ips: list[str]) -> None:
    url = f"http://{address}:{port}/kick"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps({"ips": ips}).encode()
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.post(url, data=body, headers=headers) as resp:
                logger.info("kick node=%s ips=%s status=%s", address, ips, resp.status)
    except Exception as exc:
        logger.warning("kick failed node=%s: %r", address, exc)


async def kick_ips(
    cfg: Config,
    node_addresses: dict[int, str],
    ips_by_node: dict[int, list[str]],
) -> None:
    if not cfg.node_kick_enabled or not ips_by_node:
        return
    tasks = [
        _kick_node(addr, cfg.node_kick_port, cfg.node_kick_token, ips)
        for nid, ips in ips_by_node.items()
        if (addr := node_addresses.get(nid))
    ]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
