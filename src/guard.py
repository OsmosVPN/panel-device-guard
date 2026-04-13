import asyncio
import hashlib
import hmac
import json
import logging
import socket
import ssl
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp

from .config import Config
from .log_parser import parse_log_line, parse_log_line_with_node
from .panel_api import PanelClient

logger = logging.getLogger("device_guard")
WS_USER_AGENT = "DEVICE-GUARD"


class DeviceGuard:
    def __init__(self, cfg: Config, api: PanelClient):
        self.cfg = cfg
        self.api = api
        self.last_seen: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        # username -> ip -> {"last_seen": float, "configs": set[str], "node_id": int}
        self.violation_count: dict[str, int] = defaultdict(int)
        self.user_cache: dict[str, dict[str, Any]] = {}
        self.current_node_id: int | None = None
        self.node_logs: dict[int, list[dict[str, str]]] = defaultdict(lambda: [])
        self._node_logs_maxlen = 500
        self.node_names: dict[int, str] = {}  # node_id -> display name from API
        self.node_names: dict[int, str] = {}  # node_id -> display name from API

    async def _fire_webhook(self, payload: dict[str, Any]) -> None:
        if not self.cfg.webhook_url:
            return
        url = self.cfg.webhook_url
        payload = {"timestamp": int(time.time()), **payload}
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.cfg.webhook_secret:
            sig = hmac.new(self.cfg.webhook_secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-Signature"] = f"sha256={sig}"
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.post(url, data=body, headers=headers) as resp:
                    logger.info("webhook action=%s user=%s status=%s", payload.get("action"), payload.get("username"), resp.status)
        except Exception as exc:
            logger.warning("webhook failed action=%s user=%s: %r", payload.get("action"), payload.get("username"), exc)

    def normalize_username(self, email_value: str) -> str | None:
        match = self.cfg.email_to_username_regex.match(email_value.strip())
        if not match:
            return None
        if "username" in match.groupdict():
            return match.group("username")
        return match.group(0)

    def ingest_log_line(self, line: str) -> None:
        parsed = parse_log_line(line)
        if not parsed:
            return
        ip, email = parsed
        ip = ip.lower()

        if ip in self.cfg.whitelist_ips:
            return

        username = self.normalize_username(email)
        if not username or username in self.cfg.whitelist_usernames:
            return

        record = self.last_seen[username].get(ip)
        now = time.time()
        if record is None:
            record = {"last_seen": now, "configs": set(), "node_id": self.current_node_id}
            self.last_seen[username][ip] = record
        record["last_seen"] = now
        record["configs"].add(email)
        if self.current_node_id is not None:
            record["node_id"] = self.current_node_id

    def active_ip_count(self, username: str, now_ts: float) -> int:
        ips = self.last_seen.get(username)
        if not ips:
            return 0
        cutoff = now_ts - self.cfg.active_window_seconds
        stale = [ip for ip, rec in ips.items() if float(rec.get("last_seen", 0)) < cutoff]
        for ip in stale:
            ips.pop(ip, None)
        if not ips:
            self.last_seen.pop(username, None)
            return 0
        return len(ips)

    def _prune_user_ips(self, username: str, now_ts: float) -> None:
        ips = self.last_seen.get(username)
        if not ips:
            return
        cutoff = now_ts - self.cfg.active_window_seconds
        stale = [ip for ip, rec in ips.items() if float(rec.get("last_seen", 0)) < cutoff]
        for ip in stale:
            ips.pop(ip, None)
        if not ips:
            self.last_seen.pop(username, None)

    def _extract_guard_meta(self, note: str | None) -> dict[str, str] | None:
        if not note:
            return None
        for part in note.splitlines():
            part = part.strip()
            if not part.startswith(self.cfg.note_marker_prefix):
                continue
            chunks = part.split()
            out: dict[str, str] = {}
            for chunk in chunks[1:]:
                if "=" in chunk:
                    k, v = chunk.split("=", 1)
                    out[k] = v
            if "until" in out:
                return out
        return None

    def _remove_guard_marker(self, note: str | None) -> str | None:
        if not note:
            return note
        lines = [ln for ln in note.splitlines() if not ln.strip().startswith(self.cfg.note_marker_prefix)]
        merged = "\n".join(lines).strip()
        return merged or None

    def _append_guard_marker(self, note: str | None, until_iso: str, prev_status: str) -> str:
        clean = self._remove_guard_marker(note)
        marker = f"{self.cfg.note_marker_prefix} until={until_iso} prev={prev_status}"
        if clean:
            return f"{clean}\n{marker}"[:500]
        return marker[:500]

    async def _apply_modify(self, username: str, payload: dict) -> None:
        if self.cfg.dry_run:
            logger.info("[dry-run] user=%s payload=%s", username, payload)
            return
        await asyncio.to_thread(self.api.modify_user, username, payload)

    async def evaluate_once(self) -> None:
        users = await asyncio.to_thread(self.api.list_all_users)
        self.user_cache = {u.get("username"): u for u in users if u.get("username")}
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()

        for user in users:
            username = user.get("username")
            status = user.get("status")
            device_limit = user.get("device_limit")
            note = user.get("note")

            if not username:
                continue

            if username in self.cfg.whitelist_usernames:
                self.violation_count[username] = 0
                continue

            meta = self._extract_guard_meta(note)
            if meta and status == "disabled":
                until = meta.get("until")
                prev = meta.get("prev", "active")
                try:
                    until_dt = datetime.fromisoformat(until)
                except Exception:
                    until_dt = None

                if until_dt and until_dt <= now:
                    new_note = self._remove_guard_marker(note)
                    payload = {"status": prev if prev in {"active", "disabled"} else "active"}
                    payload["note"] = new_note if new_note is not None else ""
                    logger.info("unlock user=%s reason=ttl_expired", username)
                    await self._apply_modify(username, payload)
                    asyncio.ensure_future(self._fire_webhook({
                        "action": "unban",
                        "trigger": "auto",
                        "username": username,
                    }))
                    self.violation_count[username] = 0
                continue

            if status != "active" or not device_limit:
                self.violation_count[username] = 0
                continue

            active_ips = self.active_ip_count(username, now_ts)
            threshold = int(device_limit) + self.cfg.extra_devices

            if active_ips > threshold:
                self.violation_count[username] += 1
            else:
                self.violation_count[username] = 0

            if self.violation_count[username] >= self.cfg.violation_threshold:
                until_dt = now + timedelta(seconds=self.cfg.block_ttl_seconds)
                until_iso = until_dt.isoformat()
                new_note = self._append_guard_marker(note, until_iso, status)
                payload = {
                    "status": "disabled",
                    "note": new_note,
                }
                logger.warning(
                    "block user=%s active_ips=%s threshold=%s until=%s",
                    username,
                    active_ips,
                    threshold,
                    until_iso,
                )
                await self._apply_modify(username, payload)
                ip_list = sorted(self.last_seen.get(username, {}).keys())
                asyncio.ensure_future(self._fire_webhook({
                    "action": "ban",
                    "trigger": "auto",
                    "username": username,
                    "device_limit": int(device_limit),
                    "active_ip_count": active_ips,
                    "ips": ip_list,
                }))
                # keep at threshold so UI shows the peak value until unban

    async def snapshot_users(self) -> dict[str, list[dict[str, Any]]]:
        """Return dict with 'active' and 'banned' user lists"""
        now_ts = time.time()
        usernames = set(self.last_seen.keys()) | set(self.user_cache.keys())
        active: list[dict[str, Any]] = []
        banned: list[dict[str, Any]] = []

        for username in sorted(usernames):
            if not username:
                continue

            self._prune_user_ips(username, now_ts)

            cached = self.user_cache.get(username, {})
            ips_map = self.last_seen.get(username, {})
            active_ips = []
            all_configs: set[str] = set()
            for ip, rec in ips_map.items():
                last_seen = float(rec.get("last_seen", 0))
                configs = sorted(rec.get("configs", set()))
                node_id = rec.get("node_id")
                all_configs.update(configs)
                active_ips.append(
                    {
                        "ip": ip,
                        "node_id": node_id,
                        "node_name": self.node_names.get(node_id, f"Node #{node_id}") if node_id is not None else None,
                        "last_seen": datetime.fromtimestamp(last_seen, tz=timezone.utc).isoformat(),
                        "configs": configs,
                    }
                )

            note = cached.get("note")
            meta = self._extract_guard_meta(note)
            guard_until = meta.get("until") if meta else None
            is_banned = cached.get("status") == "disabled" and bool(meta)
            tracked = bool(active_ips) or bool(meta)
            if not tracked:
                continue

            device_limit = cached.get("device_limit")
            threshold = (int(device_limit) if device_limit else 0) + self.cfg.extra_devices if device_limit else None

            user_data = {
                "username": username,
                "status": cached.get("status"),
                "device_limit": device_limit,
                "threshold": threshold,
                "active_ip_count": len(active_ips),
                "active_ips": active_ips,
                "configs": sorted(all_configs),
                "violation_count": self.violation_count.get(username, 0),
                "whitelisted": username in self.cfg.whitelist_usernames,
                "guard_until": guard_until,
                "guarded": bool(meta),
            }

            if is_banned:
                banned.append(user_data)
            else:
                active.append(user_data)

        return {"active": active, "banned": banned}

    def snapshot_logs(self) -> dict[int, dict[str, Any]]:
        """Return recent log lines per node_id with node name (newest last)."""
        return {
            node_id: {
                "name": self.node_names.get(node_id, f"Node #{node_id}"),
                "lines": list(lines),
            }
            for node_id, lines in sorted(self.node_logs.items())
        }

    async def manual_ban(self, username: str, ttl_seconds: int | None = None) -> None:
        if username in self.cfg.whitelist_usernames:
            raise ValueError("User is whitelisted")

        user = await asyncio.to_thread(self.api.get_user, username)
        now = datetime.now(timezone.utc)
        ttl = ttl_seconds if ttl_seconds and ttl_seconds > 0 else self.cfg.manual_block_ttl_seconds
        until_iso = (now + timedelta(seconds=ttl)).isoformat()

        status = user.get("status") or "active"
        note = user.get("note")
        meta = self._extract_guard_meta(note)
        prev_status = meta.get("prev", "active") if meta else (status if status != "disabled" else "active")

        payload = {
            "status": "disabled",
            "note": self._append_guard_marker(note, until_iso, prev_status),
        }

        logger.warning("manual-ban user=%s ttl=%ss until=%s", username, ttl, until_iso)
        await self._apply_modify(username, payload)
        ip_list = sorted(self.last_seen.get(username, {}).keys())
        cached = self.user_cache.get(username, {})
        device_limit = cached.get("device_limit")
        active_ip_count = len([ip for ip, rec in self.last_seen.get(username, {}).items()])
        asyncio.ensure_future(self._fire_webhook({
            "action": "ban",
            "trigger": "manual",
            "username": username,
            "device_limit": int(device_limit) if device_limit else None,
            "active_ip_count": active_ip_count,
            "ips": ip_list,
        }))

    async def manual_unban(self, username: str) -> None:
        user = await asyncio.to_thread(self.api.get_user, username)
        status = user.get("status")
        note = user.get("note")

        meta = self._extract_guard_meta(note)
        prev = meta.get("prev", "active") if meta else "active"
        new_note = self._remove_guard_marker(note)
        payload = {
            "status": prev if prev in {"active", "disabled"} else "active",
            "note": new_note if new_note is not None else "",
        }

        if status != "disabled" and not meta:
            return

        logger.info("manual-unban user=%s", username)
        await self._apply_modify(username, payload)
        asyncio.ensure_future(self._fire_webhook({
            "action": "unban",
            "trigger": "manual",
            "username": username,
        }))

    async def monitor_node(self, node_id: int) -> None:
        base = self.cfg.panel_base_url.rstrip("/")
        ws_base = "wss://" + base[8:] if base.startswith("https://") else "ws://" + base[7:]

        while True:
            ws_url: str | None = None
            try:
                await asyncio.to_thread(self.api.login)
                token = self.api._token
                interval = self.cfg.node_logs_interval
                interval_param = str(int(interval)) if float(interval).is_integer() else str(interval)
                ws_url = (
                    f"{ws_base}/api/node/{node_id}/logs?interval={interval_param}&token={token}"
                )

                # Create SSL context without certificate verification for wss://
                ssl_context = None
                if ws_url.startswith("wss://"):
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

                extra_headers = {
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                }
                connect_kwargs: dict[str, Any] = {
                    "heartbeat": 20,
                    "compress": 0,
                    "headers": {
                        "User-Agent": WS_USER_AGENT,
                        "Origin": self.cfg.panel_base_url,
                        **extra_headers,
                    },
                }

                logger.info("connect ws node_id=%s", node_id)
                timeout = aiohttp.ClientTimeout(total=None, sock_connect=20, sock_read=None)
                attempts: list[tuple[str, socket.AddressFamily]] = [
                    ("default", socket.AF_UNSPEC),
                    ("ipv4", socket.AF_INET),
                ]
                last_exc: Exception | None = None

                for attempt_name, family in attempts:
                    try:
                        connector_kwargs: dict[str, Any] = {"family": family}
                        if ssl_context is not None:
                            connector_kwargs["ssl"] = ssl_context
                        connector = aiohttp.TCPConnector(**connector_kwargs)
                        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                            async with session.ws_connect(ws_url, **connect_kwargs) as ws:
                                async for msg in ws:
                                    if msg.type == aiohttp.WSMsgType.TEXT:
                                        for line in str(msg.data).splitlines():
                                            if line.strip():
                                                ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
                                                logs = self.node_logs[node_id]
                                                logs.append({"ts": ts, "line": line})
                                                if len(logs) > self._node_logs_maxlen:
                                                    del logs[0]
                                            self.current_node_id = node_id
                                            self.ingest_log_line(line)
                                    elif msg.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED}:
                                        break
                                    elif msg.type == aiohttp.WSMsgType.ERROR:
                                        raise RuntimeError(f"ws message error: {ws.exception()}")
                        last_exc = None
                        break
                    except Exception as attempt_exc:
                        last_exc = attempt_exc
                        logger.warning(
                            "ws node_id=%s attempt=%s family=%s failed: %r",
                            node_id,
                            attempt_name,
                            family,
                            attempt_exc,
                        )

                if last_exc is not None:
                    raise last_exc
            except Exception as exc:
                safe_url = ws_url
                if safe_url and "token=" in safe_url:
                    safe_url = safe_url.split("token=", 1)[0] + "token=***"
                logger.exception(
                    "ws node_id=%s type=%s error=%r url=%s",
                    node_id,
                    type(exc).__name__,
                    exc,
                    safe_url,
                )
                await asyncio.sleep(3)

    async def _evaluation_loop(self) -> None:
        while True:
            try:
                await self.evaluate_once()
            except Exception as exc:
                logger.error("evaluation error=%s", exc)
            await asyncio.sleep(self.cfg.check_interval_seconds)

    async def run(self) -> None:
        tasks: list[asyncio.Task] = []
        while True:
            try:
                nodes = await asyncio.to_thread(self.api.list_nodes)
                node_ids = [int(n["id"]) for n in nodes if n.get("id") is not None]
                self.node_names = {
                    int(n["id"]): (n.get("name") or f"Node #{n['id']}").strip()
                    for n in nodes if n.get("id") is not None
                }
                self.node_names = {
                    int(n["id"]): (n.get("name") or f"Node #{n['id']}").strip()
                    for n in nodes if n.get("id") is not None
                }
                if node_ids:
                    logger.info("discovered nodes=%s", node_ids)
                    tasks = [asyncio.create_task(self.monitor_node(nid)) for nid in node_ids]
                    break
            except Exception as exc:
                logger.error("cannot list nodes: %s", exc)
            await asyncio.sleep(3)

        evaluator = asyncio.create_task(self._evaluation_loop())
        await asyncio.gather(*tasks, evaluator)
