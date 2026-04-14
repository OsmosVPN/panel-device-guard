import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import Config
from .log_parser import parse_log_line
from .node_kick import IpRecord, collect_ips_by_node, kick_ips
from .node_monitor import monitor_node
from .note_marker import append_guard_marker, extract_guard_meta, remove_guard_marker
from .panel_api import PanelClient
from .webhook import fire_webhook

logger = logging.getLogger("panel_device_guard")


class DeviceGuard:
    def __init__(self, cfg: Config, api: PanelClient) -> None:
        self.cfg = cfg
        self.api = api
        self.last_seen: dict[str, dict[str, IpRecord]] = defaultdict(dict)
        self.violation_count: dict[str, int] = defaultdict(int)
        self.current_node_id: int | None = None
        self.node_names: dict[int, str] = {}
        self.node_addresses: dict[int, str] = {}
        self.node_logs: dict[int, deque] = {}  # node_id -> deque of (timestamp, line)
        # Protects concurrent ban/unban from both the evaluation loop and the web UI.
        # Acquired for the duration of: API call + in-memory state update.
        self._state_lock = asyncio.Lock()

    # ------------------------------------------------------------------ #
    # Log ingestion                                                        #
    # ------------------------------------------------------------------ #

    def normalize_username(self, email_value: str) -> str | None:
        m = self.cfg.email_to_username_regex.match(email_value.strip())
        if not m:
            return None
        return m.group("username") if "username" in m.groupdict() else m.group(0)

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
        now = time.time()
        rec = self.last_seen[username].setdefault(
            ip, {"last_seen": now, "configs": set(), "node_id": self.current_node_id}
        )
        rec["last_seen"] = now
        rec["configs"].add(email)
        if self.current_node_id is not None:
            rec["node_id"] = self.current_node_id

    # ------------------------------------------------------------------ #
    # IP pruning                                                           #
    # ------------------------------------------------------------------ #

    def _prune_ips(self, username: str, now_ts: float) -> None:
        ips = self.last_seen.get(username)
        if not ips:
            return
        cutoff = now_ts - self.cfg.active_window_seconds
        stale = [ip for ip, rec in ips.items() if float(rec.get("last_seen", 0)) < cutoff]
        for ip in stale:
            del ips[ip]
        if not ips:
            del self.last_seen[username]

    def _active_ip_count(self, username: str, now_ts: float) -> int:
        self._prune_ips(username, now_ts)
        return len(self.last_seen.get(username, {}))

    # ------------------------------------------------------------------ #
    # Side-effect helpers (kick + webhook)                                 #
    # ------------------------------------------------------------------ #

    def fire_ban_side_effects(
        self,
        username: str,
        ips_by_node: dict,
        trigger: str = "auto",
        extra: dict | None = None,
    ) -> None:
        if ips_by_node:
            asyncio.ensure_future(kick_ips(self.cfg, dict(self.node_addresses), ips_by_node))
        if self.cfg.webhook_url:
            payload: dict[str, Any] = {"action": "ban", "trigger": trigger, "username": username}
            if extra:
                payload.update(extra)
            asyncio.ensure_future(fire_webhook(self.cfg.webhook_url, self.cfg.webhook_secret, payload))

    def fire_unban_side_effects(self, username: str, trigger: str = "auto") -> None:
        if self.cfg.webhook_url:
            asyncio.ensure_future(fire_webhook(
                self.cfg.webhook_url, self.cfg.webhook_secret,
                {"action": "unban", "trigger": trigger, "username": username},
            ))

    # ------------------------------------------------------------------ #
    # Panel write helpers                                                  #
    # ------------------------------------------------------------------ #

    async def _apply_modify(self, username: str, payload: dict[str, Any]) -> None:
        if self.cfg.dry_run:
            logger.info("[dry-run] user=%s payload=%s", username, payload)
            return
        await asyncio.to_thread(self.api.modify_user, username, payload)

    def _clear_user_state(self, username: str) -> None:
        self.violation_count.pop(username, None)
        self.last_seen.pop(username, None)

    # ------------------------------------------------------------------ #
    # Evaluation loop                                                      #
    # ------------------------------------------------------------------ #

    async def evaluate_once(self) -> None:
        users = await asyncio.to_thread(self.api.list_all_users)
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()

        for user in users:
            username: str | None = user.get("username")
            if not username:
                continue

            status: str = user.get("status", "")
            note: str | None = user.get("note")
            device_limit = user.get("device_limit")

            if username in self.cfg.whitelist_usernames:
                self.violation_count[username] = 0
                continue

            meta = extract_guard_meta(note, self.cfg.note_marker_prefix)

            if meta and status == "disabled":
                try:
                    until_dt = datetime.fromisoformat(meta["until"]) if "until" in meta else None
                except ValueError:
                    until_dt = None
                if until_dt and until_dt <= now:
                    prev = meta.get("prev", "active")
                    payload = {
                        "status": prev if prev in {"active", "disabled"} else "active",
                        "note": remove_guard_marker(note, self.cfg.note_marker_prefix),
                    }
                    logger.info("unlock user=%s reason=ttl_expired", username)
                    async with self._state_lock:
                        await self._apply_modify(username, payload)
                        self._clear_user_state(username)
                    self.fire_unban_side_effects(username, trigger="auto")
                continue

            if status != "active" or not device_limit:
                self.violation_count[username] = 0
                continue

            count = self._active_ip_count(username, now_ts)
            threshold = int(device_limit) + self.cfg.extra_devices
            if count > threshold:
                self.violation_count[username] += 1
            else:
                self.violation_count[username] = 0

            if self.violation_count[username] >= self.cfg.violation_threshold:
                until_iso = (now + timedelta(seconds=self.cfg.block_ttl_seconds)).isoformat()
                payload = {
                    "status": "disabled",
                    "note": append_guard_marker(note, self.cfg.note_marker_prefix, until_iso, status),
                }
                logger.warning("block user=%s active_ips=%s threshold=%s until=%s",
                               username, count, threshold, until_iso)
                # Snapshot before acquiring lock so we don't hold it longer than needed.
                ip_list = sorted(self.last_seen.get(username, {}))
                ips_by_node = collect_ips_by_node(self.last_seen, username)
                async with self._state_lock:
                    await self._apply_modify(username, payload)
                    self._clear_user_state(username)
                self.fire_ban_side_effects(
                    username, ips_by_node, trigger="auto",
                    extra={"device_limit": int(device_limit), "active_ip_count": count, "ips": ip_list},
                )

    def _on_ws_line(self, node_id: int, line: str) -> None:
        self.current_node_id = node_id
        if node_id not in self.node_logs:
            self.node_logs[node_id] = deque(maxlen=300)
        self.node_logs[node_id].append(line)
        self.ingest_log_line(line)

    # ------------------------------------------------------------------ #
    # Evaluation loop                                                      #
    # ------------------------------------------------------------------ #

    async def _evaluation_loop(self) -> None:
        while True:
            try:
                await self.evaluate_once()
            except Exception as exc:
                logger.error("evaluation error=%s", exc)
            await asyncio.sleep(self.cfg.check_interval_seconds)

    async def run(self) -> None:
        while True:
            try:
                nodes = await asyncio.to_thread(self.api.list_nodes)
                active = [n for n in nodes if n.get("id") is not None and n.get("status") == "connected"]
                skipped = [n.get("id") for n in nodes if n.get("id") is not None and n.get("status") != "connected"]
                if skipped:
                    logger.info("skipping offline nodes=%s", skipped)
                self.node_names = {int(n["id"]): (n.get("name") or f"Node #{n['id']}").strip() for n in active}
                self.node_addresses = {int(n["id"]): (n.get("address") or "").strip() for n in active}
                node_ids = [int(n["id"]) for n in active]
                if node_ids:
                    logger.info("discovered nodes=%s", node_ids)
                else:
                    logger.warning("no nodes — running evaluator only")
                break
            except Exception as exc:
                logger.error("cannot list nodes: %s", exc)
            await asyncio.sleep(3)

        evaluator = asyncio.create_task(self._evaluation_loop())
        monitors = [asyncio.create_task(monitor_node(nid, self.cfg, self.api, self._on_ws_line)) for nid in node_ids]
        await asyncio.gather(*monitors, evaluator) if monitors else await evaluator
