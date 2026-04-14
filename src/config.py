import os
import re
import secrets
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv(override=True)


@dataclass
class Config:
    panel_base_url: str
    username: str
    password: str
    extra_devices: int
    active_window_seconds: int
    violation_threshold: int
    block_ttl_seconds: int
    check_interval_seconds: int
    node_logs_interval: float
    email_to_username_regex: re.Pattern
    note_marker_prefix: str
    whitelist_usernames: set[str]
    whitelist_ips: set[str]
    dry_run: bool
    manual_block_ttl_seconds: int
    webhook_url: str | None
    webhook_secret: str | None
    node_kick_enabled: bool
    node_kick_port: int  # port where node-agent listens on each node (0 = disabled)
    node_kick_token: str | None
    # Web interface
    web_enabled: bool
    web_port: int
    web_secret_key: str
    web_username: str
    web_password: str


def _get_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)).strip())


def _get_float(name: str, default: float) -> float:
    return float(os.getenv(name, str(default)).strip())


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, str(default)).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _get_csv_set(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _random_secret() -> str:
    import logging
    logging.getLogger("panel_device_guard").warning(
        "WEB_SECRET_KEY not set — generated a random key; sessions won't survive restarts"
    )
    return secrets.token_hex(32)


def load_config() -> Config:
    panel_base_url = os.getenv("PANEL_BASE_URL", "").strip()
    username = os.getenv("PANEL_USERNAME", "").strip()
    password = os.getenv("PANEL_PASSWORD", "").strip()

    if not panel_base_url:
        raise RuntimeError("PANEL_BASE_URL is required")
    if not username or not password:
        raise RuntimeError("PANEL_USERNAME and PANEL_PASSWORD are required")

    regex_text = os.getenv("EMAIL_TO_USERNAME_REGEX", r"(?:\d+\.)?(?P<username>.+)")

    return Config(
        panel_base_url=panel_base_url,
        username=username,
        password=password,
        extra_devices=_get_int("EXTRA_DEVICES", 0),
        active_window_seconds=_get_int("ACTIVE_WINDOW_SECONDS", 600),
        violation_threshold=_get_int("VIOLATION_THRESHOLD", 3),
        block_ttl_seconds=_get_int("BLOCK_TTL_SECONDS", 1800),
        check_interval_seconds=_get_int("CHECK_INTERVAL_SECONDS", 10),
        node_logs_interval=_get_float("NODE_LOGS_INTERVAL", 1.0),
        email_to_username_regex=re.compile(regex_text),
        note_marker_prefix=os.getenv("NOTE_MARKER_PREFIX", "[DGUARD]").strip() or "[DGUARD]",
        whitelist_usernames=_get_csv_set("WHITELIST_USERNAMES"),
        whitelist_ips=_get_csv_set("WHITELIST_IPS"),
        dry_run=_get_bool("DRY_RUN", False),
        manual_block_ttl_seconds=_get_int("MANUAL_BLOCK_TTL_SECONDS", _get_int("BLOCK_TTL_SECONDS", 1800)),
        webhook_url=os.getenv("WEBHOOK_URL", "").strip() or None,
        webhook_secret=os.getenv("WEBHOOK_SECRET", "").strip() or None,
        node_kick_enabled=_get_bool("NODE_KICK_ENABLE", False),
        node_kick_port=_get_int("NODE_KICK_PORT", 62010),
        node_kick_token=os.getenv("NODE_KICK_TOKEN", "").strip() or None,
        web_enabled=_get_bool("WEB_ENABLED", False),
        web_port=_get_int("WEB_PORT", 8080),
        web_secret_key=os.getenv("WEB_SECRET_KEY", "").strip() or _random_secret(),
        web_username=os.getenv("WEB_USERNAME", "admin").strip(),
        web_password=os.getenv("WEB_PASSWORD", "").strip(),
    )
