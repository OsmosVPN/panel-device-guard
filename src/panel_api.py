import logging
import time
from typing import Any

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from .config import Config

logger = logging.getLogger("panel_device_guard")


class PanelClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.verify = False
        urllib3.disable_warnings(InsecureRequestWarning)
        self._token: str | None = None

    def _api_url(self, path: str) -> str:
        return f"{self.cfg.panel_base_url.rstrip('/')}{path}"

    def _retry_delay(self, attempt: int) -> float:
        base = max(0.1, float(self.cfg.api_retry_delay_seconds))
        cap = max(base, float(self.cfg.api_retry_max_delay_seconds))
        return min(base * (2 ** max(0, attempt - 1)), cap)

    def _reset_session(self) -> None:
        """Discard the current requests.Session and open a fresh one."""
        try:
            self.session.close()
        except Exception:
            pass
        self.session = requests.Session()
        self.session.verify = False
        self._token = None

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass

    def login(self) -> None:
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self.session.post(
                    self._api_url("/api/admin/token"),
                    data={
                        "username": self.cfg.username,
                        "password": self.cfg.password,
                    },
                    timeout=15,
                )
                resp.raise_for_status()
                try:
                    data = resp.json()
                except Exception as exc:
                    raise RuntimeError(
                        f"login: non-JSON response (status={resp.status_code}): {resp.text[:200]}"
                    ) from exc
                self._token = data["access_token"]
                self.session.headers.update({"Authorization": f"Bearer {self._token}"})
                return
            except (requests.exceptions.ConnectionError, requests.exceptions.SSLError) as exc:
                delay = self._retry_delay(attempt)
                logger.warning(
                    "login network error (attempt=%s): %r; retry in %.1fs",
                    attempt,
                    exc,
                    delay,
                )
                self._reset_session()
                time.sleep(delay)
                continue
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status in {429, 500, 502, 503, 504}:
                    delay = self._retry_delay(attempt)
                    logger.warning(
                        "login transient HTTP %s (attempt=%s); retry in %.1fs",
                        status,
                        attempt,
                        delay,
                    )
                    self._reset_session()
                    time.sleep(delay)
                    continue
                raise

    def _request(self, method: str, path: str, **kwargs):
        attempt = 0
        while True:
            attempt += 1
            if not self._token:
                self.login()

            try:
                resp = self.session.request(method, self._api_url(path), timeout=20, **kwargs)
            except (requests.exceptions.ConnectionError, requests.exceptions.SSLError) as exc:
                delay = self._retry_delay(attempt)
                logger.warning(
                    "connection error on %s %s (attempt=%s): %r; retry in %.1fs",
                    method,
                    path,
                    attempt,
                    exc,
                    delay,
                )
                self._reset_session()
                time.sleep(delay)
                continue

            if resp.status_code == 401:
                logger.warning("unauthorized on %s %s, refreshing token", method, path)
                self._reset_session()
                self.login()
                continue

            try:
                resp.raise_for_status()
                return resp
            except requests.exceptions.HTTPError as exc:
                status = resp.status_code
                if status in {429, 500, 502, 503, 504}:
                    delay = self._retry_delay(attempt)
                    logger.warning(
                        "transient HTTP %s on %s %s (attempt=%s); retry in %.1fs",
                        status,
                        method,
                        path,
                        attempt,
                        delay,
                    )
                    self._reset_session()
                    time.sleep(delay)
                    continue
                raise exc

    def list_nodes(self) -> list[dict[str, Any]]:
        resp = self._request("GET", "/api/nodes")
        if not resp.content:
            logger.warning("list_nodes: empty response body (status=%s)", resp.status_code)
            return []
        try:
            result = resp.json()
        except Exception:
            logger.error("list_nodes: non-JSON response (status=%s): %r", resp.status_code, resp.text[:300])
            return []
        if not isinstance(result, list):
            logger.warning("list_nodes: unexpected response type=%s: %r", type(result).__name__, str(result)[:200])
            return []
        return result

    def list_users_page(self, offset: int, limit: int = 200) -> list[dict[str, Any]]:
        resp = self._request("GET", "/api/users", params={"offset": offset, "limit": limit})
        if not resp.content:
            logger.warning("list_users_page: empty response body (status=%s offset=%s)", resp.status_code, offset)
            return []
        try:
            data = resp.json()
        except Exception:
            logger.error(
                "list_users_page: non-JSON response (status=%s offset=%s): %r",
                resp.status_code,
                offset,
                resp.text[:300],
            )
            return []
        users = data.get("users", []) if isinstance(data, dict) else []
        if not isinstance(users, list):
            logger.warning(
                "list_users_page: unexpected users type=%s offset=%s",
                type(users).__name__,
                offset,
            )
            return []
        return users

    def list_all_users(self) -> list[dict[str, Any]]:
        users: list[dict[str, Any]] = []
        offset = 0
        page_size = 200
        while True:
            chunk = self.list_users_page(offset=offset, limit=page_size)
            if not chunk:
                break
            users.extend(chunk)
            if len(chunk) < page_size:
                break
            offset += page_size
        return users

    def modify_user(self, username: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", f"/api/user/{username}", json=payload).json()

    def get_user(self, username: str) -> dict[str, Any]:
        return self._request("GET", f"/api/user/{username}").json()


__all__ = ["PanelClient"]
