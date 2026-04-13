from typing import Any

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from .config import Config


class PanelClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.verify = False
        urllib3.disable_warnings(InsecureRequestWarning)
        self._token: str | None = None

    def _api_url(self, path: str) -> str:
        return f"{self.cfg.panel_base_url.rstrip('/')}{path}"

    def login(self) -> None:
        resp = self.session.post(
            self._api_url("/api/admin/token"),
            data={
                "username": self.cfg.username,
                "password": self.cfg.password,
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self.session.headers.update({"Authorization": f"Bearer {self._token}"})

    def _request(self, method: str, path: str, **kwargs):
        if not self._token:
            self.login()

        resp = self.session.request(method, self._api_url(path), timeout=20, **kwargs)
        if resp.status_code == 401:
            self.login()
            resp = self.session.request(method, self._api_url(path), timeout=20, **kwargs)
        resp.raise_for_status()
        return resp

    def list_nodes(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/nodes").json()

    def list_users_page(self, offset: int, limit: int = 200) -> list[dict[str, Any]]:
        resp = self._request("GET", "/api/users", params={"offset": offset, "limit": limit})
        data = resp.json()
        return data.get("users", [])

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
