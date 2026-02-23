"""
Keycloak Admin REST API client.

Handles token acquisition and transparent token refresh on 401.
All methods raise requests.HTTPError on non-2xx responses.
"""

from __future__ import annotations

import logging

import requests

log = logging.getLogger(__name__)


class KeycloakClient:
    def __init__(
        self,
        base_url: str,
        realm: str = "master",
        admin_user: str = "admin",
        admin_password: str = "admin",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.admin_user = admin_user
        self.admin_password = admin_password
        self._token: str | None = None

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _fetch_token(self) -> str:
        resp = requests.post(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.admin_user,
                "password": self.admin_password,
            },
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _headers(self) -> dict[str, str]:
        if self._token is None:
            self._token = self._fetch_token()
        return {"Authorization": f"Bearer {self._token}"}

    def _get(self, path: str, params: dict | None = None) -> object:
        url = f"{self.base_url}/admin/realms/{self.realm}{path}"
        resp = requests.get(url, headers=self._headers(), params=params, timeout=15)
        if resp.status_code == 401:
            # Token expired — refresh and retry once
            self._token = self._fetch_token()
            resp = requests.get(url, headers=self._headers(), params=params, timeout=15)
        resp.raise_for_status()
        return resp.json()

    # ── User queries ──────────────────────────────────────────────────────────

    def list_users(self, max_results: int = 500) -> list[dict]:
        return self._get("/users", params={"max": max_results})  # type: ignore[return-value]

    def get_user_credentials(self, user_id: str) -> list[dict]:
        return self._get(f"/users/{user_id}/credentials")  # type: ignore[return-value]

    def get_user_role_mappings(self, user_id: str) -> dict:
        return self._get(f"/users/{user_id}/role-mappings")  # type: ignore[return-value]

    def get_role_users(self, role_name: str) -> list[dict]:
        return self._get(f"/roles/{role_name}/users")  # type: ignore[return-value]

    def get_realm(self) -> dict:
        """Return the realm representation, including realm-level attributes."""
        return self._get("")  # type: ignore[return-value]

    # ── Connectivity check ────────────────────────────────────────────────────

    def ping(self) -> None:
        """Raise on failure; used by startup retry loop."""
        self._fetch_token()
        log.info("Keycloak reachable at %s (realm=%s)", self.base_url, self.realm)
