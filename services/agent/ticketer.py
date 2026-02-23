"""
Client for the Meridian mock ticketing service (simulates ServiceNow).
"""

from __future__ import annotations

import logging

import requests

log = logging.getLogger(__name__)

PRIORITY_MAP = {"critical": 1, "high": 2, "medium": 3, "low": 4}


class TicketingClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def ping(self) -> None:
        """Raise on failure; used by startup retry loop."""
        resp = requests.get(f"{self.base_url}/health", timeout=5)
        resp.raise_for_status()

    def create_ticket(
        self,
        control_id: str,
        short_description: str,
        description: str,
        severity: str,
        **extra_fields,
    ) -> dict:
        """Create an incident and return the result dict."""
        payload = {
            "short_description": short_description,
            "description": description,
            "priority": PRIORITY_MAP.get(severity, 3),
            "category": "compliance",
            "caller_id": "meridian-agent",
            "control_id": control_id,
            **extra_fields,
        }
        resp = requests.post(
            f"{self.base_url}/api/now/table/incident",
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        result = resp.json()["result"]
        log.info(
            "Created ticket %s for control %s (priority=%s)",
            result["number"],
            control_id,
            result["priority"],
        )
        return result

    def get_ticket(self, sys_id: str) -> dict | None:
        resp = requests.get(
            f"{self.base_url}/api/now/table/incident/{sys_id}",
            timeout=10,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()["result"]

    def is_ticket_open(self, sys_id: str) -> bool:
        """Return True if the ticket exists and is in a non-resolved state (1 or 2)."""
        ticket = self.get_ticket(sys_id)
        if ticket is None:
            return False
        return ticket.get("state") in (1, 2)  # New or In Progress
