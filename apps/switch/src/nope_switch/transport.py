"""Outbound HTTP operations using an existing Switch agent identity.

Console keeps the incoming event connection. This adapter opens no listener,
registers no agents, changes no addressing policies, and claims no rooms.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import uuid4

import httpx

from nope_switch.config import RoomSettings


class SwitchError(RuntimeError):
    pass


class SwitchClient:
    def __init__(
        self,
        url: str,
        agent_id: str,
        key: str,
        room_id: str,
        connection_id: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise SwitchError(
                "SWITCH_BRIDGE_URL must be an HTTP(S) server URL without embedded credentials"
            )
        if not agent_id or not key:
            raise SwitchError("The existing Switch agent ID and API key are required")
        self.url = url.rstrip("/")
        self.agent_id, self.room_id = agent_id, room_id
        self.prefix = f"/agents/{quote(agent_id, safe='')}"
        self.headers = {"Authorization": f"Bearer {key}"}
        self.connection_id = connection_id
        self.client = client or httpx.Client(timeout=15, follow_redirects=False)
        self._operations: dict[str, Any] | None = None

    @classmethod
    def from_env(cls, require_room: bool = True) -> SwitchClient:
        settings = RoomSettings.from_env()
        if not settings.enabled:
            raise SwitchError("BLOCKED: NOPE_SWITCH_ENABLED is false; local evidence remains MOCK")
        if require_room and not settings.room_id:
            raise SwitchError(
                "BLOCKED: no actual room ID; use discover after configuring the real server"
            )
        return cls(
            settings.base_url,
            os.getenv("SWITCH_AGENT_ID", ""),
            os.getenv("SWITCH_API_TOKEN") or os.getenv("SWITCH_AGENT_KEY", "") or "",
            settings.room_id,
            os.getenv("SWITCH_CONNECTION_ID") or None,
        )

    def close(self) -> None:
        self.client.close()

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None, connected: bool = False
    ) -> dict[str, Any]:
        headers = dict(self.headers)
        if connected:
            if not self.connection_id:
                raise SwitchError(
                    "This operation needs SWITCH_CONNECTION_ID from the existing Console session; no room is claimed automatically"
                )
            headers["X-Switch-Connection-Id"] = self.connection_id
        try:
            response = self.client.request(method, self.url + path, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPStatusError as exc:
            raise SwitchError(
                f"Switch refused {method} {path} (HTTP {exc.response.status_code}); check identity, membership, and addressing policy"
            ) from None
        except (httpx.HTTPError, ValueError):
            raise SwitchError(f"Switch request failed: {method} {path}") from None
        if not isinstance(body, dict):
            raise SwitchError("Switch returned a non-object response")
        return body

    def operation(self, name: str, arguments: dict[str, Any], connected: bool = False) -> Any:
        if self._operations is None:
            operations = self._request("GET", self.prefix + "/ops").get("operations")
            if not isinstance(operations, dict):
                raise SwitchError("Switch returned an invalid operation registry")
            self._operations = operations
        spec = self._operations.get(name)
        if not isinstance(spec, dict):
            raise SwitchError(f"The server does not advertise operation {name}")
        schema = spec.get("input_schema", {})
        if (not isinstance(schema, dict) or not isinstance(schema.get("properties", {}), dict)
                or not isinstance(schema.get("required", []), list)
                or any(not isinstance(key, str) for key in schema.get("required", []))):
            raise SwitchError(f"Switch returned an invalid schema for operation {name}")
        missing = set(schema.get("required", [])) - arguments.keys()
        unknown = arguments.keys() - schema.get("properties", {}).keys()
        if missing or unknown:
            raise SwitchError(
                f"{name} does not match this server's discovered arguments (missing={sorted(missing)}, unknown={sorted(unknown)})"
            )
        response = self._request("POST", self.prefix + f"/ops/{name}", arguments, connected)
        if "result" not in response:
            raise SwitchError(f"{name} returned no result")
        return response["result"]

    def post(self, content: str) -> dict[str, Any]:
        if not self.room_id:
            raise SwitchError("An actual room ID is required before posting")
        # This documented route needs membership and an agent key, no event connection.
        response = self._request(
            "POST", self.prefix + "/message", {"room_id": self.room_id, "content": content}
        )
        if response.get("ok") is not True or not response.get("event_id"):
            raise SwitchError("Switch did not acknowledge the room message")
        return response

    def create_document(self, name: str, content: str) -> Any:
        return self.operation(
            "create_room_document",
            {
                "name": name,
                "description": "Approved Scar: incident, safeguard, tests and decision history",
                "instructions": "Read before changing code in this repository. Advisory guidance; CI remains authoritative.",
                "content": content,
            },
            connected=True,
        )

    def probe(self, target_name: str, target_id: str, timeout: float = 45) -> dict[str, Any]:
        """Require an observed nonce reply from the requested agent, not HTTP success."""
        nonce = uuid4().hex
        started = datetime.now(UTC).isoformat()
        ack = f"NOPE-ACK {nonce}"
        request = self.operation(
            "send_targeted_message",
            {
                "body": f"Addressing preflight only: reply with exactly {ack}. Do not run code or change policy.",
                "target_names": [target_name],
            },
            connected=True,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            context = self.operation(
                "read_context", {"room_id": self.room_id, "since": started, "limit": 100}
            )
            for thread in context.get("threads", []):
                for entry in [thread.get("root", {}), *thread.get("replies", [])]:
                    if entry.get("sender") == target_id and entry.get("body", "").strip() == ack:
                        return {
                            "verified": True,
                            "room_id": self.room_id,
                            "source_agent_id": self.agent_id,
                            "target_agent_id": target_id,
                            "target_name": target_name,
                            "nonce": nonce,
                            "request": request,
                            "reply_id": entry.get("id"),
                            "observed_at": datetime.now(UTC).isoformat(),
                        }
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise SwitchError(
            "No matching reply from the target agent. Addressing remains UNVERIFIED; do not stage the live courtroom"
        )
