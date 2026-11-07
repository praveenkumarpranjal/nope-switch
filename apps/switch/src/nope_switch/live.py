"""Discover and prove a real Console/Mattermost room without owning its transport."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from typing import Any

from nope_switch.config import RoomSettings
from nope_switch.transport import SwitchClient, SwitchError


def entries(context: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        entry
        for thread in context.get("threads", [])
        for entry in [thread.get("root", {}), *thread.get("replies", [])]
    ]


def discover(client: SwitchClient, settings: RoomSettings, room_name: str) -> dict[str, Any]:
    client._request("GET", "/health")
    rooms = client.operation("list_rooms", {})
    bridges = client.operation("list_bridges", {})
    agents = client.operation("list_agents", {"name_contains": settings.agent_name})
    matching = [
        room
        for room in rooms
        if room.get("name") == room_name
        and (not settings.room_id or room.get("room_id") == settings.room_id)
    ]
    room = matching[0] if len(matching) == 1 else None
    detail = client.operation("get_room_detail", {"room_id": room["room_id"]}) if room else None
    bridge = next((b for b in bridges if detail and b.get("id") == detail.get("bridge_id")), None)
    valid_bridge = bool(
        bridge
        and bridge.get("type") == "mattermost"
        and bridge.get("status") == "active"
        and (not settings.bridge_name or bridge.get("display_name") == settings.bridge_name)
    )
    agent = next(
        (
            a
            for a in agents
            if a.get("id") == client.agent_id and a.get("name") == settings.agent_name
        ),
        None,
    )
    if room:
        client.room_id = room["room_id"]
    return {
        "status": "BLOCKED",
        "reason": "A real room round trip is not yet verified",
        "checked_at": datetime.now(UTC).isoformat(),
        "room": detail,
        "room_url": (detail or {}).get("url") or settings.room_url or None,
        "bridge": bridge,
        "agent": agent,
        "milestones": {
            "mattermost_bridge_connected": valid_bridge,
            "room_discovered": bool(room),
            "agent_registered": bool(agent),
            "room_roundtrip": False,
        },
    }


def receive(
    client: SwitchClient, agent_name: str, since: str | None = None
) -> list[dict[str, Any]]:
    arguments: dict[str, Any] = {"room_id": client.room_id, "limit": 100}
    if since:
        arguments["since"] = since
    context = client.operation("read_context", arguments)
    command = re.compile(
        r"(?:^|\s)@" + re.escape(agent_name) + r"\s+(teach|challenge)\b", re.IGNORECASE
    )
    requests = []
    for entry in entries(context):
        match = command.search(entry.get("body", ""))
        if match:
            requests.append(
                {
                    "command": match.group(1).lower(),
                    "room_id": client.room_id,
                    "message_id": entry["id"],
                    "author_id": entry["sender"],
                    "author_name": entry.get("sender_name"),
                    "body": entry["body"],
                    "timestamp": entry.get("timestamp"),
                }
            )
    return requests


def roundtrip(
    client: SwitchClient, settings: RoomSettings, room_name: str, source_id: str
) -> dict[str, Any]:
    report = discover(client, settings, room_name)
    if not all(
        report["milestones"][k]
        for k in ("mattermost_bridge_connected", "room_discovered", "agent_registered")
    ):
        raise SwitchError(
            "BLOCKED: verify the actual Mattermost bridge, room membership, and @nope identity first"
        )
    source = next(
        (
            message
            for message in receive(client, settings.agent_name)
            if message["message_id"] == source_id
        ),
        None,
    )
    if source is None or source["author_id"] == client.agent_id:
        raise SwitchError(
            "BLOCKED: the specified teach/challenge request was not observed from another room participant"
        )
    reply = client.post(
        f"NOPE received the {source['command']} request, message {source_id}. "
        "Room round-trip verification only. Validation and authorized human approval remain required."
    )
    for _ in range(5):
        context = client.operation("read_context", {"room_id": client.room_id, "limit": 100})
        observed = next(
            (entry for entry in entries(context) if entry.get("id") == reply["event_id"]), None
        )
        if observed:
            report.update(
                {
                    "status": "LIVE",
                    "reason": "Observed original room request and persisted @nope reply",
                    "source_message": source,
                    "reply": reply,
                    "observed_reply": observed,
                }
            )
            report["milestones"]["room_roundtrip"] = True
            return report
        time.sleep(1)
    raise SwitchError(
        "BLOCKED: HTTP send succeeded but the reply was not observed in the actual room timeline"
    )
