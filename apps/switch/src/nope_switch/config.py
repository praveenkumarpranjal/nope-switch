"""NOPE application settings, not official Switch configuration names."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RoomSettings:
    enabled: bool
    base_url: str
    room_id: str
    room_url: str
    bridge_name: str
    agent_name: str

    @classmethod
    def from_env(cls) -> RoomSettings:
        return cls(
            enabled=os.getenv("NOPE_SWITCH_ENABLED", "false").lower() == "true",
            base_url=os.getenv("NOPE_SWITCH_BASE_URL")
            or os.getenv("SWITCH_API_ENDPOINT")
            or os.getenv("SWITCH_BRIDGE_URL", "")
            or "",
            room_id=os.getenv("NOPE_SWITCH_ROOM_ID") or os.getenv("SWITCH_ROOM_ID", "") or "",
            room_url=os.getenv("NOPE_SWITCH_ROOM_URL", ""),
            bridge_name=os.getenv("NOPE_SWITCH_BRIDGE_NAME", ""),
            agent_name=os.getenv("NOPE_SWITCH_AGENT_NAME", "nope"),
        )
