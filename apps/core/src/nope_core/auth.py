from __future__ import annotations

import hmac
import os
from collections.abc import Awaitable, Callable
from enum import IntEnum
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status


class Role(IntEnum):
    ANONYMOUS = 0
    CI = 10
    AGENT = 20
    APPROVER = 30
    ADMIN = 40


def parse_api_keys() -> dict[str, Role]:
    """NOPE_API_KEYS format: key:role,key:role. Roles are never supplied by clients."""
    raw = os.getenv("NOPE_API_KEYS", "").strip()
    parsed: dict[str, Role] = {}
    for entry in raw.split(","):
        if not entry.strip():
            continue
        try:
            key, role_name = entry.split(":", 1)
        except ValueError as exc:
            raise RuntimeError("NOPE_API_KEYS must use 'key:role' entries separated by commas") from exc
        role_name = role_name.strip().lower()
        try:
            parsed[key.strip()] = Role[role_name.upper()]
        except KeyError as exc:
            raise RuntimeError(f"Unknown NOPE API role: {role_name!r}") from exc
    return parsed


API_KEYS = parse_api_keys()
ALLOW_ANONYMOUS = os.getenv("NOPE_ALLOW_ANONYMOUS", "false").lower() == "true"


def authorize(minimum: Role) -> Callable[[Annotated[str | None, Header()]], Awaitable[str]]:
    async def dependency(x_nope_key: Annotated[str | None, Header()] = None) -> str:
        if not x_nope_key:
            if ALLOW_ANONYMOUS:
                return "local-anonymous"
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-NOPE-Key")
        for expected_key, role in API_KEYS.items():
            if hmac.compare_digest(expected_key, x_nope_key) and role >= minimum:
                return f"api-key:{role.name.lower()}"
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    return dependency


AdminRequired = Annotated[str, Depends(authorize(Role.ADMIN))]
ApproverRequired = Annotated[str, Depends(authorize(Role.APPROVER))]
AgentRequired = Annotated[str, Depends(authorize(Role.AGENT))]
CiRequired = Annotated[str, Depends(authorize(Role.CI))]
