from __future__ import annotations

import os

import pytest
from fastapi import HTTPException
from nope_core import auth
from nope_core.auth import Role, authorize, parse_api_keys


def test_api_keys_are_explicit_and_role_checked() -> None:
    assert os.environ["NOPE_API_KEYS"] == "admin:admin,approver:approver,agent:agent,ci:ci"
    assert parse_api_keys()["approver"] == Role.APPROVER
    assert parse_api_keys()["agent"] < Role.APPROVER


@pytest.mark.parametrize("role", [Role.APPROVER, Role.ADMIN])
@pytest.mark.asyncio
async def test_anonymous_mode_never_grants_approval_or_admin(role: Role, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "ALLOW_ANONYMOUS", True)
    with pytest.raises(HTTPException) as rejected:
        await authorize(role)(None)
    assert rejected.value.status_code == 401


@pytest.mark.asyncio
async def test_anonymous_mode_is_development_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "ALLOW_ANONYMOUS", True)
    monkeypatch.setenv("NOPE_ENV", "production")
    with pytest.raises(HTTPException) as rejected:
        await authorize(Role.AGENT)(None)
    assert rejected.value.status_code == 401
    monkeypatch.setenv("NOPE_ENV", "development")
    assert await authorize(Role.AGENT)(None) == "local-anonymous"


@pytest.mark.asyncio
async def test_non_ascii_key_is_rejected_without_server_error() -> None:
    with pytest.raises(HTTPException) as rejected:
        await authorize(Role.AGENT)("invalid-é-key")
    assert rejected.value.status_code == 403


@pytest.mark.parametrize("setting", [":admin", "same:agent,same:admin"])
def test_ambiguous_key_configuration_is_rejected(setting: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOPE_API_KEYS", setting)
    with pytest.raises(RuntimeError, match="non-empty, unique"):
        parse_api_keys()
