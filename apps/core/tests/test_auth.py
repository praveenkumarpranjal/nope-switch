from __future__ import annotations

import os

from nope_core.auth import Role, parse_api_keys


def test_api_keys_are_explicit_and_role_checked() -> None:
    assert os.environ["NOPE_API_KEYS"] == "admin:admin,approver:approver,agent:agent,ci:ci"
    assert parse_api_keys()["approver"] == Role.APPROVER
    assert parse_api_keys()["agent"] < Role.APPROVER
