"""Reuse an explicitly selected Console credential file in memory only."""

from __future__ import annotations

import json
import os
from pathlib import Path

from nope_switch.transport import SwitchError


def load_credentials(path: Path) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        env = document["env"]
        if not isinstance(env, dict):
            raise ValueError("Runtime environment must be an object")
        required = ("SWITCH_API_ENDPOINT", "SWITCH_API_TOKEN", "SWITCH_AGENT_ID")
        if not all(isinstance(env.get(key), str) and env[key] for key in required):
            raise ValueError("Missing runtime fields")
    except (OSError, ValueError, KeyError, TypeError):
        raise SwitchError(
            "Cannot read the selected Console agent's existing runtime credentials"
        ) from None
    for key in (*required, "SWITCH_CONNECTION_ID"):
        if isinstance(env.get(key), str):
            os.environ[key] = env[key]
    os.environ["NOPE_SWITCH_ENABLED"] = "true"
