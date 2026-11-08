"""Locate bundled assets in both a source checkout and an installed wheel."""

from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    configured = os.getenv("NOPE_PROJECT_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    for root in (Path.cwd(), *Path(__file__).resolve().parents):
        if (root / "pyproject.toml").is_file() and (root / "demo-app").is_dir():
            return root
    return Path.cwd()


def data_root() -> Path:
    return Path(os.getenv("NOPE_WORKDIR", str(project_root() / ".data"))).expanduser().resolve()
