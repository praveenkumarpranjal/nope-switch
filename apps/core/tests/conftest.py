from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import pytest

repo_root = Path(__file__).resolve().parents[3]
# Tests must not touch a developer's real local ledger.
os.environ["DATABASE_URL"] = f"sqlite:///{repo_root / '.data' / 'test-nope.db'}"
os.environ["NOPE_API_KEYS"] = "admin:admin,approver:approver,agent:agent,ci:ci"
os.environ["NOPE_ENV"] = "test"
os.environ["NOPE_SCAN_ROOT"] = str(repo_root)

from nope_core.db import Base, engine  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_clean_database() -> Generator[None, None, None]:
    """Ensure every test runs against a completely clean, hermetic database schema."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
