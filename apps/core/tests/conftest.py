from __future__ import annotations

import os
from pathlib import Path

repo_root = Path(__file__).resolve().parents[3]
# Tests must not touch a developer's real local ledger.
os.environ["DATABASE_URL"] = f"sqlite:///{repo_root / '.data' / 'test-nope.db'}"
os.environ["NOPE_API_KEYS"] = "admin:admin,approver:approver,agent:agent,ci:ci"
os.environ["NOPE_ENV"] = "test"
os.environ["NOPE_SCAN_ROOT"] = str(repo_root)
