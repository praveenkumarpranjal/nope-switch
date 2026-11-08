from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from nope_core.paths import project_root


def test_reset_preserves_reports_and_room_evidence(tmp_path: Path) -> None:
    sentinel = tmp_path / "room-evidence.json"
    sentinel.write_text('{"verified":true}', encoding="utf-8")
    environment = {**os.environ, "NOPE_WORKDIR": str(tmp_path),
                   "DATABASE_URL": f"sqlite:///{tmp_path / 'offline.db'}"}
    result = subprocess.run([sys.executable, "-m", "nope_core.demo", "reset"],
                            env=environment, capture_output=True, text=True, encoding="utf-8")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "offline.db").is_file()
    assert sentinel.read_text(encoding="utf-8") == '{"verified":true}'


def test_assets_resolve_from_another_working_directory(tmp_path: Path) -> None:
    root = project_root()
    result = subprocess.run([sys.executable, "-c",
        "from nope_core.paths import project_root; print(project_root())"],
        cwd=tmp_path, capture_output=True, text=True, encoding="utf-8")
    assert result.returncode == 0, result.stderr
    assert Path(result.stdout.strip()) == root
