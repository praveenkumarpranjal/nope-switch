from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Runtime configuration with production-safe defaults."""

    env: str = os.getenv("NOPE_ENV", "production")
    database_url: str = os.getenv(
        "DATABASE_URL", f"sqlite:///{Path(os.getenv('NOPE_WORKDIR', '.data')) / 'nope.db'}"
    )
    approval_ttl_days: int = int(os.getenv("NOPE_APPROVAL_TTL_DAYS", "90"))
    exception_ttl_days: int = int(os.getenv("NOPE_EXCEPTION_TTL_DAYS", "14"))
    min_bad_fixture_hits: int = int(os.getenv("NOPE_MIN_BAD_FIXTURE_HITS", "1"))
    max_good_fixture_hits: int = int(os.getenv("NOPE_MAX_GOOD_FIXTURE_HITS", "0"))
    baseline_enforce: bool = os.getenv("NOPE_BASELINE_ENFORCE", "false") == "true"
    github_webhook_secret: str = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    base_ref: str = os.getenv("NOPE_BASE_REF", "origin/main")
    allow_anonymous: bool = os.getenv("NOPE_ALLOW_ANONYMOUS", "false") == "true"

    @property
    def is_development(self) -> bool:
        return self.env.lower() in {"dev", "development", "test"}


settings = Settings()
