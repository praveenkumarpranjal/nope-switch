from __future__ import annotations

import logging

from nope_core import assurance  # noqa: F401 -- register additive revision table
from nope_core.db import init_db

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("nope.migrate")


def main() -> None:
    """Create the database schema and seed initial counter sequences.

    This is intentionally additive: it creates missing tables, seeds sequence
    counters if missing, and never drops or rewrites existing records.
    """
    logger.info("starting schema bootstrap and counter seeding")
    init_db()
    logger.info("schema and sequence counters ready")


if __name__ == "__main__":
    main()
