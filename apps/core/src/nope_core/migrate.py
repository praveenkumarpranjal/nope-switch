from __future__ import annotations

import logging

from nope_core.db import Base, engine

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("nope.migrate")


def main() -> None:
    """Create the database schema.

    This is intentionally additive: it creates missing tables and never drops or
    rewrites existing ones. A full versioned migration history can be layered
    over this bootstrap for hosted PostgreSQL environments.
    """
    logger.info("uvicorn starting schema bootstrap")
    Base.metadata.create_all(bind=engine)
    logger.info("schema ready")


if __name__ == "__main__":
    main()
