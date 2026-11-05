from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from nope_core.config import settings


class Base(DeclarativeBase):
    pass


def _ensure_sqlite_parent(database_url: str) -> None:
    if not database_url.startswith("sqlite:///"):
        return
    database_path = database_url.replace("sqlite:///", "", 1)
    path = Path(database_path).expanduser()
    if str(path) not in {":memory:", ""}:
        path.parent.mkdir(parents=True, exist_ok=True)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class Scar(Base, TimestampMixin):
    __tablename__ = "scars"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    number: Mapped[int] = mapped_column(Integer, unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    incident_summary: Mapped[str] = mapped_column(Text, nullable=False)
    invariant: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    incident_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    repository: Mapped[str] = mapped_column(String(200), index=True, nullable=False)
    scope: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    enforcement: Mapped[str] = mapped_column(String(24), nullable=False)
    origin: Mapped[str] = mapped_column(String(400), nullable=False)
    proposed_by: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(24), index=True, nullable=False, default="proposed")
    approved_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    approved_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    validations: Mapped[list[ValidationRun]] = relationship(back_populates="scar", cascade="all, delete-orphan")
    exceptions: Mapped[list[ExceptionRecord]] = relationship(back_populates="scar", cascade="all, delete-orphan")
    events: Mapped[list[AuditEvent]] = relationship(back_populates="scar", cascade="all, delete-orphan")
    rule_versions: Mapped[list[RuleVersion]] = relationship(back_populates="scar", cascade="all, delete-orphan")


class RuleVersion(Base, TimestampMixin):
    __tablename__ = "rule_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scar_id: Mapped[str] = mapped_column(ForeignKey("scars.id", ondelete="CASCADE"), index=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_yaml: Mapped[str] = mapped_column(Text, nullable=False)

    scar: Mapped[Scar] = relationship(back_populates="rule_versions")


class ValidationRun(Base, TimestampMixin):
    __tablename__ = "validation_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scar_id: Mapped[str] = mapped_column(ForeignKey("scars.id", ondelete="CASCADE"), index=True, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    bad_findings: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    good_findings: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    rule_errors: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    target_findings: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    scar: Mapped[Scar] = relationship(back_populates="validations")


class ExceptionRecord(Base, TimestampMixin):
    __tablename__ = "exceptions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scar_id: Mapped[str] = mapped_column(ForeignKey("scars.id", ondelete="CASCADE"), index=True, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approver: Mapped[str | None] = mapped_column(String(200), nullable=True)

    scar: Mapped[Scar] = relationship(back_populates="exceptions")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scar_id: Mapped[str | None] = mapped_column(ForeignKey("scars.id", ondelete="SET NULL"), index=True, nullable=True)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)

    scar: Mapped[Scar | None] = relationship(back_populates="events")


_ensure_sqlite_parent(settings.database_url)
engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db() -> None:
    """Create the local SQLite schema; production runs Alembic migrations first."""
    Base.metadata.create_all(bind=engine)


def new_id(prefix: str) -> str:
    from uuid import uuid4

    return f"{prefix}_{uuid4().hex[:24]}"
