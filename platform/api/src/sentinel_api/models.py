"""Database tables (SQLAlchemy 2). Every change here needs an Alembic migration (tests/test_schema.py)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Run(Base):
    """One pipeline run (Finding v1 `run`): what was scanned, and the findings it reported."""

    __tablename__ = "runs"
    __table_args__ = (
        CheckConstraint("context IN ('pr', 'release', 'local')", name="runs_context"),
        CheckConstraint("commit ~ '^[a-f0-9]{40}$'", name="runs_commit"),
        CheckConstraint(
            "(findings_sha256 IS NULL) = (findings_uploaded_at IS NULL)", name="runs_findings_recorded_once"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    repo: Mapped[str] = mapped_column(String(200), index=True)
    commit: Mapped[str] = mapped_column(String(40))
    context: Mapped[str] = mapped_column(String(16))
    ref: Mapped[str | None] = mapped_column(String(255))
    ci_run_id: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # sha256 of the uploaded NDJSON bytes: the evidence the platform holds for this run.
    findings_sha256: Mapped[str | None] = mapped_column(String(64))
    findings_uploaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finding_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    findings: Mapped[list[RunFinding]] = relationship(back_populates="run", cascade="all, delete-orphan")


class RunFinding(Base):
    """A Finding v1 document as one run reported it. The same fingerprint recurs across runs."""

    __tablename__ = "findings"
    __table_args__ = (Index("findings_finding_id", "finding_id"),)

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Copies of document fields, for filtering; the document itself stays exactly as uploaded.
    category: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    tool: Mapped[str] = mapped_column(Text, index=True)
    rule_id: Mapped[str] = mapped_column(Text)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB)

    run: Mapped[Run] = relationship(back_populates="findings")
