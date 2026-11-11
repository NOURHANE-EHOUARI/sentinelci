"""Database tables (SQLAlchemy 2). Every change here needs an Alembic migration (tests/test_schema.py)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, deferred, mapped_column, relationship


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
        # The uploaded bytes are kept only as the bytes the recorded digest was taken of.
        CheckConstraint(
            "findings_ndjson IS NULL OR "
            "(findings_sha256 IS NOT NULL AND encode(sha256(findings_ndjson), 'hex') = findings_sha256)",
            name="runs_findings_bytes_match",
        ),
        # One run per CI run: a re-run of the upload step gets the existing run (409), never a second one.
        Index(
            "runs_ci_run",
            "repo",
            "commit",
            "context",
            "ci_run_id",
            unique=True,
            postgresql_where=text("ci_run_id IS NOT NULL"),
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
    # The upload itself, byte for byte (since API 1.2.0): what a consumer hashes to get `findings_sha256`,
    # for example the correlator. Loaded only when asked for. Null for a run recorded before it was kept.
    findings_ndjson: Mapped[bytes | None] = deferred(mapped_column(LargeBinary))

    findings: Mapped[list[RunFinding]] = relationship(back_populates="run", cascade="all, delete-orphan")


class RunFinding(Base):
    """A Finding v1 document as one run reported it. The same fingerprint recurs across runs."""

    __tablename__ = "findings"
    __table_args__ = (Index("findings_finding_id", "finding_id"),)

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Copies of document fields, for filtering. The document is kept as JSON (JSONB keeps neither key order
    # nor bytes); the exact upload is identified by `runs.findings_sha256`.
    category: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    tool: Mapped[str] = mapped_column(Text, index=True)
    rule_id: Mapped[str] = mapped_column(Text)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB)

    run: Mapped[Run] = relationship(back_populates="findings")


class Correlation(Base):
    """One version of a run's correlation (Correlation v1, A7), kept byte for byte. Advisory: never read by
    the gate. A version is named by the sha256 of its bytes; the latest is the one recorded last (`seq`)."""

    __tablename__ = "correlations"
    __table_args__ = (
        CheckConstraint("sha256 ~ '^[a-f0-9]{64}$'", name="correlations_sha256"),
        # The bytes are kept only as the bytes the version's name was taken of.
        CheckConstraint("encode(sha256(document), 'hex') = sha256", name="correlations_bytes_match"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    # The order of recording, for "the latest version": created_at can tie.
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), unique=True)
    correlator_version: Mapped[str] = mapped_column(String(64))
    group_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    document: Mapped[bytes] = deferred(mapped_column(LargeBinary, nullable=False))
