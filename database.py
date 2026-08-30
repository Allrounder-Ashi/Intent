"""
Shared Intelligence Database (SQLite via SQLAlchemy)
------------------------------------------------------
Minimal, hackathon-scoped version of the diagram's 6 databases, collapsed
into tables that actually matter for a working demo:

  - Report            -> Reports & Evidence DB + Analysis & Incidents DB
  - ReportedIdentifier -> Reported Identifiers DB (phone/UPI/URL/email lookups)
  - AuditLog           -> Audit & Logs DB

User & Org DB / Feedback & Actions DB are represented as simple columns on
Report (status, notes) rather than separate tables, to keep this shippable
in 1-2 days. Swap for Postgres later by just changing DATABASE_URL.
"""
import datetime
import enum

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, Text, DateTime, Enum
)
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./protectx.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ReportStatus(str, enum.Enum):
    new = "new"
    investigating = "investigating"
    verified = "verified"
    resolved = "resolved"


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Raw evidence submitted by the citizen
    phone_number = Column(String, index=True, nullable=True)
    upi_id = Column(String, index=True, nullable=True)
    reported_url = Column(String, index=True, nullable=True)
    email = Column(String, index=True, nullable=True)
    transcript_text = Column(Text, nullable=True)
    sms_text = Column(Text, nullable=True)
    ocr_text = Column(Text, nullable=True)
    other_details = Column(Text, nullable=True)

    # Person 1 output
    extracted_metadata_json = Column(Text, nullable=True)

    # Person 2 output (AI analysis) - now includes scam_type, tactics_used,
    # confidence_score, summary as of their updated scam_detector.py
    ai_analysis_json = Column(Text, nullable=True)

    # Person 3 output (rules / link / rbi / identifier_analysis - now covers
    # UPI IDs and bank accounts too, not just phone numbers)
    security_check_json = Column(Text, nullable=True)

    # Person 4: Risk Assessment & Decision Engine output
    risk_score = Column(Float, nullable=True)          # 0-100
    risk_label = Column(String, nullable=True)          # low / medium / high
    risk_confidence = Column(Float, nullable=True)      # 0-1
    risk_reasoning_json = Column(Text, nullable=True)   # list[str]
    is_scam = Column(Boolean, default=False)

    # Agency workflow
    status = Column(Enum(ReportStatus), default=ReportStatus.new)
    agency_notes = Column(Text, nullable=True)


class ReportedIdentifier(Base):
    """Aggregated view: how many times has this phone/UPI/URL/email been flagged."""
    __tablename__ = "reported_identifiers"

    id = Column(Integer, primary_key=True, index=True)
    identifier = Column(String, index=True, unique=True)
    identifier_type = Column(String)  # phone | upi | url | email
    report_count = Column(Integer, default=0)
    max_risk_label = Column(String, default="low")
    last_reported_at = Column(DateTime, default=datetime.datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    actor = Column(String)       # "citizen" | "agency:<name>" | "system"
    action = Column(String)      # "report_submitted" | "case_updated" | "search"
    detail = Column(Text, nullable=True)
    report_id = Column(Integer, nullable=True)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
