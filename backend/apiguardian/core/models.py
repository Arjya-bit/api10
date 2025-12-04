"""SQLAlchemy Data Models for APIGuardian"""
import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Index, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import os

Base = declarative_base()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssetType(str, Enum):
    URL = "url"
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    ENDPOINT = "endpoint"


class Asset(Base):
    """Asset being monitored/scanned"""
    __tablename__ = "assets"
    
    id = Column(String(36), primary_key=True)
    value = Column(String(2048), nullable=False, index=True)
    type = Column(String(50), nullable=False)
    resolved_ips = Column(JSON, default=list)
    open_ports = Column(JSON, default=list)
    internal = Column(Boolean, default=False)
    asset_metadata = Column(JSON, default=dict)  # renamed from metadata (reserved)
    added_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    findings = relationship("Finding", back_populates="asset")
    
    __table_args__ = (
        Index('ix_assets_type_value', 'type', 'value'),
    )


class Finding(Base):
    """Security finding/vulnerability"""
    __tablename__ = "findings"
    
    id = Column(String(36), primary_key=True)
    fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey('assets.id'), nullable=True)
    
    issue = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False, index=True)
    category = Column(String(100))
    
    endpoint = Column(String(2048))
    method = Column(String(10))
    evidence = Column(Text)
    raw = Column(JSON, default=dict)
    
    cwe_id = Column(String(20))
    cvss_score = Column(Float)
    recommendation = Column(Text)
    
    status = Column(String(20), default=FindingStatus.OPEN.value, index=True)
    assigned_to = Column(String(100))
    comments = Column(JSON, default=list)
    
    plugin_name = Column(String(100))
    scan_job_id = Column(String(36), ForeignKey('scan_jobs.id'), nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    asset = relationship("Asset", back_populates="findings")
    scan_job = relationship("ScanJob", back_populates="findings")
    
    @staticmethod
    def generate_fingerprint(issue: str, endpoint: str, method: str, evidence: str = "") -> str:
        """Generate unique fingerprint for deduplication"""
        canonical = f"{issue}|{endpoint}|{method}|{evidence}"
        return hashlib.sha256(canonical.encode()).hexdigest()


class ScanJob(Base):
    """Scan job configuration and status"""
    __tablename__ = "scan_jobs"
    
    id = Column(String(36), primary_key=True)
    name = Column(String(256), nullable=False)
    type = Column(String(50), nullable=False)  # full, quick, targeted, scheduled
    target = Column(String(2048))
    
    config = Column(JSON, default=dict)
    modules = Column(JSON, default=list)  # List of plugin names to run
    schedule = Column(String(100))  # Cron expression for scheduled jobs
    
    status = Column(String(20), default=JobStatus.PENDING.value, index=True)
    progress = Column(Integer, default=0)
    
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_run = Column(DateTime)
    
    error_message = Column(Text)
    
    findings = relationship("Finding", back_populates="scan_job")
    plugin_runs = relationship("PluginRun", back_populates="scan_job")


class PluginRun(Base):
    """Individual plugin execution record"""
    __tablename__ = "plugin_runs"
    
    id = Column(String(36), primary_key=True)
    plugin = Column(String(100), nullable=False, index=True)
    plugin_type = Column(String(50))  # analyzer, fuzzer, recon
    
    scan_job_id = Column(String(36), ForeignKey('scan_jobs.id'), nullable=True)
    
    status = Column(String(20), default=JobStatus.PENDING.value)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    
    result_summary = Column(JSON, default=dict)
    findings_generated = Column(Integer, default=0)
    error_message = Column(Text)
    
    scan_job = relationship("ScanJob", back_populates="plugin_runs")


class ThreatIntelResult(Base):
    """Cached threat intelligence lookup results"""
    __tablename__ = "threat_intel_results"
    
    id = Column(String(36), primary_key=True)
    indicator = Column(String(2048), nullable=False, index=True)
    indicator_type = Column(String(20), nullable=False)  # ip, url, hash
    
    service = Column(String(50), nullable=False)  # virustotal, abuseipdb, etc
    result = Column(JSON, default=dict)
    
    malicious_score = Column(Integer, default=0)
    threat_level = Column(String(20))
    
    queried_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime)  # Cache expiry
    
    __table_args__ = (
        Index('ix_ti_indicator_service', 'indicator', 'service'),
    )


class Metric(Base):
    """Time-series metrics for anomaly detection"""
    __tablename__ = "metrics"
    
    id = Column(String(36), primary_key=True)
    name = Column(String(100), nullable=False, index=True)
    value = Column(Float, nullable=False)
    labels = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class User(Base):
    """Basic user model for access control"""
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(256))
    role = Column(String(50), default="analyst")  # admin, analyst, viewer
    api_key = Column(String(64))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime)


class IntegrationConfig(Base):
    """Configuration for external integrations"""
    __tablename__ = "integration_configs"
    
    id = Column(String(36), primary_key=True)
    service = Column(String(50), unique=True, nullable=False)
    enabled = Column(Boolean, default=False)
    mode = Column(String(20), default="mock")  # mock or live
    config = Column(JSON, default=dict)
    last_tested = Column(DateTime)
    status = Column(String(20), default="unknown")  # active, error, disabled


# Database initialization
def get_engine(db_url: str = None):
    """Get SQLAlchemy engine"""
    if db_url is None:
        db_path = os.environ.get('APIGUARDIAN_DB', '/app/backend/apiguardian.db')
        db_url = f"sqlite:///{db_path}"
    return create_engine(db_url, echo=False)


def get_session(engine=None):
    """Get database session"""
    if engine is None:
        engine = get_engine()
    Session = sessionmaker(bind=engine)
    return Session()


def init_db(engine=None):
    """Initialize database tables"""
    if engine is None:
        engine = get_engine()
    Base.metadata.create_all(engine)
    return engine
