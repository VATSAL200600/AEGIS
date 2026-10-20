"""AEGIS Database Models (SQLAlchemy 2.0 Declarative)"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from app.database import Base


def gen_uuid() -> str:
    """Generate string UUID for primary keys."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=gen_uuid, index=True)
    target_domain = Column(String(255), nullable=False, index=True)
    scan_profile = Column(String(32), default="standard")  # quick, standard, deep
    status = Column(String(32), default="pending")  # pending, running, completed, failed
    progress_percent = Column(Integer, default=0)
    current_phase = Column(String(64), nullable=True)

    # Aggregated Summary Stats
    total_assets = Column(Integer, default=0)
    avg_risk_score = Column(Float, default=0.0)
    max_risk_score = Column(Float, default=0.0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    error_message = Column(Text, nullable=True)
    scan_log = Column(Text, default="")
    started_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    # Relationships with CASCADE delete
    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=gen_uuid, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True, index=True)
    is_apex = Column(Boolean, default=False)
    is_live = Column(Boolean, default=True)

    # AI Risk Scoring
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(16), default="info")  # critical, high, medium, low, info
    shap_explanation = Column(JSON, default=dict)

    # Metadata & Recon
    http_status = Column(Integer, nullable=True)
    http_title = Column(String(500), nullable=True)
    country = Column(String(64), nullable=True)
    asn = Column(String(64), nullable=True)
    screenshot_path = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="assets")
    ports = relationship("Port", back_populates="asset", cascade="all, delete-orphan")
    technologies = relationship("Technology", back_populates="asset", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
    ssl_cert = relationship("SSLCertificate", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    security_headers = relationship("SecurityHeader", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    dns_records = relationship("DNSRecord", back_populates="asset", cascade="all, delete-orphan")
    threat_intel = relationship("ThreatIntel", back_populates="asset", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"

    id = Column(String(36), primary_key=True, default=gen_uuid, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    state = Column(String(20), default="open")  # open, filtered, closed
    service_name = Column(String(100), nullable=True)
    service_version = Column(String(200), nullable=True)
    banner = Column(Text, nullable=True)
    is_critical = Column(Boolean, default=False)

    asset = relationship("Asset", back_populates="ports")


class Technology(Base):
    __tablename__ = "technologies"

    id = Column(String(36), primary_key=True, default=gen_uuid, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    version = Column(String(100), nullable=True)
    category = Column(String(100), nullable=True)  # CMS, Web Server, Framework, CDN, etc.
    confidence = Column(Integer, default=100)
    is_outdated = Column(Boolean, default=False)
    detection_method = Column(String(100), nullable=True)

    asset = relationship("Asset", back_populates="technologies")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=gen_uuid, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(String(32), nullable=True, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), default="medium")  # critical, high, medium, low
    cvss_score = Column(Float, nullable=True)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    is_cisa_kev = Column(Boolean, default=False)
    affected_component = Column(String(200), nullable=True)
    remediation = Column(Text, nullable=True)
    references = Column(JSON, default=list)

    asset = relationship("Asset", back_populates="vulnerabilities")


class SSLCertificate(Base):
    __tablename__ = "ssl_certificates"

    id = Column(String(36), primary_key=True, default=gen_uuid, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    issuer = Column(String(500), nullable=True)
    subject = Column(String(500), nullable=True)
    valid_from = Column(DateTime, nullable=True)
    valid_to = Column(DateTime, nullable=True)
    expires_in_days = Column(Integer, default=0)
    is_expired = Column(Boolean, default=False)
    is_self_signed = Column(Boolean, default=False)
    has_weak_cipher = Column(Boolean, default=False)
    has_weak_protocol = Column(Boolean, default=False)
    tls_version = Column(String(32), nullable=True)
    cipher_suite = Column(String(128), nullable=True)
    san_entries = Column(JSON, default=list)

    asset = relationship("Asset", back_populates="ssl_cert")


class SecurityHeader(Base):
    __tablename__ = "security_headers"

    id = Column(String(36), primary_key=True, default=gen_uuid, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    grade = Column(String(4), default="F")  # A+, A, B, C, D, F
    score = Column(Integer, default=0)  # 0 to 100
    hsts = Column(Boolean, default=False)
    csp = Column(Boolean, default=False)
    x_frame_options = Column(String(32), nullable=True)
    x_content_type = Column(Boolean, default=False)
    referrer_policy = Column(String(64), nullable=True)
    permissions_policy = Column(Boolean, default=False)
    cors_misconfigured = Column(Boolean, default=False)
    raw_headers = Column(JSON, default=dict)

    asset = relationship("Asset", back_populates="security_headers")


class DNSRecord(Base):
    __tablename__ = "dns_records"

    id = Column(String(36), primary_key=True, default=gen_uuid, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    record_type = Column(String(10), nullable=False)  # A, AAAA, CNAME, MX, TXT, NS, SOA
    record_value = Column(Text, nullable=False)
    ttl = Column(Integer, nullable=True)
    is_dangling = Column(Boolean, default=False)
    is_misconfigured = Column(Boolean, default=False)
    finding = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="dns_records")


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id = Column(String(36), primary_key=True, default=gen_uuid, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(100), nullable=False)  # shodan, virustotal, abuseipdb
    intel_type = Column(String(100), nullable=True)
    data = Column(JSON, default=dict)
    risk_indicator = Column(String(20), nullable=True)
    retrieved_at = Column(DateTime, default=utcnow)

    asset = relationship("Asset", back_populates="threat_intel")


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=gen_uuid, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type = Column(String(32), default="executive")  # executive, technical, remediation
    title = Column(String(500), nullable=False)
    executive_summary = Column(Text, nullable=True)
    attack_surface_analysis = Column(Text, nullable=True)
    remediation_plan = Column(JSON, default=list)
    html_content = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    scan = relationship("Scan", back_populates="reports")
