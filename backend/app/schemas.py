"""AEGIS Pydantic v2 Schemas for Request/Response Validation and Serialization"""
from datetime import datetime
from typing import Optional, List, Dict, Any, Generic, TypeVar
from pydantic import BaseModel, Field, ConfigDict

T = TypeVar("T")


# --- Standard API Envelopes ---
class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorDetail


class SuccessEnvelope(BaseModel, Generic[T]):
    success: bool = True
    data: T
    message: str = "Operation completed successfully"


# --- Scan Schemas ---
class ScanCreate(BaseModel):
    target_domain: str = Field(..., min_length=3, max_length=255, examples=["example.com"])
    scan_profile: str = Field(default="standard", pattern="^(quick|standard|deep)$")
    enable_threat_intel: bool = True
    enable_port_scan: bool = True


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    progress_percent: Optional[int] = None
    current_phase: Optional[str] = None
    total_assets: Optional[int] = None
    avg_risk_score: Optional[float] = None
    max_risk_score: Optional[float] = None
    critical_count: Optional[int] = None
    high_count: Optional[int] = None
    medium_count: Optional[int] = None
    low_count: Optional[int] = None
    info_count: Optional[int] = None
    error_message: Optional[str] = None
    completed_at: Optional[datetime] = None


class ScanResponse(BaseModel):
    id: str
    target_domain: str
    scan_profile: str
    status: str
    progress_percent: int = 0
    current_phase: Optional[str] = None
    total_assets: int = 0
    avg_risk_score: float = 0.0
    max_risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    error_message: Optional[str] = None
    scan_log: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    pages: int


# --- Recon Finding Schemas ---
class PortResponse(BaseModel):
    id: str
    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    is_critical: bool = False

    model_config = ConfigDict(from_attributes=True)


class TechnologyResponse(BaseModel):
    id: str
    name: str
    version: Optional[str] = None
    category: Optional[str] = None
    confidence: int = 100
    is_outdated: bool = False
    detection_method: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class VulnerabilityResponse(BaseModel):
    id: str
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_cisa_kev: bool = False
    affected_component: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = []

    model_config = ConfigDict(from_attributes=True)


class SSLCertResponse(BaseModel):
    id: str
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    expires_in_days: int = 0
    is_expired: bool = False
    is_self_signed: bool = False
    has_weak_cipher: bool = False
    has_weak_protocol: bool = False
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    san_entries: List[str] = []

    model_config = ConfigDict(from_attributes=True)


class SecurityHeaderResponse(BaseModel):
    id: str
    grade: str = "F"
    score: int = 0
    hsts: bool = False
    csp: bool = False
    x_frame_options: Optional[str] = None
    x_content_type: bool = False
    referrer_policy: Optional[str] = None
    permissions_policy: bool = False
    cors_misconfigured: bool = False
    raw_headers: Dict[str, Any] = {}

    model_config = ConfigDict(from_attributes=True)


class DNSRecordResponse(BaseModel):
    id: str
    record_type: str
    record_value: str
    ttl: Optional[int] = None
    is_dangling: bool = False
    is_misconfigured: bool = False
    finding: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ThreatIntelResponse(BaseModel):
    id: str
    source: str
    intel_type: Optional[str] = None
    data: Dict[str, Any] = {}
    risk_indicator: Optional[str] = None
    retrieved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# --- Asset Schemas ---
class AssetSummary(BaseModel):
    id: str
    scan_id: str
    hostname: str
    ip_address: Optional[str] = None
    is_apex: bool = False
    is_live: bool = True
    risk_score: float = 0.0
    risk_level: str = "info"
    open_ports: List[int] = []
    technologies: List[str] = []
    vulnerabilities_count: int = 0
    ssl_status: Optional[str] = None
    header_grade: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AssetDetail(BaseModel):
    id: str
    scan_id: str
    hostname: str
    ip_address: Optional[str] = None
    is_apex: bool = False
    is_live: bool = True
    risk_score: float = 0.0
    risk_level: str = "info"
    shap_explanation: Dict[str, Any] = {}
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    screenshot_path: Optional[str] = None
    created_at: Optional[datetime] = None

    ports: List[PortResponse] = []
    technologies: List[TechnologyResponse] = []
    vulnerabilities: List[VulnerabilityResponse] = []
    ssl_cert: Optional[SSLCertResponse] = None
    security_headers: Optional[SecurityHeaderResponse] = None
    dns_records: List[DNSRecordResponse] = []
    threat_intel: List[ThreatIntelResponse] = []

    model_config = ConfigDict(from_attributes=True)


# --- Dashboard Schemas ---
class DashboardStats(BaseModel):
    total_scans: int = 0
    total_assets_monitored: int = 0
    overall_security_posture_score: float = 0.0
    severity_distribution: Dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    top_vulnerable_assets: List[Dict[str, Any]] = []
    exposed_critical_ports: Dict[str, int] = {}
    common_technologies: List[Dict[str, Any]] = []


# --- Report Schemas ---
class ReportCreate(BaseModel):
    scan_id: str
    report_type: str = Field(default="executive", pattern="^(executive|technical|compliance)$")
    provider: str = Field(default="gemini", pattern="^(gemini|template)$")


class ReportResponse(BaseModel):
    id: str
    scan_id: str
    report_type: str
    title: str
    executive_summary: Optional[str] = None
    attack_surface_analysis: Optional[str] = None
    remediation_plan: List[Dict[str, Any]] = []
    html_content: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
