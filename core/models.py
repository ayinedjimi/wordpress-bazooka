"""Pydantic models for WordPress BAZOOKA findings and scan metadata."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


class FPPotential(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingType(str, Enum):
    CVE = "cve"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DESIGN_FLAW = "design_flaw"


class Evidence(BaseModel):
    request: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_excerpt: Optional[str] = None
    screenshot: Optional[str] = None
    file: Optional[str] = None


class Compliance(BaseModel):
    owasp_2021: Optional[str] = None
    cwe: Optional[str] = None
    mitre_attack: Optional[str] = None
    pci_dss_v4: Optional[str] = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    cvss_score: float = 0.0
    cvss_vector: str = ""
    confidence: Confidence = Confidence.CONFIRMED
    false_positive_potential: FPPotential = FPPotential.LOW
    category: str = ""
    finding_type: FindingType = FindingType.MISCONFIGURATION
    description: str = ""
    evidence: Evidence = Field(default_factory=Evidence)
    impact: str = ""
    remediation: str = ""
    compliance: Compliance = Field(default_factory=Compliance)
    references: list[str] = Field(default_factory=list)
    chain_ids: list[str] = Field(default_factory=list)
    phase: str = ""
    module: str = ""
    disclosure_method: str = "active_test"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tags: list[str] = Field(default_factory=list)


class ScanMeta(BaseModel):
    bazooka_version: str = "1.0.0"
    schema_version: str = "2.0"
    cve_db_version: str = ""
    target: str = ""
    scope_file: Optional[str] = None
    authorization_ref: Optional[str] = None
    profile: str = "standard"
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    total_requests: int = 0
    modules_executed: int = 0
    modules_skipped: int = 0
    modules_failed: int = 0


class WPUser(BaseModel):
    id: int
    username: str = ""
    display_name: str = ""
    slug: str = ""
    avatar_url: str = ""
    gravatar_hash: str = ""
    email: Optional[str] = None
    role: Optional[str] = None
    discovery_method: str = ""


class WPPlugin(BaseModel):
    slug: str
    version: Optional[str] = None
    name: Optional[str] = None
    author: Optional[str] = None
    discovery_method: str = ""
    cves: list[dict] = Field(default_factory=list)


class WPTheme(BaseModel):
    slug: str
    version: Optional[str] = None
    name: Optional[str] = None
    author: Optional[str] = None
    parent: Optional[str] = None
    discovery_method: str = ""
    cves: list[dict] = Field(default_factory=list)


class Target(BaseModel):
    url: str
    domain: str = ""
    ip: Optional[str] = None
    origin_ip: Optional[str] = None
    cdn_detected: bool = False
    waf_detected: Optional[str] = None
    wp_version: Optional[str] = None
    wp_content_path: str = "/wp-content/"
    users: list[WPUser] = Field(default_factory=list)
    plugins: list[WPPlugin] = Field(default_factory=list)
    themes: list[WPTheme] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    meta: ScanMeta = Field(default_factory=ScanMeta)
