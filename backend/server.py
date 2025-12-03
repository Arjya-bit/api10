from fastapi import FastAPI, APIRouter, HTTPException, Query
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
from enum import Enum
import httpx
import base64


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# API Keys for external integrations
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')

# Create the main app without a prefix
app = FastAPI(title="APIGuardian", description="API Security Testing & Monitoring Platform")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


# Enums
class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class AlertType(str, Enum):
    VULNERABILITY = "vulnerability"
    ANOMALY = "anomaly"
    RATE_LIMIT = "rate_limit"
    AUTH_FAILURE = "auth_failure"
    INJECTION = "injection"


# Models
class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: SeverityLevel
    endpoint: str
    method: str = "GET"
    category: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    recommendation: Optional[str] = None
    status: str = "open"  # open, in_progress, resolved, false_positive
    scan_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class VulnerabilityCreate(BaseModel):
    title: str
    description: str
    severity: SeverityLevel
    endpoint: str
    method: str = "GET"
    category: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    recommendation: Optional[str] = None


class Scan(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    target_url: str
    scan_type: str  # full, quick, authentication, authorization
    status: ScanStatus = ScanStatus.PENDING
    modules: List[str] = []
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    progress: int = 0

class ScanCreate(BaseModel):
    name: str
    target_url: str
    scan_type: str = "full"
    modules: List[str] = []


class Alert(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    message: str
    alert_type: AlertType
    severity: SeverityLevel
    source: str
    endpoint: Optional[str] = None
    metadata: Dict[str, Any] = {}
    acknowledged: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AlertCreate(BaseModel):
    title: str
    message: str
    alert_type: AlertType
    severity: SeverityLevel
    source: str
    endpoint: Optional[str] = None
    metadata: Dict[str, Any] = {}


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    path: str
    method: str
    description: Optional[str] = None
    auth_required: bool = False
    risk_score: float = 0.0
    last_scanned: Optional[datetime] = None
    vulnerabilities_count: int = 0
    status: str = "active"  # active, deprecated, inactive
    tags: List[str] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class EndpointCreate(BaseModel):
    path: str
    method: str
    description: Optional[str] = None
    auth_required: bool = False
    tags: List[str] = []


class Metric(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    value: float
    unit: str
    category: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Report(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    scan_id: Optional[str] = None
    report_type: str  # json, html, pdf
    content: Dict[str, Any] = {}
    file_path: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Helper function for datetime serialization
def serialize_doc(doc: dict) -> dict:
    """Convert datetime objects to ISO strings for MongoDB storage"""
    for key, value in doc.items():
        if isinstance(value, datetime):
            doc[key] = value.isoformat()
    return doc

def deserialize_doc(doc: dict) -> dict:
    """Convert ISO strings back to datetime objects"""
    datetime_fields = ['created_at', 'updated_at', 'started_at', 'completed_at', 'timestamp', 'last_scanned']
    for key in datetime_fields:
        if key in doc and isinstance(doc[key], str):
            doc[key] = datetime.fromisoformat(doc[key])
    return doc


# Root endpoint
@api_router.get("/")
async def root():
    return {"message": "APIGuardian API Security Platform", "version": "1.0.0"}


# Dashboard Stats
@api_router.get("/dashboard/stats")
async def get_dashboard_stats():
    """Get aggregated dashboard statistics"""
    total_vulnerabilities = await db.vulnerabilities.count_documents({})
    critical_vulns = await db.vulnerabilities.count_documents({"severity": "critical"})
    high_vulns = await db.vulnerabilities.count_documents({"severity": "high"})
    medium_vulns = await db.vulnerabilities.count_documents({"severity": "medium"})
    low_vulns = await db.vulnerabilities.count_documents({"severity": "low"})
    
    open_vulns = await db.vulnerabilities.count_documents({"status": "open"})
    resolved_vulns = await db.vulnerabilities.count_documents({"status": "resolved"})
    
    total_scans = await db.scans.count_documents({})
    completed_scans = await db.scans.count_documents({"status": "completed"})
    running_scans = await db.scans.count_documents({"status": "running"})
    
    total_endpoints = await db.endpoints.count_documents({})
    unacked_alerts = await db.alerts.count_documents({"acknowledged": False})
    
    return {
        "vulnerabilities": {
            "total": total_vulnerabilities,
            "critical": critical_vulns,
            "high": high_vulns,
            "medium": medium_vulns,
            "low": low_vulns,
            "open": open_vulns,
            "resolved": resolved_vulns
        },
        "scans": {
            "total": total_scans,
            "completed": completed_scans,
            "running": running_scans
        },
        "endpoints": total_endpoints,
        "unacknowledged_alerts": unacked_alerts,
        "security_score": max(0, 100 - (critical_vulns * 20 + high_vulns * 10 + medium_vulns * 5 + low_vulns))
    }


# Vulnerability endpoints
@api_router.get("/vulnerabilities", response_model=List[Vulnerability])
async def get_vulnerabilities(
    severity: Optional[SeverityLevel] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
):
    """Get all vulnerabilities with optional filters"""
    query = {}
    if severity:
        query["severity"] = severity.value
    if status:
        query["status"] = status
    if category:
        query["category"] = category
    
    vulns = await db.vulnerabilities.find(query, {"_id": 0}).skip(skip).limit(limit).to_list(limit)
    return [deserialize_doc(v) for v in vulns]

@api_router.post("/vulnerabilities", response_model=Vulnerability)
async def create_vulnerability(vuln: VulnerabilityCreate):
    """Create a new vulnerability"""
    vuln_obj = Vulnerability(**vuln.model_dump())
    doc = serialize_doc(vuln_obj.model_dump())
    await db.vulnerabilities.insert_one(doc)
    return vuln_obj

@api_router.get("/vulnerabilities/{vuln_id}", response_model=Vulnerability)
async def get_vulnerability(vuln_id: str):
    """Get a specific vulnerability"""
    vuln = await db.vulnerabilities.find_one({"id": vuln_id}, {"_id": 0})
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return deserialize_doc(vuln)

@api_router.patch("/vulnerabilities/{vuln_id}")
async def update_vulnerability_status(vuln_id: str, status: str):
    """Update vulnerability status"""
    result = await db.vulnerabilities.update_one(
        {"id": vuln_id},
        {"$set": {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {"message": "Status updated successfully"}


# Scan endpoints
@api_router.get("/scans", response_model=List[Scan])
async def get_scans(status: Optional[ScanStatus] = None, skip: int = 0, limit: int = 50):
    """Get all scans"""
    query = {}
    if status:
        query["status"] = status.value
    scans = await db.scans.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [deserialize_doc(s) for s in scans]

@api_router.post("/scans", response_model=Scan)
async def create_scan(scan: ScanCreate):
    """Create a new security scan"""
    scan_obj = Scan(**scan.model_dump())
    doc = serialize_doc(scan_obj.model_dump())
    await db.scans.insert_one(doc)
    return scan_obj

@api_router.get("/scans/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str):
    """Get a specific scan"""
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return deserialize_doc(scan)

@api_router.post("/scans/{scan_id}/start")
async def start_scan(scan_id: str):
    """Start a scan"""
    result = await db.scans.update_one(
        {"id": scan_id},
        {"$set": {"status": "running", "started_at": datetime.now(timezone.utc).isoformat(), "progress": 0}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": "Scan started"}


# Alert endpoints
@api_router.get("/alerts", response_model=List[Alert])
async def get_alerts(
    alert_type: Optional[AlertType] = None,
    severity: Optional[SeverityLevel] = None,
    acknowledged: Optional[bool] = None,
    skip: int = 0,
    limit: int = 100
):
    """Get all alerts"""
    query = {}
    if alert_type:
        query["alert_type"] = alert_type.value
    if severity:
        query["severity"] = severity.value
    if acknowledged is not None:
        query["acknowledged"] = acknowledged
    
    alerts = await db.alerts.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [deserialize_doc(a) for a in alerts]

@api_router.post("/alerts", response_model=Alert)
async def create_alert(alert: AlertCreate):
    """Create a new alert"""
    alert_obj = Alert(**alert.model_dump())
    doc = serialize_doc(alert_obj.model_dump())
    await db.alerts.insert_one(doc)
    return alert_obj

@api_router.patch("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    """Acknowledge an alert"""
    result = await db.alerts.update_one(
        {"id": alert_id},
        {"$set": {"acknowledged": True}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": "Alert acknowledged"}


# Endpoint management
@api_router.get("/endpoints", response_model=List[Endpoint])
async def get_endpoints(status: Optional[str] = None, skip: int = 0, limit: int = 100):
    """Get all monitored endpoints"""
    query = {}
    if status:
        query["status"] = status
    endpoints = await db.endpoints.find(query, {"_id": 0}).skip(skip).limit(limit).to_list(limit)
    return [deserialize_doc(e) for e in endpoints]

@api_router.post("/endpoints", response_model=Endpoint)
async def create_endpoint(endpoint: EndpointCreate):
    """Create a new endpoint to monitor"""
    endpoint_obj = Endpoint(**endpoint.model_dump())
    doc = serialize_doc(endpoint_obj.model_dump())
    await db.endpoints.insert_one(doc)
    return endpoint_obj


# Metrics endpoints
@api_router.get("/metrics")
async def get_metrics(category: Optional[str] = None, days: int = 7):
    """Get security metrics"""
    query = {}
    if category:
        query["category"] = category
    
    metrics = await db.metrics.find(query, {"_id": 0}).sort("timestamp", -1).limit(1000).to_list(1000)
    return [deserialize_doc(m) for m in metrics]

@api_router.post("/metrics")
async def create_metric(metric: Metric):
    """Create a new metric"""
    doc = serialize_doc(metric.model_dump())
    await db.metrics.insert_one(doc)
    return metric

@api_router.get("/metrics/trends")
async def get_metric_trends():
    """Get vulnerability trends over time"""
    # Return mock trend data for charts
    return {
        "daily_vulnerabilities": [
            {"date": "2025-01-01", "critical": 2, "high": 5, "medium": 8, "low": 12},
            {"date": "2025-01-02", "critical": 1, "high": 4, "medium": 10, "low": 15},
            {"date": "2025-01-03", "critical": 3, "high": 6, "medium": 7, "low": 11},
            {"date": "2025-01-04", "critical": 0, "high": 3, "medium": 9, "low": 14},
            {"date": "2025-01-05", "critical": 2, "high": 5, "medium": 6, "low": 10},
            {"date": "2025-01-06", "critical": 1, "high": 4, "medium": 8, "low": 13},
            {"date": "2025-01-07", "critical": 2, "high": 7, "medium": 5, "low": 9}
        ],
        "scan_activity": [
            {"date": "2025-01-01", "scans": 5, "findings": 27},
            {"date": "2025-01-02", "scans": 8, "findings": 30},
            {"date": "2025-01-03", "scans": 4, "findings": 27},
            {"date": "2025-01-04", "scans": 6, "findings": 26},
            {"date": "2025-01-05", "scans": 10, "findings": 23},
            {"date": "2025-01-06", "scans": 7, "findings": 26},
            {"date": "2025-01-07", "scans": 9, "findings": 23}
        ],
        "category_distribution": [
            {"category": "Authentication", "count": 15},
            {"category": "Authorization", "count": 12},
            {"category": "Injection", "count": 8},
            {"category": "Rate Limiting", "count": 6},
            {"category": "Input Validation", "count": 10}
        ]
    }


# Reports endpoints
@api_router.get("/reports", response_model=List[Report])
async def get_reports(report_type: Optional[str] = None, skip: int = 0, limit: int = 50):
    """Get all reports"""
    query = {}
    if report_type:
        query["report_type"] = report_type
    reports = await db.reports.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [deserialize_doc(r) for r in reports]

@api_router.post("/reports", response_model=Report)
async def create_report(report: Report):
    """Create a new report"""
    doc = serialize_doc(report.model_dump())
    await db.reports.insert_one(doc)
    return report


# ============================================
# IP/URL/Hash Analysis Section (VirusTotal & AbuseIPDB)
# ============================================

class AnalysisType(str, Enum):
    IP = "ip"
    URL = "url"
    HASH = "hash"

class ThreatLevel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"

class IPAnalysis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ip_address: str
    analysis_type: str = "ip"
    
    # VirusTotal data
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_undetected: int = 0
    vt_country: Optional[str] = None
    vt_asn: Optional[int] = None
    vt_as_owner: Optional[str] = None
    
    # AbuseIPDB data
    abuse_confidence_score: int = 0
    abuse_total_reports: int = 0
    abuse_country_code: Optional[str] = None
    abuse_isp: Optional[str] = None
    abuse_domain: Optional[str] = None
    abuse_is_tor: bool = False
    abuse_is_whitelisted: bool = False
    abuse_usage_type: Optional[str] = None
    
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
class URLAnalysis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    analysis_type: str = "url"
    
    # VirusTotal data
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_undetected: int = 0
    vt_categories: Dict[str, str] = {}
    vt_last_http_response_code: Optional[int] = None
    
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class HashAnalysis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_hash: str
    hash_type: str = "sha256"  # md5, sha1, sha256
    analysis_type: str = "hash"
    
    # VirusTotal data
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_undetected: int = 0
    vt_file_type: Optional[str] = None
    vt_file_size: Optional[int] = None
    vt_file_names: List[str] = []
    vt_tags: List[str] = []
    
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AnalysisRequest(BaseModel):
    value: str
    analysis_type: AnalysisType

class BulkAnalysisRequest(BaseModel):
    values: List[str]
    analysis_type: AnalysisType


def determine_threat_level(malicious: int, suspicious: int, abuse_score: int = 0) -> ThreatLevel:
    """Determine threat level based on detection counts"""
    if malicious >= 5 or abuse_score >= 80:
        return ThreatLevel.MALICIOUS
    elif malicious >= 1 or suspicious >= 3 or abuse_score >= 50:
        return ThreatLevel.SUSPICIOUS
    elif malicious == 0 and suspicious == 0 and abuse_score < 25:
        return ThreatLevel.CLEAN
    return ThreatLevel.UNKNOWN


# VirusTotal API helpers
async def vt_check_ip(ip_address: str) -> Dict[str, Any]:
    """Check IP address with VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY}
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"VT API error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

async def vt_check_url(url: str) -> Dict[str, Any]:
    """Check URL with VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    
    # URL must be base64 encoded for VT API
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY}
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                # URL not in database, submit for scanning
                submit_response = await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                    data={"url": url}
                )
                if submit_response.status_code == 200:
                    return {"submitted": True, "message": "URL submitted for analysis"}
            return {"error": f"VT API error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

async def vt_check_hash(file_hash: str) -> Dict[str, Any]:
    """Check file hash with VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY}
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"VT API error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}


# AbuseIPDB API helper
async def abuseipdb_check_ip(ip_address: str) -> Dict[str, Any]:
    """Check IP address with AbuseIPDB"""
    if not ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": ABUSEIPDB_API_KEY,
                    "Accept": "application/json"
                },
                params={
                    "ipAddress": ip_address,
                    "maxAgeInDays": 90,
                    "verbose": ""
                }
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"AbuseIPDB API error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}


# Analysis Endpoints
@api_router.post("/analysis/ip", response_model=IPAnalysis)
async def analyze_ip(ip_address: str):
    """Analyze an IP address using VirusTotal and AbuseIPDB"""
    # Check VirusTotal
    vt_result = await vt_check_ip(ip_address)
    
    # Check AbuseIPDB
    abuse_result = await abuseipdb_check_ip(ip_address)
    
    # Parse VirusTotal data
    vt_data = vt_result.get("data", {}).get("attributes", {})
    vt_stats = vt_data.get("last_analysis_stats", {})
    
    # Parse AbuseIPDB data
    abuse_data = abuse_result.get("data", {})
    
    # Create analysis result
    analysis = IPAnalysis(
        ip_address=ip_address,
        vt_malicious=vt_stats.get("malicious", 0),
        vt_suspicious=vt_stats.get("suspicious", 0),
        vt_harmless=vt_stats.get("harmless", 0),
        vt_undetected=vt_stats.get("undetected", 0),
        vt_country=vt_data.get("country"),
        vt_asn=vt_data.get("asn"),
        vt_as_owner=vt_data.get("as_owner"),
        abuse_confidence_score=abuse_data.get("abuseConfidenceScore", 0),
        abuse_total_reports=abuse_data.get("totalReports", 0),
        abuse_country_code=abuse_data.get("countryCode"),
        abuse_isp=abuse_data.get("isp"),
        abuse_domain=abuse_data.get("domain"),
        abuse_is_tor=abuse_data.get("isTor", False),
        abuse_is_whitelisted=abuse_data.get("isWhitelisted", False),
        abuse_usage_type=abuse_data.get("usageType")
    )
    
    # Determine threat level
    analysis.threat_level = determine_threat_level(
        analysis.vt_malicious,
        analysis.vt_suspicious,
        analysis.abuse_confidence_score
    )
    
    # Store in database
    doc = serialize_doc(analysis.model_dump())
    await db.ip_analyses.insert_one(doc)
    
    return analysis


@api_router.post("/analysis/url", response_model=URLAnalysis)
async def analyze_url(url: str):
    """Analyze a URL using VirusTotal"""
    # Check VirusTotal
    vt_result = await vt_check_url(url)
    
    # Parse VirusTotal data
    vt_data = vt_result.get("data", {}).get("attributes", {})
    vt_stats = vt_data.get("last_analysis_stats", {})
    
    # Create analysis result
    analysis = URLAnalysis(
        url=url,
        vt_malicious=vt_stats.get("malicious", 0),
        vt_suspicious=vt_stats.get("suspicious", 0),
        vt_harmless=vt_stats.get("harmless", 0),
        vt_undetected=vt_stats.get("undetected", 0),
        vt_categories=vt_data.get("categories", {}),
        vt_last_http_response_code=vt_data.get("last_http_response_code")
    )
    
    # Determine threat level
    analysis.threat_level = determine_threat_level(
        analysis.vt_malicious,
        analysis.vt_suspicious
    )
    
    # Store in database
    doc = serialize_doc(analysis.model_dump())
    await db.url_analyses.insert_one(doc)
    
    return analysis


@api_router.post("/analysis/hash", response_model=HashAnalysis)
async def analyze_hash(file_hash: str):
    """Analyze a file hash using VirusTotal"""
    # Determine hash type
    hash_type = "sha256"
    if len(file_hash) == 32:
        hash_type = "md5"
    elif len(file_hash) == 40:
        hash_type = "sha1"
    
    # Check VirusTotal
    vt_result = await vt_check_hash(file_hash)
    
    # Parse VirusTotal data
    vt_data = vt_result.get("data", {}).get("attributes", {})
    vt_stats = vt_data.get("last_analysis_stats", {})
    
    # Create analysis result
    analysis = HashAnalysis(
        file_hash=file_hash,
        hash_type=hash_type,
        vt_malicious=vt_stats.get("malicious", 0),
        vt_suspicious=vt_stats.get("suspicious", 0),
        vt_harmless=vt_stats.get("harmless", 0),
        vt_undetected=vt_stats.get("undetected", 0),
        vt_file_type=vt_data.get("type_description"),
        vt_file_size=vt_data.get("size"),
        vt_file_names=vt_data.get("names", [])[:5],  # Limit to 5 names
        vt_tags=vt_data.get("tags", [])[:10]  # Limit to 10 tags
    )
    
    # Determine threat level
    analysis.threat_level = determine_threat_level(
        analysis.vt_malicious,
        analysis.vt_suspicious
    )
    
    # Store in database
    doc = serialize_doc(analysis.model_dump())
    await db.hash_analyses.insert_one(doc)
    
    return analysis


@api_router.get("/analysis/history")
async def get_analysis_history(
    analysis_type: Optional[AnalysisType] = None,
    threat_level: Optional[ThreatLevel] = None,
    skip: int = 0,
    limit: int = 50
):
    """Get analysis history from all types"""
    results = []
    
    if analysis_type is None or analysis_type == AnalysisType.IP:
        query = {}
        if threat_level:
            query["threat_level"] = threat_level.value
        ip_results = await db.ip_analyses.find(query, {"_id": 0}).sort("analyzed_at", -1).skip(skip).limit(limit).to_list(limit)
        results.extend([{**r, "type": "ip"} for r in ip_results])
    
    if analysis_type is None or analysis_type == AnalysisType.URL:
        query = {}
        if threat_level:
            query["threat_level"] = threat_level.value
        url_results = await db.url_analyses.find(query, {"_id": 0}).sort("analyzed_at", -1).skip(skip).limit(limit).to_list(limit)
        results.extend([{**r, "type": "url"} for r in url_results])
    
    if analysis_type is None or analysis_type == AnalysisType.HASH:
        query = {}
        if threat_level:
            query["threat_level"] = threat_level.value
        hash_results = await db.hash_analyses.find(query, {"_id": 0}).sort("analyzed_at", -1).skip(skip).limit(limit).to_list(limit)
        results.extend([{**r, "type": "hash"} for r in hash_results])
    
    # Sort by analyzed_at
    results.sort(key=lambda x: x.get("analyzed_at", ""), reverse=True)
    
    return results[:limit]


@api_router.get("/analysis/stats")
async def get_analysis_stats():
    """Get analysis statistics"""
    ip_count = await db.ip_analyses.count_documents({})
    url_count = await db.url_analyses.count_documents({})
    hash_count = await db.hash_analyses.count_documents({})
    
    ip_malicious = await db.ip_analyses.count_documents({"threat_level": "malicious"})
    url_malicious = await db.url_analyses.count_documents({"threat_level": "malicious"})
    hash_malicious = await db.hash_analyses.count_documents({"threat_level": "malicious"})
    
    ip_suspicious = await db.ip_analyses.count_documents({"threat_level": "suspicious"})
    url_suspicious = await db.url_analyses.count_documents({"threat_level": "suspicious"})
    hash_suspicious = await db.hash_analyses.count_documents({"threat_level": "suspicious"})
    
    return {
        "total_analyses": ip_count + url_count + hash_count,
        "by_type": {
            "ip": ip_count,
            "url": url_count,
            "hash": hash_count
        },
        "threats": {
            "malicious": ip_malicious + url_malicious + hash_malicious,
            "suspicious": ip_suspicious + url_suspicious + hash_suspicious
        },
        "integrations": {
            "virustotal": bool(VIRUSTOTAL_API_KEY),
            "abuseipdb": bool(ABUSEIPDB_API_KEY)
        }
    }


# Seed data endpoint (for demo purposes)
@api_router.post("/seed")
async def seed_data():
    """Seed database with sample data for demonstration"""
    # Sample vulnerabilities
    vulnerabilities = [
        {
            "id": str(uuid.uuid4()),
            "title": "SQL Injection in User Search",
            "description": "The user search endpoint is vulnerable to SQL injection attacks through the 'query' parameter.",
            "severity": "critical",
            "endpoint": "/api/users/search",
            "method": "GET",
            "category": "Injection",
            "cwe_id": "CWE-89",
            "cvss_score": 9.8,
            "recommendation": "Use parameterized queries or an ORM to prevent SQL injection.",
            "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Broken Authentication - JWT Not Verified",
            "description": "JWT tokens are not properly validated, allowing attackers to forge tokens.",
            "severity": "critical",
            "endpoint": "/api/auth/verify",
            "method": "POST",
            "category": "Authentication",
            "cwe_id": "CWE-287",
            "cvss_score": 9.1,
            "recommendation": "Implement proper JWT signature verification using a secure library.",
            "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "IDOR - User Profile Access",
            "description": "Users can access other users' profiles by manipulating the user ID parameter.",
            "severity": "high",
            "endpoint": "/api/users/{id}/profile",
            "method": "GET",
            "category": "Authorization",
            "cwe_id": "CWE-639",
            "cvss_score": 7.5,
            "recommendation": "Implement proper authorization checks to verify user ownership.",
            "status": "in_progress",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "XSS in Comment Section",
            "description": "Stored XSS vulnerability in the comments API endpoint.",
            "severity": "high",
            "endpoint": "/api/comments",
            "method": "POST",
            "category": "Input Validation",
            "cwe_id": "CWE-79",
            "cvss_score": 7.1,
            "recommendation": "Sanitize and encode all user input before storing and displaying.",
            "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Missing Rate Limiting on Login",
            "description": "No rate limiting implemented on the login endpoint, enabling brute force attacks.",
            "severity": "medium",
            "endpoint": "/api/auth/login",
            "method": "POST",
            "category": "Rate Limiting",
            "cwe_id": "CWE-307",
            "cvss_score": 5.3,
            "recommendation": "Implement rate limiting with exponential backoff.",
            "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Sensitive Data in URL",
            "description": "API tokens are passed in URL query parameters instead of headers.",
            "severity": "medium",
            "endpoint": "/api/data/export",
            "method": "GET",
            "category": "Input Validation",
            "cwe_id": "CWE-598",
            "cvss_score": 4.3,
            "recommendation": "Pass sensitive data in request headers or body instead of URL.",
            "status": "resolved",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Verbose Error Messages",
            "description": "API returns detailed error messages exposing internal implementation details.",
            "severity": "low",
            "endpoint": "/api/products",
            "method": "GET",
            "category": "Input Validation",
            "cwe_id": "CWE-209",
            "cvss_score": 2.7,
            "recommendation": "Implement generic error messages for production environments.",
            "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    # Sample scans
    scans = [
        {
            "id": str(uuid.uuid4()),
            "name": "Full Security Scan - Production API",
            "target_url": "https://api.example.com",
            "scan_type": "full",
            "status": "completed",
            "modules": ["jwt_analyzer", "idor_detector", "injection_detector"],
            "findings_count": 7,
            "critical_count": 2,
            "high_count": 2,
            "medium_count": 2,
            "low_count": 1,
            "progress": 100,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Authentication Module Scan",
            "target_url": "https://api.example.com/auth",
            "scan_type": "authentication",
            "status": "running",
            "modules": ["jwt_analyzer", "brute_force_detector", "mfa_bypass_detector"],
            "findings_count": 3,
            "critical_count": 1,
            "high_count": 1,
            "medium_count": 1,
            "low_count": 0,
            "progress": 65,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Quick Scan - Staging API",
            "target_url": "https://staging-api.example.com",
            "scan_type": "quick",
            "status": "pending",
            "modules": ["injection_detector"],
            "findings_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "progress": 0,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    # Sample alerts
    alerts = [
        {
            "id": str(uuid.uuid4()),
            "title": "Critical Vulnerability Detected",
            "message": "SQL Injection vulnerability found in /api/users/search endpoint.",
            "alert_type": "vulnerability",
            "severity": "critical",
            "source": "injection_detector",
            "endpoint": "/api/users/search",
            "metadata": {"cwe_id": "CWE-89"},
            "acknowledged": False,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Unusual Traffic Pattern Detected",
            "message": "Anomalous spike in requests to authentication endpoints.",
            "alert_type": "anomaly",
            "severity": "high",
            "source": "anomaly_detector",
            "endpoint": "/api/auth/login",
            "metadata": {"request_count": 1500, "threshold": 500},
            "acknowledged": False,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Rate Limit Exceeded",
            "message": "IP 192.168.1.100 exceeded rate limit on /api/data endpoint.",
            "alert_type": "rate_limit",
            "severity": "medium",
            "source": "rate_limiter",
            "endpoint": "/api/data",
            "metadata": {"ip": "192.168.1.100", "requests": 250},
            "acknowledged": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Failed Authentication Attempts",
            "message": "Multiple failed login attempts for user admin@example.com.",
            "alert_type": "auth_failure",
            "severity": "medium",
            "source": "brute_force_detector",
            "endpoint": "/api/auth/login",
            "metadata": {"username": "admin@example.com", "attempts": 15},
            "acknowledged": False,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    # Sample endpoints
    endpoints = [
        {
            "id": str(uuid.uuid4()),
            "path": "/api/auth/login",
            "method": "POST",
            "description": "User authentication endpoint",
            "auth_required": False,
            "risk_score": 8.5,
            "vulnerabilities_count": 2,
            "status": "active",
            "tags": ["authentication", "critical"],
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "path": "/api/users/search",
            "method": "GET",
            "description": "User search functionality",
            "auth_required": True,
            "risk_score": 9.2,
            "vulnerabilities_count": 1,
            "status": "active",
            "tags": ["search", "users"],
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "path": "/api/users/{id}/profile",
            "method": "GET",
            "description": "Get user profile information",
            "auth_required": True,
            "risk_score": 7.0,
            "vulnerabilities_count": 1,
            "status": "active",
            "tags": ["users", "profile"],
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "path": "/api/comments",
            "method": "POST",
            "description": "Create new comment",
            "auth_required": True,
            "risk_score": 6.5,
            "vulnerabilities_count": 1,
            "status": "active",
            "tags": ["comments", "content"],
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "path": "/api/products",
            "method": "GET",
            "description": "List all products",
            "auth_required": False,
            "risk_score": 2.0,
            "vulnerabilities_count": 1,
            "status": "active",
            "tags": ["products", "public"],
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "path": "/api/data/export",
            "method": "GET",
            "description": "Export data in various formats",
            "auth_required": True,
            "risk_score": 5.5,
            "vulnerabilities_count": 1,
            "status": "active",
            "tags": ["data", "export"],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    # Clear existing data and insert new
    await db.vulnerabilities.delete_many({})
    await db.scans.delete_many({})
    await db.alerts.delete_many({})
    await db.endpoints.delete_many({})
    
    await db.vulnerabilities.insert_many(vulnerabilities)
    await db.scans.insert_many(scans)
    await db.alerts.insert_many(alerts)
    await db.endpoints.insert_many(endpoints)
    
    return {
        "message": "Database seeded successfully",
        "counts": {
            "vulnerabilities": len(vulnerabilities),
            "scans": len(scans),
            "alerts": len(alerts),
            "endpoints": len(endpoints)
        }
    }


# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
