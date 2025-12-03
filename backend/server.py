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
