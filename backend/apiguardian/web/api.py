"""
APIGuardian Web API - Enterprise-Grade FastAPI with WebSocket support

This module provides a comprehensive REST API for the API Guardian security testing platform
with enterprise features including:
- Real-time WebSocket event streaming
- Advanced finding management with full detail retrieval
- Workflow execution with step-by-step result tracking
- Threat intelligence aggregation
- DNS propagation checking
- Compliance reporting and metrics
- Export capabilities (JSON, CSV, SARIF)
- Enterprise dashboard statistics
"""

import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import re
import statistics
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from contextlib import asynccontextmanager
from enum import Enum

from fastapi import FastAPI, APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from apiguardian.core.engine import engine, Engine
from apiguardian.core.models import (
    init_db, get_session, get_engine,
    Finding, ScanJob, Asset, PluginRun,
    JobStatus, FindingStatus, Severity
)
from apiguardian.core.event_bus import event_bus, Event
from apiguardian.core.scheduler import scheduler
from apiguardian.core.plugin_manager import plugin_manager
from apiguardian.core.workflow_manager import workflow_manager
from apiguardian.integrations.threatintel.adapters import get_adapter, ADAPTERS
from apiguardian.integrations.siem.connectors import get_siem_connector, SIEM_CONNECTORS
from apiguardian.integrations.messaging.notifiers import get_notifier, NOTIFIERS
from apiguardian.modules.dns_checker import dns_checker, get_supported_record_types

logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

# Severity weights for scoring
SEVERITY_WEIGHTS = {
    'critical': 10.0,
    'high': 7.5,
    'medium': 5.0,
    'low': 2.5,
    'info': 0.5
}

# CWE Category mappings for compliance
CWE_CATEGORIES = {
    'injection': ['CWE-89', 'CWE-78', 'CWE-77', 'CWE-90', 'CWE-91', 'CWE-917', 'CWE-943'],
    'broken_auth': ['CWE-287', 'CWE-384', 'CWE-613', 'CWE-640', 'CWE-798'],
    'sensitive_data': ['CWE-311', 'CWE-312', 'CWE-319', 'CWE-359', 'CWE-532'],
    'xxe': ['CWE-611'],
    'broken_access': ['CWE-639', 'CWE-284', 'CWE-285', 'CWE-862', 'CWE-863'],
    'security_misconfig': ['CWE-16', 'CWE-209', 'CWE-215', 'CWE-548'],
    'xss': ['CWE-79'],
    'deserialization': ['CWE-502'],
    'components': ['CWE-937'],
    'logging': ['CWE-778', 'CWE-223']
}

# OWASP Top 10 2021 mapping
OWASP_TOP_10_2021 = {
    'A01:2021': {'name': 'Broken Access Control', 'cwes': ['CWE-639', 'CWE-284', 'CWE-285', 'CWE-862', 'CWE-863', 'CWE-22', 'CWE-23', 'CWE-35']},
    'A02:2021': {'name': 'Cryptographic Failures', 'cwes': ['CWE-259', 'CWE-327', 'CWE-328', 'CWE-330', 'CWE-311', 'CWE-312', 'CWE-319']},
    'A03:2021': {'name': 'Injection', 'cwes': ['CWE-89', 'CWE-78', 'CWE-79', 'CWE-77', 'CWE-90', 'CWE-91', 'CWE-917', 'CWE-943']},
    'A04:2021': {'name': 'Insecure Design', 'cwes': ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522', 'CWE-532', 'CWE-602']},
    'A05:2021': {'name': 'Security Misconfiguration', 'cwes': ['CWE-16', 'CWE-209', 'CWE-215', 'CWE-548', 'CWE-611', 'CWE-614']},
    'A06:2021': {'name': 'Vulnerable Components', 'cwes': ['CWE-937', 'CWE-1035', 'CWE-1104']},
    'A07:2021': {'name': 'Auth Failures', 'cwes': ['CWE-287', 'CWE-384', 'CWE-613', 'CWE-640', 'CWE-798', 'CWE-306']},
    'A08:2021': {'name': 'Integrity Failures', 'cwes': ['CWE-502', 'CWE-494', 'CWE-829', 'CWE-830', 'CWE-915']},
    'A09:2021': {'name': 'Logging Failures', 'cwes': ['CWE-778', 'CWE-223', 'CWE-117', 'CWE-532']},
    'A10:2021': {'name': 'SSRF', 'cwes': ['CWE-918']}
}

# Export format templates
SARIF_TEMPLATE = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": []
}


# ============================================================================
# PYDANTIC MODELS FOR API
# ============================================================================

class ScanRequest(BaseModel):
    """Request model for starting a new security scan"""
    target: str = Field(..., description="Target URL or API endpoint")
    scan_type: str = Field(default="full", description="Type of scan: quick, standard, full, or deep")
    modules: List[str] = Field(default=["all"], description="List of modules to run")
    enable_destructive: bool = Field(default=False, description="Enable destructive testing")
    custom_headers: Dict[str, str] = Field(default={}, description="Custom HTTP headers")
    authentication: Optional[Dict[str, Any]] = Field(default=None, description="Authentication config")


class FindingUpdate(BaseModel):
    """Request model for updating a finding"""
    status: Optional[str] = Field(None, description="New status: open, confirmed, false_positive, resolved")
    assigned_to: Optional[str] = Field(None, description="Assignee email/name")
    comment: Optional[str] = Field(None, description="Comment to add")
    priority: Optional[str] = Field(None, description="Priority: p1, p2, p3, p4")
    tags: Optional[List[str]] = Field(None, description="Tags to add")
    due_date: Optional[str] = Field(None, description="Due date ISO format")


class FindingBulkUpdate(BaseModel):
    """Request model for bulk updating findings"""
    finding_ids: List[str] = Field(..., description="List of finding IDs to update")
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None


class ThreatIntelRequest(BaseModel):
    """Request model for threat intelligence lookup"""
    indicator: str = Field(..., description="IP, URL, or hash to lookup")
    indicator_type: str = Field(default="ip", description="Type: ip, url, hash")
    service: str = Field(default="virustotal", description="Service to query")
    mode: str = Field(default="mock", description="Mode: live or mock")


class ScheduleJobRequest(BaseModel):
    """Request model for scheduling a recurring scan"""
    name: str = Field(..., description="Job name")
    target: str = Field(..., description="Target URL")
    cron_expression: str = Field(..., description="Cron expression")
    scan_type: str = Field(default="quick", description="Scan type")
    notify_on_findings: bool = Field(default=True, description="Send notifications on new findings")
    notify_channels: List[str] = Field(default=[], description="Notification channels")


class PluginToggleRequest(BaseModel):
    """Request model for enabling/disabling a plugin"""
    enabled: bool


class WorkflowRequest(BaseModel):
    """Request model for creating/running a workflow"""
    name: str = Field(default="Custom Workflow", description="Workflow name")
    template: Optional[str] = Field(None, description="Template name to use")
    target: str = Field(default="", description="Target URL")
    steps: List[Dict[str, Any]] = Field(default=[], description="Custom workflow steps")
    notify_on_complete: bool = Field(default=False, description="Send notification on completion")


class PluginRunRequest(BaseModel):
    """Request model for running a single plugin"""
    target: str = Field(..., description="Target URL")
    config: Dict[str, Any] = Field(default={}, description="Plugin configuration")


class DNSPropagationRequest(BaseModel):
    """Request model for DNS propagation check"""
    domain: str = Field(..., description="Domain to check")
    record_type: str = Field(default="A", description="DNS record type")


class ExportRequest(BaseModel):
    """Request model for exporting findings"""
    format: str = Field(default="json", description="Export format: json, csv, sarif, html")
    severity_filter: Optional[List[str]] = Field(None, description="Filter by severities")
    status_filter: Optional[List[str]] = Field(None, description="Filter by status")
    date_from: Optional[str] = Field(None, description="Start date ISO format")
    date_to: Optional[str] = Field(None, description="End date ISO format")
    include_evidence: bool = Field(default=True, description="Include evidence in export")


class ComplianceReportRequest(BaseModel):
    """Request model for generating compliance report"""
    framework: str = Field(default="owasp", description="Framework: owasp, pci_dss, hipaa, gdpr")
    include_remediation: bool = Field(default=True, description="Include remediation steps")
    include_metrics: bool = Field(default=True, description="Include compliance metrics")


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def calculate_security_score(findings: List[Dict]) -> float:
    """Calculate overall security score based on findings (0-100)"""
    if not findings:
        return 100.0

    total_weight = sum(
        SEVERITY_WEIGHTS.get(f.get('severity', 'info').lower(), 0.5)
        for f in findings
        if f.get('status', 'open') == 'open'
    )

    # Score decreases with more severe findings
    score = max(0, 100 - (total_weight * 2))
    return round(score, 1)


def calculate_risk_rating(findings: List[Dict]) -> str:
    """Calculate risk rating based on findings"""
    if not findings:
        return 'low'

    severity_counts = defaultdict(int)
    for f in findings:
        severity_counts[f.get('severity', 'info').lower()] += 1

    if severity_counts['critical'] >= 1:
        return 'critical'
    if severity_counts['high'] >= 3 or (severity_counts['critical'] >= 0 and severity_counts['high'] >= 1):
        return 'high'
    if severity_counts['medium'] >= 5 or severity_counts['high'] >= 1:
        return 'medium'
    return 'low'


def map_finding_to_owasp(cwe_id: str) -> Optional[Dict]:
    """Map a CWE ID to OWASP Top 10 2021 category"""
    if not cwe_id:
        return None

    # Normalize CWE ID
    cwe_normalized = cwe_id.upper() if cwe_id.startswith('CWE-') else f'CWE-{cwe_id}'

    for owasp_id, data in OWASP_TOP_10_2021.items():
        if cwe_normalized in data['cwes']:
            return {
                'owasp_id': owasp_id,
                'owasp_name': data['name']
            }
    return None


def generate_finding_fingerprint(finding: Dict) -> str:
    """Generate unique fingerprint for finding deduplication"""
    key_parts = [
        finding.get('issue', ''),
        finding.get('endpoint', ''),
        finding.get('method', ''),
        finding.get('cwe_id', '')
    ]
    return hashlib.sha256('|'.join(key_parts).encode()).hexdigest()[:16]


def format_finding_for_response(finding) -> Dict:
    """Format a Finding model instance for API response with all details"""
    # Parse raw field if it contains additional data
    raw_data = {}
    if finding.raw:
        try:
            raw_data = json.loads(finding.raw) if isinstance(finding.raw, str) else finding.raw
        except (json.JSONDecodeError, TypeError):
            raw_data = {}

    # Get OWASP mapping
    owasp_mapping = map_finding_to_owasp(finding.cwe_id)

    return {
        'id': finding.id,
        'issue': finding.issue or 'Unknown Issue',
        'description': finding.description or finding.issue or 'No description available',
        'severity': finding.severity or 'info',
        'status': finding.status or 'open',
        'endpoint': finding.endpoint or 'N/A',
        'method': finding.method or 'GET',
        'category': finding.category or 'General',
        'cwe_id': finding.cwe_id or '',
        'cwe_name': raw_data.get('cwe_name', ''),
        'cvss_score': finding.cvss_score or 0.0,
        'cvss_vector': raw_data.get('cvss_vector', ''),
        'evidence': finding.evidence or '',
        'request_sample': raw_data.get('request_sample', ''),
        'response_sample': raw_data.get('response_sample', ''),
        'recommendation': finding.recommendation or 'Review and remediate this finding',
        'references': raw_data.get('references', []),
        'affected_parameter': raw_data.get('affected_parameter', ''),
        'payload_used': raw_data.get('payload_used', ''),
        'fingerprint': raw_data.get('fingerprint', generate_finding_fingerprint({
            'issue': finding.issue,
            'endpoint': finding.endpoint,
            'method': finding.method,
            'cwe_id': finding.cwe_id
        })),
        'owasp_category': owasp_mapping,
        'scan_id': finding.scan_id,
        'plugin_name': finding.plugin_name,
        'assigned_to': finding.assigned_to,
        'comments': finding.comments or [],
        'tags': raw_data.get('tags', []),
        'false_positive_reason': raw_data.get('false_positive_reason', ''),
        'remediation_status': raw_data.get('remediation_status', 'pending'),
        'remediation_notes': raw_data.get('remediation_notes', ''),
        'discovered_at': finding.created_at.isoformat() if finding.created_at else datetime.now(timezone.utc).isoformat(),
        'updated_at': finding.updated_at.isoformat() if hasattr(finding, 'updated_at') and finding.updated_at else None,
        'verified': raw_data.get('verified', False),
        'exploitable': raw_data.get('exploitable', None),
        'business_impact': raw_data.get('business_impact', ''),
        'raw': raw_data
    }


def format_finding_from_plugin(finding: Dict, plugin_name: str = '', target: str = '') -> Dict:
    """Format a finding dict from plugin execution for display"""
    return {
        'id': finding.get('id', str(uuid.uuid4())),
        'issue': finding.get('issue', 'Unknown Issue'),
        'description': finding.get('description', finding.get('issue', 'No description')),
        'severity': finding.get('severity', 'info').lower(),
        'category': finding.get('category', 'General'),
        'endpoint': finding.get('endpoint', target),
        'method': finding.get('method', 'GET'),
        'evidence': finding.get('evidence', ''),
        'cwe_id': finding.get('cwe_id', ''),
        'cwe_name': finding.get('cwe_name', ''),
        'cvss_score': finding.get('cvss_score', 0.0),
        'recommendation': finding.get('recommendation', 'Review and remediate'),
        'fingerprint': finding.get('fingerprint', ''),
        'discovered_at': finding.get('discovered_at', datetime.now(timezone.utc).isoformat()),
        'plugin_name': plugin_name,
        'owasp_category': map_finding_to_owasp(finding.get('cwe_id', '')),
        'request_sample': finding.get('request_sample', ''),
        'response_sample': finding.get('response_sample', ''),
        'affected_parameter': finding.get('affected_parameter', ''),
        'payload_used': finding.get('payload_used', ''),
        'references': finding.get('references', []),
        'verified': finding.get('verified', False),
        'status': 'open'
    }


def export_findings_to_csv(findings: List[Dict]) -> str:
    """Export findings to CSV format"""
    output = io.StringIO()

    fieldnames = [
        'id', 'issue', 'severity', 'status', 'endpoint', 'method',
        'category', 'cwe_id', 'cvss_score', 'description', 'evidence',
        'recommendation', 'discovered_at', 'plugin_name'
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()

    for finding in findings:
        # Truncate long fields for CSV
        row = {k: finding.get(k, '') for k in fieldnames}
        if row.get('description') and len(str(row['description'])) > 500:
            row['description'] = str(row['description'])[:500] + '...'
        if row.get('evidence') and len(str(row['evidence'])) > 500:
            row['evidence'] = str(row['evidence'])[:500] + '...'
        writer.writerow(row)

    return output.getvalue()


def export_findings_to_sarif(findings: List[Dict], tool_name: str = "APIGuardian") -> Dict:
    """Export findings to SARIF format for IDE integration"""
    sarif_output = json.loads(json.dumps(SARIF_TEMPLATE))

    rules = []
    results = []
    rule_ids_seen = set()

    for finding in findings:
        # Create rule if not exists
        rule_id = finding.get('cwe_id', '') or f"apiguardian-{finding.get('category', 'general').lower().replace(' ', '-')}"

        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": finding.get('issue', 'Unknown Issue'),
                "shortDescription": {
                    "text": finding.get('issue', 'Unknown Issue')
                },
                "fullDescription": {
                    "text": finding.get('description', '')
                },
                "help": {
                    "text": finding.get('recommendation', ''),
                    "markdown": finding.get('recommendation', '')
                },
                "properties": {
                    "security-severity": str(finding.get('cvss_score', 5.0))
                }
            })

        # Create result
        severity_map = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }

        results.append({
            "ruleId": rule_id,
            "level": severity_map.get(finding.get('severity', 'info').lower(), 'note'),
            "message": {
                "text": f"{finding.get('issue', 'Unknown')}: {finding.get('description', '')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get('endpoint', ''),
                            "uriBaseId": "%SRCROOT%"
                        }
                    },
                    "logicalLocations": [
                        {
                            "kind": "function",
                            "name": finding.get('method', 'GET')
                        }
                    ]
                }
            ],
            "fingerprints": {
                "primary": finding.get('fingerprint', '')
            },
            "properties": {
                "category": finding.get('category', ''),
                "cwe_id": finding.get('cwe_id', ''),
                "evidence": finding.get('evidence', '')[:1000] if finding.get('evidence') else ''
            }
        })

    sarif_output["runs"].append({
        "tool": {
            "driver": {
                "name": tool_name,
                "version": "1.0.0",
                "informationUri": "https://apiguardian.io",
                "rules": rules
            }
        },
        "results": results
    })

    return sarif_output


def generate_compliance_report(findings: List[Dict], framework: str = "owasp") -> Dict:
    """Generate compliance report for a specific framework"""
    report = {
        'framework': framework,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'summary': {},
        'categories': [],
        'findings_by_category': {},
        'compliance_score': 0.0,
        'recommendations': []
    }

    if framework == "owasp":
        # Map findings to OWASP Top 10 2021
        category_findings = defaultdict(list)

        for finding in findings:
            owasp = map_finding_to_owasp(finding.get('cwe_id', ''))
            if owasp:
                category_findings[owasp['owasp_id']].append(finding)
            else:
                category_findings['other'].append(finding)

        # Calculate compliance for each category
        total_categories = len(OWASP_TOP_10_2021)
        compliant_categories = 0

        for owasp_id, owasp_data in OWASP_TOP_10_2021.items():
            category_find = category_findings.get(owasp_id, [])
            critical_high = [f for f in category_find if f.get('severity', '').lower() in ['critical', 'high']]

            status = 'compliant'
            if len(critical_high) > 0:
                status = 'non_compliant'
            elif len(category_find) > 0:
                status = 'partial'
                compliant_categories += 0.5
            else:
                compliant_categories += 1

            report['categories'].append({
                'id': owasp_id,
                'name': owasp_data['name'],
                'status': status,
                'finding_count': len(category_find),
                'critical_high_count': len(critical_high),
                'findings': category_find[:5]  # Include top 5 findings per category
            })

            report['findings_by_category'][owasp_id] = len(category_find)

        report['compliance_score'] = round((compliant_categories / total_categories) * 100, 1)

        # Generate recommendations based on non-compliant categories
        non_compliant = [c for c in report['categories'] if c['status'] == 'non_compliant']
        for cat in non_compliant[:5]:  # Top 5 recommendations
            report['recommendations'].append({
                'priority': 'high',
                'category': cat['name'],
                'issue_count': cat['finding_count'],
                'action': f"Address {cat['critical_high_count']} critical/high severity findings in {cat['name']}"
            })

    report['summary'] = {
        'total_findings': len(findings),
        'critical': len([f for f in findings if f.get('severity', '').lower() == 'critical']),
        'high': len([f for f in findings if f.get('severity', '').lower() == 'high']),
        'medium': len([f for f in findings if f.get('severity', '').lower() == 'medium']),
        'low': len([f for f in findings if f.get('severity', '').lower() == 'low']),
        'info': len([f for f in findings if f.get('severity', '').lower() == 'info']),
        'compliance_score': report['compliance_score'],
        'risk_rating': calculate_risk_rating(findings)
    }

    return report


# ============================================================================
# IN-MEMORY STORAGE FOR REAL-TIME DATA
# ============================================================================

# Store workflow results with detailed step findings
workflow_results_store: Dict[str, Dict] = {}

# Store plugin execution results
plugin_results_store: Dict[str, List[Dict]] = {}

# Store real-time metrics
metrics_cache = {
    'last_updated': None,
    'data': {}
}


# ============================================================================
# LIFESPAN AND APP SETUP
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown"""
    # Startup
    logger.info("Starting APIGuardian API...")
    init_db()
    await engine.initialize()

    # Initialize metrics cache
    metrics_cache['last_updated'] = datetime.now(timezone.utc)

    yield

    # Shutdown
    await engine.shutdown()
    logger.info("APIGuardian API shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="APIGuardian",
    description="Enterprise API Security Testing & Monitoring Platform",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Router
api_router = APIRouter(prefix="/api")


# ============================================================================
# WEBSOCKET CONNECTION MANAGER
# ============================================================================

class ConnectionManager:
    """WebSocket connection manager for real-time updates"""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_metadata: Dict[WebSocket, Dict] = {}

    async def connect(self, websocket: WebSocket, client_id: str = None):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.connection_metadata[websocket] = {
            'client_id': client_id or str(uuid.uuid4()),
            'connected_at': datetime.now(timezone.utc).isoformat(),
            'subscriptions': set()
        }
        event_bus.register_websocket(websocket)
        logger.info(f"WebSocket client connected: {self.connection_metadata[websocket]['client_id']}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.connection_metadata:
            del self.connection_metadata[websocket]
        event_bus.unregister_websocket(websocket)

    async def broadcast(self, message: str):
        """Broadcast message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

    async def send_to_client(self, websocket: WebSocket, message: str):
        """Send message to specific client"""
        try:
            await websocket.send_text(message)
        except Exception:
            self.disconnect(websocket)

    def get_connection_count(self) -> int:
        return len(self.active_connections)


manager = ConnectionManager()


# ============================================================================
# HEALTH AND METRICS ENDPOINTS
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint for load balancers and monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0",
        "websocket_connections": manager.get_connection_count()
    }


@app.get("/metrics")
async def prometheus_metrics():
    """Prometheus-compatible metrics endpoint"""
    session = get_session()
    try:
        total_findings = session.query(Finding).count()
        open_findings = session.query(Finding).filter_by(status=FindingStatus.OPEN.value).count()
        critical_findings = session.query(Finding).filter_by(severity=Severity.CRITICAL.value).count()
        high_findings = session.query(Finding).filter_by(severity=Severity.HIGH.value).count()
        running_scans = session.query(ScanJob).filter_by(status=JobStatus.RUNNING.value).count()
        total_scans = session.query(ScanJob).count()
        total_assets = session.query(Asset).count()

        metrics = f"""# HELP apiguardian_findings_total Total number of findings
# TYPE apiguardian_findings_total counter
apiguardian_findings_total {total_findings}

# HELP apiguardian_findings_open Number of open findings
# TYPE apiguardian_findings_open gauge
apiguardian_findings_open {open_findings}

# HELP apiguardian_findings_critical Number of critical findings
# TYPE apiguardian_findings_critical gauge
apiguardian_findings_critical {critical_findings}

# HELP apiguardian_findings_high Number of high severity findings
# TYPE apiguardian_findings_high gauge
apiguardian_findings_high {high_findings}

# HELP apiguardian_scans_running Number of running scans
# TYPE apiguardian_scans_running gauge
apiguardian_scans_running {running_scans}

# HELP apiguardian_scans_total Total number of scans
# TYPE apiguardian_scans_total counter
apiguardian_scans_total {total_scans}

# HELP apiguardian_assets_total Total number of assets
# TYPE apiguardian_assets_total counter
apiguardian_assets_total {total_assets}

# HELP apiguardian_websocket_connections Active WebSocket connections
# TYPE apiguardian_websocket_connections gauge
apiguardian_websocket_connections {manager.get_connection_count()}
"""
        return HTMLResponse(content=metrics, media_type="text/plain")
    finally:
        session.close()


@api_router.get("/metrics")
async def get_dashboard_metrics():
    """Get comprehensive dashboard metrics"""
    session = get_session()
    try:
        # Get findings statistics
        all_findings = session.query(Finding).all()
        formatted_findings = [format_finding_for_response(f) for f in all_findings]

        severity_counts = defaultdict(int)
        status_counts = defaultdict(int)
        category_counts = defaultdict(int)

        for f in formatted_findings:
            severity_counts[f['severity'].lower()] += 1
            status_counts[f['status'].lower()] += 1
            category_counts[f['category']] += 1

        # Get scan statistics
        total_scans = session.query(ScanJob).count()
        running_scans = session.query(ScanJob).filter_by(status=JobStatus.RUNNING.value).count()
        completed_scans = session.query(ScanJob).filter_by(status=JobStatus.COMPLETED.value).count()
        failed_scans = session.query(ScanJob).filter_by(status=JobStatus.FAILED.value).count()

        # Calculate security score
        security_score = calculate_security_score(formatted_findings)
        risk_rating = calculate_risk_rating(formatted_findings)

        # Get trend data (last 7 days findings)
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent_findings = [f for f in formatted_findings if f.get('discovered_at')]

        return {
            'findings': {
                'total': len(formatted_findings),
                'critical': severity_counts.get('critical', 0),
                'high': severity_counts.get('high', 0),
                'medium': severity_counts.get('medium', 0),
                'low': severity_counts.get('low', 0),
                'info': severity_counts.get('info', 0),
                'open': status_counts.get('open', 0),
                'resolved': status_counts.get('resolved', 0),
                'false_positive': status_counts.get('false_positive', 0),
                'by_category': dict(category_counts)
            },
            'scans': {
                'total': total_scans,
                'running': running_scans,
                'completed': completed_scans,
                'failed': failed_scans
            },
            'security_score': security_score,
            'risk_rating': risk_rating,
            'websocket_connections': manager.get_connection_count(),
            'active_workflows': len([w for w in workflow_results_store.values() if w.get('status') == 'running']),
            'plugins_available': len(plugin_manager.list_plugins()),
            'last_updated': datetime.now(timezone.utc).isoformat()
        }
    finally:
        session.close()


@api_router.get("/metrics/trends")
async def get_metrics_trends(days: int = 30):
    """Get finding trends over time"""
    session = get_session()
    try:
        all_findings = session.query(Finding).all()

        # Group findings by date
        findings_by_date = defaultdict(lambda: defaultdict(int))
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        for f in all_findings:
            if f.created_at and f.created_at >= cutoff_date:
                date_key = f.created_at.strftime('%Y-%m-%d')
                findings_by_date[date_key]['total'] += 1
                findings_by_date[date_key][f.severity.lower() if f.severity else 'info'] += 1

        # Convert to list sorted by date
        trend_data = [
            {
                'date': date,
                **counts
            }
            for date, counts in sorted(findings_by_date.items())
        ]

        return {
            'period_days': days,
            'trends': trend_data,
            'summary': {
                'total_new_findings': sum(d.get('total', 0) for d in trend_data),
                'avg_findings_per_day': round(sum(d.get('total', 0) for d in trend_data) / max(1, len(trend_data)), 1)
            }
        }
    finally:
        session.close()


# ============================================================================
# SCAN/JOB ENDPOINTS
# ============================================================================

@api_router.get("/jobs")
async def list_jobs(
    limit: int = Query(50, ge=1, le=500),
    status: Optional[str] = None,
    offset: int = 0
):
    """List all scan jobs with optional filtering"""
    return engine.list_scans(limit=limit)


@api_router.post("/jobs")
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new security scan"""
    async def run_scan():
        await engine.run_scan(
            target=request.target,
            scan_type=request.scan_type,
            modules=request.modules,
            config_override={
                'enable_destructive': request.enable_destructive,
                'custom_headers': request.custom_headers,
                'authentication': request.authentication
            }
        )

    background_tasks.add_task(run_scan)

    return {
        "message": "Scan started",
        "target": request.target,
        "type": request.scan_type,
        "modules": request.modules,
        "started_at": datetime.now(timezone.utc).isoformat()
    }


@api_router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    """Get detailed status of a specific scan job"""
    job = engine.get_scan_status(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@api_router.delete("/jobs/{job_id}")
async def cancel_job(job_id: str):
    """Cancel a running scan job"""
    # Implementation would depend on engine capabilities
    return {"message": "Job cancellation requested", "job_id": job_id}


# ============================================================================
# FINDINGS ENDPOINTS
# ============================================================================

@api_router.get("/findings")
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    cwe_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = 0,
    sort_by: str = "created_at",
    sort_order: str = "desc"
):
    """
    List findings with comprehensive filtering and full details.
    Returns all finding fields including CWE info, CVSS scores, evidence, etc.
    """
    session = get_session()
    try:
        query = session.query(Finding)

        # Apply filters
        if severity:
            query = query.filter(Finding.severity == severity.lower())
        if status:
            query = query.filter(Finding.status == status.lower())
        if category:
            query = query.filter(Finding.category.ilike(f'%{category}%'))
        if cwe_id:
            query = query.filter(Finding.cwe_id.ilike(f'%{cwe_id}%'))

        # Apply sorting
        if sort_order.lower() == 'desc':
            query = query.order_by(Finding.created_at.desc())
        else:
            query = query.order_by(Finding.created_at.asc())

        # Apply pagination
        findings = query.offset(offset).limit(limit).all()

        # Format all findings with full details
        formatted = [format_finding_for_response(f) for f in findings]

        # Apply search filter (post-query for flexibility)
        if search:
            search_lower = search.lower()
            formatted = [
                f for f in formatted
                if search_lower in (f.get('issue', '') or '').lower()
                or search_lower in (f.get('description', '') or '').lower()
                or search_lower in (f.get('endpoint', '') or '').lower()
                or search_lower in (f.get('evidence', '') or '').lower()
            ]

        return formatted
    finally:
        session.close()


@api_router.get("/findings/summary")
async def get_findings_summary():
    """Get summary statistics for all findings"""
    session = get_session()
    try:
        all_findings = session.query(Finding).all()
        formatted = [format_finding_for_response(f) for f in all_findings]

        # Aggregate statistics
        severity_breakdown = defaultdict(int)
        status_breakdown = defaultdict(int)
        category_breakdown = defaultdict(int)
        cwe_breakdown = defaultdict(int)
        owasp_breakdown = defaultdict(int)
        plugin_breakdown = defaultdict(int)

        for f in formatted:
            severity_breakdown[f['severity']] += 1
            status_breakdown[f['status']] += 1
            category_breakdown[f['category']] += 1
            if f['cwe_id']:
                cwe_breakdown[f['cwe_id']] += 1
            if f['owasp_category']:
                owasp_breakdown[f['owasp_category']['owasp_id']] += 1
            if f.get('plugin_name'):
                plugin_breakdown[f['plugin_name']] += 1

        return {
            'total_findings': len(formatted),
            'security_score': calculate_security_score(formatted),
            'risk_rating': calculate_risk_rating(formatted),
            'by_severity': dict(severity_breakdown),
            'by_status': dict(status_breakdown),
            'by_category': dict(category_breakdown),
            'by_cwe': dict(list(sorted(cwe_breakdown.items(), key=lambda x: x[1], reverse=True))[:20]),
            'by_owasp': dict(owasp_breakdown),
            'by_plugin': dict(plugin_breakdown),
            'open_critical_high': len([f for f in formatted if f['status'] == 'open' and f['severity'] in ['critical', 'high']])
        }
    finally:
        session.close()


@api_router.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    """Get complete details for a specific finding"""
    session = get_session()
    try:
        finding = session.query(Finding).filter_by(id=finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        return format_finding_for_response(finding)
    finally:
        session.close()


@api_router.patch("/findings/{finding_id}")
async def update_finding(finding_id: str, update: FindingUpdate):
    """Update a finding's status, assignment, or add comments"""
    session = get_session()
    try:
        finding = session.query(Finding).filter_by(id=finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        # Update fields
        if update.status:
            finding.status = update.status
        if update.assigned_to:
            finding.assigned_to = update.assigned_to
        if update.comment:
            comments = finding.comments or []
            comments.append({
                'text': update.comment,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'author': 'system'
            })
            finding.comments = comments

        # Update raw data for additional fields
        raw_data = {}
        if finding.raw:
            try:
                raw_data = json.loads(finding.raw) if isinstance(finding.raw, str) else finding.raw
            except:
                raw_data = {}

        if update.priority:
            raw_data['priority'] = update.priority
        if update.tags:
            raw_data['tags'] = update.tags
        if update.due_date:
            raw_data['due_date'] = update.due_date

        finding.raw = json.dumps(raw_data)
        session.commit()

        return {"message": "Finding updated", "finding_id": finding_id}
    finally:
        session.close()


@api_router.post("/findings/bulk-update")
async def bulk_update_findings(update: FindingBulkUpdate):
    """Bulk update multiple findings"""
    session = get_session()
    try:
        updated_count = 0
        for finding_id in update.finding_ids:
            finding = session.query(Finding).filter_by(id=finding_id).first()
            if finding:
                if update.status:
                    finding.status = update.status
                if update.assigned_to:
                    finding.assigned_to = update.assigned_to
                updated_count += 1

        session.commit()
        return {"message": f"Updated {updated_count} findings", "updated": updated_count}
    finally:
        session.close()


@api_router.post("/findings/export")
async def export_findings(request: ExportRequest):
    """Export findings in various formats"""
    session = get_session()
    try:
        # Get findings with filters
        query = session.query(Finding)

        if request.severity_filter:
            query = query.filter(Finding.severity.in_([s.lower() for s in request.severity_filter]))
        if request.status_filter:
            query = query.filter(Finding.status.in_([s.lower() for s in request.status_filter]))

        findings = query.all()
        formatted = [format_finding_for_response(f) for f in findings]

        # Remove evidence if not requested
        if not request.include_evidence:
            for f in formatted:
                f['evidence'] = ''
                f['request_sample'] = ''
                f['response_sample'] = ''

        if request.format == 'json':
            return JSONResponse(content=formatted)

        elif request.format == 'csv':
            csv_data = export_findings_to_csv(formatted)
            return Response(
                content=csv_data,
                media_type='text/csv',
                headers={'Content-Disposition': 'attachment; filename=findings.csv'}
            )

        elif request.format == 'sarif':
            sarif_data = export_findings_to_sarif(formatted)
            return JSONResponse(
                content=sarif_data,
                headers={'Content-Disposition': 'attachment; filename=findings.sarif'}
            )

        elif request.format == 'html':
            # Generate HTML report
            html_content = generate_html_report(formatted)
            return HTMLResponse(
                content=html_content,
                headers={'Content-Disposition': 'attachment; filename=findings.html'}
            )

        else:
            raise HTTPException(status_code=400, detail=f"Unknown format: {request.format}")

    finally:
        session.close()


def generate_html_report(findings: List[Dict]) -> str:
    """Generate HTML report from findings"""
    severity_counts = defaultdict(int)
    for f in findings:
        severity_counts[f['severity']] += 1

    findings_html = ""
    for f in findings:
        findings_html += f"""
        <div class="finding {f['severity']}">
            <div class="finding-header">
                <span class="severity-badge {f['severity']}">{f['severity'].upper()}</span>
                <span class="issue-title">{f['issue']}</span>
            </div>
            <div class="finding-body">
                <p><strong>Endpoint:</strong> {f['method']} {f['endpoint']}</p>
                <p><strong>Category:</strong> {f['category']}</p>
                <p><strong>CWE:</strong> {f['cwe_id']} {f.get('cwe_name', '')}</p>
                <p><strong>CVSS:</strong> {f['cvss_score']}</p>
                <p><strong>Description:</strong> {f['description']}</p>
                <p><strong>Evidence:</strong> <pre>{f['evidence'][:500] if f.get('evidence') else 'N/A'}</pre></p>
                <p><strong>Recommendation:</strong> {f['recommendation']}</p>
            </div>
        </div>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>APIGuardian Security Report</title>
        <style>
            body {{ font-family: -apple-system, sans-serif; background: #0a0a0a; color: #eee; padding: 2rem; }}
            h1 {{ color: #00ff94; }}
            .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; }}
            .stat {{ background: #111; padding: 1rem; border-radius: 6px; text-align: center; }}
            .stat .value {{ font-size: 2rem; font-weight: bold; }}
            .stat.critical .value {{ color: #ff2a6d; }}
            .stat.high .value {{ color: #ff9f1c; }}
            .stat.medium .value {{ color: #f1c40f; }}
            .finding {{ background: #111; border-radius: 6px; margin-bottom: 1rem; overflow: hidden; }}
            .finding.critical {{ border-left: 4px solid #ff2a6d; }}
            .finding.high {{ border-left: 4px solid #ff9f1c; }}
            .finding.medium {{ border-left: 4px solid #f1c40f; }}
            .finding.low {{ border-left: 4px solid #3498db; }}
            .finding-header {{ padding: 1rem; background: #1a1a1a; }}
            .finding-body {{ padding: 1rem; }}
            .severity-badge {{ padding: 0.25rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: bold; margin-right: 1rem; }}
            .severity-badge.critical {{ background: rgba(255,42,109,0.2); color: #ff2a6d; }}
            .severity-badge.high {{ background: rgba(255,159,28,0.2); color: #ff9f1c; }}
            .severity-badge.medium {{ background: rgba(241,196,15,0.2); color: #f1c40f; }}
            .severity-badge.low {{ background: rgba(52,152,219,0.2); color: #3498db; }}
            pre {{ background: #0a0a0a; padding: 0.5rem; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; }}
        </style>
    </head>
    <body>
        <h1>APIGuardian Security Report</h1>
        <p>Generated: {datetime.now().isoformat()}</p>
        <div class="summary">
            <div class="stat"><div class="label">Total</div><div class="value">{len(findings)}</div></div>
            <div class="stat critical"><div class="label">Critical</div><div class="value">{severity_counts.get('critical', 0)}</div></div>
            <div class="stat high"><div class="label">High</div><div class="value">{severity_counts.get('high', 0)}</div></div>
            <div class="stat medium"><div class="label">Medium</div><div class="value">{severity_counts.get('medium', 0)}</div></div>
        </div>
        <h2>Findings</h2>
        {findings_html}
    </body>
    </html>
    """


# ============================================================================
# ASSETS ENDPOINTS
# ============================================================================

@api_router.get("/assets")
async def list_assets(limit: int = 100):
    """List all registered assets"""
    session = get_session()
    try:
        assets = session.query(Asset).limit(limit).all()
        return [
            {
                'id': a.id,
                'value': a.value,
                'type': a.type,
                'internal': a.internal,
                'added_at': a.added_at.isoformat() if a.added_at else None
            }
            for a in assets
        ]
    finally:
        session.close()


@api_router.post("/assets")
async def create_asset(value: str, asset_type: str = "url", internal: bool = False):
    """Register a new asset for scanning"""
    session = get_session()
    try:
        asset = Asset(
            id=str(uuid.uuid4()),
            value=value,
            type=asset_type,
            internal=internal
        )
        session.add(asset)
        session.commit()
        return {"id": asset.id, "value": asset.value}
    finally:
        session.close()


@api_router.delete("/assets/{asset_id}")
async def delete_asset(asset_id: str):
    """Delete an asset"""
    session = get_session()
    try:
        asset = session.query(Asset).filter_by(id=asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        session.delete(asset)
        session.commit()
        return {"message": "Asset deleted"}
    finally:
        session.close()


# ============================================================================
# PLUGINS ENDPOINTS
# ============================================================================

@api_router.get("/plugins")
async def list_plugins():
    """List all available plugins with their configuration"""
    plugins = plugin_manager.list_plugins()

    # Add execution statistics
    for plugin in plugins:
        plugin_key = f"{plugin['type']}/{plugin['name']}"
        plugin['last_results'] = plugin_results_store.get(plugin_key, [])
        plugin['last_results_count'] = len(plugin['last_results'])

    return plugins


@api_router.post("/plugins/{plugin_type}/{plugin_name}/toggle")
async def toggle_plugin(plugin_type: str, plugin_name: str, request: PluginToggleRequest):
    """Enable or disable a plugin"""
    plugins = plugin_manager.get_all_plugins()
    if plugin_type not in plugins or plugin_name not in plugins[plugin_type]:
        raise HTTPException(status_code=404, detail="Plugin not found")

    plugin_cls = plugins[plugin_type][plugin_name]
    plugin_cls.enabled = request.enabled
    return {"plugin": plugin_name, "enabled": request.enabled}


@api_router.post("/plugins/{plugin_type}/{plugin_name}/run")
async def run_plugin(
    plugin_type: str,
    plugin_name: str,
    request: PluginRunRequest,
    background_tasks: BackgroundTasks
):
    """
    Run a specific plugin against a target.
    Results are sent via WebSocket when complete.
    """
    plugin = plugin_manager.get_plugin(plugin_type, plugin_name, request.config)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")

    execution_id = str(uuid.uuid4())
    plugin_key = f"{plugin_type}/{plugin_name}"

    async def execute_plugin():
        context = {
            'target': request.target,
            'config': request.config,
            'enable_destructive': request.config.get('enable_destructive', False)
        }
        try:
            results = await plugin.execute(context)

            # Format ALL findings with complete details
            formatted_findings = []
            for r in results:
                formatted = format_finding_from_plugin(r, plugin_name, request.target)
                formatted_findings.append(formatted)

            # Store results for later retrieval
            plugin_results_store[plugin_key] = formatted_findings

            # Publish results via event bus with ALL findings and complete details
            await event_bus.publish(Event.create(
                'plugin.completed',
                {
                    'execution_id': execution_id,
                    'plugin': plugin_name,
                    'type': plugin_type,
                    'target': request.target,
                    'findings_count': len(formatted_findings),
                    'findings': formatted_findings,  # Send ALL findings with full details
                    'summary': {
                        'critical': len([f for f in formatted_findings if f['severity'] == 'critical']),
                        'high': len([f for f in formatted_findings if f['severity'] == 'high']),
                        'medium': len([f for f in formatted_findings if f['severity'] == 'medium']),
                        'low': len([f for f in formatted_findings if f['severity'] == 'low']),
                        'info': len([f for f in formatted_findings if f['severity'] == 'info'])
                    },
                    'completed_at': datetime.now(timezone.utc).isoformat()
                }
            ))
        except Exception as e:
            logger.exception(f"Plugin {plugin_name} failed: {e}")
            await event_bus.publish(Event.create(
                'plugin.failed',
                {
                    'execution_id': execution_id,
                    'plugin': plugin_name,
                    'type': plugin_type,
                    'target': request.target,
                    'error': str(e),
                    'failed_at': datetime.now(timezone.utc).isoformat()
                }
            ))

    background_tasks.add_task(execute_plugin)

    return {
        "message": f"Plugin {plugin_name} started",
        "execution_id": execution_id,
        "target": request.target,
        "started_at": datetime.now(timezone.utc).isoformat()
    }


@api_router.get("/plugins/{plugin_type}/{plugin_name}")
async def get_plugin_details(plugin_type: str, plugin_name: str):
    """Get detailed info about a plugin including last results"""
    plugins = plugin_manager.get_all_plugins()
    if plugin_type not in plugins or plugin_name not in plugins[plugin_type]:
        raise HTTPException(status_code=404, detail="Plugin not found")

    plugin_cls = plugins[plugin_type][plugin_name]
    plugin_key = f"{plugin_type}/{plugin_name}"

    return {
        'type': plugin_type,
        'name': plugin_name,
        'description': plugin_cls.description,
        'version': plugin_cls.version,
        'enabled': plugin_cls.enabled,
        'destructive': getattr(plugin_cls, 'destructive', False),
        'last_results': plugin_results_store.get(plugin_key, []),
        'last_results_count': len(plugin_results_store.get(plugin_key, []))
    }


@api_router.get("/plugins/{plugin_type}/{plugin_name}/results")
async def get_plugin_results(plugin_type: str, plugin_name: str):
    """Get the last execution results for a plugin"""
    plugin_key = f"{plugin_type}/{plugin_name}"
    results = plugin_results_store.get(plugin_key, [])

    return {
        'plugin': plugin_name,
        'type': plugin_type,
        'findings_count': len(results),
        'findings': results
    }


# ============================================================================
# WORKFLOW ENDPOINTS
# ============================================================================

@api_router.get("/workflows")
async def list_workflows():
    """List all workflows with their execution status"""
    workflows = workflow_manager.list_workflows()

    # Add stored results
    for wf in workflows:
        if wf['id'] in workflow_results_store:
            wf['detailed_results'] = workflow_results_store[wf['id']]

    return workflows


@api_router.get("/workflows/templates")
async def list_workflow_templates():
    """List available workflow templates"""
    return workflow_manager.list_templates()


@api_router.post("/workflows")
async def create_workflow(request: WorkflowRequest, background_tasks: BackgroundTasks):
    """Create and optionally start a workflow"""
    workflow = workflow_manager.create_workflow(
        name=request.name,
        template=request.template,
        steps=request.steps if not request.template else None,
        context={'target': request.target}
    )

    # Initialize workflow results store
    workflow_results_store[workflow.id] = {
        'id': workflow.id,
        'name': workflow.name,
        'status': 'pending',
        'target': request.target,
        'started_at': None,
        'finished_at': None,
        'steps': [],
        'total_findings': 0,
        'findings_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    }

    if request.target:
        async def run_workflow():
            try:
                workflow_results_store[workflow.id]['status'] = 'running'
                workflow_results_store[workflow.id]['started_at'] = datetime.now(timezone.utc).isoformat()

                await workflow_manager.execute_workflow(workflow.id, engine)

                # Collect detailed results from each step
                detailed_workflow = workflow_manager.get_workflow(workflow.id)
                all_findings = []
                step_results = []

                for step in detailed_workflow.steps:
                    step_findings = []

                    # Get plugin results for this step
                    plugin_key = f"{step.plugin_type}/{step.plugin_name}"
                    if plugin_key in plugin_results_store:
                        step_findings = plugin_results_store[plugin_key]

                    step_results.append({
                        'id': step.id,
                        'name': step.name,
                        'plugin': f"{step.plugin_type}/{step.plugin_name}",
                        'status': step.status.value,
                        'error': step.error,
                        'findings_count': len(step_findings),
                        'findings': step_findings
                    })
                    all_findings.extend(step_findings)

                # Calculate severity breakdown
                severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                for f in all_findings:
                    sev = f.get('severity', 'info').lower()
                    if sev in severity_breakdown:
                        severity_breakdown[sev] += 1

                # Update stored results
                workflow_results_store[workflow.id].update({
                    'status': 'completed',
                    'finished_at': datetime.now(timezone.utc).isoformat(),
                    'steps': step_results,
                    'total_findings': len(all_findings),
                    'findings_by_severity': severity_breakdown,
                    'all_findings': all_findings
                })

                await event_bus.publish(Event.create(
                    'workflow.completed',
                    {
                        'workflow_id': workflow.id,
                        'name': workflow.name,
                        'total_findings': len(all_findings),
                        'findings_by_severity': severity_breakdown,
                        'steps': step_results
                    }
                ))

            except Exception as e:
                workflow_results_store[workflow.id]['status'] = 'failed'
                workflow_results_store[workflow.id]['error'] = str(e)

                await event_bus.publish(Event.create(
                    'workflow.failed',
                    {'workflow_id': workflow.id, 'error': str(e)}
                ))

        background_tasks.add_task(run_workflow)

    return {
        "workflow_id": workflow.id,
        "name": workflow.name,
        "steps": len(workflow.steps),
        "status": "started" if request.target else "created"
    }


@api_router.get("/workflows/{workflow_id}")
async def get_workflow(workflow_id: str):
    """Get detailed workflow status and results"""
    workflow = workflow_manager.get_workflow(workflow_id)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    # Get stored detailed results if available
    detailed_results = workflow_results_store.get(workflow_id, {})

    return {
        'id': workflow.id,
        'name': workflow.name,
        'status': workflow.status,
        'steps': detailed_results.get('steps', [
            {
                'id': s.id,
                'name': s.name,
                'plugin': f"{s.plugin_type}/{s.plugin_name}",
                'status': s.status.value,
                'error': s.error,
                'findings': []
            }
            for s in workflow.steps
        ]),
        'total_findings': detailed_results.get('total_findings', 0),
        'findings_by_severity': detailed_results.get('findings_by_severity', {}),
        'all_findings': detailed_results.get('all_findings', []),
        'created_at': workflow.created_at.isoformat(),
        'started_at': workflow.started_at.isoformat() if workflow.started_at else detailed_results.get('started_at'),
        'finished_at': workflow.finished_at.isoformat() if workflow.finished_at else detailed_results.get('finished_at')
    }


@api_router.get("/workflows/{workflow_id}/results")
async def get_workflow_results(workflow_id: str):
    """Get all findings from a workflow execution"""
    if workflow_id not in workflow_results_store:
        raise HTTPException(status_code=404, detail="Workflow results not found")

    return workflow_results_store[workflow_id]


# ============================================================================
# COMPLIANCE ENDPOINTS
# ============================================================================

@api_router.post("/compliance/report")
async def generate_compliance_report_endpoint(request: ComplianceReportRequest):
    """Generate a compliance report for a specific framework"""
    session = get_session()
    try:
        all_findings = session.query(Finding).all()
        formatted = [format_finding_for_response(f) for f in all_findings]

        report = generate_compliance_report(formatted, request.framework)

        if request.include_remediation:
            # Add detailed remediation steps for each non-compliant category
            for category in report['categories']:
                if category['status'] == 'non_compliant':
                    category['remediation_steps'] = [
                        f"Review and address all {category['critical_high_count']} critical/high findings",
                        "Implement security controls recommended in each finding",
                        "Conduct follow-up testing after remediation",
                        "Document remediation actions taken"
                    ]

        return report
    finally:
        session.close()


@api_router.get("/compliance/owasp")
async def get_owasp_compliance():
    """Get OWASP Top 10 compliance status"""
    session = get_session()
    try:
        all_findings = session.query(Finding).all()
        formatted = [format_finding_for_response(f) for f in all_findings]

        return generate_compliance_report(formatted, "owasp")
    finally:
        session.close()


# ============================================================================
# SCHEDULER ENDPOINTS
# ============================================================================

@api_router.get("/scheduler/jobs")
async def list_scheduled_jobs():
    """List all scheduled scanning jobs"""
    return scheduler.list_jobs()


@api_router.post("/scheduler/jobs")
async def schedule_job(request: ScheduleJobRequest):
    """Schedule a recurring security scan"""
    async def run_scheduled_scan():
        await engine.run_scan(
            target=request.target,
            scan_type=request.scan_type
        )

    job_id = scheduler.add_cron_job(
        run_scheduled_scan,
        request.name,
        request.cron_expression
    )
    return {"job_id": job_id, "name": request.name}


@api_router.delete("/scheduler/jobs/{job_id}")
async def remove_scheduled_job(job_id: str):
    """Remove a scheduled job"""
    if scheduler.remove_job(job_id):
        return {"message": "Job removed"}
    raise HTTPException(status_code=404, detail="Job not found")


# ============================================================================
# THREAT INTELLIGENCE ENDPOINTS
# ============================================================================

@api_router.post("/threatintel/lookup")
async def threat_intel_lookup(request: ThreatIntelRequest):
    """Lookup an indicator against a single threat intelligence service"""
    adapter = get_adapter(request.service, mode=request.mode)
    if not adapter:
        raise HTTPException(status_code=400, detail=f"Unknown service: {request.service}")

    if request.indicator_type == "ip":
        result = adapter.lookup_ip(request.indicator)
    elif request.indicator_type == "url":
        result = adapter.lookup_url(request.indicator)
    elif request.indicator_type == "hash":
        result = adapter.lookup_hash(request.indicator)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown indicator type: {request.indicator_type}")

    return result


@api_router.post("/threatintel/lookup-all")
async def threat_intel_lookup_all(indicator: str, indicator_type: str = "ip", mode: str = "live"):
    """
    Query all configured threat intelligence services and aggregate results.
    Returns both individual service results and an overall verdict.
    """
    results = []

    for service_name in ADAPTERS.keys():
        adapter = get_adapter(service_name, mode=mode)
        if not adapter:
            continue

        try:
            if indicator_type == "ip":
                result = adapter.lookup_ip(indicator)
            elif indicator_type == "url":
                result = adapter.lookup_url(indicator)
            elif indicator_type == "hash":
                result = adapter.lookup_hash(indicator)
            else:
                continue

            result['service'] = service_name
            results.append(result)
        except Exception as e:
            logger.error(f"Error querying {service_name}: {e}")
            continue

    # Aggregate threat levels
    threat_counts = {'malicious': 0, 'suspicious': 0, 'clean': 0, 'unknown': 0}
    for result in results:
        level = result.get('threat_level', 'unknown').lower()
        if level in threat_counts:
            threat_counts[level] += 1
        else:
            threat_counts['unknown'] += 1

    # Determine overall verdict
    if threat_counts['malicious'] > 0:
        overall_verdict = 'malicious'
        verdict_reason = f"{threat_counts['malicious']}/{len(results)} services reported malicious"
    elif threat_counts['suspicious'] > 0:
        overall_verdict = 'suspicious'
        verdict_reason = f"{threat_counts['suspicious']}/{len(results)} services reported suspicious"
    elif threat_counts['clean'] > 0:
        overall_verdict = 'clean'
        verdict_reason = f"All {threat_counts['clean']} services reported clean"
    else:
        overall_verdict = 'unknown'
        verdict_reason = "Unable to determine threat level"

    return {
        'indicator': indicator,
        'indicator_type': indicator_type,
        'overall_verdict': overall_verdict,
        'verdict_reason': verdict_reason,
        'threat_counts': threat_counts,
        'total_services': len(results),
        'results': results
    }


@api_router.get("/threatintel/services")
async def list_ti_services():
    """List available threat intelligence services"""
    return [
        {
            'name': name,
            'api_key_configured': bool(os.environ.get(cls.api_key_env))
        }
        for name, cls in ADAPTERS.items()
    ]


# ============================================================================
# DNS PROPAGATION ENDPOINTS
# ============================================================================

@api_router.post("/dns/propagation")
async def check_dns_propagation(request: DNSPropagationRequest, background_tasks: BackgroundTasks):
    """Check DNS propagation for a domain across global DNS servers"""
    try:
        result = await dns_checker.check_propagation(
            domain=request.domain,
            record_type=request.record_type.upper()
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"DNS propagation check failed: {e}")
        raise HTTPException(status_code=500, detail=f"DNS check failed: {str(e)}")


@api_router.get("/dns/propagation")
async def check_dns_propagation_get(
    domain: str = Query(..., description="Domain to check"),
    record_type: str = Query("A", description="DNS record type")
):
    """Check DNS propagation for a domain (GET method)"""
    try:
        result = await dns_checker.check_propagation(
            domain=domain,
            record_type=record_type.upper()
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"DNS propagation check failed: {e}")
        raise HTTPException(status_code=500, detail=f"DNS check failed: {str(e)}")


@api_router.get("/dns/servers")
async def list_dns_servers():
    """Get list of available DNS servers with their locations"""
    return dns_checker.get_servers_list()


@api_router.get("/dns/record-types")
async def list_dns_record_types():
    """Get list of supported DNS record types"""
    return get_supported_record_types()


@api_router.post("/dns/propagation/stream")
async def check_dns_propagation_stream(request: DNSPropagationRequest):
    """Check DNS propagation and broadcast results via WebSocket"""
    async def stream_results():
        try:
            result = await dns_checker.check_propagation(
                domain=request.domain,
                record_type=request.record_type.upper()
            )
            await event_bus.publish(Event.create(
                'dns.propagation.completed',
                {
                    'domain': request.domain,
                    'record_type': request.record_type,
                    'summary': result['summary'],
                    'results': result['results']
                }
            ))
        except Exception as e:
            await event_bus.publish(Event.create(
                'dns.propagation.failed',
                {
                    'domain': request.domain,
                    'error': str(e)
                }
            ))

    asyncio.create_task(stream_results())
    return {
        "message": "DNS propagation check started",
        "domain": request.domain,
        "record_type": request.record_type
    }


# ============================================================================
# INTEGRATIONS ENDPOINTS
# ============================================================================

@api_router.get("/integrations")
async def list_integrations():
    """List all available integrations"""
    return {
        'threat_intel': list(ADAPTERS.keys()),
        'siem': list(SIEM_CONNECTORS.keys()),
        'messaging': list(NOTIFIERS.keys())
    }


@api_router.post("/integrations/test/{integration_type}/{name}")
async def test_integration(integration_type: str, name: str, mode: str = "mock"):
    """Test an integration"""
    if integration_type == "siem":
        connector = get_siem_connector(name, mode=mode)
        if connector:
            success = connector.send_finding({'issue': 'Test finding', 'severity': 'info'})
            return {"success": success, "connector": name, "mode": mode}
    elif integration_type == "messaging":
        notifier = get_notifier(name, mode=mode)
        if notifier:
            success = notifier.send_alert("Test Alert", "This is a test from APIGuardian")
            return {"success": success, "notifier": name, "mode": mode}

    raise HTTPException(status_code=400, detail="Unknown integration")


# ============================================================================
# WEBSOCKET ENDPOINT
# ============================================================================

@app.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Include router
app.include_router(api_router)


# ============================================================================
# DASHBOARD HTML
# ============================================================================

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>APIGuardian Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, sans-serif; background: #0a0a0a; color: #eee; padding: 2rem; }
        h1 { color: #00ff94; margin-bottom: 2rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: #111; border: 1px solid #222; padding: 1.5rem; border-radius: 4px; }
        .card .label { font-size: 0.75rem; color: #666; text-transform: uppercase; }
        .card .value { font-size: 2rem; font-weight: bold; margin-top: 0.5rem; }
        .critical { color: #ff2a6d; }
        .high { color: #ff9f1c; }
        .live-feed { background: #111; border: 1px solid #222; padding: 1rem; border-radius: 4px; max-height: 300px; overflow-y: auto; }
        .feed-item { padding: 0.5rem; border-bottom: 1px solid #222; font-size: 0.875rem; }
        .connected { color: #00ff94; }
        .disconnected { color: #ff2a6d; }
    </style>
</head>
<body>
    <h1>API GUARDIAN</h1>
    <p style="margin-bottom: 2rem; color: #666;">Enterprise API Security Testing Platform v2.0</p>
    <div class="grid">
        <div class="card"><div class="label">Total Findings</div><div class="value" id="total">-</div></div>
        <div class="card"><div class="label">Critical</div><div class="value critical" id="critical">-</div></div>
        <div class="card"><div class="label">High</div><div class="value high" id="high">-</div></div>
        <div class="card"><div class="label">Running Scans</div><div class="value" id="running">-</div></div>
        <div class="card"><div class="label">Security Score</div><div class="value" id="score">-</div></div>
    </div>
    <h2 style="margin-bottom: 1rem;">Live Feed <span id="ws-status" class="disconnected">(Connecting...)</span></h2>
    <div class="live-feed" id="feed"></div>
    <p style="margin-top: 2rem; color: #666;">Full dashboard available at /frontend/build/index.html</p>
    <script>
        async function fetchMetrics() {
            try {
                const res = await fetch('/api/metrics');
                const data = await res.json();
                document.getElementById('total').textContent = data.findings?.total || 0;
                document.getElementById('critical').textContent = data.findings?.critical || 0;
                document.getElementById('high').textContent = data.findings?.high || 0;
                document.getElementById('running').textContent = data.scans?.running || 0;
                document.getElementById('score').textContent = data.security_score || 100;
            } catch(e) { console.error(e); }
        }
        fetchMetrics();
        setInterval(fetchMetrics, 5000);

        const ws = new WebSocket(`ws://${location.host}/ws/stream`);
        ws.onopen = () => {
            document.getElementById('ws-status').className = 'connected';
            document.getElementById('ws-status').textContent = '(Connected)';
        };
        ws.onclose = () => {
            document.getElementById('ws-status').className = 'disconnected';
            document.getElementById('ws-status').textContent = '(Disconnected)';
        };
        ws.onmessage = (e) => {
            const feed = document.getElementById('feed');
            const item = document.createElement('div');
            item.className = 'feed-item';
            try {
                const data = JSON.parse(e.data);
                item.textContent = `[${data.type}] ${data.data?.issue || JSON.stringify(data.data).slice(0, 100)}`;
            } catch { item.textContent = e.data; }
            feed.insertBefore(item, feed.firstChild);
            if (feed.children.length > 50) feed.removeChild(feed.lastChild);
        };
    </script>
</body>
</html>
'''

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return DASHBOARD_HTML


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
