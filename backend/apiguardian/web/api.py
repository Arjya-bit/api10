"""APIGuardian Web API - FastAPI with WebSocket support"""
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
import uuid

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

logger = logging.getLogger(__name__)


# Pydantic models for API
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"
    modules: List[str] = ["all"]
    enable_destructive: bool = False

class FindingUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    comment: Optional[str] = None

class ThreatIntelRequest(BaseModel):
    indicator: str
    indicator_type: str = "ip"  # ip, url, hash
    service: str = "virustotal"
    mode: str = "mock"

class ScheduleJobRequest(BaseModel):
    name: str
    target: str
    cron_expression: str
    scan_type: str = "quick"


class PluginToggleRequest(BaseModel):
    enabled: bool


class WorkflowRequest(BaseModel):
    name: str = "Custom Workflow"
    template: Optional[str] = None
    target: str = ""
    steps: List[Dict[str, Any]] = []


class PluginRunRequest(BaseModel):
    target: str
    config: Dict[str, Any] = {}


# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting APIGuardian API...")
    init_db()
    await engine.initialize()
    yield
    # Shutdown
    await engine.shutdown()
    logger.info("APIGuardian API shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="APIGuardian",
    description="Enterprise API Security Testing & Monitoring Platform",
    version="1.0.0",
    lifespan=lifespan
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


# WebSocket connections manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        event_bus.register_websocket(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        event_bus.unregister_websocket(websocket)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()


# Health endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


# Prometheus metrics endpoint
@app.get("/metrics")
async def prometheus_metrics():
    session = get_session()
    try:
        total_findings = session.query(Finding).count()
        open_findings = session.query(Finding).filter_by(status=FindingStatus.OPEN.value).count()
        critical_findings = session.query(Finding).filter_by(severity=Severity.CRITICAL.value).count()
        running_scans = session.query(ScanJob).filter_by(status=JobStatus.RUNNING.value).count()
        total_scans = session.query(ScanJob).count()
        
        metrics = f"""# HELP apiguardian_findings_total Total number of findings
# TYPE apiguardian_findings_total counter
apiguardian_findings_total {total_findings}

# HELP apiguardian_findings_open Number of open findings
# TYPE apiguardian_findings_open gauge
apiguardian_findings_open {open_findings}

# HELP apiguardian_findings_critical Number of critical findings
# TYPE apiguardian_findings_critical gauge
apiguardian_findings_critical {critical_findings}

# HELP apiguardian_scans_running Number of running scans
# TYPE apiguardian_scans_running gauge
apiguardian_scans_running {running_scans}

# HELP apiguardian_scans_total Total number of scans
# TYPE apiguardian_scans_total counter
apiguardian_scans_total {total_scans}
"""
        return HTMLResponse(content=metrics, media_type="text/plain")
    finally:
        session.close()


# Dashboard metrics
@api_router.get("/metrics")
async def get_dashboard_metrics():
    return engine.get_metrics()


# Scans endpoints
@api_router.get("/jobs")
async def list_jobs(limit: int = 50):
    return engine.list_scans(limit=limit)


@api_router.post("/jobs")
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new security scan"""
    async def run_scan():
        await engine.run_scan(
            target=request.target,
            scan_type=request.scan_type,
            modules=request.modules,
            config_override={'enable_destructive': request.enable_destructive}
        )
    
    # Run scan in background
    background_tasks.add_task(run_scan)
    
    return {"message": "Scan started", "target": request.target, "type": request.scan_type}


@api_router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    job = engine.get_scan_status(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


# Findings endpoints
@api_router.get("/findings")
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100
):
    return engine.get_findings(severity=severity, status=status, limit=limit)


@api_router.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    session = get_session()
    try:
        finding = session.query(Finding).filter_by(id=finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        return {
            'id': finding.id,
            'issue': finding.issue,
            'description': finding.description,
            'severity': finding.severity,
            'status': finding.status,
            'endpoint': finding.endpoint,
            'method': finding.method,
            'category': finding.category,
            'cwe_id': finding.cwe_id,
            'cvss_score': finding.cvss_score,
            'evidence': finding.evidence,
            'recommendation': finding.recommendation,
            'raw': finding.raw,
            'created_at': finding.created_at.isoformat() if finding.created_at else None
        }
    finally:
        session.close()


@api_router.patch("/findings/{finding_id}")
async def update_finding(finding_id: str, update: FindingUpdate):
    session = get_session()
    try:
        finding = session.query(Finding).filter_by(id=finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        if update.status:
            finding.status = update.status
        if update.assigned_to:
            finding.assigned_to = update.assigned_to
        if update.comment:
            comments = finding.comments or []
            comments.append({
                'text': update.comment,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            finding.comments = comments
        
        session.commit()
        return {"message": "Finding updated"}
    finally:
        session.close()


# Assets endpoints
@api_router.get("/assets")
async def list_assets(limit: int = 100):
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


# Plugins endpoint
@api_router.get("/plugins")
async def list_plugins():
    return plugin_manager.list_plugins()


# Scheduler endpoints
@api_router.get("/scheduler/jobs")
async def list_scheduled_jobs():
    return scheduler.list_jobs()


@api_router.post("/scheduler/jobs")
async def schedule_job(request: ScheduleJobRequest):
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
    if scheduler.remove_job(job_id):
        return {"message": "Job removed"}
    raise HTTPException(status_code=404, detail="Job not found")


# Threat Intelligence endpoints
@api_router.post("/threatintel/lookup")
async def threat_intel_lookup(request: ThreatIntelRequest):
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


@api_router.get("/threatintel/services")
async def list_ti_services():
    return [
        {
            'name': name,
            'api_key_configured': bool(os.environ.get(cls.api_key_env))
        }
        for name, cls in ADAPTERS.items()
    ]


# Integrations endpoints
@api_router.get("/integrations")
async def list_integrations():
    return {
        'threat_intel': list(ADAPTERS.keys()),
        'siem': list(SIEM_CONNECTORS.keys()),
        'messaging': list(NOTIFIERS.keys())
    }


@api_router.post("/integrations/test/{integration_type}/{name}")
async def test_integration(integration_type: str, name: str, mode: str = "mock"):
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


# WebSocket endpoint for live updates
@app.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Echo back for ping/pong
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Include router
app.include_router(api_router)


# Simple HTML dashboard
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
    <div class="grid">
        <div class="card"><div class="label">Total Findings</div><div class="value" id="total">-</div></div>
        <div class="card"><div class="label">Critical</div><div class="value critical" id="critical">-</div></div>
        <div class="card"><div class="label">High</div><div class="value high" id="high">-</div></div>
        <div class="card"><div class="label">Running Scans</div><div class="value" id="running">-</div></div>
        <div class="card"><div class="label">Security Score</div><div class="value" id="score">-</div></div>
    </div>
    <h2 style="margin-bottom: 1rem;">Live Feed <span id="ws-status" class="disconnected">(Connecting...)</span></h2>
    <div class="live-feed" id="feed"></div>
    <script>
        async function fetchMetrics() {
            try {
                const res = await fetch('/api/metrics');
                const data = await res.json();
                document.getElementById('total').textContent = data.findings?.total || 0;
                document.getElementById('critical').textContent = data.findings?.critical || 0;
                document.getElementById('high').textContent = data.findings?.high || 0;
                document.getElementById('running').textContent = data.scans?.running || 0;
                document.getElementById('score').textContent = data.security_score || 0;
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
                item.textContent = `[${data.type}] ${data.data?.issue || JSON.stringify(data.data)}`;
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
