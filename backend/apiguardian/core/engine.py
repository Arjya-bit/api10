"""Core Engine - Orchestrates scan execution"""
import asyncio
import logging
import yaml
import uuid
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path

from .models import (
    init_db, get_session, get_engine,
    Finding, ScanJob, PluginRun, Asset,
    JobStatus, Severity, FindingStatus
)
from .plugin_manager import plugin_manager, BasePlugin
from .event_bus import event_bus, Event
from .scheduler import scheduler

logger = logging.getLogger(__name__)


class ScanContext:
    """Context passed to plugins during scan execution"""
    
    def __init__(self, job: ScanJob, config: Dict[str, Any]):
        self.job = job
        self.config = config
        self.target = job.target or config.get('target', '')
        self.findings: List[Dict] = []
        self.assets: List[Dict] = []
        self.enable_destructive = config.get('enable_destructive', False)
        self.session = get_session()
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            'job_id': self.job.id,
            'target': self.target,
            'config': self.config,
            'enable_destructive': self.enable_destructive,
            'findings': self.findings,
            'assets': self.assets
        }
    
    def close(self):
        if self.session:
            self.session.close()


class Engine:
    """Main scan orchestration engine"""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.db_engine = None
        self._initialized = False
        
    def _load_config(self, config_path: str = None) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if config_path is None:
            config_path = os.environ.get(
                'APIGUARDIAN_CONFIG',
                '/app/backend/apiguardian/configs/default.yaml'
            )
        
        config = {
            'target': '',
            'modules': ['all'],
            'enable_destructive': False,
            'timeout': 300,
            'max_concurrent': 5,
            'report_format': ['json', 'html']
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    loaded = yaml.safe_load(f)
                    if loaded:
                        config.update(loaded)
                logger.info(f"Loaded config from {config_path}")
            except Exception as e:
                logger.warning(f"Could not load config from {config_path}: {e}")
        
        return config
    
    async def initialize(self):
        """Initialize engine components"""
        if self._initialized:
            return
        
        # Initialize database
        self.db_engine = init_db()
        logger.info("Database initialized")
        
        # Initialize event bus
        await event_bus.initialize()
        
        # Discover plugins
        plugin_manager.discover_plugins()
        logger.info(f"Discovered plugins: {plugin_manager.list_plugins()}")
        
        # Start scheduler
        scheduler.start()
        
        self._initialized = True
        logger.info("Engine initialized")
    
    async def shutdown(self):
        """Shutdown engine"""
        scheduler.stop()
        await event_bus.shutdown()
        logger.info("Engine shutdown complete")
    
    async def run_scan(
        self,
        target: str = None,
        scan_type: str = "full",
        modules: List[str] = None,
        config_override: Dict[str, Any] = None
    ) -> ScanJob:
        """Run a security scan"""
        await self.initialize()
        
        # Merge config
        scan_config = {**self.config}
        if config_override:
            scan_config.update(config_override)
        if target:
            scan_config['target'] = target
        if modules:
            scan_config['modules'] = modules
        
        # Create scan job
        session = get_session()
        job = ScanJob(
            id=str(uuid.uuid4()),
            name=f"{scan_type.capitalize()} Scan - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            type=scan_type,
            target=scan_config.get('target', ''),
            config=scan_config,
            modules=scan_config.get('modules', []),
            status=JobStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc)
        )
        session.add(job)
        session.commit()
        
        # Create context
        context = ScanContext(job, scan_config)
        
        try:
            # Publish scan started event
            await event_bus.publish(Event.create(
                'scan.started',
                {'job_id': job.id, 'type': scan_type, 'target': target}
            ))
            
            # Execute scan phases
            await self._run_phase(context, 'recon', 'Reconnaissance')
            await self._run_phase(context, 'analyzer', 'Analysis')
            await self._run_phase(context, 'fuzzer', 'Fuzzing')
            
            # Generate reports
            await self._generate_reports(context)
            
            # Update job status
            job.status = JobStatus.COMPLETED.value
            job.finished_at = datetime.now(timezone.utc)
            job.findings_count = len(context.findings)
            
            # Count by severity
            for finding in context.findings:
                sev = finding.get('severity', 'info').lower()
                if sev == 'critical':
                    job.critical_count += 1
                elif sev == 'high':
                    job.high_count += 1
                elif sev == 'medium':
                    job.medium_count += 1
                elif sev == 'low':
                    job.low_count += 1
            
            session.commit()
            
            # Publish scan completed event
            await event_bus.publish(Event.create(
                'scan.completed',
                {
                    'job_id': job.id,
                    'findings_count': job.findings_count,
                    'critical': job.critical_count,
                    'high': job.high_count
                }
            ))
            
            logger.info(f"Scan completed: {job.id} - {job.findings_count} findings")
            
        except Exception as e:
            job.status = JobStatus.FAILED.value
            job.error_message = str(e)
            job.finished_at = datetime.now(timezone.utc)
            session.commit()
            
            await event_bus.publish(Event.create(
                'scan.failed',
                {'job_id': job.id, 'error': str(e)}
            ))
            
            logger.error(f"Scan failed: {job.id} - {e}")
            raise
        
        finally:
            context.close()
            session.close()
        
        return job
    
    async def _run_phase(
        self,
        context: ScanContext,
        plugin_type: str,
        phase_name: str
    ):
        """Run a scan phase (recon, analysis, fuzzing)"""
        logger.info(f"Starting {phase_name} phase")
        
        plugins = plugin_manager.get_plugins_by_type(plugin_type)
        requested_modules = context.config.get('modules', ['all'])
        
        for plugin_cls in plugins:
            # Skip if not in requested modules
            if 'all' not in requested_modules and plugin_cls.plugin_name not in requested_modules:
                continue
            
            if not plugin_cls.enabled:
                continue
            
            plugin = plugin_cls(context.config)
            
            # Record plugin run
            run = PluginRun(
                id=str(uuid.uuid4()),
                plugin=plugin_cls.plugin_name,
                plugin_type=plugin_type,
                scan_job_id=context.job.id,
                status=JobStatus.RUNNING.value,
                started_at=datetime.now(timezone.utc)
            )
            context.session.add(run)
            context.session.commit()
            
            try:
                results = await plugin.execute(context.to_dict())
                
                # Process results
                findings_count = 0
                for result in results:
                    if plugin_type == 'recon':
                        context.assets.extend(result.get('endpoints', []))
                    else:
                        await self._save_finding(context, result, plugin_cls.plugin_name)
                        context.findings.append(result)
                        findings_count += 1
                
                run.status = JobStatus.COMPLETED.value
                run.finished_at = datetime.now(timezone.utc)
                run.findings_generated = findings_count
                run.result_summary = {'count': len(results)}
                
                logger.info(f"Plugin {plugin_cls.plugin_name} completed: {findings_count} findings")
                
            except Exception as e:
                run.status = JobStatus.FAILED.value
                run.finished_at = datetime.now(timezone.utc)
                run.error_message = str(e)
                logger.error(f"Plugin {plugin_cls.plugin_name} failed: {e}")
            
            context.session.commit()
    
    async def _save_finding(
        self,
        context: ScanContext,
        finding_data: Dict[str, Any],
        plugin_name: str
    ):
        """Save finding to database with deduplication"""
        # Generate fingerprint
        fingerprint = Finding.generate_fingerprint(
            finding_data.get('issue', ''),
            finding_data.get('endpoint', ''),
            finding_data.get('method', 'GET'),
            finding_data.get('evidence', '')
        )
        
        # Check for existing finding
        existing = context.session.query(Finding).filter_by(fingerprint=fingerprint).first()
        if existing:
            logger.debug(f"Duplicate finding skipped: {fingerprint[:16]}...")
            return
        
        # Create new finding
        finding = Finding(
            id=str(uuid.uuid4()),
            fingerprint=fingerprint,
            issue=finding_data.get('issue', 'Unknown Issue'),
            description=finding_data.get('description'),
            severity=finding_data.get('severity', Severity.INFO.value),
            category=finding_data.get('category'),
            endpoint=finding_data.get('endpoint'),
            method=finding_data.get('method'),
            evidence=finding_data.get('evidence'),
            raw=finding_data,
            cwe_id=finding_data.get('cwe_id'),
            cvss_score=finding_data.get('cvss_score'),
            recommendation=finding_data.get('recommendation'),
            plugin_name=plugin_name,
            scan_job_id=context.job.id,
            status=FindingStatus.OPEN.value
        )
        
        context.session.add(finding)
        context.session.commit()
        
        # Publish finding event
        await event_bus.publish(Event.create(
            'finding.created',
            {
                'id': finding.id,
                'issue': finding.issue,
                'severity': finding.severity,
                'endpoint': finding.endpoint
            }
        ))
    
    async def _generate_reports(self, context: ScanContext):
        """Generate reports for completed scan"""
        reporters = plugin_manager.get_plugins_by_type('reporter')
        report_formats = context.config.get('report_format', ['json'])
        
        for reporter_cls in reporters:
            if reporter_cls.plugin_name in report_formats or 'all' in report_formats:
                try:
                    reporter = reporter_cls(context.config)
                    await reporter.execute(context.to_dict())
                    logger.info(f"Generated {reporter_cls.plugin_name} report")
                except Exception as e:
                    logger.error(f"Failed to generate {reporter_cls.plugin_name} report: {e}")
    
    def get_scan_status(self, job_id: str) -> Optional[Dict]:
        """Get scan job status"""
        session = get_session()
        try:
            job = session.query(ScanJob).filter_by(id=job_id).first()
            if job:
                return {
                    'id': job.id,
                    'name': job.name,
                    'type': job.type,
                    'status': job.status,
                    'progress': job.progress,
                    'findings_count': job.findings_count,
                    'critical_count': job.critical_count,
                    'high_count': job.high_count,
                    'started_at': job.started_at.isoformat() if job.started_at else None,
                    'finished_at': job.finished_at.isoformat() if job.finished_at else None
                }
            return None
        finally:
            session.close()
    
    def list_scans(self, limit: int = 50) -> List[Dict]:
        """List recent scans"""
        session = get_session()
        try:
            jobs = session.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit).all()
            return [self.get_scan_status(job.id) for job in jobs]
        finally:
            session.close()
    
    def get_findings(
        self,
        severity: str = None,
        status: str = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get findings with optional filters"""
        session = get_session()
        try:
            query = session.query(Finding)
            if severity:
                query = query.filter_by(severity=severity)
            if status:
                query = query.filter_by(status=status)
            
            findings = query.order_by(Finding.created_at.desc()).limit(limit).all()
            return [
                {
                    'id': f.id,
                    'issue': f.issue,
                    'severity': f.severity,
                    'status': f.status,
                    'endpoint': f.endpoint,
                    'method': f.method,
                    'category': f.category,
                    'cwe_id': f.cwe_id,
                    'cvss_score': f.cvss_score,
                    'created_at': f.created_at.isoformat() if f.created_at else None
                }
                for f in findings
            ]
        finally:
            session.close()
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get dashboard metrics"""
        session = get_session()
        try:
            total_findings = session.query(Finding).count()
            open_findings = session.query(Finding).filter_by(status=FindingStatus.OPEN.value).count()
            critical = session.query(Finding).filter_by(severity=Severity.CRITICAL.value).count()
            high = session.query(Finding).filter_by(severity=Severity.HIGH.value).count()
            
            running_scans = session.query(ScanJob).filter_by(status=JobStatus.RUNNING.value).count()
            total_scans = session.query(ScanJob).count()
            
            return {
                'findings': {
                    'total': total_findings,
                    'open': open_findings,
                    'critical': critical,
                    'high': high
                },
                'scans': {
                    'total': total_scans,
                    'running': running_scans
                },
                'security_score': max(0, 100 - (critical * 20 + high * 10))
            }
        finally:
            session.close()


# Global engine instance
engine = Engine()


# CLI entry point
if __name__ == '__main__':
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='APIGuardian Security Scanner')
    parser.add_argument('--mode', choices=['local', 'scan', 'report'], default='local')
    parser.add_argument('--target', type=str, help='Target URL to scan')
    parser.add_argument('--type', type=str, default='full', help='Scan type')
    parser.add_argument('--enable-destructive', action='store_true', help='Enable destructive tests')
    parser.add_argument('--config', type=str, help='Config file path')
    
    args = parser.parse_args()
    
    async def main():
        eng = Engine(args.config)
        await eng.initialize()
        
        if args.mode in ['local', 'scan']:
            job = await eng.run_scan(
                target=args.target,
                scan_type=args.type,
                config_override={'enable_destructive': args.enable_destructive}
            )
            print(f"\nScan completed: {job.id}")
            print(f"Findings: {job.findings_count} (Critical: {job.critical_count}, High: {job.high_count})")
        
        await eng.shutdown()
    
    asyncio.run(main())
