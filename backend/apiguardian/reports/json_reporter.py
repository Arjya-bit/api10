"""JSON Reporter - Generate JSON reports"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Any
from pathlib import Path

from apiguardian.core.plugin_manager import ReporterPlugin
from apiguardian.utils import atomic_write

logger = logging.getLogger(__name__)


class JSONReporter(ReporterPlugin):
    """Generate JSON format reports"""
    
    plugin_name = "json"
    description = "Generate comprehensive JSON reports"
    version = "1.0.0"
    
    async def generate(self, findings: List[Dict], context: Dict[str, Any]) -> str:
        """Generate JSON report"""
        config = context.get('config', {})
        report_dir = config.get('report_dir', 'reports')
        
        # Ensure report directory exists
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        
        # Build report
        report = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'report_version': '1.0',
            'scan_info': {
                'job_id': context.get('job_id'),
                'target': context.get('target'),
                'scan_type': context.get('scan_type', 'full')
            },
            'summary': self._generate_summary(findings),
            'findings': findings,
            'assets': context.get('assets', []),
            'metadata': {
                'engine_version': '1.0.0',
                'plugins_used': context.get('plugins_used', [])
            }
        }
        
        # Write report atomically
        report_path = os.path.join(report_dir, 'latest.json')
        atomic_write(report_path, json.dumps(report, indent=2, default=str))
        
        # Also write timestamped version
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        timestamped_path = os.path.join(report_dir, f'report_{timestamp}.json')
        atomic_write(timestamped_path, json.dumps(report, indent=2, default=str))
        
        logger.info(f"JSON report written to {report_path}")
        return report_path
    
    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """Generate findings summary"""
        summary = {
            'total': len(findings),
            'by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'by_category': {}
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
            
            category = finding.get('category', 'Other')
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
        
        return summary
