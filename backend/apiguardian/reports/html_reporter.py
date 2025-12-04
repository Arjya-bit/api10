"""HTML Reporter - Generate HTML reports with Jinja2"""
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Any
from pathlib import Path

from jinja2 import Environment, BaseLoader

from apiguardian.core.plugin_manager import ReporterPlugin
from apiguardian.utils import atomic_write

logger = logging.getLogger(__name__)


HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APIGuardian Security Report</title>
    <style>
        :root {
            --bg-primary: #0a0a0a;
            --bg-secondary: #111;
            --text-primary: #eee;
            --text-secondary: #888;
            --accent: #00ff94;
            --critical: #ff2a6d;
            --high: #ff9f1c;
            --medium: #f1c40f;
            --low: #00ff94;
            --info: #5865f2;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { 
            color: var(--accent); 
            font-size: 2rem; 
            margin-bottom: 0.5rem;
            font-family: monospace;
        }
        h2 { 
            color: var(--text-primary); 
            font-size: 1.25rem; 
            margin: 2rem 0 1rem;
            font-family: monospace;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }
        .meta { color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 2rem; }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid #222;
            border-radius: 4px;
            padding: 1rem;
        }
        .stat-card .label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-secondary);
        }
        .stat-card .value {
            font-size: 2rem;
            font-weight: bold;
            font-family: monospace;
        }
        .stat-card.critical .value { color: var(--critical); }
        .stat-card.high .value { color: var(--high); }
        .stat-card.medium .value { color: var(--medium); }
        .stat-card.low .value { color: var(--low); }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border: 1px solid #222;
            border-radius: 4px;
            overflow: hidden;
        }
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid #222;
        }
        th {
            background: #1a1a1a;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-secondary);
        }
        tr:hover { background: #1a1a1a; }
        
        .severity {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 2px;
            font-size: 0.75rem;
            font-family: monospace;
            text-transform: uppercase;
        }
        .severity.critical { background: rgba(255,42,109,0.1); color: var(--critical); border: 1px solid var(--critical); }
        .severity.high { background: rgba(255,159,28,0.1); color: var(--high); border: 1px solid var(--high); }
        .severity.medium { background: rgba(241,196,15,0.1); color: var(--medium); border: 1px solid var(--medium); }
        .severity.low { background: rgba(0,255,148,0.1); color: var(--low); border: 1px solid var(--low); }
        .severity.info { background: rgba(88,101,242,0.1); color: var(--info); border: 1px solid var(--info); }
        
        .endpoint { font-family: monospace; font-size: 0.875rem; color: var(--accent); }
        .method { font-family: monospace; font-size: 0.75rem; padding: 0.125rem 0.375rem; background: #222; border-radius: 2px; }
        
        footer {
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid #222;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>API GUARDIAN</h1>
        <p class="meta">Security Scan Report • Generated: {{ generated_at }} • Target: {{ target }}</p>
        
        <div class="summary-grid">
            <div class="stat-card">
                <div class="label">Total Findings</div>
                <div class="value">{{ summary.total }}</div>
            </div>
            <div class="stat-card critical">
                <div class="label">Critical</div>
                <div class="value">{{ summary.by_severity.critical }}</div>
            </div>
            <div class="stat-card high">
                <div class="label">High</div>
                <div class="value">{{ summary.by_severity.high }}</div>
            </div>
            <div class="stat-card medium">
                <div class="label">Medium</div>
                <div class="value">{{ summary.by_severity.medium }}</div>
            </div>
            <div class="stat-card low">
                <div class="label">Low</div>
                <div class="value">{{ summary.by_severity.low }}</div>
            </div>
        </div>
        
        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Issue</th>
                    <th>Endpoint</th>
                    <th>Category</th>
                    <th>CWE</th>
                </tr>
            </thead>
            <tbody>
                {% for finding in findings %}
                <tr>
                    <td><span class="severity {{ finding.severity }}">{{ finding.severity }}</span></td>
                    <td>{{ finding.issue }}</td>
                    <td>
                        <span class="method">{{ finding.method or 'GET' }}</span>
                        <span class="endpoint">{{ finding.endpoint or 'N/A' }}</span>
                    </td>
                    <td>{{ finding.category or 'Other' }}</td>
                    <td>{{ finding.cwe_id or '-' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <footer>
            <p>Generated by APIGuardian Security Platform</p>
        </footer>
    </div>
</body>
</html>
'''


class HTMLReporter(ReporterPlugin):
    """Generate HTML format reports"""
    
    plugin_name = "html"
    description = "Generate styled HTML reports"
    version = "1.0.0"
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.env = Environment(loader=BaseLoader())
        self.template = self.env.from_string(HTML_TEMPLATE)
    
    async def generate(self, findings: List[Dict], context: Dict[str, Any]) -> str:
        """Generate HTML report"""
        config = context.get('config', {})
        report_dir = config.get('report_dir', 'reports')
        
        # Ensure report directory exists
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        
        # Prepare template data
        summary = self._generate_summary(findings)
        
        html_content = self.template.render(
            generated_at=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            target=context.get('target', 'Unknown'),
            summary=summary,
            findings=findings
        )
        
        # Write report
        report_path = os.path.join(report_dir, 'report.html')
        atomic_write(report_path, html_content)
        
        logger.info(f"HTML report written to {report_path}")
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
            }
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
        
        return summary
