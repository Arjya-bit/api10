"""PDF Reporter - Generate PDF reports (stub)"""
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Any
from pathlib import Path

from apiguardian.core.plugin_manager import ReporterPlugin
from apiguardian.utils import atomic_write

logger = logging.getLogger(__name__)

# Try to import reportlab
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab not available - PDF reports will be stubs")


class PDFReporter(ReporterPlugin):
    """Generate PDF format reports"""
    
    plugin_name = "pdf"
    description = "Generate PDF reports (requires reportlab)"
    version = "1.0.0"
    
    async def generate(self, findings: List[Dict], context: Dict[str, Any]) -> str:
        """Generate PDF report"""
        config = context.get('config', {})
        report_dir = config.get('report_dir', 'reports')
        
        # Ensure report directory exists
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        
        report_path = os.path.join(report_dir, 'report.pdf')
        
        if not REPORTLAB_AVAILABLE:
            # Create stub file
            with open(report_path, 'w') as f:
                f.write("PDF generation requires reportlab. Install with: pip install reportlab")
            logger.warning("PDF report stub created - install reportlab for full PDF support")
            return report_path
        
        # Generate actual PDF
        self._generate_pdf(findings, context, report_path)
        
        logger.info(f"PDF report written to {report_path}")
        return report_path
    
    def _generate_pdf(self, findings: List[Dict], context: Dict[str, Any], output_path: str):
        """Generate actual PDF using reportlab"""
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=HexColor('#00ff94'),
            spaceAfter=20
        )
        story.append(Paragraph("APIGuardian Security Report", title_style))
        
        # Meta info
        meta = f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        story.append(Paragraph(meta, styles['Normal']))
        story.append(Paragraph(f"Target: {context.get('target', 'Unknown')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Summary
        story.append(Paragraph("Summary", styles['Heading2']))
        summary = self._generate_summary(findings)
        summary_text = f"Total: {summary['total']} | Critical: {summary['by_severity']['critical']} | High: {summary['by_severity']['high']} | Medium: {summary['by_severity']['medium']} | Low: {summary['by_severity']['low']}"
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Findings table
        if findings:
            story.append(Paragraph("Findings", styles['Heading2']))
            
            table_data = [['Severity', 'Issue', 'Endpoint', 'CWE']]
            for finding in findings[:50]:  # Limit to 50 for PDF
                table_data.append([
                    finding.get('severity', 'info').upper(),
                    finding.get('issue', '')[:60],
                    finding.get('endpoint', '')[:40],
                    finding.get('cwe_id', '-')
                ])
            
            table = Table(table_data, colWidths=[60, 200, 150, 50])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#333333')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f8f8')),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#cccccc'))
            ]))
            story.append(table)
        
        doc.build(story)
    
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
