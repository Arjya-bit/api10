"""Messaging Notifiers - Slack, Teams, Email"""
import json
import logging
import os
import smtplib
from abc import ABC, abstractmethod
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class BaseNotifier(ABC):
    """Base class for notification services"""
    
    notifier_name: str = "base"
    
    def __init__(self, mode: str = "mock", config: Dict[str, Any] = None):
        self.mode = mode
        self.config = config or {}
        
    @abstractmethod
    def send_alert(self, title: str, message: str, severity: str = "info", details: Dict = None) -> bool:
        """Send an alert notification"""
        pass
    
    def format_finding_alert(self, finding: Dict[str, Any]) -> Dict[str, str]:
        """Format a finding as an alert"""
        severity = finding.get('severity', 'info')
        return {
            'title': f"[{severity.upper()}] {finding.get('issue', 'Security Finding')}",
            'message': f"**Endpoint:** {finding.get('endpoint', 'N/A')}\n**Category:** {finding.get('category', 'N/A')}\n**CWE:** {finding.get('cwe_id', 'N/A')}",
            'severity': severity
        }


class SlackNotifier(BaseNotifier):
    """Slack webhook notifier"""
    
    notifier_name = "slack"
    
    SEVERITY_COLORS = {
        'critical': '#FF2A6D',
        'high': '#FF9F1C',
        'medium': '#F1C40F',
        'low': '#00FF94',
        'info': '#5865F2'
    }
    
    def __init__(self, mode: str = "mock", config: Dict[str, Any] = None):
        super().__init__(mode, config)
        config = config or {}
        self.webhook_url = config.get('webhook_url') or os.environ.get('SLACK_WEBHOOK_URL')
        
    def send_alert(self, title: str, message: str, severity: str = "info", details: Dict = None) -> bool:
        """Send Slack alert"""
        if self.mode == 'mock':
            logger.info(f"[MOCK] Slack: {title}")
            return True
        
        if not self.webhook_url:
            logger.warning("Slack webhook not configured")
            return False
        
        try:
            import httpx
            
            payload = {
                'attachments': [{
                    'color': self.SEVERITY_COLORS.get(severity, '#808080'),
                    'title': title,
                    'text': message,
                    'footer': 'APIGuardian Security',
                    'ts': int(datetime.now(timezone.utc).timestamp())
                }]
            }
            
            if details:
                payload['attachments'][0]['fields'] = [
                    {'title': k, 'value': str(v), 'short': True}
                    for k, v in details.items()
                ]
            
            response = httpx.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return False


class TeamsNotifier(BaseNotifier):
    """Microsoft Teams webhook notifier"""
    
    notifier_name = "teams"
    
    def __init__(self, mode: str = "mock", config: Dict[str, Any] = None):
        super().__init__(mode, config)
        config = config or {}
        self.webhook_url = config.get('webhook_url') or os.environ.get('TEAMS_WEBHOOK_URL')
        
    def send_alert(self, title: str, message: str, severity: str = "info", details: Dict = None) -> bool:
        """Send Teams alert"""
        if self.mode == 'mock':
            logger.info(f"[MOCK] Teams: {title}")
            return True
        
        if not self.webhook_url:
            logger.warning("Teams webhook not configured")
            return False
        
        try:
            import httpx
            
            # Teams Adaptive Card format
            payload = {
                '@type': 'MessageCard',
                '@context': 'http://schema.org/extensions',
                'themeColor': 'FF2A6D' if severity == 'critical' else '0076D7',
                'summary': title,
                'sections': [{
                    'activityTitle': title,
                    'text': message,
                    'facts': [{'name': k, 'value': str(v)} for k, v in (details or {}).items()]
                }]
            }
            
            response = httpx.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Teams notification failed: {e}")
            return False


class EmailNotifier(BaseNotifier):
    """Email SMTP notifier"""
    
    notifier_name = "email"
    
    def __init__(self, mode: str = "mock", config: Dict[str, Any] = None):
        super().__init__(mode, config)
        config = config or {}
        self.smtp_host = config.get('smtp_host') or os.environ.get('SMTP_HOST', 'localhost')
        self.smtp_port = int(config.get('smtp_port') or os.environ.get('SMTP_PORT', 587))
        self.smtp_user = config.get('smtp_user') or os.environ.get('SMTP_USER')
        self.smtp_pass = config.get('smtp_pass') or os.environ.get('SMTP_PASS')
        self.from_addr = config.get('from_addr') or os.environ.get('ALERT_FROM_EMAIL', 'alerts@apiguardian.local')
        self.to_addrs = config.get('to_addrs') or os.environ.get('ALERT_TO_EMAILS', '').split(',')
        
    def send_alert(self, title: str, message: str, severity: str = "info", details: Dict = None) -> bool:
        """Send email alert"""
        if self.mode == 'mock':
            logger.info(f"[MOCK] Email: {title}")
            return True
        
        if not self.to_addrs or not self.to_addrs[0]:
            logger.warning("Email recipients not configured")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[APIGuardian {severity.upper()}] {title}"
            msg['From'] = self.from_addr
            msg['To'] = ', '.join(self.to_addrs)
            
            # Plain text
            text_body = f"{title}\n\n{message}"
            if details:
                text_body += "\n\nDetails:\n" + "\n".join(f"{k}: {v}" for k, v in details.items())
            
            msg.attach(MIMEText(text_body, 'plain'))
            
            # Send
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_user and self.smtp_pass:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            
            return True
        except Exception as e:
            logger.error(f"Email notification failed: {e}")
            return False


# Notifier registry
NOTIFIERS = {
    'slack': SlackNotifier,
    'teams': TeamsNotifier,
    'email': EmailNotifier
}


def get_notifier(notifier_name: str, mode: str = 'mock', config: Dict = None) -> Optional[BaseNotifier]:
    """Get notifier by name"""
    notifier_cls = NOTIFIERS.get(notifier_name.lower())
    if notifier_cls:
        return notifier_cls(mode=mode, config=config)
    return None
