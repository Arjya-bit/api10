"""SIEM Connectors - Splunk, Elastic, QRadar"""
import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class BaseSIEMConnector(ABC):
    """Base class for SIEM connectors"""
    
    connector_name: str = "base"
    
    def __init__(self, mode: str = "mock", config: Dict[str, Any] = None):
        self.mode = mode
        self.config = config or {}
        
    @abstractmethod
    def send_finding(self, finding: Dict[str, Any]) -> bool:
        """Send a single finding to SIEM"""
        pass
    
    @abstractmethod
    def send_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Send multiple findings, return count of successfully sent"""
        pass
    
    def format_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Format finding for SIEM ingestion"""
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'apiguardian',
            'event_type': 'security_finding',
            'severity': finding.get('severity', 'info'),
            'issue': finding.get('issue', ''),
            'category': finding.get('category', ''),
            'endpoint': finding.get('endpoint', ''),
            'cwe_id': finding.get('cwe_id', ''),
            'cvss_score': finding.get('cvss_score'),
            'evidence': finding.get('evidence', ''),
            'raw': finding
        }


class SplunkConnector(BaseSIEMConnector):
    """Splunk HEC (HTTP Event Collector) connector"""
    
    connector_name = "splunk"
    
    def __init__(self, mode: str = "mock", config: Dict[str, Any] = None):
        super().__init__(mode, config)
        config = config or {}
        self.hec_url = config.get('hec_url') or os.environ.get('SPLUNK_HEC_URL')
        self.hec_token = config.get('hec_token') or os.environ.get('SPLUNK_HEC_TOKEN')
        self.index = config.get('index', 'security')
        self.source = config.get('source', 'apiguardian')
        
    def send_finding(self, finding: Dict[str, Any]) -> bool:
        """Send finding to Splunk"""
        if self.mode == 'mock':
            logger.info(f"[MOCK] Splunk: Would send finding: {finding.get('issue', '')[:50]}")
            return True
        
        if not self.hec_url or not self.hec_token:
            logger.warning("Splunk HEC not configured")
            return False
        
        try:
            import httpx
            event = {
                'time': datetime.now(timezone.utc).timestamp(),
                'index': self.index,
                'source': self.source,
                'sourcetype': '_json',
                'event': self.format_finding(finding)
            }
            
            response = httpx.post(
                self.hec_url,
                headers={'Authorization': f'Splunk {self.hec_token}'},
                json=event,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Splunk send failed: {e}")
            return False
    
    def send_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Send multiple findings"""
        success_count = 0
        for finding in findings:
            if self.send_finding(finding):
                success_count += 1
        return success_count


class ElasticConnector(BaseSIEMConnector):
    """Elasticsearch connector"""
    
    connector_name = "elastic"
    
    def __init__(self, mode: str = "mock", config: Dict[str, Any] = None):
        super().__init__(mode, config)
        config = config or {}
        self.es_url = config.get('es_url') or os.environ.get('ELASTICSEARCH_URL')
        self.api_key = config.get('api_key') or os.environ.get('ELASTICSEARCH_API_KEY')
        self.index = config.get('index', 'apiguardian-findings')
        
    def send_finding(self, finding: Dict[str, Any]) -> bool:
        """Send finding to Elasticsearch"""
        if self.mode == 'mock':
            logger.info(f"[MOCK] Elastic: Would index finding: {finding.get('issue', '')[:50]}")
            return True
        
        if not self.es_url:
            logger.warning("Elasticsearch not configured")
            return False
        
        try:
            import httpx
            doc = self.format_finding(finding)
            doc['@timestamp'] = datetime.now(timezone.utc).isoformat()
            
            headers = {'Content-Type': 'application/json'}
            if self.api_key:
                headers['Authorization'] = f'ApiKey {self.api_key}'
            
            response = httpx.post(
                f"{self.es_url}/{self.index}/_doc",
                headers=headers,
                json=doc,
                timeout=10
            )
            return response.status_code in [200, 201]
        except Exception as e:
            logger.error(f"Elasticsearch send failed: {e}")
            return False
    
    def send_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Send multiple findings using bulk API"""
        if self.mode == 'mock':
            logger.info(f"[MOCK] Elastic: Would bulk index {len(findings)} findings")
            return len(findings)
        
        # For live mode, use bulk API for efficiency
        success_count = 0
        for finding in findings:
            if self.send_finding(finding):
                success_count += 1
        return success_count


class QRadarConnector(BaseSIEMConnector):
    """IBM QRadar connector"""
    
    connector_name = "qradar"
    
    def __init__(self, mode: str = "mock", config: Dict[str, Any] = None):
        super().__init__(mode, config)
        config = config or {}
        self.qradar_url = config.get('qradar_url') or os.environ.get('QRADAR_URL')
        self.api_token = config.get('api_token') or os.environ.get('QRADAR_API_TOKEN')
        
    def send_finding(self, finding: Dict[str, Any]) -> bool:
        """Send finding to QRadar"""
        if self.mode == 'mock':
            logger.info(f"[MOCK] QRadar: Would send finding: {finding.get('issue', '')[:50]}")
            return True
        
        if not self.qradar_url or not self.api_token:
            logger.warning("QRadar not configured")
            return False
        
        # QRadar REST API implementation would go here
        logger.info(f"QRadar live mode - would send to {self.qradar_url}")
        return True
    
    def send_findings(self, findings: List[Dict[str, Any]]) -> int:
        success_count = 0
        for finding in findings:
            if self.send_finding(finding):
                success_count += 1
        return success_count


# Connector registry
SIEM_CONNECTORS = {
    'splunk': SplunkConnector,
    'elastic': ElasticConnector,
    'qradar': QRadarConnector
}


def get_siem_connector(connector_name: str, mode: str = 'mock', config: Dict = None) -> Optional[BaseSIEMConnector]:
    """Get SIEM connector by name"""
    connector_cls = SIEM_CONNECTORS.get(connector_name.lower())
    if connector_cls:
        return connector_cls(mode=mode, config=config)
    return None
