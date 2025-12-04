"""Cloud Security Analyzer - AWS/GCP/Azure security analysis"""
import logging
import re
from typing import Dict, List, Any

from apiguardian.core.plugin_manager import AnalyzerPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class CloudAnalyzer(AnalyzerPlugin):
    """Analyze cloud-specific security configurations"""
    
    plugin_name = "cloud_analyzer"
    description = "Detect AWS/GCP/Azure misconfigurations and exposed credentials"
    version = "1.0.0"
    
    # Cloud credential patterns
    CLOUD_PATTERNS = [
        # AWS
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'critical'),
        (r'aws_secret_access_key\s*[=:]\s*[\'"]?[A-Za-z0-9/+=]{40}', 'AWS Secret Key', 'critical'),
        (r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'AWS MWS Auth Token', 'critical'),
        (r's3\.amazonaws\.com/[a-zA-Z0-9._-]+', 'AWS S3 Bucket URL', 'medium'),
        (r'[a-zA-Z0-9._-]+\.s3\.amazonaws\.com', 'AWS S3 Bucket URL', 'medium'),
        
        # GCP
        (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key', 'high'),
        (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 'GCP OAuth Client ID', 'medium'),
        (r'ya29\.[0-9A-Za-z_-]+', 'GCP OAuth Token', 'critical'),
        (r'storage\.googleapis\.com/[a-zA-Z0-9._-]+', 'GCP Storage Bucket', 'medium'),
        
        # Azure
        (r'AccountKey=[A-Za-z0-9+/=]{88}', 'Azure Storage Account Key', 'critical'),
        (r'https://[a-zA-Z0-9_-]+\.blob\.core\.windows\.net', 'Azure Blob Storage', 'medium'),
        (r'DefaultEndpointsProtocol=https;AccountName=', 'Azure Connection String', 'critical'),
        
        # Generic cloud
        (r'sk-[A-Za-z0-9]{48}', 'OpenAI API Key', 'critical'),
        (r'ghp_[A-Za-z0-9]{36}', 'GitHub Personal Access Token', 'critical'),
        (r'gho_[A-Za-z0-9]{36}', 'GitHub OAuth Token', 'critical'),
        (r'glpat-[A-Za-z0-9_-]{20}', 'GitLab Personal Access Token', 'critical'),
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'Slack Token', 'critical'),
    ]
    
    # Cloud metadata endpoints (for SSRF detection)
    METADATA_ENDPOINTS = [
        'http://169.254.169.254/latest/meta-data/',  # AWS
        'http://metadata.google.internal/computeMetadata/v1/',  # GCP
        'http://169.254.169.254/metadata/instance',  # Azure
    ]
    
    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze for cloud security issues"""
        findings = []
        
        if not target:
            return findings
        
        # Check responses for cloud credentials
        responses = context.get('responses', [])
        for response in responses:
            findings.extend(self._scan_for_cloud_credentials(response, target))
        
        # Probe for cloud misconfigurations
        findings.extend(await self._probe_cloud_misconfig(target, context))
        
        return findings
    
    def _scan_for_cloud_credentials(self, response: Dict, target: str) -> List[Dict]:
        """Scan response for exposed cloud credentials"""
        findings = []
        body = str(response.get('body', ''))
        headers = str(response.get('headers', {}))
        endpoint = response.get('endpoint', target)
        
        content = body + headers
        
        for pattern, name, severity in self.CLOUD_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Mask the credential
                masked = matches[0][:8] + '...' + matches[0][-4:] if len(matches[0]) > 12 else '***'
                findings.append({
                    'issue': f'{name} exposed',
                    'severity': severity,
                    'category': 'Cloud Security',
                    'endpoint': endpoint,
                    'method': response.get('method', 'GET'),
                    'evidence': f'Found {name}: {masked}',
                    'cwe_id': 'CWE-798',
                    'recommendation': f'Remove {name} from response. Rotate compromised credentials immediately.'
                })
        
        return findings
    
    async def _probe_cloud_misconfig(self, target: str, context: Dict) -> List[Dict]:
        """Probe for cloud misconfigurations"""
        findings = []
        
        try:
            response = await http_client.get(target)
            if not response:
                return findings
            
            body = response.text if hasattr(response, 'text') else ''
            headers = response.headers if hasattr(response, 'headers') else {}
            
            # Check response for cloud credentials
            content = body + str(headers)
            for pattern, name, severity in self.CLOUD_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        'issue': f'Potential {name} exposure detected',
                        'severity': severity,
                        'category': 'Cloud Security',
                        'endpoint': target,
                        'method': 'GET',
                        'evidence': f'Pattern match for {name}',
                        'cwe_id': 'CWE-798',
                        'recommendation': 'Review and rotate any exposed cloud credentials'
                    })
            
            # Check for cloud provider headers
            server = headers.get('Server', '').lower()
            if 'amazons3' in server or 'awselb' in server:
                findings.append({
                    'issue': 'AWS infrastructure detected',
                    'severity': 'info',
                    'category': 'Cloud Security',
                    'endpoint': target,
                    'evidence': f'Server: {server}',
                    'recommendation': 'Ensure AWS security best practices are followed'
                })
            elif 'google' in server:
                findings.append({
                    'issue': 'GCP infrastructure detected',
                    'severity': 'info',
                    'category': 'Cloud Security',
                    'endpoint': target,
                    'evidence': f'Server: {server}',
                    'recommendation': 'Ensure GCP security best practices are followed'
                })
                
        except Exception as e:
            logger.debug(f"Cloud probe error: {e}")
        
        return findings
