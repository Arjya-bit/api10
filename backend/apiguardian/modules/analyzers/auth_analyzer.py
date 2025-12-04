"""Authentication Analyzer - Comprehensive auth security analysis"""
import logging
import re
from typing import Dict, List, Any

from apiguardian.core.plugin_manager import AnalyzerPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class AuthAnalyzer(AnalyzerPlugin):
    """Analyze authentication security"""
    
    plugin_name = "auth_analyzer"
    description = "Analyze authentication mechanisms for security issues"
    version = "1.0.0"
    
    WEAK_AUTH_PATTERNS = [
        (r'Basic\s+', 'Basic Auth', 'high'),
        (r'api[_-]?key\s*[:=]', 'API Key in URL/Header', 'medium'),
        (r'password\s*[:=]', 'Password exposure', 'critical'),
        (r'secret\s*[:=]', 'Secret exposure', 'critical'),
    ]
    
    SECURITY_HEADERS = [
        ('Strict-Transport-Security', 'HSTS missing', 'medium'),
        ('X-Content-Type-Options', 'Content type options missing', 'low'),
        ('X-Frame-Options', 'Clickjacking protection missing', 'low'),
        ('Content-Security-Policy', 'CSP missing', 'medium'),
        ('X-XSS-Protection', 'XSS protection header missing', 'info'),
    ]
    
    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze authentication security"""
        findings = []
        
        if not target:
            return findings
        
        # Check provided responses
        responses = context.get('responses', [])
        for response in responses:
            findings.extend(self._analyze_auth_response(response, target))
        
        # Probe target
        findings.extend(await self._probe_auth_security(target, context))
        
        return findings
    
    def _analyze_auth_response(self, response: Dict, target: str) -> List[Dict]:
        """Analyze response for auth issues"""
        findings = []
        headers = response.get('headers', {})
        body = response.get('body', '')
        endpoint = response.get('endpoint', target)
        
        # Check security headers
        for header, issue, severity in self.SECURITY_HEADERS:
            if header.lower() not in [h.lower() for h in headers.keys()]:
                findings.append({
                    'issue': issue,
                    'severity': severity,
                    'category': 'Security Headers',
                    'endpoint': endpoint,
                    'method': response.get('method', 'GET'),
                    'evidence': f'Missing {header} header',
                    'recommendation': f'Add {header} header to responses'
                })
        
        # Check for weak auth patterns in response
        for pattern, name, severity in self.WEAK_AUTH_PATTERNS:
            if re.search(pattern, str(body), re.IGNORECASE):
                findings.append({
                    'issue': f'{name} detected in response',
                    'severity': severity,
                    'category': 'Authentication',
                    'endpoint': endpoint,
                    'method': response.get('method', 'GET'),
                    'evidence': f'Pattern matched: {pattern}',
                    'cwe_id': 'CWE-312',
                    'recommendation': 'Avoid exposing authentication credentials in responses'
                })
        
        # Check for session cookie security
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            if 'httponly' not in set_cookie.lower():
                findings.append({
                    'issue': 'Session cookie missing HttpOnly flag',
                    'severity': 'medium',
                    'category': 'Session Management',
                    'endpoint': endpoint,
                    'evidence': f'Set-Cookie: {set_cookie[:100]}',
                    'cwe_id': 'CWE-1004',
                    'recommendation': 'Add HttpOnly flag to session cookies'
                })
            if 'secure' not in set_cookie.lower():
                findings.append({
                    'issue': 'Session cookie missing Secure flag',
                    'severity': 'medium',
                    'category': 'Session Management',
                    'endpoint': endpoint,
                    'evidence': f'Set-Cookie: {set_cookie[:100]}',
                    'cwe_id': 'CWE-614',
                    'recommendation': 'Add Secure flag to session cookies'
                })
        
        return findings
    
    async def _probe_auth_security(self, target: str, context: Dict) -> List[Dict]:
        """Probe target for auth security issues"""
        findings = []
        
        try:
            response = await http_client.get(target)
            if not response:
                return findings
            
            headers = response.headers if hasattr(response, 'headers') else {}
            
            # Check security headers
            for header, issue, severity in self.SECURITY_HEADERS:
                if header.lower() not in [h.lower() for h in headers.keys()]:
                    findings.append({
                        'issue': issue,
                        'severity': severity,
                        'category': 'Security Headers',
                        'endpoint': target,
                        'method': 'GET',
                        'evidence': f'Missing {header} header',
                        'recommendation': f'Add {header} header to responses'
                    })
            
            # Check CORS
            cors_header = headers.get('Access-Control-Allow-Origin', '')
            if cors_header == '*':
                findings.append({
                    'issue': 'Overly permissive CORS policy',
                    'severity': 'medium',
                    'category': 'CORS',
                    'endpoint': target,
                    'method': 'GET',
                    'evidence': 'Access-Control-Allow-Origin: *',
                    'cwe_id': 'CWE-942',
                    'recommendation': 'Restrict CORS to specific trusted domains'
                })
                
        except Exception as e:
            logger.debug(f"Auth probe error: {e}")
        
        return findings
