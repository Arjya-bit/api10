"""JWT Analyzer - Detect JWT vulnerabilities"""
import base64
import json
import re
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from apiguardian.core.plugin_manager import AnalyzerPlugin

logger = logging.getLogger(__name__)


class JWTAnalyzer(AnalyzerPlugin):
    """Analyze JWT tokens for security issues"""
    
    plugin_name = "jwt_analyzer"
    description = "Detect JWT token exposure, weak algorithms, and expiry issues"
    version = "1.0.0"
    
    WEAK_ALGORITHMS = ['none', 'None', 'NONE', 'HS256']
    JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
    
    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze target for JWT vulnerabilities"""
        findings = []
        
        # Check responses in context for JWTs
        responses = context.get('responses', [])
        for response in responses:
            jwt_findings = self._analyze_response(response, target)
            findings.extend(jwt_findings)
        
        # Also check if JWT provided directly
        if 'jwt_token' in context:
            jwt_findings = self._analyze_jwt(context['jwt_token'], target)
            findings.extend(jwt_findings)
        
        # Demo: analyze common patterns in target URL
        if target:
            findings.extend(await self._probe_jwt_endpoints(target, context))
        
        return findings
    
    def _analyze_response(self, response: Dict, target: str) -> List[Dict]:
        """Analyze HTTP response for JWT issues"""
        findings = []
        
        body = response.get('body', '')
        headers = response.get('headers', {})
        endpoint = response.get('endpoint', target)
        
        # Find JWTs in response
        jwts = self.JWT_PATTERN.findall(body)
        
        # Also check Authorization header
        auth_header = headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            if self._is_valid_jwt(token):
                jwts.append(token)
        
        for jwt in jwts:
            jwt_findings = self._analyze_jwt(jwt, endpoint)
            findings.extend(jwt_findings)
        
        return findings
    
    def _analyze_jwt(self, token: str, endpoint: str) -> List[Dict]:
        """Analyze a JWT token for vulnerabilities"""
        findings = []
        
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return findings
            
            # Decode header
            header = self._decode_base64(parts[0])
            payload = self._decode_base64(parts[1])
            
            if not header or not payload:
                return findings
            
            # Check for weak algorithm
            alg = header.get('alg', '')
            if alg in self.WEAK_ALGORITHMS:
                findings.append({
                    'issue': f'JWT uses weak algorithm: {alg}',
                    'severity': 'critical' if alg.lower() == 'none' else 'high',
                    'category': 'Authentication',
                    'endpoint': endpoint,
                    'method': 'GET',
                    'evidence': f'Algorithm: {alg}',
                    'cwe_id': 'CWE-327',
                    'cvss_score': 9.1 if alg.lower() == 'none' else 7.5,
                    'recommendation': 'Use RS256 or ES256 algorithms for JWT signing'
                })
            
            # Check for expired token
            exp = payload.get('exp')
            if exp:
                try:
                    exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
                    if exp_time < datetime.now(timezone.utc):
                        findings.append({
                            'issue': 'Expired JWT token still in use',
                            'severity': 'medium',
                            'category': 'Authentication',
                            'endpoint': endpoint,
                            'method': 'GET',
                            'evidence': f'Expired at: {exp_time.isoformat()}',
                            'cwe_id': 'CWE-613',
                            'recommendation': 'Implement proper token expiry validation'
                        })
                except Exception:
                    pass
            
            # Check for missing expiry
            if not exp:
                findings.append({
                    'issue': 'JWT token has no expiry (exp) claim',
                    'severity': 'medium',
                    'category': 'Authentication',
                    'endpoint': endpoint,
                    'method': 'GET',
                    'evidence': 'Missing exp claim in payload',
                    'cwe_id': 'CWE-613',
                    'recommendation': 'Always include exp claim in JWT tokens'
                })
            
            # Check for sensitive data exposure
            sensitive_fields = ['password', 'secret', 'private_key', 'ssn', 'credit_card']
            for field in sensitive_fields:
                if field in str(payload).lower():
                    findings.append({
                        'issue': f'JWT contains potentially sensitive field: {field}',
                        'severity': 'high',
                        'category': 'Information Disclosure',
                        'endpoint': endpoint,
                        'method': 'GET',
                        'evidence': f'Found field containing: {field}',
                        'cwe_id': 'CWE-200',
                        'recommendation': 'Remove sensitive data from JWT payload'
                    })
            
            # Check for token exposure in URL
            if '?' in endpoint and token in endpoint:
                findings.append({
                    'issue': 'JWT token exposed in URL',
                    'severity': 'high',
                    'category': 'Information Disclosure',
                    'endpoint': endpoint,
                    'method': 'GET',
                    'evidence': 'Token visible in query string',
                    'cwe_id': 'CWE-598',
                    'recommendation': 'Pass JWT tokens in Authorization header instead of URL'
                })
                
        except Exception as e:
            logger.debug(f"Error analyzing JWT: {e}")
        
        return findings
    
    async def _probe_jwt_endpoints(self, target: str, context: Dict) -> List[Dict]:
        """Probe common JWT-related endpoints"""
        # This would make actual requests in live mode
        # For now, return empty as this requires HTTP client
        return []
    
    def _decode_base64(self, encoded: str) -> Optional[Dict]:
        """Decode base64url encoded JWT part"""
        try:
            # Add padding if needed
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += '=' * padding
            
            decoded = base64.urlsafe_b64decode(encoded)
            return json.loads(decoded)
        except Exception:
            return None
    
    def _is_valid_jwt(self, token: str) -> bool:
        """Check if string is a valid JWT format"""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        return bool(self.JWT_PATTERN.match(token))
