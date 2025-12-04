"""Rate Limit Analyzer - Evaluate API rate limiting"""
import logging
import asyncio
from typing import Dict, List, Any
from datetime import datetime

from apiguardian.core.plugin_manager import AnalyzerPlugin
from apiguardian.utils.http_client import HTTPClient, HTTPResponse

logger = logging.getLogger(__name__)


class RateLimitAnalyzer(AnalyzerPlugin):
    """Analyze API rate limiting implementation"""
    
    plugin_name = "rate_limit_analyzer"
    description = "Evaluate rate limiting headers and behavior"
    version = "1.0.0"
    
    RATE_LIMIT_HEADERS = [
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset',
        'RateLimit-Limit',
        'RateLimit-Remaining',
        'RateLimit-Reset',
        'Retry-After',
        'X-Rate-Limit-Limit',
        'X-Rate-Limit-Remaining'
    ]
    
    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze rate limiting on target"""
        findings = []
        
        if not target:
            return findings
        
        # Check for rate limit headers in responses
        responses = context.get('responses', [])
        for response in responses:
            rate_findings = self._analyze_response(response, target)
            findings.extend(rate_findings)
        
        # If no responses provided, do basic probe
        if not responses:
            findings.extend(await self._probe_rate_limits(target, context))
        
        return findings
    
    def _analyze_response(self, response: Dict, target: str) -> List[Dict]:
        """Analyze response for rate limiting issues"""
        findings = []
        headers = response.get('headers', {})
        status_code = response.get('status_code', 0)
        endpoint = response.get('endpoint', target)
        
        # Check for rate limit headers
        found_headers = {}
        for header in self.RATE_LIMIT_HEADERS:
            header_lower = header.lower()
            for resp_header, value in headers.items():
                if resp_header.lower() == header_lower:
                    found_headers[header] = value
                    break
        
        # No rate limiting detected
        if not found_headers and status_code != 429:
            findings.append({
                'issue': 'No rate limiting headers detected',
                'severity': 'medium',
                'category': 'Rate Limiting',
                'endpoint': endpoint,
                'method': response.get('method', 'GET'),
                'evidence': 'Response lacks standard rate limiting headers',
                'cwe_id': 'CWE-770',
                'recommendation': 'Implement rate limiting with standard headers (X-RateLimit-*)'
            })
        
        # Check for overly generous limits
        limit = found_headers.get('X-RateLimit-Limit') or found_headers.get('RateLimit-Limit')
        if limit:
            try:
                limit_int = int(limit)
                if limit_int > 10000:
                    findings.append({
                        'issue': f'Rate limit may be too high: {limit_int} requests',
                        'severity': 'low',
                        'category': 'Rate Limiting',
                        'endpoint': endpoint,
                        'method': response.get('method', 'GET'),
                        'evidence': f'X-RateLimit-Limit: {limit_int}',
                        'recommendation': 'Consider lowering rate limits for sensitive endpoints'
                    })
            except ValueError:
                pass
        
        # Check 429 response
        if status_code == 429:
            if 'Retry-After' not in headers:
                findings.append({
                    'issue': 'Rate limit response (429) missing Retry-After header',
                    'severity': 'info',
                    'category': 'Rate Limiting',
                    'endpoint': endpoint,
                    'method': response.get('method', 'GET'),
                    'evidence': 'HTTP 429 response without Retry-After header',
                    'recommendation': 'Include Retry-After header in 429 responses'
                })
        
        return findings
    
    async def _probe_rate_limits(self, target: str, context: Dict) -> List[Dict]:
        """Probe endpoint for rate limiting (safe, limited requests)"""
        findings = []
        
        # This is a placeholder - in real implementation:
        # 1. Make a few requests
        # 2. Check headers
        # 3. Report missing rate limiting
        
        return findings
