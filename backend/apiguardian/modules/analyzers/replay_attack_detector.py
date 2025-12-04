"""Replay Attack Detector - Detect replay vulnerabilities"""
import logging
import hashlib
import time
import asyncio
from typing import Dict, List, Any
from datetime import datetime, timezone

from apiguardian.core.plugin_manager import AnalyzerPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class ReplayAttackDetector(AnalyzerPlugin):
    """Detect replay attack vulnerabilities in API authentication"""
    
    plugin_name = "replay_attack_detector"
    description = "Detect replay vulnerabilities in tokens and nonces"
    version = "1.0.0"
    
    REPLAY_INDICATORS = [
        'nonce', 'timestamp', 'request_id', 'req_id', 'uuid',
        'x-nonce', 'x-timestamp', 'x-request-id'
    ]
    
    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze for replay attack vulnerabilities"""
        findings = []
        
        if not target:
            return findings
        
        # Check responses for replay protection
        responses = context.get('responses', [])
        for response in responses:
            findings.extend(self._check_replay_protection(response, target))
        
        # Probe for replay vulnerabilities
        findings.extend(await self._probe_replay_vulnerability(target, context))
        
        return findings
    
    def _check_replay_protection(self, response: Dict, target: str) -> List[Dict]:
        """Check if response indicates replay protection"""
        findings = []
        headers = response.get('headers', {})
        request_headers = response.get('request_headers', {})
        endpoint = response.get('endpoint', target)
        
        # Check for nonce/timestamp in request
        has_replay_protection = False
        for indicator in self.REPLAY_INDICATORS:
            if any(indicator.lower() in h.lower() for h in request_headers.keys()):
                has_replay_protection = True
                break
            if any(indicator.lower() in h.lower() for h in headers.keys()):
                has_replay_protection = True
                break
        
        # Check for HMAC or signature-based auth
        auth_header = headers.get('Authorization', '') or request_headers.get('Authorization', '')
        if 'HMAC' in auth_header.upper() or 'Signature' in auth_header:
            has_replay_protection = True
        
        if not has_replay_protection:
            # Check if it's an auth endpoint
            if any(x in endpoint.lower() for x in ['/auth', '/login', '/token', '/api/']):
                findings.append({
                    'issue': 'No replay attack protection detected',
                    'severity': 'medium',
                    'category': 'Replay Attack',
                    'endpoint': endpoint,
                    'method': response.get('method', 'POST'),
                    'description': 'Authentication requests lack nonce/timestamp protection',
                    'evidence': 'No nonce, timestamp, or request ID found in request',
                    'cwe_id': 'CWE-294',
                    'recommendation': 'Implement nonce or timestamp-based replay protection'
                })
        
        return findings
    
    async def _probe_replay_vulnerability(self, target: str, context: Dict) -> List[Dict]:
        """Probe for actual replay vulnerabilities"""
        findings = []
        
        try:
            # Make initial request
            response1 = await http_client.get(target)
            if not response1:
                return findings
            
            # Check for idempotency tokens
            headers1 = response1.headers if hasattr(response1, 'headers') else {}
            
            # Look for idempotency key requirement
            if 'idempotency-key' not in str(headers1).lower():
                # Check if POST requests accept replays
                auth_endpoints = [
                    f"{target.rstrip('/')}/login",
                    f"{target.rstrip('/')}/auth",
                    f"{target.rstrip('/')}/api/token"
                ]
                
                for endpoint in auth_endpoints:
                    try:
                        # This is a detection-only check
                        resp = await http_client.get(endpoint)
                        if resp and resp.status_code in [200, 401, 405]:
                            # Endpoint exists, check for replay protection info
                            resp_headers = resp.headers if hasattr(resp, 'headers') else {}
                            
                            if not any(ind.lower() in str(resp_headers).lower() for ind in self.REPLAY_INDICATORS):
                                findings.append({
                                    'issue': 'Authentication endpoint lacks replay protection headers',
                                    'severity': 'low',
                                    'category': 'Replay Attack',
                                    'endpoint': endpoint,
                                    'method': 'GET',
                                    'evidence': 'No nonce or timestamp headers in response',
                                    'recommendation': 'Add X-Request-ID or nonce to auth responses'
                                })
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.debug(f"Replay probe error: {e}")
        
        return findings
