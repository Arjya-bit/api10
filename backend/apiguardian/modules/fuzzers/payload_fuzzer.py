"""Payload Fuzzer - Non-destructive payload injection testing"""
import logging
import os
from typing import Dict, List, Any
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from apiguardian.core.plugin_manager import FuzzerPlugin
from apiguardian.utils.http_client import safe_http_client, HTTPResponse

logger = logging.getLogger(__name__)


class PayloadFuzzer(FuzzerPlugin):
    """Non-destructive payload fuzzer for injection testing"""
    
    plugin_name = "payload_fuzzer"
    description = "Test for injection vulnerabilities using curated payloads"
    version = "1.0.0"
    destructive = False  # Safe by default
    
    # Default payloads if files not found
    DEFAULT_SQLI_PAYLOADS = [
        "'",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1; SELECT * FROM users--",
        "1 UNION SELECT NULL--",
        "admin'--",
    ]
    
    DEFAULT_XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
    ]
    
    DEFAULT_LFI_PAYLOADS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "..\\..\\..\\windows\\system.ini",
        "file:///etc/passwd",
    ]
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load payloads from files or use defaults"""
        payloads = {
            'sqli': self.DEFAULT_SQLI_PAYLOADS.copy(),
            'xss': self.DEFAULT_XSS_PAYLOADS.copy(),
            'lfi': self.DEFAULT_LFI_PAYLOADS.copy()
        }
        
        payload_dir = Path('/app/backend/apiguardian/data/payloads')
        
        for payload_type in ['sqli', 'xss', 'lfi']:
            payload_file = payload_dir / f'{payload_type}.txt'
            if payload_file.exists():
                try:
                    with open(payload_file, 'r') as f:
                        lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        if lines:
                            payloads[payload_type] = lines
                    logger.debug(f"Loaded {len(payloads[payload_type])} {payload_type} payloads")
                except Exception as e:
                    logger.warning(f"Could not load {payload_file}: {e}")
        
        return payloads
    
    async def fuzz(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fuzz target with injection payloads"""
        findings = []
        
        if not target:
            return findings
        
        # Get config
        config = context.get('config', {})
        fuzzer_config = config.get('fuzzers', {}).get('payload', {})
        max_payloads = fuzzer_config.get('max_payloads', 100)
        
        # Get endpoints to test
        endpoints = context.get('endpoints', [])
        if not endpoints:
            endpoints = [{'url': target, 'method': 'GET'}]
        
        # Find injection points
        for endpoint_info in endpoints:
            url = endpoint_info.get('url', '')
            method = endpoint_info.get('method', 'GET')
            
            if not url:
                continue
            
            # Find parameters to fuzz
            params = self._extract_parameters(url)
            
            for param_name, param_value in params.items():
                # Test each payload type
                for payload_type, payload_list in self.payloads.items():
                    for payload in payload_list[:max_payloads // len(self.payloads)]:
                        injection_findings = await self._test_injection(
                            url, method, param_name, payload, payload_type, context
                        )
                        findings.extend(injection_findings)
        
        return findings
    
    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract query parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if v else '' for k, v in params.items()}
    
    async def _test_injection(
        self,
        url: str,
        method: str,
        param_name: str,
        payload: str,
        payload_type: str,
        context: Dict
    ) -> List[Dict]:
        """Test a single injection payload"""
        findings = []
        
        # Create fuzzed URL
        fuzzed_url = self._inject_payload(url, param_name, payload)
        
        # In a real scenario, we'd make the request and analyze the response
        # For pattern-based detection, we check for common error patterns
        
        # Simulate response analysis (placeholder)
        response = await self._make_safe_request(fuzzed_url, method, context)
        
        if response:
            injection_findings = self._analyze_response(response, url, param_name, payload, payload_type)
            findings.extend(injection_findings)
        
        return findings
    
    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    async def _make_safe_request(self, url: str, method: str, context: Dict) -> Dict:
        """Make a safe HTTP request (GET only unless destructive mode enabled)"""
        if method.upper() != 'GET' and not context.get('enable_destructive', False):
            return None
        
        try:
            response = await safe_http_client.get(url)
            return {
                'status_code': response.status_code,
                'body': response.body,
                'headers': response.headers,
                'elapsed_ms': response.elapsed_ms
            }
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None
    
    def _analyze_response(self, response: Dict, url: str, param: str, payload: str, payload_type: str) -> List[Dict]:
        """Analyze response for injection indicators"""
        findings = []
        body = response.get('body', '').lower()
        status = response.get('status_code', 0)
        
        # SQL Injection indicators
        if payload_type == 'sqli':
            sqli_errors = [
                'sql syntax', 'mysql_fetch', 'ora-', 'postgresql',
                'sqlite_', 'jdbc', 'odbc', 'syntax error',
                'unclosed quotation', 'quoted string not properly terminated'
            ]
            for error in sqli_errors:
                if error in body:
                    findings.append({
                        'issue': f'Potential SQL Injection vulnerability',
                        'severity': 'critical',
                        'category': 'Injection',
                        'endpoint': url,
                        'method': 'GET',
                        'evidence': f'Parameter: {param}, Payload: {payload[:50]}, Error indicator: {error}',
                        'cwe_id': 'CWE-89',
                        'cvss_score': 9.8,
                        'recommendation': 'Use parameterized queries or ORM to prevent SQL injection'
                    })
                    break
        
        # XSS indicators
        elif payload_type == 'xss':
            if payload.lower() in body:
                findings.append({
                    'issue': 'Potential Cross-Site Scripting (XSS) vulnerability',
                    'severity': 'high',
                    'category': 'Injection',
                    'endpoint': url,
                    'method': 'GET',
                    'evidence': f'Parameter: {param}, Payload reflected in response',
                    'cwe_id': 'CWE-79',
                    'cvss_score': 7.1,
                    'recommendation': 'Implement proper output encoding and Content-Security-Policy'
                })
        
        # LFI indicators
        elif payload_type == 'lfi':
            lfi_indicators = ['root:', 'bin/bash', '[boot loader]', 'for 16-bit']
            for indicator in lfi_indicators:
                if indicator.lower() in body:
                    findings.append({
                        'issue': 'Local File Inclusion (LFI) vulnerability',
                        'severity': 'critical',
                        'category': 'Injection',
                        'endpoint': url,
                        'method': 'GET',
                        'evidence': f'Parameter: {param}, File content indicator found',
                        'cwe_id': 'CWE-22',
                        'cvss_score': 9.1,
                        'recommendation': 'Validate and sanitize file path inputs'
                    })
                    break
        
        return findings
