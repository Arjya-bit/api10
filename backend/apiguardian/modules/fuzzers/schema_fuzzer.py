"""Schema-Driven Fuzzer - Fuzz based on OpenAPI/JSON Schema"""
import logging
import json
import random
import string
from typing import Dict, List, Any, Optional
from datetime import datetime

from apiguardian.core.plugin_manager import FuzzerPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class SchemaFuzzer(FuzzerPlugin):
    """Fuzz API endpoints based on schema definitions"""
    
    plugin_name = "schema_fuzzer"
    description = "Schema-driven fuzzing using OpenAPI/JSON Schema"
    version = "1.0.0"
    destructive = False
    
    # Type-specific fuzz values
    FUZZ_VALUES = {
        'string': [
            '',  # Empty
            ' ',  # Space
            'a' * 10000,  # Long string
            '<script>alert(1)</script>',  # XSS
            "'; DROP TABLE users; --",  # SQLi
            '\x00\x00\x00',  # Null bytes
            '../../../etc/passwd',  # Path traversal
            '${7*7}',  # SSTI
            '{{7*7}}',  # Template injection
            '\n\r\n',  # CRLF
            '%00',  # Null byte URL encoded
            'true', 'false', 'null',  # Type confusion
            '-1', '0', '999999999',  # Numeric strings
        ],
        'integer': [
            0, -1, 1,
            2147483647,  # Max int32
            -2147483648,  # Min int32
            9999999999999,  # Large number
            None,  # Null
        ],
        'number': [
            0.0, -1.0, 1.0,
            float('inf'),
            float('-inf'),
            1e308,  # Very large
            1e-308,  # Very small
            None,
        ],
        'boolean': [
            True, False,
            'true', 'false',  # String booleans
            1, 0,  # Numeric booleans
            None,
        ],
        'array': [
            [],  # Empty
            [None],
            ['a'] * 1000,  # Large array
            [{'nested': 'object'}],
            [[[[['deep']]]]], # Deep nesting
        ],
        'object': [
            {},  # Empty
            {'__proto__': {'admin': True}},  # Prototype pollution
            {'constructor': {'prototype': {'admin': True}}},
            None,
        ],
    }
    
    async def fuzz(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fuzz based on schema"""
        findings = []
        
        if not target:
            return findings
        
        # Get schema from context (from OpenAPI scanner)
        schema = context.get('schema', {})
        endpoints = context.get('endpoints', [])
        
        if not endpoints:
            # Generate basic fuzz without schema
            findings.extend(await self._fuzz_without_schema(target, context))
        else:
            # Schema-driven fuzzing
            for endpoint in endpoints[:10]:  # Limit endpoints
                findings.extend(await self._fuzz_endpoint(target, endpoint, context))
        
        return findings
    
    async def _fuzz_without_schema(self, target: str, context: Dict) -> List[Dict]:
        """Basic fuzzing without schema"""
        findings = []
        
        # Try common parameter names with fuzz values
        common_params = ['id', 'user', 'name', 'email', 'search', 'q', 'query', 'page', 'limit']
        
        for param in common_params:
            for fuzz_type, values in self.FUZZ_VALUES.items():
                for value in values[:3]:  # Limit values per type
                    try:
                        url = f"{target}?{param}={value}"
                        response = await http_client.get(url, timeout=5)
                        if response:
                            finding = self._analyze_fuzz_response(response, target, param, value)
                            if finding:
                                findings.append(finding)
                    except Exception as e:
                        logger.debug(f"Fuzz error: {e}")
        
        return findings
    
    async def _fuzz_endpoint(self, base_url: str, endpoint: Dict, context: Dict) -> List[Dict]:
        """Fuzz a specific endpoint based on schema"""
        findings = []
        
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET').upper()
        parameters = endpoint.get('parameters', [])
        request_body = endpoint.get('requestBody', {})
        
        url = f"{base_url.rstrip('/')}{path}"
        
        # Fuzz query parameters
        for param in parameters:
            param_name = param.get('name', '')
            param_type = param.get('schema', {}).get('type', 'string')
            
            fuzz_values = self.FUZZ_VALUES.get(param_type, self.FUZZ_VALUES['string'])
            
            for value in fuzz_values[:5]:
                try:
                    if method == 'GET':
                        test_url = f"{url}?{param_name}={value}"
                        response = await http_client.get(test_url, timeout=5)
                    else:
                        response = await http_client.request(
                            method, url,
                            params={param_name: value},
                            timeout=5
                        )
                    
                    if response:
                        finding = self._analyze_fuzz_response(response, url, param_name, value)
                        if finding:
                            findings.append(finding)
                except Exception:
                    pass
        
        # Fuzz request body
        if request_body and method in ['POST', 'PUT', 'PATCH']:
            body_schema = request_body.get('content', {}).get('application/json', {}).get('schema', {})
            fuzzed_bodies = self._generate_fuzzed_bodies(body_schema)
            
            for fuzzed in fuzzed_bodies[:5]:
                try:
                    response = await http_client.request(
                        method, url,
                        json=fuzzed,
                        timeout=5
                    )
                    if response:
                        finding = self._analyze_fuzz_response(response, url, 'body', str(fuzzed)[:100])
                        if finding:
                            findings.append(finding)
                except Exception:
                    pass
        
        return findings
    
    def _generate_fuzzed_bodies(self, schema: Dict) -> List[Dict]:
        """Generate fuzzed request bodies from schema"""
        bodies = []
        
        if schema.get('type') != 'object':
            return bodies
        
        properties = schema.get('properties', {})
        
        # Empty body
        bodies.append({})
        
        # Body with fuzzed properties
        for prop_name, prop_schema in properties.items():
            prop_type = prop_schema.get('type', 'string')
            fuzz_values = self.FUZZ_VALUES.get(prop_type, self.FUZZ_VALUES['string'])
            
            for value in fuzz_values[:3]:
                bodies.append({prop_name: value})
        
        return bodies
    
    def _analyze_fuzz_response(self, response, url: str, param: str, value: Any) -> Optional[Dict]:
        """Analyze response for vulnerabilities"""
        status = response.status_code if hasattr(response, 'status_code') else 0
        body = response.text if hasattr(response, 'text') else ''
        
        # Check for error disclosure
        if status == 500:
            if any(err in body.lower() for err in ['traceback', 'exception', 'error', 'stack']):
                return {
                    'issue': 'Server error with stack trace disclosure',
                    'severity': 'medium',
                    'category': 'Information Disclosure',
                    'endpoint': url,
                    'method': 'GET',
                    'evidence': f'500 error on param {param}={str(value)[:50]}',
                    'cwe_id': 'CWE-209',
                    'recommendation': 'Implement proper error handling without stack traces'
                }
        
        # Check for SQL error
        sql_errors = ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'ora-', 'syntax error']
        if any(err in body.lower() for err in sql_errors):
            return {
                'issue': 'Potential SQL injection vulnerability',
                'severity': 'critical',
                'category': 'Injection',
                'endpoint': url,
                'method': 'GET',
                'evidence': f'SQL error triggered by {param}={str(value)[:50]}',
                'cwe_id': 'CWE-89',
                'recommendation': 'Use parameterized queries and input validation'
            }
        
        # Check for XSS reflection
        if '<script>' in str(value) and '<script>' in body:
            return {
                'issue': 'Reflected XSS vulnerability',
                'severity': 'high',
                'category': 'XSS',
                'endpoint': url,
                'method': 'GET',
                'evidence': f'Script tag reflected in response via {param}',
                'cwe_id': 'CWE-79',
                'recommendation': 'Implement output encoding and Content Security Policy'
            }
        
        # Check for path traversal
        if '../' in str(value) and ('root:' in body or 'passwd' in body):
            return {
                'issue': 'Path traversal vulnerability',
                'severity': 'critical',
                'category': 'Path Traversal',
                'endpoint': url,
                'method': 'GET',
                'evidence': f'File content exposed via {param}',
                'cwe_id': 'CWE-22',
                'recommendation': 'Validate and sanitize file paths'
            }
        
        return None
