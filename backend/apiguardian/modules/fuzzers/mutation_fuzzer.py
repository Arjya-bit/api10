"""Mutation Fuzzer - Advanced mutation-based fuzzing"""
import logging
import random
import copy
from typing import Dict, List, Any, Optional

from apiguardian.core.plugin_manager import FuzzerPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class MutationFuzzer(FuzzerPlugin):
    """Advanced mutation-based fuzzer for API testing"""
    
    plugin_name = "mutation_fuzzer"
    description = "Intelligent mutation-based fuzzing for edge cases"
    version = "1.0.0"
    destructive = False
    
    # Mutation strategies
    MUTATIONS = {
        'bit_flip': lambda s: ''.join(chr(ord(c) ^ random.randint(1, 255)) for c in s[:10]),
        'remove_chars': lambda s: s[1:] if s else '',
        'duplicate': lambda s: s + s,
        'reverse': lambda s: s[::-1],
        'case_swap': lambda s: s.swapcase(),
        'unicode_insert': lambda s: s[:len(s)//2] + '\u0000' + s[len(s)//2:],
        'special_chars': lambda s: s + '\x00\x0a\x0d\x1b',
        'overflow': lambda s: s + 'A' * 5000,
    }
    
    # Format string payloads
    FORMAT_STRINGS = [
        '%s%s%s%s%s%s%s%s%s%s',
        '%x%x%x%x%x%x%x%x%x%x',
        '%n%n%n%n%n%n%n%n%n%n',
        '{0}{1}{2}{3}{4}{5}',
        '${env:PATH}',
        '${{7*7}}',
    ]
    
    async def fuzz(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform mutation fuzzing"""
        findings = []
        
        if not target:
            return findings
        
        # Get sample requests from context
        sample_requests = context.get('sample_requests', [])
        
        if sample_requests:
            for request in sample_requests[:5]:
                findings.extend(await self._mutate_request(target, request, context))
        else:
            # Fuzz common patterns
            findings.extend(await self._fuzz_common_patterns(target, context))
        
        return findings
    
    async def _mutate_request(self, target: str, request: Dict, context: Dict) -> List[Dict]:
        """Mutate a sample request"""
        findings = []
        
        url = request.get('url', target)
        method = request.get('method', 'GET')
        params = request.get('params', {})
        body = request.get('body', {})
        headers = request.get('headers', {})
        
        # Mutate parameters
        for param_name, param_value in params.items():
            mutations = self._generate_mutations(str(param_value))
            for mutated in mutations:
                mutated_params = {**params, param_name: mutated}
                try:
                    response = await http_client.request(
                        method, url,
                        params=mutated_params,
                        timeout=5
                    )
                    if response:
                        finding = self._analyze_response(response, url, f"param:{param_name}", mutated)
                        if finding:
                            findings.append(finding)
                except Exception:
                    pass
        
        # Mutate body fields
        if body and isinstance(body, dict):
            for field_name, field_value in body.items():
                mutations = self._generate_mutations(str(field_value))
                for mutated in mutations:
                    mutated_body = {**body, field_name: mutated}
                    try:
                        response = await http_client.request(
                            method, url,
                            json=mutated_body,
                            timeout=5
                        )
                        if response:
                            finding = self._analyze_response(response, url, f"body:{field_name}", mutated)
                            if finding:
                                findings.append(finding)
                    except Exception:
                        pass
        
        return findings
    
    def _generate_mutations(self, value: str) -> List[str]:
        """Generate mutations of a value"""
        mutations = []
        
        # Apply each mutation strategy
        for name, mutator in self.MUTATIONS.items():
            try:
                mutations.append(mutator(value))
            except Exception:
                pass
        
        # Add format string payloads
        mutations.extend(self.FORMAT_STRINGS)
        
        return mutations[:15]  # Limit mutations
    
    async def _fuzz_common_patterns(self, target: str, context: Dict) -> List[Dict]:
        """Fuzz common endpoint patterns"""
        findings = []
        
        common_endpoints = [
            '/api/users', '/api/items', '/api/search',
            '/api/v1/data', '/api/v2/resource'
        ]
        
        for endpoint in common_endpoints:
            url = f"{target.rstrip('/')}{endpoint}"
            
            # Test format strings
            for payload in self.FORMAT_STRINGS:
                try:
                    test_url = f"{url}?id={payload}"
                    response = await http_client.get(test_url, timeout=5)
                    if response:
                        finding = self._analyze_response(response, test_url, 'id', payload)
                        if finding:
                            findings.append(finding)
                except Exception:
                    pass
        
        return findings
    
    def _analyze_response(self, response, url: str, field: str, payload: str) -> Optional[Dict]:
        """Analyze response for vulnerabilities"""
        status = response.status_code if hasattr(response, 'status_code') else 0
        body = response.text if hasattr(response, 'text') else ''
        
        # Check for format string vulnerability
        if any(p in payload for p in ['%s', '%x', '%n', '{0}']):
            if '(nil)' in body or '0x' in body.lower() or any(f'{i}' in body for i in range(10)):
                return {
                    'issue': 'Potential format string vulnerability',
                    'severity': 'high',
                    'category': 'Format String',
                    'endpoint': url,
                    'method': 'GET',
                    'evidence': f'Format string reflected via {field}',
                    'cwe_id': 'CWE-134',
                    'recommendation': 'Never use user input in format strings'
                }
        
        # Check for error disclosure
        if status >= 500:
            error_indicators = ['exception', 'traceback', 'error at', 'failed to', 'cannot']
            if any(ind in body.lower() for ind in error_indicators):
                return {
                    'issue': 'Server error triggered by mutation',
                    'severity': 'medium',
                    'category': 'Error Handling',
                    'endpoint': url,
                    'method': 'GET',
                    'evidence': f'Error triggered by mutating {field}',
                    'cwe_id': 'CWE-209',
                    'recommendation': 'Implement robust input validation and error handling'
                }
        
        # Check for buffer overflow indicators
        if len(payload) > 1000:
            if status == 413 or 'too large' in body.lower():
                pass  # Expected behavior
            elif status >= 500:
                return {
                    'issue': 'Potential buffer overflow',
                    'severity': 'high',
                    'category': 'Buffer Overflow',
                    'endpoint': url,
                    'method': 'GET',
                    'evidence': f'Server crashed with large input to {field}',
                    'cwe_id': 'CWE-120',
                    'recommendation': 'Implement input length validation'
                }
        
        return None
