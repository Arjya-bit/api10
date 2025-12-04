"""GraphQL Fuzzer - Security testing for GraphQL APIs"""
import logging
from typing import Dict, List, Any, Optional

from apiguardian.core.plugin_manager import FuzzerPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class GraphQLFuzzer(FuzzerPlugin):
    """Fuzz GraphQL APIs for security vulnerabilities"""
    
    plugin_name = "graphql_fuzzer"
    description = "Security fuzzing for GraphQL endpoints"
    version = "1.0.0"
    destructive = False
    
    # GraphQL introspection queries
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
        __schema {
            types { name kind fields { name type { name } } }
            queryType { name }
            mutationType { name }
        }
    }
    '''
    
    # Dangerous queries
    ATTACK_QUERIES = [
        # Deep nesting DoS
        '{__typename' + ''.join(['{__typename' for _ in range(50)]) + ''.join(['}' for _ in range(50)]) + '}',
        
        # Batch query attack
        '[' + ','.join(['{__typename}' for _ in range(100)]) + ']',
        
        # Field duplication
        '{user{id ' + 'id ' * 100 + '}}',
        
        # Alias overload
        '{' + ' '.join([f'a{i}:__typename' for i in range(100)]) + '}',
        
        # Directive overload
        '{user @skip(if: false) @include(if: true) @deprecated {id}}',
    ]
    
    # Injection payloads for variables
    INJECTION_PAYLOADS = [
        {'id': "' OR '1'='1"},
        {'id': "'; DROP TABLE users; --"},
        {'id': '<script>alert(1)</script>'},
        {'id': '{{7*7}}'},
        {'id': '../../../etc/passwd'},
        {'id': -1},
        {'id': 99999999999},
        {'id': None},
    ]
    
    async def fuzz(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fuzz GraphQL endpoint"""
        findings = []
        
        if not target:
            return findings
        
        # Detect GraphQL endpoint
        graphql_url = await self._detect_graphql(target)
        if not graphql_url:
            return findings
        
        # Test introspection
        findings.extend(await self._test_introspection(graphql_url))
        
        # Test attack queries
        findings.extend(await self._test_attack_queries(graphql_url))
        
        # Test injection
        findings.extend(await self._test_injection(graphql_url, context))
        
        return findings
    
    async def _detect_graphql(self, target: str) -> Optional[str]:
        """Detect GraphQL endpoint"""
        common_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query']
        
        for path in common_paths:
            url = f"{target.rstrip('/')}{path}"
            try:
                response = await http_client.post(
                    url,
                    json={'query': '{__typename}'},
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                if response and response.status_code == 200:
                    body = response.text if hasattr(response, 'text') else ''
                    if '__typename' in body or 'data' in body:
                        return url
            except Exception:
                pass
        
        return None
    
    async def _test_introspection(self, url: str) -> List[Dict]:
        """Test if introspection is enabled"""
        findings = []
        
        try:
            response = await http_client.post(
                url,
                json={'query': self.INTROSPECTION_QUERY},
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response and response.status_code == 200:
                body = response.text if hasattr(response, 'text') else ''
                if '__schema' in body and 'types' in body:
                    findings.append({
                        'issue': 'GraphQL introspection enabled',
                        'severity': 'medium',
                        'category': 'GraphQL Security',
                        'endpoint': url,
                        'method': 'POST',
                        'description': 'Full schema is exposed via introspection',
                        'evidence': 'Introspection query returned schema data',
                        'cwe_id': 'CWE-200',
                        'recommendation': 'Disable introspection in production environments'
                    })
        except Exception as e:
            logger.debug(f"Introspection test error: {e}")
        
        return findings
    
    async def _test_attack_queries(self, url: str) -> List[Dict]:
        """Test attack queries"""
        findings = []
        
        for query in self.ATTACK_QUERIES:
            try:
                response = await http_client.post(
                    url,
                    json={'query': query},
                    headers={'Content-Type': 'application/json'},
                    timeout=15
                )
                
                if response:
                    status = response.status_code
                    body = response.text if hasattr(response, 'text') else ''
                    
                    # Check for DoS vulnerability (slow response or error)
                    if status == 200 and 'error' not in body.lower():
                        if 'deep' in query.lower() or query.count('{') > 10:
                            findings.append({
                                'issue': 'GraphQL query depth not limited',
                                'severity': 'medium',
                                'category': 'GraphQL Security',
                                'endpoint': url,
                                'method': 'POST',
                                'evidence': 'Deep nested query executed successfully',
                                'recommendation': 'Implement query depth limiting'
                            })
                        elif '[' in query:
                            findings.append({
                                'issue': 'GraphQL batch queries not limited',
                                'severity': 'low',
                                'category': 'GraphQL Security',
                                'endpoint': url,
                                'method': 'POST',
                                'evidence': 'Large batch query executed',
                                'recommendation': 'Limit batch query size'
                            })
                    
                    # Server error indicates potential vulnerability
                    if status >= 500:
                        findings.append({
                            'issue': 'GraphQL server crash on malformed query',
                            'severity': 'high',
                            'category': 'GraphQL Security',
                            'endpoint': url,
                            'method': 'POST',
                            'evidence': f'Server returned {status} on attack query',
                            'cwe_id': 'CWE-20',
                            'recommendation': 'Implement query validation and error handling'
                        })
                        
            except Exception as e:
                logger.debug(f"Attack query error: {e}")
        
        return findings
    
    async def _test_injection(self, url: str, context: Dict) -> List[Dict]:
        """Test injection vulnerabilities"""
        findings = []
        
        # Get a valid query from introspection or context
        base_query = context.get('graphql_query', 'query($id: ID!) { user(id: $id) { id name } }')
        
        for payload in self.INJECTION_PAYLOADS:
            try:
                response = await http_client.post(
                    url,
                    json={'query': base_query, 'variables': payload},
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if response:
                    body = response.text if hasattr(response, 'text') else ''
                    
                    # Check for SQL error
                    if any(err in body.lower() for err in ['sql', 'syntax', 'mysql', 'postgresql']):
                        findings.append({
                            'issue': 'GraphQL SQL injection vulnerability',
                            'severity': 'critical',
                            'category': 'Injection',
                            'endpoint': url,
                            'method': 'POST',
                            'evidence': f'SQL error with payload: {payload}',
                            'cwe_id': 'CWE-89',
                            'recommendation': 'Use parameterized resolvers'
                        })
                        break
                    
                    # Check for path traversal
                    if '../' in str(payload) and ('root:' in body or '/etc/' in body):
                        findings.append({
                            'issue': 'GraphQL path traversal vulnerability',
                            'severity': 'critical',
                            'category': 'Path Traversal',
                            'endpoint': url,
                            'method': 'POST',
                            'evidence': 'File content exposed via GraphQL',
                            'cwe_id': 'CWE-22',
                            'recommendation': 'Validate file paths in resolvers'
                        })
                        break
                        
            except Exception as e:
                logger.debug(f"Injection test error: {e}")
        
        return findings
