"""Endpoint Discovery - Probe for common API endpoints"""
import logging
from typing import Dict, List, Any
from urllib.parse import urljoin

from apiguardian.core.plugin_manager import ReconPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class EndpointDiscovery(ReconPlugin):
    """Discover common API endpoints through probing"""
    
    plugin_name = "endpoint_discovery"
    description = "Probe for common API endpoints and paths"
    version = "1.0.0"
    
    # Common API endpoints to probe
    COMMON_ENDPOINTS = [
        # Health/Status
        '/health', '/healthz', '/status', '/ping', '/ready',
        '/api/health', '/api/status', '/api/v1/health',
        
        # API Info
        '/version', '/api/version', '/info', '/api/info',
        
        # Docs
        '/docs', '/api/docs', '/swagger', '/swagger-ui',
        '/redoc', '/api-docs', '/graphql', '/graphiql',
        
        # Auth endpoints
        '/login', '/auth/login', '/api/login', '/api/auth/login',
        '/register', '/signup', '/api/register',
        '/logout', '/api/logout',
        '/token', '/oauth/token', '/api/token',
        '/refresh', '/api/auth/refresh',
        
        # User endpoints
        '/users', '/api/users', '/api/v1/users',
        '/user', '/api/user', '/me', '/api/me',
        '/profile', '/api/profile',
        
        # Admin endpoints
        '/admin', '/api/admin', '/administration',
        '/admin/users', '/api/admin/users',
        '/settings', '/api/settings', '/config',
        
        # Debug/Dev endpoints
        '/debug', '/dev', '/test', '/internal',
        '/actuator', '/actuator/env', '/actuator/health',
        '/metrics', '/api/metrics', '/_metrics',
        
        # GraphQL
        '/graphql', '/api/graphql', '/v1/graphql',
    ]
    
    async def recon(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Discover endpoints through probing"""
        result = {
            'discovered_endpoints': [],
            'responsive_paths': [],
            'potential_sensitive': []
        }
        
        if not target:
            return result
        
        # Get timeout from config
        config = context.get('config', {})
        recon_config = config.get('recon', {})
        timeout = recon_config.get('timeout', 2)
        
        logger.info(f"Probing {len(self.COMMON_ENDPOINTS)} common endpoints on {target}")
        
        for path in self.COMMON_ENDPOINTS:
            url = urljoin(target, path)
            response = await self._probe_endpoint(url, timeout)
            
            if response:
                endpoint_info = {
                    'url': url,
                    'path': path,
                    'status_code': response.get('status_code'),
                    'content_type': response.get('content_type', ''),
                    'response_size': response.get('size', 0)
                }
                
                result['discovered_endpoints'].append(endpoint_info)
                result['responsive_paths'].append(path)
                
                # Check for potentially sensitive endpoints
                if self._is_sensitive(path, response):
                    result['potential_sensitive'].append(endpoint_info)
        
        logger.info(f"Discovered {len(result['discovered_endpoints'])} responsive endpoints")
        return result
    
    async def _probe_endpoint(self, url: str, timeout: float) -> Dict:
        """Probe a single endpoint"""
        try:
            response = await http_client.get(url, timeout=timeout)

            # Consider success if not 404/502/503/504
            if response.status_code not in [404, 502, 503, 504, 0]:
                return {
                    'status_code': response.status_code,
                    'content_type': response.headers.get('content-type', ''),
                    'size': len(response.body),
                    'headers': response.headers
                }
        except Exception as e:
            logger.debug(f"Probe failed for {url}: {e}")

        return None
    
    def _is_sensitive(self, path: str, response: Dict) -> bool:
        """Check if endpoint might be sensitive"""
        sensitive_patterns = [
            'admin', 'debug', 'internal', 'config', 'settings',
            'actuator', 'env', 'graphql', 'metrics'
        ]
        
        path_lower = path.lower()
        for pattern in sensitive_patterns:
            if pattern in path_lower:
                return True
        
        # Also check if it returns JSON data
        content_type = response.get('content_type', '')
        if 'json' in content_type.lower() and response.get('status_code') == 200:
            return True
        
        return False
