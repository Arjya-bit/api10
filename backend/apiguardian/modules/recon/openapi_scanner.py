"""OpenAPI Scanner - Parse and enumerate API endpoints from OpenAPI specs"""
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib.parse import urljoin

from apiguardian.core.plugin_manager import ReconPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class OpenAPIScanner(ReconPlugin):
    """Scan and parse OpenAPI/Swagger specifications"""
    
    plugin_name = "openapi_scanner"
    description = "Discover and parse OpenAPI specifications to enumerate endpoints"
    version = "1.0.0"
    
    COMMON_SPEC_PATHS = [
        '/openapi.json',
        '/swagger.json',
        '/api-docs',
        '/v1/openapi.json',
        '/v2/openapi.json',
        '/v3/openapi.json',
        '/.well-known/openapi',
        '/swagger/v1/swagger.json',
        '/api/swagger.json',
        '/docs/openapi.json'
    ]
    
    async def recon(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform OpenAPI reconnaissance"""
        result = {
            'spec_found': False,
            'spec_url': None,
            'endpoints': [],
            'security_schemes': [],
            'info': {},
            'servers': []
        }
        
        # Try to load spec from file first
        spec_file = context.get('spec_file') or self.config.get('spec_file')
        if spec_file:
            spec = self._load_spec_from_file(spec_file)
            if spec:
                result.update(self._parse_spec(spec, target))
                result['spec_found'] = True
                result['spec_url'] = f'file://{spec_file}'
                return result
        
        # Probe common paths
        if target:
            for path in self.COMMON_SPEC_PATHS:
                spec_url = urljoin(target, path)
                spec = await self._fetch_spec(spec_url)
                if spec:
                    result.update(self._parse_spec(spec, target))
                    result['spec_found'] = True
                    result['spec_url'] = spec_url
                    logger.info(f"Found OpenAPI spec at {spec_url}")
                    break
        
        return result
    
    def _load_spec_from_file(self, file_path: str) -> Optional[Dict]:
        """Load OpenAPI spec from local file"""
        try:
            path = Path(file_path)
            if path.exists():
                with open(path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load spec from {file_path}: {e}")
        return None
    
    async def _fetch_spec(self, url: str) -> Optional[Dict]:
        """Fetch OpenAPI spec from URL"""
        try:
            response = await http_client.get(url, headers={'Accept': 'application/json'})
            if response.is_success and response.json_body:
                # Validate it's an OpenAPI spec
                if self._is_openapi_spec(response.json_body):
                    return response.json_body
        except Exception as e:
            logger.debug(f"Could not fetch spec from {url}: {e}")
        return None
    
    def _is_openapi_spec(self, data: Dict) -> bool:
        """Check if data is a valid OpenAPI spec"""
        # OpenAPI 3.x
        if 'openapi' in data and 'paths' in data:
            return True
        # Swagger 2.x
        if 'swagger' in data and 'paths' in data:
            return True
        return False
    
    def _parse_spec(self, spec: Dict, base_url: str) -> Dict[str, Any]:
        """Parse OpenAPI spec and extract endpoints"""
        result = {
            'endpoints': [],
            'security_schemes': [],
            'info': {},
            'servers': []
        }
        
        # Extract info
        info = spec.get('info', {})
        result['info'] = {
            'title': info.get('title', 'Unknown API'),
            'version': info.get('version', ''),
            'description': info.get('description', '')
        }
        
        # Extract servers
        servers = spec.get('servers', [])
        if servers:
            result['servers'] = [s.get('url', '') for s in servers]
        else:
            # Swagger 2.x
            host = spec.get('host', '')
            basePath = spec.get('basePath', '')
            schemes = spec.get('schemes', ['https'])
            if host:
                result['servers'] = [f"{schemes[0]}://{host}{basePath}"]
        
        # Extract security schemes
        components = spec.get('components', {}) or spec.get('securityDefinitions', {})
        security_schemes = components.get('securitySchemes', {}) or components
        
        for name, scheme in security_schemes.items():
            if isinstance(scheme, dict):
                result['security_schemes'].append({
                    'name': name,
                    'type': scheme.get('type', ''),
                    'scheme': scheme.get('scheme', ''),
                    'in': scheme.get('in', '')
                })
        
        # Extract endpoints
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            
            for method, operation in methods.items():
                if method.lower() not in ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']:
                    continue
                
                if not isinstance(operation, dict):
                    continue
                
                endpoint = {
                    'path': path,
                    'method': method.upper(),
                    'url': urljoin(base_url, path),
                    'operation_id': operation.get('operationId', ''),
                    'summary': operation.get('summary', ''),
                    'description': operation.get('description', ''),
                    'tags': operation.get('tags', []),
                    'parameters': [],
                    'security': operation.get('security', []),
                    'deprecated': operation.get('deprecated', False)
                }
                
                # Extract parameters
                params = operation.get('parameters', [])
                for param in params:
                    if isinstance(param, dict):
                        endpoint['parameters'].append({
                            'name': param.get('name', ''),
                            'in': param.get('in', ''),
                            'required': param.get('required', False),
                            'type': param.get('schema', {}).get('type', param.get('type', ''))
                        })
                
                result['endpoints'].append(endpoint)
        
        logger.info(f"Parsed {len(result['endpoints'])} endpoints from OpenAPI spec")
        return result
