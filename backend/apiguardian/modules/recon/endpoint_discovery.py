"""
Enterprise Endpoint Discovery Module
=====================================
Advanced API endpoint discovery and reconnaissance with comprehensive
security analysis, detailed reporting, and enterprise-grade features.

Features:
- Comprehensive endpoint probing (200+ common API paths)
- Technology fingerprinting and version detection
- Security header analysis
- API documentation discovery (OpenAPI, Swagger, GraphQL)
- Sensitive endpoint detection with risk classification
- Response analysis and data leakage detection
- Authentication endpoint identification
- Admin/debug endpoint discovery
- Rate limiting detection
- WAF/CDN detection
- Detailed findings with CWE mappings

Author: APIGuardian Enterprise
Version: 2.0.0
"""

import logging
import re
import hashlib
import asyncio
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum

from apiguardian.core.plugin_manager import ReconPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class EndpointRisk(Enum):
    """Risk classification for discovered endpoints"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EndpointCategory(Enum):
    """Categories for endpoint classification"""
    AUTHENTICATION = "Authentication"
    AUTHORIZATION = "Authorization"
    USER_MANAGEMENT = "User Management"
    ADMIN = "Administration"
    DEBUG = "Debug/Development"
    API_DOCUMENTATION = "API Documentation"
    DATA_ACCESS = "Data Access"
    FILE_OPERATIONS = "File Operations"
    HEALTH_STATUS = "Health/Status"
    CONFIGURATION = "Configuration"
    INTERNAL = "Internal"
    GRAPHQL = "GraphQL"
    WEBSOCKET = "WebSocket"
    WEBHOOK = "Webhook"
    PAYMENT = "Payment"
    SENSITIVE = "Sensitive Data"
    GENERAL = "General"


@dataclass
class EndpointInfo:
    """Detailed information about a discovered endpoint"""
    url: str
    path: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    response_size: int = 0
    response_time_ms: float = 0
    headers: Dict[str, str] = field(default_factory=dict)
    category: EndpointCategory = EndpointCategory.GENERAL
    risk_level: EndpointRisk = EndpointRisk.INFO
    technologies: List[str] = field(default_factory=list)
    security_headers: Dict[str, bool] = field(default_factory=dict)
    requires_auth: bool = False
    data_exposure: List[str] = field(default_factory=list)
    fingerprint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'url': self.url,
            'path': self.path,
            'method': self.method,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'response_size': self.response_size,
            'response_time_ms': self.response_time_ms,
            'headers': self.headers,
            'category': self.category.value,
            'risk_level': self.risk_level.value,
            'technologies': self.technologies,
            'security_headers': self.security_headers,
            'requires_auth': self.requires_auth,
            'data_exposure': self.data_exposure,
            'fingerprint': self.fingerprint
        }


class EndpointDiscovery(ReconPlugin):
    """
    Enterprise-grade API Endpoint Discovery Plugin

    Performs comprehensive endpoint enumeration with:
    - 200+ common API endpoint paths
    - Technology fingerprinting
    - Security analysis
    - Risk classification
    - Detailed findings generation
    """

    plugin_name = "endpoint_discovery"
    description = "Advanced API endpoint discovery with security analysis and risk classification"
    version = "2.0.0"

    # Comprehensive endpoint list organized by category
    ENDPOINT_DATABASE = {
        EndpointCategory.HEALTH_STATUS: [
            '/health', '/healthz', '/healthcheck', '/health-check',
            '/status', '/ping', '/ready', '/readiness', '/live', '/liveness',
            '/api/health', '/api/status', '/api/v1/health', '/api/v2/health',
            '/_health', '/_status', '/heartbeat', '/up',
            '/actuator/health', '/actuator/info', '/actuator/metrics',
            '/management/health', '/management/info',
        ],
        EndpointCategory.API_DOCUMENTATION: [
            '/docs', '/api/docs', '/api-docs', '/api-doc',
            '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger.json', '/swagger.yaml',
            '/swagger/v1/swagger.json', '/swagger/index.html',
            '/openapi', '/openapi.json', '/openapi.yaml', '/openapi/v3/api-docs',
            '/redoc', '/api/redoc', '/rapidoc',
            '/graphql', '/graphiql', '/playground', '/graphql/playground',
            '/explorer', '/api-explorer', '/api/explorer',
            '/documentation', '/api/documentation',
            '/v1/docs', '/v2/docs', '/v3/docs',
            '/apidocs', '/api/apidocs',
        ],
        EndpointCategory.AUTHENTICATION: [
            '/login', '/signin', '/sign-in', '/auth/login', '/api/login',
            '/api/auth/login', '/api/v1/login', '/authenticate',
            '/logout', '/signout', '/sign-out', '/auth/logout', '/api/logout',
            '/register', '/signup', '/sign-up', '/api/register', '/api/signup',
            '/token', '/oauth/token', '/api/token', '/auth/token',
            '/refresh', '/auth/refresh', '/api/auth/refresh', '/token/refresh',
            '/forgot-password', '/reset-password', '/change-password',
            '/api/forgot-password', '/api/reset-password',
            '/verify', '/verify-email', '/confirm', '/activate',
            '/mfa', '/2fa', '/otp', '/totp', '/api/mfa',
            '/sso', '/saml', '/oauth', '/oauth2', '/oidc',
            '/api/sso', '/.well-known/openid-configuration',
            '/callback', '/auth/callback', '/oauth/callback',
            '/session', '/sessions', '/api/session',
        ],
        EndpointCategory.USER_MANAGEMENT: [
            '/users', '/user', '/api/users', '/api/user',
            '/api/v1/users', '/api/v2/users',
            '/me', '/api/me', '/profile', '/api/profile',
            '/account', '/api/account', '/accounts',
            '/user/profile', '/user/settings', '/user/preferences',
            '/users/me', '/users/current', '/users/self',
            '/members', '/api/members', '/people',
            '/team', '/teams', '/api/teams',
            '/roles', '/permissions', '/api/roles',
            '/groups', '/api/groups',
        ],
        EndpointCategory.ADMIN: [
            '/admin', '/administrator', '/administration',
            '/api/admin', '/admin/api', '/backoffice',
            '/admin/users', '/admin/settings', '/admin/config',
            '/admin/dashboard', '/admin/panel', '/panel',
            '/management', '/manage', '/manager',
            '/console', '/control', '/control-panel',
            '/supervisor', '/superuser', '/root',
            '/cms', '/cms/admin', '/backend',
            '/master', '/system', '/sys',
            '/ops', '/operations', '/operator',
        ],
        EndpointCategory.DEBUG: [
            '/debug', '/debug/vars', '/debug/pprof',
            '/dev', '/development', '/test', '/testing',
            '/internal', '/internal/api', '/_internal',
            '/actuator', '/actuator/env', '/actuator/beans',
            '/actuator/configprops', '/actuator/mappings',
            '/actuator/threaddump', '/actuator/heapdump',
            '/metrics', '/api/metrics', '/_metrics', '/prometheus',
            '/trace', '/traces', '/tracing', '/zipkin',
            '/profiler', '/profiling', '/perf',
            '/stats', '/statistics', '/api/stats',
            '/info', '/api/info', '/_info',
            '/env', '/environment', '/config',
            '/dump', '/heapdump', '/threaddump',
            '/logs', '/log', '/logging', '/api/logs',
            '/error', '/errors', '/exceptions',
            '/phpinfo.php', '/server-status', '/server-info',
            '/.git', '/.svn', '/.env', '/.htaccess',
            '/elmah.axd', '/trace.axd',
        ],
        EndpointCategory.CONFIGURATION: [
            '/config', '/configuration', '/settings',
            '/api/config', '/api/settings', '/api/configuration',
            '/preferences', '/options', '/parameters',
            '/setup', '/install', '/installation',
            '/features', '/flags', '/feature-flags',
            '/toggles', '/switches',
        ],
        EndpointCategory.DATA_ACCESS: [
            '/data', '/api/data', '/dataset', '/datasets',
            '/export', '/import', '/api/export', '/api/import',
            '/download', '/downloads', '/upload', '/uploads',
            '/files', '/file', '/documents', '/docs',
            '/attachments', '/media', '/images', '/assets',
            '/backup', '/backups', '/restore',
            '/reports', '/report', '/api/reports',
            '/analytics', '/api/analytics', '/insights',
            '/search', '/api/search', '/query', '/queries',
            '/bulk', '/batch', '/api/bulk',
        ],
        EndpointCategory.FILE_OPERATIONS: [
            '/upload', '/api/upload', '/file/upload',
            '/download', '/api/download', '/file/download',
            '/files', '/api/files', '/file',
            '/storage', '/api/storage', '/store',
            '/media', '/api/media', '/images',
            '/documents', '/api/documents', '/docs',
            '/attachments', '/api/attachments',
            '/assets', '/static', '/resources',
        ],
        EndpointCategory.INTERNAL: [
            '/internal', '/private', '/_private',
            '/service', '/services', '/api/services',
            '/rpc', '/grpc', '/jsonrpc',
            '/gateway', '/api-gateway', '/proxy',
            '/dispatch', '/dispatcher', '/router',
            '/queue', '/queues', '/jobs', '/tasks',
            '/workers', '/worker', '/cron',
            '/scheduler', '/scheduled',
            '/events', '/api/events', '/webhooks',
            '/callbacks', '/hooks', '/triggers',
        ],
        EndpointCategory.GRAPHQL: [
            '/graphql', '/api/graphql', '/v1/graphql',
            '/graphiql', '/playground', '/graphql-playground',
            '/explorer', '/graphql-explorer',
            '/subscriptions', '/graphql/subscriptions',
            '/schema', '/graphql/schema', '/introspection',
        ],
        EndpointCategory.WEBSOCKET: [
            '/ws', '/websocket', '/socket', '/socket.io',
            '/api/ws', '/api/websocket', '/realtime',
            '/live', '/stream', '/streaming',
            '/notifications', '/api/notifications',
            '/push', '/pubsub', '/subscribe',
        ],
        EndpointCategory.WEBHOOK: [
            '/webhook', '/webhooks', '/api/webhooks',
            '/hook', '/hooks', '/callback', '/callbacks',
            '/notify', '/notification', '/trigger',
            '/event', '/events', '/api/events',
            '/incoming', '/outgoing', '/integration',
            '/slack', '/discord', '/teams',
        ],
        EndpointCategory.PAYMENT: [
            '/payment', '/payments', '/api/payments',
            '/pay', '/checkout', '/billing',
            '/invoice', '/invoices', '/api/invoices',
            '/subscription', '/subscriptions',
            '/order', '/orders', '/api/orders',
            '/cart', '/shopping-cart', '/basket',
            '/stripe', '/paypal', '/braintree',
            '/transaction', '/transactions',
            '/refund', '/refunds', '/charge',
        ],
        EndpointCategory.SENSITIVE: [
            '/keys', '/api-keys', '/apikeys', '/api/keys',
            '/secrets', '/credentials', '/tokens',
            '/password', '/passwords', '/pwd',
            '/private', '/confidential', '/restricted',
            '/pii', '/personal', '/sensitive',
            '/credit-card', '/creditcard', '/cc',
            '/ssn', '/social-security',
            '/license', '/licenses', '/certificates',
        ],
    }

    # Security headers to check
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Content-Type-Options': 'X-Content-Type-Options',
        'X-Frame-Options': 'X-Frame-Options',
        'X-XSS-Protection': 'X-XSS-Protection',
        'Referrer-Policy': 'Referrer-Policy',
        'Permissions-Policy': 'Permissions-Policy',
        'X-Permitted-Cross-Domain-Policies': 'Cross-Domain-Policy',
    }

    # Technology fingerprints
    TECH_FINGERPRINTS = {
        # Server technologies
        'nginx': [r'nginx', r'nginx/[\d.]+'],
        'apache': [r'apache', r'Apache/[\d.]+'],
        'iis': [r'Microsoft-IIS', r'IIS/[\d.]+'],
        'tomcat': [r'Apache-Coyote', r'Apache Tomcat'],
        'express': [r'Express', r'x-powered-by:\s*express'],
        'django': [r'django', r'csrftoken', r'djangorestframework'],
        'flask': [r'Werkzeug', r'flask'],
        'rails': [r'X-Rails', r'ruby', r'phusion passenger'],
        'spring': [r'spring', r'X-Application-Context'],
        'laravel': [r'laravel', r'XSRF-TOKEN'],
        'aspnet': [r'ASP\.NET', r'X-AspNet-Version', r'X-Powered-By:\s*ASP\.NET'],
        'node': [r'node', r'Node\.js'],
        'php': [r'PHP', r'X-Powered-By:\s*PHP'],
        'aws': [r'AmazonS3', r'awselb', r'X-Amz', r'cloudfront'],
        'cloudflare': [r'cloudflare', r'cf-ray', r'cf-cache-status'],
        'akamai': [r'akamai', r'X-Akamai'],
        'fastly': [r'fastly', r'X-Fastly'],
        'varnish': [r'varnish', r'X-Varnish'],
        'kong': [r'kong', r'X-Kong'],
        'kubernetes': [r'kubernetes', r'k8s'],
        'docker': [r'docker'],
        'graphql': [r'graphql', r'__schema', r'__typename'],
        'swagger': [r'swagger', r'openapi'],
        'jwt': [r'Bearer\s+eyJ', r'Authorization.*JWT'],
    }

    # Sensitive data patterns
    SENSITIVE_PATTERNS = {
        'email': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'api_key': r'(?:api[_-]?key|apikey)["\s:=]+["\'`]?([a-zA-Z0-9_-]{20,})["\'`]?',
        'token': r'(?:token|secret|password)["\s:=]+["\'`]?([a-zA-Z0-9_-]{8,})["\'`]?',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (?:RSA |EC |)PRIVATE KEY-----',
        'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        'uuid': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'internal_ip': r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
        'stack_trace': r'(?:at\s+[\w.$]+\(|Traceback \(most recent call last\)|Exception in thread)',
        'sql_error': r'(?:SQL syntax|mysql_fetch|ORA-\d{5}|pg_query|sqlite)',
        'debug_info': r'(?:DEBUG|TRACE|VERBOSE|stack trace|line \d+)',
    }

    # CWE mappings for findings
    CWE_MAPPINGS = {
        'exposed_docs': {'id': 'CWE-200', 'name': 'Exposure of Sensitive Information'},
        'debug_endpoint': {'id': 'CWE-489', 'name': 'Active Debug Code'},
        'admin_endpoint': {'id': 'CWE-425', 'name': 'Direct Request (Forced Browsing)'},
        'sensitive_data': {'id': 'CWE-200', 'name': 'Exposure of Sensitive Information'},
        'missing_auth': {'id': 'CWE-306', 'name': 'Missing Authentication'},
        'info_disclosure': {'id': 'CWE-200', 'name': 'Information Exposure'},
        'security_header': {'id': 'CWE-693', 'name': 'Protection Mechanism Failure'},
        'version_disclosure': {'id': 'CWE-200', 'name': 'Server Version Disclosure'},
        'internal_endpoint': {'id': 'CWE-668', 'name': 'Exposure of Resource to Wrong Sphere'},
        'backup_file': {'id': 'CWE-530', 'name': 'Exposure of Backup File'},
        'graphql_introspection': {'id': 'CWE-200', 'name': 'GraphQL Introspection Enabled'},
    }

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.discovered_endpoints: List[EndpointInfo] = []
        self.findings: List[Dict[str, Any]] = []
        self.technologies_detected: Set[str] = set()
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None
        self.total_requests: int = 0
        self.successful_requests: int = 0
        self.failed_requests: int = 0

    async def recon(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive endpoint discovery

        Args:
            target: Base URL to scan
            context: Scan context with configuration

        Returns:
            Dictionary containing discovered endpoints and findings
        """
        self.scan_start_time = datetime.now(timezone.utc)
        self.discovered_endpoints = []
        self.findings = []
        self.technologies_detected = set()

        if not target:
            return self._build_result()

        # Get configuration
        config = context.get('config', {})
        recon_config = config.get('recon', {})
        timeout = recon_config.get('timeout', 5)
        max_concurrent = recon_config.get('max_concurrent', 10)
        follow_redirects = recon_config.get('follow_redirects', True)
        deep_scan = recon_config.get('deep_scan', True)

        logger.info(f"Starting endpoint discovery on {target}")

        # Build endpoint list to probe
        endpoints_to_probe = self._build_endpoint_list(target, deep_scan)

        # Probe endpoints with concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)

        async def probe_with_semaphore(url: str, path: str, category: EndpointCategory):
            async with semaphore:
                return await self._probe_endpoint(url, path, category, timeout)

        # Create tasks for all endpoints
        tasks = []
        for category, paths in self.ENDPOINT_DATABASE.items():
            for path in paths:
                url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
                tasks.append(probe_with_semaphore(url, path, category))

        # Execute all probes
        logger.info(f"Probing {len(tasks)} potential endpoints...")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.failed_requests += 1
                logger.debug(f"Probe error: {result}")
            elif result is not None:
                self.discovered_endpoints.append(result)
                self.successful_requests += 1

        # Analyze discovered endpoints for security issues
        await self._analyze_endpoints(target)

        # Generate technology summary
        self._generate_tech_summary(target)

        self.scan_end_time = datetime.now(timezone.utc)

        logger.info(
            f"Discovery complete: {len(self.discovered_endpoints)} endpoints found, "
            f"{len(self.findings)} findings generated"
        )

        return self._build_result()

    def _build_endpoint_list(self, target: str, deep_scan: bool) -> List[Tuple[str, str, EndpointCategory]]:
        """Build list of endpoints to probe based on configuration"""
        endpoints = []

        for category, paths in self.ENDPOINT_DATABASE.items():
            for path in paths:
                url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
                endpoints.append((url, path, category))

        if deep_scan:
            # Add version variations
            version_prefixes = ['/v1', '/v2', '/v3', '/api/v1', '/api/v2', '/api/v3']
            base_paths = ['/users', '/orders', '/products', '/items', '/data']

            for prefix in version_prefixes:
                for base in base_paths:
                    path = prefix + base
                    url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
                    endpoints.append((url, path, EndpointCategory.DATA_ACCESS))

        return endpoints

    async def _probe_endpoint(
        self,
        url: str,
        path: str,
        category: EndpointCategory,
        timeout: float
    ) -> Optional[EndpointInfo]:
        """
        Probe a single endpoint and collect detailed information

        Args:
            url: Full URL to probe
            path: Path component
            category: Endpoint category
            timeout: Request timeout

        Returns:
            EndpointInfo if endpoint responds, None otherwise
        """
        self.total_requests += 1
        start_time = datetime.now(timezone.utc)

        try:
            response = await http_client.get(url)

            if response is None:
                return None

            # Skip 404, 502, 503, 504 responses
            if response.status_code in [404, 502, 503, 504, 0]:
                return None

            end_time = datetime.now(timezone.utc)
            response_time = (end_time - start_time).total_seconds() * 1000

            headers = response.headers if hasattr(response, 'headers') else {}
            body = response.body if hasattr(response, 'body') else b''

            # Analyze security headers
            security_headers = self._check_security_headers(headers)

            # Detect technologies
            technologies = self._detect_technologies(headers, body)
            self.technologies_detected.update(technologies)

            # Determine risk level
            risk_level = self._assess_endpoint_risk(path, category, response.status_code, headers, body)

            # Check for authentication requirement
            requires_auth = self._check_auth_requirement(response.status_code, headers, body)

            # Detect potential data exposure
            data_exposure = self._detect_data_exposure(body)

            # Generate fingerprint
            fingerprint = hashlib.sha256(
                f"{url}{response.status_code}{len(body)}".encode()
            ).hexdigest()[:16]

            return EndpointInfo(
                url=url,
                path=path,
                method='GET',
                status_code=response.status_code,
                content_type=headers.get('content-type', ''),
                response_size=len(body) if body else 0,
                response_time_ms=response_time,
                headers=dict(headers),
                category=category,
                risk_level=risk_level,
                technologies=technologies,
                security_headers=security_headers,
                requires_auth=requires_auth,
                data_exposure=data_exposure,
                fingerprint=fingerprint
            )

        except Exception as e:
            logger.debug(f"Failed to probe {url}: {e}")
            return None

    def _is_sensitive(self, path: str, response: Dict) -> bool:
        """Check if endpoint might be sensitive"""
        sensitive_patterns = [
            'admin', 'debug', 'internal', 'config', 'settings',
            'actuator', 'env', 'graphql', 'metrics'
        ]
        return any(p in path.lower() for p in sensitive_patterns)

    def _check_security_headers(self, headers: Dict[str, str]) -> Dict[str, bool]:
        """Check presence of security headers"""
        result = {}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, name in self.SECURITY_HEADERS.items():
            result[name] = header.lower() in headers_lower

        return result

    def _detect_technologies(self, headers: Dict[str, str], body: bytes) -> List[str]:
        """Detect technologies from response"""
        detected = []

        # Combine headers and body for searching
        search_text = str(headers) + (body.decode('utf-8', errors='ignore') if body else '')

        for tech, patterns in self.TECH_FINGERPRINTS.items():
            for pattern in patterns:
                if re.search(pattern, search_text, re.IGNORECASE):
                    detected.append(tech)
                    break

        return list(set(detected))

    def _assess_endpoint_risk(
        self,
        path: str,
        category: EndpointCategory,
        status_code: int,
        headers: Dict[str, str],
        body: bytes
    ) -> EndpointRisk:
        """Assess risk level of an endpoint"""

        # Critical risk endpoints
        critical_patterns = [
            r'/admin', r'/debug', r'/actuator', r'/internal',
            r'/config', r'/env', r'/secrets', r'/keys',
            r'/backup', r'\.bak', r'\.sql', r'\.git',
        ]

        # High risk endpoints
        high_patterns = [
            r'/users', r'/api-?keys?', r'/tokens?', r'/auth',
            r'/private', r'/sensitive', r'/credentials',
            r'/graphql', r'/swagger', r'/docs',
        ]

        path_lower = path.lower()

        # Check critical patterns
        for pattern in critical_patterns:
            if re.search(pattern, path_lower):
                return EndpointRisk.CRITICAL

        # Check high risk patterns
        for pattern in high_patterns:
            if re.search(pattern, path_lower):
                return EndpointRisk.HIGH

        # Category-based risk
        if category in [EndpointCategory.ADMIN, EndpointCategory.DEBUG,
                       EndpointCategory.CONFIGURATION, EndpointCategory.SENSITIVE]:
            return EndpointRisk.HIGH

        if category in [EndpointCategory.AUTHENTICATION, EndpointCategory.INTERNAL,
                       EndpointCategory.API_DOCUMENTATION]:
            return EndpointRisk.MEDIUM

        # Check for sensitive data in response
        body_text = body.decode('utf-8', errors='ignore') if body else ''
        for name, pattern in self.SENSITIVE_PATTERNS.items():
            if re.search(pattern, body_text):
                return EndpointRisk.HIGH

        return EndpointRisk.INFO

    def _check_auth_requirement(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: bytes
    ) -> bool:
        """Check if endpoint requires authentication"""

        # 401/403 indicates auth required
        if status_code in [401, 403]:
            return True

        # Check for auth headers
        auth_indicators = ['www-authenticate', 'x-auth', 'authorization']
        for header in auth_indicators:
            if header in [h.lower() for h in headers.keys()]:
                return True

        # Check response body
        body_text = body.decode('utf-8', errors='ignore').lower() if body else ''
        auth_keywords = ['unauthorized', 'authentication required', 'login required', 'access denied']
        for keyword in auth_keywords:
            if keyword in body_text:
                return True

        return False

    def _detect_data_exposure(self, body: bytes) -> List[str]:
        """Detect potential sensitive data exposure in response"""
        exposures = []

        if not body:
            return exposures

        body_text = body.decode('utf-8', errors='ignore')

        for data_type, pattern in self.SENSITIVE_PATTERNS.items():
            if re.search(pattern, body_text):
                exposures.append(data_type)

        return exposures

    async def _analyze_endpoints(self, target: str) -> None:
        """Analyze discovered endpoints and generate security findings"""

        for endpoint in self.discovered_endpoints:
            # Generate findings based on endpoint characteristics

            # 1. Exposed API Documentation
            if endpoint.category == EndpointCategory.API_DOCUMENTATION:
                self._add_finding(
                    issue=f"API documentation publicly accessible: {endpoint.path}",
                    description=(
                        f"API documentation endpoint '{endpoint.path}' is publicly accessible. "
                        "While documentation can be helpful, exposing it publicly may reveal "
                        "internal API structure, authentication mechanisms, and potential attack vectors."
                    ),
                    severity="medium" if not endpoint.requires_auth else "low",
                    category="Information Disclosure",
                    endpoint=endpoint.url,
                    method="GET",
                    evidence=(
                        f"HTTP {endpoint.status_code} response from {endpoint.url}\n"
                        f"Content-Type: {endpoint.content_type}\n"
                        f"Response Size: {endpoint.response_size} bytes"
                    ),
                    cwe_id=self.CWE_MAPPINGS['exposed_docs']['id'],
                    cvss_score=5.3,
                    recommendation=(
                        "1. Restrict access to API documentation in production environments\n"
                        "2. Implement authentication for documentation endpoints\n"
                        "3. Consider using network-level restrictions\n"
                        "4. Review documented endpoints for sensitive information"
                    ),
                    raw_data=endpoint.to_dict()
                )

            # 2. Debug/Internal Endpoints
            if endpoint.category in [EndpointCategory.DEBUG, EndpointCategory.INTERNAL]:
                self._add_finding(
                    issue=f"Debug/Internal endpoint exposed: {endpoint.path}",
                    description=(
                        f"Debug or internal endpoint '{endpoint.path}' is accessible. "
                        "These endpoints often expose sensitive system information, "
                        "configuration details, or provide functionality that should "
                        "not be available in production environments."
                    ),
                    severity="high" if not endpoint.requires_auth else "medium",
                    category="Security Misconfiguration",
                    endpoint=endpoint.url,
                    method="GET",
                    evidence=(
                        f"HTTP {endpoint.status_code} response from {endpoint.url}\n"
                        f"Technologies detected: {', '.join(endpoint.technologies) or 'None'}\n"
                        f"Requires authentication: {endpoint.requires_auth}"
                    ),
                    cwe_id=self.CWE_MAPPINGS['debug_endpoint']['id'],
                    cvss_score=7.5 if not endpoint.requires_auth else 5.0,
                    recommendation=(
                        "1. Disable or remove debug endpoints in production\n"
                        "2. Implement strict access controls\n"
                        "3. Use network segmentation to restrict access\n"
                        "4. Configure firewall rules to block external access\n"
                        "5. Implement IP whitelisting for internal endpoints"
                    ),
                    raw_data=endpoint.to_dict()
                )

            # 3. Admin Endpoints
            if endpoint.category == EndpointCategory.ADMIN:
                self._add_finding(
                    issue=f"Administrative endpoint discovered: {endpoint.path}",
                    description=(
                        f"Administrative endpoint '{endpoint.path}' was discovered. "
                        "Admin interfaces are high-value targets for attackers and "
                        "should be properly secured with strong authentication, "
                        "rate limiting, and access controls."
                    ),
                    severity="high" if not endpoint.requires_auth else "medium",
                    category="Access Control",
                    endpoint=endpoint.url,
                    method="GET",
                    evidence=(
                        f"HTTP {endpoint.status_code} response\n"
                        f"Authentication required: {endpoint.requires_auth}\n"
                        f"Risk level: {endpoint.risk_level.value}"
                    ),
                    cwe_id=self.CWE_MAPPINGS['admin_endpoint']['id'],
                    cvss_score=8.0 if not endpoint.requires_auth else 4.0,
                    recommendation=(
                        "1. Implement multi-factor authentication\n"
                        "2. Restrict admin access to specific IP ranges\n"
                        "3. Implement account lockout after failed attempts\n"
                        "4. Enable comprehensive audit logging\n"
                        "5. Consider using a VPN for admin access\n"
                        "6. Implement role-based access control (RBAC)"
                    ),
                    raw_data=endpoint.to_dict()
                )

            # 4. Sensitive Data Exposure
            if endpoint.data_exposure:
                self._add_finding(
                    issue=f"Potential sensitive data exposure at {endpoint.path}",
                    description=(
                        f"Endpoint '{endpoint.path}' may be exposing sensitive data types: "
                        f"{', '.join(endpoint.data_exposure)}. This could lead to data breaches, "
                        "privacy violations, or compliance issues."
                    ),
                    severity="high",
                    category="Sensitive Data Exposure",
                    endpoint=endpoint.url,
                    method="GET",
                    evidence=(
                        f"Detected sensitive data patterns:\n"
                        f"  - Types: {', '.join(endpoint.data_exposure)}\n"
                        f"  - Response size: {endpoint.response_size} bytes"
                    ),
                    cwe_id=self.CWE_MAPPINGS['sensitive_data']['id'],
                    cvss_score=7.5,
                    recommendation=(
                        "1. Review endpoint for unnecessary data exposure\n"
                        "2. Implement data masking for sensitive fields\n"
                        "3. Apply field-level access controls\n"
                        "4. Consider data encryption at rest and in transit\n"
                        "5. Implement audit logging for data access"
                    ),
                    raw_data=endpoint.to_dict()
                )

            # 5. Missing Security Headers
            missing_headers = [h for h, present in endpoint.security_headers.items() if not present]
            if missing_headers and endpoint.status_code == 200:
                self._add_finding(
                    issue=f"Missing security headers on {endpoint.path}",
                    description=(
                        f"Endpoint '{endpoint.path}' is missing important security headers: "
                        f"{', '.join(missing_headers)}. These headers help protect against "
                        "common web vulnerabilities like XSS, clickjacking, and MIME-sniffing attacks."
                    ),
                    severity="low",
                    category="Security Headers",
                    endpoint=endpoint.url,
                    method="GET",
                    evidence=(
                        f"Missing headers:\n" +
                        '\n'.join(f"  - {h}" for h in missing_headers)
                    ),
                    cwe_id=self.CWE_MAPPINGS['security_header']['id'],
                    cvss_score=3.7,
                    recommendation=(
                        "Add the following security headers:\n" +
                        '\n'.join(f"  - {h}" for h in missing_headers) +
                        "\n\nRecommended header values:\n"
                        "  - Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                        "  - Content-Security-Policy: default-src 'self'\n"
                        "  - X-Content-Type-Options: nosniff\n"
                        "  - X-Frame-Options: DENY\n"
                        "  - X-XSS-Protection: 1; mode=block"
                    ),
                    raw_data=endpoint.to_dict()
                )

            # 6. GraphQL Introspection
            if endpoint.category == EndpointCategory.GRAPHQL:
                self._add_finding(
                    issue=f"GraphQL endpoint discovered: {endpoint.path}",
                    description=(
                        f"GraphQL endpoint '{endpoint.path}' was discovered. GraphQL endpoints "
                        "can expose the entire API schema through introspection queries, potentially "
                        "revealing sensitive data structures and available operations."
                    ),
                    severity="medium",
                    category="GraphQL Security",
                    endpoint=endpoint.url,
                    method="GET",
                    evidence=(
                        f"GraphQL endpoint responding at {endpoint.url}\n"
                        f"Status code: {endpoint.status_code}"
                    ),
                    cwe_id=self.CWE_MAPPINGS['graphql_introspection']['id'],
                    cvss_score=5.3,
                    recommendation=(
                        "1. Disable introspection in production\n"
                        "2. Implement query depth limiting\n"
                        "3. Use query cost analysis\n"
                        "4. Implement field-level authorization\n"
                        "5. Rate limit GraphQL queries\n"
                        "6. Consider using persisted queries"
                    ),
                    raw_data=endpoint.to_dict()
                )

            # 7. Authentication Endpoints
            if endpoint.category == EndpointCategory.AUTHENTICATION and not endpoint.requires_auth:
                self._add_finding(
                    issue=f"Authentication endpoint discovered: {endpoint.path}",
                    description=(
                        f"Authentication endpoint '{endpoint.path}' was discovered. "
                        "This endpoint should be carefully protected against brute-force attacks, "
                        "credential stuffing, and enumeration attacks."
                    ),
                    severity="info",
                    category="Authentication",
                    endpoint=endpoint.url,
                    method="GET",
                    evidence=(
                        f"Authentication endpoint at {endpoint.url}\n"
                        f"Response status: {endpoint.status_code}"
                    ),
                    cwe_id="CWE-307",
                    cvss_score=0.0,
                    recommendation=(
                        "1. Implement rate limiting\n"
                        "2. Use CAPTCHA after failed attempts\n"
                        "3. Implement account lockout\n"
                        "4. Use generic error messages\n"
                        "5. Enable MFA/2FA\n"
                        "6. Monitor for suspicious login patterns"
                    ),
                    raw_data=endpoint.to_dict()
                )

            # 8. File/Backup Endpoints
            if any(ext in endpoint.path.lower() for ext in ['.bak', '.backup', '.old', '.sql', '.dump']):
                self._add_finding(
                    issue=f"Potential backup file accessible: {endpoint.path}",
                    description=(
                        f"A potential backup or old file was found at '{endpoint.path}'. "
                        "Backup files can contain sensitive data, source code, or database dumps "
                        "that should not be publicly accessible."
                    ),
                    severity="critical",
                    category="Sensitive Data Exposure",
                    endpoint=endpoint.url,
                    method="GET",
                    evidence=(
                        f"Accessible file at {endpoint.url}\n"
                        f"File size: {endpoint.response_size} bytes\n"
                        f"Content type: {endpoint.content_type}"
                    ),
                    cwe_id=self.CWE_MAPPINGS['backup_file']['id'],
                    cvss_score=9.0,
                    recommendation=(
                        "1. Remove backup files from web-accessible directories\n"
                        "2. Configure web server to block access to backup extensions\n"
                        "3. Implement proper backup procedures outside the webroot\n"
                        "4. Regularly audit for exposed files"
                    ),
                    raw_data=endpoint.to_dict()
                )

    def _generate_tech_summary(self, target: str) -> None:
        """Generate a summary finding about detected technologies"""

        if self.technologies_detected:
            tech_list = sorted(list(self.technologies_detected))
            self._add_finding(
                issue=f"Technology stack fingerprint for {urlparse(target).netloc}",
                description=(
                    f"The following technologies were detected on the target: "
                    f"{', '.join(tech_list)}. This information can be used by attackers "
                    "to identify known vulnerabilities in specific versions."
                ),
                severity="info",
                category="Information Disclosure",
                endpoint=target,
                method="GET",
                evidence=(
                    f"Detected technologies:\n" +
                    '\n'.join(f"  - {tech}" for tech in tech_list)
                ),
                cwe_id=self.CWE_MAPPINGS['version_disclosure']['id'],
                cvss_score=0.0,
                recommendation=(
                    "1. Review server headers for unnecessary version disclosure\n"
                    "2. Configure web servers to hide version information\n"
                    "3. Ensure all detected technologies are up to date\n"
                    "4. Remove unused technologies and features"
                ),
                raw_data={'technologies': tech_list}
            )

    def _add_finding(
        self,
        issue: str,
        description: str,
        severity: str,
        category: str,
        endpoint: str,
        method: str,
        evidence: str,
        cwe_id: str,
        cvss_score: float,
        recommendation: str,
        raw_data: Dict[str, Any] = None
    ) -> None:
        """Add a finding to the results"""

        # Generate fingerprint for deduplication
        fingerprint = hashlib.sha256(
            f"{issue}|{endpoint}|{evidence}".encode()
        ).hexdigest()[:16]

        finding = {
            'issue': issue,
            'description': description,
            'severity': severity,
            'category': category,
            'endpoint': endpoint,
            'method': method,
            'evidence': evidence,
            'cwe_id': cwe_id,
            'cvss_score': cvss_score,
            'recommendation': recommendation,
            'fingerprint': fingerprint,
            'discovered_at': datetime.now(timezone.utc).isoformat(),
            'raw': raw_data or {}
        }

        # Check for duplicate
        if not any(f['fingerprint'] == fingerprint for f in self.findings):
            self.findings.append(finding)

    def _build_result(self) -> Dict[str, Any]:
        """Build the final result dictionary"""

        # Calculate statistics
        endpoints_by_category = {}
        for endpoint in self.discovered_endpoints:
            cat = endpoint.category.value
            endpoints_by_category[cat] = endpoints_by_category.get(cat, 0) + 1

        endpoints_by_risk = {}
        for endpoint in self.discovered_endpoints:
            risk = endpoint.risk_level.value
            endpoints_by_risk[risk] = endpoints_by_risk.get(risk, 0) + 1

        findings_by_severity = {}
        for finding in self.findings:
            sev = finding['severity']
            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

        scan_duration = None
        if self.scan_start_time and self.scan_end_time:
            scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()

        return {
            'discovered_endpoints': [ep.to_dict() for ep in self.discovered_endpoints],
            'findings': self.findings,
            'statistics': {
                'total_endpoints': len(self.discovered_endpoints),
                'total_findings': len(self.findings),
                'endpoints_by_category': endpoints_by_category,
                'endpoints_by_risk': endpoints_by_risk,
                'findings_by_severity': findings_by_severity,
                'technologies_detected': list(self.technologies_detected),
                'total_requests': self.total_requests,
                'successful_requests': self.successful_requests,
                'failed_requests': self.failed_requests,
                'scan_duration_seconds': scan_duration
            },
            'responsive_paths': [ep.path for ep in self.discovered_endpoints],
            'potential_sensitive': [
                ep.to_dict() for ep in self.discovered_endpoints
                if ep.risk_level in [EndpointRisk.CRITICAL, EndpointRisk.HIGH]
            ]
        }
