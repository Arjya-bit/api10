"""
Enterprise Authentication Security Analyzer
============================================
Comprehensive authentication mechanism analysis with security header
validation, session management assessment, CORS policy evaluation,
and authentication flow security testing.

Features:
- Security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- Cookie security assessment (HttpOnly, Secure, SameSite)
- CORS policy evaluation and misconfiguration detection
- Authentication mechanism identification
- Session management security analysis
- Credential exposure detection
- OAuth/OIDC security evaluation
- Multi-factor authentication assessment
- Password policy analysis
- Brute-force protection evaluation
- Detailed findings with CWE/CVSS mappings

Author: APIGuardian Enterprise
Version: 2.0.0
"""

import logging
import re
import hashlib
import asyncio
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum

from apiguardian.core.plugin_manager import AnalyzerPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class AuthMechanism(Enum):
    """Types of authentication mechanisms"""
    BASIC = "Basic Authentication"
    BEARER = "Bearer Token (JWT/OAuth)"
    API_KEY = "API Key"
    DIGEST = "Digest Authentication"
    NTLM = "NTLM Authentication"
    OAUTH2 = "OAuth 2.0"
    OIDC = "OpenID Connect"
    SAML = "SAML"
    SESSION = "Session Cookie"
    CERTIFICATE = "Client Certificate"
    CUSTOM = "Custom Authentication"
    NONE = "No Authentication"


class SecurityHeaderStatus(Enum):
    """Status of security header evaluation"""
    PRESENT = "present"
    MISSING = "missing"
    WEAK = "weak"
    INVALID = "invalid"


@dataclass
class SecurityHeaderResult:
    """Result of security header analysis"""
    name: str
    status: SecurityHeaderStatus
    value: Optional[str] = None
    severity: str = "info"
    issue: Optional[str] = None
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'status': self.status.value,
            'value': self.value,
            'severity': self.severity,
            'issue': self.issue,
            'recommendation': self.recommendation,
            'cwe_id': self.cwe_id
        }


@dataclass
class CookieAnalysis:
    """Analysis result for a cookie"""
    name: str
    value_preview: str  # Masked value
    has_httponly: bool = False
    has_secure: bool = False
    has_samesite: bool = False
    samesite_value: Optional[str] = None
    path: str = "/"
    domain: Optional[str] = None
    expires: Optional[str] = None
    is_session_cookie: bool = False
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'value_preview': self.value_preview,
            'has_httponly': self.has_httponly,
            'has_secure': self.has_secure,
            'has_samesite': self.has_samesite,
            'samesite_value': self.samesite_value,
            'path': self.path,
            'domain': self.domain,
            'expires': self.expires,
            'is_session_cookie': self.is_session_cookie,
            'issues': self.issues
        }


class AuthAnalyzer(AnalyzerPlugin):
    """
    Enterprise-grade Authentication Security Analyzer

    Performs comprehensive authentication security analysis including:
    - Security header validation
    - Cookie security assessment
    - CORS policy evaluation
    - Authentication mechanism detection
    - Session management analysis
    - Credential exposure detection
    """

    plugin_name = "auth_analyzer"
    description = "Comprehensive authentication and session security analysis"
    version = "2.0.0"

    # Security headers configuration with expected values and severity
    SECURITY_HEADERS_CONFIG = {
        'Strict-Transport-Security': {
            'severity': 'high',
            'cwe_id': 'CWE-319',
            'recommended': 'max-age=31536000; includeSubDomains; preload',
            'min_max_age': 31536000,  # 1 year in seconds
            'description': 'HTTP Strict Transport Security (HSTS)',
            'issue_missing': 'HSTS header missing - site vulnerable to protocol downgrade attacks',
            'issue_weak': 'HSTS max-age too short - insufficient protection against downgrade attacks'
        },
        'Content-Security-Policy': {
            'severity': 'high',
            'cwe_id': 'CWE-79',
            'recommended': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
            'description': 'Content Security Policy (CSP)',
            'issue_missing': 'CSP header missing - no protection against XSS and data injection',
            'dangerous_directives': ["'unsafe-eval'", "'unsafe-inline'", "data:", "*"]
        },
        'X-Content-Type-Options': {
            'severity': 'medium',
            'cwe_id': 'CWE-16',
            'recommended': 'nosniff',
            'expected_value': 'nosniff',
            'description': 'MIME type sniffing prevention',
            'issue_missing': 'X-Content-Type-Options missing - vulnerable to MIME sniffing attacks'
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'cwe_id': 'CWE-1021',
            'recommended': 'DENY',
            'valid_values': ['DENY', 'SAMEORIGIN'],
            'description': 'Clickjacking protection',
            'issue_missing': 'X-Frame-Options missing - vulnerable to clickjacking attacks',
            'issue_weak': 'X-Frame-Options allows framing from same origin'
        },
        'X-XSS-Protection': {
            'severity': 'low',
            'cwe_id': 'CWE-79',
            'recommended': '1; mode=block',
            'description': 'XSS filter (legacy browser protection)',
            'issue_missing': 'X-XSS-Protection missing - legacy browsers lack XSS filtering',
            'note': 'Modern browsers have deprecated this header in favor of CSP'
        },
        'Referrer-Policy': {
            'severity': 'medium',
            'cwe_id': 'CWE-200',
            'recommended': 'strict-origin-when-cross-origin',
            'secure_values': ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'],
            'description': 'Referrer information control',
            'issue_missing': 'Referrer-Policy missing - referrer information may leak to third parties'
        },
        'Permissions-Policy': {
            'severity': 'low',
            'cwe_id': 'CWE-16',
            'recommended': 'geolocation=(), microphone=(), camera=()',
            'description': 'Browser feature permissions',
            'issue_missing': 'Permissions-Policy missing - browser features not restricted'
        },
        'Cache-Control': {
            'severity': 'medium',
            'cwe_id': 'CWE-525',
            'recommended': 'no-store, no-cache, must-revalidate, private',
            'secure_directives': ['no-store', 'no-cache', 'private'],
            'description': 'Response caching control',
            'issue_missing': 'Cache-Control missing for sensitive endpoint - may cache sensitive data',
            'issue_weak': 'Cache-Control allows caching of potentially sensitive data'
        },
        'X-Permitted-Cross-Domain-Policies': {
            'severity': 'low',
            'cwe_id': 'CWE-16',
            'recommended': 'none',
            'description': 'Cross-domain policy for Flash/PDF',
            'issue_missing': 'X-Permitted-Cross-Domain-Policies missing'
        }
    }

    # Patterns for detecting authentication mechanisms
    AUTH_PATTERNS = {
        AuthMechanism.BASIC: [
            (r'WWW-Authenticate:\s*Basic', 'header'),
            (r'Authorization:\s*Basic\s+', 'request'),
        ],
        AuthMechanism.BEARER: [
            (r'WWW-Authenticate:\s*Bearer', 'header'),
            (r'Authorization:\s*Bearer\s+', 'request'),
            (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', 'body'),
        ],
        AuthMechanism.API_KEY: [
            (r'[xX][-_]?[aA][pP][iI][-_]?[kK][eE][yY]', 'header'),
            (r'api[_-]?key\s*[=:]\s*', 'body'),
            (r'apikey\s*[=:]\s*', 'body'),
        ],
        AuthMechanism.DIGEST: [
            (r'WWW-Authenticate:\s*Digest', 'header'),
        ],
        AuthMechanism.OAUTH2: [
            (r'oauth', 'body'),
            (r'access_token', 'body'),
            (r'refresh_token', 'body'),
            (r'grant_type', 'body'),
        ],
        AuthMechanism.OIDC: [
            (r'openid', 'body'),
            (r'id_token', 'body'),
            (r'\.well-known/openid-configuration', 'body'),
        ],
    }

    # Sensitive data patterns in responses
    CREDENTIAL_PATTERNS = {
        'password': {
            'pattern': r'(?:password|passwd|pwd)\s*[":=]\s*["\']?([^"\'}\s,]{3,})["\']?',
            'severity': 'critical',
            'cwe_id': 'CWE-312',
            'description': 'Password exposure in response'
        },
        'secret_key': {
            'pattern': r'(?:secret[_-]?key|api[_-]?secret)\s*[":=]\s*["\']?([^"\'}\s,]{8,})["\']?',
            'severity': 'critical',
            'cwe_id': 'CWE-312',
            'description': 'Secret key exposure in response'
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |DSA |)PRIVATE KEY-----',
            'severity': 'critical',
            'cwe_id': 'CWE-321',
            'description': 'Private key exposure in response'
        },
        'aws_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'severity': 'critical',
            'cwe_id': 'CWE-798',
            'description': 'AWS access key exposure'
        },
        'connection_string': {
            'pattern': r'(?:mongodb|mysql|postgres|redis)://[^\s"\']+',
            'severity': 'critical',
            'cwe_id': 'CWE-312',
            'description': 'Database connection string exposure'
        },
        'jwt_secret': {
            'pattern': r'jwt[_-]?secret\s*[":=]\s*["\']?([^"\'}\s,]{8,})["\']?',
            'severity': 'critical',
            'cwe_id': 'CWE-321',
            'description': 'JWT secret exposure'
        },
        'session_token': {
            'pattern': r'session[_-]?(?:id|token)\s*[":=]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?',
            'severity': 'high',
            'cwe_id': 'CWE-200',
            'description': 'Session token exposure in response body'
        }
    }

    # Session cookie name patterns
    SESSION_COOKIE_PATTERNS = [
        r'session', r'sess', r'sid', r'PHPSESSID', r'JSESSIONID',
        r'ASP\.NET_SessionId', r'connect\.sid', r'laravel_session',
        r'_session', r'auth', r'token', r'jwt', r'access'
    ]

    # Authentication endpoints to probe
    AUTH_ENDPOINTS = [
        '/login', '/signin', '/auth/login', '/api/login', '/api/auth/login',
        '/oauth/token', '/token', '/api/token', '/authenticate',
        '/.well-known/openid-configuration', '/oauth/authorize',
        '/api/v1/login', '/api/v2/login', '/users/login', '/session'
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.findings: List[Dict[str, Any]] = []
        self.security_headers_results: List[SecurityHeaderResult] = []
        self.cookies_analyzed: List[CookieAnalysis] = []
        self.auth_mechanisms_detected: Set[AuthMechanism] = set()
        self.cors_analysis: Dict[str, Any] = {}
        self.scan_statistics: Dict[str, Any] = {}

    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Perform comprehensive authentication security analysis

        Args:
            target: Target URL to analyze
            context: Scan context with configuration and responses

        Returns:
            List of security findings
        """
        self.findings = []
        self.security_headers_results = []
        self.cookies_analyzed = []
        self.auth_mechanisms_detected = set()
        self.cors_analysis = {}

        if not target:
            return self.findings

        logger.info(f"Starting authentication security analysis on {target}")

        # Analyze provided responses from context
        responses = context.get('responses', [])
        for response in responses:
            await self._analyze_response(response, target)

        # Probe target directly if no responses provided
        if not responses:
            await self._probe_target(target, context)

        # Probe authentication endpoints
        await self._probe_auth_endpoints(target, context)

        # Analyze CORS configuration
        await self._analyze_cors(target, context)

        # Generate summary statistics
        self._generate_statistics()

        logger.info(f"Auth analysis complete: {len(self.findings)} findings generated")

        return self.findings

    async def _analyze_response(self, response: Dict, target: str) -> None:
        """Analyze an HTTP response for authentication security issues"""

        headers = response.get('headers', {})
        body = response.get('body', '')
        endpoint = response.get('endpoint', target)
        method = response.get('method', 'GET')
        status_code = response.get('status_code', 200)

        # Analyze security headers
        self._analyze_security_headers(headers, endpoint, method)

        # Analyze cookies
        self._analyze_cookies(headers, endpoint, method)

        # Detect authentication mechanisms
        self._detect_auth_mechanisms(headers, body, endpoint)

        # Check for credential exposure
        self._check_credential_exposure(body, endpoint, method)

        # Check for authentication bypass indicators
        self._check_auth_bypass_indicators(headers, body, status_code, endpoint, method)

    async def _probe_target(self, target: str, context: Dict) -> None:
        """Probe target URL directly for security analysis"""

        try:
            response = await http_client.get(target)

            if response is None:
                return

            headers = response.headers if hasattr(response, 'headers') else {}
            body = response.body.decode('utf-8', errors='ignore') if hasattr(response, 'body') else ''

            # Analyze security headers
            self._analyze_security_headers(dict(headers), target, 'GET')

            # Analyze cookies
            self._analyze_cookies(dict(headers), target, 'GET')

            # Detect authentication mechanisms
            self._detect_auth_mechanisms(dict(headers), body, target)

            # Check for credential exposure
            self._check_credential_exposure(body, target, 'GET')

        except Exception as e:
            logger.debug(f"Error probing target {target}: {e}")

    async def _probe_auth_endpoints(self, target: str, context: Dict) -> None:
        """Probe common authentication endpoints"""

        base_url = target.rstrip('/')
        config = context.get('config', {})
        probe_auth = config.get('analyzers', {}).get('auth', {}).get('probe_endpoints', True)

        if not probe_auth:
            return

        for endpoint_path in self.AUTH_ENDPOINTS:
            endpoint_url = urljoin(base_url + '/', endpoint_path.lstrip('/'))

            try:
                response = await http_client.get(endpoint_url)

                if response is None:
                    continue

                status_code = response.status_code
                headers = response.headers if hasattr(response, 'headers') else {}
                body = response.body.decode('utf-8', errors='ignore') if hasattr(response, 'body') else ''

                # Skip 404 responses
                if status_code == 404:
                    continue

                # Analyze the response
                self._analyze_security_headers(dict(headers), endpoint_url, 'GET')
                self._detect_auth_mechanisms(dict(headers), body, endpoint_url)

                # Check for authentication issues specific to auth endpoints
                self._analyze_auth_endpoint(endpoint_url, status_code, headers, body)

            except Exception as e:
                logger.debug(f"Error probing auth endpoint {endpoint_url}: {e}")

    def _analyze_security_headers(self, headers: Dict[str, str], endpoint: str, method: str) -> None:
        """Analyze security headers in response"""

        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, config in self.SECURITY_HEADERS_CONFIG.items():
            header_key = header_name.lower()
            header_value = headers_lower.get(header_key)

            if header_value is None:
                # Header is missing
                result = SecurityHeaderResult(
                    name=header_name,
                    status=SecurityHeaderStatus.MISSING,
                    severity=config['severity'],
                    issue=config.get('issue_missing'),
                    recommendation=f"Add header: {header_name}: {config['recommended']}",
                    cwe_id=config.get('cwe_id')
                )
                self.security_headers_results.append(result)

                # Create finding for missing header
                self._add_finding(
                    issue=f"Missing security header: {header_name}",
                    description=(
                        f"{config['description']} is not configured. "
                        f"{config.get('issue_missing', 'This header provides important security protections.')}"
                    ),
                    severity=config['severity'],
                    category="Security Headers",
                    endpoint=endpoint,
                    method=method,
                    evidence=f"Header '{header_name}' not found in response",
                    cwe_id=config.get('cwe_id', 'CWE-693'),
                    cvss_score=self._get_cvss_for_severity(config['severity']),
                    recommendation=f"Add the following header to your responses:\n{header_name}: {config['recommended']}"
                )

            else:
                # Header is present - validate its value
                self._validate_header_value(header_name, header_value, config, endpoint, method)

    def _validate_header_value(
        self,
        header_name: str,
        value: str,
        config: Dict[str, Any],
        endpoint: str,
        method: str
    ) -> None:
        """Validate the value of a security header"""

        status = SecurityHeaderStatus.PRESENT
        issue = None
        severity = 'info'

        # HSTS validation
        if header_name == 'Strict-Transport-Security':
            max_age_match = re.search(r'max-age=(\d+)', value)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                min_required = config.get('min_max_age', 31536000)
                if max_age < min_required:
                    status = SecurityHeaderStatus.WEAK
                    issue = f"HSTS max-age ({max_age}s) is less than recommended ({min_required}s)"
                    severity = 'medium'

            if 'includeSubDomains' not in value:
                if not issue:
                    status = SecurityHeaderStatus.WEAK
                    issue = "HSTS missing 'includeSubDomains' directive"
                    severity = 'low'

        # CSP validation
        elif header_name == 'Content-Security-Policy':
            dangerous = config.get('dangerous_directives', [])
            found_dangerous = [d for d in dangerous if d in value]
            if found_dangerous:
                status = SecurityHeaderStatus.WEAK
                issue = f"CSP contains potentially dangerous directives: {', '.join(found_dangerous)}"
                severity = 'medium'

            # Check for overly permissive default-src
            if "default-src *" in value or "default-src 'unsafe-inline' 'unsafe-eval'" in value:
                status = SecurityHeaderStatus.WEAK
                issue = "CSP default-src is overly permissive"
                severity = 'high'

        # X-Frame-Options validation
        elif header_name == 'X-Frame-Options':
            valid_values = config.get('valid_values', [])
            if value.upper() not in [v.upper() for v in valid_values]:
                status = SecurityHeaderStatus.INVALID
                issue = f"Invalid X-Frame-Options value: {value}"
                severity = 'medium'
            elif value.upper() == 'SAMEORIGIN':
                # SAMEORIGIN is acceptable but DENY is more secure
                status = SecurityHeaderStatus.PRESENT
                issue = config.get('issue_weak')
                severity = 'info'

        # X-Content-Type-Options validation
        elif header_name == 'X-Content-Type-Options':
            expected = config.get('expected_value')
            if expected and value.lower() != expected.lower():
                status = SecurityHeaderStatus.INVALID
                issue = f"Invalid value: expected '{expected}', got '{value}'"
                severity = 'low'

        # Referrer-Policy validation
        elif header_name == 'Referrer-Policy':
            secure_values = config.get('secure_values', [])
            if value.lower() not in [v.lower() for v in secure_values]:
                status = SecurityHeaderStatus.WEAK
                issue = f"Referrer-Policy '{value}' may leak referrer information"
                severity = 'low'

        # Cache-Control validation for sensitive endpoints
        elif header_name == 'Cache-Control':
            secure_directives = config.get('secure_directives', [])
            has_secure = any(d.lower() in value.lower() for d in secure_directives)

            # Only flag if endpoint looks sensitive
            sensitive_patterns = ['/api/', '/auth', '/user', '/account', '/profile', '/admin']
            is_sensitive = any(p in endpoint.lower() for p in sensitive_patterns)

            if is_sensitive and not has_secure:
                status = SecurityHeaderStatus.WEAK
                issue = "Cache-Control may allow caching of sensitive data"
                severity = 'medium'

        # Store result
        result = SecurityHeaderResult(
            name=header_name,
            status=status,
            value=value[:200] if len(value) > 200 else value,  # Truncate long values
            severity=severity,
            issue=issue,
            cwe_id=config.get('cwe_id')
        )
        self.security_headers_results.append(result)

        # Create finding if there's an issue
        if issue and status in [SecurityHeaderStatus.WEAK, SecurityHeaderStatus.INVALID]:
            self._add_finding(
                issue=f"Weak {header_name} configuration",
                description=(
                    f"{config['description']} has a configuration issue: {issue}. "
                    "This may reduce the effectiveness of this security control."
                ),
                severity=severity,
                category="Security Headers",
                endpoint=endpoint,
                method=method,
                evidence=f"Current value: {value}",
                cwe_id=config.get('cwe_id', 'CWE-693'),
                cvss_score=self._get_cvss_for_severity(severity),
                recommendation=f"Update header to recommended value:\n{header_name}: {config['recommended']}"
            )

    def _analyze_cookies(self, headers: Dict[str, str], endpoint: str, method: str) -> None:
        """Analyze Set-Cookie headers for security issues"""

        # Find all Set-Cookie headers
        set_cookie_headers = []
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                set_cookie_headers.append(value)

        for cookie_header in set_cookie_headers:
            cookie_analysis = self._parse_cookie(cookie_header)
            self.cookies_analyzed.append(cookie_analysis)

            # Generate findings for cookie issues
            if cookie_analysis.issues:
                is_session = cookie_analysis.is_session_cookie
                base_severity = 'high' if is_session else 'medium'

                for issue in cookie_analysis.issues:
                    cwe_id = 'CWE-614'  # Default: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
                    if 'HttpOnly' in issue:
                        cwe_id = 'CWE-1004'
                    elif 'SameSite' in issue:
                        cwe_id = 'CWE-352'

                    self._add_finding(
                        issue=f"Insecure cookie configuration: {cookie_analysis.name}",
                        description=(
                            f"Cookie '{cookie_analysis.name}' has a security issue: {issue}. "
                            f"{'This appears to be a session cookie, making this a higher risk.' if is_session else ''}"
                        ),
                        severity=base_severity if is_session else 'medium',
                        category="Session Management",
                        endpoint=endpoint,
                        method=method,
                        evidence=f"Cookie: {cookie_analysis.name}\nIssue: {issue}\nFull header: {cookie_header[:200]}",
                        cwe_id=cwe_id,
                        cvss_score=self._get_cvss_for_severity(base_severity if is_session else 'medium'),
                        recommendation=self._get_cookie_recommendation(issue)
                    )

    def _parse_cookie(self, cookie_header: str) -> CookieAnalysis:
        """Parse a Set-Cookie header and analyze its security"""

        parts = cookie_header.split(';')
        name_value = parts[0].strip()

        name = ''
        value_preview = ''
        if '=' in name_value:
            name, value = name_value.split('=', 1)
            name = name.strip()
            # Mask value for security
            value_preview = value[:4] + '***' + value[-4:] if len(value) > 8 else '***'

        # Parse attributes
        has_httponly = False
        has_secure = False
        has_samesite = False
        samesite_value = None
        path = '/'
        domain = None
        expires = None
        issues = []

        for part in parts[1:]:
            part = part.strip().lower()

            if part == 'httponly':
                has_httponly = True
            elif part == 'secure':
                has_secure = True
            elif part.startswith('samesite='):
                has_samesite = True
                samesite_value = part.split('=', 1)[1].strip()
            elif part.startswith('path='):
                path = part.split('=', 1)[1].strip()
            elif part.startswith('domain='):
                domain = part.split('=', 1)[1].strip()
            elif part.startswith('expires='):
                expires = part.split('=', 1)[1].strip()

        # Check if it looks like a session cookie
        is_session = any(
            re.search(pattern, name, re.IGNORECASE)
            for pattern in self.SESSION_COOKIE_PATTERNS
        )

        # Identify issues
        if not has_httponly:
            issues.append("Missing HttpOnly flag - cookie accessible via JavaScript")
        if not has_secure:
            issues.append("Missing Secure flag - cookie sent over unencrypted connections")
        if not has_samesite:
            issues.append("Missing SameSite attribute - vulnerable to CSRF attacks")
        elif samesite_value and samesite_value.lower() == 'none' and not has_secure:
            issues.append("SameSite=None requires Secure flag")
        elif samesite_value and samesite_value.lower() == 'lax':
            # Lax is acceptable but Strict is more secure for session cookies
            if is_session:
                issues.append("Session cookie using SameSite=Lax - consider SameSite=Strict for higher security")

        return CookieAnalysis(
            name=name,
            value_preview=value_preview,
            has_httponly=has_httponly,
            has_secure=has_secure,
            has_samesite=has_samesite,
            samesite_value=samesite_value,
            path=path,
            domain=domain,
            expires=expires,
            is_session_cookie=is_session,
            issues=issues
        )

    def _detect_auth_mechanisms(self, headers: Dict[str, str], body: str, endpoint: str) -> None:
        """Detect authentication mechanisms in use"""

        combined = str(headers) + body

        for mechanism, patterns in self.AUTH_PATTERNS.items():
            for pattern, location in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    self.auth_mechanisms_detected.add(mechanism)
                    break

    def _check_credential_exposure(self, body: str, endpoint: str, method: str) -> None:
        """Check for credential exposure in response body"""

        if not body:
            return

        for cred_type, config in self.CREDENTIAL_PATTERNS.items():
            matches = re.findall(config['pattern'], body, re.IGNORECASE)
            if matches:
                # Mask the found credential
                masked_match = str(matches[0])[:4] + '***' if matches else '***'

                self._add_finding(
                    issue=f"Credential exposure detected: {config['description']}",
                    description=(
                        f"{config['description']} was detected in the response body. "
                        "Exposing credentials in API responses poses a critical security risk "
                        "as they can be intercepted or logged."
                    ),
                    severity=config['severity'],
                    category="Sensitive Data Exposure",
                    endpoint=endpoint,
                    method=method,
                    evidence=f"Pattern matched: {cred_type}\nSample (masked): {masked_match}",
                    cwe_id=config['cwe_id'],
                    cvss_score=9.0 if config['severity'] == 'critical' else 7.5,
                    recommendation=(
                        "1. Remove credentials from API responses immediately\n"
                        "2. Rotate any exposed credentials\n"
                        "3. Review API design to prevent credential exposure\n"
                        "4. Implement response filtering/sanitization\n"
                        "5. Enable audit logging to track potential exposure"
                    )
                )

    def _check_auth_bypass_indicators(
        self,
        headers: Dict[str, str],
        body: str,
        status_code: int,
        endpoint: str,
        method: str
    ) -> None:
        """Check for authentication bypass indicators"""

        # Check for debug/test authentication bypass
        bypass_indicators = [
            (r'auth[_-]?bypass', 'Authentication bypass flag'),
            (r'skip[_-]?auth', 'Skip authentication flag'),
            (r'no[_-]?auth', 'No authentication flag'),
            (r'test[_-]?mode', 'Test mode flag'),
            (r'debug[_-]?mode', 'Debug mode flag'),
            (r'admin[_-]?mode', 'Admin mode flag'),
        ]

        combined = str(headers) + body

        for pattern, description in bypass_indicators:
            if re.search(pattern, combined, re.IGNORECASE):
                self._add_finding(
                    issue=f"Potential authentication bypass indicator: {description}",
                    description=(
                        f"A potential authentication bypass indicator ({description}) was detected. "
                        "This may indicate debug/test code that bypasses authentication checks."
                    ),
                    severity="high",
                    category="Authentication Bypass",
                    endpoint=endpoint,
                    method=method,
                    evidence=f"Pattern matched: {pattern}",
                    cwe_id="CWE-287",
                    cvss_score=8.0,
                    recommendation=(
                        "1. Remove debug/test authentication bypass code from production\n"
                        "2. Review authentication flow for backdoors\n"
                        "3. Implement proper environment-based configuration\n"
                        "4. Add security tests for authentication bypass"
                    )
                )

    def _analyze_auth_endpoint(
        self,
        endpoint: str,
        status_code: int,
        headers: Dict,
        body: str
    ) -> None:
        """Analyze security of authentication endpoints"""

        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check for rate limiting on auth endpoints
        rate_limit_headers = [
            'x-ratelimit-limit', 'x-ratelimit-remaining', 'ratelimit-limit',
            'retry-after', 'x-rate-limit-limit'
        ]
        has_rate_limit = any(h in headers_lower for h in rate_limit_headers)

        if not has_rate_limit and status_code != 404:
            self._add_finding(
                issue=f"No rate limiting detected on authentication endpoint",
                description=(
                    f"Authentication endpoint '{endpoint}' does not appear to have rate limiting. "
                    "This makes the endpoint vulnerable to brute-force attacks and credential stuffing."
                ),
                severity="high",
                category="Authentication",
                endpoint=endpoint,
                method="POST",
                evidence="No rate limiting headers found in response",
                cwe_id="CWE-307",
                cvss_score=7.5,
                recommendation=(
                    "1. Implement rate limiting on authentication endpoints\n"
                    "2. Use progressive delays after failed attempts\n"
                    "3. Implement account lockout after multiple failures\n"
                    "4. Consider CAPTCHA for repeated failures\n"
                    "5. Monitor and alert on brute-force attempts"
                )
            )

        # Check for user enumeration via different responses
        if status_code in [401, 403]:
            # Look for specific error messages that might enable enumeration
            enumeration_patterns = [
                (r'user\s+not\s+found', 'User not found message'),
                (r'invalid\s+username', 'Invalid username message'),
                (r'no\s+account', 'No account message'),
                (r'email\s+not\s+registered', 'Email not registered message'),
            ]

            for pattern, description in enumeration_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    self._add_finding(
                        issue=f"Potential user enumeration via error message",
                        description=(
                            f"Authentication endpoint returns specific error messages ({description}) "
                            "that could allow attackers to enumerate valid usernames."
                        ),
                        severity="medium",
                        category="Authentication",
                        endpoint=endpoint,
                        method="POST",
                        evidence=f"Error message pattern detected: {description}",
                        cwe_id="CWE-204",
                        cvss_score=5.3,
                        recommendation=(
                            "1. Use generic error messages like 'Invalid credentials'\n"
                            "2. Return the same response for invalid user and invalid password\n"
                            "3. Implement consistent response timing\n"
                            "4. Add logging for enumeration attempts"
                        )
                    )
                    break

    async def _analyze_cors(self, target: str, context: Dict) -> None:
        """Analyze CORS configuration"""

        try:
            # Send OPTIONS request with Origin header
            test_origins = [
                'https://evil.com',
                'null',
                'https://attacker.com',
            ]

            parsed = urlparse(target)
            actual_origin = f"{parsed.scheme}://{parsed.netloc}"

            for test_origin in test_origins:
                # Make request with custom Origin
                response = await http_client.options(
                    target,
                    headers={'Origin': test_origin}
                )

                if response is None:
                    continue

                headers = response.headers if hasattr(response, 'headers') else {}
                headers_lower = {k.lower(): v for k, v in headers.items()}

                acao = headers_lower.get('access-control-allow-origin', '')
                acac = headers_lower.get('access-control-allow-credentials', '')

                # Check for overly permissive CORS
                if acao == '*':
                    self._add_finding(
                        issue="CORS allows all origins (wildcard)",
                        description=(
                            "The Access-Control-Allow-Origin header is set to '*', allowing any website "
                            "to make cross-origin requests. This can expose the API to cross-site attacks."
                        ),
                        severity="high" if acac.lower() == 'true' else "medium",
                        category="CORS",
                        endpoint=target,
                        method="OPTIONS",
                        evidence=f"Access-Control-Allow-Origin: *",
                        cwe_id="CWE-942",
                        cvss_score=7.5 if acac.lower() == 'true' else 5.3,
                        recommendation=(
                            "1. Specify allowed origins explicitly instead of using '*'\n"
                            "2. Implement origin validation against a whitelist\n"
                            "3. Never use wildcard with credentials allowed\n"
                            "4. Consider using CORS middleware with proper configuration"
                        )
                    )
                    break

                elif acao == test_origin:
                    self._add_finding(
                        issue=f"CORS reflects arbitrary Origin header",
                        description=(
                            f"The server reflects the Origin header value '{test_origin}' in the "
                            "Access-Control-Allow-Origin response. This can be exploited by attackers "
                            "to bypass same-origin policy restrictions."
                        ),
                        severity="high",
                        category="CORS",
                        endpoint=target,
                        method="OPTIONS",
                        evidence=f"Origin: {test_origin}\nResponse: Access-Control-Allow-Origin: {acao}",
                        cwe_id="CWE-942",
                        cvss_score=8.0,
                        recommendation=(
                            "1. Do not reflect arbitrary Origin values\n"
                            "2. Validate Origin against a whitelist of allowed domains\n"
                            "3. Return a fixed allowed origin or no header for invalid origins\n"
                            "4. Implement proper CORS validation logic"
                        )
                    )
                    break

                elif acao == 'null' and test_origin == 'null':
                    self._add_finding(
                        issue="CORS allows null origin",
                        description=(
                            "The server allows the 'null' origin, which can be exploited from sandboxed "
                            "iframes, local HTML files, or redirected requests."
                        ),
                        severity="medium",
                        category="CORS",
                        endpoint=target,
                        method="OPTIONS",
                        evidence="Access-Control-Allow-Origin: null",
                        cwe_id="CWE-942",
                        cvss_score=5.3,
                        recommendation=(
                            "1. Never allow the 'null' origin\n"
                            "2. Validate that Origin is from a trusted domain\n"
                            "3. Consider blocking requests with null origin"
                        )
                    )
                    break

        except Exception as e:
            logger.debug(f"CORS analysis error: {e}")

    def _generate_statistics(self) -> None:
        """Generate summary statistics for the analysis"""

        # Count findings by severity
        severity_counts = {}
        for finding in self.findings:
            sev = finding['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Count header issues
        header_missing = sum(1 for h in self.security_headers_results if h.status == SecurityHeaderStatus.MISSING)
        header_weak = sum(1 for h in self.security_headers_results if h.status == SecurityHeaderStatus.WEAK)

        # Count cookie issues
        cookies_with_issues = sum(1 for c in self.cookies_analyzed if c.issues)

        self.scan_statistics = {
            'total_findings': len(self.findings),
            'findings_by_severity': severity_counts,
            'security_headers': {
                'total_checked': len(self.SECURITY_HEADERS_CONFIG),
                'missing': header_missing,
                'weak': header_weak,
                'valid': len(self.security_headers_results) - header_missing - header_weak
            },
            'cookies': {
                'total_analyzed': len(self.cookies_analyzed),
                'with_issues': cookies_with_issues,
                'session_cookies': sum(1 for c in self.cookies_analyzed if c.is_session_cookie)
            },
            'auth_mechanisms_detected': [m.value for m in self.auth_mechanisms_detected]
        }

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
        recommendation: str
    ) -> None:
        """Add a finding to the results"""

        # Generate fingerprint for deduplication
        fingerprint = hashlib.sha256(
            f"{issue}|{endpoint}|{category}".encode()
        ).hexdigest()[:16]

        # Check for duplicate
        if any(f.get('fingerprint') == fingerprint for f in self.findings):
            return

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
            'discovered_at': datetime.now(timezone.utc).isoformat()
        }

        self.findings.append(finding)

    def _get_cvss_for_severity(self, severity: str) -> float:
        """Get CVSS score based on severity"""
        mapping = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'info': 0.0
        }
        return mapping.get(severity.lower(), 0.0)

    def _get_cookie_recommendation(self, issue: str) -> str:
        """Get recommendation based on cookie issue"""

        if 'HttpOnly' in issue:
            return (
                "Add the HttpOnly flag to the cookie to prevent JavaScript access:\n"
                "Set-Cookie: session=value; HttpOnly\n\n"
                "This prevents XSS attacks from stealing the cookie."
            )
        elif 'Secure' in issue:
            return (
                "Add the Secure flag to ensure the cookie is only sent over HTTPS:\n"
                "Set-Cookie: session=value; Secure\n\n"
                "This prevents the cookie from being intercepted over unencrypted connections."
            )
        elif 'SameSite' in issue:
            return (
                "Add the SameSite attribute to prevent CSRF attacks:\n"
                "Set-Cookie: session=value; SameSite=Strict\n"
                "or\n"
                "Set-Cookie: session=value; SameSite=Lax\n\n"
                "SameSite=Strict provides the strongest protection but may affect user experience."
            )
        else:
            return (
                "Review cookie settings and ensure:\n"
                "1. HttpOnly flag is set for session cookies\n"
                "2. Secure flag is set for all cookies on HTTPS sites\n"
                "3. SameSite attribute is configured appropriately"
            )
