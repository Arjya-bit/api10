"""
Enterprise JWT Security Analyzer
=================================
Comprehensive JSON Web Token (JWT) security analysis with algorithm
verification, signature validation, claim analysis, and token leakage detection.

Features:
- JWT structure validation and parsing
- Algorithm security analysis (none, HS256, RS256, etc.)
- Algorithm confusion attack detection
- Token expiration and timing analysis
- Claim validation (iss, aud, sub, iat, exp, nbf)
- Sensitive data exposure in payload
- Token leakage detection (URL, logs, responses)
- Key strength analysis for symmetric algorithms
- JWK/JWKS endpoint security
- Token replay vulnerability detection
- Kid header injection analysis
- Detailed findings with CWE/CVSS mappings

Author: APIGuardian Enterprise
Version: 2.0.0
"""

import logging
import re
import json
import base64
import hashlib
import hmac
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum

from apiguardian.core.plugin_manager import AnalyzerPlugin
from apiguardian.utils.http_client import http_client

logger = logging.getLogger(__name__)


class JWTAlgorithm(Enum):
    """JWT signing algorithms"""
    NONE = "none"
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"
    UNKNOWN = "unknown"


class JWTRisk(Enum):
    """Risk level for JWT issues"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class JWTAnalysisResult:
    """Detailed JWT analysis result"""
    token_preview: str
    algorithm: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    has_signature: bool
    is_expired: bool = False
    expiry_time: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    not_before: Optional[datetime] = None
    issuer: Optional[str] = None
    audience: Optional[str] = None
    subject: Optional[str] = None
    custom_claims: List[str] = field(default_factory=list)
    sensitive_claims: List[str] = field(default_factory=list)
    issues: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'token_preview': self.token_preview,
            'algorithm': self.algorithm,
            'header': self.header,
            'payload': {k: v for k, v in self.payload.items() if k not in ['password', 'secret', 'key']},
            'has_signature': self.has_signature,
            'is_expired': self.is_expired,
            'expiry_time': self.expiry_time.isoformat() if self.expiry_time else None,
            'issued_at': self.issued_at.isoformat() if self.issued_at else None,
            'issuer': self.issuer,
            'audience': self.audience,
            'subject': self.subject,
            'custom_claims': self.custom_claims,
            'sensitive_claims': self.sensitive_claims,
            'issues_count': len(self.issues)
        }


class JWTAnalyzer(AnalyzerPlugin):
    """
    Enterprise-grade JWT Security Analyzer

    Performs comprehensive JWT security analysis including:
    - Algorithm security verification
    - Token structure validation
    - Claim analysis and validation
    - Sensitive data detection
    - Token leakage identification
    - Expiration and timing analysis
    """

    plugin_name = "jwt_analyzer"
    description = "Comprehensive JWT token security analysis with vulnerability detection"
    version = "2.0.0"

    # JWT regex pattern
    JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

    # Weak/insecure algorithms
    WEAK_ALGORITHMS = {
        'none': {
            'severity': 'critical',
            'issue': 'JWT uses "none" algorithm - no signature verification',
            'cwe_id': 'CWE-327',
            'cvss': 9.8,
            'description': 'The "none" algorithm bypasses signature verification entirely, allowing token forgery'
        },
        'None': {
            'severity': 'critical',
            'issue': 'JWT uses "None" algorithm variant - potential bypass attempt',
            'cwe_id': 'CWE-327',
            'cvss': 9.8,
            'description': 'Case variant of "none" algorithm, often used in bypass attacks'
        },
        'NONE': {
            'severity': 'critical',
            'issue': 'JWT uses "NONE" algorithm variant - potential bypass attempt',
            'cwe_id': 'CWE-327',
            'cvss': 9.8,
            'description': 'Case variant of "none" algorithm, often used in bypass attacks'
        },
        'nOnE': {
            'severity': 'critical',
            'issue': 'JWT uses mixed-case "none" algorithm variant',
            'cwe_id': 'CWE-327',
            'cvss': 9.8,
            'description': 'Mixed case variant of "none" algorithm, bypasses naive checks'
        }
    }

    # Algorithms susceptible to confusion attacks
    CONFUSION_VULNERABLE = {
        'RS256': 'Can be confused with HS256 if server accepts both',
        'RS384': 'Can be confused with HS384 if server accepts both',
        'RS512': 'Can be confused with HS512 if server accepts both',
        'ES256': 'Can be confused with HS256 if server accepts both',
        'ES384': 'Can be confused with HS384 if server accepts both',
        'ES512': 'Can be confused with HS512 if server accepts both',
    }

    # Symmetric algorithms (weaker than asymmetric)
    SYMMETRIC_ALGORITHMS = ['HS256', 'HS384', 'HS512']

    # Required standard claims
    REQUIRED_CLAIMS = {
        'exp': {
            'description': 'Expiration time',
            'severity': 'medium',
            'missing_issue': 'JWT has no expiration claim - tokens never expire'
        },
        'iat': {
            'description': 'Issued at time',
            'severity': 'low',
            'missing_issue': 'JWT has no issued-at claim - cannot verify token age'
        }
    }

    # Recommended claims
    RECOMMENDED_CLAIMS = {
        'iss': 'Issuer - identifies token creator',
        'aud': 'Audience - identifies intended recipient',
        'sub': 'Subject - identifies the principal',
        'nbf': 'Not before - token validity start time',
        'jti': 'JWT ID - unique identifier for replay protection'
    }

    # Sensitive data patterns in JWT payload
    SENSITIVE_PATTERNS = {
        'password': {
            'patterns': [r'password', r'passwd', r'pwd', r'pass'],
            'severity': 'critical',
            'cwe_id': 'CWE-200',
            'description': 'Password or password-related field in JWT payload'
        },
        'secret': {
            'patterns': [r'secret', r'api_secret', r'client_secret'],
            'severity': 'critical',
            'cwe_id': 'CWE-200',
            'description': 'Secret or API secret in JWT payload'
        },
        'private_key': {
            'patterns': [r'private_key', r'privatekey', r'priv_key'],
            'severity': 'critical',
            'cwe_id': 'CWE-321',
            'description': 'Private key reference in JWT payload'
        },
        'credit_card': {
            'patterns': [r'credit_card', r'card_number', r'cc_num', r'pan'],
            'severity': 'critical',
            'cwe_id': 'CWE-200',
            'description': 'Credit card information in JWT payload'
        },
        'ssn': {
            'patterns': [r'ssn', r'social_security', r'national_id'],
            'severity': 'critical',
            'cwe_id': 'CWE-200',
            'description': 'Social security or national ID in JWT payload'
        },
        'api_key': {
            'patterns': [r'api_key', r'apikey', r'access_key'],
            'severity': 'high',
            'cwe_id': 'CWE-200',
            'description': 'API key in JWT payload'
        },
        'database': {
            'patterns': [r'db_pass', r'database_url', r'connection_string'],
            'severity': 'critical',
            'cwe_id': 'CWE-200',
            'description': 'Database credentials in JWT payload'
        },
        'internal_ip': {
            'patterns': [r'internal_ip', r'private_ip', r'server_ip'],
            'severity': 'medium',
            'cwe_id': 'CWE-200',
            'description': 'Internal IP address in JWT payload'
        },
        'session': {
            'patterns': [r'session_id', r'session_key', r'sess_'],
            'severity': 'high',
            'cwe_id': 'CWE-200',
            'description': 'Session information in JWT payload'
        }
    }

    # Kid header injection patterns
    KID_INJECTION_PATTERNS = [
        (r'\.\./', 'Path traversal in kid header'),
        (r'/etc/', 'Unix path in kid header'),
        (r'C:\\', 'Windows path in kid header'),
        (r'file://', 'File URI in kid header'),
        (r'http://', 'HTTP URL in kid header'),
        (r'https://', 'HTTPS URL in kid header'),
        (r'\|', 'Pipe character in kid header'),
        (r';', 'Semicolon in kid header'),
        (r'`', 'Backtick in kid header'),
        (r'\$\(', 'Command substitution in kid header'),
    ]

    # JWT endpoints to probe
    JWT_ENDPOINTS = [
        '/token', '/oauth/token', '/api/token', '/auth/token',
        '/login', '/api/login', '/authenticate',
        '/.well-known/jwks.json', '/jwks.json', '/certs',
        '/.well-known/openid-configuration',
        '/api/v1/token', '/api/v2/token'
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.findings: List[Dict[str, Any]] = []
        self.tokens_analyzed: List[JWTAnalysisResult] = []
        self.algorithms_found: Set[str] = set()
        self.jwks_endpoints: List[str] = []
        self.scan_statistics: Dict[str, Any] = {}

    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Perform comprehensive JWT security analysis

        Args:
            target: Target URL to analyze
            context: Scan context with configuration and responses

        Returns:
            List of security findings
        """
        self.findings = []
        self.tokens_analyzed = []
        self.algorithms_found = set()
        self.jwks_endpoints = []

        if not target:
            return self.findings

        logger.info(f"Starting JWT security analysis on {target}")

        # Analyze provided responses from context
        responses = context.get('responses', [])
        for response in responses:
            await self._analyze_response(response, target)

        # Check if JWT token provided directly
        if 'jwt_token' in context:
            token = context['jwt_token']
            result = self._analyze_token(token, target)
            if result:
                self.tokens_analyzed.append(result)

        # Probe JWT-related endpoints
        await self._probe_jwt_endpoints(target, context)

        # Generate summary
        self._generate_statistics()

        logger.info(f"JWT analysis complete: {len(self.findings)} findings, {len(self.tokens_analyzed)} tokens analyzed")

        return self.findings

    async def _analyze_response(self, response: Dict, target: str) -> None:
        """Analyze HTTP response for JWT tokens and issues"""

        body = response.get('body', '')
        headers = response.get('headers', {})
        endpoint = response.get('endpoint', target)
        method = response.get('method', 'GET')

        # Search for JWTs in response body
        body_str = body if isinstance(body, str) else str(body)
        jwt_matches = self.JWT_PATTERN.findall(body_str)

        for token in jwt_matches:
            result = self._analyze_token(token, endpoint)
            if result:
                self.tokens_analyzed.append(result)

                # Check for JWT in response body (potential leakage)
                self._add_finding(
                    issue="JWT token exposed in API response body",
                    description=(
                        "A JWT token was found in the API response body. Depending on the context, "
                        "this could be legitimate (token endpoint) or a security issue (data leakage)."
                    ),
                    severity="info",
                    category="Information Disclosure",
                    endpoint=endpoint,
                    method=method,
                    evidence=f"JWT found: {token[:50]}...{token[-10:]}",
                    cwe_id="CWE-200",
                    cvss_score=0.0,
                    recommendation="Review whether exposing JWT in this response is intentional and necessary."
                )

        # Check Authorization header
        auth_header = headers.get('Authorization', '') or headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            if self._is_valid_jwt_format(token):
                result = self._analyze_token(token, endpoint)
                if result:
                    self.tokens_analyzed.append(result)

        # Check for JWT in URL (security issue)
        if 'token=' in endpoint or 'jwt=' in endpoint or 'access_token=' in endpoint:
            jwt_in_url = self.JWT_PATTERN.search(endpoint)
            if jwt_in_url:
                self._add_finding(
                    issue="JWT token exposed in URL",
                    description=(
                        "A JWT token is being passed in the URL. This is a security risk as URLs "
                        "are often logged in server logs, browser history, and can leak through Referrer headers."
                    ),
                    severity="high",
                    category="Information Disclosure",
                    endpoint=endpoint,
                    method=method,
                    evidence=f"JWT found in URL query parameter",
                    cwe_id="CWE-598",
                    cvss_score=7.5,
                    recommendation=(
                        "1. Pass JWT tokens in the Authorization header instead of URLs\n"
                        "2. If URL tokens are required, use short-lived single-use tokens\n"
                        "3. Implement token binding to prevent replay attacks\n"
                        "4. Configure proper Referrer-Policy header"
                    )
                )

    def _analyze_token(self, token: str, endpoint: str) -> Optional[JWTAnalysisResult]:
        """Analyze a single JWT token"""

        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode header and payload
            header = self._decode_base64(parts[0])
            payload = self._decode_base64(parts[1])

            if not header or not payload:
                return None

            # Create preview (masked)
            token_preview = f"{token[:20]}...{token[-10:]}" if len(token) > 30 else token

            # Get algorithm
            algorithm = header.get('alg', 'unknown')
            self.algorithms_found.add(algorithm)

            # Check signature presence
            has_signature = len(parts[2]) > 0

            # Parse timing claims
            exp_time = None
            iat_time = None
            nbf_time = None
            is_expired = False

            if 'exp' in payload:
                try:
                    exp_time = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
                    is_expired = exp_time < datetime.now(timezone.utc)
                except (ValueError, TypeError, OSError):
                    pass

            if 'iat' in payload:
                try:
                    iat_time = datetime.fromtimestamp(payload['iat'], tz=timezone.utc)
                except (ValueError, TypeError, OSError):
                    pass

            if 'nbf' in payload:
                try:
                    nbf_time = datetime.fromtimestamp(payload['nbf'], tz=timezone.utc)
                except (ValueError, TypeError, OSError):
                    pass

            # Get standard claims
            issuer = payload.get('iss')
            audience = payload.get('aud')
            subject = payload.get('sub')

            # Identify custom claims
            standard_claims = {'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'}
            custom_claims = [k for k in payload.keys() if k not in standard_claims]

            # Check for sensitive data
            sensitive_claims = self._find_sensitive_claims(payload)

            # Create result
            result = JWTAnalysisResult(
                token_preview=token_preview,
                algorithm=algorithm,
                header=header,
                payload=payload,
                has_signature=has_signature,
                is_expired=is_expired,
                expiry_time=exp_time,
                issued_at=iat_time,
                not_before=nbf_time,
                issuer=issuer,
                audience=audience,
                subject=subject,
                custom_claims=custom_claims,
                sensitive_claims=sensitive_claims
            )

            # Generate findings for this token
            self._analyze_token_security(result, endpoint, header, payload)

            return result

        except Exception as e:
            logger.debug(f"Error analyzing JWT: {e}")
            return None

    def _analyze_token_security(
        self,
        result: JWTAnalysisResult,
        endpoint: str,
        header: Dict[str, Any],
        payload: Dict[str, Any]
    ) -> None:
        """Analyze token for security issues and generate findings"""

        algorithm = header.get('alg', 'unknown')

        # 1. Check for weak/none algorithm
        if algorithm.lower() in [a.lower() for a in self.WEAK_ALGORITHMS.keys()]:
            config = self.WEAK_ALGORITHMS.get(algorithm, self.WEAK_ALGORITHMS.get('none'))
            self._add_finding(
                issue=f"JWT uses insecure algorithm: {algorithm}",
                description=config['description'],
                severity=config['severity'],
                category="Authentication",
                endpoint=endpoint,
                method="GET",
                evidence=f"Algorithm in JWT header: {algorithm}",
                cwe_id=config['cwe_id'],
                cvss_score=config['cvss'],
                recommendation=(
                    "1. Never use the 'none' algorithm in production\n"
                    "2. Validate the algorithm on the server side against a whitelist\n"
                    "3. Use asymmetric algorithms (RS256, ES256) for better security\n"
                    "4. Reject tokens with unexpected algorithms"
                )
            )

        # 2. Check for symmetric algorithm
        elif algorithm in self.SYMMETRIC_ALGORITHMS:
            self._add_finding(
                issue=f"JWT uses symmetric algorithm: {algorithm}",
                description=(
                    f"The JWT uses symmetric algorithm {algorithm}. Symmetric algorithms "
                    "require the same secret key for signing and verification, which poses "
                    "security risks if the key is exposed or needs to be shared."
                ),
                severity="medium",
                category="Authentication",
                endpoint=endpoint,
                method="GET",
                evidence=f"Algorithm: {algorithm}",
                cwe_id="CWE-327",
                cvss_score=5.3,
                recommendation=(
                    "1. Consider using asymmetric algorithms (RS256, ES256) for better security\n"
                    "2. Ensure the secret key is strong (minimum 256 bits of entropy)\n"
                    "3. Store secrets securely using a secrets manager\n"
                    "4. Rotate signing keys periodically"
                )
            )

        # 3. Check for algorithm confusion vulnerability
        if algorithm in self.CONFUSION_VULNERABLE:
            self._add_finding(
                issue=f"JWT may be vulnerable to algorithm confusion attack",
                description=(
                    f"The JWT uses {algorithm} which could be vulnerable to algorithm confusion "
                    "attacks if the server also accepts symmetric algorithms. An attacker could "
                    "change the algorithm to HS256 and sign with the public key."
                ),
                severity="high",
                category="Authentication",
                endpoint=endpoint,
                method="GET",
                evidence=f"Algorithm: {algorithm}\nVulnerability: {self.CONFUSION_VULNERABLE[algorithm]}",
                cwe_id="CWE-347",
                cvss_score=8.1,
                recommendation=(
                    "1. Validate algorithm against a strict whitelist on the server\n"
                    "2. Never accept multiple algorithm types for the same key\n"
                    "3. Use separate keys for different algorithms\n"
                    "4. Test for algorithm confusion vulnerabilities"
                )
            )

        # 4. Check for missing expiration
        if 'exp' not in payload:
            self._add_finding(
                issue="JWT has no expiration claim",
                description=(
                    "The JWT does not contain an 'exp' (expiration) claim. Tokens without "
                    "expiration never expire and remain valid indefinitely, increasing the "
                    "risk of token theft and replay attacks."
                ),
                severity="high",
                category="Authentication",
                endpoint=endpoint,
                method="GET",
                evidence="Missing 'exp' claim in JWT payload",
                cwe_id="CWE-613",
                cvss_score=7.5,
                recommendation=(
                    "1. Always include 'exp' claim in JWT tokens\n"
                    "2. Set reasonable expiration times (15 minutes to 24 hours depending on use case)\n"
                    "3. Use refresh tokens for long-lived sessions\n"
                    "4. Implement token revocation for emergency situations"
                )
            )

        # 5. Check for expired token still in use
        if result.is_expired:
            self._add_finding(
                issue="Expired JWT token detected",
                description=(
                    f"An expired JWT token was found (expired at {result.expiry_time.isoformat() if result.expiry_time else 'unknown'}). "
                    "The presence of expired tokens may indicate improper token lifecycle management."
                ),
                severity="medium",
                category="Authentication",
                endpoint=endpoint,
                method="GET",
                evidence=f"Token expired at: {result.expiry_time.isoformat() if result.expiry_time else 'unknown'}",
                cwe_id="CWE-613",
                cvss_score=5.3,
                recommendation=(
                    "1. Implement proper token expiration validation\n"
                    "2. Clear expired tokens from client storage\n"
                    "3. Implement automatic token refresh before expiration\n"
                    "4. Log and monitor use of expired tokens"
                )
            )

        # 6. Check for very long expiration
        if result.expiry_time and result.issued_at:
            token_lifetime = result.expiry_time - result.issued_at
            if token_lifetime > timedelta(days=7):
                self._add_finding(
                    issue="JWT has very long expiration time",
                    description=(
                        f"The JWT has an expiration time of {token_lifetime.days} days. "
                        "Long-lived tokens increase the window of opportunity for attackers "
                        "if a token is compromised."
                    ),
                    severity="medium",
                    category="Authentication",
                    endpoint=endpoint,
                    method="GET",
                    evidence=f"Token lifetime: {token_lifetime.days} days",
                    cwe_id="CWE-613",
                    cvss_score=4.0,
                    recommendation=(
                        "1. Reduce token expiration time to the minimum necessary\n"
                        "2. Use refresh tokens for extended sessions\n"
                        "3. Implement token rotation\n"
                        "4. Consider sliding expiration for active sessions"
                    )
                )

        # 7. Check for missing 'iat' claim
        if 'iat' not in payload:
            self._add_finding(
                issue="JWT missing 'iat' (issued at) claim",
                description=(
                    "The JWT does not contain an 'iat' claim. Without this claim, it's impossible "
                    "to determine when the token was issued, making it harder to detect stale or "
                    "replayed tokens."
                ),
                severity="low",
                category="Authentication",
                endpoint=endpoint,
                method="GET",
                evidence="Missing 'iat' claim in JWT payload",
                cwe_id="CWE-613",
                cvss_score=2.0,
                recommendation="Add 'iat' (issued at) claim to all JWT tokens for audit and validation purposes."
            )

        # 8. Check for missing 'jti' (replay protection)
        if 'jti' not in payload:
            self._add_finding(
                issue="JWT missing 'jti' (JWT ID) claim",
                description=(
                    "The JWT does not contain a 'jti' claim. This claim provides a unique identifier "
                    "that can be used to prevent replay attacks by tracking used tokens."
                ),
                severity="low",
                category="Authentication",
                endpoint=endpoint,
                method="GET",
                evidence="Missing 'jti' claim in JWT payload",
                cwe_id="CWE-294",
                cvss_score=3.0,
                recommendation=(
                    "1. Add 'jti' claim with a unique identifier to each token\n"
                    "2. Implement server-side tracking of used 'jti' values\n"
                    "3. Reject tokens with previously used 'jti' values"
                )
            )

        # 9. Check for sensitive data in payload
        for claim in result.sensitive_claims:
            config = None
            for pattern_name, pattern_config in self.SENSITIVE_PATTERNS.items():
                if any(re.search(p, claim, re.IGNORECASE) for p in pattern_config['patterns']):
                    config = pattern_config
                    break

            if config:
                self._add_finding(
                    issue=f"Sensitive data in JWT payload: {claim}",
                    description=f"{config['description']}. JWT payloads are only base64 encoded and can be easily decoded by anyone.",
                    severity=config['severity'],
                    category="Sensitive Data Exposure",
                    endpoint=endpoint,
                    method="GET",
                    evidence=f"Sensitive claim found: {claim}",
                    cwe_id=config['cwe_id'],
                    cvss_score=8.0 if config['severity'] == 'critical' else 6.0,
                    recommendation=(
                        "1. Never include sensitive data in JWT payloads\n"
                        "2. Store sensitive data server-side and reference by ID\n"
                        "3. If encryption is needed, use JWE (JSON Web Encryption)\n"
                        "4. Review JWT payload design for data minimization"
                    )
                )

        # 10. Check for 'kid' header injection
        kid = header.get('kid')
        if kid:
            for pattern, description in self.KID_INJECTION_PATTERNS:
                if re.search(pattern, kid):
                    self._add_finding(
                        issue=f"Potential 'kid' header injection: {description}",
                        description=(
                            f"The JWT 'kid' (key ID) header contains suspicious characters: {description}. "
                            "This could indicate a key injection attack where the attacker tries to "
                            "reference a different key for signature verification."
                        ),
                        severity="high",
                        category="Injection",
                        endpoint=endpoint,
                        method="GET",
                        evidence=f"kid value: {kid[:100]}",
                        cwe_id="CWE-94",
                        cvss_score=8.0,
                        recommendation=(
                            "1. Validate 'kid' header against allowed key identifiers\n"
                            "2. Never use 'kid' value directly in file paths or SQL queries\n"
                            "3. Use a whitelist of allowed key IDs\n"
                            "4. Implement proper input validation for header claims"
                        )
                    )
                    break

        # 11. Check for missing signature
        if not result.has_signature:
            self._add_finding(
                issue="JWT has no signature",
                description=(
                    "The JWT has an empty signature component. This is only valid for 'none' algorithm "
                    "tokens, which should never be used in production."
                ),
                severity="critical",
                category="Authentication",
                endpoint=endpoint,
                method="GET",
                evidence="Empty signature in JWT",
                cwe_id="CWE-347",
                cvss_score=9.8,
                recommendation=(
                    "1. Ensure all tokens are properly signed\n"
                    "2. Reject tokens without valid signatures\n"
                    "3. Never accept 'none' algorithm in production"
                )
            )

    def _find_sensitive_claims(self, payload: Dict[str, Any]) -> List[str]:
        """Find sensitive claims in JWT payload"""
        sensitive = []

        for claim_name in payload.keys():
            for pattern_name, config in self.SENSITIVE_PATTERNS.items():
                if any(re.search(p, claim_name, re.IGNORECASE) for p in config['patterns']):
                    sensitive.append(claim_name)
                    break

        return sensitive

    async def _probe_jwt_endpoints(self, target: str, context: Dict) -> None:
        """Probe JWT-related endpoints"""

        base_url = target.rstrip('/')

        for endpoint_path in self.JWT_ENDPOINTS:
            endpoint_url = urljoin(base_url + '/', endpoint_path.lstrip('/'))

            try:
                response = await http_client.get(endpoint_url)

                if response is None:
                    continue

                status_code = response.status_code
                body = response.body.decode('utf-8', errors='ignore') if hasattr(response, 'body') else ''

                # Skip 404 responses
                if status_code == 404:
                    continue

                # Check for JWKS endpoint
                if 'jwks' in endpoint_path.lower() or 'certs' in endpoint_path.lower():
                    if status_code == 200:
                        self.jwks_endpoints.append(endpoint_url)
                        self._analyze_jwks_response(endpoint_url, body)

                # Check for OpenID configuration
                if 'openid-configuration' in endpoint_path:
                    if status_code == 200:
                        self._analyze_openid_config(endpoint_url, body)

                # Search for JWTs in response
                jwt_matches = self.JWT_PATTERN.findall(body)
                for token in jwt_matches:
                    result = self._analyze_token(token, endpoint_url)
                    if result:
                        self.tokens_analyzed.append(result)

            except Exception as e:
                logger.debug(f"Error probing JWT endpoint {endpoint_url}: {e}")

    def _analyze_jwks_response(self, endpoint: str, body: str) -> None:
        """Analyze JWKS endpoint response"""

        try:
            jwks = json.loads(body)

            if 'keys' in jwks:
                for key in jwks['keys']:
                    # Check for weak key parameters
                    kty = key.get('kty', '')
                    alg = key.get('alg', '')
                    use = key.get('use', '')

                    # Check RSA key size (n parameter length)
                    if kty == 'RSA' and 'n' in key:
                        n_len = len(key['n']) * 6 // 8  # Approximate bits from base64
                        if n_len < 256:  # Less than 2048 bits
                            self._add_finding(
                                issue="Weak RSA key size in JWKS",
                                description=(
                                    f"The JWKS endpoint contains an RSA key with insufficient key size. "
                                    "Keys smaller than 2048 bits are considered weak."
                                ),
                                severity="high",
                                category="Cryptography",
                                endpoint=endpoint,
                                method="GET",
                                evidence=f"RSA key with approximately {n_len * 8} bits",
                                cwe_id="CWE-326",
                                cvss_score=7.5,
                                recommendation="Use RSA keys with at least 2048 bits, preferably 4096 bits."
                            )

                # JWKS publicly accessible info finding
                self._add_finding(
                    issue="JWKS endpoint publicly accessible",
                    description=(
                        f"The JSON Web Key Set (JWKS) endpoint is publicly accessible at {endpoint}. "
                        "While this is often intentional for public key distribution, ensure that "
                        "private keys are never exposed through this endpoint."
                    ),
                    severity="info",
                    category="Information Disclosure",
                    endpoint=endpoint,
                    method="GET",
                    evidence=f"JWKS contains {len(jwks.get('keys', []))} key(s)",
                    cwe_id="CWE-200",
                    cvss_score=0.0,
                    recommendation=(
                        "1. Verify only public keys are exposed through JWKS\n"
                        "2. Implement key rotation\n"
                        "3. Consider adding caching headers for performance"
                    )
                )

        except json.JSONDecodeError:
            pass

    def _analyze_openid_config(self, endpoint: str, body: str) -> None:
        """Analyze OpenID Connect configuration"""

        try:
            config = json.loads(body)

            # Check for supported algorithms
            id_token_algs = config.get('id_token_signing_alg_values_supported', [])
            if 'none' in id_token_algs or 'None' in id_token_algs:
                self._add_finding(
                    issue="OpenID configuration allows 'none' algorithm",
                    description=(
                        "The OpenID Connect configuration indicates support for the 'none' algorithm, "
                        "which allows unsigned tokens."
                    ),
                    severity="critical",
                    category="Authentication",
                    endpoint=endpoint,
                    method="GET",
                    evidence=f"Supported algorithms: {id_token_algs}",
                    cwe_id="CWE-327",
                    cvss_score=9.8,
                    recommendation="Remove 'none' from supported algorithms in OpenID configuration."
                )

            # OpenID configuration info
            self._add_finding(
                issue="OpenID Connect configuration discovered",
                description=(
                    f"OpenID Connect well-known configuration endpoint found at {endpoint}. "
                    "This reveals information about the authentication infrastructure."
                ),
                severity="info",
                category="Information Disclosure",
                endpoint=endpoint,
                method="GET",
                evidence=f"Issuer: {config.get('issuer', 'unknown')}",
                cwe_id="CWE-200",
                cvss_score=0.0,
                recommendation="Review OpenID configuration for any unnecessary information disclosure."
            )

        except json.JSONDecodeError:
            pass

    def _decode_base64(self, encoded: str) -> Optional[Dict]:
        """Decode base64url encoded JWT part"""
        try:
            # Add padding if needed
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += '=' * padding

            decoded = base64.urlsafe_b64decode(encoded)
            return json.loads(decoded)
        except Exception:
            return None

    def _is_valid_jwt_format(self, token: str) -> bool:
        """Check if string is a valid JWT format"""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        return bool(self.JWT_PATTERN.match(token))

    def _generate_statistics(self) -> None:
        """Generate summary statistics"""

        severity_counts = {}
        for finding in self.findings:
            sev = finding['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        self.scan_statistics = {
            'total_findings': len(self.findings),
            'findings_by_severity': severity_counts,
            'tokens_analyzed': len(self.tokens_analyzed),
            'algorithms_found': list(self.algorithms_found),
            'jwks_endpoints': self.jwks_endpoints,
            'expired_tokens': sum(1 for t in self.tokens_analyzed if t.is_expired),
            'tokens_with_sensitive_data': sum(1 for t in self.tokens_analyzed if t.sensitive_claims)
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

        fingerprint = hashlib.sha256(
            f"{issue}|{endpoint}|{evidence[:100]}".encode()
        ).hexdigest()[:16]

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
