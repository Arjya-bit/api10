"""Replay Attack Detector - Enterprise-grade replay vulnerability detection and analysis"""
import re
import logging
import hashlib
import time
import asyncio
import base64
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, parse_qs

from apiguardian.core.plugin_manager import AnalyzerPlugin
from apiguardian.utils.http_client import safe_http_client, HTTPResponse

logger = logging.getLogger(__name__)


class ReplayRiskLevel(Enum):
    """Risk levels for replay vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ReplayVulnType(Enum):
    """Types of replay vulnerabilities"""
    NO_NONCE = "no_nonce"
    WEAK_NONCE = "weak_nonce"
    NO_TIMESTAMP = "no_timestamp"
    EXPIRED_TIMESTAMP = "expired_timestamp"
    NO_SIGNATURE = "no_signature"
    SIGNATURE_REUSE = "signature_reuse"
    TOKEN_REUSE = "token_reuse"
    SESSION_FIXATION = "session_fixation"
    NO_IDEMPOTENCY = "no_idempotency"
    REQUEST_REPLAY = "request_replay"


@dataclass
class ReplayProtection:
    """Represents replay protection mechanisms found"""
    has_nonce: bool = False
    has_timestamp: bool = False
    has_signature: bool = False
    has_idempotency_key: bool = False
    has_request_id: bool = False
    has_sequence_number: bool = False
    nonce_value: Optional[str] = None
    timestamp_value: Optional[str] = None
    signature_type: Optional[str] = None
    idempotency_key: Optional[str] = None
    protection_score: float = 0.0  # 0-100


@dataclass
class ReplayTestResult:
    """Result of a replay attack test"""
    test_type: str
    original_request: Dict
    replayed_request: Dict
    original_response_code: int
    replay_response_code: int
    replay_accepted: bool
    time_delay: float
    response_similarity: float
    evidence: str


@dataclass
class ReplayVulnerability:
    """Represents a detected replay vulnerability"""
    vuln_type: ReplayVulnType
    risk_level: ReplayRiskLevel
    endpoint: str
    method: str
    protection: ReplayProtection
    test_result: Optional[ReplayTestResult] = None
    evidence: str = ""
    confidence: float = 0.0


# CWE mappings for replay vulnerabilities
REPLAY_CWE_MAPPINGS = {
    ReplayVulnType.NO_NONCE: {
        'id': 'CWE-294',
        'name': 'Authentication Bypass by Capture-replay',
        'cvss_base': 7.0
    },
    ReplayVulnType.WEAK_NONCE: {
        'id': 'CWE-330',
        'name': 'Use of Insufficiently Random Values',
        'cvss_base': 5.5
    },
    ReplayVulnType.NO_TIMESTAMP: {
        'id': 'CWE-294',
        'name': 'Authentication Bypass by Capture-replay',
        'cvss_base': 6.5
    },
    ReplayVulnType.EXPIRED_TIMESTAMP: {
        'id': 'CWE-613',
        'name': 'Insufficient Session Expiration',
        'cvss_base': 5.0
    },
    ReplayVulnType.NO_SIGNATURE: {
        'id': 'CWE-345',
        'name': 'Insufficient Verification of Data Authenticity',
        'cvss_base': 7.0
    },
    ReplayVulnType.SIGNATURE_REUSE: {
        'id': 'CWE-294',
        'name': 'Authentication Bypass by Capture-replay',
        'cvss_base': 7.5
    },
    ReplayVulnType.TOKEN_REUSE: {
        'id': 'CWE-294',
        'name': 'Authentication Bypass by Capture-replay',
        'cvss_base': 8.0
    },
    ReplayVulnType.SESSION_FIXATION: {
        'id': 'CWE-384',
        'name': 'Session Fixation',
        'cvss_base': 8.0
    },
    ReplayVulnType.NO_IDEMPOTENCY: {
        'id': 'CWE-352',
        'name': 'Cross-Site Request Forgery',
        'cvss_base': 5.0
    },
    ReplayVulnType.REQUEST_REPLAY: {
        'id': 'CWE-294',
        'name': 'Authentication Bypass by Capture-replay',
        'cvss_base': 8.5
    }
}


# Headers that indicate replay protection
NONCE_HEADERS = [
    'x-nonce', 'nonce', 'x-request-nonce', 'x-api-nonce',
    'x-client-nonce', 'client-nonce', 'request-nonce'
]

TIMESTAMP_HEADERS = [
    'x-timestamp', 'timestamp', 'x-request-timestamp', 'x-date',
    'date', 'x-api-timestamp', 'x-request-time'
]

SIGNATURE_HEADERS = [
    'x-signature', 'signature', 'x-hub-signature', 'x-hub-signature-256',
    'x-api-signature', 'authorization', 'x-hmac-signature', 'x-auth-signature'
]

REQUEST_ID_HEADERS = [
    'x-request-id', 'request-id', 'x-correlation-id', 'correlation-id',
    'x-trace-id', 'trace-id', 'x-amzn-requestid', 'x-b3-traceid'
]

IDEMPOTENCY_HEADERS = [
    'idempotency-key', 'x-idempotency-key', 'idempotent-key',
    'x-idempotent-key', 'x-unique-id'
]

SEQUENCE_HEADERS = [
    'x-sequence-number', 'sequence-number', 'x-seq', 'seq-num'
]


# Signature patterns
SIGNATURE_PATTERNS = {
    'hmac_sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
    'hmac_sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
    'hmac_md5': re.compile(r'^[a-fA-F0-9]{32}$'),
    'base64_signature': re.compile(r'^[A-Za-z0-9+/]+={0,2}$'),
    'jwt': re.compile(r'^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$'),
    'aws_signature': re.compile(r'AWS4-HMAC-SHA256'),
    'oauth_signature': re.compile(r'OAuth\s+.*oauth_signature')
}


# Sensitive endpoint patterns that require replay protection
SENSITIVE_ENDPOINTS = [
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:auth|login|signin|authenticate)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:logout|signout)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:token|oauth|authorize)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:password|reset|change)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:payment|checkout|purchase)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:transfer|withdraw|deposit)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:order|orders)(?:/[^/]+)?$', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:transaction|transactions)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:webhook|callback)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:2fa|mfa|otp|verify)', re.I)
]


# Weak nonce patterns
WEAK_NONCE_PATTERNS = [
    re.compile(r'^[0-9]+$'),  # Pure numeric (possibly sequential)
    re.compile(r'^[0-9]{10,13}$'),  # Timestamp-like
    re.compile(r'^[a-zA-Z0-9]{1,8}$'),  # Too short
]


class ReplayAttackDetector(AnalyzerPlugin):
    """Enterprise-grade replay attack vulnerability detection"""

    plugin_name = "replay_attack_detector"
    description = "Detect replay vulnerabilities in API authentication, signatures, and transaction handling"
    version = "2.0.0"

    # Recommended timestamp window (in seconds)
    RECOMMENDED_TIMESTAMP_WINDOW = 300  # 5 minutes
    MIN_NONCE_LENGTH = 16  # Minimum recommended nonce length

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the replay attack detector"""
        super().__init__(config)
        self.config = config or {}
        self.tested_endpoints: Set[str] = set()
        self.captured_nonces: Dict[str, List[str]] = {}
        self.captured_signatures: Dict[str, List[str]] = {}
        self.request_delay = 0.5  # Delay between requests

    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze for replay attack vulnerabilities"""
        findings = []

        logger.info(f"Starting replay attack analysis for target: {target}")

        # Get configuration
        config = context.get('config', {})
        analyzer_config = config.get('analyzers', {}).get('replay', {})

        # Configuration options
        test_replay = analyzer_config.get('test_replay', True)
        timestamp_window = analyzer_config.get('timestamp_window', self.RECOMMENDED_TIMESTAMP_WINDOW)

        # Get endpoints to test
        endpoints = context.get('endpoints', [])
        if not endpoints and target:
            endpoints = [{'url': target, 'method': 'GET'}]

        # Check provided responses
        responses = context.get('responses', [])
        for response in responses:
            resp_findings = self._analyze_response_protection(response, target)
            findings.extend(resp_findings)

        logger.info(f"Analyzing {len(endpoints)} endpoints for replay vulnerabilities")

        # Test each endpoint
        for endpoint_info in endpoints:
            url = endpoint_info.get('url', '')
            method = endpoint_info.get('method', 'GET').upper()
            headers = endpoint_info.get('headers', {})
            body = endpoint_info.get('body', {})

            if not url:
                continue

            # Skip already tested
            endpoint_key = f"{method}:{url}"
            if endpoint_key in self.tested_endpoints:
                continue
            self.tested_endpoints.add(endpoint_key)

            # Check if this is a sensitive endpoint
            is_sensitive = self._is_sensitive_endpoint(url)

            # Analyze endpoint for replay protection
            vulnerabilities = await self._comprehensive_replay_analysis(
                url, method, headers, body, is_sensitive, test_replay, timestamp_window, context
            )

            # Convert to findings
            for vuln in vulnerabilities:
                finding = self._create_finding(vuln, context)
                findings.append(finding)

        # Add summary if no issues found
        if not findings:
            findings.append(self._create_no_issues_finding(target, len(endpoints), context))

        logger.info(f"Replay attack analysis complete. Found {len(findings)} findings")

        return findings

    def _is_sensitive_endpoint(self, url: str) -> bool:
        """Check if endpoint is sensitive and requires replay protection"""
        for pattern in SENSITIVE_ENDPOINTS:
            if pattern.search(url):
                return True
        return False

    def _analyze_response_protection(self, response: Dict, target: str) -> List[Dict]:
        """Analyze response for replay protection indicators"""
        findings = []
        headers = response.get('headers', {})
        request_headers = response.get('request_headers', {})
        endpoint = response.get('endpoint', target)
        method = response.get('method', 'POST')
        status_code = response.get('status_code', 200)

        # Analyze protection mechanisms
        protection = self._analyze_protection_mechanisms(headers, request_headers)

        # Check sensitive endpoints
        is_sensitive = self._is_sensitive_endpoint(endpoint)

        if is_sensitive and protection.protection_score < 50:
            vuln = ReplayVulnerability(
                vuln_type=ReplayVulnType.NO_NONCE if not protection.has_nonce else ReplayVulnType.NO_TIMESTAMP,
                risk_level=ReplayRiskLevel.HIGH,
                endpoint=endpoint,
                method=method,
                protection=protection,
                evidence=f"Protection score: {protection.protection_score}/100. Missing: " +
                         self._get_missing_protections(protection),
                confidence=0.8
            )
            findings.append(self._create_finding(vuln, {}))

        # Check for weak nonce
        if protection.has_nonce and protection.nonce_value:
            if self._is_weak_nonce(protection.nonce_value):
                vuln = ReplayVulnerability(
                    vuln_type=ReplayVulnType.WEAK_NONCE,
                    risk_level=ReplayRiskLevel.MEDIUM,
                    endpoint=endpoint,
                    method=method,
                    protection=protection,
                    evidence=f"Nonce appears weak or predictable: {protection.nonce_value[:20]}...",
                    confidence=0.7
                )
                findings.append(self._create_finding(vuln, {}))

        return findings

    def _analyze_protection_mechanisms(
        self,
        response_headers: Dict,
        request_headers: Dict
    ) -> ReplayProtection:
        """Analyze headers for replay protection mechanisms"""
        protection = ReplayProtection()
        all_headers = {**response_headers, **request_headers}
        headers_lower = {k.lower(): v for k, v in all_headers.items()}

        # Check for nonce
        for header in NONCE_HEADERS:
            if header.lower() in headers_lower:
                protection.has_nonce = True
                protection.nonce_value = str(headers_lower[header.lower()])
                break

        # Check for timestamp
        for header in TIMESTAMP_HEADERS:
            if header.lower() in headers_lower:
                protection.has_timestamp = True
                protection.timestamp_value = str(headers_lower[header.lower()])
                break

        # Check for signature
        for header in SIGNATURE_HEADERS:
            if header.lower() in headers_lower:
                value = str(headers_lower[header.lower()])
                signature_type = self._detect_signature_type(value)
                if signature_type:
                    protection.has_signature = True
                    protection.signature_type = signature_type
                    break

        # Check for idempotency key
        for header in IDEMPOTENCY_HEADERS:
            if header.lower() in headers_lower:
                protection.has_idempotency_key = True
                protection.idempotency_key = str(headers_lower[header.lower()])
                break

        # Check for request ID
        for header in REQUEST_ID_HEADERS:
            if header.lower() in headers_lower:
                protection.has_request_id = True
                break

        # Check for sequence number
        for header in SEQUENCE_HEADERS:
            if header.lower() in headers_lower:
                protection.has_sequence_number = True
                break

        # Calculate protection score
        protection.protection_score = self._calculate_protection_score(protection)

        return protection

    def _detect_signature_type(self, value: str) -> Optional[str]:
        """Detect the type of signature used"""
        for sig_type, pattern in SIGNATURE_PATTERNS.items():
            if pattern.search(value):
                return sig_type

        # Check for HMAC in authorization header
        if 'hmac' in value.lower():
            return 'hmac'
        if 'signature' in value.lower():
            return 'generic_signature'

        return None

    def _calculate_protection_score(self, protection: ReplayProtection) -> float:
        """Calculate overall replay protection score (0-100)"""
        score = 0.0

        # Nonce provides strong protection
        if protection.has_nonce:
            score += 30

        # Timestamp helps but needs nonce
        if protection.has_timestamp:
            score += 20

        # Signature with timestamp is excellent
        if protection.has_signature:
            score += 25

        # Idempotency key for mutations
        if protection.has_idempotency_key:
            score += 15

        # Request ID helps with tracking
        if protection.has_request_id:
            score += 5

        # Sequence number for ordered operations
        if protection.has_sequence_number:
            score += 5

        return min(score, 100)

    def _get_missing_protections(self, protection: ReplayProtection) -> str:
        """Get list of missing protection mechanisms"""
        missing = []
        if not protection.has_nonce:
            missing.append("nonce")
        if not protection.has_timestamp:
            missing.append("timestamp")
        if not protection.has_signature:
            missing.append("signature")
        if not protection.has_idempotency_key:
            missing.append("idempotency key")

        return ", ".join(missing) if missing else "none"

    def _is_weak_nonce(self, nonce: str) -> bool:
        """Check if nonce appears weak or predictable"""
        # Too short
        if len(nonce) < self.MIN_NONCE_LENGTH:
            return True

        # Check against weak patterns
        for pattern in WEAK_NONCE_PATTERNS:
            if pattern.match(nonce):
                return True

        # Check for low entropy (all same characters)
        if len(set(nonce)) < 4:
            return True

        return False

    async def _comprehensive_replay_analysis(
        self,
        url: str,
        method: str,
        headers: Dict,
        body: Dict,
        is_sensitive: bool,
        test_replay: bool,
        timestamp_window: int,
        context: Dict
    ) -> List[ReplayVulnerability]:
        """Perform comprehensive replay attack analysis"""
        vulnerabilities = []

        # Phase 1: Probe for protection mechanisms
        protection = await self._probe_protection_mechanisms(
            url, method, headers, body, context
        )

        # Phase 2: Analyze protection adequacy
        if is_sensitive:
            adequacy_vulns = self._analyze_protection_adequacy(
                url, method, protection, is_sensitive
            )
            vulnerabilities.extend(adequacy_vulns)

        # Phase 3: Test actual replay (if enabled)
        if test_replay and is_sensitive:
            replay_vulns = await self._test_replay_attacks(
                url, method, headers, body, protection, timestamp_window, context
            )
            vulnerabilities.extend(replay_vulns)

        # Phase 4: Check for nonce/timestamp issues
        if protection.has_nonce or protection.has_timestamp:
            crypto_vulns = self._analyze_crypto_protections(
                url, method, protection
            )
            vulnerabilities.extend(crypto_vulns)

        return vulnerabilities

    async def _probe_protection_mechanisms(
        self,
        url: str,
        method: str,
        headers: Dict,
        body: Dict,
        context: Dict
    ) -> ReplayProtection:
        """Probe endpoint to detect replay protection mechanisms"""
        try:
            async with safe_http_client(context.get('config', {})) as client:
                # Make initial request
                if method == 'GET':
                    response = await client.get(url, headers=headers)
                elif method == 'POST':
                    response = await client.post(url, headers=headers, json=body)
                else:
                    response = await client.request(method, url, headers=headers, json=body)

                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}

                # Analyze protection from response
                return self._analyze_protection_mechanisms(response_headers, headers)

        except Exception as e:
            logger.debug(f"Error probing protection mechanisms: {e}")
            return ReplayProtection()

    def _analyze_protection_adequacy(
        self,
        url: str,
        method: str,
        protection: ReplayProtection,
        is_sensitive: bool
    ) -> List[ReplayVulnerability]:
        """Analyze if protection mechanisms are adequate"""
        vulnerabilities = []

        if is_sensitive:
            # Sensitive endpoint without nonce
            if not protection.has_nonce:
                vuln = ReplayVulnerability(
                    vuln_type=ReplayVulnType.NO_NONCE,
                    risk_level=ReplayRiskLevel.HIGH,
                    endpoint=url,
                    method=method,
                    protection=protection,
                    evidence="Sensitive endpoint lacks nonce-based replay protection. Requests can be captured and replayed.",
                    confidence=0.9
                )
                vulnerabilities.append(vuln)

            # No timestamp validation
            if not protection.has_timestamp and not protection.has_nonce:
                vuln = ReplayVulnerability(
                    vuln_type=ReplayVulnType.NO_TIMESTAMP,
                    risk_level=ReplayRiskLevel.MEDIUM,
                    endpoint=url,
                    method=method,
                    protection=protection,
                    evidence="No timestamp validation detected. Old requests may be replayed indefinitely.",
                    confidence=0.8
                )
                vulnerabilities.append(vuln)

            # No signature for auth endpoints
            if not protection.has_signature and 'auth' in url.lower():
                vuln = ReplayVulnerability(
                    vuln_type=ReplayVulnType.NO_SIGNATURE,
                    risk_level=ReplayRiskLevel.MEDIUM,
                    endpoint=url,
                    method=method,
                    protection=protection,
                    evidence="Authentication endpoint lacks request signing. Captured requests can be replayed.",
                    confidence=0.7
                )
                vulnerabilities.append(vuln)

            # Financial endpoints without idempotency
            if any(x in url.lower() for x in ['payment', 'transfer', 'transaction']):
                if not protection.has_idempotency_key:
                    vuln = ReplayVulnerability(
                        vuln_type=ReplayVulnType.NO_IDEMPOTENCY,
                        risk_level=ReplayRiskLevel.HIGH,
                        endpoint=url,
                        method=method,
                        protection=protection,
                        evidence="Financial endpoint lacks idempotency protection. Transactions may be duplicated.",
                        confidence=0.85
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_replay_attacks(
        self,
        url: str,
        method: str,
        headers: Dict,
        body: Dict,
        protection: ReplayProtection,
        timestamp_window: int,
        context: Dict
    ) -> List[ReplayVulnerability]:
        """Test actual replay attack scenarios"""
        vulnerabilities = []

        try:
            async with safe_http_client(context.get('config', {})) as client:
                # Make original request
                if method == 'GET':
                    response1 = await client.get(url, headers=headers)
                elif method == 'POST':
                    response1 = await client.post(url, headers=headers, json=body)
                else:
                    response1 = await client.request(method, url, headers=headers, json=body)

                original_status = response1.status_code

                # Wait and replay
                await asyncio.sleep(self.request_delay)

                # Replay the same request
                if method == 'GET':
                    response2 = await client.get(url, headers=headers)
                elif method == 'POST':
                    response2 = await client.post(url, headers=headers, json=body)
                else:
                    response2 = await client.request(method, url, headers=headers, json=body)

                replay_status = response2.status_code

                # Analyze results
                test_result = ReplayTestResult(
                    test_type='immediate_replay',
                    original_request={'url': url, 'method': method},
                    replayed_request={'url': url, 'method': method},
                    original_response_code=original_status,
                    replay_response_code=replay_status,
                    replay_accepted=(200 <= replay_status < 400),
                    time_delay=self.request_delay,
                    response_similarity=1.0 if original_status == replay_status else 0.5,
                    evidence=f"Original: {original_status}, Replay: {replay_status}"
                )

                # Check if replay was accepted when it shouldn't be
                if test_result.replay_accepted and protection.protection_score < 50:
                    vuln = ReplayVulnerability(
                        vuln_type=ReplayVulnType.REQUEST_REPLAY,
                        risk_level=ReplayRiskLevel.HIGH,
                        endpoint=url,
                        method=method,
                        protection=protection,
                        test_result=test_result,
                        evidence=f"Request replay successful. Original status: {original_status}, Replay status: {replay_status}",
                        confidence=0.9
                    )
                    vulnerabilities.append(vuln)

                # Test delayed replay (if nonce/timestamp used)
                if protection.has_timestamp or protection.has_nonce:
                    delayed_vuln = await self._test_delayed_replay(
                        url, method, headers, body, protection, timestamp_window, context, client
                    )
                    if delayed_vuln:
                        vulnerabilities.append(delayed_vuln)

        except Exception as e:
            logger.debug(f"Error testing replay attacks: {e}")

        return vulnerabilities

    async def _test_delayed_replay(
        self,
        url: str,
        method: str,
        headers: Dict,
        body: Dict,
        protection: ReplayProtection,
        timestamp_window: int,
        context: Dict,
        client
    ) -> Optional[ReplayVulnerability]:
        """Test if old requests with expired timestamps are accepted"""
        try:
            # Modify timestamp header to be old
            test_headers = headers.copy()

            for header in TIMESTAMP_HEADERS:
                if header.lower() in [h.lower() for h in test_headers]:
                    # Set to old timestamp (beyond window)
                    old_time = int(time.time()) - timestamp_window - 60
                    for h in list(test_headers.keys()):
                        if h.lower() == header.lower():
                            test_headers[h] = str(old_time)
                            break
                    break

            # Try with old timestamp
            if method == 'GET':
                response = await client.get(url, headers=test_headers)
            elif method == 'POST':
                response = await client.post(url, headers=test_headers, json=body)
            else:
                response = await client.request(method, url, headers=test_headers, json=body)

            # If accepted with old timestamp, vulnerability exists
            if 200 <= response.status_code < 400:
                return ReplayVulnerability(
                    vuln_type=ReplayVulnType.EXPIRED_TIMESTAMP,
                    risk_level=ReplayRiskLevel.MEDIUM,
                    endpoint=url,
                    method=method,
                    protection=protection,
                    evidence=f"Request with expired timestamp ({timestamp_window + 60}s old) was accepted",
                    confidence=0.85
                )

        except Exception as e:
            logger.debug(f"Error testing delayed replay: {e}")

        return None

    def _analyze_crypto_protections(
        self,
        url: str,
        method: str,
        protection: ReplayProtection
    ) -> List[ReplayVulnerability]:
        """Analyze cryptographic protection implementations"""
        vulnerabilities = []

        # Check weak nonce
        if protection.has_nonce and protection.nonce_value:
            if self._is_weak_nonce(protection.nonce_value):
                vuln = ReplayVulnerability(
                    vuln_type=ReplayVulnType.WEAK_NONCE,
                    risk_level=ReplayRiskLevel.MEDIUM,
                    endpoint=url,
                    method=method,
                    protection=protection,
                    evidence=f"Nonce appears weak: length={len(protection.nonce_value)}, pattern appears predictable",
                    confidence=0.7
                )
                vulnerabilities.append(vuln)

        # Check weak signature
        if protection.has_signature:
            if protection.signature_type in ['hmac_md5']:
                vuln = ReplayVulnerability(
                    vuln_type=ReplayVulnType.NO_SIGNATURE,
                    risk_level=ReplayRiskLevel.LOW,
                    endpoint=url,
                    method=method,
                    protection=protection,
                    evidence=f"Using weak signature algorithm: {protection.signature_type}. Consider SHA-256 or stronger.",
                    confidence=0.6
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _create_finding(
        self,
        vuln: ReplayVulnerability,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding dictionary from vulnerability"""
        cwe_info = REPLAY_CWE_MAPPINGS.get(
            vuln.vuln_type,
            REPLAY_CWE_MAPPINGS[ReplayVulnType.NO_NONCE]
        )

        # Adjust CVSS based on endpoint sensitivity
        cvss_base = cwe_info['cvss_base']
        if self._is_sensitive_endpoint(vuln.endpoint):
            cvss_base = min(cvss_base + 1.0, 10.0)

        # Build evidence
        evidence_parts = [vuln.evidence]
        evidence_parts.append(f"Protection score: {vuln.protection.protection_score}/100")

        if vuln.test_result:
            evidence_parts.append(
                f"Replay test: Original={vuln.test_result.original_response_code}, "
                f"Replay={vuln.test_result.replay_response_code}, "
                f"Accepted={vuln.test_result.replay_accepted}"
            )

        # Create fingerprint
        fingerprint_data = f"{vuln.endpoint}:{vuln.method}:{vuln.vuln_type.value}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        # Severity mapping
        severity_map = {
            ReplayRiskLevel.CRITICAL: 'critical',
            ReplayRiskLevel.HIGH: 'high',
            ReplayRiskLevel.MEDIUM: 'medium',
            ReplayRiskLevel.LOW: 'low',
            ReplayRiskLevel.INFO: 'info'
        }

        # Get recommendations
        recommendations = self._get_recommendations(vuln.vuln_type)

        return {
            'issue': self._get_issue_title(vuln.vuln_type),
            'description': self._get_issue_description(vuln.vuln_type, vuln),
            'severity': severity_map[vuln.risk_level],
            'category': 'Replay Attack',
            'endpoint': vuln.endpoint,
            'method': vuln.method,
            'evidence': '\n'.join(evidence_parts),
            'cwe_id': cwe_info['id'],
            'cwe_name': cwe_info['name'],
            'cvss_score': round(cvss_base, 1),
            'recommendation': '\n'.join([f"• {r}" for r in recommendations]),
            'vulnerability_type': vuln.vuln_type.value,
            'protection_score': vuln.protection.protection_score,
            'has_nonce': vuln.protection.has_nonce,
            'has_timestamp': vuln.protection.has_timestamp,
            'has_signature': vuln.protection.has_signature,
            'confidence': round(vuln.confidence * 100, 1),
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def _get_issue_title(self, vuln_type: ReplayVulnType) -> str:
        """Get human-readable title for vulnerability type"""
        titles = {
            ReplayVulnType.NO_NONCE: 'Missing Nonce Protection',
            ReplayVulnType.WEAK_NONCE: 'Weak Nonce Implementation',
            ReplayVulnType.NO_TIMESTAMP: 'Missing Timestamp Validation',
            ReplayVulnType.EXPIRED_TIMESTAMP: 'Expired Timestamp Accepted',
            ReplayVulnType.NO_SIGNATURE: 'Missing Request Signature',
            ReplayVulnType.SIGNATURE_REUSE: 'Signature Reuse Detected',
            ReplayVulnType.TOKEN_REUSE: 'Token Replay Possible',
            ReplayVulnType.SESSION_FIXATION: 'Session Fixation Possible',
            ReplayVulnType.NO_IDEMPOTENCY: 'Missing Idempotency Protection',
            ReplayVulnType.REQUEST_REPLAY: 'Request Replay Vulnerability'
        }
        return titles.get(vuln_type, 'Replay Vulnerability Detected')

    def _get_issue_description(self, vuln_type: ReplayVulnType, vuln: ReplayVulnerability) -> str:
        """Get detailed description for the vulnerability"""
        descriptions = {
            ReplayVulnType.NO_NONCE: "The endpoint lacks nonce-based replay protection. Attackers can capture legitimate requests and replay them to perform unauthorized actions. Nonces ensure each request is unique and cannot be reused.",
            ReplayVulnType.WEAK_NONCE: "The nonce implementation appears weak or predictable. Attackers may be able to guess or predict future nonce values, bypassing replay protection. Nonces should be cryptographically random and sufficiently long.",
            ReplayVulnType.NO_TIMESTAMP: "The endpoint does not validate request timestamps. Without timestamp validation, captured requests can be replayed indefinitely. Timestamps should be included and validated within a reasonable time window.",
            ReplayVulnType.EXPIRED_TIMESTAMP: "The endpoint accepts requests with expired timestamps beyond the expected validation window. This allows attackers to replay old captured requests. Implement strict timestamp validation.",
            ReplayVulnType.NO_SIGNATURE: "Authentication requests lack cryptographic signatures. Without request signing, attackers can capture and replay requests without modification detection. Implement HMAC or similar signing.",
            ReplayVulnType.SIGNATURE_REUSE: "The same signature can be reused across multiple requests. Each request should have a unique signature based on nonce and timestamp to prevent replay attacks.",
            ReplayVulnType.TOKEN_REUSE: "Authentication tokens can be replayed to gain unauthorized access. Implement token binding or one-time use tokens for sensitive operations.",
            ReplayVulnType.SESSION_FIXATION: "Sessions can be fixed or replayed by attackers. Regenerate session identifiers after authentication and implement proper session management.",
            ReplayVulnType.NO_IDEMPOTENCY: "Financial or sensitive operations lack idempotency protection. Without idempotency keys, replay attacks could cause duplicate transactions or actions.",
            ReplayVulnType.REQUEST_REPLAY: "Complete request replay is possible. An attacker who captures a valid request can replay it to repeat the action. Implement comprehensive replay protection using nonces, timestamps, and signatures."
        }
        return descriptions.get(vuln_type, "A replay vulnerability was detected that could allow attackers to reuse captured requests.")

    def _get_recommendations(self, vuln_type: ReplayVulnType) -> List[str]:
        """Get recommendations for fixing the vulnerability"""
        recommendations = {
            ReplayVulnType.NO_NONCE: [
                "Implement cryptographically secure nonce generation (minimum 16 bytes)",
                "Require nonce in all sensitive API requests",
                "Store used nonces server-side to prevent reuse",
                "Set appropriate nonce expiration (5-15 minutes)",
                "Include nonce in request signature calculation"
            ],
            ReplayVulnType.WEAK_NONCE: [
                "Use cryptographically secure random number generator",
                "Increase nonce length to at least 128 bits (16 bytes)",
                "Avoid timestamp-only or sequential nonces",
                "Consider using UUID v4 or similar random identifiers",
                "Combine multiple entropy sources for nonce generation"
            ],
            ReplayVulnType.NO_TIMESTAMP: [
                "Include timestamp in all API requests",
                "Validate timestamp is within acceptable window (5 minutes recommended)",
                "Reject requests with future timestamps",
                "Use UTC timestamps to avoid timezone issues",
                "Combine timestamp with nonce for stronger protection"
            ],
            ReplayVulnType.EXPIRED_TIMESTAMP: [
                "Implement strict timestamp validation window (5 minutes max)",
                "Reject all requests outside the time window",
                "Account for clock skew between client and server",
                "Log rejected timestamp violations for monitoring",
                "Consider using NTP to synchronize server time"
            ],
            ReplayVulnType.NO_SIGNATURE: [
                "Implement HMAC-SHA256 request signing",
                "Include all request parameters in signature calculation",
                "Sign timestamp and nonce along with payload",
                "Use per-user or per-session signing keys",
                "Rotate signing keys periodically"
            ],
            ReplayVulnType.SIGNATURE_REUSE: [
                "Include nonce in signature calculation",
                "Include timestamp in signature calculation",
                "Reject duplicate signatures within time window",
                "Use unique signature per request",
                "Implement signature verification caching"
            ],
            ReplayVulnType.TOKEN_REUSE: [
                "Implement one-time use tokens for sensitive operations",
                "Bind tokens to client fingerprint or session",
                "Set short token expiration times",
                "Implement token revocation mechanism",
                "Use refresh token rotation"
            ],
            ReplayVulnType.SESSION_FIXATION: [
                "Regenerate session ID after successful authentication",
                "Invalidate old sessions on login",
                "Bind sessions to client characteristics",
                "Implement secure session cookie attributes",
                "Use short session timeouts for sensitive operations"
            ],
            ReplayVulnType.NO_IDEMPOTENCY: [
                "Require idempotency keys for all mutation operations",
                "Store idempotency keys with request results",
                "Return cached response for duplicate idempotency keys",
                "Set appropriate idempotency key expiration",
                "Document idempotency requirements in API specs"
            ],
            ReplayVulnType.REQUEST_REPLAY: [
                "Implement comprehensive replay protection using nonce + timestamp + signature",
                "Store and check all nonces server-side",
                "Use short validity windows (5 minutes)",
                "Implement request signing for all sensitive endpoints",
                "Monitor and alert on replay attempts"
            ]
        }
        return recommendations.get(vuln_type, recommendations[ReplayVulnType.NO_NONCE])

    def _create_no_issues_finding(
        self,
        target: str,
        endpoint_count: int,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding when no issues are detected"""
        fingerprint = hashlib.sha256(f"replay_scan_complete:{target}".encode()).hexdigest()[:16]

        return {
            'issue': 'Replay Attack Assessment Complete',
            'description': f"Replay attack vulnerability assessment completed for {endpoint_count} endpoint(s). The API appears to implement adequate replay protection mechanisms including nonces, timestamps, and/or request signatures.",
            'severity': 'info',
            'category': 'Replay Attack',
            'endpoint': target,
            'method': 'GET',
            'evidence': f"Analyzed {endpoint_count} endpoint(s) for replay vulnerabilities. Tests included: nonce detection, timestamp validation, signature analysis, and actual replay testing.",
            'cwe_id': 'N/A',
            'cwe_name': 'No Vulnerabilities Detected',
            'cvss_score': 0.0,
            'recommendation': '• Continue monitoring replay protection effectiveness\n• Regularly rotate signing keys\n• Review nonce storage and cleanup policies\n• Test replay protection after API changes',
            'vulnerability_type': 'assessment_complete',
            'endpoints_tested': endpoint_count,
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Generate a summary of replay analysis"""
        return {
            'endpoints_tested': len(self.tested_endpoints),
            'nonces_captured': sum(len(v) for v in self.captured_nonces.values()),
            'signatures_captured': sum(len(v) for v in self.captured_signatures.values()),
            'protection_mechanisms_checked': [
                'Nonce headers',
                'Timestamp headers',
                'Request signatures (HMAC, OAuth)',
                'Idempotency keys',
                'Request IDs',
                'Sequence numbers'
            ],
            'test_scenarios': [
                'Immediate replay',
                'Delayed replay',
                'Expired timestamp replay',
                'Signature reuse',
                'Nonce prediction'
            ]
        }
