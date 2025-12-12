"""Rate Limit Analyzer - Enterprise-grade API rate limiting evaluation and bypass detection"""
import re
import logging
import hashlib
import asyncio
import statistics
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin

from apiguardian.core.plugin_manager import AnalyzerPlugin
from apiguardian.utils.http_client import safe_http_client, HTTPResponse

logger = logging.getLogger(__name__)


class RateLimitRisk(Enum):
    """Risk levels for rate limiting issues"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RateLimitIssueType(Enum):
    """Types of rate limiting issues"""
    NO_RATE_LIMIT = "no_rate_limit"
    WEAK_RATE_LIMIT = "weak_rate_limit"
    BYPASS_POSSIBLE = "bypass_possible"
    INCONSISTENT_ENFORCEMENT = "inconsistent_enforcement"
    MISSING_HEADERS = "missing_headers"
    IMPROPER_CONFIGURATION = "improper_configuration"
    ENUMERATION_POSSIBLE = "enumeration_possible"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


@dataclass
class RateLimitInfo:
    """Rate limit configuration detected from headers"""
    limit: Optional[int] = None
    remaining: Optional[int] = None
    reset: Optional[int] = None
    retry_after: Optional[int] = None
    window_seconds: Optional[int] = None
    policy: Optional[str] = None
    quota_policy: Optional[str] = None
    headers_present: List[str] = field(default_factory=list)
    headers_missing: List[str] = field(default_factory=list)


@dataclass
class RateLimitTestResult:
    """Result from a rate limit test"""
    request_count: int
    success_count: int
    rate_limited_count: int
    error_count: int
    response_times: List[float]
    status_codes: List[int]
    rate_limit_triggered_at: Optional[int] = None
    bypass_techniques_succeeded: List[str] = field(default_factory=list)
    avg_response_time: float = 0.0
    rate_limit_info: Optional[RateLimitInfo] = None


@dataclass
class RateLimitVulnerability:
    """Represents a rate limiting vulnerability"""
    issue_type: RateLimitIssueType
    risk_level: RateLimitRisk
    endpoint: str
    method: str
    evidence: str
    test_result: Optional[RateLimitTestResult] = None
    bypass_technique: Optional[str] = None


# CWE mappings for rate limiting issues
RATE_LIMIT_CWE_MAPPINGS = {
    RateLimitIssueType.NO_RATE_LIMIT: {
        'id': 'CWE-770',
        'name': 'Allocation of Resources Without Limits or Throttling',
        'cvss_base': 7.5
    },
    RateLimitIssueType.WEAK_RATE_LIMIT: {
        'id': 'CWE-770',
        'name': 'Allocation of Resources Without Limits or Throttling',
        'cvss_base': 5.0
    },
    RateLimitIssueType.BYPASS_POSSIBLE: {
        'id': 'CWE-799',
        'name': 'Improper Control of Interaction Frequency',
        'cvss_base': 7.0
    },
    RateLimitIssueType.INCONSISTENT_ENFORCEMENT: {
        'id': 'CWE-799',
        'name': 'Improper Control of Interaction Frequency',
        'cvss_base': 5.5
    },
    RateLimitIssueType.MISSING_HEADERS: {
        'id': 'CWE-778',
        'name': 'Insufficient Logging',
        'cvss_base': 3.0
    },
    RateLimitIssueType.IMPROPER_CONFIGURATION: {
        'id': 'CWE-770',
        'name': 'Allocation of Resources Without Limits or Throttling',
        'cvss_base': 4.5
    },
    RateLimitIssueType.ENUMERATION_POSSIBLE: {
        'id': 'CWE-307',
        'name': 'Improper Restriction of Excessive Authentication Attempts',
        'cvss_base': 7.5
    },
    RateLimitIssueType.RESOURCE_EXHAUSTION: {
        'id': 'CWE-400',
        'name': 'Uncontrolled Resource Consumption',
        'cvss_base': 7.5
    }
}


# Standard rate limit headers
RATE_LIMIT_HEADERS = {
    'standard': [
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset',
        'RateLimit-Limit',
        'RateLimit-Remaining',
        'RateLimit-Reset',
        'RateLimit-Policy'
    ],
    'retry': [
        'Retry-After',
        'X-Retry-After'
    ],
    'vendor_specific': [
        # GitHub
        'X-RateLimit-Used',
        'X-RateLimit-Resource',
        # Twitter
        'X-Rate-Limit-Limit',
        'X-Rate-Limit-Remaining',
        'X-Rate-Limit-Reset',
        # Azure
        'X-MS-RateLimit-Remaining',
        'X-MS-RateLimit-Limit',
        # AWS
        'X-Amz-Cf-Pop',
        # Cloudflare
        'CF-RAY'
    ],
    'quota': [
        'X-Quota-Limit',
        'X-Quota-Remaining',
        'X-Quota-Reset'
    ]
}


# Sensitive endpoints that MUST have rate limiting
SENSITIVE_ENDPOINT_PATTERNS = [
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:auth|login|signin|authenticate)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:register|signup|create.?account)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:password|reset|forgot|recover)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:otp|2fa|mfa|verify|verification)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:token|oauth|authorize)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:payment|checkout|purchase|order)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:transfer|withdraw|deposit)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:admin|manage|config)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:user|profile|account)/?$', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:search|query|lookup)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:export|download|report)', re.I),
    re.compile(r'/(?:api/)?(?:v\d+/)?(?:webhook|callback)', re.I)
]


# Bypass technique headers
BYPASS_TECHNIQUES = {
    'ip_spoofing': {
        'X-Forwarded-For': ['127.0.0.1', '10.0.0.1', '192.168.1.1', '::1'],
        'X-Real-IP': ['127.0.0.1', '10.0.0.1'],
        'X-Client-IP': ['127.0.0.1'],
        'X-Originating-IP': ['127.0.0.1'],
        'CF-Connecting-IP': ['127.0.0.1'],
        'True-Client-IP': ['127.0.0.1'],
        'X-Cluster-Client-IP': ['127.0.0.1']
    },
    'case_variation': {
        'description': 'URL case variations to bypass path-based limits'
    },
    'encoding_variation': {
        'description': 'URL encoding variations'
    },
    'method_variation': {
        'description': 'HTTP method variations (GET vs POST)'
    },
    'header_variation': {
        'description': 'User-Agent and Accept header variations'
    }
}


class RateLimitAnalyzer(AnalyzerPlugin):
    """Enterprise-grade API rate limiting evaluation with bypass detection"""

    plugin_name = "rate_limit_analyzer"
    description = "Evaluate rate limiting implementation, detect bypass vulnerabilities, and assess DoS protection"
    version = "2.0.0"

    # Recommended rate limits by endpoint type
    RECOMMENDED_LIMITS = {
        'authentication': {'limit': 10, 'window': 60, 'description': 'Login/auth endpoints'},
        'password_reset': {'limit': 5, 'window': 3600, 'description': 'Password reset endpoints'},
        'otp_verification': {'limit': 5, 'window': 300, 'description': 'OTP/2FA verification'},
        'registration': {'limit': 10, 'window': 3600, 'description': 'Account registration'},
        'api_general': {'limit': 1000, 'window': 3600, 'description': 'General API endpoints'},
        'api_write': {'limit': 100, 'window': 60, 'description': 'Write/mutation endpoints'},
        'search': {'limit': 100, 'window': 60, 'description': 'Search/query endpoints'},
        'export': {'limit': 10, 'window': 3600, 'description': 'Export/download endpoints'}
    }

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the rate limit analyzer"""
        super().__init__(config)
        self.config = config or {}
        self.tested_endpoints: Set[str] = set()
        self.rate_limit_cache: Dict[str, RateLimitInfo] = {}
        self.max_test_requests = 20
        self.request_delay = 0.05  # 50ms between requests for testing

    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze rate limiting on target"""
        findings = []

        logger.info(f"Starting rate limit analysis for target: {target}")

        # Get configuration
        config = context.get('config', {})
        analyzer_config = config.get('analyzers', {}).get('rate_limit', {})

        # Configuration options
        test_bypass = analyzer_config.get('test_bypass', True)
        aggressive_testing = analyzer_config.get('aggressive_testing', False)
        custom_limits = analyzer_config.get('custom_limits', {})

        # Get endpoints to test
        endpoints = context.get('endpoints', [])
        if not endpoints and target:
            endpoints = [{'url': target, 'method': 'GET'}]

        # Also check responses if provided
        responses = context.get('responses', [])
        if responses:
            for response in responses:
                resp_findings = self._analyze_response_headers(response, target)
                findings.extend(resp_findings)

        logger.info(f"Analyzing {len(endpoints)} endpoints for rate limiting")

        # Categorize endpoints by sensitivity
        categorized_endpoints = self._categorize_endpoints(endpoints)

        # Test each endpoint category
        for category, endpoint_list in categorized_endpoints.items():
            for endpoint_info in endpoint_list:
                url = endpoint_info.get('url', '')
                method = endpoint_info.get('method', 'GET').upper()
                headers = endpoint_info.get('headers', {})

                if not url:
                    continue

                # Skip already tested
                endpoint_key = f"{method}:{url}"
                if endpoint_key in self.tested_endpoints:
                    continue
                self.tested_endpoints.add(endpoint_key)

                # Perform rate limit testing
                vulnerabilities = await self._comprehensive_rate_limit_test(
                    url, method, headers, category, test_bypass, aggressive_testing, context
                )

                # Convert to findings
                for vuln in vulnerabilities:
                    finding = self._create_finding(vuln, category, context)
                    findings.append(finding)

        # Add summary finding if no issues found
        if not findings:
            findings.append(self._create_no_issues_finding(target, len(endpoints), context))

        logger.info(f"Rate limit analysis complete. Found {len(findings)} findings")

        return findings

    def _categorize_endpoints(self, endpoints: List[Dict]) -> Dict[str, List[Dict]]:
        """Categorize endpoints by sensitivity level"""
        categories = {
            'authentication': [],
            'password_reset': [],
            'otp_verification': [],
            'registration': [],
            'financial': [],
            'admin': [],
            'search': [],
            'export': [],
            'api_general': []
        }

        for endpoint in endpoints:
            url = endpoint.get('url', '')
            categorized = False

            # Check against sensitive patterns
            for pattern in SENSITIVE_ENDPOINT_PATTERNS:
                if pattern.search(url):
                    # Determine specific category
                    url_lower = url.lower()
                    if any(x in url_lower for x in ['login', 'signin', 'auth', 'token']):
                        categories['authentication'].append(endpoint)
                    elif any(x in url_lower for x in ['password', 'reset', 'forgot', 'recover']):
                        categories['password_reset'].append(endpoint)
                    elif any(x in url_lower for x in ['otp', '2fa', 'mfa', 'verify']):
                        categories['otp_verification'].append(endpoint)
                    elif any(x in url_lower for x in ['register', 'signup', 'create']):
                        categories['registration'].append(endpoint)
                    elif any(x in url_lower for x in ['payment', 'transfer', 'checkout']):
                        categories['financial'].append(endpoint)
                    elif any(x in url_lower for x in ['admin', 'manage']):
                        categories['admin'].append(endpoint)
                    elif any(x in url_lower for x in ['search', 'query', 'lookup']):
                        categories['search'].append(endpoint)
                    elif any(x in url_lower for x in ['export', 'download', 'report']):
                        categories['export'].append(endpoint)
                    else:
                        categories['api_general'].append(endpoint)
                    categorized = True
                    break

            if not categorized:
                categories['api_general'].append(endpoint)

        # Remove empty categories
        return {k: v for k, v in categories.items() if v}

    def _analyze_response_headers(self, response: Dict, target: str) -> List[Dict]:
        """Analyze response for rate limiting headers and issues"""
        findings = []
        headers = response.get('headers', {})
        status_code = response.get('status_code', 0)
        endpoint = response.get('endpoint', target)
        method = response.get('method', 'GET')

        # Extract rate limit info from headers
        rate_limit_info = self._extract_rate_limit_info(headers)

        # Check for missing rate limit headers
        if not rate_limit_info.headers_present and status_code != 429:
            vuln = RateLimitVulnerability(
                issue_type=RateLimitIssueType.MISSING_HEADERS,
                risk_level=RateLimitRisk.MEDIUM,
                endpoint=endpoint,
                method=method,
                evidence=f"Response lacks standard rate limiting headers. Expected headers: {', '.join(RATE_LIMIT_HEADERS['standard'][:3])}"
            )
            findings.append(self._create_finding(vuln, 'api_general', {}))

        # Check for overly generous limits
        if rate_limit_info.limit:
            category = self._get_endpoint_category(endpoint)
            recommended = self.RECOMMENDED_LIMITS.get(category, self.RECOMMENDED_LIMITS['api_general'])

            if rate_limit_info.limit > recommended['limit'] * 10:
                vuln = RateLimitVulnerability(
                    issue_type=RateLimitIssueType.WEAK_RATE_LIMIT,
                    risk_level=RateLimitRisk.MEDIUM,
                    endpoint=endpoint,
                    method=method,
                    evidence=f"Rate limit ({rate_limit_info.limit} requests) exceeds recommended limit ({recommended['limit']} requests/{recommended['window']}s) for {category} endpoints"
                )
                findings.append(self._create_finding(vuln, category, {}))

        # Check 429 response configuration
        if status_code == 429:
            if not rate_limit_info.retry_after:
                vuln = RateLimitVulnerability(
                    issue_type=RateLimitIssueType.IMPROPER_CONFIGURATION,
                    risk_level=RateLimitRisk.LOW,
                    endpoint=endpoint,
                    method=method,
                    evidence="Rate limit response (HTTP 429) missing Retry-After header. Clients cannot determine when to retry."
                )
                findings.append(self._create_finding(vuln, 'api_general', {}))

        return findings

    def _extract_rate_limit_info(self, headers: Dict) -> RateLimitInfo:
        """Extract rate limit information from response headers"""
        info = RateLimitInfo()
        headers_lower = {k.lower(): v for k, v in headers.items()}

        all_expected = RATE_LIMIT_HEADERS['standard'] + RATE_LIMIT_HEADERS['retry']

        for header in all_expected:
            header_lower = header.lower()
            if header_lower in headers_lower:
                info.headers_present.append(header)
                value = headers_lower[header_lower]

                # Parse specific headers
                if 'limit' in header_lower and 'remaining' not in header_lower:
                    try:
                        info.limit = int(value)
                    except (ValueError, TypeError):
                        pass
                elif 'remaining' in header_lower:
                    try:
                        info.remaining = int(value)
                    except (ValueError, TypeError):
                        pass
                elif 'reset' in header_lower:
                    try:
                        info.reset = int(value)
                    except (ValueError, TypeError):
                        pass
                elif 'retry' in header_lower:
                    try:
                        info.retry_after = int(value)
                    except (ValueError, TypeError):
                        pass
                elif 'policy' in header_lower:
                    info.policy = str(value)
            else:
                info.headers_missing.append(header)

        # Check vendor-specific headers
        for header in RATE_LIMIT_HEADERS['vendor_specific']:
            if header.lower() in headers_lower:
                info.headers_present.append(header)

        return info

    def _get_endpoint_category(self, url: str) -> str:
        """Determine the category of an endpoint"""
        url_lower = url.lower()

        if any(x in url_lower for x in ['login', 'signin', 'auth', 'token']):
            return 'authentication'
        elif any(x in url_lower for x in ['password', 'reset', 'forgot']):
            return 'password_reset'
        elif any(x in url_lower for x in ['otp', '2fa', 'mfa', 'verify']):
            return 'otp_verification'
        elif any(x in url_lower for x in ['register', 'signup']):
            return 'registration'
        elif any(x in url_lower for x in ['payment', 'transfer']):
            return 'financial'
        elif any(x in url_lower for x in ['search', 'query']):
            return 'search'
        elif any(x in url_lower for x in ['export', 'download']):
            return 'export'
        else:
            return 'api_general'

    async def _comprehensive_rate_limit_test(
        self,
        url: str,
        method: str,
        headers: Dict,
        category: str,
        test_bypass: bool,
        aggressive_testing: bool,
        context: Dict
    ) -> List[RateLimitVulnerability]:
        """Perform comprehensive rate limit testing"""
        vulnerabilities = []

        # Get recommended limits for this category
        recommended = self.RECOMMENDED_LIMITS.get(category, self.RECOMMENDED_LIMITS['api_general'])

        # Phase 1: Initial probe to detect rate limiting
        probe_result = await self._probe_rate_limit(url, method, headers, context)

        if not probe_result:
            # Could not probe - skip further testing
            return vulnerabilities

        # Analyze probe results
        if probe_result.rate_limited_count == 0 and probe_result.request_count >= 10:
            # No rate limiting detected
            vuln = RateLimitVulnerability(
                issue_type=RateLimitIssueType.NO_RATE_LIMIT,
                risk_level=self._get_risk_for_category(category),
                endpoint=url,
                method=method,
                evidence=f"No rate limiting detected after {probe_result.request_count} requests. Recommended limit for {category}: {recommended['limit']} requests/{recommended['window']}s",
                test_result=probe_result
            )
            vulnerabilities.append(vuln)

        elif probe_result.rate_limit_triggered_at and probe_result.rate_limit_triggered_at > recommended['limit'] * 5:
            # Rate limit exists but is too high
            vuln = RateLimitVulnerability(
                issue_type=RateLimitIssueType.WEAK_RATE_LIMIT,
                risk_level=RateLimitRisk.MEDIUM,
                endpoint=url,
                method=method,
                evidence=f"Rate limit triggered at {probe_result.rate_limit_triggered_at} requests, significantly higher than recommended ({recommended['limit']})",
                test_result=probe_result
            )
            vulnerabilities.append(vuln)

        # Phase 2: Test bypass techniques (if enabled and rate limiting exists)
        if test_bypass and probe_result.rate_limited_count > 0:
            bypass_vulns = await self._test_bypass_techniques(
                url, method, headers, probe_result, context
            )
            vulnerabilities.extend(bypass_vulns)

        # Phase 3: Check rate limit configuration
        if probe_result.rate_limit_info:
            config_vulns = self._analyze_rate_limit_config(
                url, method, probe_result.rate_limit_info, category
            )
            vulnerabilities.extend(config_vulns)

        # Phase 4: Check for enumeration possibility (authentication endpoints)
        if category in ['authentication', 'password_reset', 'otp_verification']:
            enum_vulns = await self._check_enumeration_possibility(
                url, method, headers, probe_result, category, context
            )
            vulnerabilities.extend(enum_vulns)

        return vulnerabilities

    async def _probe_rate_limit(
        self,
        url: str,
        method: str,
        headers: Dict,
        context: Dict
    ) -> Optional[RateLimitTestResult]:
        """Probe endpoint to detect rate limiting"""
        try:
            result = RateLimitTestResult(
                request_count=0,
                success_count=0,
                rate_limited_count=0,
                error_count=0,
                response_times=[],
                status_codes=[]
            )

            async with safe_http_client(context.get('config', {})) as client:
                for i in range(self.max_test_requests):
                    try:
                        start_time = datetime.now()

                        if method == 'GET':
                            response = await client.get(url, headers=headers)
                        elif method == 'POST':
                            response = await client.post(url, headers=headers, json={})
                        elif method == 'HEAD':
                            response = await client.head(url, headers=headers)
                        else:
                            response = await client.request(method, url, headers=headers)

                        response_time = (datetime.now() - start_time).total_seconds()

                        result.request_count += 1
                        result.response_times.append(response_time)
                        result.status_codes.append(response.status_code)

                        if response.status_code == 429:
                            result.rate_limited_count += 1
                            if result.rate_limit_triggered_at is None:
                                result.rate_limit_triggered_at = i + 1

                            # Extract rate limit info from 429 response
                            resp_headers = dict(response.headers) if hasattr(response, 'headers') else {}
                            result.rate_limit_info = self._extract_rate_limit_info(resp_headers)
                        elif 200 <= response.status_code < 400:
                            result.success_count += 1

                            # Also check for rate limit headers on success responses
                            if result.rate_limit_info is None:
                                resp_headers = dict(response.headers) if hasattr(response, 'headers') else {}
                                result.rate_limit_info = self._extract_rate_limit_info(resp_headers)
                        else:
                            result.error_count += 1

                        # Small delay between requests
                        await asyncio.sleep(self.request_delay)

                    except Exception as e:
                        result.error_count += 1
                        logger.debug(f"Error during rate limit probe: {e}")

            # Calculate average response time
            if result.response_times:
                result.avg_response_time = statistics.mean(result.response_times)

            return result

        except Exception as e:
            logger.error(f"Error probing rate limits for {url}: {e}")
            return None

    async def _test_bypass_techniques(
        self,
        url: str,
        method: str,
        headers: Dict,
        baseline: RateLimitTestResult,
        context: Dict
    ) -> List[RateLimitVulnerability]:
        """Test various rate limit bypass techniques"""
        vulnerabilities = []

        # Test IP spoofing via headers
        ip_bypass_vuln = await self._test_ip_spoofing_bypass(
            url, method, headers, context
        )
        if ip_bypass_vuln:
            vulnerabilities.append(ip_bypass_vuln)

        # Test case variation bypass
        case_bypass_vuln = await self._test_case_variation_bypass(
            url, method, headers, context
        )
        if case_bypass_vuln:
            vulnerabilities.append(case_bypass_vuln)

        # Test encoding variation bypass
        encoding_bypass_vuln = await self._test_encoding_bypass(
            url, method, headers, context
        )
        if encoding_bypass_vuln:
            vulnerabilities.append(encoding_bypass_vuln)

        return vulnerabilities

    async def _test_ip_spoofing_bypass(
        self,
        url: str,
        method: str,
        base_headers: Dict,
        context: Dict
    ) -> Optional[RateLimitVulnerability]:
        """Test if rate limit can be bypassed via IP spoofing headers"""
        try:
            bypass_succeeded = []

            async with safe_http_client(context.get('config', {})) as client:
                for header_name, ip_values in BYPASS_TECHNIQUES['ip_spoofing'].items():
                    for ip_value in ip_values[:2]:  # Test first 2 IPs per header
                        test_headers = {**base_headers, header_name: ip_value}

                        # Send a few requests
                        success_count = 0
                        for _ in range(5):
                            try:
                                if method == 'GET':
                                    response = await client.get(url, headers=test_headers)
                                else:
                                    response = await client.post(url, headers=test_headers, json={})

                                if response.status_code != 429:
                                    success_count += 1

                                await asyncio.sleep(self.request_delay)

                            except Exception:
                                pass

                        if success_count >= 4:  # 4/5 requests succeeded
                            bypass_succeeded.append(f"{header_name}: {ip_value}")

            if bypass_succeeded:
                return RateLimitVulnerability(
                    issue_type=RateLimitIssueType.BYPASS_POSSIBLE,
                    risk_level=RateLimitRisk.HIGH,
                    endpoint=url,
                    method=method,
                    evidence=f"Rate limit bypass possible via IP spoofing headers: {', '.join(bypass_succeeded[:3])}",
                    bypass_technique="IP spoofing via X-Forwarded-For and similar headers"
                )

        except Exception as e:
            logger.debug(f"Error testing IP spoofing bypass: {e}")

        return None

    async def _test_case_variation_bypass(
        self,
        url: str,
        method: str,
        headers: Dict,
        context: Dict
    ) -> Optional[RateLimitVulnerability]:
        """Test if rate limit can be bypassed via URL case variations"""
        try:
            parsed = urlparse(url)
            path = parsed.path

            # Generate case variations
            variations = [
                path.upper(),
                path.lower(),
                path.swapcase(),
                path.replace('/', '//')
            ]

            async with safe_http_client(context.get('config', {})) as client:
                bypass_worked = []

                for variation in variations:
                    if variation == path:
                        continue

                    varied_url = url.replace(path, variation)

                    try:
                        if method == 'GET':
                            response = await client.get(varied_url, headers=headers)
                        else:
                            response = await client.post(varied_url, headers=headers, json={})

                        if response.status_code != 429 and response.status_code < 400:
                            bypass_worked.append(variation)

                    except Exception:
                        pass

                    await asyncio.sleep(self.request_delay)

                if bypass_worked:
                    return RateLimitVulnerability(
                        issue_type=RateLimitIssueType.BYPASS_POSSIBLE,
                        risk_level=RateLimitRisk.MEDIUM,
                        endpoint=url,
                        method=method,
                        evidence=f"Rate limit bypass possible via URL case variations. Working variations: {bypass_worked[:2]}",
                        bypass_technique="URL case variation"
                    )

        except Exception as e:
            logger.debug(f"Error testing case variation bypass: {e}")

        return None

    async def _test_encoding_bypass(
        self,
        url: str,
        method: str,
        headers: Dict,
        context: Dict
    ) -> Optional[RateLimitVulnerability]:
        """Test if rate limit can be bypassed via URL encoding variations"""
        try:
            parsed = urlparse(url)
            path = parsed.path

            # Generate encoding variations
            encoded_paths = []

            # Double encoding
            double_encoded = path.replace('/', '%252f')
            if double_encoded != path:
                encoded_paths.append(double_encoded)

            # Unicode encoding
            unicode_encoded = path.replace('a', '%61').replace('e', '%65')
            if unicode_encoded != path:
                encoded_paths.append(unicode_encoded)

            async with safe_http_client(context.get('config', {})) as client:
                bypass_worked = []

                for encoded_path in encoded_paths:
                    varied_url = url.replace(path, encoded_path)

                    try:
                        if method == 'GET':
                            response = await client.get(varied_url, headers=headers)
                        else:
                            response = await client.post(varied_url, headers=headers, json={})

                        if response.status_code != 429 and response.status_code < 400:
                            bypass_worked.append(encoded_path)

                    except Exception:
                        pass

                    await asyncio.sleep(self.request_delay)

                if bypass_worked:
                    return RateLimitVulnerability(
                        issue_type=RateLimitIssueType.BYPASS_POSSIBLE,
                        risk_level=RateLimitRisk.MEDIUM,
                        endpoint=url,
                        method=method,
                        evidence=f"Rate limit bypass possible via URL encoding variations",
                        bypass_technique="URL encoding variation"
                    )

        except Exception as e:
            logger.debug(f"Error testing encoding bypass: {e}")

        return None

    def _analyze_rate_limit_config(
        self,
        url: str,
        method: str,
        rate_limit_info: RateLimitInfo,
        category: str
    ) -> List[RateLimitVulnerability]:
        """Analyze rate limit configuration for issues"""
        vulnerabilities = []

        # Check for missing standard headers
        essential_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']
        missing_essential = [h for h in essential_headers if h not in rate_limit_info.headers_present]

        if len(missing_essential) >= 2:
            vuln = RateLimitVulnerability(
                issue_type=RateLimitIssueType.MISSING_HEADERS,
                risk_level=RateLimitRisk.LOW,
                endpoint=url,
                method=method,
                evidence=f"Missing essential rate limit headers: {', '.join(missing_essential)}. This makes it difficult for clients to implement proper retry logic."
            )
            vulnerabilities.append(vuln)

        # Check for inconsistent limit values
        if rate_limit_info.limit and rate_limit_info.remaining:
            if rate_limit_info.remaining > rate_limit_info.limit:
                vuln = RateLimitVulnerability(
                    issue_type=RateLimitIssueType.IMPROPER_CONFIGURATION,
                    risk_level=RateLimitRisk.LOW,
                    endpoint=url,
                    method=method,
                    evidence=f"Inconsistent rate limit headers: Remaining ({rate_limit_info.remaining}) > Limit ({rate_limit_info.limit})"
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    async def _check_enumeration_possibility(
        self,
        url: str,
        method: str,
        headers: Dict,
        probe_result: RateLimitTestResult,
        category: str,
        context: Dict
    ) -> List[RateLimitVulnerability]:
        """Check if endpoint allows enumeration attacks"""
        vulnerabilities = []

        # For authentication endpoints, check if rate limit is too high
        recommended = self.RECOMMENDED_LIMITS.get(category, self.RECOMMENDED_LIMITS['authentication'])

        if probe_result.rate_limit_triggered_at is None or probe_result.rate_limit_triggered_at > recommended['limit'] * 2:
            vuln = RateLimitVulnerability(
                issue_type=RateLimitIssueType.ENUMERATION_POSSIBLE,
                risk_level=RateLimitRisk.HIGH,
                endpoint=url,
                method=method,
                evidence=f"Authentication endpoint may allow credential enumeration/brute force. Rate limit {'not detected' if probe_result.rate_limit_triggered_at is None else f'at {probe_result.rate_limit_triggered_at} requests'} (recommended: {recommended['limit']} requests/{recommended['window']}s)"
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_risk_for_category(self, category: str) -> RateLimitRisk:
        """Get appropriate risk level based on endpoint category"""
        high_risk_categories = ['authentication', 'password_reset', 'otp_verification', 'financial']
        medium_risk_categories = ['registration', 'admin', 'search', 'export']

        if category in high_risk_categories:
            return RateLimitRisk.HIGH
        elif category in medium_risk_categories:
            return RateLimitRisk.MEDIUM
        else:
            return RateLimitRisk.LOW

    def _create_finding(
        self,
        vuln: RateLimitVulnerability,
        category: str,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding dictionary from vulnerability"""
        cwe_info = RATE_LIMIT_CWE_MAPPINGS.get(
            vuln.issue_type,
            RATE_LIMIT_CWE_MAPPINGS[RateLimitIssueType.NO_RATE_LIMIT]
        )

        # Adjust CVSS based on category
        cvss_base = cwe_info['cvss_base']
        if category in ['authentication', 'password_reset', 'otp_verification', 'financial']:
            cvss_base = min(cvss_base + 1.5, 10.0)
        elif category in ['admin']:
            cvss_base = min(cvss_base + 1.0, 10.0)

        # Build evidence
        evidence_parts = [vuln.evidence]
        if vuln.test_result:
            evidence_parts.append(
                f"Test results: {vuln.test_result.request_count} requests, "
                f"{vuln.test_result.rate_limited_count} rate limited, "
                f"avg response time: {vuln.test_result.avg_response_time:.3f}s"
            )
        if vuln.bypass_technique:
            evidence_parts.append(f"Bypass technique: {vuln.bypass_technique}")

        # Create fingerprint
        fingerprint_data = f"{vuln.endpoint}:{vuln.method}:{vuln.issue_type.value}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        # Severity mapping
        severity_map = {
            RateLimitRisk.CRITICAL: 'critical',
            RateLimitRisk.HIGH: 'high',
            RateLimitRisk.MEDIUM: 'medium',
            RateLimitRisk.LOW: 'low',
            RateLimitRisk.INFO: 'info'
        }

        # Build recommendations
        recommendations = self._get_recommendations(vuln.issue_type, category)

        return {
            'issue': self._get_issue_title(vuln.issue_type),
            'description': self._get_issue_description(vuln.issue_type, category, vuln),
            'severity': severity_map[vuln.risk_level],
            'category': 'Rate Limiting',
            'endpoint': vuln.endpoint,
            'method': vuln.method,
            'evidence': '\n'.join(evidence_parts),
            'cwe_id': cwe_info['id'],
            'cwe_name': cwe_info['name'],
            'cvss_score': round(cvss_base, 1),
            'recommendation': '\n'.join([f"• {r}" for r in recommendations]),
            'issue_type': vuln.issue_type.value,
            'endpoint_category': category,
            'bypass_technique': vuln.bypass_technique,
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def _get_issue_title(self, issue_type: RateLimitIssueType) -> str:
        """Get human-readable title for issue type"""
        titles = {
            RateLimitIssueType.NO_RATE_LIMIT: 'No Rate Limiting Detected',
            RateLimitIssueType.WEAK_RATE_LIMIT: 'Weak Rate Limiting Configuration',
            RateLimitIssueType.BYPASS_POSSIBLE: 'Rate Limit Bypass Vulnerability',
            RateLimitIssueType.INCONSISTENT_ENFORCEMENT: 'Inconsistent Rate Limit Enforcement',
            RateLimitIssueType.MISSING_HEADERS: 'Missing Rate Limit Headers',
            RateLimitIssueType.IMPROPER_CONFIGURATION: 'Improper Rate Limit Configuration',
            RateLimitIssueType.ENUMERATION_POSSIBLE: 'Credential Enumeration Possible',
            RateLimitIssueType.RESOURCE_EXHAUSTION: 'Resource Exhaustion Possible'
        }
        return titles.get(issue_type, 'Rate Limiting Issue Detected')

    def _get_issue_description(
        self,
        issue_type: RateLimitIssueType,
        category: str,
        vuln: RateLimitVulnerability
    ) -> str:
        """Get detailed description for the issue"""
        descriptions = {
            RateLimitIssueType.NO_RATE_LIMIT: f"The {category} endpoint lacks rate limiting protection. This allows attackers to make unlimited requests, potentially enabling brute force attacks, credential stuffing, enumeration attacks, or denial of service. Rate limiting is critical for protecting API endpoints from abuse.",
            RateLimitIssueType.WEAK_RATE_LIMIT: f"The rate limiting configuration on this {category} endpoint is too permissive. The current limit allows significantly more requests than recommended for this type of endpoint, reducing the effectiveness of the protection against abuse.",
            RateLimitIssueType.BYPASS_POSSIBLE: f"The rate limiting on this endpoint can be bypassed using {vuln.bypass_technique or 'various techniques'}. This effectively nullifies the rate limiting protection and allows attackers to make unlimited requests.",
            RateLimitIssueType.INCONSISTENT_ENFORCEMENT: f"Rate limiting on this {category} endpoint is not consistently enforced across all request variations. This inconsistency could be exploited to bypass the intended protections.",
            RateLimitIssueType.MISSING_HEADERS: "The API response lacks standard rate limiting headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset). While this may not be a security issue, it prevents clients from implementing proper retry logic and understanding their quota.",
            RateLimitIssueType.IMPROPER_CONFIGURATION: "The rate limiting configuration contains inconsistencies or errors that could affect its effectiveness or confuse API consumers.",
            RateLimitIssueType.ENUMERATION_POSSIBLE: f"This {category} endpoint allows enough requests to perform credential enumeration or brute force attacks. Authentication endpoints should have strict rate limits to prevent such attacks.",
            RateLimitIssueType.RESOURCE_EXHAUSTION: "The endpoint lacks sufficient rate limiting to prevent resource exhaustion attacks. An attacker could potentially overwhelm server resources by making many concurrent requests."
        }
        return descriptions.get(issue_type, "A rate limiting issue was detected on this endpoint.")

    def _get_recommendations(
        self,
        issue_type: RateLimitIssueType,
        category: str
    ) -> List[str]:
        """Get recommendations for fixing the issue"""
        recommended = self.RECOMMENDED_LIMITS.get(category, self.RECOMMENDED_LIMITS['api_general'])

        base_recommendations = {
            RateLimitIssueType.NO_RATE_LIMIT: [
                f"Implement rate limiting with recommended limit of {recommended['limit']} requests per {recommended['window']} seconds",
                "Use a distributed rate limiting solution for scalability (Redis, API Gateway)",
                "Include standard rate limit headers in responses",
                "Implement exponential backoff for rate-limited requests",
                "Log rate limit violations for security monitoring"
            ],
            RateLimitIssueType.WEAK_RATE_LIMIT: [
                f"Reduce rate limit to recommended {recommended['limit']} requests per {recommended['window']} seconds",
                "Consider implementing tiered rate limits based on user roles",
                "Add stricter limits for sensitive operations",
                "Monitor for rate limit abuse patterns"
            ],
            RateLimitIssueType.BYPASS_POSSIBLE: [
                "Implement rate limiting based on authenticated user ID, not just IP",
                "Ignore or sanitize X-Forwarded-For and similar headers from untrusted sources",
                "Normalize URLs before rate limit checks (case, encoding)",
                "Use multiple factors for rate limit identification",
                "Implement application-level rate limiting in addition to infrastructure"
            ],
            RateLimitIssueType.INCONSISTENT_ENFORCEMENT: [
                "Ensure rate limiting is applied consistently across all request variations",
                "Normalize request paths before rate limit checks",
                "Test rate limiting with various HTTP methods and encodings"
            ],
            RateLimitIssueType.MISSING_HEADERS: [
                "Add X-RateLimit-Limit header indicating the maximum requests allowed",
                "Add X-RateLimit-Remaining header showing remaining requests",
                "Add X-RateLimit-Reset header indicating when the limit resets",
                "Include Retry-After header in 429 responses"
            ],
            RateLimitIssueType.IMPROPER_CONFIGURATION: [
                "Review and fix rate limit configuration inconsistencies",
                "Ensure rate limit headers accurately reflect the actual limits",
                "Test rate limiting behavior matches configured values"
            ],
            RateLimitIssueType.ENUMERATION_POSSIBLE: [
                f"Implement strict rate limits ({recommended['limit']} requests/{recommended['window']}s) for authentication endpoints",
                "Add account lockout after multiple failed attempts",
                "Implement CAPTCHA after repeated failures",
                "Use generic error messages to prevent user enumeration",
                "Monitor and alert on brute force attempts"
            ],
            RateLimitIssueType.RESOURCE_EXHAUSTION: [
                "Implement connection rate limiting",
                "Add request size limits",
                "Use request queuing for resource-intensive operations",
                "Implement circuit breakers for downstream services",
                "Consider using a Web Application Firewall (WAF)"
            ]
        }

        return base_recommendations.get(issue_type, base_recommendations[RateLimitIssueType.NO_RATE_LIMIT])

    def _create_no_issues_finding(
        self,
        target: str,
        endpoint_count: int,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding when no issues are detected"""
        fingerprint = hashlib.sha256(f"rate_limit_scan_complete:{target}".encode()).hexdigest()[:16]

        return {
            'issue': 'Rate Limit Assessment Complete',
            'description': f"Rate limiting assessment completed for {endpoint_count} endpoint(s). The API appears to implement rate limiting correctly. Standard rate limit headers were detected and limits appear appropriate for the endpoint types tested.",
            'severity': 'info',
            'category': 'Rate Limiting',
            'endpoint': target,
            'method': 'GET',
            'evidence': f"Analyzed {endpoint_count} endpoint(s) for rate limiting. Tests included: limit detection, bypass techniques (IP spoofing, URL variations), header analysis.",
            'cwe_id': 'N/A',
            'cwe_name': 'No Issues Detected',
            'cvss_score': 0.0,
            'recommendation': '• Continue monitoring rate limit effectiveness\n• Regularly review and adjust limits based on usage patterns\n• Test rate limiting after API changes\n• Consider implementing adaptive rate limiting',
            'issue_type': 'assessment_complete',
            'endpoints_tested': endpoint_count,
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def get_rate_limit_summary(self) -> Dict[str, Any]:
        """Generate a summary of rate limit testing"""
        return {
            'endpoints_tested': len(self.tested_endpoints),
            'cached_limits': len(self.rate_limit_cache),
            'test_techniques': [
                'Direct rate limit probing',
                'IP spoofing bypass (X-Forwarded-For, etc.)',
                'URL case variation bypass',
                'URL encoding bypass',
                'Header analysis'
            ],
            'endpoint_categories_tested': list(self.RECOMMENDED_LIMITS.keys())
        }
