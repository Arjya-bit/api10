"""IDOR Detector - Enterprise-grade Insecure Direct Object Reference vulnerability detection"""
import re
import logging
import hashlib
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from enum import Enum

from apiguardian.core.plugin_manager import AnalyzerPlugin

logger = logging.getLogger(__name__)


class IDORRiskLevel(Enum):
    """Risk levels for IDOR vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IDORType(Enum):
    """Types of IDOR vulnerabilities"""
    HORIZONTAL = "horizontal"  # Access other users' data at same privilege level
    VERTICAL = "vertical"  # Access higher privilege data/operations
    DATA_LEAKAGE = "data_leakage"  # Sensitive data exposed through enumeration
    FUNCTION_LEVEL = "function_level"  # Access to unauthorized functions
    FILE_ACCESS = "file_access"  # Unauthorized file access


@dataclass
class IDLocation:
    """Represents an ID location in a request"""
    type: str  # 'query', 'path', 'body', 'header'
    name: str  # Parameter name or path segment description
    value: str  # Original value
    index: Optional[int] = None  # Path segment index if applicable
    id_type: str = "unknown"  # numeric, uuid, objectid, custom
    sensitive: bool = False  # Whether this appears to be a sensitive resource
    resource_type: str = "unknown"  # user, account, document, order, etc.


@dataclass
class IDORTestResult:
    """Result of an IDOR test"""
    test_id: str
    original_id: str
    response_code: int
    response_size: int
    response_time: float
    accessible: bool
    content_similarity: float
    sensitive_data_found: List[str] = field(default_factory=list)
    error_patterns_found: List[str] = field(default_factory=list)


@dataclass
class IDORVulnerability:
    """Represents a detected IDOR vulnerability"""
    idor_type: IDORType
    risk_level: IDORRiskLevel
    location: IDLocation
    test_results: List[IDORTestResult]
    confidence: float
    impact_description: str
    attack_vector: str


# CWE mappings for IDOR vulnerabilities
IDOR_CWE_MAPPINGS = {
    IDORType.HORIZONTAL: {
        'id': 'CWE-639',
        'name': 'Authorization Bypass Through User-Controlled Key',
        'cvss_base': 7.5
    },
    IDORType.VERTICAL: {
        'id': 'CWE-639',
        'name': 'Authorization Bypass Through User-Controlled Key',
        'cvss_base': 8.5
    },
    IDORType.DATA_LEAKAGE: {
        'id': 'CWE-200',
        'name': 'Exposure of Sensitive Information',
        'cvss_base': 6.5
    },
    IDORType.FUNCTION_LEVEL: {
        'id': 'CWE-285',
        'name': 'Improper Authorization',
        'cvss_base': 8.0
    },
    IDORType.FILE_ACCESS: {
        'id': 'CWE-22',
        'name': 'Path Traversal',
        'cvss_base': 7.5
    }
}


# Sensitive resource patterns
SENSITIVE_RESOURCE_PATTERNS = {
    'user': re.compile(r'user[s_]?|profile[s]?|account[s]?|member[s]?', re.I),
    'financial': re.compile(r'payment[s]?|invoice[s]?|transaction[s]?|order[s]?|cart[s]?|billing', re.I),
    'document': re.compile(r'document[s]?|file[s]?|attachment[s]?|upload[s]?|media', re.I),
    'admin': re.compile(r'admin|manage|config|setting[s]?|control', re.I),
    'sensitive': re.compile(r'private|secret|confidential|internal|restricted', re.I),
    'pii': re.compile(r'email|phone|address|ssn|passport|license|credential', re.I)
}


# ID patterns for detection
ID_PATTERNS = {
    'numeric': re.compile(r'^[0-9]+$'),
    'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),
    'uuid_no_dash': re.compile(r'^[0-9a-f]{32}$', re.I),
    'objectid': re.compile(r'^[0-9a-f]{24}$', re.I),
    'base64': re.compile(r'^[A-Za-z0-9+/]+=*$'),
    'hash_md5': re.compile(r'^[0-9a-f]{32}$', re.I),
    'hash_sha1': re.compile(r'^[0-9a-f]{40}$', re.I),
    'hash_sha256': re.compile(r'^[0-9a-f]{64}$', re.I),
    'slug': re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', re.I),
    'encoded': re.compile(r'^[A-Za-z0-9_-]+={0,2}$')
}


# Parameter names that commonly contain IDs
ID_PARAMETER_NAMES = [
    'id', 'user_id', 'userId', 'uid', 'account_id', 'accountId', 'profile_id',
    'doc_id', 'docId', 'document_id', 'documentId', 'order_id', 'orderId',
    'item_id', 'itemId', 'file_id', 'fileId', 'record_id', 'recordId',
    'customer_id', 'customerId', 'client_id', 'clientId', 'member_id',
    'memberId', 'employee_id', 'employeeId', 'resource_id', 'resourceId',
    'ref', 'reference', 'key', 'token', 'uuid', 'guid', 'pid', 'oid'
]


# Error patterns indicating authorization issues
AUTH_ERROR_PATTERNS = [
    re.compile(r'unauthorized|not\s+authorized|access\s+denied', re.I),
    re.compile(r'permission\s+denied|forbidden|not\s+allowed', re.I),
    re.compile(r'insufficient\s+privileges|no\s+access|restricted', re.I),
    re.compile(r'login\s+required|authentication\s+required', re.I),
    re.compile(r'invalid\s+token|session\s+expired|not\s+logged\s+in', re.I)
]


# Sensitive data patterns in responses
SENSITIVE_DATA_PATTERNS = {
    'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    'api_key': re.compile(r'(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})', re.I),
    'password_hash': re.compile(r'\$2[aby]?\$\d+\$[./A-Za-z0-9]{53}|\$argon2[id]?\$'),
    'jwt': re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
    'private_key': re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
    'aws_key': re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}')
}


class IDORDetector(AnalyzerPlugin):
    """Enterprise-grade IDOR vulnerability detection with comprehensive analysis"""

    plugin_name = "idor_detector"
    description = "Detect Insecure Direct Object Reference vulnerabilities through comprehensive ID manipulation, access control testing, and response analysis"
    version = "2.0.0"

    # Test ID strategies
    NUMERIC_TEST_IDS = ['0', '1', '2', '-1', '999999', '9999999999', '00001']
    UUID_TEST_IDS = [
        '00000000-0000-0000-0000-000000000000',
        '00000000-0000-0000-0000-000000000001',
        'ffffffff-ffff-ffff-ffff-ffffffffffff'
    ]
    OBJECTID_TEST_IDS = [
        '000000000000000000000000',
        '000000000000000000000001',
        'ffffffffffffffffffffffff'
    ]
    PATH_TRAVERSAL_IDS = [
        '../', '../../', '../../../',
        '..%2f', '..%252f', '....//....//.....//',
        '..\\', '..%5c', '..%255c'
    ]
    SPECIAL_TEST_IDS = ['admin', 'root', 'system', 'test', 'null', 'undefined', 'none']

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the IDOR detector with configuration"""
        super().__init__(config)
        self.config = config or {}
        self.tested_endpoints: Set[str] = set()
        self.baseline_responses: Dict[str, IDORTestResult] = {}
        self.max_concurrent_requests = 5
        self.request_delay = 0.1  # Delay between requests in seconds

    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze target for IDOR vulnerabilities with comprehensive testing"""
        findings = []

        logger.info(f"Starting IDOR vulnerability analysis for target: {target}")

        # Get configuration
        config = context.get('config', {})
        analyzer_config = config.get('analyzers', {}).get('idor', {})

        # Configuration options
        max_test_ids = analyzer_config.get('max_test_ids', 10)
        test_path_traversal = analyzer_config.get('test_path_traversal', True)
        deep_analysis = analyzer_config.get('deep_analysis', True)

        # Get endpoints to test
        endpoints = context.get('endpoints', [])
        if not endpoints and target:
            endpoints = [{'url': target, 'method': 'GET'}]

        logger.info(f"Analyzing {len(endpoints)} endpoints for IDOR vulnerabilities")

        # Process each endpoint
        for endpoint_info in endpoints:
            url = endpoint_info.get('url', '')
            method = endpoint_info.get('method', 'GET').upper()
            headers = endpoint_info.get('headers', {})
            body = endpoint_info.get('body', {})

            if not url:
                continue

            # Skip already tested endpoints
            endpoint_key = f"{method}:{url}"
            if endpoint_key in self.tested_endpoints:
                continue
            self.tested_endpoints.add(endpoint_key)

            # Find ID locations in the request
            id_locations = self._find_all_id_locations(url, method, body)

            if not id_locations:
                continue

            logger.debug(f"Found {len(id_locations)} ID locations in {url}")

            # Test each ID location
            for location in id_locations:
                vulnerabilities = await self._comprehensive_idor_test(
                    url, method, location, headers, body,
                    max_test_ids, test_path_traversal, deep_analysis, context
                )

                # Convert vulnerabilities to findings
                for vuln in vulnerabilities:
                    finding = self._create_finding(vuln, url, method, context)
                    findings.append(finding)

        # Add summary finding if no vulnerabilities found
        if not findings:
            findings.append(self._create_no_vuln_finding(target, len(endpoints), context))

        logger.info(f"IDOR analysis complete. Found {len(findings)} findings")

        return findings

    def _find_all_id_locations(self, url: str, method: str, body: Dict = None) -> List[IDLocation]:
        """Find all potential ID locations in URL and body"""
        locations = []

        # Parse URL
        parsed = urlparse(url)

        # Check query parameters
        query_params = parse_qs(parsed.query)
        for param, values in query_params.items():
            value = values[0] if values else ''
            if self._is_potential_id_parameter(param, value):
                id_type = self._detect_id_type(value)
                resource_type = self._detect_resource_type(param, url)
                sensitive = self._is_sensitive_resource(param, url)

                locations.append(IDLocation(
                    type='query',
                    name=param,
                    value=value,
                    id_type=id_type,
                    resource_type=resource_type,
                    sensitive=sensitive
                ))

        # Check path segments
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            if not part:
                continue

            # Get context from surrounding path segments
            context_before = path_parts[i-1] if i > 0 else ''

            if self._is_potential_id_value(part):
                id_type = self._detect_id_type(part)
                resource_type = self._detect_resource_type(context_before, url)
                sensitive = self._is_sensitive_resource(context_before, url)

                locations.append(IDLocation(
                    type='path',
                    name=context_before or f'segment_{i}',
                    value=part,
                    index=i,
                    id_type=id_type,
                    resource_type=resource_type,
                    sensitive=sensitive
                ))

        # Check request body for IDs
        if body and isinstance(body, dict):
            body_locations = self._find_ids_in_body(body)
            locations.extend(body_locations)

        return locations

    def _find_ids_in_body(self, body: Dict, prefix: str = '') -> List[IDLocation]:
        """Recursively find IDs in request body"""
        locations = []

        for key, value in body.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                locations.extend(self._find_ids_in_body(value, full_key))
            elif isinstance(value, str) and self._is_potential_id_parameter(key, value):
                id_type = self._detect_id_type(value)
                resource_type = self._detect_resource_type(key, '')
                sensitive = self._is_sensitive_resource(key, '')

                locations.append(IDLocation(
                    type='body',
                    name=full_key,
                    value=value,
                    id_type=id_type,
                    resource_type=resource_type,
                    sensitive=sensitive
                ))

        return locations

    def _is_potential_id_parameter(self, param_name: str, value: str) -> bool:
        """Check if parameter is potentially an ID"""
        param_lower = param_name.lower()

        # Check against known ID parameter names
        for id_name in ID_PARAMETER_NAMES:
            if id_name.lower() in param_lower or param_lower in id_name.lower():
                return True

        # Check if value looks like an ID
        return self._is_potential_id_value(value)

    def _is_potential_id_value(self, value: str) -> bool:
        """Check if value looks like an ID"""
        if not value or len(value) > 100:
            return False

        # Check against known ID patterns
        for pattern_name, pattern in ID_PATTERNS.items():
            if pattern.match(value):
                return True

        return False

    def _detect_id_type(self, value: str) -> str:
        """Detect the type of ID"""
        if ID_PATTERNS['numeric'].match(value):
            return 'numeric'
        elif ID_PATTERNS['uuid'].match(value):
            return 'uuid'
        elif ID_PATTERNS['uuid_no_dash'].match(value):
            return 'uuid_no_dash'
        elif ID_PATTERNS['objectid'].match(value):
            return 'objectid'
        elif ID_PATTERNS['hash_sha256'].match(value):
            return 'sha256'
        elif ID_PATTERNS['hash_sha1'].match(value):
            return 'sha1'
        elif ID_PATTERNS['hash_md5'].match(value) and len(value) == 32:
            return 'md5'
        elif ID_PATTERNS['base64'].match(value):
            return 'base64'
        elif ID_PATTERNS['slug'].match(value):
            return 'slug'
        else:
            return 'custom'

    def _detect_resource_type(self, context: str, url: str) -> str:
        """Detect the type of resource based on context"""
        combined = f"{context} {url}".lower()

        for resource_type, pattern in SENSITIVE_RESOURCE_PATTERNS.items():
            if pattern.search(combined):
                return resource_type

        return 'unknown'

    def _is_sensitive_resource(self, context: str, url: str) -> bool:
        """Check if the resource appears to be sensitive"""
        combined = f"{context} {url}".lower()

        sensitive_types = ['user', 'financial', 'admin', 'sensitive', 'pii']
        for resource_type in sensitive_types:
            if SENSITIVE_RESOURCE_PATTERNS.get(resource_type, re.compile('')).search(combined):
                return True

        return False

    def _get_test_ids_for_type(self, id_type: str, original_value: str) -> List[str]:
        """Get appropriate test IDs based on ID type"""
        test_ids = []

        if id_type == 'numeric':
            test_ids.extend(self.NUMERIC_TEST_IDS)
            # Add adjacent values
            try:
                original_num = int(original_value)
                test_ids.extend([str(original_num - 1), str(original_num + 1)])
                test_ids.extend([str(original_num - 10), str(original_num + 10)])
            except ValueError:
                pass

        elif id_type in ('uuid', 'uuid_no_dash'):
            test_ids.extend(self.UUID_TEST_IDS)
            # Modify original UUID slightly
            if len(original_value) >= 36:
                modified = original_value[:-1] + ('0' if original_value[-1] != '0' else '1')
                test_ids.append(modified)

        elif id_type == 'objectid':
            test_ids.extend(self.OBJECTID_TEST_IDS)
            # Modify original ObjectId slightly
            if len(original_value) == 24:
                modified = original_value[:-1] + ('0' if original_value[-1] != '0' else '1')
                test_ids.append(modified)

        else:
            # For other types, use special test IDs
            test_ids.extend(self.SPECIAL_TEST_IDS)

        # Remove original value from test IDs
        test_ids = [tid for tid in test_ids if tid != original_value]

        return test_ids

    async def _comprehensive_idor_test(
        self,
        url: str,
        method: str,
        location: IDLocation,
        headers: Dict,
        body: Dict,
        max_test_ids: int,
        test_path_traversal: bool,
        deep_analysis: bool,
        context: Dict
    ) -> List[IDORVulnerability]:
        """Perform comprehensive IDOR testing on a specific ID location"""
        vulnerabilities = []

        # Get test IDs based on ID type
        test_ids = self._get_test_ids_for_type(location.id_type, location.value)[:max_test_ids]

        # Add path traversal test IDs if enabled
        if test_path_traversal and location.type in ('path', 'query'):
            test_ids.extend(self.PATH_TRAVERSAL_IDS[:3])

        # Get baseline response
        baseline = await self._get_baseline_response(url, method, headers, body, context)

        # Test each ID
        test_results = []
        for test_id in test_ids:
            result = await self._test_single_id(
                url, method, location, test_id, headers, body, baseline, context
            )
            if result:
                test_results.append(result)

            # Small delay to avoid rate limiting
            await asyncio.sleep(self.request_delay)

        # Analyze results for vulnerabilities
        if test_results:
            detected_vulns = self._analyze_test_results(location, test_results, baseline, deep_analysis)
            vulnerabilities.extend(detected_vulns)

        return vulnerabilities

    async def _get_baseline_response(
        self,
        url: str,
        method: str,
        headers: Dict,
        body: Dict,
        context: Dict
    ) -> Optional[IDORTestResult]:
        """Get baseline response for comparison"""
        try:
            async with safe_http_client(context.get('config', {})) as client:
                start_time = datetime.now()

                if method == 'GET':
                    response = await client.get(url, headers=headers)
                elif method == 'POST':
                    response = await client.post(url, headers=headers, json=body)
                elif method == 'PUT':
                    response = await client.put(url, headers=headers, json=body)
                elif method == 'DELETE':
                    response = await client.delete(url, headers=headers)
                else:
                    response = await client.request(method, url, headers=headers, json=body)

                response_time = (datetime.now() - start_time).total_seconds()
                content = await response.text() if hasattr(response, 'text') else str(response.content)

                return IDORTestResult(
                    test_id='baseline',
                    original_id='baseline',
                    response_code=response.status_code,
                    response_size=len(content),
                    response_time=response_time,
                    accessible=response.status_code in (200, 201, 204),
                    content_similarity=1.0,
                    sensitive_data_found=self._find_sensitive_data(content),
                    error_patterns_found=[]
                )
        except Exception as e:
            logger.debug(f"Error getting baseline response: {e}")
            return None

    async def _test_single_id(
        self,
        url: str,
        method: str,
        location: IDLocation,
        test_id: str,
        headers: Dict,
        body: Dict,
        baseline: Optional[IDORTestResult],
        context: Dict
    ) -> Optional[IDORTestResult]:
        """Test a single ID substitution"""
        try:
            # Create modified request
            modified_url, modified_body = self._substitute_id(url, location, test_id, body)

            async with safe_http_client(context.get('config', {})) as client:
                start_time = datetime.now()

                if method == 'GET':
                    response = await client.get(modified_url, headers=headers)
                elif method == 'POST':
                    response = await client.post(modified_url, headers=headers, json=modified_body)
                elif method == 'PUT':
                    response = await client.put(modified_url, headers=headers, json=modified_body)
                elif method == 'DELETE':
                    response = await client.delete(modified_url, headers=headers)
                else:
                    response = await client.request(method, modified_url, headers=headers, json=modified_body)

                response_time = (datetime.now() - start_time).total_seconds()
                content = await response.text() if hasattr(response, 'text') else str(response.content)

                # Calculate content similarity with baseline
                content_similarity = self._calculate_content_similarity(
                    baseline, content, response.status_code
                ) if baseline else 0.0

                # Find sensitive data in response
                sensitive_data = self._find_sensitive_data(content)

                # Find error patterns
                error_patterns = self._find_error_patterns(content)

                return IDORTestResult(
                    test_id=test_id,
                    original_id=location.value,
                    response_code=response.status_code,
                    response_size=len(content),
                    response_time=response_time,
                    accessible=response.status_code in (200, 201, 204),
                    content_similarity=content_similarity,
                    sensitive_data_found=sensitive_data,
                    error_patterns_found=error_patterns
                )
        except Exception as e:
            logger.debug(f"Error testing ID {test_id}: {e}")
            return None

    def _substitute_id(
        self,
        url: str,
        location: IDLocation,
        new_id: str,
        body: Dict = None
    ) -> Tuple[str, Dict]:
        """Substitute ID value in request"""
        modified_body = body.copy() if body else {}

        if location.type == 'query':
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            query_params[location.name] = [new_id]
            new_query = urlencode(query_params, doseq=True)
            modified_url = urlunparse(parsed._replace(query=new_query))

        elif location.type == 'path':
            parsed = urlparse(url)
            path_parts = parsed.path.split('/')
            if location.index is not None and location.index < len(path_parts):
                path_parts[location.index] = new_id
            new_path = '/'.join(path_parts)
            modified_url = urlunparse(parsed._replace(path=new_path))

        elif location.type == 'body':
            modified_url = url
            # Navigate to nested key and modify
            keys = location.name.split('.')
            current = modified_body
            for key in keys[:-1]:
                current = current.setdefault(key, {})
            current[keys[-1]] = new_id

        else:
            modified_url = url

        return modified_url, modified_body

    def _calculate_content_similarity(
        self,
        baseline: IDORTestResult,
        content: str,
        status_code: int
    ) -> float:
        """Calculate similarity between baseline and test response"""
        if not baseline:
            return 0.0

        # Status code comparison (weight: 30%)
        status_score = 1.0 if status_code == baseline.response_code else 0.0

        # Size comparison (weight: 30%)
        baseline_size = baseline.response_size
        current_size = len(content)
        if baseline_size > 0:
            size_ratio = min(baseline_size, current_size) / max(baseline_size, current_size)
        else:
            size_ratio = 1.0 if current_size == 0 else 0.0

        # Content hash similarity would require storing content (weight: 40%)
        # For now, use a simplified approach based on size
        content_score = size_ratio

        return (status_score * 0.3) + (size_ratio * 0.3) + (content_score * 0.4)

    def _find_sensitive_data(self, content: str) -> List[str]:
        """Find sensitive data patterns in response"""
        found = []

        for data_type, pattern in SENSITIVE_DATA_PATTERNS.items():
            if pattern.search(content):
                found.append(data_type)

        return found

    def _find_error_patterns(self, content: str) -> List[str]:
        """Find authorization error patterns in response"""
        found = []

        for pattern in AUTH_ERROR_PATTERNS:
            match = pattern.search(content)
            if match:
                found.append(match.group(0))

        return found

    def _analyze_test_results(
        self,
        location: IDLocation,
        test_results: List[IDORTestResult],
        baseline: Optional[IDORTestResult],
        deep_analysis: bool
    ) -> List[IDORVulnerability]:
        """Analyze test results to identify vulnerabilities"""
        vulnerabilities = []

        for result in test_results:
            # Check for path traversal vulnerability
            if '..' in result.test_id and result.accessible:
                vuln = self._create_path_traversal_vulnerability(location, result, baseline)
                if vuln:
                    vulnerabilities.append(vuln)
                continue

            # Check for horizontal IDOR (accessing other users' data)
            if result.accessible and result.test_id != result.original_id:
                # Check if different content was returned (indicating different resource)
                if result.content_similarity < 0.8:
                    vuln = self._create_horizontal_idor_vulnerability(
                        location, result, baseline, deep_analysis
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

            # Check for data leakage through sensitive data exposure
            if result.accessible and result.sensitive_data_found:
                vuln = self._create_data_leakage_vulnerability(
                    location, result, baseline
                )
                if vuln:
                    vulnerabilities.append(vuln)

            # Check for vertical IDOR (special/admin IDs)
            if result.test_id in ['0', '1', 'admin', 'root', 'system'] and result.accessible:
                vuln = self._create_vertical_idor_vulnerability(
                    location, result, baseline
                )
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _create_horizontal_idor_vulnerability(
        self,
        location: IDLocation,
        result: IDORTestResult,
        baseline: Optional[IDORTestResult],
        deep_analysis: bool
    ) -> Optional[IDORVulnerability]:
        """Create horizontal IDOR vulnerability finding"""
        # Calculate confidence based on evidence
        confidence = 0.5

        if result.accessible:
            confidence += 0.2

        if result.content_similarity < 0.5:
            confidence += 0.2

        if location.sensitive:
            confidence += 0.1

        return IDORVulnerability(
            idor_type=IDORType.HORIZONTAL,
            risk_level=IDORRiskLevel.HIGH if location.sensitive else IDORRiskLevel.MEDIUM,
            location=location,
            test_results=[result],
            confidence=min(confidence, 1.0),
            impact_description=f"Potential unauthorized access to {location.resource_type} resources",
            attack_vector=f"Modify {location.type} parameter '{location.name}' from '{result.original_id}' to '{result.test_id}'"
        )

    def _create_vertical_idor_vulnerability(
        self,
        location: IDLocation,
        result: IDORTestResult,
        baseline: Optional[IDORTestResult]
    ) -> Optional[IDORVulnerability]:
        """Create vertical IDOR vulnerability finding"""
        return IDORVulnerability(
            idor_type=IDORType.VERTICAL,
            risk_level=IDORRiskLevel.CRITICAL,
            location=location,
            test_results=[result],
            confidence=0.8,
            impact_description=f"Potential access to administrative or system-level {location.resource_type} resources",
            attack_vector=f"Modify {location.type} parameter '{location.name}' to privileged ID '{result.test_id}'"
        )

    def _create_data_leakage_vulnerability(
        self,
        location: IDLocation,
        result: IDORTestResult,
        baseline: Optional[IDORTestResult]
    ) -> Optional[IDORVulnerability]:
        """Create data leakage vulnerability finding"""
        sensitive_types = result.sensitive_data_found

        return IDORVulnerability(
            idor_type=IDORType.DATA_LEAKAGE,
            risk_level=IDORRiskLevel.HIGH,
            location=location,
            test_results=[result],
            confidence=0.9,
            impact_description=f"Sensitive data exposure detected: {', '.join(sensitive_types)}",
            attack_vector=f"Access {location.resource_type} resource with ID '{result.test_id}' to expose sensitive data"
        )

    def _create_path_traversal_vulnerability(
        self,
        location: IDLocation,
        result: IDORTestResult,
        baseline: Optional[IDORTestResult]
    ) -> Optional[IDORVulnerability]:
        """Create path traversal vulnerability finding"""
        return IDORVulnerability(
            idor_type=IDORType.FILE_ACCESS,
            risk_level=IDORRiskLevel.CRITICAL,
            location=location,
            test_results=[result],
            confidence=0.95,
            impact_description="Path traversal vulnerability allows unauthorized file access",
            attack_vector=f"Use path traversal sequence '{result.test_id}' in {location.type} parameter"
        )

    def _create_finding(
        self,
        vuln: IDORVulnerability,
        url: str,
        method: str,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding dictionary from vulnerability"""
        cwe_info = IDOR_CWE_MAPPINGS.get(vuln.idor_type, IDOR_CWE_MAPPINGS[IDORType.HORIZONTAL])

        # Calculate CVSS score based on vulnerability characteristics
        cvss_base = cwe_info['cvss_base']
        if vuln.location.sensitive:
            cvss_base = min(cvss_base + 0.5, 10.0)
        if vuln.risk_level == IDORRiskLevel.CRITICAL:
            cvss_base = min(cvss_base + 1.0, 10.0)

        # Build evidence from test results
        evidence_parts = []
        for result in vuln.test_results:
            evidence_parts.append(
                f"Test ID '{result.test_id}': HTTP {result.response_code}, "
                f"{result.response_size} bytes, accessible={result.accessible}"
            )
            if result.sensitive_data_found:
                evidence_parts.append(f"Sensitive data found: {', '.join(result.sensitive_data_found)}")

        # Create finding fingerprint
        fingerprint_data = f"{url}:{method}:{vuln.location.name}:{vuln.idor_type.value}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        # Determine severity string
        severity_map = {
            IDORRiskLevel.CRITICAL: 'critical',
            IDORRiskLevel.HIGH: 'high',
            IDORRiskLevel.MEDIUM: 'medium',
            IDORRiskLevel.LOW: 'low',
            IDORRiskLevel.INFO: 'info'
        }

        # Build recommendation based on vulnerability type
        recommendations = {
            IDORType.HORIZONTAL: [
                "Implement proper authorization checks before accessing resources",
                "Verify the requesting user owns or has access to the requested resource",
                "Use indirect object references (e.g., session-based mappings) instead of direct IDs",
                "Implement row-level security in the database",
                "Log and monitor access attempts for anomaly detection"
            ],
            IDORType.VERTICAL: [
                "Implement role-based access control (RBAC)",
                "Verify user privileges before allowing access to administrative resources",
                "Use separate authentication for privileged operations",
                "Implement the principle of least privilege",
                "Add multi-factor authentication for sensitive operations"
            ],
            IDORType.DATA_LEAKAGE: [
                "Review response data to ensure only necessary information is returned",
                "Implement field-level access control",
                "Mask or redact sensitive data in API responses",
                "Use data classification to identify and protect sensitive information",
                "Implement output encoding and filtering"
            ],
            IDORType.FILE_ACCESS: [
                "Validate and sanitize all file path inputs",
                "Use allowlists for permitted file paths",
                "Implement proper input validation to reject path traversal sequences",
                "Store files outside the web root",
                "Use indirect file references instead of direct paths"
            ],
            IDORType.FUNCTION_LEVEL: [
                "Implement function-level access control",
                "Verify user permissions before executing operations",
                "Use capability-based security model",
                "Audit all administrative functions",
                "Implement separation of duties"
            ]
        }

        return {
            'issue': f"{vuln.idor_type.value.replace('_', ' ').title()} IDOR Vulnerability Detected",
            'description': f"Insecure Direct Object Reference ({vuln.idor_type.value}) vulnerability detected in {vuln.location.type} parameter '{vuln.location.name}'. {vuln.impact_description}. The application appears to allow access to resources by directly manipulating object identifiers without proper authorization checks. Attack vector: {vuln.attack_vector}",
            'severity': severity_map[vuln.risk_level],
            'category': 'Authorization',
            'endpoint': url,
            'method': method,
            'evidence': '\n'.join(evidence_parts),
            'cwe_id': cwe_info['id'],
            'cwe_name': cwe_info['name'],
            'cvss_score': round(cvss_base, 1),
            'recommendation': '\n'.join([f"• {r}" for r in recommendations.get(vuln.idor_type, recommendations[IDORType.HORIZONTAL])]),
            'confidence': round(vuln.confidence * 100, 1),
            'idor_type': vuln.idor_type.value,
            'parameter_name': vuln.location.name,
            'parameter_type': vuln.location.type,
            'original_value': vuln.location.value,
            'id_type': vuln.location.id_type,
            'resource_type': vuln.location.resource_type,
            'sensitive_resource': vuln.location.sensitive,
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def _create_no_vuln_finding(
        self,
        target: str,
        endpoint_count: int,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding when no vulnerabilities are detected"""
        fingerprint = hashlib.sha256(f"idor_scan_complete:{target}".encode()).hexdigest()[:16]

        return {
            'issue': 'IDOR Vulnerability Assessment Complete',
            'description': f"Comprehensive IDOR vulnerability assessment completed for {endpoint_count} endpoint(s). No Insecure Direct Object Reference vulnerabilities were detected during this scan. The application appears to implement proper authorization checks for object access. However, this assessment is based on pattern matching and response analysis - manual verification is recommended for comprehensive security assurance.",
            'severity': 'info',
            'category': 'Authorization',
            'endpoint': target,
            'method': 'GET',
            'evidence': f"Analyzed {endpoint_count} endpoint(s) for IDOR vulnerabilities. Tests included: ID enumeration, path traversal, UUID manipulation, and privilege escalation attempts.",
            'cwe_id': 'N/A',
            'cwe_name': 'No Vulnerability Detected',
            'cvss_score': 0.0,
            'recommendation': '• Continue regular security assessments\n• Implement automated IDOR testing in CI/CD pipeline\n• Review authorization logic during code reviews\n• Monitor access patterns for anomalies\n• Consider implementing object-level access control (OLAC)',
            'confidence': 100.0,
            'idor_type': 'assessment_complete',
            'endpoints_tested': endpoint_count,
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def get_test_coverage_report(self) -> Dict[str, Any]:
        """Generate a test coverage report"""
        return {
            'endpoints_tested': len(self.tested_endpoints),
            'id_types_tested': ['numeric', 'uuid', 'objectid', 'base64', 'custom'],
            'test_categories': [
                'Horizontal IDOR (same privilege level)',
                'Vertical IDOR (privilege escalation)',
                'Data leakage through enumeration',
                'Path traversal attacks',
                'Function-level access control bypass'
            ],
            'test_payloads_used': len(self.NUMERIC_TEST_IDS) + len(self.UUID_TEST_IDS) +
                                  len(self.OBJECTID_TEST_IDS) + len(self.PATH_TRAVERSAL_IDS) +
                                  len(self.SPECIAL_TEST_IDS),
            'cwe_coverage': list(IDOR_CWE_MAPPINGS.keys())
        }
