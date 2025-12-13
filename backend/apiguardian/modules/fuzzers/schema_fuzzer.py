"""Schema-Driven Fuzzer - Enterprise-grade API fuzzing based on OpenAPI/JSON Schema"""
import re
import logging
import hashlib
import asyncio
import json
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from copy import deepcopy

from apiguardian.core.plugin_manager import FuzzerPlugin
from apiguardian.utils.http_client import safe_http_client, HTTPResponse

logger = logging.getLogger(__name__)


class FuzzCategory(Enum):
    """Categories of fuzzing tests"""
    BOUNDARY = "boundary"
    TYPE_CONFUSION = "type_confusion"
    FORMAT_VIOLATION = "format_violation"
    INJECTION = "injection"
    OVERFLOW = "overflow"
    NULL_HANDLING = "null_handling"
    ENCODING = "encoding"
    SCHEMA_VIOLATION = "schema_violation"
    BUSINESS_LOGIC = "business_logic"


class FuzzRisk(Enum):
    """Risk levels for fuzz findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FuzzIssueType(Enum):
    """Types of issues found through fuzzing"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    ERROR_DISCLOSURE = "error_disclosure"
    STACK_TRACE = "stack_trace"
    TYPE_CONFUSION = "type_confusion"
    BUFFER_OVERFLOW = "buffer_overflow"
    DOS_POTENTIAL = "dos_potential"
    SCHEMA_BYPASS = "schema_bypass"
    VALIDATION_BYPASS = "validation_bypass"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    MASS_ASSIGNMENT = "mass_assignment"
    NUMERIC_OVERFLOW = "numeric_overflow"
    FORMAT_STRING = "format_string"


@dataclass
class FuzzCase:
    """Represents a single fuzz test case"""
    category: FuzzCategory
    parameter_name: str
    parameter_type: str
    original_value: Any
    fuzz_value: Any
    description: str
    expected_behavior: str


@dataclass
class FuzzResult:
    """Result of a fuzz test"""
    fuzz_case: FuzzCase
    response_code: int
    response_time: float
    response_size: int
    response_body: str
    error_indicators: List[str]
    is_anomaly: bool
    anomaly_reason: str = ""


@dataclass
class FuzzVulnerability:
    """Represents a vulnerability found through fuzzing"""
    issue_type: FuzzIssueType
    risk_level: FuzzRisk
    endpoint: str
    method: str
    fuzz_result: FuzzResult
    evidence: str
    confidence: float


# CWE mappings for fuzz findings
FUZZ_CWE_MAPPINGS = {
    FuzzIssueType.SQL_INJECTION: {'id': 'CWE-89', 'name': 'SQL Injection', 'cvss_base': 9.8},
    FuzzIssueType.XSS: {'id': 'CWE-79', 'name': 'Cross-site Scripting', 'cvss_base': 6.1},
    FuzzIssueType.COMMAND_INJECTION: {'id': 'CWE-78', 'name': 'OS Command Injection', 'cvss_base': 10.0},
    FuzzIssueType.PATH_TRAVERSAL: {'id': 'CWE-22', 'name': 'Path Traversal', 'cvss_base': 7.5},
    FuzzIssueType.ERROR_DISCLOSURE: {'id': 'CWE-209', 'name': 'Error Information Exposure', 'cvss_base': 5.3},
    FuzzIssueType.STACK_TRACE: {'id': 'CWE-209', 'name': 'Stack Trace Exposure', 'cvss_base': 5.3},
    FuzzIssueType.TYPE_CONFUSION: {'id': 'CWE-843', 'name': 'Type Confusion', 'cvss_base': 7.5},
    FuzzIssueType.BUFFER_OVERFLOW: {'id': 'CWE-120', 'name': 'Buffer Overflow', 'cvss_base': 9.8},
    FuzzIssueType.DOS_POTENTIAL: {'id': 'CWE-400', 'name': 'Resource Exhaustion', 'cvss_base': 7.5},
    FuzzIssueType.SCHEMA_BYPASS: {'id': 'CWE-20', 'name': 'Input Validation', 'cvss_base': 6.5},
    FuzzIssueType.VALIDATION_BYPASS: {'id': 'CWE-20', 'name': 'Input Validation', 'cvss_base': 6.5},
    FuzzIssueType.PROTOTYPE_POLLUTION: {'id': 'CWE-1321', 'name': 'Prototype Pollution', 'cvss_base': 8.0},
    FuzzIssueType.MASS_ASSIGNMENT: {'id': 'CWE-915', 'name': 'Mass Assignment', 'cvss_base': 7.5},
    FuzzIssueType.NUMERIC_OVERFLOW: {'id': 'CWE-190', 'name': 'Integer Overflow', 'cvss_base': 7.5},
    FuzzIssueType.FORMAT_STRING: {'id': 'CWE-134', 'name': 'Format String', 'cvss_base': 9.0}
}


# Comprehensive fuzz value sets by type
FUZZ_VALUES = {
    'string': {
        'boundary': [
            '',  # Empty string
            ' ',  # Single space
            '   ',  # Multiple spaces
            '\t\n\r',  # Whitespace characters
            'a',  # Single character
            'a' * 100,  # Medium string
            'a' * 1000,  # Long string
            'a' * 10000,  # Very long string
            'a' * 100000,  # Extremely long string (DoS test)
        ],
        'injection': [
            "'",
            "''",
            '"',
            '`',
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '{{7*7}}',
            '${7*7}',
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system.ini',
            '| ls -la',
            '; cat /etc/passwd',
            '`whoami`',
            '$(id)',
            '%s%s%s%s%s',  # Format string
            '%n%n%n%n%n',  # Format string write
            '%x%x%x%x%x',  # Format string read
        ],
        'encoding': [
            '%00',  # Null byte
            '%0d%0a',  # CRLF
            '%252e%252e%252f',  # Double encoded traversal
            '&#60;script&#62;',  # HTML entities
            '\\u003cscript\\u003e',  # Unicode escape
            '\x00\x00\x00',  # Raw null bytes
            '\xef\xbb\xbf',  # UTF-8 BOM
            '\xff\xfe',  # UTF-16 BOM
        ],
        'type_confusion': [
            'true',
            'false',
            'null',
            'undefined',
            'NaN',
            'Infinity',
            '-Infinity',
            '[]',
            '{}',
            '0',
            '-1',
            '1.5',
            '1e10',
        ],
        'special': [
            'admin',
            'root',
            'system',
            'test',
            'guest',
            'null',
            'nil',
            'none',
            'void',
            '*',
            '?',
            '\\',
            '/',
        ]
    },
    'integer': {
        'boundary': [
            0,
            1,
            -1,
            2147483647,  # Max int32
            -2147483648,  # Min int32
            2147483648,  # Overflow int32
            -2147483649,  # Underflow int32
            9223372036854775807,  # Max int64
            -9223372036854775808,  # Min int64
        ],
        'special': [
            None,
            '',
            'NaN',
            'Infinity',
            1.5,
            '1',
            '-1',
            '0x10',  # Hex
            '0o10',  # Octal
            '0b10',  # Binary
        ],
        'overflow': [
            10**20,
            10**50,
            10**100,
            -(10**20),
            -(10**50),
        ]
    },
    'number': {
        'boundary': [
            0.0,
            1.0,
            -1.0,
            0.1,
            0.01,
            0.001,
            1e-10,
            1e-100,
            1e-308,  # Near min float
            1e308,  # Near max float
            float('inf'),
            float('-inf'),
        ],
        'special': [
            None,
            '',
            'NaN',
            float('nan'),
            1,  # Integer instead of float
            '1.0',
            '-1.0',
            '1e10',
        ]
    },
    'boolean': {
        'values': [
            True,
            False,
            None,
            '',
            0,
            1,
            'true',
            'false',
            'True',
            'False',
            'TRUE',
            'FALSE',
            'yes',
            'no',
            'on',
            'off',
            '1',
            '0',
        ]
    },
    'array': {
        'boundary': [
            [],
            [None],
            [None] * 100,
            [None] * 1000,
            ['a'] * 10000,  # Large array
        ],
        'nested': [
            [[]],
            [[[]]],
            [[[[[]]]]], # Deep nesting
            [{'a': [{'b': [1]}]}],  # Mixed nesting
        ],
        'injection': [
            [{'$gt': ''}],  # NoSQL injection
            [{'__proto__': {'admin': True}}],  # Prototype pollution
            ['<script>alert(1)</script>'],
            ["'; DROP TABLE users; --"],
        ]
    },
    'object': {
        'boundary': [
            {},
            None,
            {'a': None},
        ],
        'injection': [
            {'__proto__': {'admin': True}},
            {'constructor': {'prototype': {'admin': True}}},
            {'__proto__': {'isAdmin': True}},
            {'prototype': {'admin': True}},
        ],
        'mass_assignment': [
            {'role': 'admin'},
            {'is_admin': True},
            {'admin': True},
            {'permissions': ['admin', 'superuser']},
            {'id': 1},
            {'user_id': 1},
            {'created_at': '2000-01-01'},
            {'password': 'hacked'},
            {'email_verified': True},
        ],
        'nested': [
            {'a': {'b': {'c': {'d': {'e': 'deep'}}}}},
            {'x': [{'y': [{'z': 'nested'}]}]},
        ]
    },
    'null': {
        'values': [
            None,
            'null',
            'NULL',
            'Null',
            '',
            0,
            False,
            [],
            {},
        ]
    }
}


# Error indicators by category
ERROR_INDICATORS = {
    'sql': [
        re.compile(r'sql\s*syntax', re.I),
        re.compile(r'mysql_', re.I),
        re.compile(r'mysqli_', re.I),
        re.compile(r'pg_query', re.I),
        re.compile(r'postgresql', re.I),
        re.compile(r'sqlite', re.I),
        re.compile(r'ora-\d{5}', re.I),
        re.compile(r'mssql', re.I),
        re.compile(r'unclosed quotation', re.I),
        re.compile(r'syntax error', re.I),
    ],
    'path_traversal': [
        re.compile(r'root:.*:0:0:', re.I),
        re.compile(r'/bin/bash', re.I),
        re.compile(r'\[boot loader\]', re.I),
        re.compile(r'for 16-bit app support', re.I),
    ],
    'command': [
        re.compile(r'uid=\d+.*gid=\d+', re.I),
        re.compile(r'www-data', re.I),
        re.compile(r'sh: \d+:', re.I),
    ],
    'stack_trace': [
        re.compile(r'Traceback \(most recent call last\)', re.I),
        re.compile(r'at\s+\w+\.\w+\([\w\.]+:\d+\)', re.I),  # Java stack trace
        re.compile(r'File ".*", line \d+', re.I),  # Python stack trace
        re.compile(r'Exception in thread', re.I),
        re.compile(r'NullPointerException', re.I),
        re.compile(r'StackOverflowError', re.I),
        re.compile(r'OutOfMemoryError', re.I),
        re.compile(r'\.php:\d+', re.I),  # PHP error
        re.compile(r'node_modules', re.I),  # Node.js error
    ],
    'error_disclosure': [
        re.compile(r'internal server error', re.I),
        re.compile(r'unexpected error', re.I),
        re.compile(r'debug mode', re.I),
        re.compile(r'development mode', re.I),
        re.compile(r'detailed error', re.I),
        re.compile(r'error occurred', re.I),
    ],
    'template': [
        re.compile(r'\b49\b'),  # 7*7 result
        re.compile(r'jinja2', re.I),
        re.compile(r'template.*error', re.I),
        re.compile(r'undefined variable', re.I),
    ]
}


# Format-specific fuzz values
FORMAT_FUZZ_VALUES = {
    'email': [
        'test@test.com',
        '',
        'invalid',
        'test@',
        '@test.com',
        'test@test',
        'a' * 100 + '@test.com',
        'test@' + 'a' * 100 + '.com',
        'test+tag@test.com',
        'test@test.co.uk',
        '<script>@test.com',
        "'; DROP TABLE--@test.com",
    ],
    'uri': [
        'http://example.com',
        '',
        'invalid',
        'javascript:alert(1)',
        'file:///etc/passwd',
        'http://127.0.0.1',
        'http://169.254.169.254',
        'http://localhost',
        'http://[::1]',
        'http://example.com/' + 'a' * 10000,
    ],
    'date': [
        '2024-01-01',
        '',
        'invalid',
        '0000-00-00',
        '9999-99-99',
        '2024-13-45',
        '2024-01-01T00:00:00Z',
        '-1',
        '0',
    ],
    'date-time': [
        '2024-01-01T00:00:00Z',
        '',
        'invalid',
        '0000-00-00T00:00:00Z',
        '2024-13-45T99:99:99Z',
        '2024-01-01',
    ],
    'uuid': [
        '00000000-0000-0000-0000-000000000000',
        '',
        'invalid',
        'not-a-uuid',
        '00000000-0000-0000-0000-00000000000',  # Too short
        '00000000-0000-0000-0000-0000000000000',  # Too long
    ],
    'ipv4': [
        '0.0.0.0',
        '127.0.0.1',
        '255.255.255.255',
        '999.999.999.999',
        '',
        'invalid',
        '1.2.3',
        '1.2.3.4.5',
    ],
    'ipv6': [
        '::1',
        '::',
        'invalid',
        '',
        '2001:db8::1',
    ]
}


class SchemaFuzzer(FuzzerPlugin):
    """Enterprise-grade schema-driven API fuzzer"""

    plugin_name = "schema_fuzzer"
    description = "Comprehensive API fuzzing using OpenAPI/JSON Schema with intelligent test case generation"
    version = "2.0.0"
    destructive = False

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the schema fuzzer"""
        super().__init__(config)
        self.config = config or {}
        self.tested_endpoints: Set[str] = set()
        self.baseline_responses: Dict[str, Dict] = {}
        self.request_delay = 0.1  # Delay between requests

    async def fuzz(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fuzz API endpoints based on schema"""
        findings = []

        logger.info(f"Starting schema-driven fuzzing for target: {target}")

        # Get configuration
        config = context.get('config', {})
        fuzzer_config = config.get('fuzzers', {}).get('schema', {})

        # Configuration options
        max_cases_per_param = fuzzer_config.get('max_cases_per_param', 20)
        test_all_categories = fuzzer_config.get('test_all_categories', True)
        deep_fuzzing = fuzzer_config.get('deep_fuzzing', False)

        # Get schema and endpoints from context
        schema = context.get('schema', {})
        endpoints = context.get('endpoints', [])

        if not endpoints and target:
            # Generate basic fuzz without schema
            findings.extend(await self._fuzz_without_schema(
                target, max_cases_per_param, context
            ))
        else:
            # Schema-driven fuzzing
            for endpoint in endpoints:
                endpoint_findings = await self._fuzz_endpoint(
                    target, endpoint, schema, max_cases_per_param,
                    test_all_categories, deep_fuzzing, context
                )
                findings.extend(endpoint_findings)

        # Add summary if no issues found
        if not findings:
            findings.append(self._create_no_issues_finding(target, len(endpoints), context))

        logger.info(f"Schema fuzzing complete. Found {len(findings)} findings")

        return findings

    async def _fuzz_without_schema(
        self,
        target: str,
        max_cases: int,
        context: Dict
    ) -> List[Dict]:
        """Basic fuzzing without schema definition"""
        findings = []

        # Common parameter names to test
        common_params = [
            'id', 'user', 'name', 'email', 'search', 'q', 'query',
            'page', 'limit', 'offset', 'sort', 'order', 'filter',
            'file', 'path', 'url', 'redirect', 'callback', 'data'
        ]

        # Get baseline response
        baseline = await self._get_baseline_response(target, 'GET', {}, context)

        # Fuzz each common parameter
        for param in common_params:
            # Select fuzz values based on parameter name
            fuzz_values = self._select_fuzz_values_for_param(param)

            for fuzz_value in fuzz_values[:max_cases]:
                fuzz_case = FuzzCase(
                    category=FuzzCategory.INJECTION if self._is_injection_value(fuzz_value) else FuzzCategory.BOUNDARY,
                    parameter_name=param,
                    parameter_type='string',
                    original_value='',
                    fuzz_value=fuzz_value,
                    description=f"Testing {param} with fuzz value",
                    expected_behavior="Normal response or validation error"
                )

                result = await self._execute_fuzz_case(
                    target, 'GET', fuzz_case, {}, baseline, context
                )

                if result and result.is_anomaly:
                    vuln = self._analyze_fuzz_result(target, 'GET', result)
                    if vuln:
                        findings.append(self._create_finding(vuln, context))

                await asyncio.sleep(self.request_delay)

        return findings

    async def _fuzz_endpoint(
        self,
        base_url: str,
        endpoint: Dict,
        schema: Dict,
        max_cases: int,
        test_all_categories: bool,
        deep_fuzzing: bool,
        context: Dict
    ) -> List[Dict]:
        """Fuzz a specific endpoint based on schema"""
        findings = []

        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET').upper()
        parameters = endpoint.get('parameters', [])
        request_body = endpoint.get('requestBody', {})

        url = f"{base_url.rstrip('/')}{path}"

        # Skip if already tested
        endpoint_key = f"{method}:{url}"
        if endpoint_key in self.tested_endpoints:
            return findings
        self.tested_endpoints.add(endpoint_key)

        # Get baseline response
        baseline = await self._get_baseline_response(url, method, {}, context)

        # Fuzz query/path parameters
        for param in parameters:
            param_findings = await self._fuzz_parameter(
                url, method, param, baseline, max_cases, test_all_categories, context
            )
            findings.extend(param_findings)

        # Fuzz request body
        if request_body and method in ['POST', 'PUT', 'PATCH']:
            body_findings = await self._fuzz_request_body(
                url, method, request_body, baseline, max_cases,
                test_all_categories, deep_fuzzing, context
            )
            findings.extend(body_findings)

        return findings

    async def _fuzz_parameter(
        self,
        url: str,
        method: str,
        param: Dict,
        baseline: Optional[Dict],
        max_cases: int,
        test_all_categories: bool,
        context: Dict
    ) -> List[Dict]:
        """Fuzz a single parameter"""
        findings = []

        param_name = param.get('name', '')
        param_in = param.get('in', 'query')  # query, path, header, cookie
        param_schema = param.get('schema', {})
        param_type = param_schema.get('type', 'string')
        param_format = param_schema.get('format', '')
        param_required = param.get('required', False)

        # Generate fuzz cases
        fuzz_cases = self._generate_fuzz_cases(
            param_name, param_type, param_format, param_required,
            param_schema, test_all_categories
        )

        # Execute fuzz cases
        for case in fuzz_cases[:max_cases]:
            result = await self._execute_fuzz_case(
                url, method, case, {}, baseline, context, param_in
            )

            if result and result.is_anomaly:
                vuln = self._analyze_fuzz_result(url, method, result)
                if vuln:
                    findings.append(self._create_finding(vuln, context))

            await asyncio.sleep(self.request_delay)

        return findings

    async def _fuzz_request_body(
        self,
        url: str,
        method: str,
        request_body: Dict,
        baseline: Optional[Dict],
        max_cases: int,
        test_all_categories: bool,
        deep_fuzzing: bool,
        context: Dict
    ) -> List[Dict]:
        """Fuzz request body based on schema"""
        findings = []

        # Get body schema
        content = request_body.get('content', {})
        json_content = content.get('application/json', {})
        body_schema = json_content.get('schema', {})

        if body_schema.get('type') != 'object':
            return findings

        properties = body_schema.get('properties', {})
        required = body_schema.get('required', [])

        # Generate fuzz cases for each property
        all_cases = []
        for prop_name, prop_schema in properties.items():
            prop_type = prop_schema.get('type', 'string')
            prop_format = prop_schema.get('format', '')
            prop_required = prop_name in required

            cases = self._generate_fuzz_cases(
                prop_name, prop_type, prop_format, prop_required,
                prop_schema, test_all_categories
            )
            all_cases.extend(cases)

        # Add object-level fuzz cases
        all_cases.extend(self._generate_object_fuzz_cases(body_schema))

        # Execute fuzz cases
        for case in all_cases[:max_cases]:
            # Build fuzzed body
            fuzzed_body = self._build_fuzzed_body(properties, case)

            result = await self._execute_body_fuzz(
                url, method, case, fuzzed_body, baseline, context
            )

            if result and result.is_anomaly:
                vuln = self._analyze_fuzz_result(url, method, result)
                if vuln:
                    findings.append(self._create_finding(vuln, context))

            await asyncio.sleep(self.request_delay)

        return findings

    def _generate_fuzz_cases(
        self,
        param_name: str,
        param_type: str,
        param_format: str,
        required: bool,
        schema: Dict,
        test_all_categories: bool
    ) -> List[FuzzCase]:
        """Generate comprehensive fuzz cases for a parameter"""
        cases = []

        # Get type-specific fuzz values
        type_values = FUZZ_VALUES.get(param_type, FUZZ_VALUES.get('string', {}))

        # Get format-specific fuzz values
        format_values = FORMAT_FUZZ_VALUES.get(param_format, [])

        # Boundary tests
        if 'boundary' in type_values:
            for value in type_values['boundary']:
                cases.append(FuzzCase(
                    category=FuzzCategory.BOUNDARY,
                    parameter_name=param_name,
                    parameter_type=param_type,
                    original_value=None,
                    fuzz_value=value,
                    description=f"Boundary test: {str(value)[:30]}",
                    expected_behavior="Validation error or proper handling"
                ))

        # Injection tests
        if 'injection' in type_values and test_all_categories:
            for value in type_values['injection']:
                cases.append(FuzzCase(
                    category=FuzzCategory.INJECTION,
                    parameter_name=param_name,
                    parameter_type=param_type,
                    original_value=None,
                    fuzz_value=value,
                    description=f"Injection test: {str(value)[:30]}",
                    expected_behavior="Input rejected or sanitized"
                ))

        # Type confusion tests
        if 'special' in type_values or 'type_confusion' in type_values:
            confusion_values = type_values.get('special', []) + type_values.get('type_confusion', [])
            for value in confusion_values:
                cases.append(FuzzCase(
                    category=FuzzCategory.TYPE_CONFUSION,
                    parameter_name=param_name,
                    parameter_type=param_type,
                    original_value=None,
                    fuzz_value=value,
                    description=f"Type confusion: {str(value)[:30]}",
                    expected_behavior="Type error or validation"
                ))

        # Format-specific tests
        for value in format_values:
            cases.append(FuzzCase(
                category=FuzzCategory.FORMAT_VIOLATION,
                parameter_name=param_name,
                parameter_type=param_type,
                original_value=None,
                fuzz_value=value,
                description=f"Format test ({param_format}): {str(value)[:30]}",
                expected_behavior="Format validation error"
            ))

        # Null handling tests
        if not required:
            for value in FUZZ_VALUES.get('null', {}).get('values', [None]):
                cases.append(FuzzCase(
                    category=FuzzCategory.NULL_HANDLING,
                    parameter_name=param_name,
                    parameter_type=param_type,
                    original_value=None,
                    fuzz_value=value,
                    description=f"Null test: {str(value)[:30]}",
                    expected_behavior="Null handled gracefully"
                ))

        # Schema constraint tests
        if schema:
            constraint_cases = self._generate_constraint_violation_cases(param_name, param_type, schema)
            cases.extend(constraint_cases)

        return cases

    def _generate_constraint_violation_cases(
        self,
        param_name: str,
        param_type: str,
        schema: Dict
    ) -> List[FuzzCase]:
        """Generate cases that violate schema constraints"""
        cases = []

        # minLength/maxLength violations
        if 'minLength' in schema:
            min_len = schema['minLength']
            if min_len > 0:
                cases.append(FuzzCase(
                    category=FuzzCategory.SCHEMA_VIOLATION,
                    parameter_name=param_name,
                    parameter_type=param_type,
                    original_value=None,
                    fuzz_value='a' * (min_len - 1),
                    description=f"Below minLength ({min_len})",
                    expected_behavior="Validation error"
                ))

        if 'maxLength' in schema:
            max_len = schema['maxLength']
            cases.append(FuzzCase(
                category=FuzzCategory.SCHEMA_VIOLATION,
                parameter_name=param_name,
                parameter_type=param_type,
                original_value=None,
                fuzz_value='a' * (max_len + 1),
                description=f"Above maxLength ({max_len})",
                expected_behavior="Validation error"
            ))

        # minimum/maximum violations
        if 'minimum' in schema:
            min_val = schema['minimum']
            cases.append(FuzzCase(
                category=FuzzCategory.SCHEMA_VIOLATION,
                parameter_name=param_name,
                parameter_type=param_type,
                original_value=None,
                fuzz_value=min_val - 1,
                description=f"Below minimum ({min_val})",
                expected_behavior="Validation error"
            ))

        if 'maximum' in schema:
            max_val = schema['maximum']
            cases.append(FuzzCase(
                category=FuzzCategory.SCHEMA_VIOLATION,
                parameter_name=param_name,
                parameter_type=param_type,
                original_value=None,
                fuzz_value=max_val + 1,
                description=f"Above maximum ({max_val})",
                expected_behavior="Validation error"
            ))

        # Pattern violation
        if 'pattern' in schema:
            cases.append(FuzzCase(
                category=FuzzCategory.SCHEMA_VIOLATION,
                parameter_name=param_name,
                parameter_type=param_type,
                original_value=None,
                fuzz_value='!!!INVALID_PATTERN!!!',
                description="Pattern violation",
                expected_behavior="Validation error"
            ))

        # Enum violation
        if 'enum' in schema:
            cases.append(FuzzCase(
                category=FuzzCategory.SCHEMA_VIOLATION,
                parameter_name=param_name,
                parameter_type=param_type,
                original_value=None,
                fuzz_value='INVALID_ENUM_VALUE',
                description="Invalid enum value",
                expected_behavior="Validation error"
            ))

        return cases

    def _generate_object_fuzz_cases(self, schema: Dict) -> List[FuzzCase]:
        """Generate object-level fuzz cases"""
        cases = []

        # Prototype pollution
        for obj in FUZZ_VALUES.get('object', {}).get('injection', []):
            cases.append(FuzzCase(
                category=FuzzCategory.INJECTION,
                parameter_name='__body__',
                parameter_type='object',
                original_value=None,
                fuzz_value=obj,
                description="Prototype pollution test",
                expected_behavior="Injection blocked"
            ))

        # Mass assignment
        for obj in FUZZ_VALUES.get('object', {}).get('mass_assignment', []):
            cases.append(FuzzCase(
                category=FuzzCategory.BUSINESS_LOGIC,
                parameter_name='__body__',
                parameter_type='object',
                original_value=None,
                fuzz_value=obj,
                description="Mass assignment test",
                expected_behavior="Extra fields ignored"
            ))

        # Empty and null bodies
        cases.append(FuzzCase(
            category=FuzzCategory.BOUNDARY,
            parameter_name='__body__',
            parameter_type='object',
            original_value=None,
            fuzz_value={},
            description="Empty body",
            expected_behavior="Validation error for required fields"
        ))

        cases.append(FuzzCase(
            category=FuzzCategory.NULL_HANDLING,
            parameter_name='__body__',
            parameter_type='object',
            original_value=None,
            fuzz_value=None,
            description="Null body",
            expected_behavior="Null handling"
        ))

        return cases

    def _build_fuzzed_body(self, properties: Dict, fuzz_case: FuzzCase) -> Dict:
        """Build a request body with fuzz value"""
        if fuzz_case.parameter_name == '__body__':
            # Object-level fuzz
            return fuzz_case.fuzz_value if fuzz_case.fuzz_value is not None else {}

        # Property-level fuzz
        body = {}
        for prop_name, prop_schema in properties.items():
            if prop_name == fuzz_case.parameter_name:
                body[prop_name] = fuzz_case.fuzz_value
            else:
                # Use default or sample value
                body[prop_name] = self._get_sample_value(prop_schema)

        return body

    def _get_sample_value(self, schema: Dict) -> Any:
        """Get a valid sample value for a schema"""
        prop_type = schema.get('type', 'string')
        prop_format = schema.get('format', '')

        if 'default' in schema:
            return schema['default']
        if 'example' in schema:
            return schema['example']
        if 'enum' in schema and schema['enum']:
            return schema['enum'][0]

        # Type-based defaults
        defaults = {
            'string': 'test',
            'integer': 1,
            'number': 1.0,
            'boolean': True,
            'array': [],
            'object': {}
        }

        # Format-based defaults
        format_defaults = {
            'email': 'test@example.com',
            'uri': 'http://example.com',
            'date': '2024-01-01',
            'date-time': '2024-01-01T00:00:00Z',
            'uuid': '00000000-0000-0000-0000-000000000000'
        }

        if prop_format in format_defaults:
            return format_defaults[prop_format]

        return defaults.get(prop_type, 'test')

    async def _get_baseline_response(
        self,
        url: str,
        method: str,
        body: Dict,
        context: Dict
    ) -> Optional[Dict]:
        """Get baseline response for comparison"""
        try:
            async with safe_http_client(context.get('config', {})) as client:
                if method == 'GET':
                    response = await client.get(url)
                elif method == 'POST':
                    response = await client.post(url, json=body or {})
                else:
                    response = await client.request(method, url, json=body)

                content = await response.text() if hasattr(response, 'text') else ''

                return {
                    'status_code': response.status_code,
                    'content_length': len(content),
                    'content_type': response.headers.get('content-type', ''),
                    'response_time': 0  # Would need timing
                }
        except Exception as e:
            logger.debug(f"Error getting baseline: {e}")
            return None

    async def _execute_fuzz_case(
        self,
        url: str,
        method: str,
        case: FuzzCase,
        body: Dict,
        baseline: Optional[Dict],
        context: Dict,
        param_in: str = 'query'
    ) -> Optional[FuzzResult]:
        """Execute a single fuzz case"""
        try:
            async with safe_http_client(context.get('config', {})) as client:
                # Build request based on parameter location
                if param_in == 'query':
                    fuzz_url = f"{url}?{case.parameter_name}={case.fuzz_value}"
                    if method == 'GET':
                        response = await client.get(fuzz_url)
                    else:
                        response = await client.request(method, fuzz_url, json=body)
                else:
                    if method == 'GET':
                        response = await client.get(url)
                    else:
                        response = await client.request(method, url, json=body)

                content = await response.text() if hasattr(response, 'text') else ''

                # Find error indicators
                error_indicators = self._find_error_indicators(content)

                # Determine if this is an anomaly
                is_anomaly, reason = self._is_anomalous_response(
                    response.status_code, len(content), content, baseline, case
                )

                return FuzzResult(
                    fuzz_case=case,
                    response_code=response.status_code,
                    response_time=0,
                    response_size=len(content),
                    response_body=content[:2000],  # Truncate
                    error_indicators=error_indicators,
                    is_anomaly=is_anomaly,
                    anomaly_reason=reason
                )

        except Exception as e:
            logger.debug(f"Error executing fuzz case: {e}")
            return None

    async def _execute_body_fuzz(
        self,
        url: str,
        method: str,
        case: FuzzCase,
        body: Any,
        baseline: Optional[Dict],
        context: Dict
    ) -> Optional[FuzzResult]:
        """Execute a body fuzz case"""
        try:
            async with safe_http_client(context.get('config', {})) as client:
                if body is None:
                    response = await client.request(method, url)
                else:
                    response = await client.request(method, url, json=body)

                content = await response.text() if hasattr(response, 'text') else ''

                error_indicators = self._find_error_indicators(content)

                is_anomaly, reason = self._is_anomalous_response(
                    response.status_code, len(content), content, baseline, case
                )

                return FuzzResult(
                    fuzz_case=case,
                    response_code=response.status_code,
                    response_time=0,
                    response_size=len(content),
                    response_body=content[:2000],
                    error_indicators=error_indicators,
                    is_anomaly=is_anomaly,
                    anomaly_reason=reason
                )

        except Exception as e:
            logger.debug(f"Error executing body fuzz: {e}")
            return None

    def _find_error_indicators(self, content: str) -> List[str]:
        """Find error indicators in response"""
        indicators = []

        for category, patterns in ERROR_INDICATORS.items():
            for pattern in patterns:
                if pattern.search(content):
                    indicators.append(f"{category}:{pattern.pattern[:30]}")

        return indicators

    def _is_anomalous_response(
        self,
        status_code: int,
        content_length: int,
        content: str,
        baseline: Optional[Dict],
        case: FuzzCase
    ) -> Tuple[bool, str]:
        """Determine if response is anomalous"""
        # Server error with potential info disclosure
        if status_code == 500:
            if any(pattern.search(content) for patterns in ERROR_INDICATORS.values() for pattern in patterns):
                return True, "Server error with potential information disclosure"

        # SQL error indicators
        for pattern in ERROR_INDICATORS.get('sql', []):
            if pattern.search(content):
                return True, "SQL error indicator found"

        # Path traversal indicators
        for pattern in ERROR_INDICATORS.get('path_traversal', []):
            if pattern.search(content):
                return True, "Path traversal indicator found"

        # Command injection indicators
        for pattern in ERROR_INDICATORS.get('command', []):
            if pattern.search(content):
                return True, "Command injection indicator found"

        # Template injection indicators
        for pattern in ERROR_INDICATORS.get('template', []):
            if pattern.search(content):
                return True, "Template injection indicator found"

        # XSS reflection
        if case.category == FuzzCategory.INJECTION:
            fuzz_str = str(case.fuzz_value)
            if '<script>' in fuzz_str and '<script>' in content:
                return True, "XSS payload reflected"
            if '{{' in fuzz_str and '49' in content:  # 7*7
                return True, "Template injection result"

        # Significant size difference from baseline
        if baseline:
            baseline_size = baseline.get('content_length', 0)
            if baseline_size > 0:
                size_ratio = content_length / baseline_size
                if size_ratio > 10 or size_ratio < 0.1:
                    return True, f"Unusual response size: {content_length} vs baseline {baseline_size}"

        return False, ""

    def _select_fuzz_values_for_param(self, param_name: str) -> List[Any]:
        """Select appropriate fuzz values based on parameter name"""
        values = []

        # Add string injection values
        values.extend(FUZZ_VALUES['string'].get('injection', []))

        # Add boundary values
        values.extend(FUZZ_VALUES['string'].get('boundary', [])[:5])

        # Add type confusion
        values.extend(FUZZ_VALUES['string'].get('type_confusion', [])[:5])

        # Context-specific values
        if any(x in param_name.lower() for x in ['id', 'num', 'count', 'limit', 'offset']):
            values.extend(FUZZ_VALUES['integer'].get('boundary', []))

        if any(x in param_name.lower() for x in ['email']):
            values.extend(FORMAT_FUZZ_VALUES.get('email', []))

        if any(x in param_name.lower() for x in ['url', 'uri', 'link', 'redirect']):
            values.extend(FORMAT_FUZZ_VALUES.get('uri', []))

        if any(x in param_name.lower() for x in ['file', 'path']):
            values.extend([
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system.ini',
                '/etc/passwd',
                'C:\\Windows\\System32\\drivers\\etc\\hosts'
            ])

        return values

    def _is_injection_value(self, value: Any) -> bool:
        """Check if value is an injection payload"""
        if not isinstance(value, str):
            return False

        injection_indicators = ["'", '"', '<script>', '{{', '${', '../', '|', ';', '`']
        return any(ind in str(value) for ind in injection_indicators)

    def _analyze_fuzz_result(
        self,
        url: str,
        method: str,
        result: FuzzResult
    ) -> Optional[FuzzVulnerability]:
        """Analyze fuzz result and determine vulnerability type"""
        issue_type = None
        risk_level = FuzzRisk.INFO
        confidence = 0.5

        # Determine issue type based on indicators and case
        if any('sql' in ind.lower() for ind in result.error_indicators):
            issue_type = FuzzIssueType.SQL_INJECTION
            risk_level = FuzzRisk.CRITICAL
            confidence = 0.8

        elif any('path_traversal' in ind.lower() for ind in result.error_indicators):
            issue_type = FuzzIssueType.PATH_TRAVERSAL
            risk_level = FuzzRisk.CRITICAL
            confidence = 0.85

        elif any('command' in ind.lower() for ind in result.error_indicators):
            issue_type = FuzzIssueType.COMMAND_INJECTION
            risk_level = FuzzRisk.CRITICAL
            confidence = 0.85

        elif any('template' in ind.lower() for ind in result.error_indicators):
            issue_type = FuzzIssueType.ERROR_DISCLOSURE
            risk_level = FuzzRisk.HIGH
            confidence = 0.7

        elif 'XSS' in result.anomaly_reason or 'reflected' in result.anomaly_reason.lower():
            issue_type = FuzzIssueType.XSS
            risk_level = FuzzRisk.HIGH
            confidence = 0.75

        elif any('stack_trace' in ind.lower() for ind in result.error_indicators):
            issue_type = FuzzIssueType.STACK_TRACE
            risk_level = FuzzRisk.MEDIUM
            confidence = 0.9

        elif result.response_code == 500:
            issue_type = FuzzIssueType.ERROR_DISCLOSURE
            risk_level = FuzzRisk.MEDIUM
            confidence = 0.6

        elif 'size' in result.anomaly_reason.lower():
            issue_type = FuzzIssueType.DOS_POTENTIAL
            risk_level = FuzzRisk.LOW
            confidence = 0.4

        if issue_type is None:
            return None

        return FuzzVulnerability(
            issue_type=issue_type,
            risk_level=risk_level,
            endpoint=url,
            method=method,
            fuzz_result=result,
            evidence=f"Anomaly: {result.anomaly_reason}. Indicators: {', '.join(result.error_indicators[:3])}",
            confidence=confidence
        )

    def _create_finding(
        self,
        vuln: FuzzVulnerability,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding dictionary from vulnerability"""
        cwe_info = FUZZ_CWE_MAPPINGS.get(
            vuln.issue_type,
            FUZZ_CWE_MAPPINGS[FuzzIssueType.ERROR_DISCLOSURE]
        )

        # Adjust CVSS based on confidence
        cvss_base = cwe_info['cvss_base']
        if vuln.confidence < 0.7:
            cvss_base = cvss_base * 0.8

        # Build evidence
        evidence_parts = [
            f"Parameter: {vuln.fuzz_result.fuzz_case.parameter_name}",
            f"Fuzz value: {str(vuln.fuzz_result.fuzz_case.fuzz_value)[:100]}",
            f"Response code: {vuln.fuzz_result.response_code}",
            f"Anomaly: {vuln.fuzz_result.anomaly_reason}"
        ]

        if vuln.fuzz_result.error_indicators:
            evidence_parts.append(f"Indicators: {', '.join(vuln.fuzz_result.error_indicators[:5])}")

        # Create fingerprint
        fingerprint_data = f"{vuln.endpoint}:{vuln.method}:{vuln.fuzz_result.fuzz_case.parameter_name}:{vuln.issue_type.value}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        # Severity mapping
        severity_map = {
            FuzzRisk.CRITICAL: 'critical',
            FuzzRisk.HIGH: 'high',
            FuzzRisk.MEDIUM: 'medium',
            FuzzRisk.LOW: 'low',
            FuzzRisk.INFO: 'info'
        }

        # Get recommendations
        recommendations = self._get_recommendations(vuln.issue_type)

        return {
            'issue': self._get_issue_title(vuln.issue_type),
            'description': self._get_issue_description(vuln.issue_type, vuln),
            'severity': severity_map[vuln.risk_level],
            'category': 'Fuzzing',
            'endpoint': vuln.endpoint,
            'method': vuln.method,
            'evidence': '\n'.join(evidence_parts),
            'cwe_id': cwe_info['id'],
            'cwe_name': cwe_info['name'],
            'cvss_score': round(cvss_base, 1),
            'recommendation': '\n'.join([f"• {r}" for r in recommendations]),
            'issue_type': vuln.issue_type.value,
            'fuzz_category': vuln.fuzz_result.fuzz_case.category.value,
            'parameter_name': vuln.fuzz_result.fuzz_case.parameter_name,
            'fuzz_value': str(vuln.fuzz_result.fuzz_case.fuzz_value)[:100],
            'confidence': round(vuln.confidence * 100, 1),
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def _get_issue_title(self, issue_type: FuzzIssueType) -> str:
        """Get human-readable title"""
        titles = {
            FuzzIssueType.SQL_INJECTION: 'Potential SQL Injection',
            FuzzIssueType.XSS: 'Potential Cross-Site Scripting (XSS)',
            FuzzIssueType.COMMAND_INJECTION: 'Potential Command Injection',
            FuzzIssueType.PATH_TRAVERSAL: 'Potential Path Traversal',
            FuzzIssueType.ERROR_DISCLOSURE: 'Error Information Disclosure',
            FuzzIssueType.STACK_TRACE: 'Stack Trace Exposure',
            FuzzIssueType.TYPE_CONFUSION: 'Type Confusion Vulnerability',
            FuzzIssueType.BUFFER_OVERFLOW: 'Potential Buffer Overflow',
            FuzzIssueType.DOS_POTENTIAL: 'Denial of Service Potential',
            FuzzIssueType.SCHEMA_BYPASS: 'Schema Validation Bypass',
            FuzzIssueType.VALIDATION_BYPASS: 'Input Validation Bypass',
            FuzzIssueType.PROTOTYPE_POLLUTION: 'Prototype Pollution',
            FuzzIssueType.MASS_ASSIGNMENT: 'Mass Assignment Vulnerability',
            FuzzIssueType.NUMERIC_OVERFLOW: 'Numeric Overflow',
            FuzzIssueType.FORMAT_STRING: 'Format String Vulnerability'
        }
        return titles.get(issue_type, 'Security Issue Detected')

    def _get_issue_description(self, issue_type: FuzzIssueType, vuln: FuzzVulnerability) -> str:
        """Get detailed description"""
        param = vuln.fuzz_result.fuzz_case.parameter_name
        descriptions = {
            FuzzIssueType.SQL_INJECTION: f"Schema-driven fuzzing detected a potential SQL injection vulnerability in the '{param}' parameter. The application returned error messages indicating SQL syntax issues when malformed input was provided.",
            FuzzIssueType.XSS: f"Fuzzing detected potential cross-site scripting in the '{param}' parameter. Injected script content was reflected in the response without proper encoding.",
            FuzzIssueType.COMMAND_INJECTION: f"Fuzzing detected potential command injection in the '{param}' parameter. The response contained indicators of command execution.",
            FuzzIssueType.PATH_TRAVERSAL: f"Fuzzing detected potential path traversal in the '{param}' parameter. The application may allow access to files outside the intended directory.",
            FuzzIssueType.ERROR_DISCLOSURE: f"The application exposed detailed error information when the '{param}' parameter received unexpected input. This information could help attackers understand the application's internals.",
            FuzzIssueType.STACK_TRACE: f"The application exposed a stack trace when the '{param}' parameter received malformed input. Stack traces reveal implementation details useful for attackers.",
            FuzzIssueType.DOS_POTENTIAL: f"Fuzzing detected unusual response behavior in the '{param}' parameter that could indicate denial of service potential.",
        }
        return descriptions.get(issue_type, f"A security issue was detected in the '{param}' parameter through schema-driven fuzzing.")

    def _get_recommendations(self, issue_type: FuzzIssueType) -> List[str]:
        """Get recommendations"""
        recommendations = {
            FuzzIssueType.SQL_INJECTION: [
                "Use parameterized queries (prepared statements)",
                "Implement input validation with allowlists",
                "Use an ORM framework",
                "Apply least privilege to database accounts"
            ],
            FuzzIssueType.XSS: [
                "Implement context-aware output encoding",
                "Use Content-Security-Policy headers",
                "Sanitize user input before display",
                "Use HTTPOnly and Secure cookie flags"
            ],
            FuzzIssueType.COMMAND_INJECTION: [
                "Avoid using system commands with user input",
                "Use language-specific APIs instead of shell",
                "Implement strict input validation",
                "Run with minimal privileges"
            ],
            FuzzIssueType.PATH_TRAVERSAL: [
                "Validate file paths against allowlist",
                "Use canonical paths and check boundaries",
                "Implement proper access controls",
                "Use chroot or containerization"
            ],
            FuzzIssueType.ERROR_DISCLOSURE: [
                "Implement custom error pages",
                "Log detailed errors server-side only",
                "Return generic error messages to clients",
                "Disable debug mode in production"
            ],
            FuzzIssueType.STACK_TRACE: [
                "Configure error handling to suppress stack traces",
                "Use exception handlers that log but don't expose details",
                "Implement global exception handling",
                "Test error conditions before deployment"
            ],
            FuzzIssueType.DOS_POTENTIAL: [
                "Implement input length limits",
                "Add rate limiting",
                "Set request timeouts",
                "Monitor resource usage"
            ]
        }
        return recommendations.get(issue_type, recommendations[FuzzIssueType.ERROR_DISCLOSURE])

    def _create_no_issues_finding(
        self,
        target: str,
        endpoint_count: int,
        context: Dict
    ) -> Dict[str, Any]:
        """Create finding when no issues detected"""
        fingerprint = hashlib.sha256(f"schema_fuzz_complete:{target}".encode()).hexdigest()[:16]

        return {
            'issue': 'Schema Fuzzing Assessment Complete',
            'description': f"Schema-driven fuzzing completed for {endpoint_count} endpoint(s). No vulnerabilities were detected. The API appears to handle malformed input appropriately.",
            'severity': 'info',
            'category': 'Fuzzing',
            'endpoint': target,
            'method': 'GET',
            'evidence': f"Tested {len(self.tested_endpoints)} endpoints with comprehensive fuzz cases including boundary, injection, type confusion, and schema violation tests.",
            'cwe_id': 'N/A',
            'cwe_name': 'No Issues Detected',
            'cvss_score': 0.0,
            'recommendation': '• Continue regular security assessments\n• Implement comprehensive input validation\n• Add schema validation middleware\n• Monitor for anomalous requests',
            'issue_type': 'assessment_complete',
            'endpoints_tested': len(self.tested_endpoints),
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def get_fuzzing_summary(self) -> Dict[str, Any]:
        """Generate fuzzing summary"""
        return {
            'endpoints_tested': len(self.tested_endpoints),
            'fuzz_categories': [c.value for c in FuzzCategory],
            'issue_types_checked': [t.value for t in FuzzIssueType],
            'type_specific_values': list(FUZZ_VALUES.keys()),
            'format_specific_values': list(FORMAT_FUZZ_VALUES.keys())
        }
