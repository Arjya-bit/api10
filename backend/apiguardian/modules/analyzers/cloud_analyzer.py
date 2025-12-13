"""Cloud Security Analyzer - Enterprise-grade AWS/GCP/Azure/multi-cloud security analysis"""
import re
import logging
import hashlib
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

from apiguardian.core.plugin_manager import AnalyzerPlugin
from apiguardian.utils.http_client import safe_http_client, HTTPResponse

logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    DIGITAL_OCEAN = "digitalocean"
    ALIBABA = "alibaba"
    ORACLE = "oracle"
    CLOUDFLARE = "cloudflare"
    HEROKU = "heroku"
    VERCEL = "vercel"
    GENERIC = "generic"


class CloudRiskLevel(Enum):
    """Risk levels for cloud security issues"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CloudIssueType(Enum):
    """Types of cloud security issues"""
    CREDENTIAL_EXPOSURE = "credential_exposure"
    MISCONFIGURATION = "misconfiguration"
    PUBLIC_BUCKET = "public_bucket"
    METADATA_EXPOSURE = "metadata_exposure"
    INSECURE_STORAGE = "insecure_storage"
    SSRF_VULNERABLE = "ssrf_vulnerable"
    HARDCODED_SECRET = "hardcoded_secret"
    IAM_ISSUE = "iam_issue"
    NETWORK_EXPOSURE = "network_exposure"
    LOGGING_DISABLED = "logging_disabled"
    ENCRYPTION_DISABLED = "encryption_disabled"


@dataclass
class CloudCredential:
    """Represents a detected cloud credential"""
    provider: CloudProvider
    credential_type: str
    pattern_name: str
    masked_value: str
    full_value: str  # For internal processing only
    location: str  # headers, body, url
    line_number: Optional[int] = None
    confidence: float = 1.0


@dataclass
class CloudResource:
    """Represents a detected cloud resource"""
    provider: CloudProvider
    resource_type: str
    resource_url: str
    is_public: bool = False
    permissions: List[str] = field(default_factory=list)


@dataclass
class CloudVulnerability:
    """Represents a cloud security vulnerability"""
    issue_type: CloudIssueType
    risk_level: CloudRiskLevel
    provider: CloudProvider
    endpoint: str
    method: str
    credential: Optional[CloudCredential] = None
    resource: Optional[CloudResource] = None
    evidence: str = ""
    confidence: float = 0.0


# CWE mappings for cloud issues
CLOUD_CWE_MAPPINGS = {
    CloudIssueType.CREDENTIAL_EXPOSURE: {
        'id': 'CWE-798',
        'name': 'Use of Hard-coded Credentials',
        'cvss_base': 9.0
    },
    CloudIssueType.MISCONFIGURATION: {
        'id': 'CWE-16',
        'name': 'Configuration',
        'cvss_base': 7.0
    },
    CloudIssueType.PUBLIC_BUCKET: {
        'id': 'CWE-284',
        'name': 'Improper Access Control',
        'cvss_base': 7.5
    },
    CloudIssueType.METADATA_EXPOSURE: {
        'id': 'CWE-918',
        'name': 'Server-Side Request Forgery (SSRF)',
        'cvss_base': 8.0
    },
    CloudIssueType.INSECURE_STORAGE: {
        'id': 'CWE-311',
        'name': 'Missing Encryption of Sensitive Data',
        'cvss_base': 6.5
    },
    CloudIssueType.SSRF_VULNERABLE: {
        'id': 'CWE-918',
        'name': 'Server-Side Request Forgery (SSRF)',
        'cvss_base': 8.5
    },
    CloudIssueType.HARDCODED_SECRET: {
        'id': 'CWE-798',
        'name': 'Use of Hard-coded Credentials',
        'cvss_base': 9.0
    },
    CloudIssueType.IAM_ISSUE: {
        'id': 'CWE-269',
        'name': 'Improper Privilege Management',
        'cvss_base': 7.5
    },
    CloudIssueType.NETWORK_EXPOSURE: {
        'id': 'CWE-284',
        'name': 'Improper Access Control',
        'cvss_base': 7.0
    },
    CloudIssueType.LOGGING_DISABLED: {
        'id': 'CWE-778',
        'name': 'Insufficient Logging',
        'cvss_base': 4.0
    },
    CloudIssueType.ENCRYPTION_DISABLED: {
        'id': 'CWE-311',
        'name': 'Missing Encryption of Sensitive Data',
        'cvss_base': 6.5
    }
}


# Comprehensive cloud credential patterns
CLOUD_CREDENTIAL_PATTERNS = {
    CloudProvider.AWS: [
        {
            'pattern': re.compile(r'((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})'),
            'name': 'AWS Access Key ID',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'AWS IAM access key identifier'
        },
        {
            'pattern': re.compile(r'(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.I),
            'name': 'AWS Secret Access Key',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'AWS IAM secret access key'
        },
        {
            'pattern': re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
            'name': 'AWS MWS Auth Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Amazon Marketplace Web Service token'
        },
        {
            'pattern': re.compile(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-z0-9-/]+'),
            'name': 'AWS ARN',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'AWS Resource Name exposing account structure'
        },
        {
            'pattern': re.compile(r'([a-zA-Z0-9-_.]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com)'),
            'name': 'AWS S3 Bucket URL',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'AWS S3 bucket endpoint'
        },
        {
            'pattern': re.compile(r's3://([a-zA-Z0-9._-]+)'),
            'name': 'AWS S3 URI',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'AWS S3 bucket URI'
        },
        {
            'pattern': re.compile(r'([a-z0-9-]+)\.execute-api\.[a-z0-9-]+\.amazonaws\.com'),
            'name': 'AWS API Gateway Endpoint',
            'severity': CloudRiskLevel.LOW,
            'description': 'AWS API Gateway endpoint'
        },
        {
            'pattern': re.compile(r'([a-z0-9-]+)\.lambda-url\.[a-z0-9-]+\.on\.aws'),
            'name': 'AWS Lambda Function URL',
            'severity': CloudRiskLevel.LOW,
            'description': 'AWS Lambda function URL'
        },
        {
            'pattern': re.compile(r'([a-z0-9-]+)\.[a-z0-9-]+\.rds\.amazonaws\.com'),
            'name': 'AWS RDS Endpoint',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'AWS RDS database endpoint'
        },
        {
            'pattern': re.compile(r'([a-z0-9-]+)\.cache\.amazonaws\.com'),
            'name': 'AWS ElastiCache Endpoint',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'AWS ElastiCache endpoint'
        }
    ],
    CloudProvider.GCP: [
        {
            'pattern': re.compile(r'AIza[0-9A-Za-z_-]{35}'),
            'name': 'Google API Key',
            'severity': CloudRiskLevel.HIGH,
            'description': 'Google Cloud API key'
        },
        {
            'pattern': re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
            'name': 'GCP OAuth Client ID',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'Google Cloud OAuth 2.0 client ID'
        },
        {
            'pattern': re.compile(r'ya29\.[0-9A-Za-z_-]+'),
            'name': 'GCP OAuth Access Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Google Cloud OAuth access token'
        },
        {
            'pattern': re.compile(r'[0-9a-f]{64}-compute@developer\.gserviceaccount\.com'),
            'name': 'GCP Service Account',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'Google Cloud service account email'
        },
        {
            'pattern': re.compile(r'storage\.googleapis\.com/([a-zA-Z0-9._-]+)'),
            'name': 'GCP Storage Bucket',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'Google Cloud Storage bucket'
        },
        {
            'pattern': re.compile(r'([a-z0-9-]+)\.cloudfunctions\.net'),
            'name': 'GCP Cloud Function',
            'severity': CloudRiskLevel.LOW,
            'description': 'Google Cloud Function endpoint'
        },
        {
            'pattern': re.compile(r'([a-z0-9-]+)\.appspot\.com'),
            'name': 'GCP App Engine',
            'severity': CloudRiskLevel.LOW,
            'description': 'Google App Engine application'
        },
        {
            'pattern': re.compile(r'([a-z0-9-]+)-[a-z0-9]+\.run\.app'),
            'name': 'GCP Cloud Run',
            'severity': CloudRiskLevel.LOW,
            'description': 'Google Cloud Run service'
        }
    ],
    CloudProvider.AZURE: [
        {
            'pattern': re.compile(r'AccountKey=([A-Za-z0-9+/=]{88})'),
            'name': 'Azure Storage Account Key',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Azure Storage account access key'
        },
        {
            'pattern': re.compile(r'DefaultEndpointsProtocol=https?;AccountName=([^;]+);AccountKey='),
            'name': 'Azure Connection String',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Azure Storage connection string'
        },
        {
            'pattern': re.compile(r'https://([a-zA-Z0-9_-]+)\.blob\.core\.windows\.net'),
            'name': 'Azure Blob Storage',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'Azure Blob Storage endpoint'
        },
        {
            'pattern': re.compile(r'https://([a-zA-Z0-9_-]+)\.table\.core\.windows\.net'),
            'name': 'Azure Table Storage',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'Azure Table Storage endpoint'
        },
        {
            'pattern': re.compile(r'https://([a-zA-Z0-9_-]+)\.queue\.core\.windows\.net'),
            'name': 'Azure Queue Storage',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'Azure Queue Storage endpoint'
        },
        {
            'pattern': re.compile(r'https://([a-zA-Z0-9_-]+)\.file\.core\.windows\.net'),
            'name': 'Azure File Storage',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'Azure File Storage endpoint'
        },
        {
            'pattern': re.compile(r'https://([a-zA-Z0-9_-]+)\.azurewebsites\.net'),
            'name': 'Azure Web App',
            'severity': CloudRiskLevel.LOW,
            'description': 'Azure App Service endpoint'
        },
        {
            'pattern': re.compile(r'https://([a-zA-Z0-9_-]+)\.database\.windows\.net'),
            'name': 'Azure SQL Database',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'Azure SQL Database endpoint'
        },
        {
            'pattern': re.compile(r'https://([a-zA-Z0-9_-]+)\.vault\.azure\.net'),
            'name': 'Azure Key Vault',
            'severity': CloudRiskLevel.HIGH,
            'description': 'Azure Key Vault endpoint'
        },
        {
            'pattern': re.compile(r'https://([a-zA-Z0-9_-]+)\.servicebus\.windows\.net'),
            'name': 'Azure Service Bus',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'Azure Service Bus endpoint'
        }
    ],
    CloudProvider.GENERIC: [
        {
            'pattern': re.compile(r'sk-[A-Za-z0-9]{48}'),
            'name': 'OpenAI API Key',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'OpenAI API access key'
        },
        {
            'pattern': re.compile(r'sk-ant-api03-[A-Za-z0-9_-]{95}'),
            'name': 'Anthropic API Key',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Anthropic Claude API key'
        },
        {
            'pattern': re.compile(r'ghp_[A-Za-z0-9]{36}'),
            'name': 'GitHub Personal Access Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'GitHub personal access token'
        },
        {
            'pattern': re.compile(r'gho_[A-Za-z0-9]{36}'),
            'name': 'GitHub OAuth Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'GitHub OAuth access token'
        },
        {
            'pattern': re.compile(r'ghs_[A-Za-z0-9]{36}'),
            'name': 'GitHub App Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'GitHub App installation token'
        },
        {
            'pattern': re.compile(r'ghr_[A-Za-z0-9]{36}'),
            'name': 'GitHub Refresh Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'GitHub refresh token'
        },
        {
            'pattern': re.compile(r'glpat-[A-Za-z0-9_-]{20}'),
            'name': 'GitLab Personal Access Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'GitLab personal access token'
        },
        {
            'pattern': re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
            'name': 'Slack Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Slack API token'
        },
        {
            'pattern': re.compile(r'xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[a-f0-9]+'),
            'name': 'Slack App Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Slack app-level token'
        },
        {
            'pattern': re.compile(r'sq0atp-[A-Za-z0-9_-]{22}'),
            'name': 'Square Access Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Square payment access token'
        },
        {
            'pattern': re.compile(r'sq0csp-[A-Za-z0-9_-]{43}'),
            'name': 'Square OAuth Secret',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Square OAuth secret'
        },
        {
            'pattern': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
            'name': 'Stripe Live Secret Key',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Stripe live mode secret key'
        },
        {
            'pattern': re.compile(r'sk_test_[0-9a-zA-Z]{24}'),
            'name': 'Stripe Test Secret Key',
            'severity': CloudRiskLevel.HIGH,
            'description': 'Stripe test mode secret key'
        },
        {
            'pattern': re.compile(r'pk_live_[0-9a-zA-Z]{24}'),
            'name': 'Stripe Live Publishable Key',
            'severity': CloudRiskLevel.LOW,
            'description': 'Stripe live mode publishable key'
        },
        {
            'pattern': re.compile(r'rk_live_[0-9a-zA-Z]{24}'),
            'name': 'Stripe Restricted Key',
            'severity': CloudRiskLevel.HIGH,
            'description': 'Stripe restricted API key'
        },
        {
            'pattern': re.compile(r'key-[a-zA-Z0-9]{32}'),
            'name': 'Mailgun API Key',
            'severity': CloudRiskLevel.HIGH,
            'description': 'Mailgun API key'
        },
        {
            'pattern': re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
            'name': 'SendGrid API Key',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'SendGrid API key'
        },
        {
            'pattern': re.compile(r'AC[a-z0-9]{32}'),
            'name': 'Twilio Account SID',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'Twilio account identifier'
        },
        {
            'pattern': re.compile(r'[a-f0-9]{32}', re.I),
            'name': 'Twilio Auth Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Twilio authentication token (potential)',
            'confidence': 0.5  # Lower confidence for generic pattern
        },
        {
            'pattern': re.compile(r'EAACEdEose0cBA[A-Za-z0-9]+'),
            'name': 'Facebook Access Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Facebook access token'
        },
        {
            'pattern': re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
            'name': 'JWT Token',
            'severity': CloudRiskLevel.HIGH,
            'description': 'JSON Web Token (may contain sensitive claims)'
        },
        {
            'pattern': re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
            'name': 'Private Key',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'Private key in PEM format'
        },
        {
            'pattern': re.compile(r'-----BEGIN CERTIFICATE-----'),
            'name': 'Certificate',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'X.509 certificate'
        }
    ],
    CloudProvider.DIGITAL_OCEAN: [
        {
            'pattern': re.compile(r'dop_v1_[a-f0-9]{64}'),
            'name': 'DigitalOcean Personal Access Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'DigitalOcean API token'
        },
        {
            'pattern': re.compile(r'doo_v1_[a-f0-9]{64}'),
            'name': 'DigitalOcean OAuth Token',
            'severity': CloudRiskLevel.CRITICAL,
            'description': 'DigitalOcean OAuth token'
        },
        {
            'pattern': re.compile(r'([a-z0-9-]+)\.digitaloceanspaces\.com'),
            'name': 'DigitalOcean Spaces',
            'severity': CloudRiskLevel.MEDIUM,
            'description': 'DigitalOcean Spaces endpoint'
        }
    ],
    CloudProvider.HEROKU: [
        {
            'pattern': re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
            'name': 'Heroku API Key',
            'severity': CloudRiskLevel.HIGH,
            'description': 'Heroku API key (UUID format)',
            'confidence': 0.5
        },
        {
            'pattern': re.compile(r'([a-z0-9-]+)\.herokuapp\.com'),
            'name': 'Heroku App',
            'severity': CloudRiskLevel.LOW,
            'description': 'Heroku application endpoint'
        }
    ],
    CloudProvider.CLOUDFLARE: [
        {
            'pattern': re.compile(r'([a-z0-9]+)\.workers\.dev'),
            'name': 'Cloudflare Worker',
            'severity': CloudRiskLevel.LOW,
            'description': 'Cloudflare Worker endpoint'
        },
        {
            'pattern': re.compile(r'([a-z0-9-]+)\.pages\.dev'),
            'name': 'Cloudflare Pages',
            'severity': CloudRiskLevel.LOW,
            'description': 'Cloudflare Pages deployment'
        }
    ],
    CloudProvider.VERCEL: [
        {
            'pattern': re.compile(r'([a-z0-9-]+)\.vercel\.app'),
            'name': 'Vercel Deployment',
            'severity': CloudRiskLevel.LOW,
            'description': 'Vercel deployment endpoint'
        }
    ]
}


# Cloud metadata endpoints for SSRF detection
METADATA_ENDPOINTS = {
    CloudProvider.AWS: [
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/latest/dynamic/instance-identity/document',
        'http://[fd00:ec2::254]/latest/meta-data/'
    ],
    CloudProvider.GCP: [
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.169.254/computeMetadata/v1/',
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
    ],
    CloudProvider.AZURE: [
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'http://169.254.169.254/metadata/identity/oauth2/token'
    ],
    CloudProvider.DIGITAL_OCEAN: [
        'http://169.254.169.254/metadata/v1/'
    ],
    CloudProvider.ALIBABA: [
        'http://100.100.100.200/latest/meta-data/'
    ],
    CloudProvider.ORACLE: [
        'http://169.254.169.254/opc/v1/instance/'
    ]
}


# Cloud provider detection headers
PROVIDER_HEADERS = {
    CloudProvider.AWS: [
        ('server', ['amazons3', 'awselb', 'amazon', 'cloudfront']),
        ('x-amz-', None),  # Any header starting with x-amz-
        ('x-amzn-', None)
    ],
    CloudProvider.GCP: [
        ('server', ['google', 'gws', 'gfe']),
        ('x-goog-', None),
        ('x-cloud-trace-context', None)
    ],
    CloudProvider.AZURE: [
        ('server', ['microsoft', 'azure']),
        ('x-ms-', None),
        ('x-azure-', None)
    ],
    CloudProvider.CLOUDFLARE: [
        ('server', ['cloudflare']),
        ('cf-ray', None),
        ('cf-cache-status', None)
    ]
}


class CloudAnalyzer(AnalyzerPlugin):
    """Enterprise-grade multi-cloud security analyzer"""

    plugin_name = "cloud_analyzer"
    description = "Detect cloud misconfigurations, exposed credentials, and infrastructure vulnerabilities across AWS, GCP, Azure, and other providers"
    version = "2.0.0"

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the cloud analyzer"""
        super().__init__(config)
        self.config = config or {}
        self.detected_providers: Set[CloudProvider] = set()
        self.detected_resources: List[CloudResource] = []
        self.detected_credentials: List[CloudCredential] = []

    async def analyze(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze for cloud security issues"""
        findings = []

        logger.info(f"Starting cloud security analysis for target: {target}")

        # Get configuration
        config = context.get('config', {})
        analyzer_config = config.get('analyzers', {}).get('cloud', {})

        # Configuration options
        check_buckets = analyzer_config.get('check_buckets', True)
        check_ssrf = analyzer_config.get('check_ssrf', True)
        deep_scan = analyzer_config.get('deep_scan', True)

        # Check responses for credentials and misconfigurations
        responses = context.get('responses', [])
        for response in responses:
            resp_findings = self._analyze_response(response, target)
            findings.extend(resp_findings)

        # Probe target for cloud infrastructure
        probe_findings = await self._probe_cloud_infrastructure(
            target, check_buckets, check_ssrf, deep_scan, context
        )
        findings.extend(probe_findings)

        # Get endpoints to analyze
        endpoints = context.get('endpoints', [])
        if endpoints:
            endpoint_findings = await self._analyze_endpoints(
                endpoints, check_ssrf, context
            )
            findings.extend(endpoint_findings)

        # Add summary if no issues found
        if not findings:
            findings.append(self._create_no_issues_finding(target, context))

        logger.info(f"Cloud analysis complete. Found {len(findings)} findings")

        return findings

    def _analyze_response(self, response: Dict, target: str) -> List[Dict]:
        """Analyze response for cloud security issues"""
        findings = []
        body = str(response.get('body', ''))
        headers = response.get('headers', {})
        endpoint = response.get('endpoint', target)
        method = response.get('method', 'GET')

        # Detect cloud provider from headers
        detected_provider = self._detect_provider_from_headers(headers)
        if detected_provider:
            self.detected_providers.add(detected_provider)

        # Scan for credentials
        credential_vulns = self._scan_for_credentials(body, endpoint, method, 'body')
        findings.extend([self._create_finding(v, {}) for v in credential_vulns])

        # Scan headers for credentials
        header_str = str(headers)
        header_vulns = self._scan_for_credentials(header_str, endpoint, method, 'headers')
        findings.extend([self._create_finding(v, {}) for v in header_vulns])

        # Check for cloud-specific headers that indicate misconfigurations
        header_findings = self._analyze_cloud_headers(headers, endpoint, method)
        findings.extend(header_findings)

        return findings

    def _detect_provider_from_headers(self, headers: Dict) -> Optional[CloudProvider]:
        """Detect cloud provider from response headers"""
        headers_lower = {k.lower(): v.lower() if isinstance(v, str) else v for k, v in headers.items()}

        for provider, header_patterns in PROVIDER_HEADERS.items():
            for header_name, expected_values in header_patterns:
                if expected_values is None:
                    # Check if any header starts with this prefix
                    if any(h.startswith(header_name.lower()) for h in headers_lower.keys()):
                        return provider
                else:
                    # Check if header value contains expected value
                    header_value = headers_lower.get(header_name, '')
                    if any(ev in header_value for ev in expected_values):
                        return provider

        return None

    def _scan_for_credentials(
        self,
        content: str,
        endpoint: str,
        method: str,
        location: str
    ) -> List[CloudVulnerability]:
        """Scan content for cloud credentials"""
        vulnerabilities = []

        for provider, patterns in CLOUD_CREDENTIAL_PATTERNS.items():
            for pattern_info in patterns:
                matches = pattern_info['pattern'].findall(content)

                for match in matches:
                    # Get the actual matched value
                    match_value = match if isinstance(match, str) else match[0]

                    # Create masked value
                    if len(match_value) > 12:
                        masked = match_value[:8] + '...' + match_value[-4:]
                    else:
                        masked = '***'

                    # Skip if this looks like a false positive
                    if self._is_false_positive(match_value, pattern_info['name']):
                        continue

                    credential = CloudCredential(
                        provider=provider,
                        credential_type=pattern_info['name'],
                        pattern_name=pattern_info['name'],
                        masked_value=masked,
                        full_value=match_value,
                        location=location,
                        confidence=pattern_info.get('confidence', 1.0)
                    )

                    self.detected_credentials.append(credential)

                    vuln = CloudVulnerability(
                        issue_type=CloudIssueType.CREDENTIAL_EXPOSURE,
                        risk_level=pattern_info['severity'],
                        provider=provider,
                        endpoint=endpoint,
                        method=method,
                        credential=credential,
                        evidence=f"Found {pattern_info['name']} in {location}: {masked}",
                        confidence=credential.confidence
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_false_positive(self, value: str, pattern_name: str) -> bool:
        """Check if a match is likely a false positive"""
        # Check for common false positives
        false_positive_patterns = [
            'example', 'test', 'dummy', 'sample', 'placeholder',
            '0000', '1111', 'xxxx', 'yyyy', 'zzzz'
        ]

        value_lower = value.lower()
        if any(fp in value_lower for fp in false_positive_patterns):
            return True

        # Check for repeated characters (likely placeholder)
        if len(set(value)) < 4:
            return True

        return False

    def _analyze_cloud_headers(
        self,
        headers: Dict,
        endpoint: str,
        method: str
    ) -> List[Dict]:
        """Analyze cloud-specific headers for misconfigurations"""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check for misconfigured CORS with AWS
        if 'access-control-allow-origin' in headers_lower:
            origin = headers_lower['access-control-allow-origin']
            if origin == '*':
                # Check if this is an AWS resource
                if any(h.startswith('x-amz') for h in headers_lower.keys()):
                    vuln = CloudVulnerability(
                        issue_type=CloudIssueType.MISCONFIGURATION,
                        risk_level=CloudRiskLevel.MEDIUM,
                        provider=CloudProvider.AWS,
                        endpoint=endpoint,
                        method=method,
                        evidence="AWS resource with wildcard CORS policy",
                        confidence=0.8
                    )
                    findings.append(self._create_finding(vuln, {}))

        # Check for exposed bucket listing
        if 'x-amz-bucket-region' in headers_lower:
            # Bucket region exposed
            region = headers_lower['x-amz-bucket-region']
            vuln = CloudVulnerability(
                issue_type=CloudIssueType.MISCONFIGURATION,
                risk_level=CloudRiskLevel.LOW,
                provider=CloudProvider.AWS,
                endpoint=endpoint,
                method=method,
                evidence=f"AWS S3 bucket region exposed: {region}",
                confidence=1.0
            )
            findings.append(self._create_finding(vuln, {}))

        # Check for Azure storage version
        if 'x-ms-version' in headers_lower:
            version = headers_lower['x-ms-version']
            vuln = CloudVulnerability(
                issue_type=CloudIssueType.MISCONFIGURATION,
                risk_level=CloudRiskLevel.INFO,
                provider=CloudProvider.AZURE,
                endpoint=endpoint,
                method=method,
                evidence=f"Azure Storage API version exposed: {version}",
                confidence=1.0
            )
            findings.append(self._create_finding(vuln, {}))

        return findings

    async def _probe_cloud_infrastructure(
        self,
        target: str,
        check_buckets: bool,
        check_ssrf: bool,
        deep_scan: bool,
        context: Dict
    ) -> List[Dict]:
        """Probe target for cloud infrastructure issues"""
        findings = []

        try:
            async with safe_http_client(context.get('config', {})) as client:
                # Make initial request
                response = await client.get(target)

                body = await response.text() if hasattr(response, 'text') else str(response.content)
                headers = dict(response.headers) if hasattr(response, 'headers') else {}

                # Detect provider
                provider = self._detect_provider_from_headers(headers)
                if provider:
                    self.detected_providers.add(provider)

                # Scan response for credentials
                credential_vulns = self._scan_for_credentials(body, target, 'GET', 'body')
                findings.extend([self._create_finding(v, context) for v in credential_vulns])

                # Check for cloud storage URLs in response
                storage_findings = self._detect_storage_urls(body, target)
                findings.extend(storage_findings)

                # Check for SSRF indicators
                if check_ssrf:
                    ssrf_findings = await self._check_ssrf_indicators(
                        target, body, context, client
                    )
                    findings.extend(ssrf_findings)

                # Deep scan for infrastructure info
                if deep_scan:
                    infra_findings = self._analyze_infrastructure_info(
                        headers, body, target
                    )
                    findings.extend(infra_findings)

        except Exception as e:
            logger.debug(f"Error probing cloud infrastructure: {e}")

        return findings

    def _detect_storage_urls(self, content: str, endpoint: str) -> List[Dict]:
        """Detect cloud storage URLs in content"""
        findings = []

        # Check for storage URLs across all providers
        storage_patterns = [
            (CloudProvider.AWS, re.compile(r'https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com')),
            (CloudProvider.AWS, re.compile(r's3://[a-zA-Z0-9._-]+')),
            (CloudProvider.GCP, re.compile(r'https?://storage\.googleapis\.com/[a-zA-Z0-9._-]+')),
            (CloudProvider.GCP, re.compile(r'gs://[a-zA-Z0-9._-]+')),
            (CloudProvider.AZURE, re.compile(r'https?://[a-zA-Z0-9_-]+\.blob\.core\.windows\.net')),
            (CloudProvider.DIGITAL_OCEAN, re.compile(r'https?://[a-zA-Z0-9.-]+\.digitaloceanspaces\.com'))
        ]

        for provider, pattern in storage_patterns:
            matches = pattern.findall(content)
            for match in matches:
                resource = CloudResource(
                    provider=provider,
                    resource_type='storage',
                    resource_url=match,
                    is_public=True  # Assume public if found in response
                )
                self.detected_resources.append(resource)

                vuln = CloudVulnerability(
                    issue_type=CloudIssueType.PUBLIC_BUCKET,
                    risk_level=CloudRiskLevel.MEDIUM,
                    provider=provider,
                    endpoint=endpoint,
                    method='GET',
                    resource=resource,
                    evidence=f"Cloud storage URL found: {match}",
                    confidence=0.8
                )
                findings.append(self._create_finding(vuln, {}))

        return findings

    async def _check_ssrf_indicators(
        self,
        target: str,
        content: str,
        context: Dict,
        client
    ) -> List[Dict]:
        """Check for SSRF indicators in response"""
        findings = []

        # Check if any metadata endpoints are referenced in content
        for provider, endpoints in METADATA_ENDPOINTS.items():
            for metadata_url in endpoints:
                if metadata_url in content:
                    vuln = CloudVulnerability(
                        issue_type=CloudIssueType.SSRF_VULNERABLE,
                        risk_level=CloudRiskLevel.CRITICAL,
                        provider=provider,
                        endpoint=target,
                        method='GET',
                        evidence=f"Cloud metadata URL found in response: {metadata_url}",
                        confidence=0.95
                    )
                    findings.append(self._create_finding(vuln, context))

        # Check for internal IP references
        internal_ip_pattern = re.compile(
            r'(?:169\.254\.\d{1,3}\.\d{1,3}|'
            r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
            r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
            r'192\.168\.\d{1,3}\.\d{1,3})'
        )

        internal_ips = internal_ip_pattern.findall(content)
        if internal_ips:
            vuln = CloudVulnerability(
                issue_type=CloudIssueType.NETWORK_EXPOSURE,
                risk_level=CloudRiskLevel.MEDIUM,
                provider=CloudProvider.GENERIC,
                endpoint=target,
                method='GET',
                evidence=f"Internal IP addresses exposed: {', '.join(set(internal_ips[:5]))}",
                confidence=0.7
            )
            findings.append(self._create_finding(vuln, context))

        return findings

    def _analyze_infrastructure_info(
        self,
        headers: Dict,
        content: str,
        endpoint: str
    ) -> List[Dict]:
        """Analyze for infrastructure information disclosure"""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check for AWS account ID in ARNs
        arn_pattern = re.compile(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):')
        account_ids = arn_pattern.findall(content)
        if account_ids:
            vuln = CloudVulnerability(
                issue_type=CloudIssueType.MISCONFIGURATION,
                risk_level=CloudRiskLevel.MEDIUM,
                provider=CloudProvider.AWS,
                endpoint=endpoint,
                method='GET',
                evidence=f"AWS Account ID exposed: {account_ids[0]}",
                confidence=1.0
            )
            findings.append(self._create_finding(vuln, {}))

        # Check for GCP project ID
        gcp_project_pattern = re.compile(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/')
        projects = gcp_project_pattern.findall(content)
        if projects:
            vuln = CloudVulnerability(
                issue_type=CloudIssueType.MISCONFIGURATION,
                risk_level=CloudRiskLevel.LOW,
                provider=CloudProvider.GCP,
                endpoint=endpoint,
                method='GET',
                evidence=f"GCP Project ID exposed: {projects[0]}",
                confidence=0.9
            )
            findings.append(self._create_finding(vuln, {}))

        # Check for Azure subscription ID
        azure_sub_pattern = re.compile(
            r'subscriptions/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
            re.I
        )
        subscriptions = azure_sub_pattern.findall(content)
        if subscriptions:
            vuln = CloudVulnerability(
                issue_type=CloudIssueType.MISCONFIGURATION,
                risk_level=CloudRiskLevel.MEDIUM,
                provider=CloudProvider.AZURE,
                endpoint=endpoint,
                method='GET',
                evidence=f"Azure Subscription ID exposed: {subscriptions[0]}",
                confidence=1.0
            )
            findings.append(self._create_finding(vuln, {}))

        return findings

    async def _analyze_endpoints(
        self,
        endpoints: List[Dict],
        check_ssrf: bool,
        context: Dict
    ) -> List[Dict]:
        """Analyze discovered endpoints for cloud issues"""
        findings = []

        for endpoint_info in endpoints:
            url = endpoint_info.get('url', '')

            # Check URL for cloud patterns
            url_vulns = self._scan_for_credentials(url, url, 'GET', 'url')
            findings.extend([self._create_finding(v, context) for v in url_vulns])

            # Check for cloud storage patterns in URL
            storage_findings = self._detect_storage_urls(url, url)
            findings.extend(storage_findings)

        return findings

    def _create_finding(
        self,
        vuln: CloudVulnerability,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding dictionary from vulnerability"""
        cwe_info = CLOUD_CWE_MAPPINGS.get(
            vuln.issue_type,
            CLOUD_CWE_MAPPINGS[CloudIssueType.CREDENTIAL_EXPOSURE]
        )

        # Adjust CVSS based on credential type
        cvss_base = cwe_info['cvss_base']
        if vuln.credential and vuln.credential.credential_type in ['AWS Secret Access Key', 'Private Key']:
            cvss_base = min(cvss_base + 1.0, 10.0)

        # Build evidence
        evidence_parts = [vuln.evidence]
        if vuln.credential:
            evidence_parts.append(f"Credential type: {vuln.credential.credential_type}")
            evidence_parts.append(f"Provider: {vuln.provider.value}")
        if vuln.resource:
            evidence_parts.append(f"Resource: {vuln.resource.resource_url}")

        # Create fingerprint
        fingerprint_data = f"{vuln.endpoint}:{vuln.method}:{vuln.issue_type.value}:{vuln.provider.value}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        # Severity mapping
        severity_map = {
            CloudRiskLevel.CRITICAL: 'critical',
            CloudRiskLevel.HIGH: 'high',
            CloudRiskLevel.MEDIUM: 'medium',
            CloudRiskLevel.LOW: 'low',
            CloudRiskLevel.INFO: 'info'
        }

        # Get recommendations
        recommendations = self._get_recommendations(vuln)

        return {
            'issue': self._get_issue_title(vuln),
            'description': self._get_issue_description(vuln),
            'severity': severity_map[vuln.risk_level],
            'category': 'Cloud Security',
            'endpoint': vuln.endpoint,
            'method': vuln.method,
            'evidence': '\n'.join(evidence_parts),
            'cwe_id': cwe_info['id'],
            'cwe_name': cwe_info['name'],
            'cvss_score': round(cvss_base, 1),
            'recommendation': '\n'.join([f"• {r}" for r in recommendations]),
            'issue_type': vuln.issue_type.value,
            'cloud_provider': vuln.provider.value,
            'credential_type': vuln.credential.credential_type if vuln.credential else None,
            'resource_url': vuln.resource.resource_url if vuln.resource else None,
            'confidence': round(vuln.confidence * 100, 1),
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def _get_issue_title(self, vuln: CloudVulnerability) -> str:
        """Get human-readable title for the vulnerability"""
        if vuln.credential:
            return f"{vuln.credential.credential_type} Exposed"

        titles = {
            CloudIssueType.CREDENTIAL_EXPOSURE: 'Cloud Credential Exposed',
            CloudIssueType.MISCONFIGURATION: f'{vuln.provider.value.upper()} Misconfiguration Detected',
            CloudIssueType.PUBLIC_BUCKET: f'{vuln.provider.value.upper()} Public Storage Detected',
            CloudIssueType.METADATA_EXPOSURE: 'Cloud Metadata Exposure Risk',
            CloudIssueType.INSECURE_STORAGE: 'Insecure Cloud Storage Configuration',
            CloudIssueType.SSRF_VULNERABLE: 'Cloud SSRF Vulnerability',
            CloudIssueType.HARDCODED_SECRET: 'Hardcoded Cloud Secret',
            CloudIssueType.IAM_ISSUE: 'Cloud IAM Issue Detected',
            CloudIssueType.NETWORK_EXPOSURE: 'Cloud Network Information Exposed',
            CloudIssueType.LOGGING_DISABLED: 'Cloud Logging Disabled',
            CloudIssueType.ENCRYPTION_DISABLED: 'Cloud Encryption Disabled'
        }
        return titles.get(vuln.issue_type, 'Cloud Security Issue Detected')

    def _get_issue_description(self, vuln: CloudVulnerability) -> str:
        """Get detailed description for the vulnerability"""
        if vuln.credential:
            return (
                f"A {vuln.credential.credential_type} was found exposed in the API response. "
                f"This credential belongs to {vuln.provider.value.upper()} and could allow "
                "unauthorized access to cloud resources if compromised. Exposed credentials "
                "should be immediately rotated and the source of the exposure identified and fixed."
            )

        descriptions = {
            CloudIssueType.CREDENTIAL_EXPOSURE: (
                "Cloud credentials were detected in the API response. Exposed credentials can be "
                "used by attackers to gain unauthorized access to cloud infrastructure, potentially "
                "leading to data breaches, resource abuse, or service disruption."
            ),
            CloudIssueType.MISCONFIGURATION: (
                f"A security misconfiguration was detected in {vuln.provider.value.upper()} infrastructure. "
                "Misconfigurations can expose sensitive data, allow unauthorized access, or create "
                "other security vulnerabilities in cloud resources."
            ),
            CloudIssueType.PUBLIC_BUCKET: (
                f"A potentially public {vuln.provider.value.upper()} storage resource was detected. "
                "Public cloud storage buckets can expose sensitive data to anyone on the internet "
                "and are a common source of data breaches."
            ),
            CloudIssueType.SSRF_VULNERABLE: (
                "Cloud metadata service URLs or internal endpoints were detected in the response. "
                "This could indicate a Server-Side Request Forgery (SSRF) vulnerability that allows "
                "attackers to access cloud instance metadata and potentially steal credentials."
            ),
            CloudIssueType.NETWORK_EXPOSURE: (
                "Internal network information (IP addresses, hostnames) was exposed in the response. "
                "This information can help attackers map internal infrastructure and plan attacks."
            )
        }
        return descriptions.get(vuln.issue_type, "A cloud security issue was detected.")

    def _get_recommendations(self, vuln: CloudVulnerability) -> List[str]:
        """Get recommendations for fixing the vulnerability"""
        if vuln.credential:
            return [
                f"Immediately rotate the exposed {vuln.credential.credential_type}",
                "Review audit logs for unauthorized access using this credential",
                "Remove the credential from source code and API responses",
                "Use environment variables or secret management services instead",
                "Implement credential scanning in CI/CD pipeline",
                "Enable MFA for the associated account"
            ]

        recommendations = {
            CloudIssueType.CREDENTIAL_EXPOSURE: [
                "Remove credentials from API responses",
                "Rotate all potentially exposed credentials",
                "Implement proper secret management",
                "Use IAM roles instead of static credentials where possible",
                "Enable credential rotation policies"
            ],
            CloudIssueType.MISCONFIGURATION: [
                "Review and fix the identified misconfiguration",
                "Implement infrastructure as code with security defaults",
                "Enable cloud security monitoring and alerting",
                "Regularly audit cloud configurations",
                "Use cloud security posture management (CSPM) tools"
            ],
            CloudIssueType.PUBLIC_BUCKET: [
                "Review and restrict bucket access policies",
                "Enable bucket versioning and logging",
                "Implement bucket policies that deny public access",
                "Use signed URLs for time-limited access",
                "Enable encryption at rest and in transit"
            ],
            CloudIssueType.SSRF_VULNERABLE: [
                "Implement strict input validation for URLs",
                "Use allowlists for permitted external hosts",
                "Block access to metadata service IP ranges",
                "Use IMDSv2 on AWS instances",
                "Implement network segmentation"
            ],
            CloudIssueType.NETWORK_EXPOSURE: [
                "Remove internal IP addresses from responses",
                "Implement proper error handling that doesn't leak info",
                "Use reverse proxies to hide internal structure",
                "Review and sanitize all API responses",
                "Implement security headers"
            ]
        }
        return recommendations.get(vuln.issue_type, recommendations[CloudIssueType.CREDENTIAL_EXPOSURE])

    def _create_no_issues_finding(
        self,
        target: str,
        context: Dict
    ) -> Dict[str, Any]:
        """Create a finding when no issues are detected"""
        fingerprint = hashlib.sha256(f"cloud_scan_complete:{target}".encode()).hexdigest()[:16]

        providers_checked = ', '.join([p.value for p in CLOUD_CREDENTIAL_PATTERNS.keys()])

        return {
            'issue': 'Cloud Security Assessment Complete',
            'description': f"Cloud security assessment completed. No cloud credentials, misconfigurations, or infrastructure vulnerabilities were detected. Providers checked: {providers_checked}",
            'severity': 'info',
            'category': 'Cloud Security',
            'endpoint': target,
            'method': 'GET',
            'evidence': f"Scanned for credentials across {len(CLOUD_CREDENTIAL_PATTERNS)} cloud providers. Checked for storage misconfigurations, SSRF vulnerabilities, and infrastructure exposure.",
            'cwe_id': 'N/A',
            'cwe_name': 'No Issues Detected',
            'cvss_score': 0.0,
            'recommendation': '• Continue regular cloud security assessments\n• Implement automated credential scanning\n• Enable cloud security monitoring\n• Review IAM policies periodically',
            'issue_type': 'assessment_complete',
            'detected_providers': list(self.detected_providers),
            'fingerprint': fingerprint,
            'discovered_at': datetime.now().isoformat()
        }

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Generate a summary of cloud analysis"""
        return {
            'providers_detected': [p.value for p in self.detected_providers],
            'credentials_found': len(self.detected_credentials),
            'resources_found': len(self.detected_resources),
            'providers_checked': list(CLOUD_CREDENTIAL_PATTERNS.keys()),
            'credential_patterns_checked': sum(
                len(patterns) for patterns in CLOUD_CREDENTIAL_PATTERNS.values()
            ),
            'metadata_endpoints_checked': sum(
                len(endpoints) for endpoints in METADATA_ENDPOINTS.values()
            )
        }
