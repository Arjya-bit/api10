"""Threat Intelligence Adapters - Base and implementations"""
import os
import json
import logging
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class BaseTIAdapter(ABC):
    """Base class for Threat Intelligence adapters"""
    
    service_name: str = "base"
    api_key_env: str = ""
    
    def __init__(self, mode: str = "mock", api_key: str = None):
        self.mode = mode
        self.api_key = api_key or os.environ.get(self.api_key_env, '')
        self._cache: Dict[str, Dict] = {}
        self._cache_ttl = 3600  # 1 hour
        
        if mode == 'live' and not self.api_key:
            logger.warning(f"{self.service_name}: No API key found, falling back to mock mode")
            self.mode = 'mock'
    
    def _get_cache_key(self, indicator: str, indicator_type: str) -> str:
        """Generate cache key"""
        return hashlib.md5(f"{self.service_name}:{indicator_type}:{indicator}".encode()).hexdigest()
    
    def _get_cached(self, indicator: str, indicator_type: str) -> Optional[Dict]:
        """Get cached result"""
        key = self._get_cache_key(indicator, indicator_type)
        if key in self._cache:
            cached = self._cache[key]
            if datetime.now(timezone.utc) < cached.get('expires', datetime.min.replace(tzinfo=timezone.utc)):
                return cached.get('data')
        return None
    
    def _set_cached(self, indicator: str, indicator_type: str, data: Dict):
        """Cache result"""
        key = self._get_cache_key(indicator, indicator_type)
        self._cache[key] = {
            'data': data,
            'expires': datetime.now(timezone.utc) + timedelta(seconds=self._cache_ttl)
        }
    
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Lookup IP address"""
        cached = self._get_cached(ip, 'ip')
        if cached:
            return cached
        
        if self.mode == 'mock':
            result = self._mock_ip_lookup(ip)
        else:
            result = self._live_ip_lookup(ip)
        
        self._set_cached(ip, 'ip', result)
        return result
    
    def lookup_url(self, url: str) -> Dict[str, Any]:
        """Lookup URL"""
        cached = self._get_cached(url, 'url')
        if cached:
            return cached
        
        if self.mode == 'mock':
            result = self._mock_url_lookup(url)
        else:
            result = self._live_url_lookup(url)
        
        self._set_cached(url, 'url', result)
        return result
    
    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Lookup file hash"""
        cached = self._get_cached(file_hash, 'hash')
        if cached:
            return cached
        
        if self.mode == 'mock':
            result = self._mock_hash_lookup(file_hash)
        else:
            result = self._live_hash_lookup(file_hash)
        
        self._set_cached(file_hash, 'hash', result)
        return result
    
    @abstractmethod
    def _mock_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Mock IP lookup - must be implemented"""
        pass
    
    @abstractmethod
    def _mock_url_lookup(self, url: str) -> Dict[str, Any]:
        """Mock URL lookup - must be implemented"""
        pass
    
    @abstractmethod
    def _mock_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        """Mock hash lookup - must be implemented"""
        pass
    
    def _live_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Live IP lookup - override in subclass"""
        return self._mock_ip_lookup(ip)
    
    def _live_url_lookup(self, url: str) -> Dict[str, Any]:
        """Live URL lookup - override in subclass"""
        return self._mock_url_lookup(url)
    
    def _live_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        """Live hash lookup - override in subclass"""
        return self._mock_hash_lookup(file_hash)


class VirusTotalAdapter(BaseTIAdapter):
    """VirusTotal threat intelligence adapter"""
    
    service_name = "virustotal"
    api_key_env = "VIRUSTOTAL_API_KEY"
    
    def _mock_ip_lookup(self, ip: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': ip,
            'type': 'ip',
            'malicious': 0,
            'suspicious': 0,
            'harmless': 65,
            'undetected': 20,
            'country': 'US',
            'asn': 15169,
            'as_owner': 'GOOGLE',
            'threat_level': 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _mock_url_lookup(self, url: str) -> Dict[str, Any]:
        is_suspicious = 'malware' in url.lower() or 'phishing' in url.lower()
        return {
            'service': self.service_name,
            'indicator': url,
            'type': 'url',
            'malicious': 5 if is_suspicious else 0,
            'suspicious': 2 if is_suspicious else 0,
            'harmless': 60,
            'undetected': 10,
            'threat_level': 'suspicious' if is_suspicious else 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _mock_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        # EICAR test hash
        is_malicious = file_hash.lower() == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
        return {
            'service': self.service_name,
            'indicator': file_hash,
            'type': 'hash',
            'malicious': 66 if is_malicious else 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 3 if is_malicious else 70,
            'file_type': 'Powershell' if is_malicious else 'Unknown',
            'threat_level': 'malicious' if is_malicious else 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _live_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Live VirusTotal IP lookup"""
        import httpx
        try:
            response = httpx.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.api_key},
                timeout=30
            )
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'service': self.service_name,
                    'indicator': ip,
                    'type': 'ip',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'country': data.get('country'),
                    'asn': data.get('asn'),
                    'as_owner': data.get('as_owner'),
                    'threat_level': self._determine_threat_level(stats),
                    'queried_at': datetime.now(timezone.utc).isoformat()
                }
        except Exception as e:
            logger.error(f"VirusTotal IP lookup failed: {e}")
        return self._mock_ip_lookup(ip)
    
    def _determine_threat_level(self, stats: Dict) -> str:
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        if malicious >= 5:
            return 'malicious'
        elif malicious >= 1 or suspicious >= 3:
            return 'suspicious'
        return 'clean'


class AbuseIPDBAdapter(BaseTIAdapter):
    """AbuseIPDB threat intelligence adapter"""
    
    service_name = "abuseipdb"
    api_key_env = "ABUSEIPDB_API_KEY"
    
    def _mock_ip_lookup(self, ip: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': ip,
            'type': 'ip',
            'abuse_confidence_score': 0,
            'total_reports': 0,
            'country_code': 'US',
            'isp': 'Google LLC',
            'domain': 'google.com',
            'is_tor': False,
            'is_whitelisted': True,
            'usage_type': 'Data Center/Web Hosting/Transit',
            'threat_level': 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _mock_url_lookup(self, url: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': url,
            'type': 'url',
            'note': 'AbuseIPDB does not support URL lookups',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _mock_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': file_hash,
            'type': 'hash',
            'note': 'AbuseIPDB does not support hash lookups',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _live_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Live AbuseIPDB IP lookup"""
        import httpx
        try:
            response = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                timeout=30
            )
            if response.status_code == 200:
                data = response.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                return {
                    'service': self.service_name,
                    'indicator': ip,
                    'type': 'ip',
                    'abuse_confidence_score': score,
                    'total_reports': data.get('totalReports', 0),
                    'country_code': data.get('countryCode'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'is_tor': data.get('isTor', False),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'usage_type': data.get('usageType'),
                    'threat_level': 'malicious' if score >= 80 else 'suspicious' if score >= 50 else 'clean',
                    'queried_at': datetime.now(timezone.utc).isoformat()
                }
        except Exception as e:
            logger.error(f"AbuseIPDB IP lookup failed: {e}")
        return self._mock_ip_lookup(ip)


# Stub adapters for other services
class URLhausAdapter(BaseTIAdapter):
    service_name = "urlhaus"
    api_key_env = "URLHAUS_API_KEY"
    
    def _mock_ip_lookup(self, ip: str) -> Dict: return {'service': self.service_name, 'note': 'stub'}
    def _mock_url_lookup(self, url: str) -> Dict: return {'service': self.service_name, 'threat_level': 'clean'}
    def _mock_hash_lookup(self, h: str) -> Dict: return {'service': self.service_name, 'note': 'stub'}


class PhishTankAdapter(BaseTIAdapter):
    service_name = "phishtank"
    api_key_env = "PHISHTANK_API_KEY"
    
    def _mock_ip_lookup(self, ip: str) -> Dict: return {'service': self.service_name, 'note': 'stub'}
    def _mock_url_lookup(self, url: str) -> Dict: return {'service': self.service_name, 'is_phish': False}
    def _mock_hash_lookup(self, h: str) -> Dict: return {'service': self.service_name, 'note': 'stub'}


class GoogleSafeBrowsingAdapter(BaseTIAdapter):
    service_name = "google_safebrowsing"
    api_key_env = "GOOGLE_SAFEBROWSING_API_KEY"
    
    def _mock_ip_lookup(self, ip: str) -> Dict: return {'service': self.service_name, 'note': 'stub'}
    def _mock_url_lookup(self, url: str) -> Dict: return {'service': self.service_name, 'threat_level': 'clean'}
    def _mock_hash_lookup(self, h: str) -> Dict: return {'service': self.service_name, 'note': 'stub'}


# Adapter registry
ADAPTERS = {
    'virustotal': VirusTotalAdapter,
    'abuseipdb': AbuseIPDBAdapter,
    'urlhaus': URLhausAdapter,
    'phishtank': PhishTankAdapter,
    'google_safebrowsing': GoogleSafeBrowsingAdapter
}


def get_adapter(service: str, mode: str = 'mock') -> Optional[BaseTIAdapter]:
    """Get threat intel adapter by service name"""
    adapter_cls = ADAPTERS.get(service.lower())
    if adapter_cls:
        return adapter_cls(mode=mode)
    return None
