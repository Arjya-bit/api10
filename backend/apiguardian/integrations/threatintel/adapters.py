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
        # More sensitive detection: any malicious flag or 2+ suspicious flags
        if malicious >= 3:
            return 'malicious'
        elif malicious >= 1 or suspicious >= 2:
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
                total_reports = data.get('totalReports', 0)
                
                # Better threat level detection based on score and reports
                if score >= 50 or total_reports >= 100:
                    threat_level = 'malicious'
                elif score >= 25 or total_reports >= 10:
                    threat_level = 'suspicious'
                else:
                    threat_level = 'clean'
                
                return {
                    'service': self.service_name,
                    'indicator': ip,
                    'type': 'ip',
                    'abuse_confidence_score': score,
                    'total_reports': total_reports,
                    'country_code': data.get('countryCode'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'is_tor': data.get('isTor', False),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'usage_type': data.get('usageType'),
                    'threat_level': threat_level,
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


class OTXAdapter(BaseTIAdapter):
    """AlienVault OTX (Open Threat Exchange) adapter"""
    
    service_name = "otx"
    api_key_env = "OTX_API_KEY"
    
    def _mock_ip_lookup(self, ip: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': ip,
            'type': 'ip',
            'pulse_count': 0,
            'reputation': 0,
            'country': 'US',
            'asn': 'AS15169 Google LLC',
            'threat_level': 'clean',
            'malware_samples': 0,
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _mock_url_lookup(self, url: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': url,
            'type': 'url',
            'pulse_count': 0,
            'threat_level': 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _mock_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': file_hash,
            'type': 'hash',
            'pulse_count': 0,
            'threat_level': 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _live_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Live OTX IP lookup"""
        import httpx
        try:
            # Get general info
            response = httpx.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": self.api_key},
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                reputation = data.get('reputation', 0)
                
                # Determine threat level based on pulse count and reputation
                if pulse_count >= 10 or reputation >= 3:
                    threat_level = 'malicious'
                elif pulse_count >= 3 or reputation >= 1:
                    threat_level = 'suspicious'
                else:
                    threat_level = 'clean'
                
                return {
                    'service': self.service_name,
                    'indicator': ip,
                    'type': 'ip',
                    'pulse_count': pulse_count,
                    'reputation': reputation,
                    'country': data.get('country_name'),
                    'country_code': data.get('country_code'),
                    'asn': data.get('asn'),
                    'city': data.get('city'),
                    'threat_level': threat_level,
                    'validation': data.get('validation', []),
                    'sections': data.get('sections', []),
                    'queried_at': datetime.now(timezone.utc).isoformat()
                }
        except Exception as e:
            logger.error(f"OTX IP lookup failed: {e}")
        return self._mock_ip_lookup(ip)
    
    def _live_url_lookup(self, url: str) -> Dict[str, Any]:
        """Live OTX URL lookup"""
        import httpx
        import urllib.parse
        try:
            # URL encode the indicator
            encoded_url = urllib.parse.quote(url, safe='')
            response = httpx.get(
                f"https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/general",
                headers={"X-OTX-API-KEY": self.api_key},
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                
                threat_level = 'malicious' if pulse_count >= 5 else 'suspicious' if pulse_count >= 1 else 'clean'
                
                return {
                    'service': self.service_name,
                    'indicator': url,
                    'type': 'url',
                    'pulse_count': pulse_count,
                    'threat_level': threat_level,
                    'alexa': data.get('alexa'),
                    'whois': data.get('whois'),
                    'queried_at': datetime.now(timezone.utc).isoformat()
                }
        except Exception as e:
            logger.error(f"OTX URL lookup failed: {e}")
        return self._mock_url_lookup(url)
    
    def _live_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        """Live OTX hash lookup"""
        import httpx
        try:
            hash_type = 'FileHash-SHA256' if len(file_hash) == 64 else 'FileHash-MD5' if len(file_hash) == 32 else 'FileHash-SHA1'
            response = httpx.get(
                f"https://otx.alienvault.com/api/v1/indicators/{hash_type}/{file_hash}/general",
                headers={"X-OTX-API-KEY": self.api_key},
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                
                threat_level = 'malicious' if pulse_count >= 3 else 'suspicious' if pulse_count >= 1 else 'clean'
                
                return {
                    'service': self.service_name,
                    'indicator': file_hash,
                    'type': 'hash',
                    'pulse_count': pulse_count,
                    'threat_level': threat_level,
                    'malware_families': data.get('malware_families', []),
                    'queried_at': datetime.now(timezone.utc).isoformat()
                }
        except Exception as e:
            logger.error(f"OTX hash lookup failed: {e}")
        return self._mock_hash_lookup(file_hash)


class ProjectHoneypotAdapter(BaseTIAdapter):
    """Project Honeypot http:BL threat intelligence adapter

    Uses DNS-based lookups to check IPs against Project Honeypot's database.
    Query format: {access_key}.{reversed_ip}.dnsbl.httpbl.org
    Response: 127.{days_since_last_seen}.{threat_score}.{visitor_type}

    Visitor types:
    - 0 = Search Engine
    - 1 = Suspicious
    - 2 = Harvester
    - 4 = Comment Spammer
    (values can be combined, e.g., 6 = Harvester + Comment Spammer)
    """

    service_name = "honeypot"
    api_key_env = "HONEYPOT_API_KEY"

    VISITOR_TYPES = {
        0: 'search_engine',
        1: 'suspicious',
        2: 'harvester',
        4: 'comment_spammer'
    }

    def _mock_ip_lookup(self, ip: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': ip,
            'type': 'ip',
            'listed': False,
            'days_since_last_seen': None,
            'threat_score': 0,
            'visitor_types': [],
            'threat_level': 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }

    def _mock_url_lookup(self, url: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': url,
            'type': 'url',
            'note': 'Project Honeypot only supports IP lookups',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }

    def _mock_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': file_hash,
            'type': 'hash',
            'note': 'Project Honeypot only supports IP lookups',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }

    def _decode_visitor_type(self, type_code: int) -> list:
        """Decode visitor type bitmask into list of types"""
        types = []
        for code, name in self.VISITOR_TYPES.items():
            if type_code & code or (code == 0 and type_code == 0):
                if code == 0 and type_code == 0:
                    types.append(name)
                elif code != 0 and type_code & code:
                    types.append(name)
        return types if types else ['unknown']

    def _live_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Live Project Honeypot lookup using DNS"""
        import socket
        try:
            # Reverse the IP octets
            reversed_ip = '.'.join(reversed(ip.split('.')))

            # Build the query: accesskey.reversedip.dnsbl.httpbl.org
            query = f"{self.api_key}.{reversed_ip}.dnsbl.httpbl.org"

            try:
                # Perform DNS lookup
                result = socket.gethostbyname(query)
                octets = result.split('.')

                if len(octets) == 4 and octets[0] == '127':
                    days_since_last_seen = int(octets[1])
                    threat_score = int(octets[2])
                    visitor_type = int(octets[3])

                    visitor_types = self._decode_visitor_type(visitor_type)

                    # Determine threat level
                    if visitor_type == 0:
                        threat_level = 'clean'  # Search engine
                    elif threat_score >= 50:
                        threat_level = 'malicious'
                    elif threat_score >= 25:
                        threat_level = 'suspicious'
                    else:
                        threat_level = 'suspicious' if visitor_type > 0 else 'clean'

                    return {
                        'service': self.service_name,
                        'indicator': ip,
                        'type': 'ip',
                        'listed': True,
                        'days_since_last_seen': days_since_last_seen,
                        'threat_score': threat_score,
                        'visitor_types': visitor_types,
                        'raw_visitor_type': visitor_type,
                        'threat_level': threat_level,
                        'queried_at': datetime.now(timezone.utc).isoformat()
                    }
            except socket.gaierror:
                # IP not found in database (NXDOMAIN) - this is normal for clean IPs
                pass

            return {
                'service': self.service_name,
                'indicator': ip,
                'type': 'ip',
                'listed': False,
                'days_since_last_seen': None,
                'threat_score': 0,
                'visitor_types': [],
                'threat_level': 'clean',
                'queried_at': datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            logger.error(f"Project Honeypot IP lookup failed: {e}")
        return self._mock_ip_lookup(ip)


class HetrixToolsAdapter(BaseTIAdapter):
    """HetrixTools Blacklist Check adapter

    Uses HetrixTools API to check IPs against multiple blacklists.
    API endpoint: https://api.hetrixtools.com/v2/{apikey}/blacklist-check/ipv4/{ip}/
    """

    service_name = "hetrixtools"
    api_key_env = "HETRIXTOOLS_API_KEY"

    def _mock_ip_lookup(self, ip: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': ip,
            'type': 'ip',
            'blacklisted_count': 0,
            'blacklists_checked': 100,
            'blacklisted_on': [],
            'threat_level': 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }

    def _mock_url_lookup(self, url: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': url,
            'type': 'url',
            'note': 'HetrixTools blacklist check only supports IP lookups',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }

    def _mock_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': file_hash,
            'type': 'hash',
            'note': 'HetrixTools blacklist check only supports IP lookups',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }

    def _live_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Live HetrixTools blacklist check"""
        import httpx
        try:
            # Determine if IPv4 or IPv6
            ip_type = 'ipv6' if ':' in ip else 'ipv4'

            response = httpx.get(
                f"https://api.hetrixtools.com/v2/{self.api_key}/blacklist-check/{ip_type}/{ip}/",
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                blacklisted_count = data.get('blacklisted_count', 0)
                blacklists_checked = data.get('blacklist_check_count', 0)
                blacklisted_on = []

                # Extract blacklist names where IP is listed
                for bl_name, bl_status in data.get('blacklisted_on', {}).items():
                    if bl_status == 1:
                        blacklisted_on.append(bl_name)

                # Determine threat level
                if blacklisted_count >= 5:
                    threat_level = 'malicious'
                elif blacklisted_count >= 2:
                    threat_level = 'suspicious'
                elif blacklisted_count >= 1:
                    threat_level = 'suspicious'
                else:
                    threat_level = 'clean'

                return {
                    'service': self.service_name,
                    'indicator': ip,
                    'type': 'ip',
                    'blacklisted_count': blacklisted_count,
                    'blacklists_checked': blacklists_checked,
                    'blacklisted_on': blacklisted_on,
                    'links': data.get('links', {}),
                    'threat_level': threat_level,
                    'queried_at': datetime.now(timezone.utc).isoformat()
                }
            elif response.status_code == 429:
                logger.warning("HetrixTools rate limit reached")
            else:
                logger.warning(f"HetrixTools returned status {response.status_code}")
        except Exception as e:
            logger.error(f"HetrixTools IP lookup failed: {e}")
        return self._mock_ip_lookup(ip)


class PulseDiveAdapter(BaseTIAdapter):
    """PulseDive threat intelligence adapter"""

    service_name = "pulsedive"
    api_key_env = "PULSEDIVE_API_KEY"
    
    def _mock_ip_lookup(self, ip: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': ip,
            'type': 'ip',
            'risk': 'none',
            'risk_score': 0,
            'threats': [],
            'feeds': [],
            'threat_level': 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _mock_url_lookup(self, url: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': url,
            'type': 'url',
            'risk': 'none',
            'risk_score': 0,
            'threat_level': 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _mock_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        return {
            'service': self.service_name,
            'indicator': file_hash,
            'type': 'hash',
            'risk': 'none',
            'risk_score': 0,
            'threat_level': 'clean',
            'queried_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _live_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Live PulseDive IP lookup"""
        import httpx
        try:
            response = httpx.get(
                "https://pulsedive.com/api/info.php",
                params={
                    "indicator": ip,
                    "key": self.api_key,
                    "pretty": "1"
                },
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                
                # Check if error
                if 'error' in data:
                    logger.warning(f"PulseDive returned error: {data.get('error')}")
                    return self._mock_ip_lookup(ip)
                
                risk = data.get('risk', 'unknown')
                risk_factors = data.get('riskfactors', [])
                threats = data.get('threats', [])
                feeds = data.get('feeds', [])
                
                # Determine threat level
                if risk == 'critical' or risk == 'high' or len(threats) > 0:
                    threat_level = 'malicious'
                elif risk == 'medium' or len(risk_factors) > 0:
                    threat_level = 'suspicious'
                else:
                    threat_level = 'clean'
                
                return {
                    'service': self.service_name,
                    'indicator': ip,
                    'type': 'ip',
                    'risk': risk,
                    'risk_factors': [rf.get('description') for rf in risk_factors] if risk_factors else [],
                    'threats': [t.get('name') for t in threats] if threats else [],
                    'feeds': [f.get('name') for f in feeds] if feeds else [],
                    'threat_level': threat_level,
                    'stamp_seen': data.get('stamp_seen'),
                    'stamp_updated': data.get('stamp_updated'),
                    'queried_at': datetime.now(timezone.utc).isoformat()
                }
        except Exception as e:
            logger.error(f"PulseDive IP lookup failed: {e}")
        return self._mock_ip_lookup(ip)
    
    def _live_url_lookup(self, url: str) -> Dict[str, Any]:
        """Live PulseDive URL lookup"""
        import httpx
        try:
            response = httpx.get(
                "https://pulsedive.com/api/info.php",
                params={
                    "indicator": url,
                    "key": self.api_key,
                    "pretty": "1"
                },
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                
                if 'error' in data:
                    return self._mock_url_lookup(url)
                
                risk = data.get('risk', 'unknown')
                threats = data.get('threats', [])
                
                if risk == 'critical' or risk == 'high' or len(threats) > 0:
                    threat_level = 'malicious'
                elif risk == 'medium':
                    threat_level = 'suspicious'
                else:
                    threat_level = 'clean'
                
                return {
                    'service': self.service_name,
                    'indicator': url,
                    'type': 'url',
                    'risk': risk,
                    'threats': [t.get('name') for t in threats] if threats else [],
                    'threat_level': threat_level,
                    'queried_at': datetime.now(timezone.utc).isoformat()
                }
        except Exception as e:
            logger.error(f"PulseDive URL lookup failed: {e}")
        return self._mock_url_lookup(url)
    
    def _live_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        """Live PulseDive hash lookup"""
        import httpx
        try:
            response = httpx.get(
                "https://pulsedive.com/api/info.php",
                params={
                    "indicator": file_hash,
                    "key": self.api_key,
                    "pretty": "1"
                },
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                
                if 'error' in data:
                    return self._mock_hash_lookup(file_hash)
                
                risk = data.get('risk', 'unknown')
                
                return {
                    'service': self.service_name,
                    'indicator': file_hash,
                    'type': 'hash',
                    'risk': risk,
                    'threat_level': 'malicious' if risk in ['critical', 'high'] else 'suspicious' if risk == 'medium' else 'clean',
                    'queried_at': datetime.now(timezone.utc).isoformat()
                }
        except Exception as e:
            logger.error(f"PulseDive hash lookup failed: {e}")
        return self._mock_hash_lookup(file_hash)


# Adapter registry
ADAPTERS = {
    'virustotal': VirusTotalAdapter,
    'abuseipdb': AbuseIPDBAdapter,
    'urlhaus': URLhausAdapter,
    'phishtank': PhishTankAdapter,
    'google_safebrowsing': GoogleSafeBrowsingAdapter,
    'otx': OTXAdapter,
    'pulsedive': PulseDiveAdapter,
    'honeypot': ProjectHoneypotAdapter,
    'hetrixtools': HetrixToolsAdapter
}


def get_adapter(service: str, mode: str = 'mock') -> Optional[BaseTIAdapter]:
    """Get threat intel adapter by service name"""
    adapter_cls = ADAPTERS.get(service.lower())
    if adapter_cls:
        return adapter_cls(mode=mode)
    return None
