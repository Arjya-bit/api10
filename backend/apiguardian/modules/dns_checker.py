"""DNS Propagation Checker Module - Check DNS propagation across global servers"""
import asyncio
import time
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# Global DNS servers with location metadata
# Similar to DNSChecker.org's server list
DNS_SERVERS = [
    # North America
    {"ip": "8.8.8.8", "name": "Google", "location": "United States", "city": "Mountain View", "lat": 37.386, "lon": -122.084, "country_code": "US"},
    {"ip": "8.8.4.4", "name": "Google Secondary", "location": "United States", "city": "Mountain View", "lat": 37.386, "lon": -122.084, "country_code": "US"},
    {"ip": "1.1.1.1", "name": "Cloudflare", "location": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "country_code": "US"},
    {"ip": "1.0.0.1", "name": "Cloudflare Secondary", "location": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "country_code": "US"},
    {"ip": "208.67.222.222", "name": "OpenDNS", "location": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "country_code": "US"},
    {"ip": "208.67.220.220", "name": "OpenDNS Secondary", "location": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "country_code": "US"},
    {"ip": "9.9.9.9", "name": "Quad9", "location": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "country_code": "US"},
    {"ip": "149.112.112.112", "name": "Quad9 Secondary", "location": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "country_code": "US"},
    {"ip": "64.6.64.6", "name": "Verisign", "location": "United States", "city": "Reston", "lat": 38.9586, "lon": -77.3570, "country_code": "US"},
    {"ip": "199.85.126.10", "name": "Norton ConnectSafe", "location": "United States", "city": "Mountain View", "lat": 37.386, "lon": -122.084, "country_code": "US"},
    {"ip": "76.76.19.19", "name": "Alternate DNS", "location": "United States", "city": "New York", "lat": 40.7128, "lon": -74.0060, "country_code": "US"},
    {"ip": "156.154.70.1", "name": "Neustar UltraDNS", "location": "United States", "city": "Sterling", "lat": 39.0062, "lon": -77.4286, "country_code": "US"},

    # Canada
    {"ip": "204.101.251.2", "name": "CIRAShield", "location": "Canada", "city": "Ottawa", "lat": 45.4215, "lon": -75.6972, "country_code": "CA"},

    # Europe
    {"ip": "185.228.168.9", "name": "CleanBrowsing", "location": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "country_code": "DE"},
    {"ip": "195.46.39.39", "name": "SafeDNS", "location": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "country_code": "DE"},
    {"ip": "217.237.150.188", "name": "Deutsche Telekom", "location": "Germany", "city": "Bonn", "lat": 50.7374, "lon": 7.0982, "country_code": "DE"},
    {"ip": "80.80.80.80", "name": "Freenom World", "location": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "country_code": "NL"},
    {"ip": "77.88.8.8", "name": "Yandex DNS", "location": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "country_code": "RU"},
    {"ip": "77.88.8.1", "name": "Yandex Secondary", "location": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "country_code": "RU"},
    {"ip": "176.103.130.130", "name": "AdGuard DNS", "location": "Cyprus", "city": "Limassol", "lat": 34.7071, "lon": 33.0226, "country_code": "CY"},
    {"ip": "212.71.8.53", "name": "Linode UK", "location": "United Kingdom", "city": "London", "lat": 51.5074, "lon": -0.1278, "country_code": "GB"},
    {"ip": "195.129.12.122", "name": "Telecom Italia", "location": "Italy", "city": "Rome", "lat": 41.9028, "lon": 12.4964, "country_code": "IT"},
    {"ip": "80.58.61.250", "name": "Telefonica Spain", "location": "Spain", "city": "Madrid", "lat": 40.4168, "lon": -3.7038, "country_code": "ES"},
    {"ip": "89.233.43.71", "name": "UncensoredDNS", "location": "Denmark", "city": "Copenhagen", "lat": 55.6761, "lon": 12.5683, "country_code": "DK"},
    {"ip": "91.239.100.100", "name": "UncensoredDNS Secondary", "location": "Denmark", "city": "Copenhagen", "lat": 55.6761, "lon": 12.5683, "country_code": "DK"},
    {"ip": "193.17.47.1", "name": "Swisscom", "location": "Switzerland", "city": "Zurich", "lat": 47.3769, "lon": 8.5417, "country_code": "CH"},
    {"ip": "62.179.104.196", "name": "Orange France", "location": "France", "city": "Paris", "lat": 48.8566, "lon": 2.3522, "country_code": "FR"},

    # Asia-Pacific
    {"ip": "168.126.63.1", "name": "Korea Telecom", "location": "South Korea", "city": "Seoul", "lat": 37.5665, "lon": 126.9780, "country_code": "KR"},
    {"ip": "203.248.252.2", "name": "Korea Telecom Secondary", "location": "South Korea", "city": "Seoul", "lat": 37.5665, "lon": 126.9780, "country_code": "KR"},
    {"ip": "180.76.76.76", "name": "Baidu DNS", "location": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "country_code": "CN"},
    {"ip": "119.29.29.29", "name": "DNSPod", "location": "China", "city": "Shenzhen", "lat": 22.5431, "lon": 114.0579, "country_code": "CN"},
    {"ip": "223.5.5.5", "name": "AliDNS", "location": "China", "city": "Hangzhou", "lat": 30.2741, "lon": 120.1551, "country_code": "CN"},
    {"ip": "114.114.114.114", "name": "114DNS", "location": "China", "city": "Nanjing", "lat": 32.0603, "lon": 118.7969, "country_code": "CN"},
    {"ip": "101.226.4.6", "name": "China Unicom", "location": "China", "city": "Shanghai", "lat": 31.2304, "lon": 121.4737, "country_code": "CN"},
    {"ip": "202.45.84.58", "name": "TPG Singapore", "location": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "country_code": "SG"},
    {"ip": "202.67.220.220", "name": "PacificNet HK", "location": "Hong Kong", "city": "Hong Kong", "lat": 22.3193, "lon": 114.1694, "country_code": "HK"},
    {"ip": "202.12.30.131", "name": "APNIC", "location": "Australia", "city": "Brisbane", "lat": -27.4698, "lon": 153.0251, "country_code": "AU"},
    {"ip": "203.146.4.4", "name": "TOT Thailand", "location": "Thailand", "city": "Bangkok", "lat": 13.7563, "lon": 100.5018, "country_code": "TH"},
    {"ip": "202.88.162.2", "name": "BSNL India", "location": "India", "city": "New Delhi", "lat": 28.6139, "lon": 77.2090, "country_code": "IN"},
    {"ip": "203.94.227.70", "name": "MTNL India", "location": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777, "country_code": "IN"},
    {"ip": "210.2.4.8", "name": "JPNIC Japan", "location": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "country_code": "JP"},
    {"ip": "203.112.2.4", "name": "NTT Japan", "location": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "country_code": "JP"},

    # Middle East
    {"ip": "212.118.241.1", "name": "STC Saudi", "location": "Saudi Arabia", "city": "Riyadh", "lat": 24.7136, "lon": 46.6753, "country_code": "SA"},
    {"ip": "94.200.200.200", "name": "Du UAE", "location": "UAE", "city": "Dubai", "lat": 25.2048, "lon": 55.2708, "country_code": "AE"},
    {"ip": "217.66.50.20", "name": "Etisalat UAE", "location": "UAE", "city": "Abu Dhabi", "lat": 24.4539, "lon": 54.3773, "country_code": "AE"},
    {"ip": "78.109.17.10", "name": "Bezeq Israel", "location": "Israel", "city": "Tel Aviv", "lat": 32.0853, "lon": 34.7818, "country_code": "IL"},
    {"ip": "85.132.128.2", "name": "AzOnline", "location": "Azerbaijan", "city": "Baku", "lat": 40.4093, "lon": 49.8671, "country_code": "AZ"},

    # South America
    {"ip": "200.221.11.100", "name": "Telefonica Brazil", "location": "Brazil", "city": "São Paulo", "lat": -23.5505, "lon": -46.6333, "country_code": "BR"},
    {"ip": "200.49.159.68", "name": "Telecom Argentina", "location": "Argentina", "city": "Buenos Aires", "lat": -34.6037, "lon": -58.3816, "country_code": "AR"},
    {"ip": "200.75.51.132", "name": "Movistar Chile", "location": "Chile", "city": "Santiago", "lat": -33.4489, "lon": -70.6693, "country_code": "CL"},
    {"ip": "200.1.123.46", "name": "UNE Colombia", "location": "Colombia", "city": "Bogotá", "lat": 4.7110, "lon": -74.0721, "country_code": "CO"},

    # Africa
    {"ip": "41.231.21.7", "name": "Tunisie Telecom", "location": "Tunisia", "city": "Tunis", "lat": 36.8065, "lon": 10.1815, "country_code": "TN"},
    {"ip": "197.0.14.29", "name": "Maroc Telecom", "location": "Morocco", "city": "Casablanca", "lat": 33.5731, "lon": -7.5898, "country_code": "MA"},
    {"ip": "197.234.4.4", "name": "MainOne Nigeria", "location": "Nigeria", "city": "Lagos", "lat": 6.5244, "lon": 3.3792, "country_code": "NG"},
    {"ip": "196.28.127.4", "name": "Telkom SA", "location": "South Africa", "city": "Johannesburg", "lat": -26.2041, "lon": 28.0473, "country_code": "ZA"},
    {"ip": "41.63.145.2", "name": "MTN SA", "location": "South Africa", "city": "Cape Town", "lat": -33.9249, "lon": 18.4241, "country_code": "ZA"},
    {"ip": "41.217.204.165", "name": "Safaricom Kenya", "location": "Kenya", "city": "Nairobi", "lat": -1.2921, "lon": 36.8219, "country_code": "KE"},
    {"ip": "41.202.224.130", "name": "Ghana Telecom", "location": "Ghana", "city": "Accra", "lat": 5.6037, "lon": -0.1870, "country_code": "GH"},

    # Oceania
    {"ip": "61.88.88.88", "name": "Telstra Australia", "location": "Australia", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "country_code": "AU"},
    {"ip": "203.16.49.2", "name": "Optus Australia", "location": "Australia", "city": "Melbourne", "lat": -37.8136, "lon": 144.9631, "country_code": "AU"},
    {"ip": "202.27.158.40", "name": "Spark NZ", "location": "New Zealand", "city": "Auckland", "lat": -36.8485, "lon": 174.7633, "country_code": "NZ"},
]

# Supported DNS record types
RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA']


@dataclass
class DNSResult:
    """Result from a single DNS query"""
    server_ip: str
    server_name: str
    location: str
    city: str
    country_code: str
    lat: float
    lon: float
    record_type: str
    records: List[str]
    ttl: Optional[int]
    response_time_ms: float
    success: bool
    error: Optional[str] = None


class DNSPropagationChecker:
    """Check DNS propagation across global servers"""

    def __init__(self, timeout: float = 3.0, servers: Optional[List[Dict]] = None):
        self.timeout = timeout
        self.servers = servers or DNS_SERVERS

    async def check_single_server(
        self,
        domain: str,
        record_type: str,
        server: Dict[str, Any]
    ) -> DNSResult:
        """Query a single DNS server"""
        start_time = time.time()

        try:
            # Create resolver with specific nameserver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server['ip']]
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout

            # Run DNS query in thread pool (dnspython is sync)
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: resolver.resolve(domain, record_type)
            )

            response_time = (time.time() - start_time) * 1000

            # Extract records and TTL
            records = []
            ttl = None

            for rdata in answers:
                if record_type == 'MX':
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif record_type == 'SOA':
                    records.append(f"{rdata.mname} {rdata.rname} {rdata.serial}")
                elif record_type == 'SRV':
                    records.append(f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}")
                else:
                    records.append(str(rdata))

                if ttl is None:
                    ttl = answers.rrset.ttl

            return DNSResult(
                server_ip=server['ip'],
                server_name=server['name'],
                location=server['location'],
                city=server['city'],
                country_code=server['country_code'],
                lat=server['lat'],
                lon=server['lon'],
                record_type=record_type,
                records=records,
                ttl=ttl,
                response_time_ms=round(response_time, 2),
                success=True
            )

        except dns.resolver.NXDOMAIN:
            response_time = (time.time() - start_time) * 1000
            return DNSResult(
                server_ip=server['ip'],
                server_name=server['name'],
                location=server['location'],
                city=server['city'],
                country_code=server['country_code'],
                lat=server['lat'],
                lon=server['lon'],
                record_type=record_type,
                records=[],
                ttl=None,
                response_time_ms=round(response_time, 2),
                success=False,
                error="NXDOMAIN - Domain does not exist"
            )
        except dns.resolver.NoAnswer:
            response_time = (time.time() - start_time) * 1000
            return DNSResult(
                server_ip=server['ip'],
                server_name=server['name'],
                location=server['location'],
                city=server['city'],
                country_code=server['country_code'],
                lat=server['lat'],
                lon=server['lon'],
                record_type=record_type,
                records=[],
                ttl=None,
                response_time_ms=round(response_time, 2),
                success=True,  # Server responded, just no records of this type
                error=f"No {record_type} records found"
            )
        except dns.resolver.Timeout:
            response_time = (time.time() - start_time) * 1000
            return DNSResult(
                server_ip=server['ip'],
                server_name=server['name'],
                location=server['location'],
                city=server['city'],
                country_code=server['country_code'],
                lat=server['lat'],
                lon=server['lon'],
                record_type=record_type,
                records=[],
                ttl=None,
                response_time_ms=round(response_time, 2),
                success=False,
                error="Timeout"
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return DNSResult(
                server_ip=server['ip'],
                server_name=server['name'],
                location=server['location'],
                city=server['city'],
                country_code=server['country_code'],
                lat=server['lat'],
                lon=server['lon'],
                record_type=record_type,
                records=[],
                ttl=None,
                response_time_ms=round(response_time, 2),
                success=False,
                error=str(e)
            )

    async def check_propagation(
        self,
        domain: str,
        record_type: str = 'A',
        servers: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """Check DNS propagation across multiple servers"""
        servers_to_check = servers or self.servers

        if record_type not in RECORD_TYPES:
            raise ValueError(f"Invalid record type. Supported: {RECORD_TYPES}")

        # Run all queries concurrently
        tasks = [
            self.check_single_server(domain, record_type, server)
            for server in servers_to_check
        ]

        results = await asyncio.gather(*tasks)

        # Analyze results
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]

        # Find unique record values
        all_records = set()
        for r in successful:
            for record in r.records:
                all_records.add(record)

        # Calculate propagation statistics
        total_servers = len(results)
        responding_servers = len(successful)
        propagation_percentage = (responding_servers / total_servers * 100) if total_servers > 0 else 0

        # Find most common record value
        record_counts = {}
        for r in successful:
            for record in r.records:
                record_counts[record] = record_counts.get(record, 0) + 1

        most_common_record = max(record_counts.items(), key=lambda x: x[1])[0] if record_counts else None

        # Check if all successful servers have the same records
        is_fully_propagated = len(all_records) <= 1 and responding_servers == total_servers

        # Calculate average response time
        avg_response_time = sum(r.response_time_ms for r in successful) / len(successful) if successful else 0

        return {
            'domain': domain,
            'record_type': record_type,
            'timestamp': time.time(),
            'summary': {
                'total_servers': total_servers,
                'responding_servers': responding_servers,
                'failed_servers': len(failed),
                'propagation_percentage': round(propagation_percentage, 1),
                'is_fully_propagated': is_fully_propagated,
                'unique_records': list(all_records),
                'most_common_record': most_common_record,
                'average_response_time_ms': round(avg_response_time, 2)
            },
            'results': [
                {
                    'server_ip': r.server_ip,
                    'server_name': r.server_name,
                    'location': r.location,
                    'city': r.city,
                    'country_code': r.country_code,
                    'lat': r.lat,
                    'lon': r.lon,
                    'records': r.records,
                    'ttl': r.ttl,
                    'response_time_ms': r.response_time_ms,
                    'success': r.success,
                    'error': r.error
                }
                for r in results
            ]
        }

    def get_servers_list(self) -> List[Dict[str, Any]]:
        """Get list of available DNS servers with their locations"""
        return [
            {
                'ip': s['ip'],
                'name': s['name'],
                'location': s['location'],
                'city': s['city'],
                'country_code': s['country_code'],
                'lat': s['lat'],
                'lon': s['lon']
            }
            for s in self.servers
        ]


# Singleton instance
dns_checker = DNSPropagationChecker()


def get_supported_record_types() -> List[str]:
    """Get list of supported DNS record types"""
    return RECORD_TYPES.copy()
