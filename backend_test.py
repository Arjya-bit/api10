#!/usr/bin/env python3

import requests
import sys
import json
from datetime import datetime
from typing import Dict, List, Any

class APIGuardianTester:
    def __init__(self, base_url="https://api-shield-3.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.failed_tests = []
        self.passed_tests = []

    def log_test(self, name: str, success: bool, details: str = ""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            self.passed_tests.append(name)
            print(f"✅ {name} - PASSED")
        else:
            self.failed_tests.append({"test": name, "details": details})
            print(f"❌ {name} - FAILED: {details}")

    def run_test(self, name: str, method: str, endpoint: str, expected_status: int, data: Dict = None) -> tuple:
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=30)
            elif method == 'PATCH':
                response = requests.patch(url, json=data, headers=headers, timeout=30)
            else:
                self.log_test(name, False, f"Unsupported method: {method}")
                return False, {}

            success = response.status_code == expected_status
            
            if success:
                try:
                    response_data = response.json() if response.content else {}
                    self.log_test(name, True)
                    return True, response_data
                except json.JSONDecodeError:
                    self.log_test(name, False, f"Invalid JSON response")
                    return False, {}
            else:
                error_details = f"Expected {expected_status}, got {response.status_code}"
                try:
                    if response.content:
                        error_response = response.json()
                        error_details += f" - {error_response}"
                except:
                    error_details += f" - Response: {response.text[:200]}"
                self.log_test(name, False, error_details)
                return False, {}

        except requests.exceptions.RequestException as e:
            self.log_test(name, False, f"Request failed: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test GET /api/ - root endpoint"""
        success, data = self.run_test(
            "Root Endpoint",
            "GET", 
            "",
            200
        )
        return success and "message" in data

    def test_dashboard_stats(self):
        """Test GET /api/dashboard/stats"""
        success, data = self.run_test(
            "Dashboard Stats",
            "GET",
            "dashboard/stats",
            200
        )
        
        if success:
            required_keys = ["vulnerabilities", "scans", "endpoints", "security_score"]
            missing_keys = [key for key in required_keys if key not in data]
            if missing_keys:
                self.log_test("Dashboard Stats Structure", False, f"Missing keys: {missing_keys}")
                return False
            else:
                self.log_test("Dashboard Stats Structure", True)
                return True
        return False

    def test_seed_data(self):
        """Test POST /api/seed - seed sample data"""
        success, data = self.run_test(
            "Seed Data",
            "POST",
            "seed",
            200
        )
        return success and "message" in data

    def test_vulnerabilities_crud(self):
        """Test vulnerabilities CRUD operations"""
        # Test GET vulnerabilities
        success, vulns = self.run_test(
            "Get Vulnerabilities",
            "GET",
            "vulnerabilities",
            200
        )
        
        if not success:
            return False

        # Test POST vulnerability
        vuln_data = {
            "title": "Test Vulnerability",
            "description": "Test description for automated testing",
            "severity": "medium",
            "endpoint": "/api/test",
            "method": "GET",
            "category": "Testing"
        }
        
        success, created_vuln = self.run_test(
            "Create Vulnerability",
            "POST",
            "vulnerabilities",
            200
        )
        
        if success and "id" in created_vuln:
            # Test GET specific vulnerability
            vuln_id = created_vuln["id"]
            success, _ = self.run_test(
                "Get Specific Vulnerability",
                "GET",
                f"vulnerabilities/{vuln_id}",
                200
            )
            return success
        
        return False

    def test_scans_crud(self):
        """Test scans CRUD operations"""
        # Test GET scans
        success, _ = self.run_test(
            "Get Scans",
            "GET",
            "scans",
            200
        )
        
        if not success:
            return False

        # Test POST scan
        scan_data = {
            "name": "Test Scan",
            "target_url": "https://api.example.com",
            "scan_type": "quick",
            "modules": ["test_module"]
        }
        
        success, created_scan = self.run_test(
            "Create Scan",
            "POST",
            "scans",
            200
        )
        
        return success and "id" in created_scan

    def test_alerts_crud(self):
        """Test alerts CRUD operations"""
        # Test GET alerts
        success, _ = self.run_test(
            "Get Alerts",
            "GET",
            "alerts",
            200
        )
        
        if not success:
            return False

        # Test POST alert
        alert_data = {
            "title": "Test Alert",
            "message": "Test alert message",
            "alert_type": "vulnerability",
            "severity": "medium",
            "source": "test_scanner"
        }
        
        success, created_alert = self.run_test(
            "Create Alert",
            "POST",
            "alerts",
            200
        )
        
        if success and "id" in created_alert:
            # Test acknowledge alert
            alert_id = created_alert["id"]
            success, _ = self.run_test(
                "Acknowledge Alert",
                "PATCH",
                f"alerts/{alert_id}/acknowledge",
                200
            )
            return success
        
        return False

    def test_endpoints_crud(self):
        """Test endpoints CRUD operations"""
        # Test GET endpoints
        success, _ = self.run_test(
            "Get Endpoints",
            "GET",
            "endpoints",
            200
        )
        
        if not success:
            return False

        # Test POST endpoint
        endpoint_data = {
            "path": "/api/test/endpoint",
            "method": "GET",
            "description": "Test endpoint for automated testing",
            "auth_required": False,
            "tags": ["test"]
        }
        
        success, created_endpoint = self.run_test(
            "Create Endpoint",
            "POST",
            "endpoints",
            200
        )
        
        return success and "id" in created_endpoint

    def test_metrics_endpoints(self):
        """Test metrics endpoints"""
        # Test GET metrics
        success, _ = self.run_test(
            "Get Metrics",
            "GET",
            "metrics",
            200
        )
        
        if not success:
            return False

        # Test GET metrics trends
        success, trends = self.run_test(
            "Get Metrics Trends",
            "GET",
            "metrics/trends",
            200
        )
        
        if success:
            required_keys = ["daily_vulnerabilities", "scan_activity", "category_distribution"]
            missing_keys = [key for key in required_keys if key not in trends]
            if missing_keys:
                self.log_test("Metrics Trends Structure", False, f"Missing keys: {missing_keys}")
                return False
            else:
                self.log_test("Metrics Trends Structure", True)
                return True
        
        return False

    def test_reports_crud(self):
        """Test reports CRUD operations"""
        # Test GET reports
        success, _ = self.run_test(
            "Get Reports",
            "GET",
            "reports",
            200
        )
        
        if not success:
            return False

        # Test POST report
        report_data = {
            "id": "test-report-123",
            "name": "Test Report",
            "report_type": "json",
            "content": {"test": "data"}
        }
        
        success, _ = self.run_test(
            "Create Report",
            "POST",
            "reports",
            200
        )
        
        return success

    def test_threat_intel_ip_analysis(self):
        """Test IP analysis with VirusTotal and AbuseIPDB"""
        # Test with a known safe IP (Google DNS)
        success, data = self.run_test(
            "IP Analysis - Google DNS",
            "POST",
            "analysis/ip?ip_address=8.8.8.8",
            200
        )
        
        if success:
            required_keys = ["ip_address", "threat_level", "vt_malicious", "vt_suspicious", 
                           "abuse_confidence_score", "analyzed_at"]
            missing_keys = [key for key in required_keys if key not in data]
            if missing_keys:
                self.log_test("IP Analysis Structure", False, f"Missing keys: {missing_keys}")
                return False
            else:
                self.log_test("IP Analysis Structure", True)
                # Verify IP address matches
                if data.get("ip_address") == "8.8.8.8":
                    self.log_test("IP Analysis Data Integrity", True)
                    return True
                else:
                    self.log_test("IP Analysis Data Integrity", False, f"IP mismatch: {data.get('ip_address')}")
                    return False
        return False

    def test_threat_intel_url_analysis(self):
        """Test URL analysis with VirusTotal"""
        # Test with a known safe URL
        success, data = self.run_test(
            "URL Analysis - Google",
            "POST",
            "analysis/url?url=https://www.google.com",
            200
        )
        
        if success:
            required_keys = ["url", "threat_level", "vt_malicious", "vt_suspicious", "analyzed_at"]
            missing_keys = [key for key in required_keys if key not in data]
            if missing_keys:
                self.log_test("URL Analysis Structure", False, f"Missing keys: {missing_keys}")
                return False
            else:
                self.log_test("URL Analysis Structure", True)
                # Verify URL matches
                if data.get("url") == "https://www.google.com":
                    self.log_test("URL Analysis Data Integrity", True)
                    return True
                else:
                    self.log_test("URL Analysis Data Integrity", False, f"URL mismatch: {data.get('url')}")
                    return False
        return False

    def test_threat_intel_hash_analysis(self):
        """Test hash analysis with VirusTotal"""
        # Test with a known hash (EICAR test file SHA256)
        test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        success, data = self.run_test(
            "Hash Analysis - EICAR Test",
            "POST",
            f"analysis/hash?file_hash={test_hash}",
            200
        )
        
        if success:
            required_keys = ["file_hash", "hash_type", "threat_level", "vt_malicious", 
                           "vt_suspicious", "analyzed_at"]
            missing_keys = [key for key in required_keys if key not in data]
            if missing_keys:
                self.log_test("Hash Analysis Structure", False, f"Missing keys: {missing_keys}")
                return False
            else:
                self.log_test("Hash Analysis Structure", True)
                # Verify hash matches and type is detected correctly
                if data.get("file_hash") == test_hash and data.get("hash_type") == "sha256":
                    self.log_test("Hash Analysis Data Integrity", True)
                    return True
                else:
                    self.log_test("Hash Analysis Data Integrity", False, 
                                f"Hash/type mismatch: {data.get('file_hash')}, {data.get('hash_type')}")
                    return False
        return False

    def test_threat_intel_stats(self):
        """Test analysis statistics endpoint"""
        success, data = self.run_test(
            "Analysis Stats",
            "GET",
            "analysis/stats",
            200
        )
        
        if success:
            required_keys = ["total_analyses", "by_type", "threats", "integrations"]
            missing_keys = [key for key in required_keys if key not in data]
            if missing_keys:
                self.log_test("Analysis Stats Structure", False, f"Missing keys: {missing_keys}")
                return False
            else:
                self.log_test("Analysis Stats Structure", True)
                
                # Check integrations status
                integrations = data.get("integrations", {})
                if "virustotal" in integrations and "abuseipdb" in integrations:
                    self.log_test("Integration Status Check", True)
                    return True
                else:
                    self.log_test("Integration Status Check", False, "Missing integration status")
                    return False
        return False

    def test_threat_intel_history(self):
        """Test analysis history endpoint"""
        success, data = self.run_test(
            "Analysis History",
            "GET",
            "analysis/history?limit=10",
            200
        )
        
        if success:
            # Should return a list (even if empty)
            if isinstance(data, list):
                self.log_test("Analysis History Structure", True)
                return True
            else:
                self.log_test("Analysis History Structure", False, f"Expected list, got {type(data)}")
                return False
        return False

    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting APIGuardian Backend Tests")
        print("=" * 50)
        
        # Test basic connectivity
        print("\n📡 Testing Basic Connectivity...")
        self.test_root_endpoint()
        
        # Seed data first
        print("\n🌱 Seeding Test Data...")
        self.test_seed_data()
        
        # Test dashboard
        print("\n📊 Testing Dashboard...")
        self.test_dashboard_stats()
        
        # Test CRUD operations
        print("\n🔧 Testing CRUD Operations...")
        self.test_vulnerabilities_crud()
        self.test_scans_crud()
        self.test_alerts_crud()
        self.test_endpoints_crud()
        
        # Test metrics
        print("\n📈 Testing Metrics...")
        self.test_metrics_endpoints()
        
        # Test reports
        print("\n📄 Testing Reports...")
        self.test_reports_crud()
        
        # Test Threat Intelligence
        print("\n🛡️ Testing Threat Intelligence...")
        self.test_threat_intel_stats()
        self.test_threat_intel_ip_analysis()
        self.test_threat_intel_url_analysis()
        self.test_threat_intel_hash_analysis()
        self.test_threat_intel_history()
        
        # Print summary
        print("\n" + "=" * 50)
        print(f"📊 Test Summary:")
        print(f"   Total Tests: {self.tests_run}")
        print(f"   Passed: {self.tests_passed}")
        print(f"   Failed: {len(self.failed_tests)}")
        print(f"   Success Rate: {(self.tests_passed/self.tests_run*100):.1f}%")
        
        if self.failed_tests:
            print(f"\n❌ Failed Tests:")
            for test in self.failed_tests:
                print(f"   - {test['test']}: {test['details']}")
        
        return self.tests_passed == self.tests_run

def main():
    tester = APIGuardianTester()
    success = tester.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())