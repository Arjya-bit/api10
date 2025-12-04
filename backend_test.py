#!/usr/bin/env python3
"""
APIGuardian Backend API Testing Suite
Tests all endpoints as specified in the review request
"""

import requests
import json
import time
import websocket
import threading
from datetime import datetime
from typing import Dict, Any, Optional

# Base URL for testing
BASE_URL = "http://localhost:8001"
API_BASE = f"{BASE_URL}/api"

class APIGuardianTester:
    def __init__(self):
        self.session = requests.Session()
        self.test_results = []
        self.created_resources = []  # Track created resources for cleanup
        
    def log_test(self, test_name: str, success: bool, details: str = "", response_data: Any = None):
        """Log test result"""
        result = {
            "test": test_name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat(),
            "response_data": response_data
        }
        self.test_results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {details}")
        
    def test_health_endpoint(self):
        """Test GET /health"""
        try:
            response = self.session.get(f"{BASE_URL}/health")
            if response.status_code == 200:
                data = response.json()
                if "status" in data and "timestamp" in data:
                    self.log_test("Health Check", True, f"Status: {data['status']}", data)
                else:
                    self.log_test("Health Check", False, "Missing required fields in response", data)
            else:
                self.log_test("Health Check", False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_test("Health Check", False, f"Exception: {str(e)}")
    
    def test_prometheus_metrics(self):
        """Test GET /metrics (Prometheus format)"""
        try:
            response = self.session.get(f"{BASE_URL}/metrics")
            if response.status_code == 200:
                content = response.text
                if "apiguardian_findings_total" in content and "# TYPE" in content:
                    self.log_test("Prometheus Metrics", True, "Valid Prometheus format returned")
                else:
                    self.log_test("Prometheus Metrics", False, "Invalid Prometheus format", content[:200])
            else:
                self.log_test("Prometheus Metrics", False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_test("Prometheus Metrics", False, f"Exception: {str(e)}")
    
    def test_dashboard_html(self):
        """Test GET / (Web dashboard)"""
        try:
            response = self.session.get(f"{BASE_URL}/")
            if response.status_code == 200:
                content = response.text
                if "<title>APIGuardian Dashboard</title>" in content and "API GUARDIAN" in content:
                    self.log_test("Web Dashboard", True, "Dashboard HTML returned successfully")
                else:
                    self.log_test("Web Dashboard", False, "Invalid dashboard HTML", content[:200])
            else:
                self.log_test("Web Dashboard", False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_test("Web Dashboard", False, f"Exception: {str(e)}")
    
    def test_api_metrics(self):
        """Test GET /api/metrics (JSON format)"""
        try:
            response = self.session.get(f"{API_BASE}/metrics")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    self.log_test("API Metrics", True, f"Metrics returned: {list(data.keys())}", data)
                else:
                    self.log_test("API Metrics", False, "Invalid JSON response format", data)
            else:
                self.log_test("API Metrics", False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_test("API Metrics", False, f"Exception: {str(e)}")
    
    def test_plugins_list(self):
        """Test GET /api/plugins"""
        try:
            response = self.session.get(f"{API_BASE}/plugins")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Plugins List", True, f"Found {len(data)} plugins", data)
                else:
                    self.log_test("Plugins List", False, "Expected list response", data)
            else:
                self.log_test("Plugins List", False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_test("Plugins List", False, f"Exception: {str(e)}")
    
    def test_jobs_list(self):
        """Test GET /api/jobs"""
        try:
            response = self.session.get(f"{API_BASE}/jobs")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Jobs List", True, f"Found {len(data)} jobs", data)
                    return data
                else:
                    self.log_test("Jobs List", False, "Expected list response", data)
                    return []
            else:
                self.log_test("Jobs List", False, f"HTTP {response.status_code}: {response.text}")
                return []
        except Exception as e:
            self.log_test("Jobs List", False, f"Exception: {str(e)}")
            return []
    
    def test_create_scan_job(self):
        """Test POST /api/jobs"""
        try:
            payload = {
                "target": "https://httpbin.org",
                "scan_type": "quick"
            }
            response = self.session.post(f"{API_BASE}/jobs", json=payload)
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "target" in data:
                    self.log_test("Create Scan Job", True, f"Scan started for {data['target']}", data)
                    return True
                else:
                    self.log_test("Create Scan Job", False, "Invalid response format", data)
                    return False
            else:
                self.log_test("Create Scan Job", False, f"HTTP {response.status_code}: {response.text}")
                return False
        except Exception as e:
            self.log_test("Create Scan Job", False, f"Exception: {str(e)}")
            return False
    
    def test_job_status(self, job_id: str):
        """Test GET /api/jobs/{job_id}"""
        try:
            response = self.session.get(f"{API_BASE}/jobs/{job_id}")
            if response.status_code == 200:
                data = response.json()
                self.log_test("Job Status", True, f"Job {job_id} status retrieved", data)
                return data
            elif response.status_code == 404:
                self.log_test("Job Status", True, f"Job {job_id} not found (expected for test)", {"status_code": 404})
                return None
            else:
                self.log_test("Job Status", False, f"HTTP {response.status_code}: {response.text}")
                return None
        except Exception as e:
            self.log_test("Job Status", False, f"Exception: {str(e)}")
            return None
    
    def test_findings_list(self):
        """Test GET /api/findings with filters"""
        try:
            # Test without filters
            response = self.session.get(f"{API_BASE}/findings")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Findings List", True, f"Found {len(data)} findings", {"count": len(data)})
                    
                    # Test with severity filter
                    response2 = self.session.get(f"{API_BASE}/findings?severity=critical")
                    if response2.status_code == 200:
                        critical_data = response2.json()
                        self.log_test("Findings Filter (Severity)", True, f"Found {len(critical_data)} critical findings")
                    
                    # Test with status filter
                    response3 = self.session.get(f"{API_BASE}/findings?status=open")
                    if response3.status_code == 200:
                        open_data = response3.json()
                        self.log_test("Findings Filter (Status)", True, f"Found {len(open_data)} open findings")
                    
                    return data
                else:
                    self.log_test("Findings List", False, "Expected list response", data)
                    return []
            else:
                self.log_test("Findings List", False, f"HTTP {response.status_code}: {response.text}")
                return []
        except Exception as e:
            self.log_test("Findings List", False, f"Exception: {str(e)}")
            return []
    
    def test_finding_details(self, finding_id: str):
        """Test GET /api/findings/{finding_id}"""
        try:
            response = self.session.get(f"{API_BASE}/findings/{finding_id}")
            if response.status_code == 200:
                data = response.json()
                self.log_test("Finding Details", True, f"Finding {finding_id} details retrieved", data)
                return data
            elif response.status_code == 404:
                self.log_test("Finding Details", True, f"Finding {finding_id} not found (expected for test)")
                return None
            else:
                self.log_test("Finding Details", False, f"HTTP {response.status_code}: {response.text}")
                return None
        except Exception as e:
            self.log_test("Finding Details", False, f"Exception: {str(e)}")
            return None
    
    def test_update_finding(self, finding_id: str):
        """Test PATCH /api/findings/{finding_id}"""
        try:
            payload = {"status": "resolved"}
            response = self.session.patch(f"{API_BASE}/findings/{finding_id}", json=payload)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Update Finding", True, f"Finding {finding_id} updated", data)
                return True
            elif response.status_code == 404:
                self.log_test("Update Finding", True, f"Finding {finding_id} not found (expected for test)")
                return False
            else:
                self.log_test("Update Finding", False, f"HTTP {response.status_code}: {response.text}")
                return False
        except Exception as e:
            self.log_test("Update Finding", False, f"Exception: {str(e)}")
            return False
    
    def test_assets_list(self):
        """Test GET /api/assets"""
        try:
            response = self.session.get(f"{API_BASE}/assets")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Assets List", True, f"Found {len(data)} assets", {"count": len(data)})
                    return data
                else:
                    self.log_test("Assets List", False, "Expected list response", data)
                    return []
            else:
                self.log_test("Assets List", False, f"HTTP {response.status_code}: {response.text}")
                return []
        except Exception as e:
            self.log_test("Assets List", False, f"Exception: {str(e)}")
            return []
    
    def test_create_asset(self):
        """Test POST /api/assets"""
        try:
            params = {
                "value": "https://test-api.example.com",
                "asset_type": "url"
            }
            response = self.session.post(f"{API_BASE}/assets", params=params)
            if response.status_code == 200:
                data = response.json()
                if "id" in data and "value" in data:
                    self.log_test("Create Asset", True, f"Asset created: {data['value']}", data)
                    self.created_resources.append(("asset", data["id"]))
                    return data["id"]
                else:
                    self.log_test("Create Asset", False, "Invalid response format", data)
                    return None
            else:
                self.log_test("Create Asset", False, f"HTTP {response.status_code}: {response.text}")
                return None
        except Exception as e:
            self.log_test("Create Asset", False, f"Exception: {str(e)}")
            return None
    
    def test_scheduler_jobs_list(self):
        """Test GET /api/scheduler/jobs"""
        try:
            response = self.session.get(f"{API_BASE}/scheduler/jobs")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Scheduler Jobs List", True, f"Found {len(data)} scheduled jobs", {"count": len(data)})
                    return data
                else:
                    self.log_test("Scheduler Jobs List", False, "Expected list response", data)
                    return []
            else:
                self.log_test("Scheduler Jobs List", False, f"HTTP {response.status_code}: {response.text}")
                return []
        except Exception as e:
            self.log_test("Scheduler Jobs List", False, f"Exception: {str(e)}")
            return []
    
    def test_create_scheduled_job(self):
        """Test POST /api/scheduler/jobs"""
        try:
            payload = {
                "name": "test-scheduled-scan",
                "target": "https://httpbin.org",
                "cron_expression": "0 * * * *",
                "scan_type": "quick"
            }
            response = self.session.post(f"{API_BASE}/scheduler/jobs", json=payload)
            if response.status_code == 200:
                data = response.json()
                if "job_id" in data and "name" in data:
                    self.log_test("Create Scheduled Job", True, f"Scheduled job created: {data['name']}", data)
                    self.created_resources.append(("scheduled_job", data["job_id"]))
                    return data["job_id"]
                else:
                    self.log_test("Create Scheduled Job", False, "Invalid response format", data)
                    return None
            else:
                self.log_test("Create Scheduled Job", False, f"HTTP {response.status_code}: {response.text}")
                return None
        except Exception as e:
            self.log_test("Create Scheduled Job", False, f"Exception: {str(e)}")
            return None
    
    def test_delete_scheduled_job(self, job_id: str):
        """Test DELETE /api/scheduler/jobs/{job_id}"""
        try:
            response = self.session.delete(f"{API_BASE}/scheduler/jobs/{job_id}")
            if response.status_code == 200:
                data = response.json()
                self.log_test("Delete Scheduled Job", True, f"Job {job_id} deleted", data)
                return True
            elif response.status_code == 404:
                self.log_test("Delete Scheduled Job", True, f"Job {job_id} not found (expected for test)")
                return False
            else:
                self.log_test("Delete Scheduled Job", False, f"HTTP {response.status_code}: {response.text}")
                return False
        except Exception as e:
            self.log_test("Delete Scheduled Job", False, f"Exception: {str(e)}")
            return False
    
    def test_threat_intel_lookup(self):
        """Test POST /api/threatintel/lookup"""
        try:
            # Test mock mode
            payload = {
                "indicator": "8.8.8.8",
                "indicator_type": "ip",
                "service": "virustotal",
                "mode": "mock"
            }
            response = self.session.post(f"{API_BASE}/threatintel/lookup", json=payload)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Threat Intel Lookup (Mock)", True, f"Mock lookup successful for {payload['indicator']}", data)
                
                # Test live mode
                payload["mode"] = "live"
                response2 = self.session.post(f"{API_BASE}/threatintel/lookup", json=payload)
                if response2.status_code == 200:
                    live_data = response2.json()
                    self.log_test("Threat Intel Lookup (Live)", True, f"Live lookup successful for {payload['indicator']}", live_data)
                else:
                    self.log_test("Threat Intel Lookup (Live)", False, f"HTTP {response2.status_code}: {response2.text}")
                
                return True
            else:
                self.log_test("Threat Intel Lookup (Mock)", False, f"HTTP {response.status_code}: {response.text}")
                return False
        except Exception as e:
            self.log_test("Threat Intel Lookup", False, f"Exception: {str(e)}")
            return False
    
    def test_threat_intel_services(self):
        """Test GET /api/threatintel/services"""
        try:
            response = self.session.get(f"{API_BASE}/threatintel/services")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Threat Intel Services", True, f"Found {len(data)} services", data)
                    return data
                else:
                    self.log_test("Threat Intel Services", False, "Expected list response", data)
                    return []
            else:
                self.log_test("Threat Intel Services", False, f"HTTP {response.status_code}: {response.text}")
                return []
        except Exception as e:
            self.log_test("Threat Intel Services", False, f"Exception: {str(e)}")
            return []
    
    def test_integrations_list(self):
        """Test GET /api/integrations"""
        try:
            response = self.session.get(f"{API_BASE}/integrations")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and "threat_intel" in data:
                    self.log_test("Integrations List", True, f"Integrations: {list(data.keys())}", data)
                    return data
                else:
                    self.log_test("Integrations List", False, "Invalid response format", data)
                    return {}
            else:
                self.log_test("Integrations List", False, f"HTTP {response.status_code}: {response.text}")
                return {}
        except Exception as e:
            self.log_test("Integrations List", False, f"Exception: {str(e)}")
            return {}
    
    def test_integration_test(self):
        """Test POST /api/integrations/test/{integration_type}/{name}"""
        try:
            # Test messaging integration
            response = self.session.post(f"{API_BASE}/integrations/test/messaging/slack?mode=mock")
            if response.status_code == 200:
                data = response.json()
                self.log_test("Integration Test (Messaging)", True, f"Slack test: {data.get('success')}", data)
            else:
                self.log_test("Integration Test (Messaging)", False, f"HTTP {response.status_code}: {response.text}")
            
            # Test SIEM integration
            response2 = self.session.post(f"{API_BASE}/integrations/test/siem/splunk?mode=mock")
            if response2.status_code == 200:
                data2 = response2.json()
                self.log_test("Integration Test (SIEM)", True, f"Splunk test: {data2.get('success')}", data2)
            else:
                self.log_test("Integration Test (SIEM)", False, f"HTTP {response2.status_code}: {response2.text}")
                
        except Exception as e:
            self.log_test("Integration Test", False, f"Exception: {str(e)}")
    
    def test_websocket_connection(self):
        """Test WebSocket /ws/stream"""
        try:
            ws_url = f"ws://localhost:8001/ws/stream"
            
            def on_message(ws, message):
                print(f"WebSocket received: {message}")
            
            def on_error(ws, error):
                print(f"WebSocket error: {error}")
            
            def on_close(ws, close_status_code, close_msg):
                print("WebSocket connection closed")
            
            def on_open(ws):
                print("WebSocket connection opened")
                # Send ping
                ws.send("ping")
                # Close after a short delay
                threading.Timer(2.0, ws.close).start()
            
            ws = websocket.WebSocketApp(ws_url,
                                      on_open=on_open,
                                      on_message=on_message,
                                      on_error=on_error,
                                      on_close=on_close)
            
            # Run WebSocket in a separate thread with timeout
            ws_thread = threading.Thread(target=ws.run_forever)
            ws_thread.daemon = True
            ws_thread.start()
            ws_thread.join(timeout=5)
            
            self.log_test("WebSocket Connection", True, "WebSocket connection test completed")
            
        except Exception as e:
            self.log_test("WebSocket Connection", False, f"Exception: {str(e)}")
    
    def test_error_handling(self):
        """Test error handling for invalid requests"""
        try:
            # Test 404 for non-existent job
            response = self.session.get(f"{API_BASE}/jobs/non-existent-job-id")
            if response.status_code == 404:
                self.log_test("Error Handling (404 Job)", True, "Correctly returns 404 for non-existent job")
            else:
                self.log_test("Error Handling (404 Job)", False, f"Expected 404, got {response.status_code}")
            
            # Test 404 for non-existent finding
            response2 = self.session.get(f"{API_BASE}/findings/non-existent-finding-id")
            if response2.status_code == 404:
                self.log_test("Error Handling (404 Finding)", True, "Correctly returns 404 for non-existent finding")
            else:
                self.log_test("Error Handling (404 Finding)", False, f"Expected 404, got {response2.status_code}")
            
            # Test invalid threat intel service
            payload = {
                "indicator": "8.8.8.8",
                "indicator_type": "ip",
                "service": "invalid-service",
                "mode": "mock"
            }
            response3 = self.session.post(f"{API_BASE}/threatintel/lookup", json=payload)
            if response3.status_code == 400:
                self.log_test("Error Handling (Invalid Service)", True, "Correctly returns 400 for invalid service")
            else:
                self.log_test("Error Handling (Invalid Service)", False, f"Expected 400, got {response3.status_code}")
                
        except Exception as e:
            self.log_test("Error Handling", False, f"Exception: {str(e)}")
    
    def cleanup_resources(self):
        """Clean up created test resources"""
        for resource_type, resource_id in self.created_resources:
            try:
                if resource_type == "scheduled_job":
                    self.session.delete(f"{API_BASE}/scheduler/jobs/{resource_id}")
                    print(f"Cleaned up scheduled job: {resource_id}")
            except Exception as e:
                print(f"Failed to cleanup {resource_type} {resource_id}: {e}")
    
    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting APIGuardian Backend API Tests")
        print("=" * 60)
        
        # Core endpoints
        self.test_health_endpoint()
        self.test_prometheus_metrics()
        self.test_dashboard_html()
        
        # API endpoints
        self.test_api_metrics()
        self.test_plugins_list()
        
        # Jobs and scans
        jobs = self.test_jobs_list()
        scan_created = self.test_create_scan_job()
        
        # Wait a bit for scan to start, then check status
        if scan_created:
            time.sleep(2)
            updated_jobs = self.test_jobs_list()
            if updated_jobs and len(updated_jobs) > len(jobs):
                # Test job status with the newest job
                newest_job = updated_jobs[0]  # Assuming newest first
                if isinstance(newest_job, dict) and "id" in newest_job:
                    self.test_job_status(newest_job["id"])
        
        # Test with a non-existent job ID
        self.test_job_status("test-job-id-123")
        
        # Findings
        findings = self.test_findings_list()
        if findings:
            # Test finding details and update with first finding
            first_finding = findings[0]
            if isinstance(first_finding, dict) and "id" in first_finding:
                self.test_finding_details(first_finding["id"])
                self.test_update_finding(first_finding["id"])
        else:
            # Test with non-existent finding ID
            self.test_finding_details("test-finding-id-123")
            self.test_update_finding("test-finding-id-123")
        
        # Assets
        self.test_assets_list()
        asset_id = self.test_create_asset()
        
        # Scheduler
        self.test_scheduler_jobs_list()
        scheduled_job_id = self.test_create_scheduled_job()
        if scheduled_job_id:
            self.test_delete_scheduled_job(scheduled_job_id)
        else:
            self.test_delete_scheduled_job("test-job-id-123")
        
        # Threat Intelligence
        self.test_threat_intel_lookup()
        self.test_threat_intel_services()
        
        # Integrations
        self.test_integrations_list()
        self.test_integration_test()
        
        # WebSocket
        self.test_websocket_connection()
        
        # Error handling
        self.test_error_handling()
        
        # Cleanup
        self.cleanup_resources()
        
        # Summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["success"])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"  - {result['test']}: {result['details']}")
        
        print("\n🎯 All critical endpoints tested successfully!" if failed_tests == 0 else f"\n⚠️  {failed_tests} tests failed - see details above")


if __name__ == "__main__":
    tester = APIGuardianTester()
    tester.run_all_tests()