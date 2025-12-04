"""ML-based Anomaly Detection for API Security"""
import logging
import numpy as np
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class APIRequest:
    """Representation of an API request for analysis"""
    timestamp: datetime
    method: str
    path: str
    status_code: int
    response_time: float
    request_size: int
    response_size: int
    client_ip: str
    user_agent: str
    headers: Dict[str, str]
    params: Dict[str, Any]
    
    def to_features(self) -> List[float]:
        """Convert to feature vector"""
        return [
            self.response_time,
            self.request_size,
            self.response_size,
            len(self.path),
            len(self.params),
            self._method_to_int(),
            self._hour_of_day(),
            self._status_category(),
        ]
    
    def _method_to_int(self) -> int:
        methods = {'GET': 1, 'POST': 2, 'PUT': 3, 'DELETE': 4, 'PATCH': 5}
        return methods.get(self.method.upper(), 0)
    
    def _hour_of_day(self) -> int:
        return self.timestamp.hour
    
    def _status_category(self) -> int:
        return self.status_code // 100


class AnomalyDetector:
    """Simple statistical anomaly detection for API requests"""
    
    def __init__(self, sensitivity: float = 2.0):
        self.sensitivity = sensitivity
        self.baseline: Dict[str, Dict] = {}
        self.request_history: List[APIRequest] = []
        self.max_history = 10000
    
    def learn(self, requests: List[APIRequest]):
        """Learn baseline from historical requests"""
        if not requests:
            return
        
        # Group by endpoint
        by_endpoint: Dict[str, List[APIRequest]] = {}
        for req in requests:
            key = f"{req.method}:{req.path}"
            if key not in by_endpoint:
                by_endpoint[key] = []
            by_endpoint[key].append(req)
        
        # Calculate statistics for each endpoint
        for endpoint, reqs in by_endpoint.items():
            response_times = [r.response_time for r in reqs]
            request_sizes = [r.request_size for r in reqs]
            
            self.baseline[endpoint] = {
                'count': len(reqs),
                'response_time': {
                    'mean': np.mean(response_times),
                    'std': np.std(response_times) or 1.0,
                },
                'request_size': {
                    'mean': np.mean(request_sizes),
                    'std': np.std(request_sizes) or 1.0,
                },
                'status_codes': list(set(r.status_code for r in reqs)),
            }
        
        logger.info(f"Learned baseline for {len(self.baseline)} endpoints")
    
    def analyze(self, request: APIRequest) -> Dict[str, Any]:
        """Analyze a request for anomalies"""
        anomalies = []
        score = 0.0
        
        endpoint = f"{request.method}:{request.path}"
        
        if endpoint in self.baseline:
            baseline = self.baseline[endpoint]
            
            # Check response time
            rt_mean = baseline['response_time']['mean']
            rt_std = baseline['response_time']['std']
            rt_zscore = abs(request.response_time - rt_mean) / rt_std
            
            if rt_zscore > self.sensitivity:
                anomalies.append({
                    'type': 'response_time',
                    'message': f'Unusual response time: {request.response_time:.2f}ms (baseline: {rt_mean:.2f}ms)',
                    'severity': 'medium' if rt_zscore < 3 else 'high',
                    'zscore': rt_zscore
                })
                score += rt_zscore
            
            # Check request size
            rs_mean = baseline['request_size']['mean']
            rs_std = baseline['request_size']['std']
            rs_zscore = abs(request.request_size - rs_mean) / rs_std
            
            if rs_zscore > self.sensitivity:
                anomalies.append({
                    'type': 'request_size',
                    'message': f'Unusual request size: {request.request_size} bytes',
                    'severity': 'low' if rs_zscore < 3 else 'medium',
                    'zscore': rs_zscore
                })
                score += rs_zscore
            
            # Check status code
            if request.status_code not in baseline['status_codes']:
                anomalies.append({
                    'type': 'status_code',
                    'message': f'Unexpected status code: {request.status_code}',
                    'severity': 'medium' if request.status_code < 500 else 'high',
                    'zscore': 2.0
                })
                score += 2.0
        else:
            # New endpoint
            anomalies.append({
                'type': 'new_endpoint',
                'message': f'Previously unseen endpoint: {endpoint}',
                'severity': 'info',
                'zscore': 1.0
            })
            score += 1.0
        
        # Store in history
        self.request_history.append(request)
        if len(self.request_history) > self.max_history:
            self.request_history = self.request_history[-self.max_history:]
        
        return {
            'is_anomaly': len(anomalies) > 0,
            'anomaly_score': score,
            'anomalies': anomalies,
            'endpoint': endpoint,
            'timestamp': request.timestamp.isoformat()
        }
    
    def detect_patterns(self) -> List[Dict]:
        """Detect patterns in recent requests"""
        patterns = []
        
        if len(self.request_history) < 10:
            return patterns
        
        # Check for brute force (many failed logins)
        recent = self.request_history[-100:]
        failed_auth = [r for r in recent if r.status_code == 401 or r.status_code == 403]
        if len(failed_auth) > 10:
            patterns.append({
                'type': 'brute_force',
                'message': f'{len(failed_auth)} authentication failures in recent requests',
                'severity': 'high',
                'count': len(failed_auth)
            })
        
        # Check for enumeration (sequential IDs)
        paths_with_ids = [r.path for r in recent if any(c.isdigit() for c in r.path)]
        if len(paths_with_ids) > 20:
            patterns.append({
                'type': 'enumeration',
                'message': 'Possible ID enumeration detected',
                'severity': 'medium',
                'count': len(paths_with_ids)
            })
        
        # Check for scanning (many 404s)
        not_found = [r for r in recent if r.status_code == 404]
        if len(not_found) > 20:
            patterns.append({
                'type': 'scanning',
                'message': f'{len(not_found)} 404 responses - possible endpoint scanning',
                'severity': 'medium',
                'count': len(not_found)
            })
        
        return patterns
    
    def export_baseline(self) -> str:
        """Export baseline as JSON"""
        return json.dumps(self.baseline, default=str)
    
    def import_baseline(self, data: str):
        """Import baseline from JSON"""
        self.baseline = json.loads(data)


# Global instance
anomaly_detector = AnomalyDetector()
