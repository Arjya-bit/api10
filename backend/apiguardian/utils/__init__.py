"""Utility functions for APIGuardian"""
import json
import logging
import os
import tempfile
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict
from pathlib import Path


def setup_logging(level: str = "INFO", json_format: bool = False):
    """Configure logging"""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    if json_format:
        formatter = JSONLogFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = [handler]
    
    return root_logger


class JSONLogFormatter(logging.Formatter):
    """JSON log formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        if hasattr(record, 'extra'):
            log_entry.update(record.extra)
        
        return json.dumps(log_entry)


def atomic_write(filepath: str, content: str):
    """Write content to file atomically using tempfile + rename"""
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    # Write to temp file in same directory
    fd, temp_path = tempfile.mkstemp(
        dir=filepath.parent,
        prefix='.tmp_',
        suffix=filepath.suffix
    )
    
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        os.replace(temp_path, filepath)
    except Exception:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


def generate_fingerprint(*args) -> str:
    """Generate SHA256 fingerprint from arguments"""
    canonical = '|'.join(str(arg) for arg in args)
    return hashlib.sha256(canonical.encode()).hexdigest()


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string to max length with ellipsis"""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + '...'


def safe_json_loads(s: str, default: Any = None) -> Any:
    """Safely parse JSON string"""
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return default


def deep_merge(base: Dict, override: Dict) -> Dict:
    """Deep merge two dictionaries"""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result
