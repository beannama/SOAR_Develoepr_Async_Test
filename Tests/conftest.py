"""
Pytest Configuration and Shared Fixtures

Provides reusable test fixtures for all test modules:
- Alert structures at different pipeline stages
- Temporary directories for file operations
- Mock configuration data
"""

import pytest
import os
import tempfile
import shutil
from typing import Dict, Any, List
from datetime import datetime


# ============================================================================
# Alert Fixtures - Pipeline Stages
# ============================================================================

@pytest.fixture
def valid_raw_alert() -> Dict[str, Any]:
    """Raw alert from SIEM (before normalization)."""
    return {
        "alert_id": "test-001",
        "source": "test-siem",
        "type": "CredentialAccess",
        "created_at": "2025-12-10T10:00:00Z",
        "asset": {
            "device_id": "dev-test-01",
            "hostname": "TEST-LAPTOP",
            "ip": "10.1.1.100"
        },
        "indicators": {
            "ipv4": ["1.2.3.4", "5.6.7.8"],
            "domains": ["bad.example.net"],
            "urls": ["http://bad.example.net/login"],
            "sha256": ["7b1f4c2d16e0a0b43cbae2f9a9c2dd7e2bb3a0aaad6c0ad66b341f8b7deadbe0"]
        },
        "raw": {
            "provider": "test",
            "workspace": "test-workspace"
        }
    }


@pytest.fixture
def valid_normalized_alert() -> Dict[str, Any]:
    """Normalized alert with flattened indicators."""
    return {
        "incident_id": "INC-20251210T100000Z-abc12345",
        "source_alert": {
            "alert_id": "test-001",
            "source": "test-siem",
            "type": "CredentialAccess",
            "created_at": "2025-12-10T10:00:00Z"
        },
        "type": "CredentialAccess",
        "asset": {
            "device_id": "dev-test-01",
            "hostname": "TEST-LAPTOP",
            "ip": "10.1.1.100"
        },
        "indicators": [
            {"type": "ipv4", "value": "1.2.3.4"},
            {"type": "ipv4", "value": "5.6.7.8"},
            {"type": "domains", "value": "bad.example.net"},
            {"type": "urls", "value": "http://bad.example.net/login"},
            {"type": "sha256", "value": "7b1f4c2d16e0a0b43cbae2f9a9c2dd7e2bb3a0aaad6c0ad66b341f8b7deadbe0"}
        ],
        "timeline": []
    }


@pytest.fixture
def valid_enriched_alert() -> Dict[str, Any]:
    """Enriched alert with risk data added to indicators."""
    return {
        "incident_id": "INC-20251210T100000Z-abc12345",
        "source_alert": {
            "alert_id": "test-001",
            "source": "test-siem",
            "type": "CredentialAccess",
            "created_at": "2025-12-10T10:00:00Z"
        },
        "type": "CredentialAccess",
        "asset": {
            "device_id": "dev-test-01",
            "hostname": "TEST-LAPTOP",
            "ip": "10.1.1.100"
        },
        "indicators": [
            {
                "type": "ipv4",
                "value": "1.2.3.4",
                "risk": {
                    "verdict": "malicious",
                    "score": 90,
                    "sources": ["defender_ti", "anomali"],
                    "provider_details": []
                }
            },
            {
                "type": "domains",
                "value": "bad.example.net",
                "risk": {
                    "verdict": "suspicious",
                    "score": 65,
                    "sources": ["defender_ti"],
                    "provider_details": []
                }
            }
        ],
        "timeline": []
    }


@pytest.fixture
def valid_triaged_alert() -> Dict[str, Any]:
    """Triaged alert with severity, bucket, and MITRE data."""
    return {
        "incident_id": "INC-20251210T100000Z-abc12345",
        "source_alert": {
            "alert_id": "test-001",
            "source": "test-siem",
            "type": "CredentialAccess",
            "created_at": "2025-12-10T10:00:00Z"
        },
        "type": "CredentialAccess",
        "asset": {
            "device_id": "dev-test-01",
            "hostname": "TEST-LAPTOP",
            "ip": "10.1.1.100"
        },
        "indicators": [
            {
                "type": "ipv4",
                "value": "1.2.3.4",
                "risk": {
                    "verdict": "malicious",
                    "score": 90,
                    "sources": ["defender_ti"],
                    "provider_details": []
                }
            }
        ],
        "triage": {
            "severity_score": 75,
            "bucket": "High",
            "tags": [],
            "suppressed": False
        },
        "mitre": {
            "techniques": ["T1078", "T1110"]
        },
        "timeline": [],
        "actions": []
    }


# ============================================================================
# Invalid Alert Fixtures - Negative Testing
# ============================================================================

@pytest.fixture
def invalid_alert_missing_field() -> Dict[str, Any]:
    """Alert missing required 'type' field."""
    return {
        "alert_id": "test-001",
        "source": "test-siem",
        "created_at": "2025-12-10T10:00:00Z",
        "indicators": {"ipv4": ["1.2.3.4"]}
    }


@pytest.fixture
def invalid_alert_wrong_type() -> Any:
    """Alert with wrong type (list instead of dict)."""
    return ["not", "a", "dict"]


@pytest.fixture
def invalid_alert_empty_string() -> Dict[str, Any]:
    """Alert with empty string in required field."""
    return {
        "alert_id": "",
        "source": "test-siem",
        "type": "Test",
        "created_at": "2025-12-10T10:00:00Z",
        "indicators": {"ipv4": ["1.2.3.4"]}
    }


# ============================================================================
# Temporary Directory Fixtures
# ============================================================================

@pytest.fixture
def temp_output_dir(tmp_path):
    """Temporary output directory for test artifacts."""
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "incidents").mkdir()
    (output_dir / "summaries").mkdir()
    yield str(output_dir)
    # Cleanup handled by tmp_path


@pytest.fixture
def temp_config_dir(tmp_path):
    """Temporary config directory with mock YAML files."""
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    
    # Create mock connectors.yml
    connectors_yml = config_dir / "connectors.yml"
    connectors_yml.write_text("""
providers:
  defender_ti:
    base_url: "https://mock.defender.ti"
  anomali:
    base_url: "https://mock.anomali"
  reversinglabs:
    base_url: "https://mock.reversinglabs"
edr:
  base_url: "https://mock.edr"
""")
    
    # Create mock allowlists.yml
    allowlist_yml = config_dir / "allowlists.yml"
    allowlist_yml.write_text("""
indicators:
  ipv4:
    - "203.0.113.10"
    - "192.168.1.1"
  domains:
    - "ok.partner.example"
    - "trusted.com"
assets:
  device_ids:
    - "dev-allowlisted-01"
    - "dev-critical-server"
""")
    
    yield str(config_dir)


@pytest.fixture
def temp_ti_dir(tmp_path):
    """Temporary TI directory with mock JSON files."""
    ti_dir = tmp_path / "ti_data"
    ti_dir.mkdir()
    
    # Create mock TI file for IP
    ip_ti = ti_dir / "anomali_ip_1.2.3.4.json"
    ip_ti.write_text("""
{
  "provider": "anomali",
  "ioc_type": "ipv4",
  "ioc_value": "1.2.3.4",
  "verdict": "malicious",
  "confidence": 95,
  "last_seen": "2025-12-10T10:00:00Z"
}
""")
    
    # Create mock TI file for domain
    domain_ti = ti_dir / "defender_ti_domain_bad.example.net.json"
    domain_ti.write_text("""
{
  "provider": "defender_ti",
  "ioc_type": "domains",
  "ioc_value": "bad.example.net",
  "verdict": "suspicious",
  "score": 65,
  "threat_types": ["phishing"]
}
""")
    
    yield str(ti_dir)


# ============================================================================
# Mock Configuration Fixtures
# ============================================================================

@pytest.fixture
def mock_triage_config() -> Dict[str, Any]:
    """Mock triage configuration."""
    return {
        "severity": {
            "base": {
                "CredentialAccess": 60,
                "Malware": 70,
                "Phishing": 50,
                "C2": 80,
                "Beaconing": 65,
                "Unknown": 40
            },
            "intel_boosts": {
                "malicious": 20,
                "suspicious": 10,
                "extra_flagged_per_ioc": 5,
                "extra_flagged_cap": 15
            }
        },
        "suppression": {
            "allowlist_path": "../configs/allowlists.yml",
            "allowlist_penalty": 25
        },
        "bucket": {
            "ranges": [
                {"name": "Suppressed", "min": 0, "max": 0},
                {"name": "Low", "min": 1, "max": 39},
                {"name": "Medium", "min": 40, "max": 69},
                {"name": "High", "min": 70, "max": 89},
                {"name": "Critical", "min": 90, "max": 100}
            ]
        },
        "mitre": {
            "mapping_path": "../configs/mitre_map.yml"
        }
    }


@pytest.fixture
def mock_response_config() -> Dict[str, Any]:
    """Mock response configuration."""
    return {
        "device_isolation": {
            "enabled": True,
            "severity_threshold": 70,
            "allowlist_path": "../configs/allowlists.yml",
            "log_path": "../../out/isolation.log"
        }
    }


# ============================================================================
# Helper Functions
# ============================================================================

@pytest.fixture
def create_temp_alert_file(tmp_path):
    """Factory fixture to create temporary alert JSON files."""
    def _create_file(alert_data: Dict[str, Any], filename: str = "test_alert.json") -> str:
        import json
        file_path = tmp_path / filename
        file_path.write_text(json.dumps(alert_data, indent=2))
        return str(file_path)
    return _create_file


@pytest.fixture
def mock_iso_timestamp():
    """Mock ISO timestamp for consistent testing."""
    return "2025-12-10T10:00:00Z"


@pytest.fixture
def mock_incident_id():
    """Mock incident ID for consistent testing."""
    return "INC-20251210T100000Z-abc12345"
