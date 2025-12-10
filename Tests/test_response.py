"""
Unit Tests for SOAR/Response/response.py

Tests response action execution, device isolation logic, and validation.
"""

import pytest
import os
import sys
import tempfile
import yaml
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Response.response import respond, _validate_triaged_alert


class TestValidateTriagedAlert:
    """Test suite for _validate_triaged_alert function."""
    
    def test_validate_with_valid_alert(self, valid_triaged_alert):
        """Test validation with valid triaged alert."""
        # Should not raise exception
        _validate_triaged_alert(valid_triaged_alert)
    
    def test_validate_non_dict_raises_error(self):
        """Test that non-dict alert raises ValueError."""
        with pytest.raises(ValueError, match="alert must be a dictionary"):
            _validate_triaged_alert("not a dict")
    
    def test_validate_missing_incident_id_raises_error(self):
        """Test that missing incident_id raises ValueError."""
        alert = {
            "triage": {"severity_score": 80}
        }
        
        with pytest.raises(ValueError, match="incident_id"):
            _validate_triaged_alert(alert)
    
    def test_validate_empty_incident_id_raises_error(self):
        """Test that empty incident_id raises ValueError."""
        alert = {
            "incident_id": "",
            "triage": {"severity_score": 80}
        }
        
        with pytest.raises(ValueError, match="incident_id"):
            _validate_triaged_alert(alert)
    
    def test_validate_missing_triage_raises_error(self):
        """Test that missing triage block raises ValueError."""
        alert = {
            "incident_id": "INC-123"
        }
        
        with pytest.raises(ValueError, match="triage.*dictionary"):
            _validate_triaged_alert(alert)
    
    def test_validate_missing_severity_score_raises_error(self):
        """Test that missing severity_score raises ValueError."""
        alert = {
            "incident_id": "INC-123",
            "triage": {}
        }
        
        with pytest.raises(ValueError, match="severity_score.*number"):
            _validate_triaged_alert(alert)
    
    def test_validate_non_numeric_severity_raises_error(self):
        """Test that non-numeric severity raises ValueError."""
        alert = {
            "incident_id": "INC-123",
            "triage": {"severity_score": "high"}
        }
        
        with pytest.raises(ValueError, match="severity_score.*number"):
            _validate_triaged_alert(alert)


class TestRespondBasicFunctionality:
    """Test suite for basic respond() function behavior."""
    
    def test_respond_returns_alert_with_actions(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that respond() returns alert with actions array."""
        # Setup temp response config
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: false
""")
        
        # Patch config path
        monkeypatch.setattr(
            "SOAR.Response.response._build_config_path",
            lambda: str(config_file)
        )
        
        # Reset singletons
        import SOAR.Response.response as response_module
        response_module._CONFIG_LOADER = None
        response_module._ALLOWLIST_LOADER = None
        response_module._DEVICE_ISOLATION_EXECUTOR = None
        
        result = respond(valid_triaged_alert)
        
        assert "actions" in result
        assert isinstance(result["actions"], list)
    
    def test_respond_initializes_empty_actions_if_missing(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that respond() initializes empty actions array if not present."""
        # Setup temp response config
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: false
""")
        
        # Patch config path
        monkeypatch.setattr(
            "SOAR.Response.response._build_config_path",
            lambda: str(config_file)
        )
        
        # Reset singletons
        import SOAR.Response.response as response_module
        response_module._CONFIG_LOADER = None
        response_module._ALLOWLIST_LOADER = None
        response_module._DEVICE_ISOLATION_EXECUTOR = None
        
        # Remove actions if present
        if "actions" in valid_triaged_alert:
            del valid_triaged_alert["actions"]
        
        result = respond(valid_triaged_alert)
        
        assert "actions" in result
        assert result["actions"] == []
    
    def test_respond_validates_alert_structure(self):
        """Test that respond() validates alert structure."""
        invalid_alert = {"incident_id": "INC-123"}
        
        with pytest.raises(ValueError):
            respond(invalid_alert)


class TestRespondDeviceIsolationDisabled:
    """Test suite for respond() with device isolation disabled."""
    
    def test_no_isolation_when_disabled(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that no isolation occurs when disabled in config."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: false
  severity_threshold: 70
""")
        
        # Patch config path
        monkeypatch.setattr(
            "SOAR.Response.response._build_config_path",
            lambda: str(config_file)
        )
        
        # Reset singletons
        import SOAR.Response.response as response_module
        response_module._CONFIG_LOADER = None
        response_module._ALLOWLIST_LOADER = None
        response_module._DEVICE_ISOLATION_EXECUTOR = None
        
        # Set high severity
        valid_triaged_alert["triage"]["severity_score"] = 90
        valid_triaged_alert["asset"] = {"device_id": "dev-9001"}
        
        result = respond(valid_triaged_alert)
        
        # No isolation action should be added
        assert len(result["actions"]) == 0


class TestRespondDeviceIsolationEnabled:
    """Test suite for respond() with device isolation enabled."""
    
    def test_isolation_when_severity_above_threshold(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that isolation occurs when severity is above threshold."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
  log_path: "../../output/isolation.log"
""")
        
        # Patch config path
        monkeypatch.setattr(
            "SOAR.Response.response._build_config_path",
            lambda: str(config_file)
        )
        
        # Reset singletons
        import SOAR.Response.response as response_module
        response_module._CONFIG_LOADER = None
        response_module._ALLOWLIST_LOADER = None
        response_module._DEVICE_ISOLATION_EXECUTOR = None
        
        # Set high severity
        valid_triaged_alert["triage"]["severity_score"] = 80
        valid_triaged_alert["asset"] = {"device_id": "dev-9001"}
        valid_triaged_alert["incident_id"] = "INC-TEST-123"
        
        result = respond(valid_triaged_alert)
        
        # Should have isolation action
        assert len(result["actions"]) == 1
        action = result["actions"][0]
        assert action["type"] == "isolate"
        assert "device:dev-9001" in action["target"]
        assert action["result"] == "isolated"
    
    def test_no_isolation_when_severity_below_threshold(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that no isolation occurs when severity is below threshold."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        # Patch config path
        monkeypatch.setattr(
            "SOAR.Response.response._build_config_path",
            lambda: str(config_file)
        )
        
        # Reset singletons
        import SOAR.Response.response as response_module
        response_module._CONFIG_LOADER = None
        response_module._ALLOWLIST_LOADER = None
        response_module._DEVICE_ISOLATION_EXECUTOR = None
        
        # Set low severity
        valid_triaged_alert["triage"]["severity_score"] = 40
        valid_triaged_alert["asset"] = {"device_id": "dev-9001"}
        
        result = respond(valid_triaged_alert)
        
        # No isolation action should be added
        assert len(result["actions"]) == 0
    
    def test_no_isolation_when_device_allowlisted(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that no isolation occurs for allowlisted device."""
        config_file = tmp_path / "config.yml"
        allowlist_file = tmp_path / "allowlist.yml"
        
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
  allowlist_path: "allowlist.yml"
""")
        
        allowlist_file.write_text("""
assets:
  device_ids:
    - "dev-protected-123"
""")
        
        # Patch config path
        monkeypatch.setattr(
            "SOAR.Response.response._build_config_path",
            lambda: str(config_file)
        )
        
        # Reset singletons
        import SOAR.Response.response as response_module
        response_module._CONFIG_LOADER = None
        response_module._ALLOWLIST_LOADER = None
        response_module._DEVICE_ISOLATION_EXECUTOR = None
        
        # Set high severity but allowlisted device
        valid_triaged_alert["triage"]["severity_score"] = 90
        valid_triaged_alert["asset"] = {"device_id": "dev-protected-123"}
        
        result = respond(valid_triaged_alert)
        
        # No isolation action should be added
        assert len(result["actions"]) == 0
    
    def test_no_isolation_when_device_id_missing(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that no isolation occurs when device_id is missing."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        # Patch config path
        monkeypatch.setattr(
            "SOAR.Response.response._build_config_path",
            lambda: str(config_file)
        )
        
        # Reset singletons
        import SOAR.Response.response as response_module
        response_module._CONFIG_LOADER = None
        response_module._ALLOWLIST_LOADER = None
        response_module._DEVICE_ISOLATION_EXECUTOR = None
        
        # Set high severity but no device_id
        valid_triaged_alert["triage"]["severity_score"] = 90
        valid_triaged_alert["asset"] = {}
        
        result = respond(valid_triaged_alert)
        
        # No isolation action should be added
        assert len(result["actions"]) == 0


class TestRespondEdgeCases:
    """Test suite for respond() edge cases."""
    
    def test_respond_preserves_existing_actions(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that respond() preserves existing actions."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
  log_path: "../../output/isolation.log"
""")
        
        # Patch config path
        monkeypatch.setattr(
            "SOAR.Response.response._build_config_path",
            lambda: str(config_file)
        )
        
        # Reset singletons
        import SOAR.Response.response as response_module
        response_module._CONFIG_LOADER = None
        response_module._ALLOWLIST_LOADER = None
        response_module._DEVICE_ISOLATION_EXECUTOR = None
        
        # Add existing action
        valid_triaged_alert["actions"] = [
            {"type": "existing", "target": "something"}
        ]
        valid_triaged_alert["triage"]["severity_score"] = 80
        valid_triaged_alert["asset"] = {"device_id": "dev-9001"}
        
        result = respond(valid_triaged_alert)
        
        # Should have 2 actions: existing + isolation
        assert len(result["actions"]) == 2
        assert result["actions"][0]["type"] == "existing"
        assert result["actions"][1]["type"] == "isolate"
    
    def test_respond_handles_missing_asset_block(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that respond() handles missing asset block gracefully."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        # Patch config path
        monkeypatch.setattr(
            "SOAR.Response.response._build_config_path",
            lambda: str(config_file)
        )
        
        # Reset singletons
        import SOAR.Response.response as response_module
        response_module._CONFIG_LOADER = None
        response_module._ALLOWLIST_LOADER = None
        response_module._DEVICE_ISOLATION_EXECUTOR = None
        
        # Remove asset block
        if "asset" in valid_triaged_alert:
            del valid_triaged_alert["asset"]
        
        valid_triaged_alert["triage"]["severity_score"] = 90
        
        result = respond(valid_triaged_alert)
        
        # No isolation should occur (no device_id)
        assert len(result["actions"]) == 0
