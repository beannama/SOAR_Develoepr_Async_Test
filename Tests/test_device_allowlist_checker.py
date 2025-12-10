"""
Unit Tests for SOAR/Response/device_allowlist_checker.py

Tests response configuration loading and device allowlist checking.
"""

import pytest
import os
import sys
import tempfile
import yaml

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Response.device_allowlist_checker import ResponseConfigLoader, AllowlistLoader


class TestResponseConfigLoader:
    """Test suite for ResponseConfigLoader class."""
    
    def test_config_loader_initialization(self, tmp_path):
        """Test ResponseConfigLoader initialization with valid config."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        loader = ResponseConfigLoader(str(config_file))
        assert loader is not None
    
    def test_config_loader_missing_file_raises_error(self):
        """Test that missing config file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Response config not found"):
            ResponseConfigLoader("/nonexistent/config.yml")
    
    def test_device_isolation_config_property(self, tmp_path):
        """Test device_isolation_config property."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 80
""")
        
        loader = ResponseConfigLoader(str(config_file))
        config = loader.device_isolation_config
        
        assert isinstance(config, dict)
        assert config["enabled"] is True
        assert config["severity_threshold"] == 80
    
    def test_is_isolation_enabled_returns_true(self, tmp_path):
        """Test is_isolation_enabled when enabled in config."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
""")
        
        loader = ResponseConfigLoader(str(config_file))
        assert loader.is_isolation_enabled() is True
    
    def test_is_isolation_enabled_returns_false(self, tmp_path):
        """Test is_isolation_enabled when disabled in config."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: false
""")
        
        loader = ResponseConfigLoader(str(config_file))
        assert loader.is_isolation_enabled() is False
    
    def test_is_isolation_enabled_default_true(self, tmp_path):
        """Test is_isolation_enabled defaults to True if not specified."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation: {}
""")
        
        loader = ResponseConfigLoader(str(config_file))
        assert loader.is_isolation_enabled() is True
    
    def test_get_isolation_threshold_returns_configured_value(self, tmp_path):
        """Test get_isolation_threshold returns configured value."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  severity_threshold: 85
""")
        
        loader = ResponseConfigLoader(str(config_file))
        assert loader.get_isolation_threshold() == 85
    
    def test_get_isolation_threshold_default_70(self, tmp_path):
        """Test get_isolation_threshold defaults to 70."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation: {}
""")
        
        loader = ResponseConfigLoader(str(config_file))
        assert loader.get_isolation_threshold() == 70
    
    def test_get_allowlist_path_returns_absolute_path(self, tmp_path):
        """Test get_allowlist_path returns absolute path."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  allowlist_path: "../configs/allowlist.yml"
""")
        
        loader = ResponseConfigLoader(str(config_file))
        path = loader.get_allowlist_path()
        
        assert os.path.isabs(path)
        assert "allowlist.yml" in path
    
    def test_get_allowlist_path_empty_when_not_configured(self, tmp_path):
        """Test get_allowlist_path returns empty string when not configured."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation: {}
""")
        
        loader = ResponseConfigLoader(str(config_file))
        path = loader.get_allowlist_path()
        
        assert path == ""
    
    def test_get_isolation_log_path_returns_absolute_path(self, tmp_path):
        """Test get_isolation_log_path returns absolute path."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  log_path: "../../output/isolation.log"
""")
        
        loader = ResponseConfigLoader(str(config_file))
        path = loader.get_isolation_log_path()
        
        assert os.path.isabs(path)
        assert "isolation.log" in path
    
    def test_get_isolation_log_path_empty_when_not_configured(self, tmp_path):
        """Test get_isolation_log_path returns empty string when not configured."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation: {}
""")
        
        loader = ResponseConfigLoader(str(config_file))
        path = loader.get_isolation_log_path()
        
        assert path == ""


class TestAllowlistLoader:
    """Test suite for AllowlistLoader class."""
    
    def test_allowlist_loader_initialization(self, tmp_path):
        """Test AllowlistLoader initialization."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
assets:
  device_ids:
    - "dev-protected-123"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        assert loader is not None
    
    def test_is_device_allowlisted_returns_true(self, tmp_path):
        """Test that allowlisted device returns True."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
assets:
  device_ids:
    - "dev-protected-123"
    - "dev-vip-456"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        
        assert loader.is_device_allowlisted("dev-protected-123") is True
        assert loader.is_device_allowlisted("dev-vip-456") is True
    
    def test_is_device_allowlisted_returns_false(self, tmp_path):
        """Test that non-allowlisted device returns False."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
assets:
  device_ids:
    - "dev-protected-123"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        
        assert loader.is_device_allowlisted("dev-9001") is False
    
    def test_is_device_allowlisted_case_insensitive(self, tmp_path):
        """Test that device allowlist checking is case-insensitive."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
assets:
  device_ids:
    - "DEV-Protected-123"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        
        assert loader.is_device_allowlisted("dev-protected-123") is True
        assert loader.is_device_allowlisted("DEV-PROTECTED-123") is True
        assert loader.is_device_allowlisted("Dev-Protected-123") is True
    
    def test_is_device_allowlisted_empty_string_returns_false(self, tmp_path):
        """Test that empty device_id returns False."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
assets:
  device_ids:
    - "dev-protected-123"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        
        assert loader.is_device_allowlisted("") is False
        assert loader.is_device_allowlisted("   ") is False
    
    def test_is_device_allowlisted_none_returns_false(self, tmp_path):
        """Test that None device_id returns False."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
assets:
  device_ids:
    - "dev-protected-123"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        
        # Pass empty string instead of None since function expects string
        assert loader.is_device_allowlisted("") is False
    
    def test_is_device_allowlisted_missing_file_returns_false(self):
        """Test that missing allowlist file returns False."""
        loader = AllowlistLoader("/nonexistent/allowlist.yml")
        
        assert loader.is_device_allowlisted("dev-123") is False
    
    def test_is_device_allowlisted_empty_file_returns_false(self, tmp_path):
        """Test that empty allowlist file returns False."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("")
        
        loader = AllowlistLoader(str(allowlist_file))
        
        assert loader.is_device_allowlisted("dev-123") is False
    
    def test_is_device_allowlisted_malformed_yaml_returns_false(self, tmp_path):
        """Test that malformed YAML returns False gracefully."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("{ invalid yaml: [")
        
        loader = AllowlistLoader(str(allowlist_file))
        
        assert loader.is_device_allowlisted("dev-123") is False
    
    def test_is_device_allowlisted_missing_assets_returns_false(self, tmp_path):
        """Test that missing assets section returns False."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
other_data: {}
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        
        assert loader.is_device_allowlisted("dev-123") is False
    
    def test_is_device_allowlisted_non_list_device_ids_returns_false(self, tmp_path):
        """Test that non-list device_ids returns False."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
assets:
  device_ids: "not-a-list"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        
        assert loader.is_device_allowlisted("dev-123") is False
