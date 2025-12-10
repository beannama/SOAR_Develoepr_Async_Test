"""
Unit Tests for SOAR/Response/isolation_executor.py

Tests device isolation execution logic, log generation, and action tracking.
"""

import pytest
import os
import sys
import tempfile
import yaml
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Response.isolation_executor import DeviceIsolationExecutor
from SOAR.Response.device_allowlist_checker import ResponseConfigLoader, AllowlistLoader


class TestDeviceIsolationExecutorInitialization:
    """Test suite for DeviceIsolationExecutor initialization."""
    
    def test_initialization_with_valid_components(self, tmp_path):
        """Test DeviceIsolationExecutor initialization."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        assert executor is not None


class TestShouldIsolate:
    """Test suite for should_isolate method."""
    
    def test_should_isolate_when_all_conditions_met(self, tmp_path):
        """Test isolation when all conditions are met."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        # Severity 80 >= threshold 70, device not allowlisted
        result = executor.should_isolate(80, "dev-9001")
        
        assert result is True
    
    def test_should_not_isolate_when_disabled(self, tmp_path):
        """Test no isolation when disabled in config."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: false
  severity_threshold: 70
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        result = executor.should_isolate(90, "dev-9001")
        
        assert result is False
    
    def test_should_not_isolate_below_threshold(self, tmp_path):
        """Test no isolation when severity is below threshold."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        result = executor.should_isolate(50, "dev-9001")
        
        assert result is False
    
    def test_should_isolate_at_exact_threshold(self, tmp_path):
        """Test isolation when severity equals threshold."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        result = executor.should_isolate(70, "dev-9001")
        
        assert result is True
    
    def test_should_not_isolate_empty_device_id(self, tmp_path):
        """Test no isolation when device_id is empty."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        result = executor.should_isolate(90, "")
        
        assert result is False
    
    def test_should_not_isolate_allowlisted_device(self, tmp_path):
        """Test no isolation when device is allowlisted."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
assets:
  device_ids:
    - "dev-protected-123"
""")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        result = executor.should_isolate(90, "dev-protected-123")
        
        assert result is False
    
    def test_should_not_isolate_non_numeric_severity(self, tmp_path):
        """Test no isolation when severity is non-numeric."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation:
  enabled: true
  severity_threshold: 70
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        result = executor.should_isolate("high", "dev-9001")
        
        assert result is False


class TestGenerateIsolationLogEntry:
    """Test suite for generate_isolation_log_entry method."""
    
    def test_generate_log_entry_with_valid_inputs(self, tmp_path):
        """Test log entry generation with valid inputs."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("device_isolation: {}")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        log_entry = executor.generate_isolation_log_entry("dev-9001", "INC-123")
        
        # Check format: <ISO-TS> isolate device_id=<ID> incident=<INCIDENT_ID> result=isolated
        assert "isolate" in log_entry
        assert "device_id=dev-9001" in log_entry
        assert "incident=INC-123" in log_entry
        assert "result=isolated" in log_entry
        
        # Check ISO timestamp format (basic validation)
        assert log_entry[0].isdigit()  # Year starts with digit
        assert "T" in log_entry  # ISO format has T separator
        assert "Z" in log_entry  # UTC timezone indicator
    
    def test_generate_log_entry_empty_device_id_raises_error(self, tmp_path):
        """Test that empty device_id raises ValueError."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("device_isolation: {}")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        with pytest.raises(ValueError, match="device_id"):
            executor.generate_isolation_log_entry("", "INC-123")
    
    def test_generate_log_entry_empty_incident_id_raises_error(self, tmp_path):
        """Test that empty incident_id raises ValueError."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("device_isolation: {}")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        with pytest.raises(ValueError, match="incident_id"):
            executor.generate_isolation_log_entry("dev-9001", "")


class TestExecuteIsolation:
    """Test suite for execute_isolation method."""
    
    def test_execute_isolation_writes_to_log(self, tmp_path):
        """Test that execute_isolation writes to log file."""
        log_file = tmp_path / "isolation.log"
        
        config_file = tmp_path / "config.yml"
        # Use forward slashes to avoid Windows backslash escaping issues in YAML
        log_path_str = str(log_file).replace('\\', '/')
        config_file.write_text(f"""
device_isolation:
  log_path: "{log_path_str}"
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        result = executor.execute_isolation("dev-9001", "INC-123")
        
        assert result is True
        assert log_file.exists()
        
        log_content = log_file.read_text()
        assert "device_id=dev-9001" in log_content
        assert "incident=INC-123" in log_content
    
    def test_execute_isolation_appends_to_existing_log(self, tmp_path):
        """Test that execute_isolation appends to existing log."""
        log_file = tmp_path / "isolation.log"
        log_file.write_text("existing log entry\n")
        
        config_file = tmp_path / "config.yml"
        # Use forward slashes to avoid Windows backslash escaping issues in YAML
        log_path_str = str(log_file).replace('\\', '/')
        config_file.write_text(f"""
device_isolation:
  log_path: "{log_path_str}"
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        executor.execute_isolation("dev-9001", "INC-123")
        
        log_content = log_file.read_text()
        assert "existing log entry" in log_content
        assert "device_id=dev-9001" in log_content
    
    def test_execute_isolation_creates_log_directory(self, tmp_path):
        """Test that execute_isolation creates log directory if missing."""
        log_dir = tmp_path / "nested" / "dir"
        log_file = log_dir / "isolation.log"
        
        config_file = tmp_path / "config.yml"
        # Use forward slashes to avoid Windows backslash escaping issues in YAML
        log_path_str = str(log_file).replace('\\', '/')
        config_file.write_text(f"""
device_isolation:
  log_path: "{log_path_str}"
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        result = executor.execute_isolation("dev-9001", "INC-123")
        
        assert result is True
        assert log_dir.exists()
        assert log_file.exists()
    
    def test_execute_isolation_returns_false_on_empty_log_path(self, tmp_path):
        """Test that execute_isolation returns False when log path is empty."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
device_isolation: {}
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        result = executor.execute_isolation("dev-9001", "INC-123")
        
        assert result is False


class TestGenerateActionEntry:
    """Test suite for generate_action_entry method."""
    
    def test_generate_action_entry_with_valid_inputs(self, tmp_path):
        """Test action entry generation with valid inputs."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("device_isolation: {}")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        action_entry = executor.generate_action_entry("dev-9001", "INC-123")
        
        assert action_entry["type"] == "isolate"
        assert action_entry["target"] == "device:dev-9001"
        assert action_entry["result"] == "isolated"
        assert "ts" in action_entry
        
        # Validate ISO timestamp format
        ts = action_entry["ts"]
        assert "T" in ts
        assert "Z" in ts
    
    def test_generate_action_entry_empty_device_id_raises_error(self, tmp_path):
        """Test that empty device_id raises ValueError."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("device_isolation: {}")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        with pytest.raises(ValueError, match="device_id"):
            executor.generate_action_entry("", "INC-123")
    
    def test_generate_action_entry_empty_incident_id_raises_error(self, tmp_path):
        """Test that empty incident_id raises ValueError."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("device_isolation: {}")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        with pytest.raises(ValueError, match="incident_id"):
            executor.generate_action_entry("dev-9001", "")


class TestIsolationExecutorEdgeCases:
    """Test suite for edge cases in DeviceIsolationExecutor."""
    
    def test_multiple_isolations_create_multiple_log_entries(self, tmp_path):
        """Test that multiple isolations create multiple log entries."""
        log_file = tmp_path / "isolation.log"
        
        config_file = tmp_path / "config.yml"
        # Use forward slashes to avoid Windows backslash escaping issues in YAML
        log_path_str = str(log_file).replace('\\', '/')
        config_file.write_text(f"""
device_isolation:
  log_path: "{log_path_str}"
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("assets: {}")
        
        config_loader = ResponseConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        executor = DeviceIsolationExecutor(config_loader, allowlist_loader)
        
        executor.execute_isolation("dev-001", "INC-001")
        executor.execute_isolation("dev-002", "INC-002")
        executor.execute_isolation("dev-003", "INC-003")
        
        log_content = log_file.read_text()
        assert "device_id=dev-001" in log_content
        assert "device_id=dev-002" in log_content
        assert "device_id=dev-003" in log_content
        
        # Count newlines to verify 3 entries
        lines = log_content.strip().split("\n")
        assert len(lines) == 3
