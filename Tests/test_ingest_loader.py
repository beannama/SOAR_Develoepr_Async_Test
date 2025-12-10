"""
Unit Tests for SOAR/Ingest/loader.py

Tests alert ingestion from JSON files and sample alert generation.
"""

import pytest
import os
import sys
import json
import tempfile

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Ingest.loader import load_alert, SAMPLE_ALERT


class TestLoadAlertWithSample:
    """Test suite for load_alert() with --sample flag."""
    
    def test_load_sample_alert_returns_dict(self):
        """Test that sample alert returns a dictionary."""
        result = load_alert(use_sample=True)
        assert isinstance(result, dict)
    
    def test_load_sample_alert_has_required_fields(self):
        """Test that sample alert contains all required fields."""
        result = load_alert(use_sample=True)
        required_fields = ["alert_id", "source", "type", "created_at", "asset", "indicators", "raw"]
        for field in required_fields:
            assert field in result, f"Sample alert missing required field: {field}"
    
    def test_load_sample_alert_matches_constant(self):
        """Test that sample alert matches SAMPLE_ALERT constant."""
        result = load_alert(use_sample=True)
        assert result == SAMPLE_ALERT
    
    def test_sample_alert_structure_validity(self):
        """Test that SAMPLE_ALERT has valid structure."""
        assert SAMPLE_ALERT["alert_id"] == "sen-001"
        assert SAMPLE_ALERT["source"] == "sentinel"
        assert SAMPLE_ALERT["type"] == "CredentialAccess"
        assert isinstance(SAMPLE_ALERT["asset"], dict)
        assert isinstance(SAMPLE_ALERT["indicators"], dict)
        assert isinstance(SAMPLE_ALERT["raw"], dict)
    
    def test_sample_alert_indicators_structure(self):
        """Test that sample alert indicators are properly structured."""
        indicators = SAMPLE_ALERT["indicators"]
        assert "ipv4" in indicators
        assert "domains" in indicators
        assert "urls" in indicators
        assert "sha256" in indicators
        assert isinstance(indicators["ipv4"], list)
        assert isinstance(indicators["domains"], list)
        assert len(indicators["ipv4"]) > 0
    
    def test_sample_alert_asset_fields(self):
        """Test that sample alert asset has required fields."""
        asset = SAMPLE_ALERT["asset"]
        assert "device_id" in asset
        assert "hostname" in asset
        assert "ip" in asset
        assert asset["device_id"] == "dev-9001"


class TestLoadAlertFromFile:
    """Test suite for load_alert() with file path."""
    
    def test_load_valid_json_file(self, create_temp_alert_file, valid_raw_alert):
        """Test loading a valid JSON alert file."""
        file_path = create_temp_alert_file(valid_raw_alert, "valid_alert.json")
        result = load_alert(path=file_path, use_sample=False)
        
        assert isinstance(result, dict)
        assert result["alert_id"] == valid_raw_alert["alert_id"]
        assert result["source"] == valid_raw_alert["source"]
        assert result["type"] == valid_raw_alert["type"]
    
    def test_load_file_preserves_all_fields(self, create_temp_alert_file, valid_raw_alert):
        """Test that loading from file preserves all fields."""
        file_path = create_temp_alert_file(valid_raw_alert, "complete_alert.json")
        result = load_alert(path=file_path, use_sample=False)
        
        assert result == valid_raw_alert
    
    def test_load_sentinel_alert_file(self, tmp_path):
        """Test loading the actual sentinel.json alert file."""
        # Get path to real sentinel.json
        workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sentinel_path = os.path.join(workspace_root, "alerts", "sentinel.json")
        
        if os.path.exists(sentinel_path):
            result = load_alert(path=sentinel_path, use_sample=False)
            assert isinstance(result, dict)
            assert "alert_id" in result
            assert "source" in result
    
    def test_load_sumologic_alert_file(self):
        """Test loading the actual sumologic.json alert file."""
        workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sumologic_path = os.path.join(workspace_root, "alerts", "sumologic.json")
        
        if os.path.exists(sumologic_path):
            result = load_alert(path=sumologic_path, use_sample=False)
            assert isinstance(result, dict)
            assert "alert_id" in result


class TestLoadAlertErrorHandling:
    """Test suite for load_alert() error handling."""
    
    def test_file_not_found_raises_error(self):
        """Test that non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Alert file not found"):
            load_alert(path="/nonexistent/path/alert.json", use_sample=False)
    
    def test_none_path_without_sample_raises_error(self):
        """Test that None path without sample flag raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Alert file not found"):
            load_alert(path=None, use_sample=False)
    
    def test_empty_path_raises_error(self):
        """Test that empty path string raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Alert file not found"):
            load_alert(path="", use_sample=False)
    
    def test_directory_path_raises_error(self, tmp_path):
        """Test that passing a directory path raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Alert file not found"):
            load_alert(path=str(tmp_path), use_sample=False)
    
    def test_malformed_json_raises_error(self, tmp_path):
        """Test that malformed JSON raises JSONDecodeError."""
        malformed_file = tmp_path / "malformed.json"
        malformed_file.write_text("{this is not: valid json}")
        
        with pytest.raises(json.JSONDecodeError):
            load_alert(path=str(malformed_file), use_sample=False)
    
    def test_empty_file_raises_error(self, tmp_path):
        """Test that empty file raises JSONDecodeError."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")
        
        with pytest.raises(json.JSONDecodeError):
            load_alert(path=str(empty_file), use_sample=False)
    
    def test_non_json_file_raises_error(self, tmp_path):
        """Test that non-JSON file raises JSONDecodeError."""
        text_file = tmp_path / "text.txt"
        text_file.write_text("This is plain text, not JSON")
        
        with pytest.raises(json.JSONDecodeError):
            load_alert(path=str(text_file), use_sample=False)


class TestLoadAlertParameterPriority:
    """Test suite for parameter priority in load_alert()."""
    
    def test_sample_flag_overrides_path(self, create_temp_alert_file, valid_raw_alert):
        """Test that use_sample=True ignores the path parameter."""
        file_path = create_temp_alert_file(valid_raw_alert, "ignored.json")
        result = load_alert(path=file_path, use_sample=True)
        
        # Should return SAMPLE_ALERT, not the file content
        assert result == SAMPLE_ALERT
        assert result["alert_id"] == "sen-001"
        assert result != valid_raw_alert
    
    def test_sample_flag_with_invalid_path(self):
        """Test that use_sample=True works even with invalid path."""
        result = load_alert(path="/invalid/path.json", use_sample=True)
        assert result == SAMPLE_ALERT


class TestSampleAlertConstant:
    """Test suite for SAMPLE_ALERT constant validation."""
    
    def test_sample_alert_is_dict(self):
        """Test that SAMPLE_ALERT is a dictionary."""
        assert isinstance(SAMPLE_ALERT, dict)
    
    def test_sample_alert_immutability(self):
        """Test that loading sample doesn't modify SAMPLE_ALERT."""
        original = SAMPLE_ALERT.copy()
        result = load_alert(use_sample=True)
        result["alert_id"] = "modified"
        
        # Original should be unchanged
        assert SAMPLE_ALERT["alert_id"] == "sen-001"
        assert SAMPLE_ALERT == original
    
    def test_sample_alert_has_valid_timestamps(self):
        """Test that SAMPLE_ALERT has valid timestamp format."""
        timestamp = SAMPLE_ALERT["created_at"]
        assert isinstance(timestamp, str)
        assert "T" in timestamp
        assert "Z" in timestamp
    
    def test_sample_alert_indicators_not_empty(self):
        """Test that SAMPLE_ALERT has non-empty indicators."""
        indicators = SAMPLE_ALERT["indicators"]
        for ioc_type, values in indicators.items():
            assert len(values) > 0, f"No values for indicator type: {ioc_type}"
            for value in values:
                assert isinstance(value, str)
                assert len(value) > 0


class TestLoadAlertEdgeCases:
    """Test suite for edge cases in load_alert()."""
    
    def test_load_alert_with_unicode_content(self, tmp_path):
        """Test loading alert with Unicode characters."""
        unicode_alert = {
            "alert_id": "test-unicode",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "asset": {"device_id": "dev-001", "hostname": "测试-主机", "ip": "10.0.0.1"},
            "indicators": {"domains": ["例え.jp"]},
            "raw": {}
        }
        
        file_path = tmp_path / "unicode_alert.json"
        file_path.write_text(json.dumps(unicode_alert, ensure_ascii=False), encoding="utf-8")
        
        result = load_alert(path=str(file_path), use_sample=False)
        assert result["asset"]["hostname"] == "测试-主机"
        assert result["indicators"]["domains"][0] == "例え.jp"
    
    def test_load_alert_with_large_indicators_list(self, tmp_path):
        """Test loading alert with many indicators."""
        large_alert = {
            "alert_id": "test-large",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "asset": {"device_id": "dev-001"},
            "indicators": {
                "ipv4": [f"192.168.1.{i}" for i in range(1, 255)]
            },
            "raw": {}
        }
        
        file_path = tmp_path / "large_alert.json"
        file_path.write_text(json.dumps(large_alert))
        
        result = load_alert(path=str(file_path), use_sample=False)
        assert len(result["indicators"]["ipv4"]) == 254
    
    def test_load_alert_with_nested_raw_data(self, tmp_path):
        """Test loading alert with deeply nested raw data."""
        nested_alert = {
            "alert_id": "test-nested",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "asset": {"device_id": "dev-001"},
            "indicators": {"ipv4": ["1.2.3.4"]},
            "raw": {
                "level1": {
                    "level2": {
                        "level3": {
                            "data": "deep"
                        }
                    }
                }
            }
        }
        
        file_path = tmp_path / "nested_alert.json"
        file_path.write_text(json.dumps(nested_alert))
        
        result = load_alert(path=str(file_path), use_sample=False)
        assert result["raw"]["level1"]["level2"]["level3"]["data"] == "deep"
