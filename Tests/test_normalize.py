"""
Unit Tests for SOAR/Normalize/normalize.py

Tests alert normalization, validation, indicator flattening, and incident ID generation.
"""

import pytest
import os
import sys
import re
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Normalize.normalize import (
    normalize,
    _generate_incident_id,
    _validate_raw_alert,
    _flatten_indicators,
    _flatten_nested_dict
)


class TestNormalize:
    """Test suite for normalize() function."""
    
    def test_normalize_valid_alert(self, valid_raw_alert):
        """Test normalizing a valid raw alert."""
        result = normalize(valid_raw_alert)
        
        assert isinstance(result, dict)
        assert "incident_id" in result
        assert "source_alert" in result
        assert "indicators" in result
        assert "timeline" in result
        assert "actions" in result
    
    def test_normalize_generates_incident_id(self, valid_raw_alert):
        """Test that normalize generates a valid incident ID."""
        result = normalize(valid_raw_alert)
        
        incident_id = result["incident_id"]
        assert isinstance(incident_id, str)
        # Format: INC-20251210T100000Z-abc12345
        pattern = r'^INC-\d{8}T\d{6}Z-[a-f0-9]{8}$'
        assert re.match(pattern, incident_id), f"Invalid incident ID format: {incident_id}"
    
    def test_normalize_preserves_source_alert(self, valid_raw_alert):
        """Test that normalize preserves the original alert."""
        result = normalize(valid_raw_alert)
        
        source_alert = result["source_alert"]
        assert source_alert["alert_id"] == valid_raw_alert["alert_id"]
        assert source_alert["source"] == valid_raw_alert["source"]
        assert source_alert["type"] == valid_raw_alert["type"]
    
    def test_normalize_flattens_indicators(self, valid_raw_alert):
        """Test that normalize flattens indicators from dict to list."""
        result = normalize(valid_raw_alert)
        
        indicators = result["indicators"]
        assert isinstance(indicators, list)
        assert len(indicators) > 0
        
        # Check structure of flattened indicators
        for indicator in indicators:
            assert isinstance(indicator, dict)
            assert "type" in indicator
            assert "value" in indicator
    
    def test_normalize_initializes_timeline(self, valid_raw_alert):
        """Test that normalize initializes timeline array."""
        result = normalize(valid_raw_alert)
        
        assert "timeline" in result
        assert isinstance(result["timeline"], list)
    
    def test_normalize_initializes_actions(self, valid_raw_alert):
        """Test that normalize initializes actions array."""
        result = normalize(valid_raw_alert)
        
        assert "actions" in result
        assert isinstance(result["actions"], list)
        assert len(result["actions"]) == 0
    
    def test_normalize_preserves_asset(self, valid_raw_alert):
        """Test that normalize preserves asset information."""
        result = normalize(valid_raw_alert)
        
        assert "asset" in result
        assert result["asset"]["device_id"] == valid_raw_alert["asset"]["device_id"]
        assert result["asset"]["hostname"] == valid_raw_alert["asset"]["hostname"]
        assert result["asset"]["ip"] == valid_raw_alert["asset"]["ip"]
    
    def test_normalize_preserves_type(self, valid_raw_alert):
        """Test that normalize preserves alert type at top level."""
        result = normalize(valid_raw_alert)
        
        assert "type" in result
        assert result["type"] == valid_raw_alert["type"]
    
    def test_normalize_does_not_modify_input(self, valid_raw_alert):
        """Test that normalize doesn't modify the input alert."""
        original = valid_raw_alert.copy()
        result = normalize(valid_raw_alert)
        
        # Input should be unchanged
        assert valid_raw_alert == original
    
    def test_normalize_unique_incident_ids(self, valid_raw_alert):
        """Test that multiple normalizations generate unique incident IDs."""
        result1 = normalize(valid_raw_alert)
        result2 = normalize(valid_raw_alert)
        
        assert result1["incident_id"] != result2["incident_id"]


class TestGenerateIncidentId:
    """Test suite for _generate_incident_id() function."""
    
    def test_generate_incident_id_format(self):
        """Test that incident ID has correct format."""
        incident_id = _generate_incident_id()
        
        # Format: INC-20251210T100000Z-abc12345
        pattern = r'^INC-\d{8}T\d{6}Z-[a-f0-9]{8}$'
        assert re.match(pattern, incident_id), f"Invalid format: {incident_id}"
    
    def test_generate_incident_id_prefix(self):
        """Test that incident ID starts with INC- prefix."""
        incident_id = _generate_incident_id()
        assert incident_id.startswith("INC-")
    
    def test_generate_incident_id_has_timestamp(self):
        """Test that incident ID contains timestamp component."""
        incident_id = _generate_incident_id()
        parts = incident_id.split("-")
        
        assert len(parts) == 3
        timestamp_part = parts[1]
        assert "T" in timestamp_part
        assert timestamp_part.endswith("Z")
    
    def test_generate_incident_id_has_uuid(self):
        """Test that incident ID contains UUID component."""
        incident_id = _generate_incident_id()
        parts = incident_id.split("-")
        
        assert len(parts) == 3
        uuid_part = parts[2]
        assert len(uuid_part) == 8
        assert all(c in "0123456789abcdef" for c in uuid_part)
    
    def test_generate_incident_id_uniqueness(self):
        """Test that generated incident IDs are unique."""
        ids = [_generate_incident_id() for _ in range(100)]
        assert len(ids) == len(set(ids)), "Generated duplicate incident IDs"
    
    def test_generate_incident_id_returns_string(self):
        """Test that incident ID is a string."""
        incident_id = _generate_incident_id()
        assert isinstance(incident_id, str)


class TestValidateRawAlert:
    """Test suite for _validate_raw_alert() function."""
    
    def test_validate_valid_alert(self, valid_raw_alert):
        """Test that valid alert passes validation."""
        # Should not raise any exception
        _validate_raw_alert(valid_raw_alert)
    
    def test_validate_alert_not_dict_raises_error(self):
        """Test that non-dict alert raises ValueError."""
        with pytest.raises(ValueError, match="alert must be a dictionary"):
            _validate_raw_alert("not a dict")
    
    def test_validate_alert_list_raises_error(self):
        """Test that list alert raises ValueError."""
        with pytest.raises(ValueError, match="alert must be a dictionary"):
            _validate_raw_alert(["alert", "as", "list"])
    
    def test_validate_missing_alert_id_raises_error(self):
        """Test that missing alert_id raises ValueError."""
        invalid = {
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {}
        }
        with pytest.raises(ValueError, match="alert missing required field: 'alert_id'"):
            _validate_raw_alert(invalid)
    
    def test_validate_missing_source_raises_error(self):
        """Test that missing source raises ValueError."""
        invalid = {
            "alert_id": "test-001",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {}
        }
        with pytest.raises(ValueError, match="alert missing required field: 'source'"):
            _validate_raw_alert(invalid)
    
    def test_validate_missing_type_raises_error(self):
        """Test that missing type raises ValueError."""
        invalid = {
            "alert_id": "test-001",
            "source": "test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {}
        }
        with pytest.raises(ValueError, match="alert missing required field: 'type'"):
            _validate_raw_alert(invalid)
    
    def test_validate_missing_created_at_raises_error(self):
        """Test that missing created_at raises ValueError."""
        invalid = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "indicators": {}
        }
        with pytest.raises(ValueError, match="alert missing required field: 'created_at'"):
            _validate_raw_alert(invalid)
    
    def test_validate_missing_indicators_raises_error(self):
        """Test that missing indicators raises ValueError."""
        invalid = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z"
        }
        with pytest.raises(ValueError, match="alert missing required field: 'indicators'"):
            _validate_raw_alert(invalid)
    
    def test_validate_empty_alert_id_raises_error(self):
        """Test that empty alert_id raises ValueError."""
        invalid = {
            "alert_id": "",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {}
        }
        with pytest.raises(ValueError, match="alert\\['alert_id'\\] must be a non-empty string"):
            _validate_raw_alert(invalid)
    
    def test_validate_whitespace_alert_id_raises_error(self):
        """Test that whitespace-only alert_id raises ValueError."""
        invalid = {
            "alert_id": "   ",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {}
        }
        with pytest.raises(ValueError, match="alert\\['alert_id'\\] must be a non-empty string"):
            _validate_raw_alert(invalid)
    
    def test_validate_non_string_alert_id_raises_error(self):
        """Test that non-string alert_id raises ValueError."""
        invalid = {
            "alert_id": 123,
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {}
        }
        with pytest.raises(ValueError, match="alert\\['alert_id'\\] must be a non-empty string"):
            _validate_raw_alert(invalid)
    
    def test_validate_indicators_not_dict_raises_error(self):
        """Test that non-dict indicators raises ValueError."""
        invalid = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": ["list", "of", "indicators"]
        }
        with pytest.raises(ValueError, match="alert\\['indicators'\\] must be a dictionary"):
            _validate_raw_alert(invalid)
    
    def test_validate_indicator_values_not_list_raises_error(self):
        """Test that non-list indicator values raise ValueError."""
        invalid = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {"ipv4": "1.2.3.4"}  # Should be a list
        }
        with pytest.raises(ValueError, match="alert\\['indicators'\\]\\['ipv4'\\] must be a list"):
            _validate_raw_alert(invalid)
    
    def test_validate_empty_indicator_value_raises_error(self):
        """Test that empty string in indicator values raises ValueError."""
        invalid = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {"ipv4": ["1.2.3.4", ""]}
        }
        with pytest.raises(ValueError, match="IOC values for 'ipv4' must be non-empty strings"):
            _validate_raw_alert(invalid)
    
    def test_validate_asset_not_dict_raises_error(self):
        """Test that non-dict asset raises ValueError."""
        invalid = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {},
            "asset": "not a dict"
        }
        with pytest.raises(ValueError, match="alert\\['asset'\\] must be a dictionary"):
            _validate_raw_alert(invalid)
    
    def test_validate_raw_not_dict_raises_error(self):
        """Test that non-dict raw raises ValueError."""
        invalid = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {},
            "raw": ["not", "dict"]
        }
        with pytest.raises(ValueError, match="alert\\['raw'\\] must be a dictionary"):
            _validate_raw_alert(invalid)
    
    def test_validate_empty_indicators_dict(self):
        """Test that empty indicators dict is valid."""
        valid = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {}
        }
        # Should not raise exception
        _validate_raw_alert(valid)


class TestFlattenIndicators:
    """Test suite for _flatten_indicators() function."""
    
    def test_flatten_single_type(self):
        """Test flattening indicators with single type."""
        indicators = {"ipv4": ["1.2.3.4", "5.6.7.8"]}
        result = _flatten_indicators(indicators)
        
        assert isinstance(result, list)
        assert len(result) == 2
        assert {"type": "ipv4", "value": "1.2.3.4"} in result
        assert {"type": "ipv4", "value": "5.6.7.8"} in result
    
    def test_flatten_multiple_types(self):
        """Test flattening indicators with multiple types."""
        indicators = {
            "ipv4": ["1.2.3.4"],
            "domains": ["bad.example.com"],
            "sha256": ["deadbeef"]
        }
        result = _flatten_indicators(indicators)
        
        assert len(result) == 3
        assert {"type": "ipv4", "value": "1.2.3.4"} in result
        assert {"type": "domains", "value": "bad.example.com"} in result
        assert {"type": "sha256", "value": "deadbeef"} in result
    
    def test_flatten_empty_indicators(self):
        """Test flattening empty indicators dict."""
        indicators = {}
        result = _flatten_indicators(indicators)
        
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_flatten_indicators_preserves_order(self):
        """Test that flattening preserves indicator order within types."""
        indicators = {"ipv4": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]}
        result = _flatten_indicators(indicators)
        
        values = [ind["value"] for ind in result if ind["type"] == "ipv4"]
        assert values == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    
    def test_flatten_indicators_returns_new_list(self):
        """Test that flattening returns a new list."""
        indicators = {"ipv4": ["1.2.3.4"]}
        result1 = _flatten_indicators(indicators)
        result2 = _flatten_indicators(indicators)
        
        assert result1 is not result2
        assert result1 == result2


class TestFlattenNestedDict:
    """Test suite for _flatten_nested_dict() function."""
    
    def test_flatten_single_level(self):
        """Test flattening single-level dict."""
        data = {"key1": "value1", "key2": "value2"}
        result = _flatten_nested_dict(data)
        
        assert result == {"key1": "value1", "key2": "value2"}
    
    def test_flatten_nested_dict(self):
        """Test flattening nested dict with dot notation."""
        data = {"level1": {"level2": {"level3": "value"}}}
        result = _flatten_nested_dict(data)
        
        assert "level1.level2.level3" in result
        assert result["level1.level2.level3"] == "value"
    
    def test_flatten_mixed_types(self):
        """Test flattening dict with mixed value types."""
        data = {
            "string": "text",
            "number": 42,
            "bool": True,
            "list": [1, 2, 3],
            "nested": {"inner": "value"}
        }
        result = _flatten_nested_dict(data)
        
        assert result["string"] == "text"
        assert result["number"] == 42
        assert result["bool"] is True
        assert result["list"] == [1, 2, 3]
        assert result["nested.inner"] == "value"
    
    def test_flatten_preserves_lists(self):
        """Test that lists are not flattened."""
        data = {"items": ["a", "b", "c"]}
        result = _flatten_nested_dict(data)
        
        assert result["items"] == ["a", "b", "c"]
    
    def test_flatten_empty_dict(self):
        """Test flattening empty dict."""
        data = {}
        result = _flatten_nested_dict(data)
        
        assert result == {}
    
    def test_flatten_max_depth_exceeded_raises_error(self):
        """Test that exceeding max depth raises ValueError."""
        # Create deeply nested dict
        data = {"l1": {"l2": {"l3": {"l4": {"l5": {"l6": {"l7": {"l8": {"l9": {"l10": {"l11": "value"}}}}}}}}}}}
        
        with pytest.raises(ValueError, match="Flattening exceeded max depth"):
            _flatten_nested_dict(data, max_depth=5)
    
    def test_flatten_non_dict_with_prefix(self):
        """Test flattening non-dict value with prefix."""
        result = _flatten_nested_dict("value", prefix="key")
        assert result == {"key": "value"}
    
    def test_flatten_non_dict_without_prefix(self):
        """Test flattening non-dict value without prefix."""
        result = _flatten_nested_dict("value")
        assert result == {}


class TestNormalizeEdgeCases:
    """Test suite for edge cases in normalize()."""
    
    def test_normalize_alert_without_asset(self):
        """Test normalizing alert without asset field."""
        alert = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {"ipv4": ["1.2.3.4"]}
        }
        result = normalize(alert)
        
        assert "incident_id" in result
        assert "indicators" in result
        assert isinstance(result["indicators"], list)
    
    def test_normalize_alert_without_raw(self):
        """Test normalizing alert without raw field."""
        alert = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {"ipv4": ["1.2.3.4"]}
        }
        result = normalize(alert)
        
        assert "incident_id" in result
        assert "source_alert" in result
    
    def test_normalize_alert_with_empty_indicators(self):
        """Test normalizing alert with empty indicators."""
        alert = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {}
        }
        result = normalize(alert)
        
        assert "indicators" in result
        assert isinstance(result["indicators"], list)
        assert len(result["indicators"]) == 0
    
    def test_normalize_preserves_extra_fields(self):
        """Test that normalize preserves extra fields in alert."""
        alert = {
            "alert_id": "test-001",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {},
            "extra_field": "extra_value",
            "custom_data": {"nested": "value"}
        }
        result = normalize(alert)
        
        assert "extra_field" in result
        assert result["extra_field"] == "extra_value"
        assert "custom_data" in result
