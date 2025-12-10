"""
Unit Tests for SOAR/Enrichment/enricher.py

Tests IOC enrichment with threat intelligence data.
"""

import pytest
import os
import sys
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Enrichment.enricher import (
    enrich,
    _validate_alert,
    _get_indicators_for_enrichment,
    _get_mock_ti
)


class TestEnrich:
    """Test suite for enrich() function."""
    
    def test_enrich_valid_alert(self, valid_normalized_alert):
        """Test enriching a valid normalized alert."""
        result = enrich(valid_normalized_alert)
        
        assert isinstance(result, dict)
        assert "indicators" in result
        
        # Check that risk was added to indicators
        for indicator in result["indicators"]:
            assert "risk" in indicator
            assert isinstance(indicator["risk"], dict)
    
    def test_enrich_adds_risk_fields(self, valid_normalized_alert):
        """Test that enrich adds all required risk fields."""
        result = enrich(valid_normalized_alert)
        
        for indicator in result["indicators"]:
            risk = indicator["risk"]
            assert "verdict" in risk
            assert "score" in risk
            assert "sources" in risk
            assert "provider_details" in risk
    
    def test_enrich_modifies_in_place(self, valid_normalized_alert):
        """Test that enrich modifies indicators in place."""
        original_indicators = valid_normalized_alert["indicators"]
        result = enrich(valid_normalized_alert)
        
        # Should modify the same alert object
        assert result is valid_normalized_alert
        assert result["indicators"] is original_indicators
    
    def test_enrich_preserves_alert_fields(self, valid_normalized_alert):
        """Test that enrich preserves other alert fields."""
        original_id = valid_normalized_alert.get("incident_id")
        original_type = valid_normalized_alert.get("type")
        
        result = enrich(valid_normalized_alert)
        
        assert result.get("incident_id") == original_id
        assert result.get("type") == original_type
    
    def test_enrich_handles_empty_indicators(self):
        """Test enriching alert with empty indicators list."""
        alert = {
            "type": "Test",
            "indicators": []
        }
        
        result = enrich(alert)
        assert "indicators" in result
        assert len(result["indicators"]) == 0
    
    def test_enrich_handles_malformed_indicators(self):
        """Test that enrich validates and rejects malformed indicators."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "ipv4", "value": "1.2.3.4"},  # Valid
                {"type": 123, "value": "bad"},  # Invalid type
                {"type": "domains", "value": 456},  # Invalid value
            ]
        }
        
        # Should raise ValueError due to strict validation
        with pytest.raises(ValueError, match="indicator 'type' must be a non-empty string"):
            enrich(alert)
    
    def test_enrich_with_known_iocs(self):
        """Test enriching with IOCs that exist in TI data."""
        alert = {
            "type": "CredentialAccess",
            "indicators": [
                {"type": "ipv4", "value": "1.2.3.4"},
                {"type": "domains", "value": "bad.example.net"}
            ]
        }
        
        result = enrich(alert)
        
        # Check that known IOCs get risk data
        for indicator in result["indicators"]:
            assert "risk" in indicator
            risk = indicator["risk"]
            assert risk["verdict"] in ["malicious", "suspicious", "clean", "unknown"]


class TestValidateAlert:
    """Test suite for _validate_alert() function."""
    
    def test_validate_valid_alert(self, valid_normalized_alert):
        """Test that valid alert passes validation."""
        # Should not raise exception
        _validate_alert(valid_normalized_alert)
    
    def test_validate_alert_not_dict_raises_error(self):
        """Test that non-dict alert raises ValueError."""
        with pytest.raises(ValueError, match="alert must be a dict"):
            _validate_alert("not a dict")
    
    def test_validate_alert_list_raises_error(self):
        """Test that list alert raises ValueError."""
        with pytest.raises(ValueError, match="alert must be a dict"):
            _validate_alert(["alert", "list"])
    
    def test_validate_missing_type_raises_error(self):
        """Test that missing type field raises ValueError."""
        alert = {"indicators": []}
        with pytest.raises(ValueError, match="alert must contain 'type'"):
            _validate_alert(alert)
    
    def test_validate_empty_type_raises_error(self):
        """Test that empty type string raises ValueError."""
        alert = {"type": "", "indicators": []}
        with pytest.raises(ValueError, match="alert\\['type'\\] must be a non-empty string"):
            _validate_alert(alert)
    
    def test_validate_whitespace_type_raises_error(self):
        """Test that whitespace-only type raises ValueError."""
        alert = {"type": "   ", "indicators": []}
        with pytest.raises(ValueError, match="alert\\['type'\\] must be a non-empty string"):
            _validate_alert(alert)
    
    def test_validate_non_string_type_raises_error(self):
        """Test that non-string type raises ValueError."""
        alert = {"type": 123, "indicators": []}
        with pytest.raises(ValueError, match="alert\\['type'\\] must be a non-empty string"):
            _validate_alert(alert)
    
    def test_validate_indicators_not_list_raises_error(self):
        """Test that non-list indicators raises ValueError."""
        alert = {"type": "Test", "indicators": {"dict": "value"}}
        with pytest.raises(ValueError, match="alert must contain 'indicators' as a list"):
            _validate_alert(alert)
    
    def test_validate_missing_indicators_raises_error(self):
        """Test that missing indicators raises ValueError."""
        alert = {"type": "Test"}
        with pytest.raises(ValueError, match="alert must contain 'indicators' as a list"):
            _validate_alert(alert)
    
    def test_validate_indicator_not_dict_raises_error(self):
        """Test that non-dict indicator raises ValueError."""
        alert = {"type": "Test", "indicators": ["string", "indicator"]}
        with pytest.raises(ValueError, match="each indicator must be a dict"):
            _validate_alert(alert)
    
    def test_validate_indicator_missing_type_raises_error(self):
        """Test that indicator missing type raises ValueError."""
        alert = {"type": "Test", "indicators": [{"value": "1.2.3.4"}]}
        with pytest.raises(ValueError, match="each indicator must have 'type' and 'value'"):
            _validate_alert(alert)
    
    def test_validate_indicator_missing_value_raises_error(self):
        """Test that indicator missing value raises ValueError."""
        alert = {"type": "Test", "indicators": [{"type": "ipv4"}]}
        with pytest.raises(ValueError, match="each indicator must have 'type' and 'value'"):
            _validate_alert(alert)
    
    def test_validate_indicator_empty_type_raises_error(self):
        """Test that indicator with empty type raises ValueError."""
        alert = {"type": "Test", "indicators": [{"type": "", "value": "1.2.3.4"}]}
        with pytest.raises(ValueError, match="indicator 'type' must be a non-empty string"):
            _validate_alert(alert)
    
    def test_validate_indicator_empty_value_raises_error(self):
        """Test that indicator with empty value raises ValueError."""
        alert = {"type": "Test", "indicators": [{"type": "ipv4", "value": ""}]}
        with pytest.raises(ValueError, match="indicator 'value' must be a non-empty string"):
            _validate_alert(alert)
    
    def test_validate_indicator_non_string_type_raises_error(self):
        """Test that indicator with non-string type raises ValueError."""
        alert = {"type": "Test", "indicators": [{"type": 123, "value": "1.2.3.4"}]}
        with pytest.raises(ValueError, match="indicator 'type' must be a non-empty string"):
            _validate_alert(alert)
    
    def test_validate_indicator_non_string_value_raises_error(self):
        """Test that indicator with non-string value raises ValueError."""
        alert = {"type": "Test", "indicators": [{"type": "ipv4", "value": 12345}]}
        with pytest.raises(ValueError, match="indicator 'value' must be a non-empty string"):
            _validate_alert(alert)
    
    def test_validate_empty_indicators_list(self):
        """Test that empty indicators list is valid."""
        alert = {"type": "Test", "indicators": []}
        # Should not raise exception
        _validate_alert(alert)


class TestGetIndicatorsForEnrichment:
    """Test suite for _get_indicators_for_enrichment() function."""
    
    def test_get_indicators_returns_list(self, valid_normalized_alert):
        """Test that function returns a list."""
        result = _get_indicators_for_enrichment(valid_normalized_alert)
        assert isinstance(result, list)
    
    def test_get_indicators_returns_reference(self, valid_normalized_alert):
        """Test that function returns reference, not copy."""
        result = _get_indicators_for_enrichment(valid_normalized_alert)
        
        # Modifying result should modify original
        assert result is valid_normalized_alert["indicators"]
    
    def test_get_indicators_empty_alert(self):
        """Test getting indicators from alert without indicators field."""
        alert = {"type": "Test"}
        result = _get_indicators_for_enrichment(alert)
        
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_get_indicators_preserves_structure(self, valid_normalized_alert):
        """Test that returned indicators preserve structure."""
        result = _get_indicators_for_enrichment(valid_normalized_alert)
        
        for indicator in result:
            assert isinstance(indicator, dict)
            assert "type" in indicator
            assert "value" in indicator


class TestGetMockTI:
    """Test suite for _get_mock_ti() singleton behavior."""
    
    def test_get_mock_ti_returns_instance(self):
        """Test that _get_mock_ti returns a MockTI instance."""
        from SOAR.Enrichment.mock_ti import MockTI
        
        result = _get_mock_ti()
        assert isinstance(result, MockTI)
    
    def test_get_mock_ti_singleton_behavior(self):
        """Test that _get_mock_ti returns same instance on multiple calls."""
        instance1 = _get_mock_ti()
        instance2 = _get_mock_ti()
        
        assert instance1 is instance2


class TestEnrichmentEdgeCases:
    """Test suite for edge cases in enrichment."""
    
    def test_enrich_with_special_characters(self):
        """Test enriching indicators with special characters."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "domains", "value": "例え.jp"},
                {"type": "ipv4", "value": "1.2.3.4"}
            ]
        }
        
        result = enrich(alert)
        
        for indicator in result["indicators"]:
            assert "risk" in indicator
    
    def test_enrich_with_multiple_ioc_types(self):
        """Test enriching alert with all IOC types."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "ipv4", "value": "1.2.3.4"},
                {"type": "domains", "value": "bad.example.net"},
                {"type": "urls", "value": "http://bad.example.net/login"},
                {"type": "sha256", "value": "deadbeef" * 8}
            ]
        }
        
        result = enrich(alert)
        
        assert len(result["indicators"]) == 4
        for indicator in result["indicators"]:
            assert "risk" in indicator
    
    def test_enrich_preserves_existing_fields(self):
        """Test that enrich preserves existing indicator fields."""
        alert = {
            "type": "Test",
            "indicators": [
                {
                    "type": "ipv4",
                    "value": "1.2.3.4",
                    "custom_field": "custom_value",
                    "metadata": {"key": "value"}
                }
            ]
        }
        
        result = enrich(alert)
        
        indicator = result["indicators"][0]
        assert indicator["custom_field"] == "custom_value"
        assert indicator["metadata"] == {"key": "value"}
        assert "risk" in indicator
    
    def test_enrich_does_not_override_existing_risk(self):
        """Test that enrich overwrites any existing risk field."""
        alert = {
            "type": "Test",
            "indicators": [
                {
                    "type": "ipv4",
                    "value": "1.2.3.4",
                    "risk": {"old": "data"}
                }
            ]
        }
        
        result = enrich(alert)
        
        # Risk should be replaced with new TI data
        indicator = result["indicators"][0]
        assert "verdict" in indicator["risk"]
        assert "old" not in indicator["risk"]
    
    def test_enrich_handles_duplicate_iocs(self):
        """Test enriching alert with duplicate IOCs."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "ipv4", "value": "1.2.3.4"},
                {"type": "ipv4", "value": "1.2.3.4"},
                {"type": "ipv4", "value": "1.2.3.4"}
            ]
        }
        
        result = enrich(alert)
        
        # All duplicates should be enriched
        assert len(result["indicators"]) == 3
        for indicator in result["indicators"]:
            assert "risk" in indicator
    
    def test_enrich_case_sensitivity(self):
        """Test that enrichment handles case variations."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "domains", "value": "BAD.EXAMPLE.NET"},
                {"type": "domains", "value": "bad.example.net"}
            ]
        }
        
        result = enrich(alert)
        
        # Both should be enriched
        for indicator in result["indicators"]:
            assert "risk" in indicator
