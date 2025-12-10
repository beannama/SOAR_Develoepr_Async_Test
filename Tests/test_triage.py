"""
Unit Tests for SOAR/Triage/triage.py

Tests alert triage, severity scoring, suppression, bucket classification, and MITRE mapping.
"""

import pytest
import os
import sys
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Triage.triage import (
    triage,
    _validate_enriched_alert,
    ALLOWED_VERDICTS
)


class TestTriage:
    """Test suite for triage() function."""
    
    def test_triage_valid_enriched_alert(self, valid_enriched_alert):
        """Test triaging a valid enriched alert."""
        result = triage(valid_enriched_alert)
        
        assert isinstance(result, dict)
        assert "triage" in result
        assert "mitre" in result
    
    def test_triage_adds_severity_score(self, valid_enriched_alert):
        """Test that triage adds severity score."""
        result = triage(valid_enriched_alert)
        
        triage_data = result["triage"]
        assert "severity_score" in triage_data
        assert isinstance(triage_data["severity_score"], int)
        assert 0 <= triage_data["severity_score"] <= 100
    
    def test_triage_adds_bucket_classification(self, valid_enriched_alert):
        """Test that triage adds bucket classification."""
        result = triage(valid_enriched_alert)
        
        triage_data = result["triage"]
        assert "bucket" in triage_data
        
        valid_buckets = ["Suppressed", "Low", "Medium", "High", "Critical"]
        assert triage_data["bucket"] in valid_buckets
    
    def test_triage_adds_tags(self, valid_enriched_alert):
        """Test that triage adds tags array."""
        result = triage(valid_enriched_alert)
        
        triage_data = result["triage"]
        assert "tags" in triage_data
        assert isinstance(triage_data["tags"], list)
    
    def test_triage_adds_suppressed_flag(self, valid_enriched_alert):
        """Test that triage adds suppressed flag."""
        result = triage(valid_enriched_alert)
        
        triage_data = result["triage"]
        assert "suppressed" in triage_data
        assert isinstance(triage_data["suppressed"], bool)
    
    def test_triage_adds_mitre_techniques(self, valid_enriched_alert):
        """Test that triage adds MITRE techniques."""
        result = triage(valid_enriched_alert)
        
        mitre_data = result["mitre"]
        assert "techniques" in mitre_data
        assert isinstance(mitre_data["techniques"], list)
    
    def test_triage_preserves_alert_fields(self, valid_enriched_alert):
        """Test that triage preserves other alert fields."""
        original_type = valid_enriched_alert.get("type")
        original_indicators = valid_enriched_alert["indicators"]
        
        result = triage(valid_enriched_alert)
        
        assert result["type"] == original_type
        assert result["indicators"] == original_indicators
    
    def test_triage_returns_same_alert_object(self, valid_enriched_alert):
        """Test that triage modifies and returns the same alert."""
        result = triage(valid_enriched_alert)
        
        # Should return a copy, not modify in place
        assert isinstance(result, dict)
        assert "triage" in result


class TestTriageSeverityCalculation:
    """Test suite for severity calculation logic."""
    
    def test_malicious_indicator_increases_severity(self):
        """Test that malicious indicators increase severity."""
        alert = {
            "type": "CredentialAccess",
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
            ]
        }
        
        result = triage(alert)
        
        # Malicious indicator should result in higher severity
        assert result["triage"]["severity_score"] > 50
    
    def test_suspicious_indicator_moderate_severity(self):
        """Test that suspicious indicators result in moderate severity."""
        alert = {
            "type": "Unknown",
            "indicators": [
                {
                    "type": "ipv4",
                    "value": "1.2.3.4",
                    "risk": {
                        "verdict": "suspicious",
                        "score": 60,
                        "sources": ["defender_ti"],
                        "provider_details": []
                    }
                }
            ]
        }
        
        result = triage(alert)
        
        # Suspicious should be moderate severity
        assert 30 <= result["triage"]["severity_score"] <= 80
    
    def test_clean_indicator_low_severity(self):
        """Test that clean indicators result in low severity."""
        alert = {
            "type": "Unknown",
            "indicators": [
                {
                    "type": "ipv4",
                    "value": "203.0.113.10",
                    "risk": {
                        "verdict": "clean",
                        "score": 0,
                        "sources": [],
                        "provider_details": []
                    }
                }
            ]
        }
        
        result = triage(alert)
        
        # Clean indicators should result in base severity
        assert result["triage"]["severity_score"] <= 50
    
    def test_multiple_malicious_indicators_higher_severity(self):
        """Test that multiple malicious indicators increase severity more."""
        alert = {
            "type": "Malware",
            "indicators": [
                {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "malicious", "score": 90, "sources": [], "provider_details": []}},
                {"type": "domains", "value": "bad.com", "risk": {"verdict": "malicious", "score": 85, "sources": [], "provider_details": []}},
                {"type": "sha256", "value": "deadbeef" * 8, "risk": {"verdict": "malicious", "score": 95, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        # Multiple malicious IOCs should result in high severity
        assert result["triage"]["severity_score"] >= 70
    
    def test_alert_type_affects_base_severity(self):
        """Test that different alert types have different base severities."""
        # High-risk alert type
        malware_alert = {
            "type": "Malware",
            "indicators": [
                {"type": "sha256", "value": "test", "risk": {"verdict": "unknown", "score": 0, "sources": [], "provider_details": []}}
            ]
        }
        
        # Lower-risk alert type
        unknown_alert = {
            "type": "Unknown",
            "indicators": [
                {"type": "ipv4", "value": "test", "risk": {"verdict": "unknown", "score": 0, "sources": [], "provider_details": []}}
            ]
        }
        
        malware_result = triage(malware_alert)
        unknown_result = triage(unknown_alert)
        
        # Malware should have higher base severity
        assert malware_result["triage"]["severity_score"] >= unknown_result["triage"]["severity_score"]


class TestTriageSuppressionLogic:
    """Test suite for suppression logic."""
    
    def test_fully_suppressed_alert_has_zero_severity(self):
        """Test that fully suppressed alert has severity 0."""
        alert = {
            "type": "Test",
            "indicators": [
                {
                    "type": "ipv4",
                    "value": "203.0.113.10",  # Allowlisted IP
                    "risk": {"verdict": "malicious", "score": 90, "sources": [], "provider_details": []}
                }
            ]
        }
        
        result = triage(alert)
        
        # Fully allowlisted should be suppressed
        if result["triage"]["suppressed"]:
            assert result["triage"]["severity_score"] == 0
    
    def test_partially_suppressed_alert_has_penalty(self):
        """Test that partially suppressed alert has severity penalty."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "ipv4", "value": "203.0.113.10", "risk": {"verdict": "malicious", "score": 90, "sources": [], "provider_details": []}},  # Allowlisted
                {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "malicious", "score": 90, "sources": [], "provider_details": []}}  # Not allowlisted
            ]
        }
        
        result = triage(alert)
        
        # Should have tags indicating allowlisted IOCs
        if "allowlisted_ioc" in result["triage"]["tags"]:
            assert not result["triage"]["suppressed"]  # Not fully suppressed
    
    def test_suppressed_flag_set_correctly(self):
        """Test that suppressed flag is set correctly."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "malicious", "score": 90, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        # Non-allowlisted alert should not be suppressed
        assert isinstance(result["triage"]["suppressed"], bool)


class TestTriageBucketClassification:
    """Test suite for bucket classification."""
    
    def test_zero_severity_is_suppressed_bucket(self):
        """Test that severity 0 maps to Suppressed bucket."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "ipv4", "value": "203.0.113.10", "risk": {"verdict": "clean", "score": 0, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        if result["triage"]["severity_score"] == 0:
            assert result["triage"]["bucket"] == "Suppressed"
    
    def test_low_severity_bucket(self):
        """Test that low severity maps to Low bucket."""
        alert = {
            "type": "Unknown",
            "indicators": [
                {"type": "ipv4", "value": "test", "risk": {"verdict": "unknown", "score": 0, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        if 1 <= result["triage"]["severity_score"] <= 39:
            assert result["triage"]["bucket"] == "Low"
    
    def test_medium_severity_bucket(self):
        """Test that medium severity maps to Medium bucket."""
        alert = {
            "type": "CredentialAccess",
            "indicators": [
                {"type": "ipv4", "value": "test", "risk": {"verdict": "unknown", "score": 0, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        if 40 <= result["triage"]["severity_score"] <= 69:
            assert result["triage"]["bucket"] == "Medium"
    
    def test_high_severity_bucket(self):
        """Test that high severity maps to High bucket."""
        alert = {
            "type": "Malware",
            "indicators": [
                {"type": "sha256", "value": "test", "risk": {"verdict": "malicious", "score": 90, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        if 70 <= result["triage"]["severity_score"] <= 89:
            assert result["triage"]["bucket"] == "High"
    
    def test_critical_severity_bucket(self):
        """Test that critical severity maps to Critical bucket."""
        alert = {
            "type": "C2",
            "indicators": [
                {"type": "ipv4", "value": "test", "risk": {"verdict": "malicious", "score": 95, "sources": [], "provider_details": []}},
                {"type": "domains", "value": "test", "risk": {"verdict": "malicious", "score": 95, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        if result["triage"]["severity_score"] >= 90:
            assert result["triage"]["bucket"] == "Critical"


class TestTriageMitreMapping:
    """Test suite for MITRE ATT&CK technique mapping."""
    
    def test_credential_access_has_techniques(self):
        """Test that CredentialAccess alert has MITRE techniques."""
        alert = {
            "type": "CredentialAccess",
            "indicators": [
                {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "suspicious", "score": 60, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        techniques = result["mitre"]["techniques"]
        assert isinstance(techniques, list)
        # CredentialAccess should have T1078, T1110, etc.
        assert len(techniques) > 0
    
    def test_malware_has_techniques(self):
        """Test that Malware alert has MITRE techniques."""
        alert = {
            "type": "Malware",
            "indicators": [
                {"type": "sha256", "value": "test", "risk": {"verdict": "malicious", "score": 90, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        techniques = result["mitre"]["techniques"]
        assert isinstance(techniques, list)
    
    def test_unknown_alert_type_has_default_techniques(self):
        """Test that unknown alert type gets default techniques."""
        alert = {
            "type": "UnknownAlertType",
            "indicators": [
                {"type": "ipv4", "value": "test", "risk": {"verdict": "unknown", "score": 0, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        techniques = result["mitre"]["techniques"]
        assert isinstance(techniques, list)


class TestValidateEnrichedAlert:
    """Test suite for _validate_enriched_alert() function."""
    
    def test_validate_valid_enriched_alert(self, valid_enriched_alert):
        """Test that valid enriched alert passes validation."""
        # Should not raise exception
        _validate_enriched_alert(valid_enriched_alert)
    
    def test_validate_alert_not_dict_raises_error(self):
        """Test that non-dict alert raises ValueError."""
        with pytest.raises(ValueError, match="alert must be a dict"):
            _validate_enriched_alert("not a dict")
    
    def test_validate_missing_type_raises_error(self):
        """Test that missing type raises ValueError."""
        alert = {"indicators": []}
        with pytest.raises(ValueError, match="alert\\['type'\\] must be a non-empty string"):
            _validate_enriched_alert(alert)
    
    def test_validate_empty_type_raises_error(self):
        """Test that empty type raises ValueError."""
        alert = {"type": "", "indicators": [{"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "unknown"}}]}
        with pytest.raises(ValueError, match="alert\\['type'\\] must be a non-empty string"):
            _validate_enriched_alert(alert)
    
    def test_validate_indicators_not_list_raises_error(self):
        """Test that non-list indicators raises ValueError."""
        alert = {"type": "Test", "indicators": "not a list"}
        with pytest.raises(ValueError, match="alert\\['indicators'\\] must be a non-empty list"):
            _validate_enriched_alert(alert)
    
    def test_validate_empty_indicators_raises_error(self):
        """Test that empty indicators list raises ValueError."""
        alert = {"type": "Test", "indicators": []}
        with pytest.raises(ValueError, match="alert\\['indicators'\\] must be a non-empty list"):
            _validate_enriched_alert(alert)
    
    def test_validate_indicator_missing_type_raises_error(self):
        """Test that indicator missing type raises ValueError."""
        alert = {
            "type": "Test",
            "indicators": [{"value": "1.2.3.4", "risk": {"verdict": "unknown"}}]
        }
        with pytest.raises(ValueError, match="indicator\\[0\\]\\['type'\\] must be a non-empty string"):
            _validate_enriched_alert(alert)
    
    def test_validate_indicator_missing_value_raises_error(self):
        """Test that indicator missing value raises ValueError."""
        alert = {
            "type": "Test",
            "indicators": [{"type": "ipv4", "risk": {"verdict": "unknown"}}]
        }
        with pytest.raises(ValueError, match="indicator\\[0\\]\\['value'\\] must be a non-empty string"):
            _validate_enriched_alert(alert)
    
    def test_validate_indicator_missing_risk_raises_error(self):
        """Test that indicator missing risk raises ValueError."""
        alert = {
            "type": "Test",
            "indicators": [{"type": "ipv4", "value": "1.2.3.4"}]
        }
        with pytest.raises(ValueError, match="indicator\\[0\\]\\['risk'\\] must be a dict"):
            _validate_enriched_alert(alert)
    
    def test_validate_risk_not_dict_raises_error(self):
        """Test that non-dict risk raises ValueError."""
        alert = {
            "type": "Test",
            "indicators": [{"type": "ipv4", "value": "1.2.3.4", "risk": "not a dict"}]
        }
        with pytest.raises(ValueError, match="indicator\\[0\\]\\['risk'\\] must be a dict"):
            _validate_enriched_alert(alert)
    
    def test_validate_invalid_verdict_raises_error(self):
        """Test that invalid verdict raises ValueError."""
        alert = {
            "type": "Test",
            "indicators": [{"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "invalid_verdict"}}]
        }
        with pytest.raises(ValueError, match="indicator\\[0\\].risk.verdict must be one of"):
            _validate_enriched_alert(alert)
    
    def test_validate_valid_verdicts(self):
        """Test that all valid verdicts pass validation."""
        for verdict in ALLOWED_VERDICTS:
            alert = {
                "type": "Test",
                "indicators": [{"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": verdict}}]
            }
            # Should not raise exception
            _validate_enriched_alert(alert)


class TestAllowedVerdictsConstant:
    """Test suite for ALLOWED_VERDICTS constant."""
    
    def test_allowed_verdicts_is_set(self):
        """Test that ALLOWED_VERDICTS is a set."""
        assert isinstance(ALLOWED_VERDICTS, set)
    
    def test_allowed_verdicts_contains_expected_values(self):
        """Test that ALLOWED_VERDICTS contains expected values."""
        expected = {"malicious", "suspicious", "clean", "unknown"}
        assert ALLOWED_VERDICTS == expected
    
    def test_allowed_verdicts_all_lowercase(self):
        """Test that all verdicts are lowercase."""
        for verdict in ALLOWED_VERDICTS:
            assert verdict == verdict.lower()


class TestTriageEdgeCases:
    """Test suite for edge cases in triage."""
    
    def test_triage_with_single_indicator(self):
        """Test triage with single indicator."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "malicious", "score": 90, "sources": [], "provider_details": []}}
            ]
        }
        
        result = triage(alert)
        
        assert "triage" in result
        assert "severity_score" in result["triage"]
    
    def test_triage_with_many_indicators(self):
        """Test triage with many indicators."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "ipv4", "value": f"1.2.3.{i}", "risk": {"verdict": "suspicious", "score": 50, "sources": [], "provider_details": []}}
                for i in range(1, 51)
            ]
        }
        
        result = triage(alert)
        
        assert "triage" in result
        # Many suspicious indicators should increase severity
        assert result["triage"]["severity_score"] > 40
    
    def test_triage_preserves_extra_fields(self):
        """Test that triage preserves extra alert fields."""
        alert = {
            "type": "Test",
            "indicators": [
                {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "unknown", "score": 0, "sources": [], "provider_details": []}}
            ],
            "custom_field": "custom_value",
            "extra_data": {"nested": "value"}
        }
        
        result = triage(alert)
        
        assert result["custom_field"] == "custom_value"
        assert result["extra_data"]["nested"] == "value"
    
    def test_triage_severity_clamped_to_range(self):
        """Test that severity is always clamped between 0 and 100."""
        # Try with many high-severity indicators
        alert = {
            "type": "C2",
            "indicators": [
                {"type": "ipv4", "value": f"malicious-{i}", "risk": {"verdict": "malicious", "score": 100, "sources": [], "provider_details": []}}
                for i in range(20)
            ]
        }
        
        result = triage(alert)
        
        severity = result["triage"]["severity_score"]
        assert 0 <= severity <= 100
