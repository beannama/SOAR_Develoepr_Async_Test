"""
Unit Tests for SOAR/Triage/rules.py

Tests triage configuration, severity scoring, allowlist checking, suppression, 
bucket classification, and MITRE mapping.
"""

import pytest
import os
import sys
import tempfile
import yaml
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Triage.rules import (
    TriageConfigLoader,
    SeverityScorer,
    AllowlistLoader,
    SuppressionEngine,
    BucketClassifier,
    MitreMapper
)


class TestTriageConfigLoader:
    """Test suite for TriageConfigLoader class."""
    
    def test_config_loader_initialization(self, tmp_path):
        """Test TriageConfigLoader initialization with valid config."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
severity:
  base:
    Malware: 70
    Unknown: 40
  intel_boosts:
    malicious: 20
    suspicious: 10
suppression:
  allowlist_path: "../configs/allowlists.yml"
  allowlist_penalty: 25
bucket:
  ranges:
    - name: "Low"
      min: 1
      max: 39
mitre:
  mapping_path: "../configs/mitre_map.yml"
""")
        
        loader = TriageConfigLoader(str(config_file))
        assert loader is not None
    
    def test_config_loader_missing_file_raises_error(self):
        """Test that missing config file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Triage config not found"):
            TriageConfigLoader("/nonexistent/config.yml")
    
    def test_severity_base_property(self, tmp_path):
        """Test severity_base property returns base severity dict."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
severity:
  base:
    Malware: 70
    Phishing: 50
    Unknown: 40
""")
        
        loader = TriageConfigLoader(str(config_file))
        base = loader.severity_base
        
        assert isinstance(base, dict)
        assert base["Malware"] == 70
        assert base["Phishing"] == 50
        assert base["Unknown"] == 40
    
    def test_intel_boosts_property(self, tmp_path):
        """Test intel_boosts property returns boost values."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
severity:
  intel_boosts:
    malicious: 20
    suspicious: 10
    extra_flagged_per_ioc: 5
    extra_flagged_cap: 15
""")
        
        loader = TriageConfigLoader(str(config_file))
        boosts = loader.intel_boosts
        
        assert boosts["malicious"] == 20
        assert boosts["suspicious"] == 10
        assert boosts["extra_flagged_per_ioc"] == 5
    
    def test_get_allowlist_penalty(self, tmp_path):
        """Test get_allowlist_penalty method."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
suppression:
  allowlist_penalty: 25
""")
        
        loader = TriageConfigLoader(str(config_file))
        penalty = loader.get_allowlist_penalty()
        
        assert penalty == 25
    
    def test_get_bucket_for_score(self, tmp_path):
        """Test get_bucket_for_score method."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
bucket:
  ranges:
    - name: "Suppressed"
      min: 0
      max: 0
    - name: "Low"
      min: 1
      max: 39
    - name: "Medium"
      min: 40
      max: 69
    - name: "High"
      min: 70
      max: 89
    - name: "Critical"
      min: 90
      max: 100
""")
        
        loader = TriageConfigLoader(str(config_file))
        
        assert loader.get_bucket_for_score(0) == "Suppressed"
        assert loader.get_bucket_for_score(25) == "Low"
        assert loader.get_bucket_for_score(50) == "Medium"
        assert loader.get_bucket_for_score(75) == "High"
        assert loader.get_bucket_for_score(95) == "Critical"


class TestSeverityScorer:
    """Test suite for SeverityScorer class."""
    
    def test_severity_scorer_initialization(self, mock_triage_config, tmp_path):
        """Test SeverityScorer initialization."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        scorer = SeverityScorer(loader)
        
        assert scorer is not None
    
    def test_calculate_base_severity_only(self, mock_triage_config, tmp_path):
        """Test severity calculation with base severity only (no intel boosts)."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        scorer = SeverityScorer(loader)
        
        indicators = [
            {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "unknown"}}
        ]
        
        result = scorer.calculate("CredentialAccess", indicators)
        
        # Should return base severity for CredentialAccess (60)
        assert result["severity_score"] == 60
        assert result["scoring_details"]["base"] == 60
        assert result["scoring_details"]["flagged_iocs"] == 0
    
    def test_calculate_with_malicious_boost(self, mock_triage_config, tmp_path):
        """Test severity calculation with malicious verdict boost."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        scorer = SeverityScorer(loader)
        
        indicators = [
            {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "malicious"}}
        ]
        
        result = scorer.calculate("CredentialAccess", indicators)
        
        # Base 60 + malicious boost 20 = 80
        assert result["severity_score"] == 80
        assert result["scoring_details"]["flagged_iocs"] == 1
        assert result["scoring_details"]["first_flag_boost"] == 20
    
    def test_calculate_with_suspicious_boost(self, mock_triage_config, tmp_path):
        """Test severity calculation with suspicious verdict boost."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        scorer = SeverityScorer(loader)
        
        indicators = [
            {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "suspicious"}}
        ]
        
        result = scorer.calculate("Unknown", indicators)
        
        # Base 40 + suspicious boost 10 = 50
        assert result["severity_score"] == 50
        assert result["scoring_details"]["first_flag_boost"] == 10
    
    def test_calculate_with_multiple_flagged_iocs(self, mock_triage_config, tmp_path):
        """Test severity calculation with multiple flagged IOCs."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        scorer = SeverityScorer(loader)
        
        indicators = [
            {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "malicious"}},
            {"type": "domains", "value": "bad.com", "risk": {"verdict": "suspicious"}},
            {"type": "sha256", "value": "deadbeef", "risk": {"verdict": "malicious"}}
        ]
        
        result = scorer.calculate("Malware", indicators)
        
        # Base 70 + malicious boost 20 + extra boost (2 more * 5 = 10) = 100
        assert result["severity_score"] == 100
        assert result["scoring_details"]["flagged_iocs"] == 3
        assert result["scoring_details"]["extra_boost"] == 10
    
    def test_calculate_extra_boost_capped(self, mock_triage_config, tmp_path):
        """Test that extra boost is capped at max value."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        scorer = SeverityScorer(loader)
        
        # Create 10 malicious indicators
        indicators = [
            {"type": "ipv4", "value": f"1.2.3.{i}", "risk": {"verdict": "malicious"}}
            for i in range(10)
        ]
        
        result = scorer.calculate("Test", indicators)
        
        # Extra boost should be capped at 15
        assert result["scoring_details"]["extra_boost"] <= 15
    
    def test_calculate_severity_clamped_to_100(self, mock_triage_config, tmp_path):
        """Test that severity is clamped to maximum 100."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        scorer = SeverityScorer(loader)
        
        # High base + boosts could exceed 100
        indicators = [
            {"type": "ipv4", "value": f"bad-{i}", "risk": {"verdict": "malicious"}}
            for i in range(20)
        ]
        
        result = scorer.calculate("C2", indicators)
        
        assert result["severity_score"] <= 100
    
    def test_calculate_unknown_alert_type_uses_default(self, mock_triage_config, tmp_path):
        """Test that unknown alert types use default base severity."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        scorer = SeverityScorer(loader)
        
        indicators = [
            {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "unknown"}}
        ]
        
        result = scorer.calculate("NonExistentAlertType", indicators)
        
        # Should use Unknown default (40)
        assert result["scoring_details"]["base"] == 40


class TestAllowlistLoader:
    """Test suite for AllowlistLoader class."""
    
    def test_allowlist_loader_initialization(self, tmp_path):
        """Test AllowlistLoader initialization."""
        allowlist_file = tmp_path / "allowlists.yml"
        allowlist_file.write_text("""
indicators:
  ipv4:
    - "203.0.113.10"
    - "192.168.1.1"
  domains:
    - "ok.partner.example"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        assert loader is not None
    
    def test_is_allowlisted_with_allowlisted_ioc(self, tmp_path):
        """Test that allowlisted IOC returns True."""
        allowlist_file = tmp_path / "allowlists.yml"
        allowlist_file.write_text("""
indicators:
  ipv4:
    - "203.0.113.10"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        result = loader.is_allowlisted("ipv4", "203.0.113.10")
        
        assert result is True
    
    def test_is_allowlisted_with_non_allowlisted_ioc(self, tmp_path):
        """Test that non-allowlisted IOC returns False."""
        allowlist_file = tmp_path / "allowlists.yml"
        allowlist_file.write_text("""
indicators:
  ipv4:
    - "203.0.113.10"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        result = loader.is_allowlisted("ipv4", "1.2.3.4")
        
        assert result is False
    
    def test_is_allowlisted_case_insensitive(self, tmp_path):
        """Test that allowlist checking is case-insensitive."""
        allowlist_file = tmp_path / "allowlists.yml"
        allowlist_file.write_text("""
indicators:
  domains:
    - "OK.Partner.Example"
""")
        
        loader = AllowlistLoader(str(allowlist_file))
        
        assert loader.is_allowlisted("domains", "ok.partner.example") is True
        assert loader.is_allowlisted("domains", "OK.PARTNER.EXAMPLE") is True
    
    def test_is_allowlisted_missing_file_returns_false(self):
        """Test that missing allowlist file returns False."""
        loader = AllowlistLoader("/nonexistent/allowlist.yml")
        result = loader.is_allowlisted("ipv4", "1.2.3.4")
        
        assert result is False
    
    def test_is_allowlisted_empty_ioc_type(self, tmp_path):
        """Test that empty IOC type returns False."""
        allowlist_file = tmp_path / "allowlists.yml"
        allowlist_file.write_text("indicators: {}")
        
        loader = AllowlistLoader(str(allowlist_file))
        result = loader.is_allowlisted("", "1.2.3.4")
        
        assert result is False


class TestSuppressionEngine:
    """Test suite for SuppressionEngine class."""
    
    def test_suppression_engine_initialization(self, tmp_path):
        """Test SuppressionEngine initialization."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
suppression:
  allowlist_path: "allowlist.yml"
  allowlist_penalty: 25
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        config_loader = TriageConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        engine = SuppressionEngine(config_loader, allowlist_loader)
        
        assert engine is not None
    
    def test_evaluate_no_allowlisted_iocs(self, tmp_path):
        """Test evaluation with no allowlisted IOCs."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
suppression:
  allowlist_penalty: 25
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        config_loader = TriageConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        engine = SuppressionEngine(config_loader, allowlist_loader)
        
        indicators = [
            {"type": "ipv4", "value": "1.2.3.4"}
        ]
        
        result = engine.evaluate(indicators)
        
        assert result["allowlisted_count"] == 0
        assert result["is_fully_suppressed"] is False
        assert result["severity_penalty"] == 0
        assert "allowlisted" not in result["tags"]
    
    def test_evaluate_partially_allowlisted(self, tmp_path):
        """Test evaluation with partially allowlisted IOCs."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
suppression:
  allowlist_penalty: 25
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
indicators:
  ipv4:
    - "203.0.113.10"
""")
        
        config_loader = TriageConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        engine = SuppressionEngine(config_loader, allowlist_loader)
        
        indicators = [
            {"type": "ipv4", "value": "203.0.113.10"},  # Allowlisted
            {"type": "ipv4", "value": "1.2.3.4"}  # Not allowlisted
        ]
        
        result = engine.evaluate(indicators)
        
        assert result["allowlisted_count"] == 1
        assert result["total_count"] == 2
        assert result["is_fully_suppressed"] is False
        assert result["severity_penalty"] == 25
        assert "allowlisted" in result["tags"]
        assert "suppressed" not in result["tags"]
    
    def test_evaluate_fully_suppressed(self, tmp_path):
        """Test evaluation with all IOCs allowlisted."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
suppression:
  allowlist_penalty: 25
""")
        
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
indicators:
  ipv4:
    - "203.0.113.10"
    - "192.168.1.1"
""")
        
        config_loader = TriageConfigLoader(str(config_file))
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        engine = SuppressionEngine(config_loader, allowlist_loader)
        
        indicators = [
            {"type": "ipv4", "value": "203.0.113.10"},
            {"type": "ipv4", "value": "192.168.1.1"}
        ]
        
        result = engine.evaluate(indicators)
        
        assert result["allowlisted_count"] == 2
        assert result["total_count"] == 2
        assert result["is_fully_suppressed"] is True
        assert "suppressed" in result["tags"]


class TestBucketClassifier:
    """Test suite for BucketClassifier class."""
    
    def test_bucket_classifier_initialization(self, mock_triage_config, tmp_path):
        """Test BucketClassifier initialization."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        classifier = BucketClassifier(loader)
        
        assert classifier is not None
    
    def test_classify_suppressed(self, mock_triage_config, tmp_path):
        """Test classification of severity 0."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        classifier = BucketClassifier(loader)
        
        assert classifier.classify(0) == "Suppressed"
    
    def test_classify_low(self, mock_triage_config, tmp_path):
        """Test classification of low severity."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        classifier = BucketClassifier(loader)
        
        assert classifier.classify(1) == "Low"
        assert classifier.classify(20) == "Low"
        assert classifier.classify(39) == "Low"
    
    def test_classify_medium(self, mock_triage_config, tmp_path):
        """Test classification of medium severity."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        classifier = BucketClassifier(loader)
        
        assert classifier.classify(40) == "Medium"
        assert classifier.classify(55) == "Medium"
        assert classifier.classify(69) == "Medium"
    
    def test_classify_high(self, mock_triage_config, tmp_path):
        """Test classification of high severity."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        classifier = BucketClassifier(loader)
        
        assert classifier.classify(70) == "High"
        assert classifier.classify(80) == "High"
        assert classifier.classify(89) == "High"
    
    def test_classify_critical(self, mock_triage_config, tmp_path):
        """Test classification of critical severity."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(mock_triage_config))
        
        loader = TriageConfigLoader(str(config_file))
        classifier = BucketClassifier(loader)
        
        assert classifier.classify(90) == "Critical"
        assert classifier.classify(95) == "Critical"
        assert classifier.classify(100) == "Critical"


class TestMitreMapper:
    """Test suite for MitreMapper class."""
    
    def test_mitre_mapper_initialization(self, tmp_path):
        """Test MitreMapper initialization."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
mitre:
  mapping_path: "mitre_map.yml"
""")
        
        mitre_file = tmp_path / "mitre_map.yml"
        mitre_file.write_text("""
types:
  CredentialAccess:
    - "T1078"
    - "T1110"
defaults:
  - "T1059"
""")
        
        loader = TriageConfigLoader(str(config_file))
        mapper = MitreMapper(loader)
        
        assert mapper is not None
    
    def test_get_techniques_for_known_type(self, tmp_path):
        """Test getting techniques for known alert type."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
mitre:
  mapping_path: "mitre_map.yml"
""")
        
        mitre_file = tmp_path / "mitre_map.yml"
        mitre_file.write_text("""
types:
  CredentialAccess:
    - "T1078"
    - "T1110"
defaults:
  - "T1059"
""")
        
        loader = TriageConfigLoader(str(config_file))
        mapper = MitreMapper(loader)
        
        techniques = mapper.get_techniques("CredentialAccess")
        
        assert "T1078" in techniques
        assert "T1110" in techniques
    
    def test_get_techniques_for_unknown_type_returns_defaults(self, tmp_path):
        """Test that unknown alert type returns default techniques."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
mitre:
  mapping_path: "mitre_map.yml"
""")
        
        mitre_file = tmp_path / "mitre_map.yml"
        mitre_file.write_text("""
types:
  CredentialAccess:
    - "T1078"
defaults:
  - "T1059"
""")
        
        loader = TriageConfigLoader(str(config_file))
        mapper = MitreMapper(loader)
        
        techniques = mapper.get_techniques("UnknownType")
        
        assert techniques == ["T1059"]
    
    def test_get_techniques_missing_mapping_file(self, tmp_path):
        """Test that missing MITRE mapping file returns empty list."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
mitre:
  mapping_path: "nonexistent.yml"
""")
        
        loader = TriageConfigLoader(str(config_file))
        mapper = MitreMapper(loader)
        
        techniques = mapper.get_techniques("CredentialAccess")
        
        assert isinstance(techniques, list)
        assert len(techniques) == 0
    
    def test_get_techniques_empty_string_returns_defaults(self, tmp_path):
        """Test that empty alert type returns defaults."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
mitre:
  mapping_path: "mitre_map.yml"
""")
        
        mitre_file = tmp_path / "mitre_map.yml"
        mitre_file.write_text("""
defaults:
  - "T1059"
""")
        
        loader = TriageConfigLoader(str(config_file))
        mapper = MitreMapper(loader)
        
        techniques = mapper.get_techniques("")
        
        assert techniques == ["T1059"]
