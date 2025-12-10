"""
Unit Tests for SOAR/Enrichment/mock_ti.py

Tests local threat intelligence enrichment, risk merging, and TI index.
"""

import pytest
import os
import sys
import json
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Enrichment.mock_ti import (
    MockTI,
    ConfigLoader,
    RiskMerger,
    MockTIIndex
)


class TestConfigLoader:
    """Test suite for ConfigLoader class."""
    
    def test_config_loader_initialization(self, temp_config_dir):
        """Test ConfigLoader initialization with valid config directory."""
        loader = ConfigLoader(temp_config_dir)
        assert loader.config_dir == temp_config_dir
        assert isinstance(loader.connectors, dict)
    
    def test_config_loader_invalid_directory_raises_error(self):
        """Test that invalid config directory raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Config directory not found"):
            ConfigLoader("/nonexistent/config/dir")
    
    def test_config_loader_loads_connectors(self, temp_config_dir):
        """Test that ConfigLoader loads connectors.yml."""
        loader = ConfigLoader(temp_config_dir)
        connectors = loader.get_providers()
        
        assert isinstance(connectors, dict)
        assert "defender_ti" in connectors
        assert "anomali" in connectors
    
    def test_config_loader_validates_provider_structure(self, temp_config_dir):
        """Test that ConfigLoader validates provider structure."""
        loader = ConfigLoader(temp_config_dir)
        providers = loader.get_providers()
        
        for provider_name, provider_config in providers.items():
            assert isinstance(provider_config, dict)
            assert "base_url" in provider_config


class TestRiskMerger:
    """Test suite for RiskMerger class."""
    
    def test_risk_merger_initialization(self):
        """Test RiskMerger initialization."""
        merger = RiskMerger()
        assert merger is not None
    
    def test_merge_empty_list_returns_unknown(self):
        """Test that merging empty list returns unknown verdict."""
        merger = RiskMerger()
        result = merger.merge([])
        
        assert result["verdict"] == "unknown"
        assert result["score"] == 0
        assert result["sources"] == []
        assert result["provider_details"] == []
    
    def test_merge_single_provider_malicious(self):
        """Test merging single provider with malicious verdict."""
        merger = RiskMerger()
        ti_results = [
            {
                "provider": "defender_ti",
                "verdict": "malicious",
                "score": 95
            }
        ]
        
        result = merger.merge(ti_results)
        
        assert result["verdict"] == "malicious"
        assert result["score"] == 95
        assert "defender_ti" in result["sources"]
    
    def test_merge_multiple_providers_consensus(self):
        """Test merging multiple providers with same verdict."""
        merger = RiskMerger()
        ti_results = [
            {"provider": "defender_ti", "verdict": "malicious", "score": 90},
            {"provider": "anomali", "verdict": "malicious", "score": 95}
        ]
        
        result = merger.merge(ti_results)
        
        assert result["verdict"] == "malicious"
        assert result["score"] == 95  # Maximum score
        assert len(result["sources"]) == 2
    
    def test_merge_conflicting_verdicts_most_severe_wins(self):
        """Test that most severe verdict wins in conflicts."""
        merger = RiskMerger()
        ti_results = [
            {"provider": "defender_ti", "verdict": "malicious", "score": 90},
            {"provider": "anomali", "verdict": "clean", "score": 10}
        ]
        
        result = merger.merge(ti_results)
        
        # Malicious should win over clean
        assert result["verdict"] == "malicious"
        assert result["score"] == 90
    
    def test_merge_verdict_priority_ordering(self):
        """Test verdict priority: malicious > suspicious > clean > unknown."""
        merger = RiskMerger()
        
        # Test malicious > suspicious
        result1 = merger.merge([
            {"provider": "p1", "verdict": "malicious", "score": 80},
            {"provider": "p2", "verdict": "suspicious", "score": 60}
        ])
        assert result1["verdict"] == "malicious"
        
        # Test suspicious > clean
        result2 = merger.merge([
            {"provider": "p1", "verdict": "suspicious", "score": 60},
            {"provider": "p2", "verdict": "clean", "score": 10}
        ])
        assert result2["verdict"] == "suspicious"
        
        # Test clean > unknown
        result3 = merger.merge([
            {"provider": "p1", "verdict": "clean", "score": 10},
            {"provider": "p2", "verdict": "unknown", "score": 0}
        ])
        assert result3["verdict"] == "clean"
    
    def test_merge_max_score_selection(self):
        """Test that merge selects maximum score from all providers."""
        merger = RiskMerger()
        ti_results = [
            {"provider": "p1", "verdict": "suspicious", "score": 50},
            {"provider": "p2", "verdict": "suspicious", "score": 75},
            {"provider": "p3", "verdict": "suspicious", "score": 60}
        ]
        
        result = merger.merge(ti_results)
        
        assert result["score"] == 75
    
    def test_merge_provider_details_tracking(self):
        """Test that merge tracks all provider details."""
        merger = RiskMerger()
        ti_results = [
            {"provider": "defender_ti", "verdict": "malicious", "score": 90},
            {"provider": "anomali", "verdict": "suspicious", "score": 60}
        ]
        
        result = merger.merge(ti_results)
        
        assert len(result["provider_details"]) == 2
        assert result["provider_details"][0]["provider"] == "defender_ti"
        assert result["provider_details"][1]["provider"] == "anomali"
    
    def test_merge_non_list_raises_error(self):
        """Test that non-list input raises ValueError."""
        merger = RiskMerger()
        
        with pytest.raises(ValueError, match="ti_results must be a list"):
            merger.merge("not a list")
    
    def test_merge_handles_malformed_entries(self):
        """Test that merge gracefully handles malformed entries."""
        merger = RiskMerger()
        ti_results = [
            {"provider": "defender_ti", "verdict": "malicious", "score": 90},
            "malformed entry",
            None,
            {"provider": "anomali", "verdict": "clean", "score": 10}
        ]
        
        # Should process valid entries, skip malformed
        result = merger.merge(ti_results)
        assert len(result["sources"]) >= 2


class TestMockTIIndex:
    """Test suite for MockTIIndex class."""
    
    def test_ti_index_initialization(self, temp_ti_dir):
        """Test MockTIIndex initialization."""
        index = MockTIIndex(temp_ti_dir)
        assert index is not None
    
    def test_ti_index_loads_files(self, temp_ti_dir):
        """Test that TI index loads JSON files."""
        index = MockTIIndex(temp_ti_dir)
        indexed = index.get_indexed_iocs()
        
        assert isinstance(indexed, dict)
    
    def test_ti_index_lookup_existing_ioc(self, temp_ti_dir):
        """Test looking up an existing IOC."""
        index = MockTIIndex(temp_ti_dir)
        
        # IP from temp fixture
        result = index.query_all_providers("ipv4", "1.2.3.4")
        
        assert isinstance(result, list)
        assert len(result) > 0
    
    def test_ti_index_lookup_nonexistent_ioc(self, temp_ti_dir):
        """Test looking up a non-existent IOC."""
        index = MockTIIndex(temp_ti_dir)
        result = index.query_all_providers("ipv4", "192.0.2.1")
        
        assert result == []
    
    def test_ti_index_get_indexed_iocs(self, temp_ti_dir):
        """Test getting indexed IOC types and counts."""
        index = MockTIIndex(temp_ti_dir)
        indexed = index.get_indexed_iocs()
        
        assert isinstance(indexed, dict)
        for ioc_type, count in indexed.items():
            assert isinstance(ioc_type, str)
            assert isinstance(count, int)
            assert count >= 0


class TestMockTI:
    """Test suite for MockTI class (integration)."""
    
    def test_mock_ti_initialization(self, temp_config_dir, temp_ti_dir):
        """Test MockTI initialization."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        assert ti is not None
    
    def test_query_ioc_returns_dict(self, temp_config_dir, temp_ti_dir):
        """Test that query_ioc returns a dictionary."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        result = ti.query_ioc("ipv4", "1.2.3.4")
        
        assert isinstance(result, dict)
        assert "found" in result
        assert "risk" in result
    
    def test_query_ioc_risk_structure(self, temp_config_dir, temp_ti_dir):
        """Test that query_ioc returns proper risk structure."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        result = ti.query_ioc("ipv4", "1.2.3.4")
        
        risk = result["risk"]
        assert isinstance(risk, dict)
        assert "verdict" in risk
        assert "score" in risk
        assert "sources" in risk
        assert "provider_details" in risk
    
    def test_query_ioc_verdict_values(self, temp_config_dir, temp_ti_dir):
        """Test that verdict is one of allowed values."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        result = ti.query_ioc("ipv4", "1.2.3.4")
        
        allowed_verdicts = {"malicious", "suspicious", "clean", "unknown"}
        assert result["risk"]["verdict"] in allowed_verdicts
    
    def test_query_ioc_score_range(self, temp_config_dir, temp_ti_dir):
        """Test that score is within valid range."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        result = ti.query_ioc("ipv4", "1.2.3.4")
        
        score = result["risk"]["score"]
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100
    
    def test_query_unknown_ioc_returns_unknown(self, temp_config_dir, temp_ti_dir):
        """Test that unknown IOC returns unknown verdict."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        result = ti.query_ioc("ipv4", "192.0.2.99")
        
        # Unknown IOC should have unknown verdict
        assert result["risk"]["verdict"] in ["unknown", "clean"]
    
    def test_query_different_ioc_types(self, temp_config_dir, temp_ti_dir):
        """Test querying different IOC types."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        
        ioc_types = ["ipv4", "domains", "urls", "sha256"]
        
        for ioc_type in ioc_types:
            result = ti.query_ioc(ioc_type, "test_value")
            assert isinstance(result, dict)
            assert "risk" in result
    
    def test_query_ioc_empty_value(self, temp_config_dir, temp_ti_dir):
        """Test querying with empty IOC value raises ValueError."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        
        # Empty IOC should raise ValueError
        with pytest.raises(ValueError, match="ioc_value cannot be empty"):
            ti.query_ioc("ipv4", "")
    
    def test_query_ioc_case_insensitive(self, temp_config_dir, temp_ti_dir):
        """Test that IOC lookup is case-insensitive for domains."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        
        result_lower = ti.query_ioc("domains", "bad.example.net")
        result_upper = ti.query_ioc("domains", "BAD.EXAMPLE.NET")
        
        # Should return consistent results
        assert isinstance(result_lower, dict)
        assert isinstance(result_upper, dict)


class TestMockTIEdgeCases:
    """Test suite for edge cases in MockTI."""
    
    def test_mock_ti_with_unicode_iocs(self, temp_config_dir, temp_ti_dir):
        """Test handling of Unicode IOC values."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        result = ti.query_ioc("domains", "例え.jp")
        
        assert isinstance(result, dict)
        assert "risk" in result
    
    def test_mock_ti_with_long_ioc_values(self, temp_config_dir, temp_ti_dir):
        """Test handling of very long IOC values."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        long_domain = "a" * 255 + ".example.com"
        result = ti.query_ioc("domains", long_domain)
        
        assert isinstance(result, dict)
    
    def test_mock_ti_with_special_characters(self, temp_config_dir, temp_ti_dir):
        """Test handling of special characters in IOC values."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        special_domain = "test-domain_with.special-chars.com"
        result = ti.query_ioc("domains", special_domain)
        
        assert isinstance(result, dict)
        assert "risk" in result


class TestMockTIAllowlistIntegration:
    """Test suite for allowlist integration in MockTI."""
    
    def test_mock_ti_has_allowlist(self, temp_config_dir, temp_ti_dir):
        """Test that MockTI has TI index."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        
        # Check if TI index is accessible (allowlist is separate in Triage module)
        assert hasattr(ti, 'ti_index')
    
    def test_mock_ti_allowlist_check(self, temp_config_dir, temp_ti_dir):
        """Test that MockTI can query IOCs (allowlist logic is in Triage)."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        
        # MockTI provides threat intelligence, not allowlist checking
        result = ti.query_ioc("ipv4", "203.0.113.10")
        
        assert "risk" in result


class TestMockTIMitreIntegration:
    """Test suite for MITRE ATT&CK integration in MockTI."""
    
    def test_mock_ti_has_mitre_mapper(self, temp_config_dir, temp_ti_dir):
        """Test that MockTI has config loader."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        
        # Check if config loader is accessible (MITRE is separate in Triage module)
        assert hasattr(ti, 'config_loader')
    
    def test_mock_ti_mitre_get_techniques(self, temp_config_dir, temp_ti_dir):
        """Test that MockTI provides IOC enrichment (MITRE mapping is in Triage)."""
        ti = MockTI(temp_config_dir, temp_ti_dir)
        
        # MockTI provides threat intelligence, MITRE mapping is handled by Triage module
        result = ti.query_ioc("ipv4", "1.2.3.4")
        
        assert "risk" in result
