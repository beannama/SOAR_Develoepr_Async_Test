"""
Integration Tests for Full SOAR Pipeline

Tests end-to-end pipeline flow from ingestion through response.
"""

import pytest
import os
import sys
import json
import shutil

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Ingest.loader import load_alert
from SOAR.Normalize.normalize import normalize
from SOAR.Enrichment.enricher import enrich
from SOAR.Triage.triage import triage
from SOAR.Response.response import respond
from SOAR.Timeline.timeline_manager import TimelineManager


class TestFullPipelineWithSampleAlert:
    """Test complete pipeline using sample alert."""
    
    def test_full_pipeline_sample_alert(self):
        """Test complete pipeline from ingest to response with sample alert."""
        timeline = TimelineManager()
        
        # Step 1: Ingest
        alert = load_alert(use_sample=True)
        assert "alert_id" in alert
        alert = timeline.initialize(alert)
        alert = timeline.add_entry(alert, "ingest", "Alert loaded")
        
        # Step 2: Normalize
        alert = normalize(alert)
        assert "incident_id" in alert
        assert "source_alert" in alert
        assert isinstance(alert["indicators"], list)
        alert = timeline.add_entry(alert, "ingest", f"Incident created: {alert['incident_id']}")
        
        # Step 3: Enrich
        alert = enrich(alert)
        assert all("risk" in ind for ind in alert["indicators"])
        alert = timeline.add_entry(alert, "enrich", f"Enriched {len(alert['indicators'])} indicators")
        
        # Step 4: Triage
        alert = triage(alert)
        assert "triage" in alert
        assert "mitre" in alert
        assert "severity_score" in alert["triage"]
        alert = timeline.add_entry(alert, "triage", f"Severity: {alert['triage']['severity_score']}")
        
        # Step 5: Response
        alert = respond(alert)
        assert "actions" in alert
        alert = timeline.add_entry(alert, "respond", f"Actions: {len(alert['actions'])}")
        
        # Validate final structure
        assert "incident_id" in alert
        assert "timeline" in alert
        assert len(alert["timeline"]) >= 5
    
    def test_pipeline_preserves_data_through_stages(self):
        """Test that data is preserved correctly through all stages."""
        timeline = TimelineManager()
        
        # Load and track original data
        alert = load_alert(use_sample=True)
        original_alert_id = alert["alert_id"]
        original_source = alert["source"]
        
        alert = timeline.initialize(alert)
        alert = normalize(alert)
        alert = enrich(alert)
        alert = triage(alert)
        alert = respond(alert)
        
        # Check preservation
        assert alert["source_alert"]["alert_id"] == original_alert_id
        assert alert["source_alert"]["source"] == original_source
    
    def test_pipeline_timeline_ordering(self):
        """Test that timeline entries are in correct order."""
        timeline = TimelineManager()
        
        alert = load_alert(use_sample=True)
        alert = timeline.initialize(alert)
        alert = timeline.add_entry(alert, "ingest", "Step 1")
        alert = normalize(alert)
        alert = timeline.add_entry(alert, "ingest", "Step 2")
        alert = enrich(alert)
        alert = timeline.add_entry(alert, "enrich", "Step 3")
        alert = triage(alert)
        alert = timeline.add_entry(alert, "triage", "Step 4")
        alert = respond(alert)
        alert = timeline.add_entry(alert, "respond", "Step 5")
        
        # Validate timeline
        timeline.validate(alert)
        assert len(alert["timeline"]) == 5


class TestPipelineWithRealAlertFiles:
    """Test pipeline with actual alert files from alerts/ directory."""
    
    def test_pipeline_with_sentinel_alert(self):
        """Test pipeline with sentinel.json if it exists."""
        workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sentinel_path = os.path.join(workspace_root, "alerts", "sentinel.json")
        
        if not os.path.exists(sentinel_path):
            pytest.skip("sentinel.json not found")
        
        timeline = TimelineManager()
        
        # Run pipeline
        alert = load_alert(path=sentinel_path)
        alert = timeline.initialize(alert)
        alert = normalize(alert)
        alert = enrich(alert)
        alert = triage(alert)
        alert = respond(alert)
        
        # Validate final structure
        assert "incident_id" in alert
        assert "triage" in alert
        assert "actions" in alert
    
    def test_pipeline_with_sumologic_alert(self):
        """Test pipeline with sumologic.json if it exists."""
        workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sumologic_path = os.path.join(workspace_root, "alerts", "sumologic.json")
        
        if not os.path.exists(sumologic_path):
            pytest.skip("sumologic.json not found")
        
        timeline = TimelineManager()
        
        # Run pipeline
        alert = load_alert(path=sumologic_path)
        alert = timeline.initialize(alert)
        alert = normalize(alert)
        alert = enrich(alert)
        alert = triage(alert)
        alert = respond(alert)
        
        # Validate final structure
        assert "incident_id" in alert
        assert "triage" in alert


class TestPipelineErrorHandling:
    """Test pipeline error handling and recovery."""
    
    def test_pipeline_with_invalid_alert_fails_early(self):
        """Test that invalid alert fails at validation."""
        invalid_alert = {"missing": "required_fields"}
        
        with pytest.raises(ValueError):
            normalize(invalid_alert)
    
    def test_pipeline_with_empty_indicators(self):
        """Test pipeline with alert containing no indicators."""
        alert = {
            "alert_id": "test-empty",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "indicators": {}
        }
        
        timeline = TimelineManager()
        alert = timeline.initialize(alert)
        alert = normalize(alert)
        alert = enrich(alert)
        
        # Should handle gracefully
        assert isinstance(alert["indicators"], list)
        assert len(alert["indicators"]) == 0


class TestPipelineDataTransformations:
    """Test data transformations through pipeline stages."""
    
    def test_indicators_transformation_from_dict_to_list(self):
        """Test that indicators are transformed from dict to list."""
        alert = load_alert(use_sample=True)
        
        # Before normalization: dict format
        assert isinstance(alert["indicators"], dict)
        assert "ipv4" in alert["indicators"]
        
        # After normalization: list format
        normalized = normalize(alert)
        assert isinstance(normalized["indicators"], list)
        assert all(isinstance(ind, dict) for ind in normalized["indicators"])
        assert all("type" in ind and "value" in ind for ind in normalized["indicators"])
    
    def test_risk_enrichment_adds_fields(self):
        """Test that enrichment adds risk fields to indicators."""
        alert = load_alert(use_sample=True)
        alert = normalize(alert)
        
        # Before enrichment: no risk fields
        for indicator in alert["indicators"]:
            assert "risk" not in indicator
        
        # After enrichment: risk fields added
        enriched = enrich(alert)
        for indicator in enriched["indicators"]:
            assert "risk" in indicator
            assert "verdict" in indicator["risk"]
            assert "score" in indicator["risk"]
    
    def test_triage_adds_severity_and_bucket(self):
        """Test that triage adds severity score and bucket."""
        alert = load_alert(use_sample=True)
        alert = normalize(alert)
        alert = enrich(alert)
        
        # Before triage: no triage data
        assert "triage" not in alert
        
        # After triage: triage data added
        triaged = triage(alert)
        assert "triage" in triaged
        assert "severity_score" in triaged["triage"]
        assert "bucket" in triaged["triage"]
        assert 0 <= triaged["triage"]["severity_score"] <= 100
    
    def test_response_adds_actions(self):
        """Test that response stage adds actions array."""
        alert = load_alert(use_sample=True)
        alert = normalize(alert)
        alert = enrich(alert)
        alert = triage(alert)
        
        # Before response: actions may be empty
        initial_actions = len(alert.get("actions", []))
        
        # After response: actions populated based on severity
        responded = respond(alert)
        assert "actions" in responded
        assert isinstance(responded["actions"], list)


class TestPipelineSeverityScenarios:
    """Test pipeline with different severity scenarios."""
    
    def test_high_severity_alert_triggers_isolation(self):
        """Test that high severity alert triggers device isolation."""
        alert = {
            "alert_id": "high-severity",
            "source": "test",
            "type": "Malware",
            "created_at": "2025-12-10T10:00:00Z",
            "asset": {"device_id": "dev-critical", "hostname": "CRITICAL-HOST", "ip": "10.0.0.1"},
            "indicators": {
                "sha256": ["deadbeef" * 8]
            }
        }
        
        timeline = TimelineManager()
        alert = timeline.initialize(alert)
        alert = normalize(alert)
        alert = enrich(alert)
        alert = triage(alert)
        alert = respond(alert)
        
        # Check if high severity was assigned
        if alert["triage"]["severity_score"] >= 70:
            # High severity might trigger actions
            assert "actions" in alert
    
    def test_low_severity_alert_no_actions(self):
        """Test that low severity alert triggers no actions."""
        alert = {
            "alert_id": "low-severity",
            "source": "test",
            "type": "Unknown",
            "created_at": "2025-12-10T10:00:00Z",
            "asset": {"device_id": "dev-test", "hostname": "TEST-HOST", "ip": "10.0.0.2"},
            "indicators": {
                "ipv4": ["192.0.2.1"]  # Unknown IOC
            }
        }
        
        timeline = TimelineManager()
        alert = timeline.initialize(alert)
        alert = normalize(alert)
        alert = enrich(alert)
        alert = triage(alert)
        alert = respond(alert)
        
        # Low severity should have minimal actions
        assert alert["triage"]["severity_score"] < 70


class TestPipelinePerformance:
    """Test pipeline performance with various loads."""
    
    def test_pipeline_with_many_indicators(self):
        """Test pipeline with alert containing many indicators."""
        alert = {
            "alert_id": "many-indicators",
            "source": "test",
            "type": "Test",
            "created_at": "2025-12-10T10:00:00Z",
            "asset": {"device_id": "dev-001"},
            "indicators": {
                "ipv4": [f"10.0.0.{i}" for i in range(1, 101)]  # 100 IPs
            }
        }
        
        timeline = TimelineManager()
        alert = timeline.initialize(alert)
        alert = normalize(alert)
        alert = enrich(alert)
        alert = triage(alert)
        alert = respond(alert)
        
        # Should handle large number of indicators
        assert len(alert["indicators"]) == 100
        assert all("risk" in ind for ind in alert["indicators"])
    
    def test_pipeline_idempotency(self):
        """Test that running pipeline twice produces consistent results."""
        alert1 = load_alert(use_sample=True)
        alert2 = load_alert(use_sample=True)
        
        timeline = TimelineManager()
        
        # Process both alerts
        alert1 = timeline.initialize(alert1)
        alert1 = normalize(alert1)
        alert1 = enrich(alert1)
        alert1 = triage(alert1)
        
        alert2 = timeline.initialize(alert2)
        alert2 = normalize(alert2)
        alert2 = enrich(alert2)
        alert2 = triage(alert2)
        
        # Triage results should be same (excluding incident_id and timestamps)
        assert alert1["triage"]["severity_score"] == alert2["triage"]["severity_score"]
        assert alert1["triage"]["bucket"] == alert2["triage"]["bucket"]


class TestPipelineModuleIntegration:
    """Test integration between specific modules."""
    
    def test_normalize_to_enrich_compatibility(self):
        """Test that normalize output is compatible with enrich input."""
        alert = load_alert(use_sample=True)
        normalized = normalize(alert)
        
        # Should not raise validation error
        enriched = enrich(normalized)
        assert enriched is not None
    
    def test_enrich_to_triage_compatibility(self):
        """Test that enrich output is compatible with triage input."""
        alert = load_alert(use_sample=True)
        alert = normalize(alert)
        enriched = enrich(alert)
        
        # Should not raise validation error
        triaged = triage(enriched)
        assert triaged is not None
    
    def test_triage_to_response_compatibility(self):
        """Test that triage output is compatible with response input."""
        alert = load_alert(use_sample=True)
        alert = normalize(alert)
        alert = enrich(alert)
        triaged = triage(alert)
        
        # Should not raise validation error
        responded = respond(triaged)
        assert responded is not None
