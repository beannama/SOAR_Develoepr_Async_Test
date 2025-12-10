"""
Unit Tests for SOAR/Reporting/incident_exporter.py

Tests incident JSON export, data extraction, and validation.
"""

import pytest
import os
import sys
import json
import tempfile
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Reporting.incident_exporter import (
    IncidentDataExtractor,
    export_incident
)


class TestIncidentDataExtractorValidation:
    """Test suite for IncidentDataExtractor validation."""
    
    def test_validation_with_valid_alert(self, valid_triaged_alert, tmp_path):
        """Test validation with valid alert structure."""
        # Setup allowlist
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        from SOAR.Triage.rules import AllowlistLoader
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        extractor = IncidentDataExtractor(allowlist_loader)
        
        # Ensure required fields present
        valid_triaged_alert["incident_id"] = "INC-20251210T010027Z-bf066066"
        valid_triaged_alert["indicators"] = []
        valid_triaged_alert["triage"] = {"severity_score": 50}
        valid_triaged_alert["mitre"] = {"techniques": []}
        valid_triaged_alert["actions"] = []
        valid_triaged_alert["timeline"] = [
            {"stage": "ingest", "ts": "2025-12-10T01:00:27Z", "details": "Alert loaded"}
        ]
        
        # Should not raise exception
        extractor._validate_input(valid_triaged_alert)
    
    def test_validation_non_dict_raises_error(self, tmp_path):
        """Test that non-dict alert raises ValueError."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        from SOAR.Triage.rules import AllowlistLoader
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        extractor = IncidentDataExtractor(allowlist_loader)
        
        with pytest.raises(ValueError, match="alert must be a dictionary"):
            extractor._validate_input("not a dict")
    
    def test_validation_missing_required_field_raises_error(self, tmp_path):
        """Test that missing required field raises ValueError."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        from SOAR.Triage.rules import AllowlistLoader
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        extractor = IncidentDataExtractor(allowlist_loader)
        
        alert = {
            "incident_id": "INC-20251210T010027Z-bf066066",
            "indicators": [],
            "triage": {},
            # Missing: mitre, actions, timeline
        }
        
        with pytest.raises(ValueError, match="missing required field"):
            extractor._validate_input(alert)
    
    def test_validation_invalid_incident_id_format_raises_error(self, tmp_path):
        """Test that invalid incident_id format raises ValueError."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        from SOAR.Triage.rules import AllowlistLoader
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        extractor = IncidentDataExtractor(allowlist_loader)
        
        alert = {
            "incident_id": "INVALID-ID",
            "indicators": [],
            "triage": {},
            "mitre": {},
            "actions": [],
            "timeline": []
        }
        
        with pytest.raises(ValueError, match="incident_id has invalid format"):
            extractor._validate_input(alert)
    
    def test_validation_indicators_not_list_raises_error(self, tmp_path):
        """Test that indicators not being a list raises ValueError."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        from SOAR.Triage.rules import AllowlistLoader
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        extractor = IncidentDataExtractor(allowlist_loader)
        
        alert = {
            "incident_id": "INC-20251210T010027Z-bf066066",
            "indicators": "not a list",
            "triage": {},
            "mitre": {},
            "actions": [],
            "timeline": []
        }
        
        with pytest.raises(ValueError, match="indicators must be a list"):
            extractor._validate_input(alert)


class TestIncidentDataExtractorCoreFields:
    """Test suite for extract_core_fields method."""
    
    def test_extract_core_fields_with_valid_data(self, tmp_path):
        """Test extracting core fields from alert."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        from SOAR.Triage.rules import AllowlistLoader
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        extractor = IncidentDataExtractor(allowlist_loader)
        
        alert = {
            "incident_id": "INC-20251210T010027Z-bf066066",
            "source_alert": {"type": "CredentialAccess"}
        }
        
        result = extractor.extract_core_fields(alert)
        
        assert result["incident_id"] == "INC-20251210T010027Z-bf066066"
        assert result["source_alert"]["type"] == "CredentialAccess"


class TestIncidentDataExtractorAsset:
    """Test suite for extract_asset method."""
    
    def test_extract_asset_with_complete_data(self, tmp_path):
        """Test extracting asset with all fields present."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        from SOAR.Triage.rules import AllowlistLoader
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        extractor = IncidentDataExtractor(allowlist_loader)
        
        alert = {
            "asset": {
                "device_id": "dev-9001",
                "hostname": "workstation-01",
                "ip": "10.0.1.5"
            }
        }
        
        result = extractor.extract_asset(alert)
        
        assert result["device_id"] == "dev-9001"
        assert result["hostname"] == "workstation-01"
        assert result["ip"] == "10.0.1.5"
    
    def test_extract_asset_with_missing_fields_returns_defaults(self, tmp_path):
        """Test extracting asset with missing fields returns empty strings."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        from SOAR.Triage.rules import AllowlistLoader
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        extractor = IncidentDataExtractor(allowlist_loader)
        
        alert = {"asset": {}}
        
        result = extractor.extract_asset(alert)
        
        assert result["device_id"] == ""
        assert result["hostname"] == ""
        assert result["ip"] == ""


class TestIncidentDataExtractorIndicators:
    """Test suite for extract_indicators_with_allowlist method."""
    
    def test_extract_indicators_with_allowlist_status(self, tmp_path):
        """Test extracting indicators with allowlist status added."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("""
indicators:
  ipv4:
    - "203.0.113.10"
""")
        
        from SOAR.Triage.rules import AllowlistLoader
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        extractor = IncidentDataExtractor(allowlist_loader)
        
        alert = {
            "indicators": [
                {"type": "ipv4", "value": "203.0.113.10", "risk": {"verdict": "unknown"}},
                {"type": "ipv4", "value": "1.2.3.4", "risk": {"verdict": "malicious"}}
            ]
        }
        
        result = extractor.extract_indicators_with_allowlist(alert)
        
        assert len(result) == 2
        assert result[0]["allowlisted"] is True
        assert result[1]["allowlisted"] is False


class TestIncidentDataExtractorTriage:
    """Test suite for extract_triage_data method."""
    
    def test_extract_triage_data_renames_severity_score(self, tmp_path):
        """Test that severity_score is renamed to severity."""
        allowlist_file = tmp_path / "allowlist.yml"
        allowlist_file.write_text("indicators: {}")
        
        from SOAR.Triage.rules import AllowlistLoader
        allowlist_loader = AllowlistLoader(str(allowlist_file))
        extractor = IncidentDataExtractor(allowlist_loader)
        
        alert = {
            "triage": {
                "severity_score": 75,
                "bucket": "High",
                "tags": ["flagged"],
                "suppressed": False
            }
        }
        
        result = extractor.extract_triage_data(alert)
        
        assert result["severity"] == 75
        assert result["bucket"] == "High"
        assert result["tags"] == ["flagged"]
        assert result["suppressed"] is False


class TestExportIncident:
    """Test suite for export_incident function."""
    
    def test_export_incident_creates_json_file(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that export_incident creates JSON file."""
        output_dir = tmp_path / "out"
        
        # Setup config
        config_file = tmp_path / "config.yml"
        allowlist_file = tmp_path / "allowlist.yml"
        
        config_file.write_text("""
suppression:
  allowlist_path: "allowlist.yml"
""")
        allowlist_file.write_text("indicators: {}")
        
        # Patch config path
        monkeypatch.setattr(
            "SOAR.Reporting.incident_exporter._build_config_path",
            lambda: str(config_file)
        )
        
        # Reset singletons
        import SOAR.Reporting.incident_exporter as exporter_module
        exporter_module._CONFIG_LOADER = None
        exporter_module._ALLOWLIST_LOADER = None
        
        # Ensure required fields
        valid_triaged_alert["incident_id"] = "INC-20251210T010027Z-bf066066"
        valid_triaged_alert["indicators"] = []
        valid_triaged_alert["mitre"] = {"techniques": []}
        valid_triaged_alert["actions"] = []
        valid_triaged_alert["timeline"] = [
            {"stage": "ingest", "ts": "2025-12-10T01:00:27Z", "details": "Alert loaded"}
        ]
        
        result = export_incident(valid_triaged_alert, str(output_dir))
        
        assert result is True
        incidents_dir = output_dir / "incidents"
        assert incidents_dir.exists()
        
        json_file = incidents_dir / "INC-20251210T010027Z-bf066066.json"
        assert json_file.exists()
        
        # Verify JSON structure
        with open(json_file, "r") as f:
            data = json.load(f)
            assert data["incident_id"] == "INC-20251210T010027Z-bf066066"
    
    def test_export_incident_returns_false_on_error(self, tmp_path):
        """Test that export_incident returns False on error."""
        output_dir = tmp_path / "out"
        
        # Invalid alert (missing required fields)
        invalid_alert = {"incident_id": "INVALID"}
        
        result = export_incident(invalid_alert, str(output_dir))
        
        assert result is False
