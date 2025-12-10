"""
Unit Tests for SOAR/Reporting/summary_renderer.py

Tests Markdown summary rendering, data transformation, and Jinja2 template usage.
"""

import pytest
import os
import sys
import tempfile
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Reporting.summary_renderer import (
    SummaryDataTransformer,
    MarkdownTemplateLoader,
    render_summary,
    JINJA2_AVAILABLE
)


class TestSummaryDataTransformerIncidentOverview:
    """Test suite for transform_incident_overview method."""
    
    def test_transform_incident_overview(self):
        """Test transforming incident overview data."""
        extracted_data = {
            "incident_id": "INC-20251210T010027Z-bf066066",
            "source_alert": {
                "created_at": "2025-12-10T01:00:27Z",
                "source": "Sentinel",
                "type": "CredentialAccess"
            }
        }
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform_incident_overview()
        
        assert result["id"] == "INC-20251210T010027Z-bf066066"
        assert result["created_at"] == "2025-12-10T01:00:27Z"
        assert result["source"] == "Sentinel"
        assert result["type"] == "CredentialAccess"


class TestSummaryDataTransformerAsset:
    """Test suite for transform_asset method."""
    
    def test_transform_asset_with_complete_data(self):
        """Test transforming asset with all fields."""
        extracted_data = {
            "asset": {
                "device_id": "dev-9001",
                "hostname": "workstation-01",
                "ip": "10.0.1.5"
            }
        }
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform_asset()
        
        assert result["device_id"] == "dev-9001"
        assert result["hostname"] == "workstation-01"
        assert result["ip"] == "10.0.1.5"
    
    def test_transform_asset_with_missing_fields(self):
        """Test transforming asset with missing fields returns empty strings."""
        extracted_data = {"asset": {}}
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform_asset()
        
        assert result["device_id"] == ""
        assert result["hostname"] == ""
        assert result["ip"] == ""


class TestSummaryDataTransformerIndicatorsTable:
    """Test suite for transform_indicators_table method."""
    
    def test_transform_indicators_table(self):
        """Test transforming indicators into table format."""
        extracted_data = {
            "indicators": [
                {
                    "type": "ipv4",
                    "value": "1.2.3.4",
                    "risk": {"verdict": "malicious", "score": 80},
                    "allowlisted": False
                },
                {
                    "type": "domains",
                    "value": "bad.com",
                    "risk": {"verdict": "suspicious", "score": 60},
                    "allowlisted": False
                }
            ]
        }
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform_indicators_table()
        
        assert len(result) == 2
        assert result[0]["type"] == "ipv4"
        assert result[0]["value"] == "1.2.3.4"
        assert result[0]["verdict"] == "malicious"
        assert result[0]["score"] == 80
        assert result[0]["allowlisted"] is False


class TestSummaryDataTransformerSeverity:
    """Test suite for transform_severity_section method."""
    
    def test_transform_severity_section(self):
        """Test transforming severity/triage data."""
        extracted_data = {
            "triage": {
                "severity": 75,
                "bucket": "High",
                "tags": ["flagged"],
                "suppressed": False
            }
        }
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform_severity_section()
        
        assert result["score"] == 75
        assert result["bucket"] == "High"
        assert result["tags"] == ["flagged"]
        assert result["suppressed"] is False
    
    def test_transform_severity_section_with_missing_triage(self):
        """Test transform_severity_section with missing triage returns defaults."""
        extracted_data = {}
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform_severity_section()
        
        assert result["score"] == 0
        assert result["bucket"] == "Unknown"
        assert result["tags"] == []
        assert result["suppressed"] is False


class TestSummaryDataTransformerMitre:
    """Test suite for transform_mitre_techniques method."""
    
    def test_transform_mitre_techniques(self):
        """Test transforming MITRE ATT&CK techniques."""
        extracted_data = {
            "mitre": {
                "techniques": ["T1078", "T1110"]
            }
        }
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform_mitre_techniques()
        
        assert result["techniques"] == ["T1078", "T1110"]
    
    def test_transform_mitre_techniques_with_missing_data(self):
        """Test transform_mitre_techniques with missing data returns defaults."""
        extracted_data = {}
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform_mitre_techniques()
        
        assert result["techniques"] == []


class TestSummaryDataTransformerActions:
    """Test suite for transform_actions_section method."""
    
    def test_transform_actions_section(self):
        """Test transforming response actions."""
        extracted_data = {
            "actions": [
                {
                    "type": "isolate",
                    "target": "device:dev-9001",
                    "result": "isolated",
                    "ts": "2025-12-10T01:05:00Z"
                }
            ]
        }
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform_actions_section()
        
        assert len(result) == 1
        assert result[0]["type"] == "isolate"
        assert result[0]["target"] == "device:dev-9001"
        assert result[0]["result"] == "isolated"


class TestSummaryDataTransformerTimeline:
    """Test suite for transform_timeline method."""
    
    def test_transform_timeline(self):
        """Test transforming timeline entries."""
        extracted_data = {
            "timeline": [
                {"stage": "ingest", "ts": "2025-12-10T01:00:00Z", "details": "Alert loaded"},
                {"stage": "normalize", "ts": "2025-12-10T01:00:01Z", "details": "Normalized"}
            ]
        }
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform_timeline()
        
        assert len(result) == 2
        assert result[0]["stage"] == "ingest"


class TestSummaryDataTransformerFullTransform:
    """Test suite for full transform method."""
    
    def test_transform_includes_all_sections(self):
        """Test that transform includes all expected sections."""
        extracted_data = {
            "incident_id": "INC-20251210T010027Z-bf066066",
            "source_alert": {"created_at": "2025-12-10T01:00:00Z", "source": "Sentinel", "type": "Test"},
            "asset": {},
            "indicators": [],
            "triage": {"severity": 50, "bucket": "Medium", "tags": [], "suppressed": False},
            "mitre": {"techniques": []},
            "actions": [],
            "timeline": []
        }
        
        transformer = SummaryDataTransformer(extracted_data)
        result = transformer.transform()
        
        assert "incident" in result
        assert "asset" in result
        assert "indicators" in result
        assert "severity" in result
        assert "mitre" in result
        assert "actions" in result
        assert "timeline" in result
        assert "summary_generated_at" in result


class TestMarkdownTemplateLoader:
    """Test suite for MarkdownTemplateLoader class."""
    
    def test_template_loader_initialization(self):
        """Test MarkdownTemplateLoader initialization."""
        loader = MarkdownTemplateLoader()
        assert loader is not None
    
    def test_get_template_dir_returns_absolute_path(self):
        """Test that _get_template_dir returns absolute path."""
        loader = MarkdownTemplateLoader()
        template_dir = loader._get_template_dir()
        
        assert os.path.isabs(template_dir)
        assert "templates" in template_dir
    
    def test_create_inline_fallback_returns_template_string(self):
        """Test that inline fallback template is created."""
        loader = MarkdownTemplateLoader()
        template_str = loader._create_inline_fallback()
        
        assert isinstance(template_str, str)
        assert "# Incident Report" in template_str
        assert "{{ incident.id }}" in template_str


@pytest.mark.skipif(not JINJA2_AVAILABLE, reason="Jinja2 not installed")
class TestRenderSummary:
    """Test suite for render_summary function."""
    
    def test_render_summary_creates_markdown_file(self, valid_triaged_alert, tmp_path, monkeypatch):
        """Test that render_summary creates Markdown file."""
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
            "SOAR.Reporting.summary_renderer._build_config_path",
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
        valid_triaged_alert["source_alert"] = {
            "created_at": "2025-12-10T01:00:27Z",
            "source": "Sentinel",
            "type": "CredentialAccess"
        }
        
        result = render_summary(valid_triaged_alert, str(output_dir))
        
        assert result is True
        summaries_dir = output_dir / "summaries"
        assert summaries_dir.exists()
        
        md_file = summaries_dir / "INC-20251210T010027Z-bf066066.md"
        assert md_file.exists()
        
        # Verify Markdown content
        content = md_file.read_text(encoding="utf-8")
        assert "# Incident Report" in content
        assert "INC-20251210T010027Z-bf066066" in content
    
    def test_render_summary_returns_false_on_error(self, tmp_path):
        """Test that render_summary returns False on error."""
        output_dir = tmp_path / "out"
        
        # Invalid alert (missing required fields)
        invalid_alert = {"incident_id": "INVALID"}
        
        result = render_summary(invalid_alert, str(output_dir))
        
        assert result is False


class TestRenderSummaryWithoutJinja2:
    """Test suite for render_summary when Jinja2 is not available."""
    
    def test_render_summary_returns_false_without_jinja2(self, tmp_path, monkeypatch):
        """Test that render_summary returns False when Jinja2 not available."""
        # Mock JINJA2_AVAILABLE to False
        import SOAR.Reporting.summary_renderer as renderer_module
        monkeypatch.setattr(renderer_module, "JINJA2_AVAILABLE", False)
        
        output_dir = tmp_path / "out"
        alert = {
            "incident_id": "INC-20251210T010027Z-bf066066",
            "indicators": [],
            "triage": {},
            "mitre": {},
            "actions": [],
            "timeline": []
        }
        
        result = render_summary(alert, str(output_dir))
        
        assert result is False
