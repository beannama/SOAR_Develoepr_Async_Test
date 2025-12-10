"""
Unit Tests for SOAR/Timeline/timeline_manager.py

Tests timeline initialization, entry management, and validation.
"""

import pytest
import os
import sys
import re
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Timeline.timeline_manager import TimelineManager, TIMELINE_STAGES


class TestTimelineManagerInitialize:
    """Test suite for initialize() method."""
    
    def test_initialize_adds_timeline_array(self):
        """Test that initialize adds empty timeline array."""
        manager = TimelineManager()
        alert = {"alert_id": "test-001"}
        
        result = manager.initialize(alert)
        
        assert "timeline" in result
        assert isinstance(result["timeline"], list)
        assert len(result["timeline"]) == 0
    
    def test_initialize_preserves_existing_fields(self):
        """Test that initialize preserves other alert fields."""
        manager = TimelineManager()
        alert = {
            "alert_id": "test-001",
            "type": "Test",
            "indicators": []
        }
        
        result = manager.initialize(alert)
        
        assert result["alert_id"] == "test-001"
        assert result["type"] == "Test"
        assert "indicators" in result
    
    def test_initialize_overwrites_existing_timeline(self):
        """Test that initialize ensures timeline is a list."""
        manager = TimelineManager()
        alert = {
            "alert_id": "test-001",
            "timeline": "not a list"
        }
        
        result = manager.initialize(alert)
        
        assert isinstance(result["timeline"], list)
    
    def test_initialize_non_dict_raises_error(self):
        """Test that non-dict alert raises ValueError."""
        manager = TimelineManager()
        
        with pytest.raises(ValueError, match="alert must be a dictionary"):
            manager.initialize("not a dict")
    
    def test_initialize_modifies_in_place(self):
        """Test that initialize modifies alert in place."""
        manager = TimelineManager()
        alert = {"alert_id": "test-001"}
        
        result = manager.initialize(alert)
        
        assert result is alert
        assert "timeline" in alert


class TestTimelineManagerAddEntry:
    """Test suite for add_entry() method."""
    
    def test_add_entry_appends_to_timeline(self):
        """Test that add_entry appends entry to timeline."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        result = manager.add_entry(alert, "ingest", "Alert loaded")
        
        assert len(result["timeline"]) == 1
        assert result["timeline"][0]["stage"] == "ingest"
        assert result["timeline"][0]["details"] == "Alert loaded"
    
    def test_add_entry_includes_timestamp(self):
        """Test that add_entry includes ISO timestamp."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        result = manager.add_entry(alert, "ingest", "Test entry")
        
        entry = result["timeline"][0]
        assert "ts" in entry
        assert isinstance(entry["ts"], str)
        # Check ISO format: 2025-12-10T10:00:00Z
        assert re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', entry["ts"])
    
    def test_add_entry_valid_stages(self):
        """Test adding entries for all valid stages."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        for stage in TIMELINE_STAGES:
            manager.add_entry(alert, stage, f"Test {stage}")
        
        assert len(alert["timeline"]) == len(TIMELINE_STAGES)
    
    def test_add_entry_invalid_stage_raises_error(self):
        """Test that invalid stage raises ValueError."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        with pytest.raises(ValueError, match="stage must be one of"):
            manager.add_entry(alert, "invalid_stage", "Test")
    
    def test_add_entry_empty_details_raises_error(self):
        """Test that empty details raises ValueError."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        with pytest.raises(ValueError, match="details must be a non-empty string"):
            manager.add_entry(alert, "ingest", "")
    
    def test_add_entry_whitespace_details_raises_error(self):
        """Test that whitespace-only details raises ValueError."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        with pytest.raises(ValueError, match="details must be a non-empty string"):
            manager.add_entry(alert, "ingest", "   ")
    
    def test_add_entry_non_string_details_raises_error(self):
        """Test that non-string details raises ValueError."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        with pytest.raises(ValueError, match="details must be a non-empty string"):
            manager.add_entry(alert, "ingest", 123)
    
    def test_add_entry_non_dict_alert_raises_error(self):
        """Test that non-dict alert raises ValueError."""
        manager = TimelineManager()
        
        with pytest.raises(ValueError, match="alert must be a dictionary"):
            manager.add_entry("not a dict", "ingest", "Test")
    
    def test_add_entry_creates_timeline_if_missing(self):
        """Test that add_entry creates timeline array if missing."""
        manager = TimelineManager()
        alert = {"alert_id": "test-001"}
        
        result = manager.add_entry(alert, "ingest", "Test")
        
        assert "timeline" in result
        assert isinstance(result["timeline"], list)
        assert len(result["timeline"]) == 1
    
    def test_add_entry_multiple_entries(self):
        """Test adding multiple entries to timeline."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        manager.add_entry(alert, "ingest", "Step 1")
        manager.add_entry(alert, "enrich", "Step 2")
        manager.add_entry(alert, "triage", "Step 3")
        
        assert len(alert["timeline"]) == 3
        assert alert["timeline"][0]["details"] == "Step 1"
        assert alert["timeline"][1]["details"] == "Step 2"
        assert alert["timeline"][2]["details"] == "Step 3"
    
    def test_add_entry_strips_whitespace(self):
        """Test that add_entry strips whitespace from details."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        result = manager.add_entry(alert, "ingest", "  Test entry  ")
        
        assert result["timeline"][0]["details"] == "Test entry"
    
    def test_add_entry_modifies_in_place(self):
        """Test that add_entry modifies alert in place."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        result = manager.add_entry(alert, "ingest", "Test")
        
        assert result is alert


class TestTimelineManagerValidate:
    """Test suite for validate() method."""
    
    def test_validate_valid_timeline(self):
        """Test that valid timeline passes validation."""
        manager = TimelineManager()
        alert = {
            "timeline": [
                {"stage": "ingest", "ts": "2025-12-10T10:00:00Z", "details": "Test"}
            ]
        }
        
        # Should not raise exception
        manager.validate(alert)
    
    def test_validate_missing_timeline_raises_error(self):
        """Test that missing timeline raises ValueError."""
        manager = TimelineManager()
        alert = {"alert_id": "test-001"}
        
        with pytest.raises(ValueError, match="timeline missing from alert"):
            manager.validate(alert)
    
    def test_validate_timeline_not_list_raises_error(self):
        """Test that non-list timeline raises ValueError."""
        manager = TimelineManager()
        alert = {"timeline": "not a list"}
        
        with pytest.raises(ValueError, match="timeline must be a list"):
            manager.validate(alert)
    
    def test_validate_entry_not_dict_raises_error(self):
        """Test that non-dict entry raises ValueError."""
        manager = TimelineManager()
        alert = {"timeline": ["string entry"]}
        
        with pytest.raises(ValueError, match="each timeline entry must be a dict"):
            manager.validate(alert)
    
    def test_validate_invalid_stage_raises_error(self):
        """Test that invalid stage raises ValueError."""
        manager = TimelineManager()
        alert = {
            "timeline": [
                {"stage": "invalid", "ts": "2025-12-10T10:00:00Z", "details": "Test"}
            ]
        }
        
        with pytest.raises(ValueError, match="timeline entry stage invalid"):
            manager.validate(alert)
    
    def test_validate_empty_timestamp_raises_error(self):
        """Test that empty timestamp raises ValueError."""
        manager = TimelineManager()
        alert = {
            "timeline": [
                {"stage": "ingest", "ts": "", "details": "Test"}
            ]
        }
        
        with pytest.raises(ValueError, match="timeline entry ts must be a non-empty string"):
            manager.validate(alert)
    
    def test_validate_empty_details_raises_error(self):
        """Test that empty details raises ValueError."""
        manager = TimelineManager()
        alert = {
            "timeline": [
                {"stage": "ingest", "ts": "2025-12-10T10:00:00Z", "details": ""}
            ]
        }
        
        with pytest.raises(ValueError, match="timeline entry details must be a non-empty string"):
            manager.validate(alert)
    
    def test_validate_empty_timeline(self):
        """Test that empty timeline is valid."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        # Should not raise exception
        manager.validate(alert)
    
    def test_validate_multiple_same_stage(self):
        """Test that multiple entries with same stage are valid."""
        manager = TimelineManager()
        alert = {
            "timeline": [
                {"stage": "ingest", "ts": "2025-12-10T10:00:00Z", "details": "Step 1"},
                {"stage": "ingest", "ts": "2025-12-10T10:01:00Z", "details": "Step 2"}
            ]
        }
        
        # Should not raise exception
        manager.validate(alert)


class TestTimelineManagerGet:
    """Test suite for get() method."""
    
    def test_get_returns_timeline_list(self):
        """Test that get returns timeline list."""
        manager = TimelineManager()
        alert = {
            "timeline": [
                {"stage": "ingest", "ts": "2025-12-10T10:00:00Z", "details": "Test"}
            ]
        }
        
        result = manager.get(alert)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["stage"] == "ingest"
    
    def test_get_returns_empty_for_missing_timeline(self):
        """Test that get returns empty list if timeline missing."""
        manager = TimelineManager()
        alert = {"alert_id": "test-001"}
        
        result = manager.get(alert)
        
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_get_returns_empty_for_non_dict_alert(self):
        """Test that get returns empty list for non-dict alert."""
        manager = TimelineManager()
        
        result = manager.get("not a dict")
        
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_get_returns_empty_for_non_list_timeline(self):
        """Test that get returns empty list if timeline is not list."""
        manager = TimelineManager()
        alert = {"timeline": "not a list"}
        
        result = manager.get(alert)
        
        assert isinstance(result, list)
        assert len(result) == 0


class TestTimelineStagesConstant:
    """Test suite for TIMELINE_STAGES constant."""
    
    def test_timeline_stages_is_set(self):
        """Test that TIMELINE_STAGES is a set."""
        assert isinstance(TIMELINE_STAGES, set)
    
    def test_timeline_stages_contains_expected_stages(self):
        """Test that TIMELINE_STAGES contains expected stages."""
        expected_stages = {"ingest", "normalize", "enrich", "triage", "respond"}
        assert expected_stages.issubset(TIMELINE_STAGES)
    
    def test_timeline_stages_not_empty(self):
        """Test that TIMELINE_STAGES is not empty."""
        assert len(TIMELINE_STAGES) > 0
    
    def test_timeline_stages_all_strings(self):
        """Test that all stages are strings."""
        for stage in TIMELINE_STAGES:
            assert isinstance(stage, str)


class TestTimelineManagerEdgeCases:
    """Test suite for edge cases in TimelineManager."""
    
    def test_timeline_manager_now_format(self):
        """Test that _now() returns proper ISO format."""
        manager = TimelineManager()
        timestamp = manager._now()
        
        assert isinstance(timestamp, str)
        assert re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', timestamp)
    
    def test_multiple_managers_independent(self):
        """Test that multiple TimelineManager instances are independent."""
        manager1 = TimelineManager()
        manager2 = TimelineManager()
        
        alert1 = {"timeline": []}
        alert2 = {"timeline": []}
        
        manager1.add_entry(alert1, "ingest", "Manager 1")
        manager2.add_entry(alert2, "enrich", "Manager 2")
        
        assert len(alert1["timeline"]) == 1
        assert len(alert2["timeline"]) == 1
        assert alert1["timeline"][0]["stage"] == "ingest"
        assert alert2["timeline"][0]["stage"] == "enrich"
    
    def test_add_entry_with_long_details(self):
        """Test adding entry with very long details."""
        manager = TimelineManager()
        alert = {"timeline": []}
        long_details = "A" * 1000
        
        result = manager.add_entry(alert, "ingest", long_details)
        
        assert result["timeline"][0]["details"] == long_details
    
    def test_add_entry_with_unicode_details(self):
        """Test adding entry with Unicode characters."""
        manager = TimelineManager()
        alert = {"timeline": []}
        
        result = manager.add_entry(alert, "ingest", "Unicode test: 测试 العربية 日本語")
        
        assert "Unicode test:" in result["timeline"][0]["details"]
