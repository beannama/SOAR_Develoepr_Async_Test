'''
Triage Rules Engine

Purpose: Deterministic rule evaluation for alert triage.

Components:
- TriageConfigLoader: Load and validate triage configuration
- SuppressionEngine: Evaluate suppression rules
- SeverityScorer: Calculate deterministic severity scores
- TagGenerator: Generate alert tags based on rules
'''

import os
import yaml
from typing import Dict, List, Any, Optional, Tuple


class TriageConfigLoader:
    """Load and validate triage configuration from YAML."""
    
    def __init__(self, config_path: str) -> None:
        """
        Initialize TriageConfigLoader.
        
        Args:
            config_path: Path to config.yml file
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If YAML is malformed
            ValueError: If config structure is invalid
        """
        if not os.path.isfile(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        self.config_path = config_path
        self.config = self._load_and_validate()
    
    def _load_and_validate(self) -> Dict[str, Any]:
        """Load config file and validate structure."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Malformed YAML in config: {str(e)}")
        
        if config is None:
            raise ValueError("Config file is empty")
        
        # Validate required top-level keys
        required_keys = ["severity", "tags", "suppression", "prioritization"]
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required config key: '{key}'")
        
        # Validate severity structure
        self._validate_severity(config["severity"])
        
        # Validate suppression structure
        self._validate_suppression(config["suppression"])
        
        # Validate prioritization structure
        self._validate_prioritization(config["prioritization"])
        
        return config
    
    def _validate_severity(self, severity: Dict[str, Any]) -> None:
        """Validate severity configuration."""
        if "weights" not in severity:
            raise ValueError("severity.weights is required")
        
        weights = severity["weights"]
        required_weights = ["malicious", "suspicious", "unknown", "clean", "whitelisted"]
        for weight in required_weights:
            if weight not in weights:
                raise ValueError(f"Missing severity weight: '{weight}'")
            if not isinstance(weights[weight], (int, float)) or weights[weight] < 0:
                raise ValueError(f"Invalid weight for '{weight}': must be non-negative number")
        
        if "multipliers" not in severity:
            raise ValueError("severity.multipliers is required")
        
        if "max_score" not in severity:
            raise ValueError("severity.max_score is required")
        
        if not isinstance(severity["max_score"], int) or severity["max_score"] <= 0:
            raise ValueError("severity.max_score must be positive integer")
    
    def _validate_suppression(self, suppression: Dict[str, Any]) -> None:
        """Validate suppression rules."""
        if "rules" not in suppression:
            raise ValueError("suppression.rules is required")
        
        if not isinstance(suppression["rules"], list):
            raise ValueError("suppression.rules must be a list")
        
        for rule in suppression["rules"]:
            if not isinstance(rule, dict):
                raise ValueError("Each suppression rule must be a dictionary")
            if "name" not in rule or "condition" not in rule or "reason" not in rule:
                raise ValueError("Suppression rule must have 'name', 'condition', and 'reason'")
    
    def _validate_prioritization(self, prioritization: Dict[str, Any]) -> None:
        """Validate priority thresholds."""
        required_priorities = ["critical", "high", "medium", "low", "informational"]
        for priority in required_priorities:
            if priority not in prioritization:
                raise ValueError(f"Missing priority level: '{priority}'")
            
            level = prioritization[priority]
            if "min" not in level or "max" not in level:
                raise ValueError(f"Priority '{priority}' must have 'min' and 'max' fields")
    
    def get_severity_weights(self) -> Dict[str, float]:
        """Get severity weights."""
        return self.config["severity"]["weights"]
    
    def get_alert_type_multiplier(self, alert_type: str) -> float:
        """Get multiplier for alert type."""
        multipliers = self.config["severity"]["multipliers"]["alert_types"]
        return multipliers.get(alert_type, multipliers.get("default", 1.0))
    
    def get_max_score(self) -> int:
        """Get maximum severity score."""
        return self.config["severity"]["max_score"]
    
    def get_suppression_rules(self) -> List[Dict[str, str]]:
        """Get suppression rules."""
        return self.config["suppression"]["rules"]
    
    def get_alert_type_tags(self, alert_type: str) -> List[str]:
        """Get tags for alert type."""
        by_type = self.config["tags"].get("by_alert_type", {})
        return by_type.get(alert_type, [])
    
    def get_threat_distribution_rules(self) -> List[Dict[str, Any]]:
        """Get threat distribution tagging rules."""
        return self.config["tags"].get("by_threat_distribution", [])
    
    def get_priority_for_score(self, score: int) -> str:
        """Determine priority level based on severity score."""
        priorities = self.config["prioritization"]
        
        for priority_name, thresholds in priorities.items():
            if thresholds["min"] <= score <= thresholds["max"]:
                return priority_name
        
        # Default to informational if no match
        return "informational"


class SuppressionEngine:
    """Evaluate suppression rules on enriched alerts."""
    
    def __init__(self, config_loader: TriageConfigLoader) -> None:
        """
        Initialize SuppressionEngine.
        
        Args:
            config_loader: Loaded triage configuration
        """
        self.rules = config_loader.get_suppression_rules()
    
    def evaluate(self, summary: Dict[str, int]) -> Tuple[bool, Optional[str]]:
        """
        Evaluate suppression rules.
        
        Args:
            summary: Enrichment summary with IOC counts
            
        Returns:
            Tuple of (suppressed: bool, reason: Optional[str])
        """
        total_iocs = summary.get("total_iocs", 0)
        whitelisted = summary.get("whitelisted", 0)
        clean = summary.get("clean", 0)
        
        # Evaluate each rule in order
        for rule in self.rules:
            condition = rule["condition"]
            
            # Parse and evaluate condition
            if self._evaluate_condition(condition, summary):
                return True, rule["reason"]
        
        return False, None
    
    def _evaluate_condition(self, condition: str, summary: Dict[str, int]) -> bool:
        """
        Evaluate a suppression condition.
        
        Args:
            condition: Condition string (e.g., "whitelisted == total_iocs")
            summary: Enrichment summary
            
        Returns:
            True if condition matches
        """
        # Extract values from summary
        total_iocs = summary.get("total_iocs", 0)
        malicious = summary.get("malicious", 0)
        suspicious = summary.get("suspicious", 0)
        clean = summary.get("clean", 0)
        whitelisted = summary.get("whitelisted", 0)
        unknown = summary.get("unknown", 0)
        
        # Safe evaluation with limited scope
        try:
            # Create safe evaluation context
            context = {
                "total_iocs": total_iocs,
                "malicious": malicious,
                "suspicious": suspicious,
                "clean": clean,
                "whitelisted": whitelisted,
                "unknown": unknown
            }
            
            # Evaluate condition
            return eval(condition, {"__builtins__": {}}, context)
        except Exception:
            # If evaluation fails, don't suppress
            return False


class SeverityScorer:
    """Calculate deterministic severity scores."""
    
    def __init__(self, config_loader: TriageConfigLoader) -> None:
        """
        Initialize SeverityScorer.
        
        Args:
            config_loader: Loaded triage configuration
        """
        self.weights = config_loader.get_severity_weights()
        self.config_loader = config_loader
    
    def calculate(self, summary: Dict[str, int], alert_type: str) -> Dict[str, Any]:
        """
        Calculate severity score.
        
        Args:
            summary: Enrichment summary with IOC counts
            alert_type: Alert type for multiplier lookup
            
        Returns:
            Dict with score and calculation details
        """
        # Calculate base score
        base_score = (
            summary.get("malicious", 0) * self.weights["malicious"] +
            summary.get("suspicious", 0) * self.weights["suspicious"] +
            summary.get("unknown", 0) * self.weights["unknown"] +
            summary.get("clean", 0) * self.weights["clean"] +
            summary.get("whitelisted", 0) * self.weights["whitelisted"]
        )
        
        # Get alert type multiplier
        multiplier = self.config_loader.get_alert_type_multiplier(alert_type)
        
        # Apply multiplier
        adjusted_score = base_score * multiplier
        
        # Cap at maximum
        max_score = self.config_loader.get_max_score()
        final_score = min(int(adjusted_score), max_score)
        
        return {
            "severity_score": final_score,
            "scoring_details": {
                "base_score": int(base_score),
                "alert_type": alert_type,
                "multiplier": multiplier,
                "adjusted_score": int(adjusted_score),
                "capped_at": max_score
            }
        }


class TagGenerator:
    """Generate alert tags based on rules."""
    
    def __init__(self, config_loader: TriageConfigLoader) -> None:
        """
        Initialize TagGenerator.
        
        Args:
            config_loader: Loaded triage configuration
        """
        self.config_loader = config_loader
    
    def generate(self, alert_type: str, summary: Dict[str, int]) -> List[str]:
        """
        Generate tags for alert.
        
        Args:
            alert_type: Alert type
            summary: Enrichment summary
            
        Returns:
            List of tags
        """
        tags = []
        
        # Add alert type-based tags
        type_tags = self.config_loader.get_alert_type_tags(alert_type)
        tags.extend(type_tags)
        
        # Add threat distribution-based tags
        distribution_rules = self.config_loader.get_threat_distribution_rules()
        for rule in distribution_rules:
            condition = rule.get("condition", "")
            rule_tags = rule.get("tags", [])
            
            if self._evaluate_condition(condition, summary):
                tags.extend(rule_tags)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_tags = []
        for tag in tags:
            if tag not in seen:
                seen.add(tag)
                unique_tags.append(tag)
        
        return unique_tags
    
    def _evaluate_condition(self, condition: str, summary: Dict[str, int]) -> bool:
        """
        Evaluate a tag condition.
        
        Args:
            condition: Condition string
            summary: Enrichment summary
            
        Returns:
            True if condition matches
        """
        # Extract values
        malicious = summary.get("malicious", 0)
        suspicious = summary.get("suspicious", 0)
        clean = summary.get("clean", 0)
        whitelisted = summary.get("whitelisted", 0)
        unknown = summary.get("unknown", 0)
        total_iocs = summary.get("total_iocs", 0)
        
        try:
            context = {
                "malicious": malicious,
                "suspicious": suspicious,
                "clean": clean,
                "whitelisted": whitelisted,
                "unknown": unknown,
                "total_iocs": total_iocs
            }
            
            return eval(condition, {"__builtins__": {}}, context)
        except Exception:
            return False
