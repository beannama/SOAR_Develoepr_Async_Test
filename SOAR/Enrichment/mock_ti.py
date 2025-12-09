'''
Local Threat Intelligence

Purpose: Offline enrichment source.

Responsibilities:
- Store known bad IPs, domains, hashes    
- Maintain whitelist/suppression lists
- Provide confidence and MITRE hints

Why important:
- Demonstrates enrichment without external dependencies
- Safe for labs and interviews
'''

import os
import json
import yaml
from typing import Dict, List, Optional, Tuple, Any


class ConfigLoader:
    """
    Load and validate YAML configuration files.
    
    Responsibilities:
    - Load connectors.yml, allowlists.yml, mitre_map.yml
    - Validate YAML structure and schema
    - Provide safe access to configuration data
    - Handle missing/malformed configs gracefully
    """
    
    def __init__(self, config_dir: str) -> None:
        """
        Initialize ConfigLoader with path to configs directory.
        
        Args:
            config_dir: Path to SOAR/Enrichment/configs directory
            
        Raises:
            FileNotFoundError: If config_dir does not exist
            ValueError: If critical config files are missing
        """
        if not os.path.isdir(config_dir):
            raise FileNotFoundError(f"Config directory not found: {config_dir}")
        
        self.config_dir = config_dir
        self.connectors: Dict[str, Any] = {}
        self.allowlists: Dict[str, Any] = {}
        self.mitre_map: Dict[str, Any] = {}
        
        # Load all configurations
        self._load_configs()
    
    def _load_configs(self) -> None:
        """Load all configuration files."""
        self.connectors = self.load_connectors()
        self.allowlists = self.load_allowlists()
        self.mitre_map = self.load_mitre_map()
    
    def _safe_load_yaml(self, filepath: str, filename: str) -> dict:
        """
        Safely load a YAML file.
        
        Args:
            filepath: Full path to YAML file
            filename: Name of file (for error messages)
            
        Returns:
            Parsed YAML dict
            
        Raises:
            FileNotFoundError: If file doesn't exist
            yaml.YAMLError: If YAML is malformed
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"{filename} not found at {filepath}")
        
        try:
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
                if data is None:
                    data = {}
                return data
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Malformed YAML in {filename}: {str(e)}")
    
    def load_connectors(self) -> Dict[str, Any]:
        """
        Load and validate connectors.yml.
        
        Expected structure:
        {
            "providers": {
                "provider_name": {"base_url": "..."},
                ...
            },
            "edr": {"base_url": "..."}
        }
        
        Returns:
            Parsed connectors configuration
            
        Raises:
            ValueError: If required keys are missing
        """
        filepath = os.path.join(self.config_dir, "connectors.yml")
        data = self._safe_load_yaml(filepath, "connectors.yml")
        
        # Validate structure
        if "providers" not in data:
            raise ValueError("connectors.yml missing required key: 'providers'")
        
        if not isinstance(data["providers"], dict):
            raise ValueError("connectors.yml 'providers' must be a dictionary")
        
        # Validate each provider has base_url
        for provider_name, provider_config in data["providers"].items():
            if not isinstance(provider_config, dict):
                raise ValueError(f"Provider '{provider_name}' config must be a dictionary")
            if "base_url" not in provider_config:
                raise ValueError(f"Provider '{provider_name}' missing required key: 'base_url'")
        
        return data
    
    def load_allowlists(self) -> Dict[str, Any]:
        """
        Load and validate allowlists.yml.
        
        Expected structure:
        {
            "indicators": {
                "ipv4": [...],
                "domains": [...],
                "urls": [...],
                "sha256": [...]
            },
            "assets": {
                "device_ids": [...]
            }
        }
        
        Returns:
            Parsed allowlists configuration
            
        Raises:
            ValueError: If required keys are missing
        """
        filepath = os.path.join(self.config_dir, "allowlists.yml")
        data = self._safe_load_yaml(filepath, "allowlists.yml")
        
        # Validate structure
        if "indicators" not in data:
            raise ValueError("allowlists.yml missing required key: 'indicators'")
        
        if not isinstance(data["indicators"], dict):
            raise ValueError("allowlists.yml 'indicators' must be a dictionary")
        
        # Validate allowed IOC types
        valid_ioc_types = {"ipv4", "domains", "urls", "sha256"}
        for ioc_type in data["indicators"].keys():
            if ioc_type not in valid_ioc_types:
                raise ValueError(f"Invalid IOC type in allowlists: '{ioc_type}'. "
                               f"Must be one of: {valid_ioc_types}")
        
        # Validate each IOC type is a list
        for ioc_type, values in data["indicators"].items():
            if not isinstance(values, list):
                raise ValueError(f"Allowlist for '{ioc_type}' must be a list, got {type(values)}")
            # Ensure all values are strings
            if not all(isinstance(v, str) for v in values):
                raise ValueError(f"Allowlist for '{ioc_type}' contains non-string values")
        
        return data
    
    def load_mitre_map(self) -> Dict[str, Any]:
        """
        Load and validate mitre_map.yml.
        
        Expected structure:
        {
            "types": {
                "AlertType": ["T1234", "T5678"],
                ...
            },
            "defaults": ["T9999", ...]
        }
        
        Returns:
            Parsed MITRE mapping configuration
            
        Raises:
            ValueError: If required keys are missing
        """
        filepath = os.path.join(self.config_dir, "mitre_map.yml")
        data = self._safe_load_yaml(filepath, "mitre_map.yml")
        
        # Validate structure
        if "types" not in data:
            raise ValueError("mitre_map.yml missing required key: 'types'")
        if "defaults" not in data:
            raise ValueError("mitre_map.yml missing required key: 'defaults'")
        
        if not isinstance(data["types"], dict):
            raise ValueError("mitre_map.yml 'types' must be a dictionary")
        if not isinstance(data["defaults"], list):
            raise ValueError("mitre_map.yml 'defaults' must be a list")
        
        # Validate default techniques are strings
        if not all(isinstance(t, str) for t in data["defaults"]):
            raise ValueError("mitre_map.yml 'defaults' contains non-string values")
        
        # Validate each alert type maps to a list
        for alert_type, techniques in data["types"].items():
            if not isinstance(techniques, list):
                raise ValueError(f"MITRE techniques for '{alert_type}' must be a list")
            if not all(isinstance(t, str) for t in techniques):
                raise ValueError(f"MITRE techniques for '{alert_type}' contains non-string values")
        
        return data
    
    def get_providers(self) -> Dict[str, Dict[str, str]]:
        """Return the providers configuration."""
        return self.connectors.get("providers", {})
    
    def get_allowlists(self) -> Dict[str, List[str]]:
        """Return the indicators allowlist."""
        return self.allowlists.get("indicators", {})
    
    def get_mitre_types(self) -> Dict[str, List[str]]:
        """Return the MITRE types mapping."""
        return self.mitre_map.get("types", {})
    
    def get_mitre_defaults(self) -> List[str]:
        """Return the default MITRE techniques."""
        return self.mitre_map.get("defaults", [])


class AllowlistValidator:
    """
    Validate if IOCs are whitelisted.
    
    Responsibilities:
    - Check if IOC is in allowlist
    - Normalize IOC values for comparison (lowercase domains, strip whitespace)
    - Support multiple IOC types (ipv4, domains, urls, sha256)
    """
    
    def __init__(self, allowlist_data: Dict[str, List[str]]) -> None:
        """
        Initialize AllowlistValidator with allowlist data.
        
        Args:
            allowlist_data: Dict from ConfigLoader.get_allowlists()
                           Expected: {"ipv4": [...], "domains": [...], ...}
                           
        Raises:
            ValueError: If data structure is invalid
        """
        if not isinstance(allowlist_data, dict):
            raise ValueError("allowlist_data must be a dictionary")
        
        # Normalize all allowlist entries (lowercase and strip)
        self.allowlists: Dict[str, List[str]] = {}
        
        for ioc_type, values in allowlist_data.items():
            if not isinstance(values, list):
                raise ValueError(f"Allowlist for '{ioc_type}' must be a list")
            
            # Normalize each value based on IOC type
            normalized_values = [self._normalize_value(ioc_type, v) for v in values]
            self.allowlists[ioc_type] = normalized_values
    
    def _normalize_value(self, ioc_type: str, value: str) -> str:
        """
        Normalize IOC value based on type.
        
        Args:
            ioc_type: Type of IOC (ipv4, domains, urls, sha256)
            value: IOC value to normalize
            
        Returns:
            Normalized value
            
        Raises:
            ValueError: If value is not a string
        """
        if not isinstance(value, str):
            raise ValueError(f"IOC value must be string, got {type(value)}")
        
        value = value.strip()
        
        # Normalize based on IOC type
        if ioc_type == "domains":
            # Domains are case-insensitive, convert to lowercase
            return value.lower()
        elif ioc_type == "urls":
            # URLs are case-insensitive for domain part, lowercase full URL for comparison
            return value.lower()
        elif ioc_type == "ipv4":
            # IPs are already case-insensitive, just strip
            return value
        elif ioc_type == "sha256":
            # Hashes are case-insensitive, convert to lowercase
            return value.lower()
        else:
            # Unknown type, return as-is after strip
            return value
    
    def is_whitelisted(self, ioc_type: str, ioc_value: str) -> bool:
        """
        Check if an IOC is whitelisted.
        
        Args:
            ioc_type: Type of IOC (ipv4, domains, urls, sha256)
            ioc_value: IOC value to check
            
        Returns:
            True if whitelisted, False otherwise
            
        Raises:
            ValueError: If inputs are invalid
        """
        # Validate inputs
        if not isinstance(ioc_type, str):
            raise ValueError(f"ioc_type must be string, got {type(ioc_type)}")
        if not isinstance(ioc_value, str):
            raise ValueError(f"ioc_value must be string, got {type(ioc_value)}")
        
        # Check if IOC type is known
        if ioc_type not in self.allowlists:
            # Unknown IOC type - not whitelisted (erring on side of caution)
            return False
        
        # Normalize the input value
        normalized_value = self._normalize_value(ioc_type, ioc_value)
        
        # Check if normalized value is in allowlist
        return normalized_value in self.allowlists[ioc_type]
    
    def get_whitelisted_count(self) -> Dict[str, int]:
        """
        Get count of whitelisted IOCs by type.
        
        Returns:
            Dict mapping IOC type to count of whitelisted entries
        """
        return {ioc_type: len(values) for ioc_type, values in self.allowlists.items()}


class MitreMapper:
    """
    Map alert types to MITRE ATT&CK techniques.
    
    Responsibilities:
    - Map alert types to MITRE T-codes
    - Handle missing alert types with fallback to defaults
    - Validate MITRE mapping data
    """
    
    def __init__(self, mitre_types: Dict[str, List[str]], 
                 mitre_defaults: List[str]) -> None:
        """
        Initialize MitreMapper with MITRE mapping data.
        
        Args:
            mitre_types: Dict mapping alert types to T-codes
                        (from ConfigLoader.get_mitre_types())
            mitre_defaults: List of default T-codes if alert type not found
                           (from ConfigLoader.get_mitre_defaults())
                           
        Raises:
            ValueError: If data structure is invalid
        """
        if not isinstance(mitre_types, dict):
            raise ValueError("mitre_types must be a dictionary")
        if not isinstance(mitre_defaults, list):
            raise ValueError("mitre_defaults must be a list")
        
        # Validate all values are lists of strings
        for alert_type, techniques in mitre_types.items():
            if not isinstance(techniques, list):
                raise ValueError(f"Techniques for '{alert_type}' must be a list")
            if not all(isinstance(t, str) for t in techniques):
                raise ValueError(f"Techniques for '{alert_type}' contains non-string values")
        
        # Validate defaults are strings
        if not all(isinstance(t, str) for t in mitre_defaults):
            raise ValueError("mitre_defaults contains non-string values")
        
        if not mitre_defaults:
            raise ValueError("mitre_defaults cannot be empty")
        
        self.mitre_types = mitre_types
        self.mitre_defaults = mitre_defaults
    
    def get_techniques(self, alert_type: str) -> List[str]:
        """
        Get MITRE techniques for an alert type.
        
        Args:
            alert_type: Alert type from alert.type field
            
        Returns:
            List of MITRE T-codes for this alert type,
            or defaults if alert_type not found
            
        Raises:
            ValueError: If alert_type is not a string
        """
        if not isinstance(alert_type, str):
            raise ValueError(f"alert_type must be string, got {type(alert_type)}")
        
        # Return techniques for this alert type, or defaults if not found
        return self.mitre_types.get(alert_type, self.mitre_defaults)
    
    def get_all_alert_types(self) -> List[str]:
        """
        Get list of all known alert types in mapping.
        
        Returns:
            List of alert types
        """
        return list(self.mitre_types.keys())
    
    def get_default_techniques(self) -> List[str]:
        """
        Get default fallback MITRE techniques.
        
        Returns:
            List of default T-codes
        """
        return self.mitre_defaults.copy()


class MockTIIndex:
    """
    Index and query mock Threat Intelligence data from local JSON files.
    
    Responsibilities:
    - Discover and index IOC files from mocks/it/ directory
    - Parse filename format: {provider}_{ioc_type}_{ioc_value}.json
    - Validate file paths (prevent directory traversal)
    - Lazy-load JSON content on demand
    - Return normalized TI responses
    """
    
    def __init__(self, ti_dir: str) -> None:
        """
        Initialize MockTIIndex with path to TI directory.
        
        Args:
            ti_dir: Path to SOAR/Enrichment/mocks/it directory
            
        Raises:
            FileNotFoundError: If ti_dir does not exist
            ValueError: If ti_dir is not a directory
        """
        if not os.path.isdir(ti_dir):
            raise FileNotFoundError(f"TI directory not found: {ti_dir}")
        
        self.ti_dir = os.path.abspath(ti_dir)
        
        # In-memory index: {ioc_type: {ioc_value: [(provider, filepath), ...]}}
        self.index: Dict[str, Dict[str, List[Tuple[str, str]]]] = {}
        
        # Cache for loaded TI data: {filepath: parsed_json}
        self._cache: Dict[str, Dict[str, Any]] = {}
        
        # Discover and index all IOC files
        self._discover_and_index_files()
    
    def _discover_and_index_files(self) -> None:
        """
        Scan ti_dir for IOC files and build index.
        
        File naming convention: {provider}_{ioc_type}_{ioc_value}.json
        Examples:
        - anomali_ip_1.2.3.4.json
        - defender_ti_domain_bad.example.net.json
        - reversinglabs_sha256_7b1f4c2d16e0a0b43cbae2f9a9c2dd7e2bb3a0aaad6c0ad66b341f8b7deadbe0.json
        """
        if not os.path.isdir(self.ti_dir):
            return
        
        try:
            files = os.listdir(self.ti_dir)
        except OSError as e:
            raise ValueError(f"Cannot read TI directory: {str(e)}")
        
        for filename in files:
            if not filename.endswith('.json'):
                continue
            
            filepath = os.path.join(self.ti_dir, filename)
            
            # Security: Prevent symlink attacks
            if os.path.islink(filepath):
                continue
            
            # Security: Verify filepath is within ti_dir (prevent traversal)
            try:
                real_path = os.path.realpath(filepath)
                real_ti_dir = os.path.realpath(self.ti_dir)
                if not real_path.startswith(real_ti_dir):
                    continue
            except OSError:
                continue
            
            # Parse filename
            try:
                provider, ioc_type, ioc_value = self._parse_filename(filename)
            except ValueError:
                # Skip files that don't match naming convention
                continue
            
            # Add to index
            if ioc_type not in self.index:
                self.index[ioc_type] = {}
            
            if ioc_value not in self.index[ioc_type]:
                self.index[ioc_type][ioc_value] = []
            
            self.index[ioc_type][ioc_value].append((provider, filepath))
    
    def _parse_filename(self, filename: str) -> Tuple[str, str, str]:
        """
        Parse filename to extract provider, IOC type, and IOC value.
        
        Handles multiple filename formats:
        - {provider}_{ioc_type}_{ioc_value}.json  (e.g., anomali_ip_1.2.3.4.json)
        - {provider}_{qualifier}_{ioc_type}_{ioc_value}.json  (e.g., defender_ti_domain_bad.example.net.json)
        
        Args:
            filename: Filename to parse
            
        Returns:
            Tuple of (provider, normalized_ioc_type, ioc_value)
            
        Raises:
            ValueError: If filename doesn't match expected format
        """
        if not filename.endswith('.json'):
            raise ValueError("Filename must end with .json")
        
        # Remove .json extension
        name_without_ext = filename[:-5]
        
        # Split by underscores
        parts = name_without_ext.split('_')
        if len(parts) < 3:
            raise ValueError("Filename must have at least 3 parts separated by underscores")
        
        # Known qualifiers that appear between provider and IOC type
        qualifiers = {'ti'}
        # Mapping of known IOC type keywords
        ioc_type_keywords = {'ip', 'ipv4', 'domain', 'domains', 'url', 'urls', 'hash', 'sha256'}
        
        provider = parts[0]
        
        # Find the IOC type by scanning through parts, checking if it's a known IOC type
        # Strategy: Look for first occurrence of a known IOC type keyword
        ioc_type_raw = None
        ioc_value_start_idx = None
        
        for idx in range(1, len(parts)):
            if parts[idx].lower() in ioc_type_keywords:
                ioc_type_raw = parts[idx]
                ioc_value_start_idx = idx + 1
                break
        
        if ioc_type_raw is None or ioc_value_start_idx is None:
            raise ValueError(f"Cannot determine IOC type in filename: {filename}")
        
        if ioc_value_start_idx >= len(parts):
            raise ValueError(f"IOC value is missing in filename: {filename}")
        
        # Join remaining parts as IOC value (handles values with dots like domains and hashes)
        ioc_value = '_'.join(parts[ioc_value_start_idx:])
        
        if not ioc_value:
            raise ValueError("IOC value cannot be empty")
        
        # Normalize IOC type aliases to standard types
        ioc_type_mapping = {
            'ip': 'ipv4',
            'ipv4': 'ipv4',
            'domain': 'domains',
            'domains': 'domains',
            'url': 'urls',
            'urls': 'urls',
            'hash': 'sha256',
            'sha256': 'sha256'
        }
        
        # Map raw IOC type to standard type
        ioc_type = ioc_type_mapping.get(ioc_type_raw.lower(), ioc_type_raw)
        
        return provider, ioc_type, ioc_value
    
    def query(self, ioc_type: str, ioc_value: str) -> Optional[Dict[str, Any]]:
        """
        Query TI data for an IOC.
        
        Args:
            ioc_type: Type of IOC (ipv4, domains, urls, sha256)
            ioc_value: IOC value to query
            
        Returns:
            TI data dict if found, None if not found
            
        Raises:
            ValueError: If inputs are invalid
        """
        if not isinstance(ioc_type, str) or not isinstance(ioc_value, str):
            raise ValueError("ioc_type and ioc_value must be strings")
        
        ioc_value = ioc_value.strip()
        
        # Check if IOC type exists in index
        if ioc_type not in self.index:
            return None
        
        # Check if specific IOC value exists
        if ioc_value not in self.index[ioc_type]:
            return None
        
        # Get list of providers with data for this IOC
        provider_files = self.index[ioc_type][ioc_value]
        
        # Load and return data from first provider
        # (In future, could aggregate from multiple providers)
        for provider, filepath in provider_files:
            ti_data = self._load_ioc_file(filepath)
            if ti_data:
                # Add metadata about provider
                ti_data['provider'] = provider
                ti_data['ioc_type'] = ioc_type
                ti_data['ioc_value'] = ioc_value
                return ti_data
        
        return None
    
    def _load_ioc_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Load and parse TI JSON file (with caching).
        
        Args:
            filepath: Full path to JSON file
            
        Returns:
            Parsed JSON dict, or None if parsing fails
        """
        # Check cache first
        if filepath in self._cache:
            return self._cache[filepath]
        
        try:
            # Security: Verify filepath is within ti_dir
            real_path = os.path.realpath(filepath)
            real_ti_dir = os.path.realpath(self.ti_dir)
            if not real_path.startswith(real_ti_dir):
                return None
            
            # Check file size (prevent loading huge files)
            file_size = os.path.getsize(filepath)
            max_size = 10 * 1024 * 1024  # 10MB limit
            if file_size > max_size:
                return None
            
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Cache the result
            self._cache[filepath] = data
            
            return data
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            # File not found, not readable, or invalid JSON
            return None
    
    def get_indexed_iocs(self) -> Dict[str, Dict[str, int]]:
        """
        Get summary of indexed IOCs.
        
        Returns:
            Dict mapping IOC type to count of indexed values
        """
        return {
            ioc_type: len(values)
            for ioc_type, values in self.index.items()
        }
    
    def has_ioc(self, ioc_type: str, ioc_value: str) -> bool:
        """
        Check if an IOC is indexed.
        
        Args:
            ioc_type: Type of IOC
            ioc_value: IOC value
            
        Returns:
            True if IOC is indexed, False otherwise
        """
        return (ioc_type in self.index and 
                ioc_value in self.index[ioc_type])


class MockTI:
    """
    Main TI orchestrator - integrates all components.
    
    Responsibilities:
    - Load all configurations
    - Orchestrate queries across validators, mappers, and index
    - Provide normalized enrichment responses
    - Handle whitelisting, MITRE mapping, and TI lookups
    """
    
    def __init__(self, config_dir: str, ti_dir: str) -> None:
        """
        Initialize MockTI with configuration and TI data directories.
        
        Args:
            config_dir: Path to SOAR/Enrichment/configs directory
            ti_dir: Path to SOAR/Enrichment/mocks/it directory
            
        Raises:
            FileNotFoundError: If directories don't exist
            ValueError: If configuration is invalid
        """
        # Load configurations
        self.config_loader = ConfigLoader(config_dir)
        
        # Initialize validators and mappers
        self.allowlist = AllowlistValidator(self.config_loader.get_allowlists())
        self.mitre = MitreMapper(
            self.config_loader.get_mitre_types(),
            self.config_loader.get_mitre_defaults()
        )
        
        # Initialize TI index
        self.ti_index = MockTIIndex(ti_dir)
    
    def query_ioc(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """
        Query an IOC and return enriched TI data.
        
        Workflow:
        1. Validate inputs
        2. Check if whitelisted
        3. Query TI index
        4. Return normalized response
        
        Args:
            ioc_type: Type of IOC (ipv4, domains, urls, sha256)
            ioc_value: IOC value to query
            
        Returns:
            Dict with enrichment data:
            {
                "ioc_type": str,
                "ioc_value": str,
                "whitelisted": bool,
                "found": bool,
                "threat_level": str,  # "malicious", "suspicious", "clean", "unknown"
                "provider": str or None,
                "confidence": float or None,
                "source": str,  # "whitelist", "ti_data", "not_found"
                "raw_ti": dict or None  # Raw TI data from provider
            }
            
        Raises:
            ValueError: If inputs are invalid
        """
        # Validate inputs
        if not isinstance(ioc_type, str) or not isinstance(ioc_value, str):
            raise ValueError("ioc_type and ioc_value must be strings")
        
        ioc_value = ioc_value.strip()
        
        if not ioc_value:
            raise ValueError("ioc_value cannot be empty")
        
        # Initialize response
        response: Dict[str, Any] = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "whitelisted": False,
            "found": False,
            "threat_level": "unknown",
            "provider": None,
            "confidence": None,
            "source": None,
            "raw_ti": None
        }
        
        # Check if whitelisted
        if self.allowlist.is_whitelisted(ioc_type, ioc_value):
            response["whitelisted"] = True
            response["threat_level"] = "clean"
            response["source"] = "whitelist"
            return response
        
        # Query TI index
        ti_data = self.ti_index.query(ioc_type, ioc_value)
        
        if ti_data:
            response["found"] = True
            response["source"] = "ti_data"
            response["raw_ti"] = ti_data
            response["provider"] = ti_data.get("provider")
            
            # Determine threat level based on TI data
            response["threat_level"] = self._determine_threat_level(ti_data)
            
            # Extract confidence if available
            if "confidence" in ti_data:
                response["confidence"] = ti_data["confidence"]
            elif "score" in ti_data:
                response["confidence"] = ti_data["score"]
        else:
            response["source"] = "not_found"
        
        return response
    
    def _determine_threat_level(self, ti_data: Dict[str, Any]) -> str:
        """
        Determine threat level from TI data.
        
        Args:
            ti_data: TI data dict from query
            
        Returns:
            Threat level: "malicious", "suspicious", "clean", "unknown"
        """
        # Check for explicit reputation/classification
        reputation = ti_data.get("reputation", "").lower()
        classification = ti_data.get("classification", "").lower()
        risk = ti_data.get("risk", "").lower()
        
        if reputation == "malicious" or classification == "malicious":
            return "malicious"
        if reputation == "suspicious" or risk == "suspicious":
            return "suspicious"
        
        # Check confidence/score thresholds
        confidence = ti_data.get("confidence", 0)
        score = ti_data.get("score", 0)
        
        # Treat as confidence score (0-100)
        max_score = max(confidence, score)
        
        if max_score >= 80:
            return "malicious"
        elif max_score >= 50:
            return "suspicious"
        
        return "clean"

    def get_mitre_techniques(self, alert_type: str) -> List[str]:
        """Public helper to resolve MITRE techniques for an alert type."""
        if not isinstance(alert_type, str):
            raise ValueError("alert_type must be a string")
        return self.mitre.get_techniques(alert_type)
    


