'''
Local Threat Intelligence

Purpose: Offline enrichment source.

Responsibilities:
- Store known bad IPs, domains, hashes    
- Maintain whitelist/suppression lists
- Provide confidence

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
    - Load connectors.yml
    - Validate YAML structure and schema
    - Provide safe access to configuration data
    - Handle missing/malformed configs gracefully
    """
    
    def __init__(self, config_dir: str) -> None:
        """
        Initialize ConfigLoader with path to configs directory.
        
        Args:
            config_dir: Path to SOAR/configs directory
            
        Raises:
            FileNotFoundError: If config_dir does not exist
            ValueError: If critical config files are missing
        """
        if not os.path.isdir(config_dir):
            raise FileNotFoundError(f"Config directory not found: {config_dir}")
        
        self.config_dir = config_dir
        self.connectors: Dict[str, Any] = {}
        
        # Load all configurations
        self._load_configs()
    
    def _load_configs(self) -> None:
        """Load all configuration files."""
        self.connectors = self.load_connectors()
    
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
    
    def get_providers(self) -> Dict[str, Dict[str, str]]:
        """Return the providers configuration."""
        return self.connectors.get("providers", {})
    


class RiskMerger:
    """
    Merge TI results from multiple providers into unified risk assessment.
    
    Responsibilities:
    - Normalize provider-specific fields (confidence/score/reputation)
    - Determine consensus verdict (malicious/suspicious/clean/unknown)
    - Calculate weighted risk score (0-100)
    - Track which providers contributed
    """
    
    # Verdict priority for consensus (higher = more severe)
    VERDICT_PRIORITY = {
        "malicious": 4,
        "suspicious": 3,
        "clean": 2,
        "unknown": 1
    }
    
    def __init__(self) -> None:
        """Initialize RiskMerger."""
        pass
    
    def merge(self, ti_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Merge TI results from multiple providers into unified risk assessment.
        
        Args:
            ti_results: List of TI data dicts from different providers
                       Each dict should have been loaded from a provider JSON file
        
        Returns:
            {
                "verdict": "malicious|suspicious|clean|unknown",
                "score": 0-100,
                "sources": ["defender_ti", "anomali", ...],
                "provider_details": [
                    {"provider": "defender_ti", "verdict": "malicious", "score": 92},
                    ...
                ]
            }
        
        Raises:
            ValueError: If ti_results is not a list or is empty
        """
        if not isinstance(ti_results, list):
            raise ValueError("ti_results must be a list")
        
        if not ti_results:
            # No providers found - return unknown
            return {
                "verdict": "unknown",
                "score": 0,
                "sources": [],
                "provider_details": []
            }
        
        provider_details: List[Dict[str, Any]] = []
        sources: List[str] = []
        max_score = 0
        consensus_verdict = "unknown"
        
        for ti_data in ti_results:
            if not isinstance(ti_data, dict):
                continue
            
            # Normalize provider data
            normalized = self._normalize_provider_data(ti_data)
            
            provider_name = normalized["provider"]
            verdict = normalized["verdict"]
            score = normalized["score"]
            
            # Track provider details
            provider_details.append({
                "provider": provider_name,
                "verdict": verdict,
                "score": score
            })
            
            sources.append(provider_name)
            
            # Update max score
            if score > max_score:
                max_score = score
            
            # Update consensus verdict (most severe wins)
            if self.VERDICT_PRIORITY.get(verdict, 0) > self.VERDICT_PRIORITY.get(consensus_verdict, 0):
                consensus_verdict = verdict
        
        return {
            "verdict": consensus_verdict,
            "score": max_score,
            "sources": sources,
            "provider_details": provider_details
        }
    
    def _normalize_provider_data(self, ti_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize provider-specific fields to standard format.
        
        Args:
            ti_data: Raw TI data from provider JSON file
        
        Returns:
            {
                "provider": str,
                "verdict": "malicious|suspicious|clean|unknown",
                "score": 0-100
            }
        
        Raises:
            ValueError: If required fields are missing
        """
        if not isinstance(ti_data, dict):
            raise ValueError("ti_data must be a dictionary")
        
        # Extract provider name
        provider = ti_data.get("provider", "unknown")
        if not isinstance(provider, str):
            provider = "unknown"
        
        # Normalize verdict from various field names
        verdict = self._extract_verdict(ti_data)
        
        # Normalize score from various field names
        score = self._extract_score(ti_data)
        
        return {
            "provider": provider,
            "verdict": verdict,
            "score": score
        }
    
    def _extract_verdict(self, ti_data: Dict[str, Any]) -> str:
        """
        Extract and normalize verdict from provider data.
        
        Provider field mappings:
        - Anomali: "risk" field
        - Defender TI: "reputation" field
        - ReversingLabs: "classification" field
        
        Args:
            ti_data: Raw TI data
        
        Returns:
            Normalized verdict: "malicious", "suspicious", "clean", or "unknown"
        """
        # Check common verdict field names
        verdict_fields = ["risk", "reputation", "classification", "verdict", "threat_level"]
        
        for field in verdict_fields:
            if field in ti_data:
                raw_verdict = ti_data[field]
                if isinstance(raw_verdict, str):
                    raw_verdict_lower = raw_verdict.lower().strip()
                    
                    # Map to standard verdicts
                    if raw_verdict_lower in ["malicious", "malware", "threat", "bad"]:
                        return "malicious"
                    elif raw_verdict_lower in ["suspicious", "medium", "moderate"]:
                        return "suspicious"
                    elif raw_verdict_lower in ["clean", "benign", "safe", "good"]:
                        return "clean"
        
        # Fallback: infer from score if available
        score = self._extract_score(ti_data)
        if score >= 80:
            return "malicious"
        elif score >= 50:
            return "suspicious"
        elif score > 0:
            return "clean"
        
        return "unknown"
    
    def _extract_score(self, ti_data: Dict[str, Any]) -> int:
        """
        Extract and normalize score from provider data.
        
        Provider field mappings:
        - Anomali: "confidence" field
        - Defender TI: "score" field
        - ReversingLabs: "score" field
        
        Args:
            ti_data: Raw TI data
        
        Returns:
            Normalized score (0-100)
        """
        # Check common score field names
        score_fields = ["score", "confidence", "risk_score", "threat_score"]
        
        for field in score_fields:
            if field in ti_data:
                raw_score = ti_data[field]
                
                # Convert to integer if possible
                try:
                    if isinstance(raw_score, (int, float)):
                        score = int(raw_score)
                        # Ensure 0-100 range
                        return max(0, min(100, score))
                    elif isinstance(raw_score, str):
                        score = int(float(raw_score))
                        return max(0, min(100, score))
                except (ValueError, TypeError):
                    continue
        
        # No score found - return default based on verdict
        verdict = self._extract_verdict(ti_data)
        if verdict == "malicious":
            return 90
        elif verdict == "suspicious":
            return 60
        elif verdict == "clean":
            return 10
        
        return 0


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
    
    def query_all_providers(self, ioc_type: str, ioc_value: str) -> List[Dict[str, Any]]:
        """
        Query TI data from ALL providers for an IOC.
        
        Args:
            ioc_type: Type of IOC (ipv4, domains, urls, sha256)
            ioc_value: IOC value to query
            
        Returns:
            List of TI data dicts from all providers (empty list if none found)
            
        Raises:
            ValueError: If inputs are invalid
        """
        if not isinstance(ioc_type, str) or not isinstance(ioc_value, str):
            raise ValueError("ioc_type and ioc_value must be strings")
        
        ioc_value = ioc_value.strip()
        
        # Check if IOC type exists in index
        if ioc_type not in self.index:
            return []
        
        # Check if specific IOC value exists
        if ioc_value not in self.index[ioc_type]:
            return []
        
        # Get list of providers with data for this IOC
        provider_files = self.index[ioc_type][ioc_value]
        
        # Load data from ALL providers
        ti_results: List[Dict[str, Any]] = []
        for provider, filepath in provider_files:
            ti_data = self._load_ioc_file(filepath)
            if ti_data:
                # Add metadata about provider
                ti_data['provider'] = provider
                ti_data['ioc_type'] = ioc_type
                ti_data['ioc_value'] = ioc_value
                ti_results.append(ti_data)
        
        return ti_results
    
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
    - Handle TI lookups
    """
    
    def __init__(self, config_dir: str, ti_dir: str) -> None:
        """
        Initialize MockTI with configuration and TI data directories.
        
        Args:
            config_dir: Path to SOAR/configs directory
            ti_dir: Path to SOAR/Enrichment/mocks/it directory
            
        Raises:
            FileNotFoundError: If directories don't exist
            ValueError: If configuration is invalid
        """
        # Load configurations
        self.config_loader = ConfigLoader(config_dir)
        
        # Initialize TI index and risk merger
        self.ti_index = MockTIIndex(ti_dir)
        self.risk_merger = RiskMerger()
    
    def query_ioc(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """
        Query an IOC and return enriched TI data from multiple providers.
        
        Workflow:
        1. Validate inputs
        2. Query all providers from TI index
        3. Merge risk assessments using RiskMerger
        4. Return normalized response

        This stage focuses solely on threat intelligence enrichment.
        
        Args:
            ioc_type: Type of IOC (ipv4, domains, urls, sha256)
            ioc_value: IOC value to query
            
        Returns:
            Dict with enrichment data:
            {
                "ioc_type": str,
                "ioc_value": str,
                "found": bool,
                "source": str,  # "ti_data" or "not_found"
                "risk": {  # Merged risk from all providers
                    "verdict": "malicious|suspicious|clean|unknown",
                    "score": 0-100,
                    "sources": ["defender_ti", "anomali", ...],
                    "provider_details": [...]
                }
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
            "found": False,
            "source": None,
            "risk": {
                "verdict": "unknown",
                "score": 0,
                "sources": [],
                "provider_details": []
            }
        }
        
        # Query ALL providers from TI index
        ti_results = self.ti_index.query_all_providers(ioc_type, ioc_value)
        
        if ti_results:
            response["found"] = True
            response["source"] = "ti_data"
            
            # Merge risk assessments from all providers
            merged_risk = self.risk_merger.merge(ti_results)
            response["risk"] = merged_risk
        else:
            response["source"] = "not_found"
        
        return response

    
    


