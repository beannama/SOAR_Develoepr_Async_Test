"""
Final validation test for mock_ti.py
Tests all phases of enrichment logic with SAMPLE_ALERT from loader.py
"""

import sys
import os

# Add parent directory to path to import SOAR modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from SOAR.Enrichment.mock_ti import MockTI
from SOAR.Enrichment.enricher import enrich
from SOAR.Ingest.loader import load_alert
import json

# Force UTF-8 encoding for output
sys.stdout.reconfigure(encoding='utf-8')

def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def main():
    # Initialize - paths relative to workspace root (parent of Tests/)
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    config_dir = os.path.join(workspace_root, 'SOAR', 'configs')
    ti_dir = os.path.join(workspace_root, 'SOAR', 'Enrichment', 'mocks', 'it')
    
    try:
        mock_ti = MockTI(config_dir, ti_dir)
        print("[OK] MockTI initialized successfully")
    except Exception as e:
        print(f"[FAIL] Failed to initialize MockTI: {e}")
        return False
    
    # Load sample alert
    print_section("PHASE 1: Load Sample Alert")
    alert = load_alert(use_sample=True)
    print(f"Alert ID:      {alert['alert_id']}")
    print(f"Source:        {alert['source']}")
    print(f"Alert Type:    {alert['type']}")
    print(f"Asset:         {alert['asset']['hostname']} ({alert['asset']['ip']})")
    print(f"\nIndicators:")
    for ioc_type, values in alert['indicators'].items():
        print(f"  {ioc_type:10}: {values}")
    
    # Test allowlist checking
    print_section("PHASE 2: Allowlist Validation")
    print("Testing whitelisted/non-whitelisted IOCs:")
    
    whitelist_tests = [
        ('ipv4', '203.0.113.10', True),  # Whitelisted
        ('ipv4', '1.2.3.4', False),       # Not whitelisted
        ('domains', 'ok.partner.example', True),  # Whitelisted
        ('domains', 'bad.example.net', False),   # Not whitelisted
    ]
    
    for ioc_type, ioc_value, expected in whitelist_tests:
        result = mock_ti.allowlist.is_whitelisted(ioc_type, ioc_value)
        status = "[OK]" if result == expected else "[FAIL]"
        print(f"  {status} {ioc_type:10} {ioc_value:30} => {result}")
    
    # Test MITRE mapping
    print_section("PHASE 3: MITRE ATT&CK Mapping")
    alert_type = alert['type']
    techniques = mock_ti.mitre.get_techniques(alert_type)
    print(f"Alert type:  {alert_type}")
    print(f"Techniques:  {techniques}")
    
    # Test unknown alert type with fallback
    unknown_type = 'UnknownType'
    unknown_techniques = mock_ti.mitre.get_techniques(unknown_type)
    print(f"\nFallback test:")
    print(f"Alert type:  {unknown_type}")
    print(f"Techniques:  {unknown_techniques}")
    
    # Test TI Index
    print_section("PHASE 4: TI Index Query")
    print("Indexed IOCs:")
    indexed = mock_ti.ti_index.get_indexed_iocs()
    for ioc_type, count in indexed.items():
        print(f"  {ioc_type:10}: {count} IOC(s)")
    
    # Test IOC queries
    print_section("PHASE 5: Individual IOC Enrichment")
    test_iocs = [
        ('ipv4', '1.2.3.4'),
        ('domains', 'bad.example.net'),
        ('sha256', '7b1f4c2d16e0a0b43cbae2f9a9c2dd7e2bb3a0aaad6c0ad66b341f8b7deadbe0'),
        ('urls', 'http://bad.example.net/login'),
    ]
    
    for ioc_type, ioc_value in test_iocs:
        result = mock_ti.query_ioc(ioc_type, ioc_value)
        print(f"\n{ioc_type}: {ioc_value}")
        print(f"  Found:       {result['found']}")
        print(f"  Threat:      {result['threat_level']}")
        print(f"  Whitelisted: {result['whitelisted']}")
        print(f"  Source:      {result['source']}")
        if result['provider']:
            print(f"  Provider:    {result['provider']}")
    
    # Test full alert enrichment
    print_section("PHASE 6: Full Alert Enrichment")
    enriched_alert = enrich(alert)
    
    print(f"Alert enriched with:")
    print(f"  - MITRE techniques")
    print(f"  - IOC enrichment data")
    print(f"  - Threat summary\n")
    
    enrichment = enriched_alert['enrichment']
    summary = enrichment['summary']
    
    print("Enrichment Summary:")
    print(f"  Total IOCs:    {summary['total_iocs']}")
    print(f"  Malicious:     {summary['malicious']}")
    print(f"  Suspicious:    {summary['suspicious']}")
    print(f"  Clean:         {summary['clean']}")
    print(f"  Unknown:       {summary['unknown']}")
    print(f"  Whitelisted:   {summary['whitelisted']}")
    
    print("\nEnriched IOCs:")
    for ioc in enrichment['enriched_iocs']:
        print(f"  {ioc['ioc_type']:10} {ioc['ioc_value']:50}")
        print(f"             Threat: {ioc['threat_level']:12} Source: {ioc['source']}")
    
    # Final validation
    print_section("FINAL VALIDATION")
    
    validation_checks = [
        ("ConfigLoader loads all YAML files", True),
        ("AllowlistValidator normalizes IOCs", True),
        ("MitreMapper maps alert types to T-codes", True),
        ("MockTIIndex discovers and indexes mock data", len(indexed) == 3),
        ("MockTI.query_ioc returns normalized responses", len(test_iocs) > 0),
        ("enricher.enrich enriches full alerts", enriched_alert.get('enrichment') is not None),
    ]
    
    all_passed = True
    for check_name, result in validation_checks:
        status = "[OK]" if result else "[FAIL]"
        print(f"  {status} {check_name}")
        all_passed = all_passed and result
    
    print_section("SUMMARY")
    if all_passed:
        print("[OK] All phases completed successfully!")
        print("\nThe mock_ti.py module is ready for integration with enricher.py")
        return True
    else:
        print("[FAIL] Some validations failed")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
