"""Test MITRE mapping with various alert types."""

import sys
import os

# Add parent directory to path to enable imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from SOAR.Triage.triage import triage

# Test 1: Malware alert
malware_alert = {
  'type': 'Malware',
  'indicators': [
    {'type': 'sha256', 'value': 'deadbeef', 'risk': {'verdict': 'malicious', 'score': 90, 'sources': [], 'provider_details': []}}
  ]
}
result = triage(malware_alert)
print('Test 1 - Malware alert:')
print(f"  MITRE techniques: {result['mitre']['techniques']}")
print()

# Test 2: Unknown alert (should use defaults)
unknown_alert = {
  'type': 'Unknown',
  'indicators': [
    {'type': 'ipv4', 'value': '1.2.3.4', 'risk': {'verdict': 'suspicious', 'score': 50, 'sources': [], 'provider_details': []}}
  ]
}
result = triage(unknown_alert)
print('Test 2 - Unknown alert (should use defaults):')
print(f"  MITRE techniques: {result['mitre']['techniques']}")
print()

# Test 3: Phishing alert
phishing_alert = {
  'type': 'Phishing',
  'indicators': [
    {'type': 'urls', 'value': 'http://fake.com', 'risk': {'verdict': 'malicious', 'score': 85, 'sources': [], 'provider_details': []}}
  ]
}
result = triage(phishing_alert)
print('Test 3 - Phishing alert:')
print(f"  MITRE techniques: {result['mitre']['techniques']}")
print()

# Test 4: C2 alert
c2_alert = {
  'type': 'C2',
  'indicators': [
    {'type': 'ipv4', 'value': '1.1.1.1', 'risk': {'verdict': 'malicious', 'score': 95, 'sources': [], 'provider_details': []}}
  ]
}
result = triage(c2_alert)
print('Test 4 - C2 alert:')
print(f"  MITRE techniques: {result['mitre']['techniques']}")
print()

# Test 5: Beaconing alert
beaconing_alert = {
  'type': 'Beaconing',
  'indicators': [
    {'type': 'domains', 'value': 'beacon.bad.net', 'risk': {'verdict': 'suspicious', 'score': 75, 'sources': [], 'provider_details': []}}
  ]
}
result = triage(beaconing_alert)
print('Test 5 - Beaconing alert:')
print(f"  MITRE techniques: {result['mitre']['techniques']}")
