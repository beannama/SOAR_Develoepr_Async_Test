'''
IOC Enrichment

Purpose: Enrich observables with threat context.

Responsibilities:
- Match IOCs against mock_ti
- Attach threat level, confidence, notes
- Flag whitelisted indicators
Design notes:
- Stateless and idempotent
- Easy to swap with real TI feeds
'''