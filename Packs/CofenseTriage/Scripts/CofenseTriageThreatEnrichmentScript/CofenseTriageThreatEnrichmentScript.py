from CommonServerPython import *

# Fetch threat indicators based on threat value provided in the argument.
# cofense-threat-indicator-list command will enrich the information based on value.
threat_indicator = demisto.executeCommand('cofense-threat-indicator-list',
                                          {'threat_value': f"{demisto.get(demisto.args(), 'threat_value')}"})

# Populate response
demisto.results(threat_indicator)
