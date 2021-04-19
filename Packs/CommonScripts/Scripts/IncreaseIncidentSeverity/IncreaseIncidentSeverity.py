import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

SEVERITY_VALUES = {
    "unknown": 0,
    "informational": 0.5,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "0": 0,
    "0.5": 0.5,
    "1": 1,
    "2": 2,
    "3": 3,
    "4": 4
}

current_incident = demisto.incidents()[0]
current_severity = str(current_incident.get('severity', {}))
severity_arg = demisto.args().get('severity')

if severity_arg:
    severity_arg = severity_arg.lower()
    severity_to_increase_to = SEVERITY_VALUES.get(severity_arg.lower())
    if severity_to_increase_to > float(current_severity):
        demisto.executeCommand("setIncident", {"severity": severity_to_increase_to})
        demisto.results(f"Severity increased to {severity_to_increase_to}")
    else:
        demisto.results(f"Severity not increased because the same severity or a lower severity was chosen.")

elif current_severity == "0.5":
    demisto.executeCommand("setIncident", {'severity': "1"})
elif current_severity == "4":
    demisto.results("The incident is already at the highest possible severity (critical).")
else:
    new_severity = int(current_severity) + 1
    demisto.executeCommand("setIncident", {'severity': new_severity})
