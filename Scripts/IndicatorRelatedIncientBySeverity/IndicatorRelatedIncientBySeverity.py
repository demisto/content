import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

investigation_ids = demisto.get(demisto.args()['indicator'], 'investigationIDs')
if not investigation_ids:
    demisto.results("No related incidents were found")
    sys.exit(0)

if investigation_ids is list:
    investigation_ids = [id for id in investigation_ids if isinstance(id, int) or id.isdigit()]
else:
    if isinstance(investigation_ids, int) or investigation_ids.isdigit():
        investigation_ids = [investigation_ids]
    else:
        investigation_ids = None
if not investigation_ids:
    demisto.results("No related incidents were found")
    sys.exit(0)

severity_dict = {
    "0": 0,
    "1": 0,
    "2": 0,
    "3": 0,
    "4": 0,
    "5": 0}

for investigation_id in investigation_ids:
    incident = demisto.executeCommand("getIncidents", {"id": investigation_id})
    severity = incident[0]["Contents"]["data"][0]["severity"]

    severity_dict[str(severity)] = severity_dict[str(severity)] + 1

data = {
    "Type": 17,
    "ContentsFormat": "pie",
    "Contents": {
        "stats": [
            {
                "data": [
                    int(severity_dict["0"])
                ],
                "groups": None,
                "name": "Unknown",
                "label": "incident.severity.unknown",
                "color": "rgb(121, 149, 212)"
            },
            {
                "data": [
                    int(severity_dict["1"])
                ],
                "groups": None,
                "name": "Low",
                "label": "incident.severity.low",
                "color": "rgb(0, 205, 51)"
            },
            {
                "data": [
                    int(severity_dict["2"])
                ],
                "groups": None,
                "name": "Medium",
                "label": "incident.severity.medium",
                "color": "rgb(255, 144, 0)"
            },
            {
                "data": [
                    int(severity_dict["3"])
                ],
                "groups": None,
                "name": "High",
                "label": "incident.severity.high",
                "color": "rgb(255, 23, 68)"
            },
            {
                "data": [
                    int(severity_dict["4"])
                ],
                "groups": None,
                "name": "Critical",
                "label": "incident.severity.critical",
                "color": "rgb(208, 2, 27)"
            },
            {
                "data": [
                    int(severity_dict["5"])
                ],
                "groups": None,
                "name": "Informational",
                "label": "incident.severity.informational",
                "color": "rgb(154, 160, 163)"
            },
        ],
        "params": {
            "layout": "horizontal"
        }
    }
}

demisto.results(data)
