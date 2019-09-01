import demistomock as demisto
from CommonServerPython import *
incident = demisto.incidents()
data = {
    "Type": 17,
    "ContentsFormat": "pie",
    "Contents": {
        "stats": [
            {
                "data": [
                    int(incident[0].get('CustomFields', {}).get('xdrhighseverityalerts', 0))
                ],
                "groups": None,
                "name": "high",
                "label": "incident.severity.high",
                "color": "rgb(255, 23, 68)"
            },
            {
                "data": [
                    int(incident[0].get('CustomFields', {}).get('xdrmediumseverityalerts', 0))
                ],
                "groups": None,
                "name": "medium",
                "label": "incident.severity.medium",
                "color": "rgb(255, 144, 0)"
            },
            {
                "data": [
                    int(incident[0].get('CustomFields', {}).get('xdrlowseverityalerts', 0))
                ],
                "groups": None,
                "name": "low",
                "label": "incident.severity.low",
                "color": "rgb(0, 205, 51)"
            },
        ],
        "params": {
            "layout": "horizontal"
        }
    }
}

demisto.results(data)
