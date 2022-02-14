import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
issues = (incident[0].get('CustomFields', {}).get('panosnetworkoperationsconfigurationhygieneissues'))

data = {
    "Type": 17,
    "ContentsFormat": "number",
    "Contents": {
        "stats": len(issues),
        "params": {
            "layout": "horizontal",
            "name": "PAN-OS Configuration Hygiene Issues",
            "sign": "",
            "colors": {
                "items": {
                    "#FAC100": {
                      "value": 5
                    },
                    "#00CD33": {
                        "value": 1
                    },
                }
            },
            "type": "above"
        }
    }
}

demisto.results(data)
