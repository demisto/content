import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
data = {
    "Type": 17,
    "ContentsFormat": "number",
    "Contents": {
        "stats": int(incident[0].get('CustomFields', {}).get('ransomwareapproximatenumberofencryptedendpoints', 0)),
        "params": {
            "layout": "horizontal",
            "name": "Hosts Count",
            "sign": "",
            "colors": {
                "items": {
                    "#32CD32": {
                        "value": -1
                    },
                    "#FF9000": {
                        "value": 0
                    },
                    "#EE4443": {
                        "value": 3
                    }
                }
            },
            "type": "above"
        }
    }
}

demisto.results(data)
