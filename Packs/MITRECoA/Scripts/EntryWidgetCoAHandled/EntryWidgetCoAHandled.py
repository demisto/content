import demistomock as demisto
from CommonServerPython import *

incident = demisto.incident()
count = len(incident.get('CustomFields', {}).get('techniqueslist', "").split(","))
handled = incident.get('CustomFields', {}).get('handledtechniques', [])
stats = len([h for h in handled if h])

data = {
    "Type": 17,
    "ContentsFormat": "number",
    "Contents": {
        "stats": stats,
        "params": {
            "layout": "horizontal",
            "name": "Handled Techniques",
            "sign": "",
            "colors": {
                "items": {
                    "#00CD33": {
                        "value": count - 50
                    },
                    "#FF9000": {
                        "value": count - 150
                    },
                    "#FF1744": {
                        "value": 0
                    }
                }
            },
            "type": "above"
        }
    }
}

return_results(data)
