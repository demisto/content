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
        "stats": count - stats,
        "params": {
            "layout": "horizontal",
            "name": "Techniques to Handle",
            "sign": "",
            "colors": {
                "items": {
                    "#8C9EFF": {
                        "value": 0
                    },
                }
            },
            "type": "above"
        }
    }
}

return_results(data)
