import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

indicator_data = demisto.args().get('indicator')

if not (indicator_data and 'detectionengines' in indicator_data['CustomFields']
        and 'positivedetections' in indicator_data['CustomFields']):
    demisto.results("None")
    sys.exit(0)

detection_engines = indicator_data['CustomFields']['detectionengines']
positive_detections = indicator_data['CustomFields']['positivedetections']

data = {
    "Type": 17,
    "ContentsFormat": "pie",
    "Contents": {
        "stats": [
            {
                "data": [
                    positive_detections
                ],
                "groups": None,
                "name": "Positive Detections",
                "label": "Positive Detections",
                "color": "rgb(255, 23, 68)"
            },
            {
                "data": [
                    detection_engines - positive_detections
                ],
                "groups": None,
                "name": "Unknown",
                "label": "Unknown",
                "color": "rgb(255, 144, 0)"
            }
        ],
        "params": {
            "layout": "vertical"
        }
    }
}

demisto.results(data)
