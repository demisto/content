import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

positive_detections = demisto.get(demisto.args()['indicator'], 'CustomFields.positivedetections')
detection_engines = demisto.get(demisto.args()['indicator'], 'CustomFields.detectionengines')

if not (positive_detections and detection_engines):
    demisto.results("None")
    sys.exit(0)

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
