import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def extract_engines_data_from_indicator(indicator_data):
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

    return data


def main():
    indicator_data = demisto.args().get('indicator')
    demisto.results(extract_engines_data_from_indicator(indicator_data))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
