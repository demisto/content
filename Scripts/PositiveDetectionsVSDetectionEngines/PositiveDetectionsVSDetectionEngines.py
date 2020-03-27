import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def extract_engines_data_from_indicator(indicator_data):
<<<<<<< HEAD
    if not (indicator_data and 'detectionengines' in indicator_data['CustomFields']
            and 'positivedetections' in indicator_data['CustomFields']):
        demisto.results("None")
        sys.exit(0)

    detection_engines = indicator_data['CustomFields']['detectionengines']
    positive_detections = indicator_data['CustomFields']['positivedetections']

=======
    if not indicator_data:
        raise DemistoException("No indicator found")
    cstm_fields = indicator_data.get("CustomFields")
    if not cstm_fields:
        # No content, so will display 0/0
        return create_pie(0, 0)
    if "detectionengines" not in cstm_fields:
        detection_engines = 0
    else:
        detection_engines = try_parse_int(
            cstm_fields["detectionengines"], '"Detection Engines" must be a number'
        )
    if "positivedetections" not in cstm_fields:
        positive_detections = 0
    else:
        positive_detections = try_parse_int(
            cstm_fields["positivedetections"], '"Positive Detections" must be a number'
        )
    unknown_detections = detection_engines - positive_detections
    if unknown_detections < 0:
        raise ValueError(
            f'"Detection Engines ({detection_engines})" must be greater or equal '
            f'to "Positive Detections ({positive_detections})"')
    return create_pie(unknown_detections, positive_detections)


def create_pie(unknown_detections, positive_detections):
>>>>>>> upstream/master
    data = {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats": [
                {
<<<<<<< HEAD
                    "data": [
                        positive_detections
                    ],
=======
                    "data": [positive_detections],
>>>>>>> upstream/master
                    "groups": None,
                    "name": "Positive Detections",
                    "label": "Positive Detections",
                    "color": "rgb(255, 23, 68)"
                },
                {
<<<<<<< HEAD
                    "data": [
                        detection_engines - positive_detections
                    ],
=======
                    "data": [unknown_detections],
>>>>>>> upstream/master
                    "groups": None,
                    "name": "Unknown",
                    "label": "Unknown",
                    "color": "rgb(255, 144, 0)"
                }
            ],
<<<<<<< HEAD
            "params": {
                "layout": "vertical"
            }
        }
    }

    return data


def main():
    indicator_data = demisto.args().get('indicator')
    demisto.results(extract_engines_data_from_indicator(indicator_data))
=======
            "params": {"layout": "vertical"}
        },
    }
    return data


def try_parse_int(num, err_msg):
    try:
        return int(num)
    except (ValueError, TypeError):
        raise ValueError(err_msg)


def main():
    try:
        indicator_data = demisto.args().get("indicator")
        demisto.results(extract_engines_data_from_indicator(indicator_data))
    except Exception as e:
        demisto.error(f"PostiveDetectionsVSDetectiongEngines failed with [{e}]")
        msg = f"Could not load widget:\n{e}"
        demisto.results(msg)
>>>>>>> upstream/master


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
