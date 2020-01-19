import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def extract_engines_data_from_indicator(indicator_data):
    if not indicator_data:
        exit_with_message("No indicator found")
    cstm_fields = indicator_data.get("CustomFields")
    if not cstm_fields:
        # No content, so will display 0/0
        return create_pie(0, 0)
    elif "detectionengines" not in cstm_fields:
        exit_with_message('Please provide  Custom Field "Detection Engines"')
    elif "positivedetections" not in cstm_fields:
        exit_with_message('Please provide  Custom Field "Positive Detections"')

    detection_engines = try_parse_int(
        cstm_fields["detectionengines"], '"detectionengines" must be an integer'
    )
    positive_detections = try_parse_int(
        cstm_fields["positivedetections"], '"positivedetections" must be an integer'
    )

    return create_pie(detection_engines, positive_detections)


def create_pie(detection_engines, positive_detections):
    data = {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats": [
                {
                    "data": [positive_detections],
                    "groups": None,
                    "name": "Positive Detections",
                    "label": "Positive Detections",
                    "color": "rgb(255, 23, 68)",
                },
                {
                    "data": [detection_engines - positive_detections],
                    "groups": None,
                    "name": "Unknown",
                    "label": "Unknown",
                    "color": "rgb(255, 144, 0)",
                },
            ],
            "params": {"layout": "vertical"},
        },
    }
    return data


def exit_with_message(msg="Failed to load"):
    msg = f"Could not load widget:\n{msg}"
    demisto.results(msg)
    sys.exit(0)


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
        demisto.debug(f"PostiveDetectionsVSDetectiongEngines failed with [{e}]")
        exit_with_message(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
