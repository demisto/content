import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import copy
import json

""" CONSTANTS """

UTM_PIVOT = "?pivot=Vectra-XSOAR-1.0.10"  # temp replacement for the get_pack_version()


def trim_api_version(url: str) -> str:
    """
    Trim the '/api/v3.3' portion from a URL.

    Args:
        url (str): The URL to trim.

    Returns:
        str: The trimmed URL.
    """
    api_versions = ["/api/v3.3", "/api/v3"]
    for api_version in api_versions:
        if api_version in url:
            trimmed_url = url.replace(api_version, "") + UTM_PIVOT
            return trimmed_url
    return url


def get_detections_list_hr(detections) -> CommandResults:
    """
    Convert a list of detections into a human-readable format for display.

    Args:
        detections (list): A list of detections, each represented as a JSON string.

    Returns:
        CommandResults: An object containing the human-readable output of the detections.
    """
    hr_dict = []
    detection_list = copy.deepcopy(detections)
    if not bool(detection_list) or not json.loads(detection_list[0]):
        return CommandResults(readable_output="##### Couldn't find any matching entity detections for "
                                              "provided filters.")
    # Process detection_set and create detection_ids field
    for detection in detection_list:  # type: ignore
        # Trim API version from url
        detection = json.loads(detection)
        detection['url'] = trim_api_version(detection.get('url')) if detection.get('url') else None
        # Convert ID into clickable URL
        detection['id'] = f"[{detection.get('id')}]({detection.get('url')})"
        summary = detection.get('summary')
        num_events = 0
        # For counting number of events
        if summary and summary.get('num_events'):
            num_events = int(summary.get('num_events'))

        hr_dict.append({
            'ID': detection.get('id'),
            'Detection Type': detection.get('detection_type'),
            'Category': detection.get('category'),
            'Src IP': detection.get('src_ip'),
            'Number Of Events': num_events,
            'State': detection.get('state'),
            'Tags': detection.get('tags'),
            'Last Timestamp': detection.get('last_timestamp')
        })
    human_readable = tableToMarkdown("", hr_dict,
                                     ['ID', 'Detection Type', 'Category', 'Src IP',
                                      'Number Of Events', 'State', 'Tags',
                                      'Last Timestamp'],
                                     removeNull=True)

    return CommandResults(readable_output=human_readable)


''' MAIN FUNCTION '''


def main():
    try:
        detection_details = demisto.incident().get('CustomFields', {}).get('vectraxdrentitydetectiondetails', [])
        return_results(get_detections_list_hr(detection_details))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute VectraXDRDisplayEntityDetections. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
