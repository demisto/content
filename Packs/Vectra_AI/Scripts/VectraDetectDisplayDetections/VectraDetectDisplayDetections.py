import json
import traceback
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


""" CONSTANTS """

UTM_PIVOT = f"?pivot=Vectra_AI-XSOAR-{get_pack_version(pack_name='Vectra AI') or '2.0.0'}"


def trim_api_version(url: str) -> str:
    """
    Trim the '/api/v2.5' portion from a URL.

    Args:
        url (str): The URL to trim.

    Returns:
        str: The trimmed URL.
    """
    if 'pivot' in url:
        return url
    api_versions = ["/api/v2.5", "/api/v2"]
    for api_version in api_versions:
        if api_version in url:
            trimmed_url = url.replace(api_version, "") + UTM_PIVOT
            return trimmed_url
    return url


def convert_to_string(value):
    """
    A function that recursively converts the input value to a string.
    If the value is a dictionary, it recurses into the dictionary and converts all values to string.
    If the value is a list, it recurses into the list and converts all items to string.
    For any other type, it converts the value to a string.

    Args:
        value: The value to be converted to a string.

    Returns:
        The converted value as a string.
    """
    if isinstance(value, dict):
        # Recurse into dictionaries
        return {k: convert_to_string(v) for k, v in value.items()}
    elif isinstance(value, list):
        # Recurse into lists
        return [convert_to_string(item) for item in value]
    else:
        # Convert everything else to string
        return str(value)


def get_detections_list_hr(detections) -> CommandResults:
    """
    Convert a list of detections into a human-readable format for display.

    Args:
        detections (list): A list of detections, each represented as a JSON string.

    Returns:
        CommandResults: An object containing the human-readable output of the detections.
    """
    hr_dict = []
    if not detections or not json.loads(detections[0]):
        return CommandResults(readable_output="##### Couldn't find any matching entity detections for "
                                              "provided filters.")
    # Process detection_set and create detection_ids field
    for detection in detections:  # type: ignore
        # Trim API version from url
        detection = json.loads(detection)
        detection['detection_url'] = trim_api_version(detection.get('url')) if detection.get('url') else None
        # Convert ID into clickable URL
        detection['detection_id'] = f"[{detection.get('id')}]({detection.get('detection_url')})"
        summary = remove_empty_elements(detection.get('summary', {}))
        summary = convert_to_string(summary)

        hr_dict.append({
            'ID': detection.get('detection_id'),
            'Detection Type': detection.get('detection_type'),
            'Category': detection.get('detection_category'),
            'Threat Score': detection.get('threat'),
            'Certainty Score': detection.get('certainty'),
            'State': detection.get('state'),
            'Tags': detection.get('tags'),
            'Summary': summary,
        })
    human_readable = tableToMarkdown("", hr_dict,
                                     ['ID', 'Detection Type', 'Category', 'Threat Score',
                                      'Certainty Score', 'State', 'Tags', 'Summary'],
                                     removeNull=True, json_transform_mapping={'Summary': JsonTransformer()})

    return CommandResults(readable_output=human_readable)


''' MAIN FUNCTION '''


def main():
    try:
        detection_details = demisto.incident().get('CustomFields', {}).get('vectradetectiondetails', [])
        return_results(get_detections_list_hr(detection_details))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute VectraDetectDisplayDetections. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
