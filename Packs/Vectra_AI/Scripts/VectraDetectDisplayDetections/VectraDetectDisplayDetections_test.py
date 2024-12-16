import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from pathlib import Path
from VectraDetectDisplayDetections import get_detections_list_hr, trim_api_version, convert_to_string


def test_trim_api_version():
    """
    Given:
    - A URL containing an API version as a prefix.

    When:
    - Calling the 'trim_api_version' function with the provided URL.

    Then:
    - Assert that the function removes the API version prefix from the URL and returns the trimmed URL.
    """
    url_with_version = "/api/v2.5/some/endpoint"
    trimmed_url = trim_api_version(url_with_version)
    assert trimmed_url == "/some/endpoint?pivot=Vectra_AI-XSOAR-"\
        f"{get_pack_version(pack_name='Vectra AI') or '2.0.0'}"

    url_without_version = "/some/endpoint"
    trimmed_url = trim_api_version(url_without_version)
    assert trimmed_url == "/some/endpoint"

    url_without_version = "/some/endpoint?pivot=Vectra_AI-XSOAR-2.0.0"
    trimmed_url = trim_api_version(url_without_version)
    assert trimmed_url == "/some/endpoint?pivot=Vectra_AI-XSOAR-2.0.0"


def test_convert_to_string():
    """
    Given:
    - A dictionary with mixed types of values.

    When:
    - Calling the 'convert_to_string' function with the provided dictionary.

    Then:
    - Assert that the function converts all values in the dictionary to string.
    """
    input_dict = {"key1": 1, "key2": ["value1", "value2"], "key3": {"nested_key": True}}
    expected_output = {"key1": "1", "key2": ["value1", "value2"], "key3": {"nested_key": "True"}}
    assert convert_to_string(input_dict) == expected_output


def test_get_detections_list_hr_empty_detection_list():
    """
    Given:
    - An empty detection list.

    When:
    - Calling the 'get_detections_list_hr' function with the provided empty detection list.

    Then:
    - Assert that the result contains the appropriate human-readable output indicating that no matching
      entity detections were found.
    """
    # Call the function with an empty detection list
    result = get_detections_list_hr([])

    # Assert that the result contains the appropriate human-readable output
    assert "Couldn't find any matching entity detections for provided filters." in result.readable_output


def test_get_detections_list_hr_with_detection_details():
    """
    Given:
    - Sample detection details data for testing.

    When:
    - Calling the 'get_detections_list_hr' function with the provided sample detection details.

    Then:
    - Assert that the result contains the appropriate human-readable output matching the expected output.
    """
    # Sample detection details data for testing
    sample_detection_details = [
        '{"id":1,"url":"https://dummyurl.com/api/v2.5/detections/1","detection_type":"Type 1", '
        '"detection_category":"Category 1","is_targeting_key_asset":false,"state":"fixed","threat":47,"certainty":65, '
        '"is_triaged":false,"tags":["Tag1","Tag2"],"summary":{"dst_ports":[1,2,3],"protocols":["tcp"],"num_attempts":600, '
        '"num_successes":0},"assigned_to":"test_user","assigned_date":"2024-07-12T05:50:48Z"}',
        '{"id":2,"url":"https://dummyurl.com/api/v2.5/detections/2","detection_type":"Type 2", '
        '"detection_category":"Category 2","is_targeting_key_asset":false,"state":"active","threat":74,"certainty":50, '
        '"is_triaged":false, "tags":["Tag1", "Tag2"], "summary":{"src_accounts": [{"name": "account_name",'
        '"privilege_category": "Low", "privilege_level": "1", "id": 23}], "src_hosts": [{"name": "IP-0.0.0.1",'
        '"privilege_category": null,"privilege_level": null, "id": 2}], "services_accessed": [{"name": "http/dummy_url.com",'
        '"privilege_category": null,"privilege_level": null,"id": null}, '
        '{"name": "http/test_url.com","privilege_category": null,"privilege_level": null,"id": null}] '
        '},"assigned_to":"test_user","assigned_date":"2024-07-12T05:50:48Z"}'
    ]
    test_data_path = Path(__file__).parent / 'test_data'
    with open(f"{test_data_path}/vectra_detect_detections_hr.md") as f:
        result_hr = f.read()

    # Call the function with the sample detection details
    result = get_detections_list_hr(sample_detection_details)
    # Assert that the result contains the appropriate human-readable output
    assert result.readable_output == result_hr
    # To avoid the error, we need to ensure that the input is a valid JSON string
