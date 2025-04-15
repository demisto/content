import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from pathlib import Path
from VectraXDRDisplayEntityDetections import get_detections_list_hr, trim_api_version


def test_trim_api_version():
    """
    Given:
    - A URL containing an API version as a prefix.

    When:
    - Calling the 'trim_api_version' function with the provided URL.

    Then:
    - Assert that the function removes the API version prefix from the URL and returns the trimmed URL.
    """
    url_with_version = "/api/v3.3/some/endpoint"
    trimmed_url = trim_api_version(url_with_version)
    assert trimmed_url == "/some/endpoint?pivot=Vectra-XSOAR-1.0.11"  # temp fix - need to change the version suffix

    url_without_version = "/some/endpoint"
    trimmed_url = trim_api_version(url_without_version)
    assert trimmed_url == "/some/endpoint"


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
        '{"id": "1", "url": "/api/v3.3/detections/1", "detection": "Detection 1", "detection_type": "Type 1", '
        '"category": "Category 1", "src_ip": "1.2.3.4", "threat": "High", "certainty": 85, '
        '"grouped_details": [], "summary": {"num_events": 2}, "state": "Active", "tags": ["Tag1", "Tag2"], '
        '"last_timestamp": "2023-07-22T12:34:56Z"}',
        '{"id": "2", "url": "/api/v3.3/detections/2", "detection": "Detection 2", "detection_type": "Type 2", '
        '"category": "Category 2", "src_ip": "5.6.7.8", "threat": "Medium", "certainty": 70, '
        '"grouped_details": [], "summary": {"num_events": 1}, "state": "Closed", "tags": ["Tag3"], '
        '"last_timestamp": "2023-07-20T10:30:00Z"}'
    ]
    test_data_path = Path(__file__).parent / 'test_data'
    with open(f"{test_data_path}/vectra_entity_detections_hr.md") as f:
        result_hr = f.read()

    # Call the function with the sample detection details
    result = get_detections_list_hr(sample_detection_details)
    # Assert that the result contains the appropriate human-readable output
    assert result.readable_output == result_hr
