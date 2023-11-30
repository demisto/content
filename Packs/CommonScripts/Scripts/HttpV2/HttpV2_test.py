import json
import pytest
from CommonServerPython import DemistoException


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('status_list, expected_output', [
    (["400-402", "405"], [400, 401, 402, 405]),
    (["401", "405"], [401, 405]),
    (["401-404"], [401, 402, 403, 404]),
])
def test_format_status_list(status_list, expected_output):
    """
    Given
        List of statuses
    When
        - User wants to retry the requests for these statuses.
    Then
        - Get a list of status codes for the status range the user entered.
    """
    from HttpV2 import format_status_list

    output = format_status_list(status_list)
    assert output == expected_output


@pytest.mark.parametrize('headers, request_content_type_header, response_content_type_header, expected_headers', [
    ({}, 'json', 'json', {'Content-Type': 'application/json', 'Accept': 'application/json'}),
    ({'Content-Type': 'application/json'}, '', 'json', {'Content-Type': 'application/json',
                                                        'Accept': 'application/json'}),
    ({}, '', '', {})

])
def test_create_headers(headers, request_content_type_header, response_content_type_header, expected_headers):
    """
    Given
        List of statuses
    When
        - User wants to retry the requests for these statuses.
    Then
        - Get a list of status codes for the status range the user entered.
    """
    from HttpV2 import create_headers

    output = create_headers(headers, request_content_type_header, response_content_type_header)
    assert output == expected_headers


@pytest.mark.parametrize('headers, expected_headers', [
    ('"key": "value"', {"key": "value"}),
    ('{"key": "value"}', {"key": "value"}),
    ('"key": "value", "key1": "value1"', {"key": "value", "key1": "value1"}),
    ('{"key": "value", "key1": "value1"}', {"key": "value", "key1": "value1"}),
])
def test_parse_headers(headers, expected_headers):
    from HttpV2 import parse_headers

    output = parse_headers(headers)
    assert output == expected_headers


@pytest.mark.parametrize('headers', [
    'key: "value"',
    '"key": "value"}',
    '"key": "value", "key1": value1"',
    '{"key": "value", "key1": "value1"',
    '"key": "value", "key1": "value1"}',
])
def test_parse_wrong_headers(headers):
    from HttpV2 import parse_headers

    with pytest.raises(DemistoException, match="Make sure the headers are in one of the allowed formats."):
        parse_headers(headers)
