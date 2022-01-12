"""Base Script for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

"""

import json
import io
import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('status_list, expected_output', [
    (["400-402", "405"], [400, 401, 402, 405]),
    (["401", "405"], [401, 405]),
    (["401-404"], [401, 402, 403, 404]),
])
def test_get_status_list(status_list, expected_output):
    """
    Given
        List of statuses
    When
        - User wants to retry the requests for these statuses.
    Then
        - Get a list of status codes for the status range the user entered.
    """
    from HttpV2 import get_status_list

    output = get_status_list(status_list)
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

