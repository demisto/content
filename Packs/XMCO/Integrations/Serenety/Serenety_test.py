"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
from datetime import datetime, timezone
import pytest
from Serenety import Client

BASE_URL = "https://test.leportail.xmco.fr/api"
HEADERS = {'Authentication': 'Bearer some_api_key'}


def create_mock_client():
    return Client(
        base_url=BASE_URL,
        verify=False,
        headers=HEADERS
    )


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    "xmco_severity, expected_xsoar_severity",
    [
        ("none", 0.5),
        ("low", 1),
        ("medium", 2),
        ("high", 3),
        ("critical", 4),
    ],
)
def test_convert_to_demisto_severity(xmco_severity, expected_xsoar_severity):
    """
    Given:
        - A string represents a XMCO Serenety severity.
    When:
        - convert_to_demisto_severity is called.
    Then:
        - Verify that the severity was correctly translated to a Cortex XSOAR severity.
    """
    from Serenety import convert_to_demisto_severity

    assert convert_to_demisto_severity(xmco_severity) == expected_xsoar_severity


def test_client(requests_mock):
    client = create_mock_client()
    mock_response = util_load_json('test_data/serenety_alerts.json')

    requests_mock.register_uri('GET', f'{BASE_URL}/ticketor/serenety', json=mock_response)

    response = client.fetch_alert()

    assert response[0]['type'] == 'serenety'
    assert response[0]['data']['title'] == 'Test Ticketor 01'


def test_test_module(requests_mock):
    """
    Test the test_module command
    """
    from Serenety import test_module
    client = create_mock_client()
    mock_response = util_load_json('test_data/user.json')

    requests_mock.register_uri('GET', f'{BASE_URL}/user/current', json=mock_response)

    result = test_module(client)
    assert result == "ok"

    mock_response_unauthorized = util_load_json('test_data/user_unauthorized.json')

    requests_mock.register_uri('GET', f'{BASE_URL}/user/current', json=mock_response_unauthorized)

    result = test_module(client)
    assert result == "Authorization Error: make sure API Key is correctly set"


def test_fetch_incidents(requests_mock):
    """
    Test the fetch_incidents command
    """
    from Serenety import fetch_incidents
    last_run: dict = {}
    first_fetch = '2024-04-17T00:00:00Z'
    client = create_mock_client()
    mock_response = util_load_json('test_data/serenety_alerts.json')

    requests_mock.register_uri('GET', f'{BASE_URL}/ticketor/serenety', json=mock_response)

    next_run, incidents = fetch_incidents(client, last_run, first_fetch)

    # Assertions
    assert incidents[0]['name'] == 'Test Ticketor 01'
    assert incidents[0]['CustomFields']['xmcoserenetycategory'] == 'image_and_reputation'
    assert incidents[0]['CustomFields']['xmcoserenetysubcategory'] == 'image_and_reputation_suspicious_domain'
    assert incidents[0]['CustomFields']['xmcoserenetymonitoring'] == 'out_of_scope'
    assert incidents[0]['CustomFields']['xmcoserenetyidentification'] == 'manual'

    current_datetime = datetime.utcnow().astimezone(timezone.utc)
    current_datetime.strftime("%Y-%m-%dT%H:%M:%S")

    next_run, incidents = fetch_incidents(client, last_run, first_fetch, scope="65e83a81cba69ffd2d9384c1")

    # Assertions
    assert incidents[0]['name'] == 'Test Ticketor 01'
    assert incidents[0]['CustomFields']['xmcoserenetycategory'] == 'image_and_reputation'
    assert incidents[0]['CustomFields']['xmcoserenetysubcategory'] == 'image_and_reputation_suspicious_domain'
    assert incidents[0]['CustomFields']['xmcoserenetymonitoring'] == 'out_of_scope'
    assert incidents[0]['CustomFields']['xmcoserenetyidentification'] == 'manual'

    # Test no result
    mock_response = util_load_json('test_data/serenety_alerts_no_result.json')
    requests_mock.register_uri('GET', f'{BASE_URL}/ticketor/serenety', json=mock_response)
    last_run: dict = {'last_fetch': first_fetch}

    next_run, incidents = fetch_incidents(client, last_run, first_fetch)

    assert next_run.get('last_fetch') > last_run.get('last_fetch')
    assert incidents == []
