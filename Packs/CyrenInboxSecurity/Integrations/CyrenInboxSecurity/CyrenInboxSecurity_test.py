"""Cyren Inbox Security Integration for Cortex XSOAR - Unit Tests file

"""

import json
import io
import datetime


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_simulate_fetch():
    from CyrenInboxSecurity import simulate_fetch

    # fetch
    incidents = simulate_fetch()

    assert incidents[0]["name"] ==\
        'Cyren Inbox Security Sample - phishing (admin@sample.com)'


def test_test_module(requests_mock):
    """Tests the test function."""

    from CyrenInboxSecurity import Client, test_module

    requests_mock.post(
        'https://test.com/v1/token',
        json="ok"
    )

    client = Client(
        base_url='https://test.com/',
        verify=False
    )

    # test
    results = test_module(
        client=client,
        client_id="sample",
        client_secret="sample",
    )

    assert results == 'ok'


def test_resolve_and_remediate_command(requests_mock):
    """Tests the cyren-resolve-and-remediate command function.
    """
    from CyrenInboxSecurity import Client, resolve_and_remediate_command

    requests_mock.patch(
        'https://test.com/v1/cases',
        json={"data": {"status": "ok"}}
    )

    requests_mock.post(
        'https://test.com/v1/token',
        json={"data": {"access_token": "sample"}}
    )

    client = Client(
        base_url='https://test.com/',
        verify=False
    )

    # resolve and remediate
    cmd_results = resolve_and_remediate_command(
        client=client,
        args={
            "case_id": '123',
            "resolution": 'phishing',
            "resolution_reason_text": '',
            "actions": [],
        },
        client_id="sample",
        client_secret="sample",
    )

    attrs = vars(cmd_results)
    assert attrs["raw_response"]["data"]["status"] == 'ok'


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from CyrenInboxSecurity import Client, fetch_incidents

    mock_response = util_load_json('test_data/sample-incidents.json')

    requests_mock.get(
        'https://test.com/v1/incidents',
        json=mock_response
    )

    requests_mock.post(
        'https://test.com/v1/token',
        json={"data": {"access_token": "sample"}}
    )

    client = Client(
        base_url='https://test.com/',
        verify=False
    )

    last_run = {
    }

    # fetch
    incidents = fetch_incidents(
        client=client,
        client_id="sample",
        client_secret="sample",
        last_run=last_run,
        first_fetch_time=datetime.datetime.now(),
        max_fetch=10,
    )

    assert incidents[0]["name"] ==\
        'Cyren Inbox Security - phishing (System)'
