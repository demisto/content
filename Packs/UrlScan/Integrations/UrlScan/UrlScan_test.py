import json
import time
from threading import Thread

import pytest

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

RETURN_ERROR_TARGET = 'UrlScan.return_error'
SCAN_URL = 'https://urlscan.io/api/v1/scan/'
RESULT_URL = 'https://urlscan.io/api/v1/result/'


@pytest.mark.parametrize('continue_on_blacklisted_urls', [(True), (False)])
def test_continue_on_blacklisted_error_arg(mocker, requests_mock, continue_on_blacklisted_urls):
    from UrlScan import http_request, BLACKLISTED_URL_ERROR_MESSAGES, Client
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    response_json = {
        'status': 400,
        'message': 'Scan prevented ...',
        'description': BLACKLISTED_URL_ERROR_MESSAGES[0],
    }
    args = {
        'continue_on_blacklisted_urls': continue_on_blacklisted_urls
    }
    data = {
        'url': 'www.test.com'
    }
    requests_mock.post(SCAN_URL, status_code=400, json=response_json)
    mocker.patch.object(demisto, 'args', return_value=args)
    client = Client()

    response = http_request(client, 'POST', 'scan/', json=json.dumps(data))
    if continue_on_blacklisted_urls:
        assert return_error_mock.call_count == 0
    else:
        assert response[0].get('is_error') is True
        assert (
            'The submitted domain is on our blacklist. '
            'For your own safety we did not perform this scan...'
        ) in response[0].get('error_string')


def test_endless_loop_on_failed_response(requests_mock, mocker):
    """
    Given
    - Some uuid
    When
    - Running format results on it
    Then
    - Assert it does not enter an endless loop
    """
    from UrlScan import format_results, Client
    mocker.patch(RETURN_ERROR_TARGET)
    client = Client()

    with open('./test_data/capitalne.json', 'r') as f:
        response_data = json.loads(f.read())
    requests_mock.get(RESULT_URL + 'uuid', status_code=200, json=response_data)
    thread = Thread(target=format_results, args=(client, 'uuid', ))
    thread.start()
    time.sleep(10)
    assert not thread.is_alive(), 'format_results method have probably entered an endless loop'


def test_urlscan_submit_url(requests_mock, mocker):
    """
    Given
    - Two URLs which are rate limited
    When
    - running the !url command
    Then
    - Assert the items are scheduled and the metrics are correct.
    """
    from UrlScan import urlscan_submit_command, Client
    import CommonServerPython

    response_json = {
        'is_error': True
    }
    args = {
        'url': 'https://something.com,https://somethingelse.com'
    }
    requests_mock.post(SCAN_URL, status_code=429, json=response_json, headers={'X-Rate-Limit-Reset-After': '123'})
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')

    client = Client()

    response = urlscan_submit_command(client=client)
    scheduled_command = response[0].scheduled_command
    scheduled_command_args = scheduled_command._args
    assert scheduled_command_args['polling'] is True
    assert scheduled_command_args['url'] == ['https://something.com', 'https://somethingelse.com']
    assert scheduled_command._next_run == '123'
    assert scheduled_command._items_remaining == 2

    metrics = response[1]
    assert metrics.execution_metrics == [{'Type': 'QuotaError', 'APICallsCount': 2}]


def test_format_results_check_lists(mocker):
    from UrlScan import format_results, Client
    client = Client()

    with open('./test_data/capitalne.json', 'r') as f:
        response_data = json.loads(f.read())

    mocker.patch('UrlScan.urlscan_submit_request', return_value=(response_data, '', ''))
    mocker.patch.object(demisto, 'results', return_value='')
    command_results_inputs = mocker.patch('UrlScan.CommandResults')

    format_results(client, 'uuid', '')
    outputs = command_results_inputs.call_args[1]['outputs']['URLScan(val.URL && val.URL == obj.URL)']
    assert outputs.get('links') == [
        "http://capitalne.com/home",
        "http://capitalne.com/about",
        "https://urlscan.io/"
    ]
