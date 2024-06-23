import json
import time
from threading import Thread

import pytest
from pytest_mock import MockerFixture

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


def thread_target():
    from UrlScan import format_results, Client
    client = Client()
    try:
        format_results(client, 'uuid', '')
    except Exception:
        pass


def test_endless_loop_on_failed_response(requests_mock, mocker):
    """
    Given
    - Some uuid
    When
    - Running format results on it
    Then
    - Assert it does not enter an endless loop
    """
    mocker.patch(RETURN_ERROR_TARGET)

    with open('./test_data/capitalne.json') as f:
        response_data = json.loads(f.read())
    requests_mock.get(RESULT_URL + 'uuid', status_code=200, json=response_data)
    thread = Thread(target=thread_target)
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


def test_urlscan_search_only_found(mocker: MockerFixture):
    """
    Given:
        Client, execution metrics and empty command results
    When:
        urlscan_search_only is called with a url that has a result
    Then:
        - Execution metrics success is incremented by 1
        - The command_results is empty
    """
    from UrlScan import urlscan_search_only, Client

    client = Client()
    command_results = []
    execution_metrics = ExecutionMetrics()
    url = "http://example.com"
    mocker.patch(
        "UrlScan.urlscan_search",
        return_value={
            "results": [{"task": {"uuid": "123"}, "page": {"url": "http://example.com"}}]
        },
    )
    mocker.patch("UrlScan.format_results")

    urlscan_search_only(client, url, command_results, execution_metrics)

    assert execution_metrics.success == 1
    assert len(command_results) == 0


def test_urlscan_search_only_not_found(mocker: MockerFixture):
    """
    Given:
        Client, execution metrics and empty command results
    When:
        urlscan_search_only is called with a url that has no result
    Then:
        - No results message is added to command_results
        - Execution metrics is unchanged
    """
    from UrlScan import urlscan_search_only, Client

    client = Client()
    command_results = []
    execution_metrics = ExecutionMetrics()
    url = "http://example.com"
    mocker.patch("UrlScan.urlscan_search", return_value={"results": []})

    urlscan_search_only(client, url, command_results, execution_metrics)

    assert execution_metrics.success == 0
    assert len(command_results) == 1
    assert command_results[0].readable_output.startswith("No results found for")


def test_urlscan_search_only_error(mocker: MockerFixture):
    """
    Given:
        Client, execution metrics and empty command results
    When:
        urlscan_search_only is called with a url that return an error
    Then:
        - Error message is added to command_results
        - Execution metrics general error is incremented by 1
    """
    from UrlScan import urlscan_search_only, Client

    client = Client()
    command_results = []
    execution_metrics = ExecutionMetrics()
    url = "http://example.com"

    mocker.patch(
        "UrlScan.urlscan_search",
        return_value={"is_error": True, "error_string": "Test error"},
    )

    urlscan_search_only(client, url, command_results, execution_metrics)

    assert execution_metrics.general_error == 1
    assert "Test error" in command_results[0].readable_output


def test_format_results_check_lists(mocker):
    from UrlScan import format_results, Client
    client = Client()

    with open('./test_data/capitalne.json') as f:
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
