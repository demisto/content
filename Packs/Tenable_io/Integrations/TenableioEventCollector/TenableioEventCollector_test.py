import io
import json

import pytest as pytest
import demistomock as demisto

from CommonServerPython import arg_to_datetime
from TenableioEventCollector import Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_AUDIT_LOGS = util_load_json('test_data/mock_events.json')
MOCK_CHUNKS_STATUS = util_load_json('test_data/mock_chunks_status.json')
MOCK_CHUNKS_STATUS_PROCESSING = util_load_json('test_data/mock_chunks_status_processing.json')
MOCK_CHUNKS_STATUS_ERROR = util_load_json('test_data/mock_chunks_status_error.json')
MOCK_UUID = util_load_json('test_data/mock_export_uuid.json')
MOCK_CHUNK_CONTENT = util_load_json('test_data/mock_chunk_content.json')
BASE_URL = 'https://cloud.tenable.com'


def test_get_audit_logs_command(requests_mock):
    """
    Given:
        - get-audit-logs command arguments.
    When:
        - Running the command tenable-get-audit-logs
    Then:
        - Verify that when a list of events exists, it will take the last timestamp
        - Verify that when there are no events yet (first fetch) the timestamp for all will be as the first fetch
    """
    from TenableioEventCollector import get_audit_logs_command
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.get(f'{BASE_URL}/audit-log/v1/events?limit=2', json=MOCK_AUDIT_LOGS)

    results, audit_logs = get_audit_logs_command(client, limit=2)

    assert len(audit_logs) == 3


def test_vulnerabilities_process(requests_mock):
    """
    Given:
        - vulnerabilities fetch interval.
    When:
        - Running the fetch vulnerabilities process running.
    Then:
        - Verify that fetch should run
        - Verify export uuid being updated in the integration context
        - Verify vulnerabilities returned and finished flag is up.
    """
    from TenableioEventCollector import generate_export_uuid, try_get_chunks, run_vulnerabilities_fetch
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.post(f'{BASE_URL}/vulns/export', json=MOCK_UUID)
    requests_mock.get(f'{BASE_URL}/vulns/export/123/status', json=MOCK_CHUNKS_STATUS)
    requests_mock.get(f'{BASE_URL}/vulns/export/123/chunks/1', json=MOCK_CHUNK_CONTENT)
    first_fetch = arg_to_datetime('3 days')
    last_run = {}
    assert run_vulnerabilities_fetch(first_fetch=first_fetch, last_run=last_run, vuln_fetch_interval=0)

    generate_export_uuid(client, first_fetch, last_run=last_run, severity=[])
    assert last_run.get('export_uuid') == '123'

    vulnerabilities, finished = try_get_chunks(client, '123')

    assert len(vulnerabilities) == 1
    assert finished


def test_fetch_audit_logs_no_duplications(requests_mock):
    """

    Given:
        - last run object and audit log response from API.
    When:
        - Running the fetch events process.
    Then:
        - Verify no duplicated audit logs are returned from the API.

    """
    from TenableioEventCollector import fetch_events_command
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.get(f'{BASE_URL}/audit-log/v1/events?f=date.gt:2022-09-20&limit=5000', json=MOCK_AUDIT_LOGS)
    last_run = {'last_fetch_time': '2022-09-20'}
    first_fetch = arg_to_datetime('3 days')
    audit_logs, new_last_run = fetch_events_command(client, first_fetch, last_run, 1)

    assert len(audit_logs) == 1
    assert audit_logs[0].get('id') == '1234'

    last_run.update({'index_audit_logs': new_last_run.get('index_audit_logs'), 'last_fetch_time': '2022-09-20'})
    audit_logs, new_last_run = fetch_events_command(client, first_fetch, last_run, 1)

    assert len(audit_logs) == 1
    assert audit_logs[0].get('id') == '12345'
    assert new_last_run.get('index_audit_logs') == 2

    last_run.update({'last_id': new_last_run.get('index_audit_logs'), 'last_fetch_time': '2022-09-20'})
    audit_logs, new_last_run = fetch_events_command(client, first_fetch, last_run, 1)

    assert len(audit_logs) == 1
    assert audit_logs[0].get('id') == '123456'
    assert new_last_run.get('index_audit_logs') == 3


@pytest.mark.parametrize('response_to_use_status, expected_result', [
    (MOCK_CHUNKS_STATUS, 'finished'),
    (MOCK_CHUNKS_STATUS_PROCESSING, 'polling'),
    (MOCK_CHUNKS_STATUS_ERROR, 'error')])
def test_get_vulnerabilities(requests_mock, response_to_use_status, expected_result, mocker):
    """
    Given:
        - get vulnerabilities arguments (lsat_found, num_assets and sevirity)
    When:
        - Running the get vulnerabilities command.
    Then:
        - Verify results when error and success.
        - Verify scheduled command result is in the right format in case of polling.
    """
    from TenableioEventCollector import get_vulnerabilities_command
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.post(f'{BASE_URL}/vulns/export', json=MOCK_UUID)
    requests_mock.get(f'{BASE_URL}/vulns/export/123/status', json=response_to_use_status)
    requests_mock.get(f'{BASE_URL}/vulns/export/123/chunks/1', json=MOCK_CHUNK_CONTENT)
    mocker.patch.object(demisto, 'demistoVersion', return_value={
        'version': '6.2.1',
        'buildNumber': '12345'
    })
    args = {
        'last_found': '1663844866',
        'num_assets': '50',
        'severity': 'test1, test2'
    }
    res = get_vulnerabilities_command(args, client)
    if expected_result == 'finished':
        assert len(res.raw_response) == 1
    elif expected_result == 'polling':
        assert res.scheduled_command._args.get('export_uuid') == '123'
        assert res.readable_output == 'Fetching Results:'
    else:  # error
        assert res.readable_output == 'Export job failed'


def test_test_module(requests_mock):
    """
    Given:
        - The client object.
    When:
        - Running the test_module function.
    Then:
        - Verify the result is ok as expected.
    """
    from TenableioEventCollector import test_module
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.get(f'{BASE_URL}/audit-log/v1/events?limit=10', json=MOCK_AUDIT_LOGS)
    result = test_module(client)

    assert result == 'ok'
