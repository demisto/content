import io
import json
from CommonServerPython import arg_to_datetime
from Tenable_ioEventCollector import Client
import demistomock as demisto

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_events.json')
MOCK_CHUNKS_STATUS = util_load_json('test_data/mock_chunks_status.json')
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
    from Tenable_ioEventCollector import get_audit_logs_command
    client = Client(verify=False, headers={}, proxy=False)
    requests_mock.get(f'{BASE_URL}/audit-log/v1/events?limit=2', json=MOCK_ENTRY)

    results, audit_logs = get_audit_logs_command(client, limit=2)

    assert results.outputs_prefix == "Tenable.AuditLogs"
    assert len(audit_logs) == 2


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
    from Tenable_ioEventCollector import generate_export_uuid, try_get_chunks, run_vulnerabilities_fetch
    client = Client(verify=False, headers={}, proxy=False)
    requests_mock.post(f'{BASE_URL}/vulns/export', json=MOCK_UUID)
    requests_mock.get(f'{BASE_URL}/vulns/export/123/status', json=MOCK_CHUNKS_STATUS)
    requests_mock.get(f'{BASE_URL}/vulns/export/123/chunks/1', json=MOCK_CHUNK_CONTENT)
    first_fetch = arg_to_datetime('3 days')
    assert run_vulnerabilities_fetch(first_fetch=first_fetch, last_run={}, vuln_fetch_interval=0)

    generate_export_uuid(client, first_fetch, last_run={}, severity=[])
    assert demisto.getIntegrationContext().get('export_uuid') == '123'

    vulnerabilities, finished = try_get_chunks(client, '123')

    assert len(vulnerabilities) == 1
    assert finished

