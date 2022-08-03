import copy
from freezegun import freeze_time
import json
import os
import zipfile

import pytest

import demistomock as demisto
from CommonServerPython import Common, tableToMarkdown, pascalToSpace
from CoreIRApiModule import CoreClient

test_client = CoreClient(
    base_url='https://test_api.com/public_api/v1', headers={}
)


def test_client_update_incident():
    with pytest.raises(ValueError, match="Can't provide both assignee_email/assignee_name and unassign_user"):
        test_client.update_incident(incident_id='1',
                                    status='new',
                                    unassign_user="user",
                                    assigned_user_mail="user")


Core_URL = 'https://api.xdrurl.com'

''' HELPER FUNCTIONS '''


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def get_incident_extra_data_by_status(incident_id, alerts_limit):
    """
        The function simulate the client.get_incident_extra_data method for the test_fetch_incidents_filtered_by_status.
        The function got the incident_id, and return the json file by the incident id.
    """
    if incident_id == '1':
        incident_extra_data = load_test_data('./test_data/get_incident_extra_data.json')
    else:
        incident_extra_data = load_test_data('./test_data/get_incident_extra_data_new_status.json')
    return incident_extra_data['reply']


''' TESTS FUNCTIONS '''


# Note this test will fail when run locally (in pycharm/vscode) as it assumes the machine (docker image) has UTC timezone set

@pytest.mark.parametrize(argnames='time_to_convert, expected_value',
                         argvalues=[('1322683200000', 1322683200000),
                                    ('2018-11-06T08:56:41', 1541494601000)])
def test_convert_time_to_epoch(time_to_convert, expected_value):
    from CoreIRApiModule import convert_time_to_epoch
    assert convert_time_to_epoch(time_to_convert) == expected_value


def return_extra_data_result(*args):
    if args[1].get('incident_id') == '2':
        raise Exception("Rate limit exceeded")
    else:
        incident_from_extra_data_command = load_test_data('./test_data/incident_example_from_extra_data_command.json')
        return {}, {}, {"incident": incident_from_extra_data_command}


def test_update_incident(requests_mock):
    from CoreIRApiModule import update_incident_command, CoreClient

    update_incident_response = load_test_data('./test_data/update_incident.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/incidents/update_incident/', json=update_incident_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'incident_id': '1',
        'status': 'new'
    }
    readable_output, outputs, _ = update_incident_command(client, args)

    assert outputs is None
    assert readable_output == 'Incident 1 has been updated'


def test_get_endpoints(requests_mock):
    from CoreIRApiModule import get_endpoints_command, CoreClient

    get_endpoints_response = load_test_data('./test_data/get_endpoints.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json=get_endpoints_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'hostname': 'foo',
        'page': 1,
        'limit': 3
    }

    res = get_endpoints_command(client, args)
    assert get_endpoints_response.get('reply').get('endpoints') == \
           res.outputs['CoreApiModule.Endpoint(val.endpoint_id == obj.endpoint_id)']


def test_get_all_endpoints_using_limit(requests_mock):
    from CoreIRApiModule import get_endpoints_command, CoreClient

    get_endpoints_response = load_test_data('./test_data/get_all_endpoints.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoints/', json=get_endpoints_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'limit': 1,
        'page': 0,
        'sort_order': 'asc'
    }
    res = get_endpoints_command(client, args)
    expected_endpoint = get_endpoints_response.get('reply')[0]

    assert [expected_endpoint] == res.outputs['CoreApiModule.Endpoint(val.endpoint_id == obj.endpoint_id)']


def test_endpoint_command(requests_mock):
    from CoreIRApiModule import endpoint_command, CoreClient

    get_endpoints_response = load_test_data('./test_data/get_endpoints.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json=get_endpoints_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {'id': 'identifier'}

    outputs = endpoint_command(client, args)

    get_endpoints_response = {
        Common.Endpoint.CONTEXT_PATH: [{'ID': '1111',
                                        'Hostname': 'ip-3.3.3.3',
                                        'IPAddress': '3.3.3.3',
                                        'OS': 'Linux',
                                        'Vendor': 'CoreApiModule',
                                        'Status': 'Online',
                                        'IsIsolated': 'No'}]}

    results = outputs[0].to_context()
    for key, val in results.get("EntryContext").items():
        assert results.get("EntryContext")[key] == get_endpoints_response[key]
    assert results.get("EntryContext") == get_endpoints_response


def test_isolate_endpoint(requests_mock):
    from CoreIRApiModule import isolate_endpoint_command, CoreClient

    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json={
        'reply': {
            'endpoints': [
                {
                    'endpoint_id': '1111',
                    "endpoint_status": "CONNECTED"
                }
            ]
        }
    })

    isolate_endpoint_response = load_test_data('./test_data/isolate_endpoint.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/isolate', json=isolate_endpoint_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    args = {
        "endpoint_id": "1111"
    }

    res = isolate_endpoint_command(client, args)
    assert res.readable_output == 'The isolation request has been submitted successfully on Endpoint 1111.\n'


def test_isolate_endpoint_unconnected_machine(requests_mock, mocker):
    from CoreIRApiModule import isolate_endpoint_command, CoreClient
    #    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)

    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json={
        'reply': {
            'endpoints': [
                {
                    'endpoint_id': '1111',
                    "endpoint_status": "DISCONNECTED"
                }
            ]
        }
    })

    isolate_endpoint_response = load_test_data('./test_data/isolate_endpoint.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/isolate', json=isolate_endpoint_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    args = {
        "endpoint_id": "1111",
        "suppress_disconnected_endpoint_error": False
    }
    with pytest.raises(ValueError, match='Error: Endpoint 1111 is disconnected and therefore can not be isolated.'):
        isolate_endpoint_command(client, args)


def test_unisolate_endpoint(requests_mock):
    from CoreIRApiModule import unisolate_endpoint_command, CoreClient

    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json={
        'reply': {
            'endpoints': [
                {
                    'endpoint_id': '1111',
                    "endpoint_status": "CONNECTED"
                }
            ]
        }
    })

    unisolate_endpoint_response = load_test_data('./test_data/unisolate_endpoint.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/unisolate', json=unisolate_endpoint_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    args = {
        "endpoint_id": "1111"
    }

    res = unisolate_endpoint_command(client, args)
    assert res.readable_output == 'The un-isolation request has been submitted successfully on Endpoint 1111.\n'


def test_unisolate_endpoint_unconnected_machine(requests_mock):
    from CoreIRApiModule import unisolate_endpoint_command, CoreClient

    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json={
        'reply': {
            'endpoints': [
                {
                    'endpoint_id': '1111',
                    "endpoint_status": "DISCONNECTED"
                }
            ]
        }
    })

    unisolate_endpoint_response = load_test_data('./test_data/unisolate_endpoint.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/unisolate', json=unisolate_endpoint_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    args = {
        "endpoint_id": "1111",
        "suppress_disconnected_endpoint_error": True
    }

    res = unisolate_endpoint_command(client, args)
    assert res.readable_output == 'Warning: un-isolation action is pending for the following disconnected endpoint: 1111.'


def test_unisolate_endpoint_pending_isolation(requests_mock):
    from CoreIRApiModule import unisolate_endpoint_command, CoreClient

    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json={
        'reply': {
            'endpoints': [
                {
                    'endpoint_id': '1111',
                    "is_isolated": "AGENT_PENDING_ISOLATION"
                }
            ]
        }
    })

    unisolate_endpoint_response = load_test_data('./test_data/unisolate_endpoint.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/unisolate', json=unisolate_endpoint_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    args = {
        "endpoint_id": "1111"
    }
    with pytest.raises(ValueError, match='Error: Endpoint 1111 is pending isolation and therefore can not be'
                                         ' un-isolated.'):
        unisolate_endpoint_command(client, args)


def test_get_distribution_url(requests_mock):
    from CoreIRApiModule import get_distribution_url_command, CoreClient

    get_distribution_url_response = load_test_data('./test_data/get_distribution_url.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/distributions/get_dist_url/', json=get_distribution_url_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    args = {
        'distribution_id': '1111',
        'package_type': 'x86'
    }

    readable_output, outputs, _ = get_distribution_url_command(client, args)
    expected_url = get_distribution_url_response.get('reply').get('distribution_url')
    assert outputs == {
        'CoreApiModule.Distribution(val.id == obj.id)': {
            'id': '1111',
            'url': expected_url
        }
    }

    assert readable_output == f'[Distribution URL]({expected_url})'


def test_get_audit_management_logs(requests_mock):
    from CoreIRApiModule import get_audit_management_logs_command, CoreClient

    get_audit_management_logs_response = load_test_data('./test_data/get_audit_management_logs.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/audits/management_logs/', json=get_audit_management_logs_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    args = {
        'email': 'woo@demisto.com',
        'limit': '3',
        'timestamp_gte': '3 month'
    }

    readable_output, outputs, _ = get_audit_management_logs_command(client, args)

    expected_outputs = get_audit_management_logs_response.get('reply').get('data')
    assert outputs['CoreApiModule.AuditManagementLogs(val.AUDIT_ID == obj.AUDIT_ID)'] == expected_outputs


def test_get_audit_agent_reports(requests_mock):
    from CoreIRApiModule import get_audit_agent_reports_command, CoreClient

    get_audit_agent_reports_response = load_test_data('./test_data/get_audit_agent_report.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/audits/agents_reports/', json=get_audit_agent_reports_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    args = {
        'endpoint_names': 'woo.demisto',
        'limit': '3',
        'timestamp_gte': '3 month'
    }

    readable_output, outputs, _ = get_audit_agent_reports_command(client, args)
    expected_outputs = get_audit_agent_reports_response.get('reply').get('data')
    assert outputs['CoreApiModule.AuditAgentReports'] == expected_outputs
    assert outputs['Endpoint(val.ID && val.ID == obj.ID)'] == [{'ID': '1111', 'Hostname': '1111.eu-central-1'},
                                                               {'ID': '1111', 'Hostname': '1111.eu-central-1'},
                                                               {'ID': '1111', 'Hostname': '1111.eu-central-1'}]


def test_get_distribution_status(requests_mock):
    from CoreIRApiModule import get_distribution_status_command, CoreClient

    get_distribution_status_response = load_test_data('./test_data/get_distribution_status.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/distributions/get_status/', json=get_distribution_status_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    args = {
        "distribution_ids": "588a56de313549b49d70d14d4c1fd0e3"
    }

    readable_output, outputs, _ = get_distribution_status_command(client, args)

    assert outputs == {
        'CoreApiModule.Distribution(val.id == obj.id)': [
            {
                'id': '588a56de313549b49d70d14d4c1fd0e3',
                'status': 'Completed'
            }
        ]
    }


def test_get_distribution_versions(requests_mock):
    from CoreIRApiModule import get_distribution_versions_command, CoreClient

    get_distribution_versions_response = load_test_data('./test_data/get_distribution_versions.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/distributions/get_versions/', json=get_distribution_versions_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    readable_output, outputs, _ = get_distribution_versions_command(client, args={})

    assert outputs == {
        'CoreApiModule.DistributionVersions': {
            "windows": [
                "7.0.0.27797"
            ],
            "linux": [
                "7.0.0.1915"
            ],
            "macos": [
                "7.0.0.1914"
            ]
        }
    }


def test_create_distribution(requests_mock):
    from CoreIRApiModule import create_distribution_command, CoreClient

    create_distribution_response = load_test_data('./test_data/create_distribution.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/distributions/create/', json=create_distribution_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    args = {
        "name": "dfslcxe",
        "platform": "windows",
        "package_type": "standalone",
        "agent_version": "7.0.0.28644"
    }

    readable_output, outputs, _ = create_distribution_command(client, args)

    expected_distribution_id = create_distribution_response.get('reply').get('distribution_id')
    assert outputs == {
        'CoreApiModule.Distribution(val.id == obj.id)': {
            'id': expected_distribution_id,
            "name": "dfslcxe",
            "platform": "windows",
            "package_type": "standalone",
            "agent_version": "7.0.0.28644",
            'description': None
        }
    }
    assert readable_output == f'Distribution {expected_distribution_id} created successfully'


def test_blocklist_files_command_with_more_than_one_file(requests_mock):
    """
    Given:
        - List of files' hashes to put in blocklist
    When
        - A user desires to mark more than one file
    Then
        - returns markdown, context data and raw response.
    """

    from CoreIRApiModule import blocklist_files_command, CoreClient
    test_data = load_test_data('test_data/blocklist_allowlist_files_success.json')
    expected_command_result = {'CoreApiModule.blocklist.added_hashes.fileHash(val.fileHash == obj.fileHash)': test_data[
        'multi_command_args']['hash_list']}

    requests_mock.post(f'{Core_URL}/public_api/v1/hash_exceptions/blocklist/', json=test_data['api_response'])

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = blocklist_files_command(client, test_data['multi_command_args'])

    assert expected_command_result == res.outputs


def test_blocklist_files_command_with_single_file(requests_mock):
    """
    Given:
        - List of a file hashes to put in blocklist.
    When
        - A user desires to blocklist one file.
    Then
        - returns markdown, context data and raw response.
    """

    from CoreIRApiModule import blocklist_files_command, CoreClient
    test_data = load_test_data('test_data/blocklist_allowlist_files_success.json')
    expected_command_result = {
        'CoreApiModule.blocklist.added_hashes.fileHash(val.fileHash == obj.fileHash)':
            test_data['single_command_args']['hash_list']}
    requests_mock.post(f'{Core_URL}/public_api/v1/hash_exceptions/blocklist/', json=test_data['api_response'])

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = blocklist_files_command(client, test_data['single_command_args'])

    assert expected_command_result == res.outputs


def test_blocklist_files_command_with_no_comment_file(requests_mock):
    """
    Given:
        - ￿List of files' hashes to put in blocklist without passing the comment argument.
    When
        - A user desires to blocklist files without adding a comment.
    Then
        - returns markdown, context data and raw response.
    """

    from CoreIRApiModule import blocklist_files_command, CoreClient
    test_data = load_test_data('test_data/blocklist_allowlist_files_success.json')
    expected_command_result = {
        'CoreApiModule.blocklist.added_hashes.fileHash(val.fileHash == obj.fileHash)':
            test_data['no_comment_command_args']['hash_list']}
    requests_mock.post(f'{Core_URL}/public_api/v1/hash_exceptions/blocklist/', json=test_data['api_response'])

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = blocklist_files_command(client, test_data['no_comment_command_args'])

    assert expected_command_result == res.outputs


def test_allowlist_files_command_with_more_than_one_file(requests_mock):
    """
    Given:
        - ￿List of files' hashes to put in allowlist
    When
        - A user desires to mark more than one file
    Then
        - returns markdown, context data and raw response.
    """

    from CoreIRApiModule import allowlist_files_command, CoreClient
    test_data = load_test_data('test_data/blocklist_allowlist_files_success.json')
    expected_command_result = {'CoreApiModule.allowlist.added_hashes.fileHash(val.fileHash == obj.fileHash)': test_data[
        'multi_command_args']['hash_list']}
    requests_mock.post(f'{Core_URL}/public_api/v1/hash_exceptions/allowlist/', json=test_data['api_response'])

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = allowlist_files_command(client, test_data['multi_command_args'])

    assert expected_command_result == res.outputs


def test_allowlist_files_command_with_single_file(requests_mock):
    """
    Given:
        - List of a file hashes to put in allowlist.
    When
        - A user desires to allowlist one file.
    Then
        - returns markdown, context data and raw response.
    """

    from CoreIRApiModule import allowlist_files_command, CoreClient
    test_data = load_test_data('test_data/blocklist_allowlist_files_success.json')
    expected_command_result = {
        'CoreApiModule.allowlist.added_hashes.fileHash(val.fileHash == obj.fileHash)':
            test_data['single_command_args']['hash_list']}
    requests_mock.post(f'{Core_URL}/public_api/v1/hash_exceptions/allowlist/', json=test_data['api_response'])

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = allowlist_files_command(client, test_data['single_command_args'])

    assert expected_command_result == res.outputs


def test_allowlist_files_command_with_no_comment_file(requests_mock):
    """
    Given:
        - List of files' hashes to put in allowlist without passing the comment argument.
    When
        - A user desires to allowlist files without adding a comment.
    Then
        - returns markdown, context data and raw response.
    """

    from CoreIRApiModule import allowlist_files_command, CoreClient
    test_data = load_test_data('test_data/blocklist_allowlist_files_success.json')
    expected_command_result = {
        'CoreApiModule.allowlist.added_hashes.fileHash(val.fileHash == obj.fileHash)': test_data['no_comment_command_args'][
            'hash_list']}
    requests_mock.post(f'{Core_URL}/public_api/v1/hash_exceptions/allowlist/', json=test_data['api_response'])

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = allowlist_files_command(client, test_data['no_comment_command_args'])

    assert expected_command_result == res.outputs


def test_quarantine_files_command(requests_mock):
    """
    Given:
        - List of files' hashes to put in quarantine
    When
        - A user desires to quarantine files.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import quarantine_files_command, CoreClient
    test_data = load_test_data('test_data/quarantine_files.json')
    quarantine_files_expected_tesult = {
        'CoreApiModule.quarantineFiles.actionIds(val.actionId === obj.actionId)': test_data['context_data']}
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/quarantine/', json=test_data['api_response'])

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = quarantine_files_command(client, test_data['command_args'])

    assert quarantine_files_expected_tesult == res.outputs


def test_get_quarantine_status_command(requests_mock):
    """
    Given:
        - Endpoint_id, file_path, file_hash
    When
        - A user desires to check a file's quarantine status.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import get_quarantine_status_command, CoreClient
    test_data = load_test_data('test_data/get_quarantine_status.json')
    quarantine_files_expected_tesult = {
        'CoreApiModule.quarantineFiles.status(val.fileHash === obj.fileHash &&val.endpointId'
        ' === obj.endpointId && val.filePath === obj.filePath)':
            test_data['context_data']}
    requests_mock.post(f'{Core_URL}/public_api/v1/quarantine/status/', json=test_data['api_response'])

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = get_quarantine_status_command(client, test_data['command_args'])

    assert quarantine_files_expected_tesult == res.outputs


def test_restore_file_command(requests_mock):
    """
    Given:
        - file_hash
    When
        - A user desires to restore a file.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import restore_file_command, CoreClient

    restore_expected_tesult = {'CoreApiModule.restoredFiles.actionId(val.actionId == obj.actionId)': 123}
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/restore/', json={"reply": {"action_id": 123}})

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = restore_file_command(client, {"file_hash": "123"})

    assert restore_expected_tesult == res.outputs


def test_endpoint_scan_command(requests_mock):
    """
    Given:
    -   endpoint_id_list, dist_name, gte_first_seen, gte_last_seen, lte_first_seen, lte_last_seen, ip_list,
    group_name, platform, alias, isolate, hostname
    When
        - A user desires to scan endpoint.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import endpoint_scan_command, CoreClient
    test_data = load_test_data('test_data/scan_endpoints.json')
    scan_expected_tesult = {'CoreApiModule.endpointScan(val.actionId == obj.actionId)': {'actionId': 123,
                                                                                         'aborted': False}}
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/scan/', json={"reply": {"action_id": 123}})

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = endpoint_scan_command(client, test_data['command_args'])

    assert scan_expected_tesult == res.outputs


def test_endpoint_scan_command_scan_all_endpoints(requests_mock):
    """
    Given:
    -  the filter all as true.
    When
        - A user desires to scan all endpoints.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import endpoint_scan_command, CoreClient
    test_data = load_test_data('test_data/scan_all_endpoints.json')
    scan_expected_tesult = {'CoreApiModule.endpointScan(val.actionId == obj.actionId)': {'actionId': 123,
                                                                                         'aborted': False}}
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/scan/', json={"reply": {"action_id": 123}})

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = endpoint_scan_command(client, test_data['command_args'])

    assert scan_expected_tesult == res.outputs


def test_endpoint_scan_command_scan_all_endpoints_no_filters_error(requests_mock):
    """
    Given:
    -  No filters.
    When
        - A user desires to scan all endpoints but without the correct argumetns.
    Then
        - raise a descriptive error.
    """
    from CoreIRApiModule import endpoint_scan_command, CoreClient
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/scan/', json={"reply": {"action_id": 123}})

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    err_msg = 'To scan/abort scan all the endpoints run this command with the \'all\' argument as True ' \
              'and without any other filters. This may cause performance issues.\n' \
              'To scan/abort scan some of the endpoints, please use the filter arguments.'
    with pytest.raises(Exception, match=err_msg):
        endpoint_scan_command(client, {})


def test_endpoint_scan_abort_command_scan_all_endpoints_no_filters_error(requests_mock):
    """
    Given:
    -  No filters.
    When
        - A user desires to abort scan on all endpoints but without the correct arguments.
    Then
        - raise a descriptive error.
    """
    from CoreIRApiModule import endpoint_scan_abort_command, CoreClient
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/abort_scan/', json={"reply": {"action_id": 123}})

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    err_msg = 'To scan/abort scan all the endpoints run this command with the \'all\' argument as True ' \
              'and without any other filters. This may cause performance issues.\n' \
              'To scan/abort scan some of the endpoints, please use the filter arguments.'
    with pytest.raises(Exception, match=err_msg):
        endpoint_scan_abort_command(client, {})


def test_endpoint_scan_abort_command(requests_mock):
    """
    Given:
    -   endpoint_id_list, dist_name, gte_first_seen, gte_last_seen, lte_first_seen, lte_last_seen, ip_list,
    group_name, platform, alias, isolate, hostname
    When
        - A user desires to abort scan endpoint.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import endpoint_scan_abort_command, CoreClient
    test_data = load_test_data('test_data/scan_endpoints.json')
    scan_expected_tesult = {'CoreApiModule.endpointScan(val.actionId == obj.actionId)': {'actionId': 123,
                                                                                         'aborted': True}}
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/abort_scan/', json={"reply": {"action_id": 123}})

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = endpoint_scan_abort_command(client, test_data['command_args'])

    assert scan_expected_tesult == res.outputs


def test_endpoint_scan_abort_command_all_endpoints(requests_mock):
    """
    Given:
    -  the filter all as true.
    When
        - A user desires to abort scan for all endpoints.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import endpoint_scan_abort_command, CoreClient
    test_data = load_test_data('test_data/scan_all_endpoints.json')
    scan_expected_tesult = {'CoreApiModule.endpointScan(val.actionId == obj.actionId)': {'actionId': 123,
                                                                                         'aborted': True}}
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/abort_scan/', json={"reply": {"action_id": 123}})

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    client._headers = {}
    res = endpoint_scan_abort_command(client, test_data['command_args'])

    assert scan_expected_tesult == res.outputs


def test_get_update_args_unassgning_user():
    """
    Given:
        -  a dict indicating changed fields (delta) with assigned_user_mail set to "None"
        - the incident status - set to 1 == Active
    When
        - running get_update_args
    Then
        - update_args have assigned_user_mail and assigned_user_pretty_name set to None and unassign_user set to 'true'
    """
    from CoreIRApiModule import get_update_args
    delta = {'assigned_user_mail': 'None'}
    update_args = get_update_args(delta, 1)
    assert update_args.get('assigned_user_mail') is None
    assert update_args.get('assigned_user_pretty_name') is None
    assert update_args.get('unassign_user') == 'true'


def test_get_update_args_close_incident():
    """
    Given:
        -  a dict indicating changed fields (delta) with a change in owner
        - the incident status - set to 1 == Active
    When
        - running get_update_args
    Then
        - update_args assigned_user_mail has the correct associated mail
    """
    from CoreIRApiModule import get_update_args
    delta = {'closeReason': 'Other', "closeNotes": "Not Relevant", 'closingUserId': 'admin'}
    update_args = get_update_args(delta, 2)
    assert update_args.get('status') == 'resolved_other'
    assert update_args.get('resolve_comment') == 'Not Relevant'


def test_get_update_args_owner_sync(mocker):
    """
    Given:
        -  a dict indicating changed fields (delta) with closeReason set to Other and a closeNotes
        - the incident status - set to 2 == Closed
    When
        - running get_update_args
    Then
        - update_args status has the correct status (resolved_other)
        - the resolve_comment is the same as the closeNotes
    """
    from CoreIRApiModule import get_update_args
    mocker.patch.object(demisto, 'params', return_value={"sync_owners": True, "mirror_direction": "Incoming"})
    mocker.patch.object(demisto, 'findUser', return_value={"email": "moo@demisto.com", 'username': 'username'})
    delta = {'owner': 'username'}

    update_args = get_update_args(delta, 1)

    assert update_args.get('assigned_user_mail') == 'moo@demisto.com'


def test_get_policy(requests_mock):
    """
        Given:
            -endpoint_id

        When:
            -Retrieving the policy name of the requested actions according to the specific endpoint.

        Then:
            - Assert the returned markdown, context data and raw response are as expected.
        """
    from CoreIRApiModule import get_policy_command, CoreClient

    expected_context = {
        'endpoint_id': 'aeec6a2cc92e46fab3b6f621722e9916',
        'policy_name': 'test'
    }
    run_script_expected_result = {'CoreApiModule.Policy(val.endpoint_id == obj.endpoint_id)': expected_context}
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_policy/', json={'reply': {
        'policy_name': 'test'}})

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'endpoint_id': 'aeec6a2cc92e46fab3b6f621722e9916'
    }

    hr, context, raw_response = get_policy_command(client, args)
    assert hr == 'The policy name of endpoint: aeec6a2cc92e46fab3b6f621722e9916 is: test.'
    assert run_script_expected_result == context
    assert raw_response == {'policy_name': 'test'}


def test_get_endpoint_device_control_violations_command(requests_mock):
    """
        Given:
            - violation_id_list='100'
        When:
            -Request for list of device control violations filtered by selected fields. You can retrieve up to 100 violations.
        Then:
            - Assert the returned markdown, context data and raw response are as expected.
        """
    from CoreIRApiModule import get_endpoint_device_control_violations_command, CoreClient
    from CommonServerPython import timestamp_to_datestring, tableToMarkdown, string_to_table_header

    get_endpoint_violations_reply = load_test_data('./test_data/get_endpoint_violations.json')
    violations = get_endpoint_violations_reply.get('reply').get('violations')
    for violation in violations:
        timestamp = violation.get('timestamp')
        violation['date'] = timestamp_to_datestring(timestamp, '%Y-%m-%dT%H:%M:%S')
    get_endpoint_violations_expected_result = {
        'CoreApiModule.EndpointViolations(val.violation_id==obj.violation_id)':
            violations
    }
    headers = ['date', 'hostname', 'platform', 'username', 'ip', 'type', 'violation_id', 'vendor', 'product',
               'serial']
    requests_mock.post(f'{Core_URL}/public_api/v1/device_control/get_violations/', json=get_endpoint_violations_reply)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'violation_id_list': '100'
    }

    hr, context, raw_response = get_endpoint_device_control_violations_command(client, args)

    assert hr == tableToMarkdown(name='Endpoint Device Control Violation', t=violations, headers=headers,
                                 headerTransform=string_to_table_header, removeNull=True)
    assert context == get_endpoint_violations_expected_result
    assert raw_response == get_endpoint_violations_reply.get('reply')


def test_retrieve_files_command(requests_mock):
    """
    Given:
        - endpoint_ids
        - windows_file_paths
    When
        - A user desires to retrieve a file.
    Then
        - Assert the returned markdown, context data and raw response are as expected.
    """
    from CoreIRApiModule import retrieve_files_command, CoreClient
    from CommonServerPython import tableToMarkdown, string_to_table_header

    retrieve_expected_result = {'action_id': 1773}
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/file_retrieval/', json={'reply': {'action_id': 1773}})
    result = {'action_id': 1773}

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    res = retrieve_files_command(client, {'endpoint_ids': 'aeec6a2cc92e46fab3b6f621722e9916',
                                          'windows_file_paths': 'C:\\Users\\demisto\\Desktop\\demisto.txt'})

    assert res.readable_output == tableToMarkdown(name='Retrieve files', t=result, headerTransform=string_to_table_header)
    assert res.outputs == retrieve_expected_result
    assert res.raw_response == {'action_id': 1773}


def test_retrieve_files_command_using_general_file_path(requests_mock):
    """
    Given:
        - endpoint_ids
        - generic_file_path
    When
        - A user desires to retrieve a file.
    Then
        - Assert the returned markdown, context data and raw response are as expected.
    """
    from CoreIRApiModule import retrieve_files_command, CoreClient
    from CommonServerPython import tableToMarkdown, string_to_table_header

    retrieve_expected_result = {'action_id': 1773}
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/file_retrieval/', json={'reply': {'action_id': 1773}})
    result = {'action_id': 1773}

    get_endpoints_response = load_test_data('./test_data/get_endpoints.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json=get_endpoints_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    res = retrieve_files_command(client, {'endpoint_ids': 'aeec6a2cc92e46fab3b6f621722e9916',
                                          'generic_file_path': 'C:\\Users\\demisto\\Desktop\\demisto.txt'})

    assert res.readable_output == tableToMarkdown(name='Retrieve files', t=result, headerTransform=string_to_table_header)
    assert res.outputs == retrieve_expected_result
    assert res.raw_response == {'action_id': 1773}


def test_retrieve_files_command_using_general_file_path_without_valid_endpint(requests_mock):
    """
    Given:
        - endpoint_ids
        - generic_file_path
    When
        - A user desires to retrieve a file.
        - The endpoint is invalid
    Then
        - Assert the returned markdown, context data and raw response are as expected.
    """
    from CoreIRApiModule import retrieve_files_command, CoreClient
    get_endpoints_response = {"reply": {"result_count": 1, "endpoints": []}}
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json=get_endpoints_response)
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    with pytest.raises(ValueError) as error:
        retrieve_files_command(client, {'endpoint_ids': 'aeec6a2cc92e46fab3b6f621722e9916',
                                        'generic_file_path': 'C:\\Users\\demisto\\Desktop\\demisto.txt'})
    assert str(error.value) == "Error: Endpoint aeec6a2cc92e46fab3b6f621722e9916 was not found"


def test_retrieve_file_details_command(requests_mock):
    """
    Given:
        - action_id
    When
        - Requesting to view the file retrieved by the Retrieve File request according to the action ID.
    Then
        - Assert the returned markdown, file result are as expected.
    """
    from CoreIRApiModule import retrieve_file_details_command, CoreClient

    data = load_test_data('./test_data/retrieve_file_details.json')
    data1 = 'test_file'
    retrieve_expected_hr = {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': [data.get('reply').get('data')],
        'HumanReadable': '### Action id : 1788 \n Retrieved 1 files from 1 endpoints. \n '
                         'To get the exact action status run the core-action-status-get command',
        'ReadableContentsFormat': 'markdown',
        'EntryContext': {}
    }

    requests_mock.post(f'{Core_URL}/public_api/v1/actions/file_retrieval_details/', json=data)
    requests_mock.get(f'{Core_URL}/public_api/v1/download/file_hash', json=data1)
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'action_id': '1788'
    }
    results, file_result = retrieve_file_details_command(client, args, False)
    assert results == retrieve_expected_hr
    assert file_result[0]['File'] == 'endpoint_test_1.zip'


def test_get_scripts_command(requests_mock):
    """
        Given:
            - script_name
        When:
            - Requesting for a list of scripts available in the scripts library.
        Then:
            - Assert the returned markdown, context data and raw response are as expected.
        """
    from CoreIRApiModule import get_scripts_command, CoreClient
    from CommonServerPython import timestamp_to_datestring, tableToMarkdown, string_to_table_header

    get_scripts_response = load_test_data('./test_data/get_scripts.json')
    scripts = copy.deepcopy(get_scripts_response.get('reply').get('scripts')[0::50])
    for script in scripts:
        timestamp = script.get('modification_date')
        script['modification_date_timestamp'] = timestamp
        script['modification_date'] = timestamp_to_datestring(timestamp, '%Y-%m-%dT%H:%M:%S')
    headers: list = ['name', 'description', 'script_uid', 'modification_date', 'created_by',
                     'windows_supported', 'linux_supported', 'macos_supported', 'is_high_risk']
    get_scripts_expected_result = {
        'CoreApiModule.Scripts(val.script_uid == obj.script_uid)': scripts
    }
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/get_scripts/', json=get_scripts_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'script_name': 'process_get'
    }

    hr, context, raw_response = get_scripts_command(client, args)

    assert hr == tableToMarkdown(name='Scripts', t=scripts, headers=headers, removeNull=True,
                                 headerTransform=string_to_table_header)
    assert context == get_scripts_expected_result
    assert raw_response == get_scripts_response.get('reply')


def test_get_script_metadata_command(requests_mock):
    """
        Given:
            - A script_uid
        When:
            - Requesting for a given script metadata.
        Then:
            - Assert the returned markdown, context data and raw response are as expected.
        """
    from CoreIRApiModule import get_script_metadata_command, CoreClient
    from CommonServerPython import timestamp_to_datestring, tableToMarkdown, string_to_table_header

    get_script_metadata_response = load_test_data('./test_data/get_script_metadata.json')
    get_scripts_expected_result = {
        'CoreApiModule.ScriptMetadata(val.script_uid == obj.script_uid)': get_script_metadata_response.get(
            'reply')
    }
    script_metadata = copy.deepcopy(get_script_metadata_response).get('reply')
    timestamp = script_metadata.get('modification_date')
    script_metadata['modification_date_timestamp'] = timestamp
    script_metadata['modification_date'] = timestamp_to_datestring(timestamp, '%Y-%m-%dT%H:%M:%S')

    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/get_script_metadata/', json=get_script_metadata_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'script_uid': '956e8989f67ebcb2c71c4635311e47e4'
    }

    hr, context, raw_response = get_script_metadata_command(client, args)

    assert hr == tableToMarkdown(name='Script Metadata', t=script_metadata,
                                 removeNull=True, headerTransform=string_to_table_header)
    assert context == get_scripts_expected_result
    assert raw_response == get_script_metadata_response.get('reply')


def test_get_script_code_command(requests_mock):
    """
        Given:
            - A script_uid.
        When:
            - Requesting the code of a specific script in the script library.
        Then:
            - Assert the returned markdown, context data and raw response are as expected.
        """
    from CoreIRApiModule import get_script_code_command, CoreClient

    get_script_code_command_reply = load_test_data('./test_data/get_script_code.json')
    context = {
        'script_uid': '548023b6e4a01ec51a495ba6e5d2a15d',
        'code': get_script_code_command_reply.get('reply')
    }
    get_script_code_command_expected_result = {
        'CoreApiModule.ScriptCode(val.script_uid == obj.script_uid)':
            context}
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/get_script_code/',
                       json=get_script_code_command_reply)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'script_uid': '548023b6e4a01ec51a495ba6e5d2a15d'
    }

    hr, context, raw_response = get_script_code_command(client, args)

    assert hr == f'### Script code: \n ``` {str(get_script_code_command_reply.get("reply"))} ```'
    assert context == get_script_code_command_expected_result
    assert raw_response == get_script_code_command_reply.get("reply")


def test_action_status_get_command(requests_mock):
    """
        Given:
            - An action_id
        When:
            - Retrieving the status of the requested actions according to the action ID.
        Then:
            - Assert the returned markdown, context data and raw response are as expected.
        """
    from CoreIRApiModule import action_status_get_command, CoreClient
    from CommonServerPython import tableToMarkdown

    action_status_get_command_command_reply = load_test_data('./test_data/action_status_get.json')

    data = action_status_get_command_command_reply.get('reply').get('data')
    result = []
    for item in data:
        result.append({
            'action_id': 1810,
            'endpoint_id': item,
            'status': data.get(item)
        })
    action_status_get_command_expected_result = result

    requests_mock.post(f'{Core_URL}/public_api/v1/actions/get_action_status/',
                       json=action_status_get_command_command_reply)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'action_id': '1810'
    }

    res = action_status_get_command(client, args)
    assert res.readable_output == tableToMarkdown(name='Get Action Status', t=result, removeNull=True)
    assert res.outputs == action_status_get_command_expected_result
    assert res.raw_response == result


def test_sort_by_key__only_main_key():
    """
    Given:
        -  a list of dicts to sort where main key is entered for all elements
        -  the main key to sort by
        -  the fallback key to sort by
    When
        - running sort_by_key
    Then
        - resulting list is sorted by main key only.
    """
    from CoreIRApiModule import sort_by_key
    list_to_sort = [
        {
            "name": "element2",
            "main_key": 2,
            "fallback_key": 4
        },
        {
            "name": "element1",
            "main_key": 1,
            "fallback_key": 3
        },

        {
            "name": "element4",
            "main_key": 4,
            "fallback_key": 2
        },
        {
            "name": "element3",
            "main_key": 3,
            "fallback_key": 1
        }
    ]

    expected_result = [
        {
            "name": "element1",
            "main_key": 1,
            "fallback_key": 3
        },
        {
            "name": "element2",
            "main_key": 2,
            "fallback_key": 4
        },
        {
            "name": "element3",
            "main_key": 3,
            "fallback_key": 1
        },
        {
            "name": "element4",
            "main_key": 4,
            "fallback_key": 2
        }
    ]

    assert expected_result == sort_by_key(list_to_sort, "main_key", "fallback_key")


def test_sort_by_key__main_key_and_fallback_key():
    """
    Given:
        -  a list of dicts to sort where some elements have main key and some don't but they have fallback key
        -  the main key to sort by
        -  the fallback key to sort by
    When
        - running sort_by_key
    Then
        - resulting list is sorted by main key on elements with the main key and
          then sorted by fallback key for elements who dont have it
    """
    from CoreIRApiModule import sort_by_key
    list_to_sort = [
        {
            "name": "element2",
            "fallback_key": 4
        },
        {
            "name": "element1",
            "main_key": 1,
            "fallback_key": 3
        },

        {
            "name": "element4",
            "main_key": None,
            "fallback_key": 2
        },
        {
            "name": "element3",
            "main_key": 3,
            "fallback_key": 1
        }
    ]

    expected_result = [
        {
            "name": "element1",
            "main_key": 1,
            "fallback_key": 3
        },
        {
            "name": "element3",
            "main_key": 3,
            "fallback_key": 1
        },
        {
            "name": "element4",
            "main_key": None,
            "fallback_key": 2
        },
        {
            "name": "element2",
            "fallback_key": 4
        },
    ]

    assert expected_result == sort_by_key(list_to_sort, "main_key", "fallback_key")


def test_sort_by_key__only_fallback_key():
    """
    Given:
        -  a list of dicts to sort where main key is not entered for all elements and fallback key is.
        -  the main key to sort by
        -  the fallback key to sort by
    When
        - running sort_by_key
    Then
        - resulting list is sorted by fallback key only.
    """
    from CoreIRApiModule import sort_by_key
    list_to_sort = [
        {
            "name": "element2",
            "fallback_key": 4
        },
        {
            "name": "element1",
            "fallback_key": 3
        },
        {
            "name": "element4",
            "fallback_key": 2
        },
        {
            "name": "element3",
            "fallback_key": 1
        }
    ]

    expected_result = [
        {
            "name": "element3",
            "fallback_key": 1
        },
        {
            "name": "element4",
            "fallback_key": 2
        },
        {
            "name": "element1",
            "fallback_key": 3
        },
        {
            "name": "element2",
            "fallback_key": 4
        },
    ]

    assert expected_result == sort_by_key(list_to_sort, "main_key", "fallback_key")


def test_sort_by_key__main_key_and_fallback_key_and_additional():
    """
    Given:
        -  a list of dicts to sort where main key is entered for some elements, fallback for others
           and some dont have either
        -  the main key to sort by
        -  the fallback key to sort by
    When
        - running sort_by_key
    Then
        - resulting list is sorted by main key for elements with main key,
          then by fallback key for those with fallback key and then the rest of the elements that dont have either key.
    """
    from CoreIRApiModule import sort_by_key
    list_to_sort = [
        {
            "name": "element2",
            "fallback_key": 4
        },
        {
            "name": "element1",
            "main_key": 1,
            "fallback_key": 3
        },

        {
            "name": "element4",
            "main_key": None,
            "fallback_key": None
        },
        {
            "name": "element3",
            "main_key": 3,
            "fallback_key": 1
        }
    ]

    expected_result = [
        {
            "name": "element1",
            "main_key": 1,
            "fallback_key": 3
        },
        {
            "name": "element3",
            "main_key": 3,
            "fallback_key": 1
        },
        {
            "name": "element2",
            "fallback_key": 4
        },
        {
            "name": "element4",
            "main_key": None,
            "fallback_key": None
        },
    ]

    assert expected_result == sort_by_key(list_to_sort, "main_key", "fallback_key")


def test_create_account_context_with_data():
    """
    Given:
        - get_endpoints command
    When
        - creating the account context from the response succeeds - which means there exists both domain and user in the
         response.
    Then
        - verify the context is created successfully.
    """
    from CoreIRApiModule import create_account_context
    get_endpoints_response = load_test_data('./test_data/get_endpoints.json')
    endpoints_list = get_endpoints_response.get('reply').get('endpoints')
    endpoints_list[0]['domain'] = 'test.domain'

    account_context = create_account_context(endpoints_list)

    assert account_context == [{'Username': 'ec2-user', 'Domain': 'test.domain'}]


def test_create_account_context_no_domain():
    """
    Given:
        - get_endpoints command
    When
        -  the endpoint is missing a domain - which means an account context can't be created.
    Then
        - verify the account context is an empty list and the method is finished with no errors.
    """
    from CoreIRApiModule import create_account_context
    get_endpoints_response = load_test_data('./test_data/get_endpoints.json')
    endpoints_list = get_endpoints_response.get('reply').get('endpoints')
    account_context = create_account_context(endpoints_list)

    assert account_context == []


def test_create_account_context_user_is_none():
    """
    Given:
        - get_endpoints command
    When
        -  the user value is None - which means an account context can't be created.
    Then
        - verify the account context is an empty list and the method is finished with no errors.
    """
    from CoreIRApiModule import create_account_context
    get_endpoints_response = load_test_data('./test_data/get_endpoints.json')
    endpoints_list = get_endpoints_response.get('reply').get('endpoints')
    endpoints_list[0]['user'] = None

    account_context = create_account_context(endpoints_list)

    assert account_context == []


def test_run_script_command(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs, script UID, script parameters and incident ID
    When
        - Running run-script command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_script_command, CoreClient

    api_response = load_test_data('./test_data/run_script.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_script/', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    script_uid = 'script_uid'
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    parameters = '{"param1":"value1","param2":2}'
    args = {
        'script_uid': script_uid,
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
        'parameters': parameters,
        'incident_id': '4',
    }

    response = run_script_command(client, args)

    assert response.outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'script_uid': script_uid,
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': json.loads(parameters)
        }
    }


def test_run_script_command_empty_params(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs, script UID, empty params and incident ID
    When
        - Running run-script command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_script_command, CoreClient

    api_response = load_test_data('./test_data/run_script.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_script/', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    script_uid = 'script_uid'
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    parameters = ''
    args = {
        'script_uid': script_uid,
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
        'parameters': parameters,
        'incident_id': '4',
    }

    response = run_script_command(client, args)

    assert response.outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'script_uid': script_uid,
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {}
        }
    }


def test_run_snippet_code_script_command_no_incident_id(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs and snippet code
    When
        - Running run-snippet-code-script command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_snippet_code_script_command, CoreClient

    api_response = load_test_data('./test_data/run_script.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_snippet_code_script', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    snippet_code = 'print("hello world")'
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    args = {
        'snippet_code': snippet_code,
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
    }

    response = run_snippet_code_script_command(client, args)

    assert response.outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'snippet_code': snippet_code,
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
        }
    }


def test_run_snippet_code_script_command(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs snippet code and incident ID
    When
        - Running run-snippet-code-script command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_snippet_code_script_command, CoreClient

    api_response = load_test_data('./test_data/run_script.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_snippet_code_script', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    snippet_code = 'print("hello world")'
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    args = {
        'snippet_code': snippet_code,
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
        'incident_id': '4',
    }

    response = run_snippet_code_script_command(client, args)

    assert response.outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'snippet_code': snippet_code,
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4
        }
    }


def test_get_script_execution_status_command(requests_mock):
    """
    Given:
        - Core client
        - Action ID
    When
        - Running get-script-execution-status command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import get_script_execution_status_command, CoreClient

    api_response = load_test_data('./test_data/get_script_execution_status.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/get_script_execution_status/', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    action_id = '1'
    args = {
        'action_id': action_id
    }

    response = get_script_execution_status_command(client, args)

    api_response['reply']['action_id'] = int(action_id)
    assert response[0].outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'action_id': action_id
        }
    }


def test_get_script_execution_results_command(requests_mock):
    """
    Given:
        - Core client
        - Action ID
    When
        - Running get-script-execution-results command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import get_script_execution_results_command, CoreClient

    api_response = load_test_data('./test_data/get_script_execution_results.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/get_script_execution_results', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    action_id = '1'
    args = {
        'action_id': action_id
    }

    response = get_script_execution_results_command(client, args)

    expected_output = {
        'action_id': int(action_id),
        'results': api_response.get('reply').get('results')
    }
    assert response[0].outputs == expected_output
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'action_id': action_id
        }
    }


def test_get_script_execution_files_command(requests_mock, mocker, request):
    """
    Given:
        - Core client
        - Action ID and endpoint ID
    When
        - Running get-script-execution-files command
    Then
        - Verify file name is extracted
        - Verify output ZIP file contains text file
    """
    from CoreIRApiModule import get_script_execution_result_files_command, CoreClient
    mocker.patch.object(demisto, 'uniqueFile', return_value="test_file_result")
    mocker.patch.object(demisto, 'investigation', return_value={'id': '1'})
    file_name = "1_test_file_result"

    def cleanup():
        try:
            os.remove(file_name)
        except OSError:
            pass

    request.addfinalizer(cleanup)
    zip_link = 'https://example-link'
    zip_filename = 'file.zip'
    requests_mock.post(
        f'{Core_URL}/public_api/v1/scripts/get_script_execution_results_files',
        json={'reply': {'DATA': zip_link}}
    )
    requests_mock.get(
        zip_link,
        content=b'PK\x03\x04\x14\x00\x00\x00\x00\x00%\x98>R\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x00\x00'
                b'\x00your_file.txtPK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00%\x98>R\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb6\x81\x00\x00\x00\x00your_file'
                b'.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00;\x00\x00\x00+\x00\x00\x00\x00\x00',
        headers={
            'Content-Disposition': f'attachment; filename={zip_filename}'
        }
    )

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    action_id = 'action_id'
    endpoint_id = 'endpoint_id'
    args = {
        'action_id': action_id,
        'endpoint_id': endpoint_id
    }

    response = get_script_execution_result_files_command(client, args)
    assert response['File'] == zip_filename
    assert zipfile.ZipFile(file_name).namelist() == ['your_file.txt']


def test_run_script_execute_commands_command(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs, shell commands and incident ID
    When
        - Running run-script-execute-commands command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_script_execute_commands_command, CoreClient

    api_response = load_test_data('./test_data/run_script.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_script/', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    commands = 'echo hi'
    args = {
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
        'commands': commands,
        'incident_id': '4',
    }

    response = run_script_execute_commands_command(client, args)

    assert response.outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'script_uid': 'a6f7683c8e217d85bd3c398f0d3fb6bf',
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {'commands_list': commands.split(',')}
        }
    }


def test_run_script_delete_file_command(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs, file path and incident ID
    When
        - Running run-script-delete-file command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_script_delete_file_command, CoreClient

    api_response = load_test_data('./test_data/run_script.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_script/', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    file_path = 'my_file.txt'
    args = {
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
        'file_path': file_path,
        'incident_id': '4',
    }

    response = run_script_delete_file_command(client, args)

    assert response[0].outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'script_uid': '548023b6e4a01ec51a495ba6e5d2a15d',
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {'file_path': args.get('file_path')}
        }
    }


def test_run_script_delete_multiple_files_command(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs, files paths and incident ID
    When
        - Running run-script-delete-file command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_script_delete_file_command, CoreClient

    api_response = load_test_data('./test_data/run_script_multiple_inputs_and_endpoints.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_script/', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    file_path = 'my_file.txt,test.txt'
    args = {
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
        'file_path': file_path,
        'incident_id': '4',
    }

    response = run_script_delete_file_command(client, args)

    assert response[0].outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'script_uid': '548023b6e4a01ec51a495ba6e5d2a15d',
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {'file_path': 'my_file.txt'}
        }
    }
    assert requests_mock.request_history[1].json() == {
        'request_data': {
            'script_uid': '548023b6e4a01ec51a495ba6e5d2a15d',
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {'file_path': 'test.txt'}
        }
    }


def test_run_script_file_exists_command(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs, file path and incident ID
    When
        - Running run-script-file-exists command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_script_file_exists_command, CoreClient

    api_response = load_test_data('./test_data/run_script.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_script/', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    file_path = 'my_file.txt'
    args = {
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
        'file_path': file_path,
        'incident_id': '4',
    }

    response = run_script_file_exists_command(client, args)

    assert response[0].outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'script_uid': '414763381b5bfb7b05796c9fe690df46',
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {'path': args.get('file_path')}
        }
    }


def test_run_script_file_exists_multiple_files_command(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs, files paths and incident ID
    When
        - Running run-script-file-exists command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_script_file_exists_command, CoreClient

    api_response = load_test_data('./test_data/run_script_multiple_inputs_and_endpoints.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_script/', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    file_path = 'my_file.txt,test.txt'
    args = {
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
        'file_path': file_path,
        'incident_id': '4',
    }

    response = run_script_file_exists_command(client, args)

    assert response[0].outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'script_uid': '414763381b5bfb7b05796c9fe690df46',
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {'path': 'my_file.txt'}
        }
    }
    assert requests_mock.request_history[1].json() == {
        'request_data': {
            'script_uid': '414763381b5bfb7b05796c9fe690df46',
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {'path': 'test.txt'}
        }
    }


def test_run_script_kill_process_command(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs, process name and incident ID
    When
        - Running run-script-kill-process command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_script_kill_process_command, CoreClient

    api_response = load_test_data('./test_data/run_script.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_script/', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    process_name = 'process.exe'
    args = {
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
        'process_name': process_name,
        'incident_id': '4',
    }

    response = run_script_kill_process_command(client, args)

    assert response[0].outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'script_uid': 'fd0a544a99a9421222b4f57a11839481',
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {'process_name': process_name}
        }
    }


def test_run_script_kill_multiple_processes_command(requests_mock):
    """
    Given:
        - Core client
        - Endpoint IDs, multiple processes names and incident ID
    When
        - Running run-script-kill-process command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import run_script_kill_process_command, CoreClient

    api_response = load_test_data('./test_data/run_script_multiple_inputs_and_endpoints.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/scripts/run_script/', json=api_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    endpoint_ids = 'endpoint_id1,endpoint_id2'
    timeout = '10'
    processes_names = 'process1.exe,process2.exe'
    args = {
        'endpoint_ids': endpoint_ids,
        'timeout': timeout,
        'process_name': processes_names,
        'incident_id': '4',
    }

    response = run_script_kill_process_command(client, args)

    assert response[0].outputs == api_response.get('reply')
    assert requests_mock.request_history[0].json() == {
        'request_data': {
            'script_uid': 'fd0a544a99a9421222b4f57a11839481',
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {'process_name': 'process1.exe'}
        }
    }
    assert requests_mock.request_history[1].json() == {
        'request_data': {
            'script_uid': 'fd0a544a99a9421222b4f57a11839481',
            'timeout': int(timeout),
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids.split(',')
            }],
            'incident_id': 4,
            'parameters_values': {'process_name': 'process2.exe'}
        }
    }


CONNECTED_STATUS = {
    'endpoint_status': 'Connected',
    'is_isolated': 'Isolated',
    'host_name': 'TEST',
    'ip': '1.1.1.1'
}

NO_STATUS = {
    'is_isolated': 'Isolated',
    'host_name': 'TEST',
    'ip': '1.1.1.1'
}

OFFLINE_STATUS = {
    'endpoint_status': 'Offline',
    'is_isolated': 'Isolated',
    'host_name': 'TEST',
    'ip': '1.1.1.1'
}


@pytest.mark.parametrize("endpoint, expected", [
    (CONNECTED_STATUS, 'Online'),
    (NO_STATUS, 'Offline'),
    (OFFLINE_STATUS, 'Offline')
])
def test_get_endpoint_properties(endpoint, expected):
    """
    Given:
        - Endpoint data
    When
        - The status of the enndpoint is 'Connected' with a capital C.
    Then
        - The status of the endpointn is determined to be 'Online'
    """
    from CoreIRApiModule import get_endpoint_properties

    status, is_isolated, hostname, ip = get_endpoint_properties(endpoint)
    assert status == expected


def test_get_update_args_when_getting_close_reason():
    """
    Given:
        - closingUserId from update_remote_system
    When
        - An incident in XSOAR was closed with "Duplicate" as a close reason.
    Then
        - The status that the incident is getting to be mirrored out is "resolved_duplicate"
    """
    from CoreIRApiModule import get_update_args
    update_args = get_update_args({'closeReason': 'Duplicate', 'closeNote': 'Closed as Duplicate.',
                                   'closingUserId': 'Admin'}, 2)
    assert update_args.get('status') == 'resolved_duplicate'
    assert update_args.get('closeNote') == 'Closed as Duplicate.'


def test_get_update_args_when_not_getting_close_reason():
    """
    Given:
        - delta from update_remote_system
    When
        - An incident in XSOAR was closed and update_remote_system has occurred.
    Then
        - Because There is no change in the "closeReason" value, the status should not change.
    """
    from CoreIRApiModule import get_update_args
    update_args = get_update_args({'someChange': '1234'}, 2)
    assert update_args.get('status') is None


def test_remove_blocklist_files_command(requests_mock):
    """
    Given:
        - List of files' hashes to remove from blocklist.
    When
        - A user desires to remove blocklist files.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import remove_blocklist_files_command, CoreClient

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    remove_blocklist_files_response = load_test_data('./test_data/remove_blocklist_files.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/hash_exceptions/blocklist/remove/', json=remove_blocklist_files_response)
    hash_list = ["11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a25b",
                 "e5ab4d81607668baf7d196ae65c9cf56dd138e3fe74c4bace4765324a9e1c565"]
    res = remove_blocklist_files_command(client=client, args={
        "hash_list": hash_list,
        "comment": "",
        "incident_id": 606})
    markdown_data = [{'removed_hashes': file_hash} for file_hash in hash_list]
    assert res.readable_output == tableToMarkdown('Blocklist Files Removed',
                                                  markdown_data,
                                                  headers=['removed_hashes'],
                                                  headerTransform=pascalToSpace)


def test_blocklist_files_command_with_detailed_response(requests_mock):
    """
    Given:
        - List of files' hashes to add in blocklist with detailed_response.
    When
        - A user desires to blocklist files with detailed_response.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import blocklist_files_command, CoreClient

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    blocklist_files_response = load_test_data('./test_data/add_blocklist_files_detailed_response.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/hash_exceptions/blocklist/', json=blocklist_files_response)
    hash_list = ["11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a25b",
                 "e5ab4d81607668baf7d196ae65c9cf56dd138e3fe74c4bace4765324a9e1c565"]
    res = blocklist_files_command(client=client, args={
        "hash_list": hash_list,
        "comment": "",
        "incident_id": 606,
        "detailed_response": "true"})
    assert res.readable_output == tableToMarkdown('Blocklist Files', res.raw_response)


def test_remove_allowlist_files_command(requests_mock):
    """
    Given:
        - List of files' hashes to remove from allowlist.
    When
        - A user desires to remove allowlist files.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import remove_allowlist_files_command, CoreClient

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    remove_allowlist_files_response = load_test_data('./test_data/remove_blocklist_files.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/hash_exceptions/allowlist/remove/', json=remove_allowlist_files_response)
    hash_list = ["11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a25b",
                 "e5ab4d81607668baf7d196ae65c9cf56dd138e3fe74c4bace4765324a9e1c565"]
    res = remove_allowlist_files_command(client=client, args={
        "hash_list": hash_list,
        "comment": "",
        "incident_id": 606})
    markdown_data = [{'removed_hashes': file_hash} for file_hash in hash_list]
    assert res.readable_output == tableToMarkdown('Allowlist Files Removed',
                                                  markdown_data,
                                                  headers=['removed_hashes'],
                                                  headerTransform=pascalToSpace)


def test_allowlist_files_command_with_detailed_response(requests_mock):
    """
    Given:
        - List of files' hashes to add in allowlist with detailed_response.
    When
        - A user desires to allowlist files with detailed_response.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import allowlist_files_command, CoreClient

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )

    allowlist_files_response = load_test_data('./test_data/add_blocklist_files_detailed_response.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/hash_exceptions/allowlist/', json=allowlist_files_response)
    hash_list = ["11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a25b",
                 "e5ab4d81607668baf7d196ae65c9cf56dd138e3fe74c4bace4765324a9e1c565"]
    res = allowlist_files_command(client=client,
                                  args={
                                      "hash_list": hash_list,
                                      "comment": "",
                                      "incident_id": 606,
                                      "detailed_response": "true"
                                  })
    assert res.readable_output == tableToMarkdown('Allowlist Files', res.raw_response)


def test_decode_dict_values():
    """
    Given:
        - a dict to decode
    When
        - Running decode_dict_values command
    Then
        - Verify expected output
    """
    from CoreIRApiModule import decode_dict_values

    test_dict: dict = {
        'x': 1,
        'y': 'test',
        'z': '{\"a\": \"test1\", \"b\": \"test2\"}',
        'w': {
            't': '{\"a\": \"test1\", \"b\": \"test2\"}',
            'm': 'test3'
        }
    }
    decode_dict_values(test_dict)
    assert test_dict == {
        'x': 1,
        'y': 'test',
        'z': {"a": "test1", "b": "test2"},
        'w': {
            't': {"a": "test1", "b": "test2"},
            'm': 'test3'
        }
    }


def test_filter_vendor_fields():
    """
    Given:
        - An alert dict to filter
    When
        - Running test_filter_vendor_fields command
    Then
        - Verify that the vendor fields were filtered properly
    """
    from CoreIRApiModule import filter_vendor_fields

    alert = {
        'x': 1,
        'event': {
            'vendor': 'Amazon',
            'raw_log': {
                'eventSource': 'test1',
                'requestID': 'test2',
                'should_be_filter': 'N',
            }
        }
    }
    filter_vendor_fields(alert)
    assert alert == {
        'x': 1,
        'event': {
            'vendor': 'Amazon',
            'raw_log': {
                'eventSource': 'test1',
                'requestID': 'test2',
            }
        }
    }


def test_filter_general_fields():
    """
    Given:
        - An alert dict
    When
        - Running filter_general_fields command
    Then
        - Verify expected output
    """
    from CoreIRApiModule import filter_general_fields
    alert = {
        'detection_modules': 'test1',
        "content_version": "version1",
        "detector_id": 'ID',
        'should_be_filtered1': 'N',
        'should_be_filtered2': 'N',
        'should_be_filtered3': 'N',
        'raw_abioc': {
            'event': {
                'event_type': 'type',
                'event_id': 'id',
                'identity_sub_type': 'subtype',
                'should_be_filtered1': 'N',
                'should_be_filtered2': 'N',
                'should_be_filtered3': 'N',
            }
        }
    }
    assert filter_general_fields(alert) == {
        'detection_modules': 'test1',
        "content_version": "version1",
        "detector_id": 'ID',
        'event': {
            'event_type': 'type',
            'event_id': 'id',
            'identity_sub_type': 'subtype',
        }
    }


def test_filter_general_fields_no_event(mocker):
    """
    Given:
        - An alert dict with no event
    When
        - Running filter_general_fields command
    Then
        - Verify a warning is printed and the program exits
    """
    from CoreIRApiModule import filter_general_fields
    alert = {
        'detection_modules': 'test1',
        "content_version": "version1",
        "detector_id": 'ID',
        'should_be_filtered1': 'N',
        'should_be_filtered2': 'N',
        'should_be_filtered3': 'N',
        'raw_abioc': {
        }
    }
    err = mocker.patch('CoreIRApiModule.return_warning')
    filter_general_fields(alert)
    assert err.call_args[0][0] == "No XDR cloud analytics event."


def test_add_exclusion_command(requests_mock):
    """
    Given:
        - FilterObject and name to add to exclision.
    When
        - A user desires to add exclusion.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import add_exclusion_command, CoreClient
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    add_exclusion_response = load_test_data('./test_data/add_exclusion_response.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/alerts_exclusion/add/', json=add_exclusion_response)
    res = add_exclusion_command(
        client=client,
        args={
            'filterObject': '{\"filter\":{\"AND\":[{\"SEARCH_FIELD\":\"alert_category\",'
                            '\"SEARCH_TYPE\":\"NEQ\",\"SEARCH_VALUE\":\"Phishing\"}]}}',
            'name': 'test1'
        }
    )
    expected_res = add_exclusion_response.get("reply")
    assert res.readable_output == tableToMarkdown('Add Exclusion', expected_res)


def test_delete_exclusion_command(requests_mock):
    """
    Given:
        - alert_exclusion_id of the exclusion to delete.
    When
        - A user desires to delete exclusion.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import delete_exclusion_command, CoreClient
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    delete_exclusion_response = load_test_data('./test_data/delete_exclusion_response.json')
    alert_exclusion_id = 42
    requests_mock.post(f'{Core_URL}/public_api/v1/alerts_exclusion/delete/', json=delete_exclusion_response)
    res = delete_exclusion_command(
        client=client,
        args={
            'alert_exclusion_id': alert_exclusion_id
        }
    )
    assert res.readable_output == f"Successfully deleted the following exclusion: {alert_exclusion_id}"


def test_get_exclusion_command(requests_mock):
    """
    Given:
        - FilterObject and name to get by exclisions.
    When
        - A user desires to get exclusions.
    Then
        - returns markdown, context data and raw response.
    """
    from CoreIRApiModule import get_exclusion_command, CoreClient
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    get_exclusion_response = load_test_data('./test_data/get_exclusion_response.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/alerts_exclusion/', json=get_exclusion_response)
    res = get_exclusion_command(
        client=client,
        args={}
    )
    expected_result = get_exclusion_response.get('reply')
    assert res.readable_output == tableToMarkdown('Exclusion', expected_result)


def test_get_original_alerts_command(requests_mock):
    """
    Given:
        - Core client
        - Alert IDs
    When
        - Running get_original_alerts_command command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import get_original_alerts_command, CoreClient
    api_response = load_test_data('./test_data/get_original_alerts_results.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_original_alerts/', json=api_response)
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'alert_ids': '2',
    }

    response = get_original_alerts_command(client, args)
    event = response.outputs[0].get('event', {})
    assert event.get('_time') == 'DATE'  # assert general filter is correct
    assert event.get('cloud_provider') == 'AWS'  # assert general filter is correct
    assert event.get('raw_log', {}).get('userIdentity', {}).get('accountId') == 'ID'  # assert vendor filter is correct


def test_get_dynamic_analysis(requests_mock):
    """
    Given:
        - Core client
        - Alert IDs
    When
        - Running get_dynamic_analysis_command command
    Then
        - Verify expected output
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import get_dynamic_analysis_command, CoreClient
    api_response = load_test_data('./test_data/get_dynamic_analysis.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_original_alerts/', json=api_response)
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'alert_ids': '6536',
    }

    response = get_dynamic_analysis_command(client, args)
    dynamic_analysis = response.outputs[0]
    assert dynamic_analysis.get('causalityId') == 'AAA'


def test_parse_get_script_execution_results():
    from CoreIRApiModule import parse_get_script_execution_results
    results = [{'endpoint_name': 'endpoint_name', 'endpoint_ip_address': ['1.1.1.1'], 'endpoint_status': 'endpoint_status',
                'domain': 'env', 'endpoint_id': 'endpoint_id', 'execution_status': 'COMPLETED_SUCCESSFULLY',
                'standard_output': 'Running command "command_executed"', 'retrieved_files': 0, 'failed_files': 0,
                'retention_date': None, 'command_executed': ['command_output']}]
    res = parse_get_script_execution_results(results)
    expected_res = [{'endpoint_name': 'endpoint_name', 'endpoint_ip_address': ['1.1.1.1'], 'endpoint_status': 'endpoint_status',
                     'domain': 'env', 'endpoint_id': 'endpoint_id', 'execution_status': 'COMPLETED_SUCCESSFULLY',
                     'standard_output': 'Running command "command_executed"', 'retrieved_files': 0, 'failed_files': 0,
                     'retention_date': None, 'command_executed': ['command_output'], 'command': 'command_executed',
                     'command_output': ['command_output']}]
    assert res == expected_res


class TestGetAlertByFilter:

    @freeze_time("2022-05-03 11:00:00 GMT")
    def test_get_alert_by_filter(self, requests_mock, mocker):
        """
        Given:
            - Core client
            - timeframe, start_time, end_time
        When
            - Running get_alerts_by_filter command
        Then
            - Verify expected output
            - Ensure request filter sent as expected
        """
        from CoreIRApiModule import get_alerts_by_filter_command, CoreClient
        api_response = load_test_data('./test_data/get_alerts_by_filter_results.json')
        requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_alerts_by_filter_data/', json=api_response)
        request_data_log = mocker.patch.object(demisto, 'debug')
        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )
        args = {
            'time_frame': "custom",
            'start_time': '2018-11-06T08:56:41',
            'end_time': '2018-11-06T08:56:41',
            "limit": '2',
        }
        response = get_alerts_by_filter_command(client, args)
        assert response.outputs[0].get('internal_id', {}) == 33333
        assert "{'filter_data': {'sort': [{'FIELD': 'source_insert_ts', 'ORDER': 'DESC'}], 'paging': {'from': 0, " \
               "'to': 2}, 'filter': {'AND': [{'SEARCH_FIELD': 'source_insert_ts', 'SEARCH_TYPE': 'RANGE', 'SEARCH_VALUE': " \
               "{'from': 1541494601000, 'to': 1541494601000}}]}}}" in request_data_log.call_args[0][0]

    def test_get_alert_by_filter_command_multiple_values_in_same_arg(self, requests_mock, mocker):
        """
        Given:
            - Core client
            - alert_source
        When
            - Running get_alerts_by_filter command
        Then
            - Verify expected output
            - Ensure request filter sent as expected (connected with OR operator)
        """
        from CoreIRApiModule import get_alerts_by_filter_command, CoreClient
        api_response = load_test_data('./test_data/get_alerts_by_filter_results.json')
        requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_alerts_by_filter_data/', json=api_response)
        request_data_log = mocker.patch.object(demisto, 'debug')
        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )
        args = {
            'alert_source': "first,second",
        }
        response = get_alerts_by_filter_command(client, args)
        assert response.outputs[0].get('internal_id', {}) == 33333
        assert "{'filter_data': {'sort': [{'FIELD': 'source_insert_ts', 'ORDER': 'DESC'}], 'paging': {'from': 0, " \
               "'to': 50}, 'filter': {'AND': [{'OR': [{'SEARCH_FIELD': 'alert_source', 'SEARCH_TYPE': 'CONTAINS', " \
               "'SEARCH_VALUE': 'first'}, {'SEARCH_FIELD': 'alert_source', 'SEARCH_TYPE': 'CONTAINS', 'SEARCH_VALUE': " \
               "'second'}]}]}}}" in request_data_log.call_args[0][0]

    def test_get_alert_by_filter_command_multiple_args(self, requests_mock, mocker):
        """
        Given:
            - Core client
            - alert_source
            - user_name
        When
            - Running get_alerts_by_filter command
        Then
            - Verify expected output
            - Ensure request filter sent as expected (connected with AND operator)
        """
        from CoreIRApiModule import get_alerts_by_filter_command, CoreClient
        api_response = load_test_data('./test_data/get_alerts_by_filter_results.json')
        requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_alerts_by_filter_data/', json=api_response)
        request_data_log = mocker.patch.object(demisto, 'debug')
        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )
        args = {
            'alert_source': "first,second",
            'user_name': 'N/A'
        }
        response = get_alerts_by_filter_command(client, args)
        assert response.outputs[0].get('internal_id', {}) == 33333
        assert "{'AND': [{'OR': [{'SEARCH_FIELD': 'alert_source', 'SEARCH_TYPE': 'CONTAINS', " \
               "'SEARCH_VALUE': 'first'}, {'SEARCH_FIELD': 'alert_source', 'SEARCH_TYPE': 'CONTAINS', 'SEARCH_VALUE': " \
               "'second'}]}, {'OR': [{'SEARCH_FIELD': 'actor_effective_username', 'SEARCH_TYPE': 'CONTAINS', " \
               "'SEARCH_VALUE': 'N/A'}]}]}" in request_data_log.call_args[0][0]

    @freeze_time('2022-05-26T13:00:00Z')
    def test_get_alert_by_filter_complex_custom_filter_and_timeframe(self, requests_mock, mocker):
        """
        Given:
            - Core client
            - custom_filter (filters are connected with AND operator)
            - timeframe
        When
            - Running get_alerts_by_filter command
        Then
            - Verify expected output
            - Ensure request filter sent as expected (connected with AND operator)
        """
        import dateparser
        from datetime import datetime as dt
        from CoreIRApiModule import get_alerts_by_filter_command, CoreClient

        custom_filter = '{"AND": [{"OR": [{"SEARCH_FIELD": "alert_source","SEARCH_TYPE": "EQ","SEARCH_VALUE": "CORRELATION"},' \
                        '{"SEARCH_FIELD": "alert_source","SEARCH_TYPE": "EQ","SEARCH_VALUE": "IOC"}]},' \
                        '{"SEARCH_FIELD": "severity","SEARCH_TYPE": "EQ","SEARCH_VALUE": "SEV_040_HIGH"}]}'
        api_response = load_test_data('./test_data/get_alerts_by_filter_results.json')
        requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_alerts_by_filter_data/', json=api_response)
        request_data_log = mocker.patch.object(demisto, 'debug')
        mocker.patch.object(dateparser, 'parse', return_value=dt(year=2022, month=5, day=24, hour=13, minute=0, second=0))
        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )
        args = {
            'custom_filter': custom_filter,
            'time_frame': '2 days'
        }
        get_alerts_by_filter_command(client, args)
        assert "{'filter_data': {'sort': [{'FIELD': 'source_insert_ts', 'ORDER': 'DESC'}], " \
               "'paging': {'from': 0, 'to': 50}, " \
               "'filter': {'AND': [{'SEARCH_FIELD': 'source_insert_ts', 'SEARCH_TYPE': 'RELATIVE_TIMESTAMP', " \
               "'SEARCH_VALUE': '172800000'}, " \
               "{'OR': [{'SEARCH_FIELD': 'alert_source', 'SEARCH_TYPE': 'EQ', 'SEARCH_VALUE': 'CORRELATION'}, " \
               "{'SEARCH_FIELD': 'alert_source', 'SEARCH_TYPE': 'EQ', 'SEARCH_VALUE': 'IOC'}]}, " \
               "{'SEARCH_FIELD': 'severity', 'SEARCH_TYPE': 'EQ', 'SEARCH_VALUE': 'SEV_040_HIGH'}]}}}" \
               in request_data_log.call_args[0][0]

    @freeze_time('2022-05-26T13:00:00Z')
    def test_get_alert_by_filter_custom_filter_and_timeframe_(self, requests_mock, mocker):
        """
        Given:
            - Core client
            - custom_filter (filters are connected with OR operator)
            - timeframe
        When
            - Running get_alerts_by_filter command
        Then
            - Verify expected output
            - Ensure request filter sent as expected (connected with AND operator)
        """
        import dateparser
        from datetime import datetime as dt
        from CoreIRApiModule import get_alerts_by_filter_command, CoreClient

        custom_filter = '{"OR": [{"SEARCH_FIELD": "actor_process_image_sha256",' \
                        '"SEARCH_TYPE": "EQ",' \
                        '"SEARCH_VALUE": "222"}]}'
        api_response = load_test_data('./test_data/get_alerts_by_filter_results.json')
        requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_alerts_by_filter_data/', json=api_response)
        request_data_log = mocker.patch.object(demisto, 'debug')
        mocker.patch.object(dateparser, 'parse', return_value=dt(year=2022, month=5, day=24, hour=13, minute=0, second=0))
        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )
        args = {
            'custom_filter': custom_filter,
            'time_frame': '2 days'
        }
        get_alerts_by_filter_command(client, args)
        assert "{'filter_data': {'sort': [{'FIELD': 'source_insert_ts', 'ORDER': 'DESC'}], " \
               "'paging': {'from': 0, 'to': 50}, " \
               "'filter': {'AND': [{'SEARCH_FIELD': 'source_insert_ts', 'SEARCH_TYPE': 'RELATIVE_TIMESTAMP', " \
               "'SEARCH_VALUE': '172800000'}, " \
               "{'OR': [{'SEARCH_FIELD': 'actor_process_image_sha256', 'SEARCH_TYPE': 'EQ'," \
               " 'SEARCH_VALUE': '222'}]}]}" in request_data_log.call_args[0][0]


class TestPollingCommands:

    @staticmethod
    def create_mocked_responses(status_count):

        response_queue = [  # xdr-run-script response
            {
                "reply": {
                    "action_id": 1,
                    "status": 1,
                    "endpoints_count": 1
                }
            }
        ]

        for i in range(status_count):
            if i == status_count - 1:
                general_status = 'COMPLETED_SUCCESSFULLY'
            elif i < 2:
                general_status = 'PENDING'
            else:
                general_status = 'IN_PROGRESS'

            response_queue.append(
                {
                    "reply": {  # get script status response
                        "general_status": general_status,
                        "endpoints_pending": 1 if i < 2 else 0,
                        "endpoints_in_progress": 0 if i < 2 else 1,
                    }
                }
            )
            response_queue.append(
                {
                    "reply": {   # get script execution result response
                        "script_name": "snippet script",
                        "error_message": "",
                        "results": [
                            {
                                "endpoint_name": "test endpoint",
                                "endpoint_ip_address": [
                                    "1.1.1.1"
                                ],
                                "endpoint_status": "STATUS_010_CONNECTED",
                                "domain": "aaaa",
                                "endpoint_id": "1",
                                "execution_status": "COMPLETED_SUCCESSFULLY",
                                "failed_files": 0,
                            }
                        ]
                    }
                }
            )

        return response_queue

    @pytest.mark.parametrize(argnames='status_count', argvalues=[1, 3, 7, 9, 12, 15])
    def test_script_run_command(self, mocker, status_count):
        """
        Given -
            xdr-script-run command arguments including polling true where each time a different amount of response
            is returned.

        When -
            Running the xdr-script-run

        Then
            - Make sure the readable output is returned to war-room only once indicating on polling.
            - Make sure the correct context output is returned once the command finished polling
            - Make sure context output is returned only at the end of polling.
            - Make sure the readable output is returned only in the first run.
            - Make sure the correct output prefix is returned.
        """
        from CoreIRApiModule import script_run_polling_command
        from CommonServerPython import ScheduledCommand

        client = CoreClient(base_url='https://test_api.com/public_api/v1', headers={})

        mocker.patch.object(client, '_http_request', side_effect=self.create_mocked_responses(status_count))
        mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

        command_result = script_run_polling_command({'endpoint_ids': '1', 'script_uid': '1'}, client)

        assert command_result.readable_output == "Waiting for the script to " \
                                                 "finish running on the following endpoints: ['1']..."
        assert not command_result.outputs

        polling_args = {
            'endpoint_ids': '1', 'script_uid': '1', 'action_id': '1', 'hide_polling_output': True
        }

        command_result = script_run_polling_command(polling_args, client)
        # if scheduled_command is set, it means that command should still poll
        while not isinstance(command_result, list) and command_result.scheduled_command:
            # if command result is a list, it means command execution finished
            assert not command_result.readable_output  # make sure that indication of polling is printed only once
            assert not command_result.outputs  # make sure no context output is being returned to war-room during polling
            command_result = script_run_polling_command(polling_args, client)

        assert command_result[0].outputs == {
            'action_id': 1,
            'results': [
                {
                    'endpoint_name': 'test endpoint',
                    'endpoint_ip_address': ['1.1.1.1'],
                    'endpoint_status': 'STATUS_010_CONNECTED',
                    'domain': 'aaaa',
                    'endpoint_id': '1',
                    'execution_status': 'COMPLETED_SUCCESSFULLY',
                    'failed_files': 0
                }
            ]
        }
        assert command_result[0].outputs_prefix == 'PaloAltoNetworksXDR.ScriptResult'
