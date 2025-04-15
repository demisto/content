import copy
from freezegun import freeze_time
import json
import os
import zipfile
from typing import Any
from pytest_mock import MockerFixture
import pytest

import demistomock
import demistomock as demisto
from CommonServerPython import Common, tableToMarkdown, pascalToSpace, DemistoException
from CoreIRApiModule import CoreClient, handle_outgoing_issue_closure, XSOAR_RESOLVED_STATUS_TO_XDR
from CoreIRApiModule import add_tag_to_endpoints_command, remove_tag_from_endpoints_command, quarantine_files_command, \
    isolate_endpoint_command, list_user_groups_command, parse_user_groups, list_users_command, list_roles_command, \
    change_user_role_command, list_risky_users_or_host_command, enrich_error_message_id_group_role, get_incidents_command

test_client = CoreClient(
    base_url='https://test_api.com/public_api/v1', headers={}
)

Core_URL = 'https://api.xdrurl.com'

POWERSHELL_COMMAND_CASES = [
    pytest.param(
        "Write-Output 'Hello, world, it`s me!'",
        "powershell -Command 'Write-Output ''Hello, world, it`s me!'''",
        id='Hello World message',
    ),
    pytest.param(
        r"New-Item -Path 'C:\Users\User\example.txt' -ItemType 'File'",
        "powershell -Command 'New-Item -Path ''C:\\Users\\User\\example.txt'' -ItemType ''File'''",
        id='New file in path with backslashes',
    ),
    pytest.param(
        "$message = 'This is a test with special chars: `&^%$#@!'; Write-Output $message",
        "powershell -Command '$message = ''This is a test with special chars: `&^%$#@!''; Write-Output $message'",
        id='Special characters message',
    ),
    pytest.param(
        (
            "$users = @(JohnDoe) -split ';'; query user | Select-Object -Skip 1 | "
            "ForEach-Object { $sessionInfo = $_ -split '\s+' | "
            "Where-Object { $_ -ne '' -and $_ -notlike 'Disc' }; "
            "if ($sessionInfo.Length -ge 6) { $username = $sessionInfo[0].TrimStart('>'); "
            "$sessionId = $sessionInfo[2]; if ($users -contains $username) { logoff $sessionId } } }"
        ),
        (
            "powershell -Command '$users = @(JohnDoe) -split '';''; query user | Select-Object -Skip 1 | "
            "ForEach-Object { $sessionInfo = $_ -split ''\\s+'' | "
            "Where-Object { $_ -ne '''' -and $_ -notlike ''Disc'' }; "
            "if ($sessionInfo.Length -ge 6) { $username = $sessionInfo[0].TrimStart(''>''); "
            "$sessionId = $sessionInfo[2]; if ($users -contains $username) { logoff $sessionId } } }'"
        ),
        id='End RDP session for users',
    ),
]

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


# Note this test will fail when run locally (in pycharm/vscode)
# as it assumes the machine (docker image) has UTC timezone set

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


def test_retrieve_all_endpoints(mocker):
    """
    Given:
    - endpoints is populated with the first round.
    When
        - Retrieve_all_endpoints is called.
    Then
        - Retrieve all endpoints.
    """
    from CoreIRApiModule import retrieve_all_endpoints
    mock_endpoints_page_1 = {'reply': {'endpoints': [{'id': 1, 'hostname': 'endpoint1'}]}}
    mock_endpoints_page_2 = {'reply': {'endpoints': [{'id': 2, 'hostname': 'endpoint2'}]}}
    mock_endpoints_page_3 = {'reply': {'endpoints': []}}
    http_request = mocker.patch.object(test_client, '_http_request')
    http_request.side_effect = [mock_endpoints_page_1, mock_endpoints_page_2, mock_endpoints_page_3]

    endpoints = retrieve_all_endpoints(
        client=test_client,
        endpoints=[{'id': 2, 'hostname': 'endpoint2'}],
        endpoint_id_list=[],
        dist_name=None,
        ip_list=[],
        public_ip_list=[],
        group_name=None,
        platform=None,
        alias_name=None,
        isolate=None,
        hostname=None,
        page_number=0,
        limit=10,
        first_seen_gte=None,
        first_seen_lte=None,
        last_seen_gte=None,
        last_seen_lte=None,
        sort_by_first_seen=None,
        sort_by_last_seen=None,
        status=None,
        username=None,
    )

    assert len(endpoints) == 3
    assert endpoints[1]['hostname'] == 'endpoint1'


def test_get_endpoints_command(mocker):
    """
    When
        - Retrieve_all_endpoints is called.
    Then
        - Retrieve all endpoints.
    """
    from CoreIRApiModule import get_endpoints_command
    mock_endpoints_page_1 = {'reply': {'endpoints': [{'id': 1, 'hostname': 'endpoint1'}]}}
    mock_endpoints_page_2 = {'reply': {'endpoints': [{'id': 2, 'hostname': 'endpoint2'}]}}
    mock_endpoints_page_3 = {'reply': {'endpoints': []}}
    http_request = mocker.patch.object(test_client, '_http_request')
    http_request.side_effect = [mock_endpoints_page_1, mock_endpoints_page_2, mock_endpoints_page_3]
    args = {'all_results': 'true'}
    result = get_endpoints_command(test_client, args)
    assert result.readable_output == '### Endpoints\n|hostname|id|\n|---|---|\n| endpoint1 | 1 |\n| endpoint2 | 2 |\n'
    assert result.raw_response == [{'id': 1, 'hostname': 'endpoint1'}, {'id': 2, 'hostname': 'endpoint2'}]


def test_convert_to_hr_timestamps():
    """
    Given
        - Endpoints results.
    When
        - convert_to_hr_timestamps is called.
    Then
        - Convert to an hr date.
    """
    from CoreIRApiModule import convert_timestamps_to_datestring

    expected_first_seen = "2019-12-08T09:06:09.000Z"
    expected_last_seen = "2019-12-09T07:10:04.000Z"
    endpoints_res = load_test_data('./test_data/get_endpoints.json').get('reply').get('endpoints')

    converted_endpoint = convert_timestamps_to_datestring(endpoints_res)[0]
    assert converted_endpoint.get('first_seen') == expected_first_seen
    assert converted_endpoint.get('last_seen') == expected_last_seen


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
    """
    Given:
        The default arguments for the get endpoints command: limit = 1, page = 0, sort_order = 'asc'.
    When:
        Calling the get_endpoints_command function
    Then:
        a. Make sure the 'get_endpoints' API is not called (not to be confused with get_endpoint - see last comment
            here: https://jira-hq.paloaltonetworks.local/browse/XSUP-15995)
        b. Make sure the returned result as in the expected format.
    """
    from CoreIRApiModule import get_endpoints_command, CoreClient

    get_endpoints_response = load_test_data('./test_data/get_all_endpoints.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json=get_endpoints_response)
    get_endpoints_mock = requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoints/')

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'limit': 1,
        'page': 0,
        'sort_order': 'asc'
    }
    res = get_endpoints_command(client, args)
    expected_endpoint = get_endpoints_response.get('reply').get('endpoints')

    assert not get_endpoints_mock.called
    assert res.outputs['CoreApiModule.Endpoint(val.endpoint_id == obj.endpoint_id)'] == expected_endpoint


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
    for key, value in results.get("EntryContext", {}).items():
        assert get_endpoints_response[key] == value
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

    result = get_distribution_url_command(client, args)
    expected_url = get_distribution_url_response.get('reply').get('distribution_url')
    assert result.outputs == {
        'id': '1111',
        'url': expected_url
    }

    assert result.readable_output == f'[Distribution URL]({expected_url})'


def test_download_distribution(requests_mock):
    """
    Given:
        - Core client
        - Distribution ID and package type
    When
        - Running xdr-download-distribution command
    Then
        - Verify filename
        - Verify readable output is as expected
    """
    from CoreIRApiModule import get_distribution_url_command, CoreClient

    get_distribution_url_response = load_test_data('./test_data/get_distribution_url.json')
    dummy_url = "https://xdrdummyurl.com/11111-distributions/11111/sh"
    requests_mock.post(
        f'{Core_URL}/public_api/v1/distributions/get_dist_url/',
        json=get_distribution_url_response
    )
    requests_mock.get(
        dummy_url,
        content=b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    )
    installer_file_name = "xdr-agent-install-package.msi"

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'distribution_id': '1111',
        'package_type': 'x86',
        'download_package': 'true'
    }
    result = get_distribution_url_command(client, args)
    assert result[0]['File'] == installer_file_name
    assert result[1].readable_output == "Installation package downloaded successfully."


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
    assert outputs['Endpoint(val.ID && val.ID == obj.ID && val.Vendor == obj.Vendor)'] == [
        {'ID': '1111', 'Hostname': '1111.eu-central-1'},
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
    expected_command_result = {
        'CoreApiModule.blocklist.added_hashes.fileHash(val.fileHash == obj.fileHash)':
            test_data['multi_command_args']['hash_list']
    }

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
    expected_command_result = {
        'CoreApiModule.allowlist.added_hashes.fileHash(val.fileHash == obj.fileHash)':
            test_data['multi_command_args']['hash_list']
    }
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
        'CoreApiModule.allowlist.added_hashes.fileHash(val.fileHash == obj.fileHash)':
            test_data['no_comment_command_args'][
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


def test_get_update_args_unassgning_user(mocker):
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
    from CommonServerPython import UpdateRemoteSystemArgs
    mocker.patch('CoreIRApiModule.handle_outgoing_issue_closure')
    remote_args = UpdateRemoteSystemArgs({'delta': {'assigned_user_mail': 'None'}})
    update_args = get_update_args(remote_args)
    assert update_args.get('assigned_user_mail') is None
    assert update_args.get('assigned_user_pretty_name') is None
    assert update_args.get('unassign_user') == 'true'


def test_handle_outgoing_issue_closure_close_reason(mocker):
    """
    Given:
        -  a dict indicating changed fields (delta)
        - the incident status - set to set to 2 == Closed
    When
        - running handle_outgoing_issue_closure
    Then
        - Closing the issue with the resolved_security_testing status
    """
    from CoreIRApiModule import handle_outgoing_issue_closure
    from CommonServerPython import UpdateRemoteSystemArgs
    remote_args = UpdateRemoteSystemArgs({'delta': {'assigned_user_mail': 'None', 'closeReason': 'Security Testing'},
                                          'status': 2, 'inc_status': 2, 'data': {'status': 'other'}})
    request_data_log = mocker.patch.object(demisto, 'debug')
    handle_outgoing_issue_closure(remote_args)

    assert "handle_outgoing_issue_closure Closing Remote incident ID: None with status resolved_security_testing" in \
           request_data_log.call_args[  # noqa: E501
               0][0]


def test_get_update_args_close_incident():
    """
    Given:
        -  a dict indicating changed fields (delta) with closeReason set to Other and a closeNotes
        - the incident status - set to 2 == Closed
        - the current status of the remote incident are 'new'
    When
        - running get_update_args
    Then
        - update_args status has the correct status (resolved_other)
        - the resolve_comment is the same as the closeNotes
    """
    from CoreIRApiModule import get_update_args
    from CommonServerPython import UpdateRemoteSystemArgs
    remote_args = UpdateRemoteSystemArgs({
        'delta': {'closeReason': 'Other', "closeNotes": "Not Relevant", 'closingUserId': 'admin'},
        'data': {'status': 'new'},
        'status': 2}
    )
    update_args = get_update_args(remote_args)
    assert update_args.get('status') == 'resolved_other'
    assert update_args.get('resolve_comment') == 'Not Relevant'


def test_get_update_args_owner_sync(mocker):
    """
    Given:
        -  a dict indicating changed fields (delta) with a change in owner
        - the incident status - set to 2 == Close
    When
        - running get_update_args
    Then
        - update_args assigned_user_mail has the correct associated mail
    """
    from CoreIRApiModule import get_update_args
    from CommonServerPython import UpdateRemoteSystemArgs
    remote_args = UpdateRemoteSystemArgs({
        'delta': {'owner': 'username'},
        'data': {'status': 'new'}}
    )
    mocker.patch.object(demisto, 'params', return_value={"sync_owners": True, "mirror_direction": "Incoming"})
    mocker.patch.object(demisto, 'findUser', return_value={"email": "moo@demisto.com", 'username': 'username'})

    update_args = get_update_args(remote_args)

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
            - Request for list of device control violations filtered by selected fields.
              You can retrieve up to 100 violations.
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

    assert res.readable_output == tableToMarkdown(
        name='Retrieve files', t=result, headerTransform=string_to_table_header)
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

    assert res.readable_output == tableToMarkdown(
        name='Retrieve files', t=result, headerTransform=string_to_table_header)
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


def test_action_status_get_command(mocker):
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
    error_reasons = action_status_get_command_command_reply.get('reply').get('errorReasons') or {}
    result = []
    for item in data:
        result.append({
            'action_id': 1810,
            'endpoint_id': item,
            'status': data.get(item)
        })
        if error_reason := error_reasons.get(item):
            result[-1]['error_description'] = error_reason['errorDescription']
            result[-1]['ErrorReasons'] = error_reason

    action_status_get_command_expected_result = result

    mocker.patch.object(CoreClient, '_http_request', return_value=action_status_get_command_command_reply)
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'action_id': '1810'
    }

    res = action_status_get_command(client, args)
    assert res.readable_output == tableToMarkdown(name='Get Action Status', t=result, removeNull=True,
                                                  headers=['action_id', 'endpoint_id', 'status', 'error_description'])
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
        - creating the account context from the response succeeds - which means there exists both domain
          and user in the response.
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
    assert response.outputs[0] == api_response.get('reply')
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
    zip_link = 'https://download/example-link'
    zip_filename = 'file.zip'
    requests_mock.post(
        f'{Core_URL}/public_api/v1/scripts/get_script_execution_results_files',
        json={'reply': {'DATA': zip_link}}
    )
    requests_mock.get(
        f"{Core_URL}/public_api/v1/download/example-link",
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


@pytest.mark.parametrize('command_input, expected_command', POWERSHELL_COMMAND_CASES)
def test_form_powershell_command(command_input: str, expected_command: str):
    """
    Given:
        - An unescaped command containing characters like ', `, ", \

    When:
        - Calling the form_powershell_command function

    Assert:
        - Command starts with 'powershell -Command' and is properly escaped.
    """
    from CoreIRApiModule import form_powershell_command

    command = form_powershell_command(command_input)

    assert not command_input.startswith('powershell -Command ')
    assert command == expected_command


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

    assert response.outputs[0] == api_response.get('reply')
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

    assert response.outputs[0] == api_response.get('reply')
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

    assert response.outputs[0] == api_response.get('reply')
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

    assert response.outputs[0] == api_response.get('reply')
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

    assert response.outputs[0] == api_response.get('reply')
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

    assert response.outputs[0] == api_response.get('reply')
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
PUBLIC_IP = {
    'endpoint_status': 'Connected',
    'is_isolated': 'Isolated',
    'host_name': 'TEST',
    'ip': [],
    'public_ip': ['1.1.1.1']
}
NO_IP = {
    'endpoint_status': 'Connected',
    'is_isolated': 'Isolated',
    'host_name': 'TEST',
    'ip': [],
    'public_ip': []
}


@pytest.mark.parametrize("endpoint, expected_status, expected_ip", [
    (CONNECTED_STATUS, 'Online', '1.1.1.1'),
    (NO_STATUS, 'Offline', '1.1.1.1'),
    (OFFLINE_STATUS, 'Offline', '1.1.1.1'),
    (PUBLIC_IP, 'Online', ['1.1.1.1']),
    (NO_IP, 'Online', '')
])
def test_get_endpoint_properties(endpoint, expected_status, expected_ip):
    """
    Given:
        - Endpoint data
    When
        - Case a: The status of the endpoint is 'Connected' with a capital C and ip is 1.1.1.1.
        - Case b: When no status is not given and ip is 1.1.1.1.
        - Case c: The status of the endpoint is offline and ip is 1.1.1.1.
        - Case d: The status of the endpoint is 'Connected' with a capital C ip is empty but public_ip is 1.1.1.1.
        - Case d: The status of the endpoint is 'Connected' with a capital C and both ip and public_ip are empty.
    Then
        - Case a: The status of the endpoint is determined to be 'Online' and the ip is set to 1.1.1.1.
        - Case b: The status of the endpoint is determined to be 'Offline' and the ip is set to 1.1.1.1.
        - Case c: The status of the endpoint is determined to be 'Offline' and the ip is set to 1.1.1.1.
        - Case d: The status of the endpoint is determined to be 'Online' and the ip is set to 1.1.1.1.
        - Case d: The status of the endpoint is determined to be 'Online' and the ip is set to empty.
    """
    from CoreIRApiModule import get_endpoint_properties

    status, is_isolated, hostname, ip = get_endpoint_properties(endpoint)
    assert status == expected_status
    assert ip == expected_ip


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
    requests_mock.post(
        f'{Core_URL}/public_api/v1/hash_exceptions/blocklist/remove/',
        json=remove_blocklist_files_response)
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
    requests_mock.post(
        f'{Core_URL}/public_api/v1/hash_exceptions/allowlist/remove/',
        json=remove_allowlist_files_response)
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


def test_filter_general_fields_with_stateful_raw_data():
    """
    Given:
        - An alert dict with stateful_raw_data section
    When
        - Running filter_general_fields command once with events_from_decider_as_list as False and once as True.
    Then
        - Verify expected output
    """
    from CoreIRApiModule import filter_general_fields
    alert = {
        'detection_modules': 'test1',
        "content_version": "version1",
        "detector_id": 'ID',
        'raw_abioc': {
            'event': {
                'event_type': 'type',
                'event_id': 'id',
                'identity_sub_type': 'subtype',
            }
        },
        'stateful_raw_data': {
            'events_from_decider': {
                "test_1": {
                    "story_id": "test_1",
                    "additional_info": "this is a test."
                },
                "test_2": {
                    "story_id": "test_2",
                    "additional_info": "this is a test."
                }
            }
        }
    }
    assert filter_general_fields(alert, False, False) == {
        'detection_modules': 'test1',
        "content_version": "version1",
        "detector_id": 'ID',
        'raw_abioc': {
            'event': {
                'event_type': 'type',
                'event_id': 'id',
                'identity_sub_type': 'subtype',
            }
        },
        'stateful_raw_data': {
            'events_from_decider': {
                "test_1": {
                    "story_id": "test_1",
                    "additional_info": "this is a test."
                },
                "test_2": {
                    "story_id": "test_2",
                    "additional_info": "this is a test."
                }
            }
        },
        'event': {
            'event_type': 'type',
            'event_id': 'id',
            'identity_sub_type': 'subtype',
        }
    }
    assert filter_general_fields(alert, False, True) == {
        'detection_modules': 'test1',
        "content_version": "version1",
        "detector_id": 'ID',
        'raw_abioc': {
            'event': {
                'event_type': 'type',
                'event_id': 'id',
                'identity_sub_type': 'subtype',
            }
        },
        'stateful_raw_data': {
            'events_from_decider': [{
                "story_id": "test_1",
                "additional_info": "this is a test."
            }, {
                "story_id": "test_2",
                "additional_info": "this is a test."
            }]
        },
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


def test_get_original_alerts_command__with_filter(requests_mock):
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
        'alert_ids': '2', 'filter_alert_fields': True
    }

    output = get_original_alerts_command(client, args).outputs[0]
    assert len(output) == 4  # make sure fields were filtered
    event = output['event']
    assert len(event) == 23  # make sure fields were filtered
    assert event.get('_time') == 'DATE'  # assert general filter is correct
    assert event.get('cloud_provider') == 'AWS'  # assert general filter is correct
    assert event.get('raw_log', {}).get('userIdentity', {}).get('accountId') == 'ID'  # assert vendor filter is correct


def test_get_original_alerts_command__without_filtering(requests_mock):
    """
    Given:
        - Core client
        - Alert IDs
    When
        - Running get_original_alerts_command command
    Then
        - Verify expected output length
        - Ensure request body sent as expected
    """
    from CoreIRApiModule import get_original_alerts_command, CoreClient
    api_response = load_test_data('./test_data/get_original_alerts_results.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_original_alerts/', json=api_response)
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {
        'alert_ids': '2', 'filter_alert_fields': False
    }

    alert = get_original_alerts_command(client, args).outputs[0]
    event = alert['event']
    assert len(alert) == 13  # make sure fields were not filtered
    assert len(event) == 41  # make sure fields were not filtered


@pytest.mark.parametrize("alert_ids, raises_demisto_exception",
                         [("59cf36bbdedb8f05deabf00d9ae77ee5$&$A Successful login from TOR", True),
                          ("b0e754480d79eb14cc9308613960b84b$&$A successful SSO sign-in from TOR", True),
                          ("9d657d2dfd14e63d0b98c9dfc3647b4f$&$A successful SSO sign-in from TOR", True),
                          ("561675a86f68413b6e7a3b12e48c6072$&$External Login Password Spray", True),
                          ("fe925817cddbd11e6efe5a108cf4d4c5$&$SSO Password Spray", True),
                          ("e2d2a0dd589e8ca97d468cdb0468e94d$&$SSO Brute Force", True),
                          ("3978e33b76cc5b2503ba60efd4445603$&$A successful SSO sign-in from TOR", True),
                          ("79", False)])
def test_get_original_alerts_command_raises_exception_playbook_debugger_input(alert_ids, raises_demisto_exception,
                                                                              requests_mock):
    """
    Given:
        - A list of alert IDs with invalid formats for the alert ID of the form <GUID>$&$<Playbook name>
    When:
        - Running get_original_alerts_command command
    Then:
        - Verify that DemistoException is raised
    """
    from CoreIRApiModule import get_original_alerts_command, CoreClient

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args = {'alert_ids': alert_ids}

    if raises_demisto_exception:
        with pytest.raises(DemistoException):
            get_original_alerts_command(client, args)
    else:
        api_response = load_test_data('./test_data/get_original_alerts_results.json')
        requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_original_alerts/', json=api_response)
        get_original_alerts_command(client, args)


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
    results = [
        {'endpoint_name': 'endpoint_name', 'endpoint_ip_address': ['1.1.1.1'], 'endpoint_status': 'endpoint_status',
         'domain': 'env', 'endpoint_id': 'endpoint_id', 'execution_status': 'COMPLETED_SUCCESSFULLY',
         'standard_output': 'Running command "command_executed"', 'retrieved_files': 0, 'failed_files': 0,
         'retention_date': None, 'command_executed': ['command_output']}]
    res = parse_get_script_execution_results(results)
    expected_res = [
        {'endpoint_name': 'endpoint_name', 'endpoint_ip_address': ['1.1.1.1'], 'endpoint_status': 'endpoint_status',
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
               "'to': 2}, 'filter': {'AND': [{'SEARCH_FIELD': 'source_insert_ts', 'SEARCH_TYPE': 'RANGE', " \
               "'SEARCH_VALUE': {'from': 1541494601000, 'to': 1541494601000}}]}}}" in request_data_log.call_args[0][0]

    def test_get_alert_by_alert_action_status_filter(self, requests_mock, mocker):
        """
        Given:
            - Core client
            - Alert with action status of SCANNED
        When
            - Running get_alerts_by_filter command with alert_action_status="detected (scanned)"
        Then
            - Verify the alert in the output contains alert_action_status and alert_action_status_readable
            - Ensure request filter contains the alert_action_status as SCANNED
        """
        from CoreIRApiModule import get_alerts_by_filter_command, CoreClient
        api_response = load_test_data('./test_data/get_alerts_by_filter_results.json')
        requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_alerts_by_filter_data/', json=api_response)
        request_data_log = mocker.patch.object(demisto, 'debug')
        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )
        args = {
            'alert_action_status': 'detected (scanned)'
        }
        response = get_alerts_by_filter_command(client, args)
        assert response.outputs[0].get('internal_id', {}) == 33333
        assert response.outputs[0].get('alert_action_status', {}) == 'SCANNED'
        assert response.outputs[0].get('alert_action_status_readable', {}) == 'detected (scanned)'
        assert "{'SEARCH_FIELD': 'alert_action_status', 'SEARCH_TYPE': 'EQ', 'SEARCH_VALUE': " \
               "'SCANNED'" in request_data_log.call_args[0][0]

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
               "'SEARCH_VALUE': 'first'}, {'SEARCH_FIELD': 'alert_source', 'SEARCH_TYPE': 'CONTAINS', " \
               "'SEARCH_VALUE': 'second'}]}]}}}" in request_data_log.call_args[0][0]

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
               "'SEARCH_VALUE': 'first'}, {'SEARCH_FIELD': 'alert_source', 'SEARCH_TYPE': 'CONTAINS', " \
               "'SEARCH_VALUE': 'second'}]}, {'OR': [{'SEARCH_FIELD': 'actor_effective_username', " \
               "'SEARCH_TYPE': 'CONTAINS', 'SEARCH_VALUE': 'N/A'}]}]}" in request_data_log.call_args[0][0]

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

        custom_filter = '{"AND": [{"OR": [{"SEARCH_FIELD": "alert_source","SEARCH_TYPE": "EQ",' \
                        '"SEARCH_VALUE": "CORRELATION"},' \
                        '{"SEARCH_FIELD": "alert_source","SEARCH_TYPE": "EQ","SEARCH_VALUE": "IOC"}]},' \
                        '{"SEARCH_FIELD": "severity","SEARCH_TYPE": "EQ","SEARCH_VALUE": "SEV_040_HIGH"}]}'
        api_response = load_test_data('./test_data/get_alerts_by_filter_results.json')
        requests_mock.post(f'{Core_URL}/public_api/v1/alerts/get_alerts_by_filter_data/', json=api_response)
        request_data_log = mocker.patch.object(demisto, 'debug')
        mocker.patch.object(dateparser, 'parse',
                            return_value=dt(year=2022, month=5, day=24, hour=13, minute=0, second=0))
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
        mocker.patch.object(dateparser, 'parse',
                            return_value=dt(year=2022, month=5, day=24, hour=13, minute=0, second=0))
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
                    "reply": {  # get script execution result response
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
        assert command_result.outputs == {'action_id': 1, 'endpoints_count': 1, 'status': 1}

        polling_args = {
            'endpoint_ids': '1', 'script_uid': '1', 'action_id': '1', 'hide_polling_output': True
        }

        command_result = script_run_polling_command(polling_args, client)
        # if scheduled_command is set, it means that command should still poll
        while not isinstance(command_result, list) and command_result.scheduled_command:
            # if command result is a list, it means command execution finished
            assert not command_result.readable_output  # make sure that indication of polling is printed only once
            # make sure no context output is being returned to war-room during polling
            assert not command_result.outputs
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


@pytest.mark.parametrize(
    'args, expected_filters, func, url_suffix, expected_human_readable',
    [
        (
            {'endpoint_ids': '1,2', 'tag': 'test'},
            [{'field': 'endpoint_id_list', 'operator': 'in', 'value': ['1', '2']}],
            add_tag_to_endpoints_command,
            '/tags/agents/assign/',
            "Successfully added tag test to endpoint(s) ['1', '2']"
        ),
        (
            {'endpoint_ids': '1,2', 'tag': 'test', 'status': 'disconnected'},
            [{'field': 'endpoint_status', 'operator': 'IN', 'value': ['disconnected']}],
            add_tag_to_endpoints_command,
            '/tags/agents/assign/',
            "Successfully added tag test to endpoint(s) ['1', '2']"
        ),
        (
            {'endpoint_ids': '1,2', 'tag': 'test', 'hostname': 'hostname', 'group_name': 'test_group'},
            [
                {'field': 'group_name', 'operator': 'in', 'value': ['test_group']},
                {'field': 'hostname', 'operator': 'in', 'value': ['hostname']}
            ],
            add_tag_to_endpoints_command,
            '/tags/agents/assign/',
            "Successfully added tag test to endpoint(s) ['1', '2']"
        ),
        (
            {'endpoint_ids': '1,2', 'tag': 'test'},
            [{'field': 'endpoint_id_list', 'operator': 'in', 'value': ['1', '2']}],
            remove_tag_from_endpoints_command,
            '/tags/agents/remove/',
            "Successfully removed tag test from endpoint(s) ['1', '2']"
        ),
        (
            {'endpoint_ids': '1,2', 'tag': 'test', 'platform': 'linux'},
            [{'field': 'platform', 'operator': 'in', 'value': ['linux']}],
            remove_tag_from_endpoints_command,
            '/tags/agents/remove/',
            "Successfully removed tag test from endpoint(s) ['1', '2']"
        ),
        (
            {'endpoint_ids': '1,2', 'tag': 'test', 'isolate': 'isolated', 'alias_name': 'alias_name'},
            [
                {'field': 'alias', 'operator': 'in', 'value': ['alias_name']},
                {'field': 'isolate', 'operator': 'in', 'value': ['isolated']}
            ],
            remove_tag_from_endpoints_command,
            '/tags/agents/remove/',
            "Successfully removed tag test from endpoint(s) ['1', '2']"
        )
    ]
)
def test_add_or_remove_tag_endpoint_command(requests_mock, args, expected_filters, func,
                                            url_suffix, expected_human_readable):
    """
    Given:
      - command arguments
      - expected filters as a body request

    When:
      - executing the core-add-tag-endpoint command

    Then:
      - make sure the body request was sent as expected to the api request and that human readable is valid.
    """
    client = CoreClient(base_url=f'{Core_URL}/public_api/v1/', headers={})
    add_tag_mock = requests_mock.post(f'{Core_URL}/public_api/v1{url_suffix}', json={})

    result = func(client=client, args=args)

    assert result.readable_output == expected_human_readable
    assert add_tag_mock.last_request.json() == {
        'context': {
            'lcaas_id': ['1', '2'],
        },
        'request_data': {
            'filters': expected_filters,
            'tag': 'test'
        }
    }


excepted_output_1 = {'filters': [{'field': 'endpoint_status',
                                  'operator': 'IN', 'value': ['connected']}], 'new_alias_name': 'test'}
excepted_output_2 = {'filters': [{'field': 'endpoint_status',
                                  'operator': 'IN', 'value': ['connected']}], 'new_alias_name': ""}


@pytest.mark.parametrize('input, expected_output', [("test", excepted_output_1),
                                                    ('""', excepted_output_2)])
def test_endpoint_alias_change_command__diffrent_alias_new_names(mocker, input, expected_output):
    """
    Given:
    - valid new alias name as string - empty new alias name (due to xsoar limitation,
    represented by a string of double quote)

    When:
    - executing the endpoint-alias-change command

    Then:
    - Makes sure the request body is created correctly.

    """
    client = CoreClient(base_url=f'{Core_URL}/public_api/v1/', headers={})
    mocker_set = mocker.patch.object(client, 'set_endpoints_alias')
    from CoreIRApiModule import endpoint_alias_change_command
    endpoint_alias_change_command(client=client, status="connected", new_alias_name=input)
    assert mocker_set.call_args[1] == expected_output


def test_endpoint_alias_change_command__no_filters(mocker):
    """
    Given:
    - command withot endpoint filters
    when:
    - executing the endpoint-alias-change command
    then:
    - make sure the correct error message wil raise.
    """
    client = CoreClient(base_url=f'{Core_URL}/public_api/v1/', headers={})
    mocker.patch.object(client, 'set_endpoints_alias')
    from CoreIRApiModule import endpoint_alias_change_command
    with pytest.raises(Exception) as e:
        endpoint_alias_change_command(client=client, new_alias_name='test')
    assert e.value.message == "Please provide at least one filter."


GRACEFULLY_FAILING = [
    pytest.param(
        quarantine_files_command,
        {
            "endpoint_id_list": "123",
            "file_path": "C:\\Users\\test\\Desktop\\test_x64.msi",
            "file_hash": "123",
        },
        {
            "err_msg": "An error occurred while processing XDR public API - No endpoint "
                       "was found "
                       "for creating the requested action",
            "status_code": 500,
        },
        False,
        id="Success",
    ),
    pytest.param(
        isolate_endpoint_command,
        {"endpoint_id": "1111"},
        {"err_msg": "Other error", "status_code": 401},
        True,
        id="Failure",
    ),
]


@pytest.mark.parametrize("command_to_run, args, error, raises", GRACEFULLY_FAILING)
def test_core_commands_raise_exception(mocker, command_to_run, args, error, raises):
    """
    Given:
    - XDR API error.
    when:
    - executing the isolate-endpoint-command and quarantine-files-command command
    then:
    - make sure the correct error message wil raise.
    """

    class MockException:
        def __init__(self, status_code) -> None:
            self.status_code = status_code

    client = CoreClient(base_url=f"{Core_URL}/public_api/v1/", headers={})
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=DemistoException(
            error.get("err_msg"), res=MockException(error.get("status_code"))
        ),
    )

    if raises:
        with pytest.raises(Exception) as e:
            command_to_run(client, args)
            assert "Other error" in str(e)
    else:
        assert (command_to_run(client, args).readable_output == "The operation executed is not supported on the given "
                                                                "machine.")


@pytest.mark.parametrize(
    "command, func_http, args, excepted_calls, path_test_data",
    [
        (
            "user",
            "list_risky_users",
            {"user_id": "test"},
            {"risk_score_user_or_host": 1, "list_risky_users": 0},
            "./test_data/list_risky_users_hosts.json"

        ),
        (
            "user",
            "list_risky_users",
            {},
            {"risk_score_user_or_host": 0, "list_risky_users": 1},
            "./test_data/list_risky_users.json"
        ),
        (
            "host",
            "list_risky_hosts",
            {"host_id": "test"},
            {"risk_score_user_or_host": 1, "list_risky_hosts": 0},
            "./test_data/list_risky_users_hosts.json"
        ),
        (
            "host",
            "list_risky_hosts",
            {},
            {"risk_score_user_or_host": 0, "list_risky_hosts": 1},
            "./test_data/list_risky_hosts.json"
        ),
    ],
)
def test_list_risky_users_or_hosts_command(
    mocker, command: str, func_http: str, args: dict[str, str], excepted_calls: dict[str, int], path_test_data: str
):
    """
    Test case to verify the behavior of the 'list_risky_users_or_hosts_command' function.

    Args:
        mocker (Any): The mocker object to patch the required methods.
        command (str): The command to be tested ('user' or 'host').
        func_http (str): The name of the HTTP function to be called.
        args (dict[str, str]): The arguments for the command.
        expected_calls (dict[str, int]): The expected number of calls for each mocked method.

    Returns:
        None
    """
    test_data = load_test_data(path_test_data)
    client = CoreClient("test", {})

    risk_by_user_or_host = mocker.patch.object(
        CoreClient, "risk_score_user_or_host", return_value=test_data
    )
    list_risky_users = mocker.patch.object(CoreClient, func_http, return_value=test_data)

    result = list_risky_users_or_host_command(client=client, command=command, args=args)

    assert result.outputs == test_data["reply"]
    assert (
        risk_by_user_or_host.call_count
        == excepted_calls["risk_score_user_or_host"]
    )
    assert list_risky_users.call_count == excepted_calls[func_http]


@pytest.mark.parametrize(
    "command ,id_",
    [
        ('user', "user_id"),
        ('host', "host_id"),
    ],
)
def test_list_risky_users_hosts_command_raise_exception(
    mocker, command: str, id_: str
):
    """
    Given:
    - XDR API error indicating that the user / host was not found

    When:
    - executing the list_risky_users_or_host_command function

    Then:
    - make sure a message indicating that the user was not found is returned
    """

    client = CoreClient(
        base_url="test",
        headers={},
    )

    class MockException:
        def __init__(self, status_code) -> None:
            self.status_code = status_code

    mocker.patch.object(
        client,
        "risk_score_user_or_host",
        side_effect=DemistoException(
            message="id 'test' was not found", res=MockException(500)
        ),
    )

    result = list_risky_users_or_host_command(client, command, {id_: "test"})
    assert result.readable_output == f'The {command} test was not found'


@pytest.mark.parametrize(
    "command ,args, client_func",
    [
        ('user', {"user_id": "test"}, "risk_score_user_or_host"),
        ('host', {"host_id": "test"}, "risk_score_user_or_host"),
        ('user', {}, "list_risky_users"),
        ('host', {}, "list_risky_hosts"),
    ],
    ids=['user_id', 'host_id', 'list_users', 'list_hosts']
)
def test_list_risky_users_hosts_command_no_license_warning(mocker: MockerFixture, command: str, args: dict, client_func: str):
    """
    Given:
    - XDR API error indicating that the user / host was not found

    When:
    - executing the list_risky_users_or_host_command function

    Then:
    - make sure a message indicating that the user was not found is returned
    """

    client = CoreClient(
        base_url="test",
        headers={},
    )

    class MockException:
        def __init__(self, status_code) -> None:
            self.status_code = status_code

    mocker.patch.object(
        client,
        client_func,
        side_effect=DemistoException(
            message="An error occurred while processing XDR public API, No identity threat",
            res=MockException(500)
        ),
    )
    import CoreIRApiModule
    warning = mocker.patch.object(CoreIRApiModule, 'return_warning')

    with pytest.raises(DemistoException):
        list_risky_users_or_host_command(client, command, args)
    assert warning.call_args[0][0] == ('Please confirm the XDR Identity Threat Module is enabled.\n'
                                       'Full error message: An error occurred while processing XDR public API,'
                                       ' No identity threat')
    assert warning.call_args[1] == {"exit": True}


def test_list_user_groups_command(mocker):
    """
    Test function to validate the behavior of the `list_user_groups_command` function.

    Args:
        mocker: Pytest mocker object.
        args (dict): A dictionary containing optional `group_names` argument.

    Returns:
        None

    Raises:
        AssertionError: If the expected output doesn't match the actual output.
    """
    client = CoreClient("test", {})
    test_data = load_test_data("./test_data/get_list_user_groups.json")
    mocker.patch.object(CoreClient, "list_user_groups", return_value=test_data)

    results = list_user_groups_command(client=client, args={"group_names": "test"})
    assert test_data["reply"] == results.outputs


@pytest.mark.parametrize(
    "data, expected_results",
    [
        (
            {
                "group_name": "Group2",
                "description": None,
                "pretty_name": "dummy1",
                "insert_time": 1111111111111,
                "update_time": 2222222222222,
                "user_email": [
                    "dummy1@gmail.com",
                    "dummy2@gmail.com",
                ],
                "source": "Custom",
            },
            [
                {'User email': 'dummy1@gmail.com', 'Group Name': 'Group2', 'Group Description': None},
                {'User email': 'dummy2@gmail.com', 'Group Name': 'Group2', 'Group Description': None}
            ]
        )
    ],
)
def test_parse_user_groups(data: dict[str, Any], expected_results: list[dict[str, Any]]):
    """
    Test the 'parse_user_groups' function that parses user group information.

    Args:
        data (dict): A dictionary containing a sample user group data.

    Returns:
        None

    Raises:
        AssertionError: If the parsing of user groups data fails.
    """
    assert parse_user_groups(data) == expected_results


@pytest.mark.parametrize(
    "test_data, excepted_error",
    [
        ({"group_names": "test"}, "Error: Group test was not found. Full error message: Group 'test' was not found"),
        ({"group_names": "test, test2"}, "Error: Group test was not found. Note: If you sent more than one group name, "
                                         "they may not exist either. Full error message: Group 'test' was not found")
    ]
)
def test_list_user_groups_command_raise_exception(mocker, test_data: dict[str, str], excepted_error: str):
    """
    Tests that the 'list_user_groups_command' function raises an exception when the 'list_user_groups' method of
    the 'CoreClient' class raises a 'DemistoException'.

    Args:
        mocker: The pytest mocker object.

    Raises:
        Exception: If the 'list_user_groups_command' function does not raise an exception when expected.

    Returns:
        None.
    """
    client = CoreClient(
        base_url="test",
        headers={},
    )

    class MockException:
        def __init__(self, status_code) -> None:
            self.status_code = status_code

    mocker.patch.object(
        client,
        "list_user_groups",
        side_effect=DemistoException(
            message="Group 'test' was not found", res=MockException(500)
        ),
    )
    with pytest.raises(
        DemistoException,
        match=excepted_error,
    ):
        list_user_groups_command(client, test_data)


def test_list_users_command(mocker):
    """
    Tests the `list_users_command` function.

    Args:
        mocker: The pytest mocker object.

    Returns:
        None.

    Raises:
        AssertionError: If the test fails.
    """
    client = CoreClient("test", {})
    test_data = load_test_data("./test_data/get_list_users.json")
    mocker.patch.object(CoreClient, "list_users", return_value=test_data)

    results = list_users_command(client=client, args={})
    assert test_data["reply"] == results.outputs


@pytest.mark.parametrize(
    "role_data",
    [

        {
            "reply": [
                [
                    {
                        "pretty_name": "test",
                        "description": "test",
                        "permissions": "test",
                        "users": "test",
                        "groups": "test",
                    }
                ]
            ]
        },

    ],
)
def test_list_roles_command(
    mocker, role_data: dict[str, str]
) -> None:
    """
    Tests the 'list_roles_command' function.

    Args:
        mocker: A pytest-mock object.
        role_data (dict): A dictionary containing the test data for the roles.
        expected_output (str): The expected output for the test.

    Raises:
        AssertionError: If the test fails.
    """
    client = CoreClient("test", {})

    mocker.patch.object(CoreClient, "list_roles", return_value=role_data)

    results = list_roles_command(client=client, args={"role_names": "test"})

    assert role_data["reply"] == results.outputs


@pytest.mark.parametrize(
    "func, args, update_count, expected_output",
    [
        (
            "remove_user_role",
            {"user_emails": "test1@example.com,test2@example.com"},
            {"reply": {"update_count": "2"}},
            "Role was removed successfully for 2 users."
        ),
        (
            "remove_user_role",
            {"user_emails": "test1@example.com,test2@example.com"},
            {"reply": {"update_count": "1"}},
            "Role was removed successfully for 1 user."
        ),
        (
            "set_user_role",
            {"user_emails": "test1@example.com,test2@example.com", "role_name": "admin"},
            {"reply": {"update_count": "2"}},
            "Role was updated successfully for 2 users."
        ),
    ]
)
def test_change_user_role_command_happy_path(
    mocker, func: str,
    args: dict[str, str],
    update_count: dict[str, dict[str, str]],
    expected_output: str
):
    """
    Given:
    - Valid user emails and role name provided.

    When:
    - Running the change_user_role_command function.

    Then:
    - Ensure the function returns a CommandResults object with the expected readable output.
    """

    client = CoreClient("test", {})
    mocker.patch.object(CoreClient, func, return_value=update_count)

    result = change_user_role_command(client, args)

    assert result.readable_output == expected_output


@pytest.mark.parametrize(
    "func, args, update_count, expected_output",
    [
        (
            "remove_user_role",
            {"user_emails": "test1@example.com,test2@example.com"},
            {"reply": {"update_count": 0}},
            "No user role has been removed."
        ),
        (
            "set_user_role",
            {"user_emails": "test1@example.com,test2@example.com", "role_name": "admin"},
            {"reply": {"update_count": 0}},
            "No user role has been updated."
        )
    ]
)
def test_change_user_role_command_with_raise(
    mocker, func: str,
    args: dict[str, str],
    update_count: dict[str, dict[str, int]],
    expected_output: str
):
    client = CoreClient("test", {})
    mocker.patch.object(CoreClient, func, return_value=update_count)

    with pytest.raises(DemistoException, match=expected_output):
        change_user_role_command(client, args)


def test_endpoint_command_fails(requests_mock):
    """
    Given:
    - no arguments
    When:
    - we mock the endpoint command
    Then:
    - Validate that there is a correct error
    """
    from CoreIRApiModule import endpoint_command, CoreClient
    get_endpoints_response = load_test_data('./test_data/get_endpoints.json')
    requests_mock.post(f'{Core_URL}/public_api/v1/endpoints/get_endpoint/', json=get_endpoints_response)

    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={}
    )
    args: dict = {}
    with pytest.raises(DemistoException) as e:
        endpoint_command(client, args)
    assert 'In order to run this command, please provide a valid id, ip or hostname' in str(e)


def test_generate_files_dict(mocker):
    """
    Given:
    - no arguments
    When:
    - we mock the get_endpoints command with mac, linux and windows endpoints
    Then:
    - Validate that the dict is generated right
    """

    mocker.patch.object(test_client, "get_endpoints",
                        side_effect=[load_test_data('test_data/get_endpoints_mac_response.json'),
                                     load_test_data('test_data/get_endpoints_linux_response.json'),
                                     load_test_data('test_data/get_endpoints_windows_response.json')])

    res = test_client.generate_files_dict(endpoint_id_list=['1', '2', '3'],
                                          file_path_list=['fake\\path1', 'fake\\path2', 'fake\\path3'])

    assert res == {"macos": ['fake\\path1'], "linux": ['fake\\path2'], "windows": ['fake\\path3']}


def test_get_script_execution_result_files(mocker):
    """
    Given:
    - no arguments
    When:
    - executing the get_script_execution_result_files command
    Then:
    - Validate that the url_suffix generated correctly
    """
    http_request = mocker.patch.object(test_client, '_http_request',
                                       return_value={
                                           "reply": {
                                               "DATA": "https://test_api/public_api/v1/download/test"
                                           }
                                       })
    test_client.get_script_execution_result_files(action_id="1", endpoint_id="1")
    http_request.assert_called_with(method='GET', url_suffix="download/test", resp_type="response")


@pytest.mark.parametrize(
    "error_message, expected_error_message",
    [
        (
            "id 'test' was not found",
            ["Error: id test was not found. Full error message: id 'test' was not found"],
        ),
        ("some error", [None]),
    ],
)
def test_enrich_error_message_id_group_role(error_message: str, expected_error_message: list):
    """
    Test case for the enrich_error_message_id_group_role function.

    Args:
        error_message (str): The error message to be passed to the function.
        expected_error_message (str): The expected error message after enriching.

    Raises:
        AssertionError: If the error response from the function does not match the expected error message.
    """

    class MockException:
        def __init__(self, status_code) -> None:
            self.status_code = status_code

    error_response = enrich_error_message_id_group_role(
        DemistoException(message=error_message, res=MockException(500)), "test", "test"
    )
    assert error_response == expected_error_message[0]


def get_incident_by_status(incident_id_list=None, lte_modification_time=None, gte_modification_time=None,
                           lte_creation_time=None, gte_creation_time=None, starred=None,
                           starred_incidents_fetch_window=None, status=None, sort_by_modification_time=None,
                           sort_by_creation_time=None, page_number=0, limit=100, gte_creation_time_milliseconds=0):
    """
        The function simulate the client.get_incidents method for the test_fetch_incidents_filtered_by_status
        and for the test_get_incident_list_by_status.
        The function got the status as a string, and return from the json file only the incidents
        that are in the given status.
    """
    incidents_list = load_test_data('./test_data/get_incidents_list.json')['reply']['incidents']
    return [incident for incident in incidents_list if incident['status'] == status]


class TestGetIncidents:

    def test_get_incident_list(self, requests_mock):
        """
        Given: Incidents returned from client.
        When: Running get_incidents_command.
        Then: Ensure the outputs contain the incidents from the client.
        """

        get_incidents_list_response = load_test_data('./test_data/get_incidents_list.json')
        requests_mock.post(f'{Core_URL}/public_api/v1/incidents/get_incidents/', json=get_incidents_list_response)

        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )

        args = {
            'incident_id_list': '1 day'
        }
        _, outputs, _ = get_incidents_command(client, args)

        expected_output = {
            'CoreApiModule.Incident(val.incident_id==obj.incident_id)':
                get_incidents_list_response.get('reply').get('incidents')
        }
        assert expected_output == outputs

    def test_get_incident_list_by_status(self, mocker):
        """
        Given: A status query, and incidents filtered by the query.
        When: Running get_incidents_command.
        Then: Ensure outputs contain the incidents from the client.
        """

        get_incidents_list_response = load_test_data('./test_data/get_incidents_list.json')

        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )

        args = {
            'incident_id_list': '1 day',
            'status': 'under_investigation,new'
        }
        mocker.patch.object(client, 'get_incidents', side_effect=get_incident_by_status)

        _, outputs, _ = get_incidents_command(client, args)

        expected_output = {
            'CoreApiModule.Incident(val.incident_id==obj.incident_id)':
                get_incidents_list_response.get('reply').get('incidents')
        }
        assert expected_output == outputs

    @freeze_time("2024-01-15 17:00:00 UTC")
    @pytest.mark.parametrize('starred, expected_starred',
                             [(True, True),
                              (False, False),
                              ('true', True),
                              ('false', False),
                              (None, None),
                              ('', None)])
    def test_get_starred_incident_list_from_get(self, mocker, requests_mock, starred, expected_starred):
        """
        Given: A query with starred parameters.
        When: Running get_incidents_command.
        Then: Ensure the starred output is returned and the request filters are set correctly.
        """

        get_incidents_list_response = load_test_data('./test_data/get_starred_incidents_list.json')
        get_incidents_request = requests_mock.post(f'{Core_URL}/public_api/v1/incidents/get_incidents/',
                                                   json=get_incidents_list_response)
        mocker.patch.object(demisto, 'command', return_value='get-incidents')

        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )

        args = {
            'incident_id_list': '1 day',
            'starred': starred,
            'starred_incidents_fetch_window': '3 days'
        }

        starred_filter_true = {
            'field': 'starred',
            'operator': 'eq',
            'value': True
        }

        starred_filter_false = {
            'field': 'starred',
            'operator': 'eq',
            'value': False
        }

        starred_fetch_window_filter = {
            'field': 'creation_time',
            'operator': 'gte',
            'value': 1705078800000
        }

        _, outputs, _ = get_incidents_command(client, args)

        request_filters = get_incidents_request.last_request.json()['request_data']['filters']
        assert len(outputs['CoreApiModule.Incident(val.incident_id==obj.incident_id)']) >= 1
        if expected_starred:
            assert starred_filter_true in request_filters
            assert starred_fetch_window_filter in request_filters
            assert outputs['CoreApiModule.Incident(val.incident_id==obj.incident_id)'][0]['starred'] is True
        elif expected_starred is False:
            assert starred_filter_false in request_filters
            assert starred_fetch_window_filter not in request_filters
        else:  # expected_starred is None
            assert starred_filter_true not in request_filters
            assert starred_filter_false not in request_filters
            assert starred_fetch_window_filter not in request_filters

    @freeze_time("2024-01-15 17:00:00 UTC")
    @pytest.mark.parametrize('starred', [False, "False", 'false', None, ''])
    def test_get_starred_false_incident_list_from_fetch(self, mocker, requests_mock, starred):
        """
        Given: A query with starred=false parameter.
        When: Running get_incidents_command from fetch-incidents.
        Then: Ensure the request doesn't filter on starred incidents.
        """

        get_incidents_list_response = load_test_data('./test_data/get_starred_incidents_list.json')
        mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
        get_incidents_request = requests_mock.post(f'{Core_URL}/public_api/v1/incidents/get_incidents/',
                                                   json=get_incidents_list_response)

        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )

        args = {
            'incident_id_list': '1 day',
            'starred': starred,
            'starred_incidents_fetch_window': '3 days'
        }

        starred_filter_true = {
            'field': 'starred',
            'operator': 'eq',
            'value': True
        }

        starred_filter_false = {
            'field': 'starred',
            'operator': 'eq',
            'value': False
        }

        starred_fetch_window_filter = {
            'field': 'creation_time',
            'operator': 'gte',
            'value': 1705078800000
        }

        _, outputs, _ = get_incidents_command(client, args)

        request_filters = get_incidents_request.last_request.json()['request_data']['filters']
        assert len(outputs['CoreApiModule.Incident(val.incident_id==obj.incident_id)']) >= 1
        assert starred_filter_true not in request_filters
        assert starred_filter_false not in request_filters
        assert starred_fetch_window_filter not in request_filters

    @freeze_time("2024-01-15 17:00:00 UTC")
    @pytest.mark.parametrize('starred', [True, 'true', "True"])
    def test_get_starred_true_incident_list_from_fetch(self, mocker, starred):
        """
        Given: A query with starred=true parameter.
        When: Running get_incidents_command from fetch-incidents.
        Then: Ensure the request filters on starred incidents and contains the starred_fetch_window_filter filter.
        """

        get_incidents_list_response = load_test_data('./test_data/get_starred_incidents_list.json')
        mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
        handle_fetch_starred_mock = mocker.patch.object(CoreClient,
                                                        'handle_fetch_starred_incidents',
                                                        return_value=get_incidents_list_response["reply"]['incidents'])

        client = CoreClient(
            base_url=f'{Core_URL}/public_api/v1', headers={}
        )

        args = {
            'incident_id_list': '1 day',
            'starred': starred,
            'starred_incidents_fetch_window': '3 days'
        }

        starred_filter_true = {
            'field': 'starred',
            'operator': 'eq',
            'value': True
        }

        starred_fetch_window_filter = {
            'field': 'creation_time',
            'operator': 'gte',
            'value': 1705078800000
        }

        _, outputs, _ = get_incidents_command(client, args)

        handle_fetch_starred_mock.assert_called()
        request_filters = handle_fetch_starred_mock.call_args.args[2]['filters']
        assert len(outputs['CoreApiModule.Incident(val.incident_id==obj.incident_id)']) >= 1
        assert starred_filter_true in request_filters
        assert starred_fetch_window_filter in request_filters
        assert outputs['CoreApiModule.Incident(val.incident_id==obj.incident_id)'][0]['starred'] is True


INPUT_test_handle_outgoing_issue_closure = load_test_data('./test_data/handle_outgoing_issue_closure_input.json')


@pytest.mark.parametrize("args, expected_delta",
                         [
                             # close an incident from xsoar ui, and the incident type isn't cortex xdr incident
                             (INPUT_test_handle_outgoing_issue_closure["xsoar_ui_common_mapping"]["args"],
                              INPUT_test_handle_outgoing_issue_closure["xsoar_ui_common_mapping"]["expected_delta"]),
                             # close an incident from xsoar ui, and the incident type is cortex xdr incident
                             (INPUT_test_handle_outgoing_issue_closure["xsoar_ui_cortex_xdr_incident"]["args"],
                              INPUT_test_handle_outgoing_issue_closure["xsoar_ui_cortex_xdr_incident"]["expected_delta"]),
                             # close an incident from XDR
                             (INPUT_test_handle_outgoing_issue_closure["xdr"]["args"],
                              INPUT_test_handle_outgoing_issue_closure["xdr"]["expected_delta"])
                         ])
def test_handle_outgoing_issue_closure(args, expected_delta):
    """
    Given: An UpdateRemoteSystemArgs object.
    - case A: data & delta that match a case of closing an incident from xsoar ui, and the incident type isn't cortex xdr incident
    - case B: data & delta that match a case of closing an incident from xsoar ui, and the incident type is cortex xdr incident
    - case C: data & delta that match a case of closing an incident from XDR.
    When: Closing an incident.
    Then: Ensure the update_args has the expected value.
    - case A: a status is added with the correct value.
    - case B: a status is added with the correct value.
    - case C: a status isn't added. (If the closing status came from XDR, there is no need to update it again)
    """
    from CommonServerPython import UpdateRemoteSystemArgs

    remote_args = UpdateRemoteSystemArgs(args)
    handle_outgoing_issue_closure(remote_args)
    assert remote_args.delta == expected_delta


@pytest.mark.parametrize('custom_mapping, expected_resolved_status',
                         [
                             ("Other=Other,Duplicate=Other,False Positive=False Positive,Resolved=True Positive",
                              ["resolved_other", "resolved_other", "resolved_false_positive", "resolved_true_positive",
                               "resolved_security_testing", "resolved_other"]),

                             ("Other=True Positive,Duplicate=Other,False Positive=False Positive,Resolved=True Positive",
                              ["resolved_true_positive", "resolved_other", "resolved_false_positive",
                               "resolved_true_positive", "resolved_security_testing", "resolved_other"]),

                             ("Duplicate=Other", ["resolved_other", "resolved_other", "resolved_false_positive",
                                                  "resolved_true_positive", "resolved_security_testing", "resolved_other"]),

                             # Expecting default mapping to be used when no mapping provided.
                             ("", ["resolved_other", "resolved_duplicate", "resolved_false_positive",
                                   "resolved_true_positive", "resolved_security_testing", "resolved_other"]),

                             # Expecting default mapping to be used when improper mapping is provided.
                             ("Duplicate=RANDOM1, Other=Random2",
                              ["resolved_other", "resolved_duplicate", "resolved_false_positive",
                               "resolved_true_positive", "resolved_security_testing", "resolved_other"]),

                             ("Random1=Duplicate Incident",
                              ["resolved_other", "resolved_duplicate", "resolved_false_positive",
                               "resolved_true_positive", "resolved_security_testing", "resolved_other"]),

                             # Expecting default mapping to be used when improper mapping *format* is provided.
                             ("Duplicate=Other False Positive=Other",
                              ["resolved_other", "resolved_duplicate", "resolved_false_positive",
                               "resolved_true_positive", "resolved_security_testing", "resolved_other"]),

                             # Expecting default mapping to be used for when improper key-value pair *format* is provided.
                             ("Duplicate=Other, False Positive=Other True Positive=Other, Other=True Positive",
                              ["resolved_true_positive", "resolved_other", "resolved_false_positive",
                               "resolved_true_positive", "resolved_security_testing", "resolved_other"]),

                         ],
                         ids=["case-1", "case-2", "case-3", "empty-case", "improper-input-case-1", "improper-input-case-2",
                              "improper-input-case-3", "improper-input-case-4"]
                         )
def test_xsoar_to_xdr_flexible_close_reason_mapping(capfd, mocker, custom_mapping, expected_resolved_status):
    """
    Given:
        - A custom XSOAR->XDR close-reason mapping
        - Expected resolved XDR status according to the custom mapping.
    When
        - Handling outgoing issue closure (handle_outgoing_issue_closure(...) executed).
    Then
        - The resolved XDR statuses match the expected statuses for all possible XSOAR close-reasons.
    """
    from CoreIRApiModule import handle_outgoing_issue_closure
    from CommonServerPython import UpdateRemoteSystemArgs

    mocker.patch.object(demisto, 'params', return_value={"mirror_direction": "Both",
                                                         "custom_xsoar_to_xdr_close_reason_mapping": custom_mapping})

    possible_xsoar_close_reasons = list(XSOAR_RESOLVED_STATUS_TO_XDR.keys()) + ["CUSTOM_CLOSE_REASON"]
    for i, close_reason in enumerate(possible_xsoar_close_reasons):
        remote_args = UpdateRemoteSystemArgs({'delta': {'closeReason': close_reason},
                                              'status': 2,
                                              'inc_status': 2,
                                              'data': {'status': 'other'}
                                              })
        # Overcoming expected non-empty stderr test failures (Errors are submitted to stderr when improper mapping is provided).
        with capfd.disabled():
            handle_outgoing_issue_closure(remote_args)

        assert remote_args.delta.get('status')
        assert remote_args.delta['status'] == expected_resolved_status[i]


@pytest.mark.parametrize('data, expected_result',
                         [('{"reply": {"container": ["1.1.1.1"]}}', {"reply": {"container": ["1.1.1.1"]}}),
                          (b'XXXXXXX', b'XXXXXXX')])
def test_http_request_demisto_call(mocker, data, expected_result):
    """
    Given:
        - An XSIAM machine with a build version that supports demisto._apiCall() with RBAC validations.
    When:
        - Calling the http_request method.
    Then:
        - Make sure demisto._apiCall() is being called and the method returns the expected result.
        - converting to json is possible - do it and return json
        - converting to json is impossible - catch the error and return the data as is
    """
    from CoreIRApiModule import CoreClient
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={},
    )
    mocker.patch("CoreIRApiModule.FORWARD_USER_RUN_RBAC", new=True)
    mocker.patch.object(demisto, "_apiCall", return_value={'name': '/api/webapp/public_api/v1/distributions/get_versions/',
                                                           'status': 200,
                                                           'data': data})
    res = client._http_request(method="POST",
                               url_suffix="/distributions/get_versions/")
    assert expected_result == res


@pytest.mark.parametrize('allow_bin_response', [True, False])
def test_request_for_bin_file_via_demisto_call(mocker, allow_bin_response):
    """
    Given:
        - An XSIAM machine with a build version that supports demisto._apiCall() with RBAC validations.
        - case 1 - build version that support response of binary files.
        - case 2 - build version that doesn't support response of binary files.
    When:
        - Calling the http_request method.
    Then:
        - case 1 - Make sure the response are as expected (base64 decoded).
        - case 2 - Make sure en DemistoException was thrown with details about the server version that allowed bin response.
    """
    from CoreIRApiModule import CoreClient, ALLOW_BIN_CONTENT_RESPONSE_SERVER_VERSION, ALLOW_BIN_CONTENT_RESPONSE_BUILD_NUM
    import base64
    test_bin_data = b'test bin data'
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={},
    )
    mocker.patch("CoreIRApiModule.FORWARD_USER_RUN_RBAC", new=True)
    mocker.patch("CoreIRApiModule.ALLOW_RESPONSE_AS_BINARY", new=allow_bin_response)
    mocker.patch.object(demisto, "_apiCall", return_value={'name': '/api/webapp/public_api/v1/distributions/get_versions/',
                                                           'status': 200,
                                                           'data': base64.b64encode(test_bin_data)})
    try:
        res = client._http_request(method="get",
                                   resp_type='content')
        assert res == test_bin_data
    except DemistoException as e:
        assert f'{ALLOW_BIN_CONTENT_RESPONSE_SERVER_VERSION}-{ALLOW_BIN_CONTENT_RESPONSE_BUILD_NUM}' in str(e)


def test_terminate_process_command(mocker):
    """
    Given:
        - An XSIAM machine with a build version that supports demisto._apiCall() with RBAC validations.
        - instance_id_1
        - instance_id_2
        - agent_id
    When:
        - Calling the terminate_process_command method.
    Then:
        - case 1 - Make sure the response are as expected (action_id).
    """
    from CoreIRApiModule import CoreClient, terminate_process_command
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={},
    )

    mocker.patch("CoreIRApiModule.FORWARD_USER_RUN_RBAC", new=True)
    mocker.patch.object(demisto, "_apiCall", side_effect=[
        {'name': '/api/webapp/public_api/v1/endpoints/terminate_process',
         'status': 200,
         'data': json.dumps({'reply': {'group_action_id': 1}})},
        {'name': '/api/webapp/public_api/v1/endpoints/terminate_process',
         'status': 200,
         'data': json.dumps({'reply': {'group_action_id': 2}})}
    ]
    )

    result = terminate_process_command(client=client, args={'agent_id': '1', 'instance_id': ['instance_id_1', 'instance_id_2']})
    assert result.readable_output == ('### Action terminate process created on instance ids:'
                                      ' instance_id_1, instance_id_2\n|action_id|\n|---|\n| 1 |\n| 2 |\n')
    assert result.raw_response == [{'action_id': 1}, {'action_id': 2}]


def test_terminate_causality_command(mocker):
    """
    Given:
        - An XSIAM machine with a build version that supports demisto._apiCall() with RBAC validations.
        - causality_id
        - agent_id
    When:
        - Calling the terminate_causality_command method.
    Then:
        - case 1 - Make sure the response are as expected (action_id).
    """
    from CoreIRApiModule import CoreClient, terminate_causality_command
    client = CoreClient(
        base_url=f'{Core_URL}/public_api/v1', headers={},
    )

    mocker.patch("CoreIRApiModule.FORWARD_USER_RUN_RBAC", new=True)
    mocker.patch.object(demisto, "_apiCall", side_effect=[
        {'name': '/api/webapp/public_api/v1/endpoints/terminate_causality',
         'status': 200,
         'data': json.dumps({'reply': {'group_action_id': 1}})},
        {'name': '/api/webapp/public_api/v1/endpoints/terminate_causality',
         'status': 200,
         'data': json.dumps({'reply': {'group_action_id': 2}})}
    ]
    )

    result = terminate_causality_command(client=client, args={'agent_id': '1', 'causality_id': [
        'causality_id_1', 'causality_id_2']})
    assert result.readable_output == ('### Action terminate causality created on causality_id_1,'
                                      'causality_id_2\n|action_id|\n|---|\n| 1 |\n| 2 |\n')
    assert result.raw_response == [{'action_id': 1}, {'action_id': 2}]


def test_run_polling_command_values_raise_error(mocker):
    """
    Given -
        - run_polling_command arguments.

    When -
        - Running the run_polling_command

    Then
        - Make sure that an error is raised with the correct output.
    """
    from CoreIRApiModule import run_polling_command
    from CommonServerPython import DemistoException, ScheduledCommand
    from unittest.mock import Mock

    polling_args = {
        'endpoint_ids': '1', 'command_decision_field': 'action_id', 'action_id': '1', 'hide_polling_output': True
    }
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)
    client = Mock()
    mock_command_results = Mock()
    mock_command_results.raw_response = {"status": "TIMEOUT"}
    mock_command_results.return_value = mock_command_results
    client.get_command_results.return_value = mock_command_results
    mocker.patch('CoreIRApiModule.return_results')

    with pytest.raises(DemistoException) as e:
        run_polling_command(client=client,
                            args=polling_args,
                            cmd="core-terminate-causality",
                            command_function=Mock(),
                            command_decision_field="action_id",
                            results_function=mock_command_results,
                            polling_field="status",
                            polling_value=["PENDING",
                                           "IN_PROGRESS",
                                           "PENDING_ABORT"],
                            values_raise_error=["FAILED",
                                                "TIMEOUT",
                                                "ABORTED",
                                                "CANCELED"]
                            )
    assert str(e.value) == 'The command core-terminate-causality failed. Received status TIMEOUT'
