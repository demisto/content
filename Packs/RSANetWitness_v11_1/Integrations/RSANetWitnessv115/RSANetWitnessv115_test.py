import json
import io
import pytest
import demistomock as demisto

from CommonServerPython import CommandResults, DemistoException
from RSANetWitnessv115 import Client, list_incidents_command, update_incident_command, remove_incident_command, \
    incident_add_journal_entry_command, incident_list_alerts_command, services_list_command, hosts_list_command, \
    snapshots_list_for_host_command, snapshot_details_get_command, files_list_command, scan_request_command, \
    host_alerts_list_command, file_alerts_list_command, file_download_command, mft_download_request_command, \
    system_dump_download_request_command, process_dump_download_request_command, endpoint_isolate_from_network_command, \
    endpoint_update_exclusions_command, endpoint_isolation_remove_command, endpoint_command, create_time, create_filter, \
    create_exclusions_list, remove_duplicates_in_items, remove_duplicates_for_fetch, fetch_incidents, paging_command


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def write_to_json(path, new_data):
    with io.open(path, mode='w') as f:
        f.write(json.dumps(new_data))


client = Client(server_url='http://test.com', verify=False, proxy=False, headers={}, service_id='abc',
                fetch_time='1 year',
                fetch_limit='1', cred={'identifier': 'test', 'password': 'test'})
http_responses = util_load_json('test_data/http_responses.json')
command_results = util_load_json('test_data/command_results.json')
args_single_inc = {'id': 'INC-1'}


@pytest.mark.parametrize(
    'function_to_mock, function_to_test, args, http_response_key, expected_command_results_key', [
        ('get_incident_request', list_incidents_command, {'id': 'INC-1'}, 'single_incident', 'single_incident'),
        ('list_incidents_request', list_incidents_command, {}, 'list_incidents', 'list_incidents'),
        ('update_incident_request', update_incident_command, {'id': 'INC-1', 'status': 'InProgress'}, 'single_incident',
         'update_incident'),
        ('remove_incident_request', remove_incident_command, {'id': 'INC-1'}, 'empty_response', 'empty_response'),
        ('incident_add_journal_entry_request', incident_add_journal_entry_command, {'id': 'INC-1', 'notes': 'test',
                                                                                    'author': 'Admin'},
         'empty_response', 'empty_response'),
        ('incident_list_alerts_request', incident_list_alerts_command, {'id': 'INC-1'}, 'list_alerts_for_incident',
         'list_alerts_for_incident'),
        ('services_list_request', services_list_command, {}, 'services_list', 'services_list'),
        ('hosts_list_request', hosts_list_command, {}, 'hosts_list', 'hosts_list'),
        ('snapshots_list_for_host_request', snapshots_list_for_host_command, {'agent_id': '1'}, 'snapshot_list',
         'snapshot_list'),
        ('snapshot_details_get_request', snapshot_details_get_command,
         {'agent_id': '1', 'snapshot_timestamp': '"2021-10-19T08:51:50.913Z"', 'limit': '1'}, 'snapshot_details',
         'snapshot_details'),
        ('files_list_request', files_list_command, {}, 'files_list', 'files_list'),
        ('scan_request_request', scan_request_command, {'agent_id': '1'}, 'empty_response', 'empty_response'),
        ('host_alerts_list_request', host_alerts_list_command, {'agent_id': '1'}, 'host_alerts', 'host_alerts'),
        ('file_alerts_list_request', file_alerts_list_command, {'check_sum': '1'}, 'file_alerts', 'file_alerts'),
        ('file_download_request', file_download_command, {'path': 'test/path'}, 'empty_response', 'empty_response'),
        ('mft_download_request_request', mft_download_request_command, {'agent_id': '1'}, 'empty_response',
         'empty_response'),
        ('system_dump_download_request_request', system_dump_download_request_command, {'agent_id': '1'},
         'empty_response', 'empty_response'),
        ('process_dump_download_request_request', process_dump_download_request_command, {'agent_id': '1'},
         'empty_response', 'empty_response'),
        ('endpoint_isolate_from_network_request', endpoint_isolate_from_network_command, {'agent_id': '1'},
         'empty_response', 'empty_response'),
        ('endpoint_update_exclusions_request', endpoint_update_exclusions_command, {'agent_id': '1'},
         'empty_response', 'empty_response'),
        ('endpoint_isolation_remove_request', endpoint_isolation_remove_command, {'agent_id': '1'},
         'empty_response', 'empty_response')
    ])
def test_commands(mocker, function_to_mock, function_to_test, args, http_response_key, expected_command_results_key):
    """
        Given:
        - RSA NW client.

        When:
         Calling the relevant command with basic arguments.

        Then:
         Assert the command outputs are as expected.

    """
    mocked_http_response = http_responses[http_response_key]
    expected_command_results = command_results[expected_command_results_key]

    mocker.patch.object(client, function_to_mock, return_value=mocked_http_response)

    command_result: CommandResults = function_to_test(client, args)
    assert command_result.outputs == expected_command_results


def test_hosts_command_bad_filter(mocker):
    """
     Given:
        - RSA NW client.

        When:
         Calling the hosts_list command with bad filter

        Then:
         Value Error is raised.
    """
    mocker.patch.object(client, 'hosts_list_request', return_value={})
    with pytest.raises(DemistoException, match="filter structure is invalid"):
        hosts_list_command(client, {"filter": 'bad:filter'})


def test_endpoint_command_service_id_error(mocker):
    """
     Given:
        - RSA NW client.

        When:
         Calling the endpoint_command command without service_id in client.

        Then:
         Error is raised.
    """
    no_service_id_client = Client(server_url='http://test.com', verify=False, proxy=False, headers={}, service_id=None,
                                  fetch_time='1 year', fetch_limit='100', cred={})

    mocker.patch.object(no_service_id_client, 'hosts_list_request', return_value={})
    with pytest.raises(DemistoException, match="No Service Id provided - To use endpoint command via RSA NetWitness"
                                               " service id must be set in the integration configuration."):
        endpoint_command(no_service_id_client, {})


def test_endpoint_command(mocker):
    """
        Given:
        - RSA NW client.

        When:
         Calling the endpoint command with basic arguments.

        Then:
         Assert the command outputs are as expected (common results list).

    """
    mocked_http_response = http_responses['hosts_list']
    expected_command_results = command_results['endpoint_command']
    mocker.patch.object(client, 'hosts_list_request', return_value=mocked_http_response)

    command_result = endpoint_command(client, {'id': '1'})
    assert command_result[0].to_context() == expected_command_results


def test_create_time():
    """
        Given:
        - A date.

        When:
         Calling the create_time function.

        Then:
         Assert the result date string is as expected.

    """
    res = create_time('2020-1-1')
    assert res == '2020-01-01T00:00:00.00Z'


def test_create_filter():
    """
        Given:
        - Args dict.

        When:
         Calling the create_filter function.

        Then:
         Assert the filter is as expected.

    """
    args = {'agentId': '1', 'riskScore': '1', 'ip': '1.1.1.1,2.3.4.5', 'hostName': 'host_name_test'}
    expected_filter = util_load_json('test_data/create_filter_res.json')
    res = create_filter(args)
    assert res == expected_filter


def test_create_exclusions_list():
    """
        Given:
        - IP's list in string form from mixed types (v4 and v6).

        When:
         Calling the create_exclusions_list function.

        Then:
         Assert the result is the expected list.

    """
    ip_list = '1.2.3.4,0000:0000:0000:0000:0000:0000:0000:0000'
    res = create_exclusions_list(ip_list)

    assert res == [{'ip': '1.2.3.4', 'v4': True}, {'ip': '0000:0000:0000:0000:0000:0000:0000:0000', 'v4': False}]


def test_remove_duplicates_in_items():
    """
        Given:
        - List of incident's id duplicate items

        When:
         Calling the remove_duplicates_in_items

        Then:
         Assert the result is list without duplicates.

    """

    inc_list = [{'id': '1'}, {'id': '2'}, {'id': '1'}]
    new_list = remove_duplicates_in_items(inc_list, 'id')

    assert new_list == [{'id': '1'}, {'id': '2'}]


def test_remove_duplicates_for_fetch():
    """
        Given:
        - List of incident's and list of id's

        When:
         Calling the remove_duplicates_for_fetch.

        Then:
         Assert the result is list without given id's.

    """

    inc_list = [{'id': '1'}, {'id': '2'}]
    ids_list = ['1']
    new_list = remove_duplicates_for_fetch(inc_list, ids_list)

    assert new_list == [{'id': '2'}]


def test_get_incidents(mocker):
    """
            Given:
            - client with fetch parameters

            When:
             Calling the get_incidents command.

            Then:
             Assert the amount of results is according to fetch limit.

        """

    fetch_responses = util_load_json('test_data/fetch_results.json')
    mocked_http_response = fetch_responses['get_inc_response']
    mocker.patch.object(client, 'list_incidents_request', return_value=mocked_http_response)

    items, _, timestamp = client.get_incidents()
    assert items == fetch_responses['get_inc_results']


def test_fetch_incidents(mocker):
    """
            Given:
            client with fetch parameters

            When:
             Calling the fetch_incidents command.

            Then:
             Assert that the incidents received are as expected

        """
    fetch_responses = util_load_json('test_data/fetch_results.json')
    mocked_http_response = fetch_responses['get_inc_response']
    mocker.patch.object(client, 'list_incidents_request', return_value=mocked_http_response)

    incidents = fetch_incidents(client)
    assert incidents == fetch_responses['fetch_results']


def test_generate_token(mocker):
    """
        Given:
        client with credentials

        When:
        Calling the generate_token() command.

        Then:
        Make api request and save the new token and refresh token

    """
    token_resp = util_load_json('test_data/token_resp.json')
    mocker.patch.object(client, '_http_request', return_value=token_resp)
    mocker.patch.object(demisto, 'setIntegrationContext')
    client.generate_new_token()
    assert client.refresh_token == token_resp['refreshToken']


def test_paging_command(mocker):
    """
        Given:
        A - command to run with no limit and page size = 2
        B - command to run with limit that require 2 requests

        When:
        Calling the paging_command.

        Then:
        Assert results are as expected and paging happens.

    """
    paging_data = util_load_json('test_data/paging_command_data.json')
    mocker.patch.object(client, 'list_incidents_request', return_value=paging_data['api_response'])
    _, no_limit_results = paging_command(None, '2', None, client.list_incidents_request)
    _, limit_req_results = paging_command(2, None, None, client.list_incidents_request)

    assert no_limit_results == limit_req_results == paging_data['results']
