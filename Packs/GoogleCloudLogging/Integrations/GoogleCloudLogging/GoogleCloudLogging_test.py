import json
import io
import pytest
from CommonServerPython import *
import demistomock as demisto
import GoogleCloudLogging
from GSuiteApiModule import *

test_log_entries_command_data = [(1, {'next_token': '', 'filter': None,
                                      'organization_name': 'some_resource',
                                      'billing_account_name': 'some_resource',
                                      'folders_names': 'some_resource',
                                      'project_name': 'some_resource',
                                      'order_by': None, 'limit': 2,
                                      'page_size': None},
                                  {'resourceNames': ['projects/some_resource',
                                                     'organizations/some_resource',
                                                     'billingAccounts/some_resource'],
                                      'filter': None, 'orderBy': None, 'pageSize': 2}),
                                 (1, {'next_token': '', 'filter': None,
                                      'organization_name': 'some_resource',
                                      'billing_account_name': 'some_resource',
                                      'folders_names': 'some_resource',
                                      'project_name': 'some_resource',
                                      'order_by': None, 'limit': 2,
                                      'page_size': 3},
                                     {'resourceNames': ['projects/some_resource',
                                                        'organizations/some_resource',
                                                        'billingAccounts/some_resource'],
                                      'filter': None, 'orderBy': None, 'pageSize': 2}),
                                 (1, {'next_token': 'xx', 'filter': None,
                                      'organization_name': 'some_resource',
                                      'billing_account_name': 'some_resource',
                                      'folders_names': 'some_resource',
                                      'project_name': 'some_resource',
                                      'order_by': None, 'limit': None,
                                      'page_size': 3},
                                     {'resourceNames': ['projects/some_resource',
                                                        'organizations/some_resource',
                                                        'billingAccounts/some_resource'],
                                      'filter': None, 'orderBy': None, 'pageSize': 3,
                                      'pageToken': 'xx'}),
                                 (1, {'pageToken': 'xx', 'filter': None,
                                      'order_by': None, 'limit': None,
                                      'page_size': 3},
                                  {})]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


TEST_JSON = util_load_json('test_data/service_account_json.json')
DATA = util_load_json('test_data/test_data.json')


@pytest.fixture
def client():
    headers = {
        'Content-Type': 'application/json'
    }
    return GSuiteClient(TEST_JSON, verify=False, proxy=False, headers=headers)


def test_create_readable_output():
    """
    Given:
        - response from the google logging API.
    When:
        - Calling function create_readable_output
    Then:
        - Ensure the readable output is as expected.
    """
    from GoogleCloudLogging import create_readable_output
    result = create_readable_output(DATA.get('api_response').get('entries'))
    assert result == '### Lists log entries\n|TimeStamp|Log Name|Insert ID|Principal Email|Type|Project ID|Cluster Name|\n' \
                     '|---|---|---|---|---|---|---|\n| 2022-04-04T13:26:12.087281Z | logName |' \
                     ' wwww-wwww-wwww-www | user@example.com ' \
                     '| some_type | some_project_id | some_cluster_name |\n|' \
                     ' 2025-05-06T12:22:12.112188Z | logName | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx |' \
                     ' user@example.com | some_type |' \
                     ' some_project_id | some_cluster_name |\n|' \
                     ' 2027-07-07T12:27:12.112496Z | logName | xxxx-xxxx-xxxx-xxxx | user@example.com | some_type |' \
                     ' some_project_id | some_cluster_name |\n'


@pytest.mark.parametrize('limit, expected_result, request_page_size', [(1001, 2, 1), (2567, 3, 567), (3000, 3, 1000)])
def test_get_all_results(mocker, client, limit, request_page_size, expected_result):
    """
    Given:
        - client - GoogleCloudLoggingClient.
        - limit - limit greater than 1000.
    When:
        - Calling function get_all_results.
    Then:
        - Ensure the number of the API calls and the pageSize in the request.
    """
    from GoogleCloudLogging import get_all_results
    mocker_for_request = mocker.patch.object(GoogleCloudLogging, 'get_entries_request',
                                             return_value={'entries': [], 'nextPageToken': 'xxx'})
    get_all_results(client, limit, {'resourceNames': [''],
                                    'filter': None,
                                    'orderBy': '',
                                    'pageSize': None,
                                    'pageToken': None})
    assert mocker_for_request.call_args[0][1] == {'filter': None, 'orderBy': '',
                                                  'pageSize': request_page_size, 'pageToken': 'xxx', 'resourceNames': ['']}
    assert mocker_for_request.call_count == expected_result


@pytest.mark.parametrize('expected_call_count, args ,expected_request_body',
                         test_log_entries_command_data)
def test_log_entries_list_command(mocker, client, args, expected_call_count, expected_request_body):
    """
    Given:
        - client - GoogleCloudLoggingClient.
        - args - Command arguments from XSOAR.
        - expected_call_count - Expected call count.
        - expected_request_body - Expected request body.
    When:
        - Calling function get_all_results.
    Then:
        - Ensure the number of the API calls.
    """
    from GoogleCloudLogging import log_entries_list_command
    mocker_for_request = mocker.patch.object(GoogleCloudLogging, 'get_entries_request',
                                             return_value=DATA.get('api_response'))
    if not all(resource in args for resource in ['organization_name', 'billing_account_name', 'folders_names', 'project_name']):
        with pytest.raises(DemistoException) as ve:
            log_entries_list_command(client, args)
        assert str(ve.value) == 'At least one of the following resources must be provided: project_name, organization_name, ' \
            'billing_account_name, or folder_name.'
    else:
        command_result = log_entries_list_command(client, args)
        request_body = mocker_for_request.call_args[0][1]
        assert request_body == expected_request_body
        assert mocker_for_request.call_count == expected_call_count
        assert command_result.outputs == {'GoogleCloudLogging(true)': {'nextPageToken': 'xxxxxx-xxxxxx'},
                                          'GoogleCloudLogging.LogsEntry(val.insertId === obj.insertId)':
                                          DATA.get('api_response').get('entries')}
        assert command_result.readable_output == '### Lists log entries\n'\
            '|TimeStamp|Log Name|Insert ID|Principal Email|Type|Project ID|Cluster Name|\n'\
            '|---|---|---|---|---|---|---|\n|'\
            ' 2022-04-04T13:26:12.087281Z | logName | wwww-wwww-wwww-www | user@example.com | some_type |'\
            ' some_project_id | some_cluster_name |\n|'\
            ' 2025-05-06T12:22:12.112188Z | logName | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx | user@example.com |'\
            ' some_type | some_project_id | some_cluster_name |\n|'\
            ' 2027-07-07T12:27:12.112496Z | logName | xxxx-xxxx-xxxx-xxxx | user@example.com |'\
            ' some_type | some_project_id | some_cluster_name |\n'\
            '### Next page token\n|nextPageToken|\n|---|\n| xxxxxx-xxxxxx |\n'


@pytest.mark.parametrize('params, args, command, expected_result',
                         [({'credentials': {'password': "{334}"}}, {}, 'test-module',
                           'Unable to parse JSON string. Please verify the JSON is valid.'),
                          ({'credentials': {'password': json.dumps(TEST_JSON)}}, {}, 'test-module',
                           'ok')])
def test_main(mocker, params, args, command, expected_result):
    """
    Given:
        - params - params from XSOAR.
        - args - Command arguments from XSOAR.
        - command - Command name.
    When:
        - Calling main function.
    Then:
        - Ensure the returned message.
    """
    from GoogleCloudLogging import main
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value=command)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(sys, 'exit')
    mocker.patch.object(demisto, 'results')
    if params.get('credentials').get('password') == "{334}":
        with pytest.raises(Exception) as ve:
            main()
            assert str(ve.value) == expected_result
    else:
        main()
        call_args = demisto.results.call_args[0][0]
        if isinstance(call_args, str):
            assert call_args == expected_result
        else:
            assert call_args.get('Contents') == expected_result
