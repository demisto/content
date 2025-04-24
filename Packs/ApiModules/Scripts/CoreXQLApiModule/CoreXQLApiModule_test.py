import gzip
import json
from freezegun import freeze_time
import CoreXQLApiModule
import pytest
from CommonServerPython import *

CLIENT = CoreXQLApiModule.CoreClient(headers={}, base_url='some_mock_url', verify=False)
ENDPOINT_IDS = '"test1","test2"'
INTEGRATION_CONTEXT = {}


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def get_integration_context():
    return INTEGRATION_CONTEXT


def set_integration_context(integration_context):
    global INTEGRATION_CONTEXT
    INTEGRATION_CONTEXT = integration_context


# =========================================== TEST Built-In Queries helpers ===========================================#


@pytest.mark.parametrize(
    'input_arg, expected',
    [('12345678,87654321', '"12345678","87654321"'),
     ('[12345678, 87654321]', '"12345678","87654321"'),
     ("12345678", '"12345678"'),
     ("", '""'),
     ]
)
def test_wrap_list_items_in_double_quotes(input_arg, expected):
    """
    Given:
    - A string list to format.
    When:
    - Calling format_arg function.
    Then:
    - Ensure the returned string is correct.
    """
    response = CoreXQLApiModule.wrap_list_items_in_double_quotes(input_arg)
    assert response == expected


def test_get_file_event_query():
    """
    Given:
    - ENDPOINT_IDS and file_sha256 list (as a string).

    When:
    - Calling get_file_event_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'file_sha256': 'testSHA1,testSHA2'
    }
    response = CoreXQLApiModule.get_file_event_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter agent_id in ("test1","test2") and event_type = FILE and action_file_sha256
 in ("testSHA1","testSHA2")| fields agent_hostname, agent_ip_addresses, agent_id, action_file_path, action_file_sha256,
 actor_process_file_create_time'''


def test_get_process_event_query():
    """
    Given:
    - ENDPOINT_IDS and process_sha256 list (as a string).

    When:
    - Calling get_process_event_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'process_sha256': 'testSHA1,testSHA2'
    }
    response = CoreXQLApiModule.get_process_event_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter agent_id in ("test1","test2") and event_type = PROCESS and
 action_process_image_sha256 in ("testSHA1","testSHA2") | fields agent_hostname, agent_ip_addresses, agent_id,
 action_process_image_sha256, action_process_image_name,action_process_image_path, action_process_instance_id,
 action_process_causality_id, action_process_signature_vendor, action_process_signature_product,
 action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_instance_id,
 actor_process_causality_id'''


def test_get_dll_module_query():
    """
    Given:
    - ENDPOINT_IDS and loaded_module_sha256 list (as a string).

    When:
    - Calling get_dll_module_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'loaded_module_sha256': 'testSHA1,testSHA2'
    }
    response = CoreXQLApiModule.get_dll_module_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter agent_id in ("test1","test2") and event_type = LOAD_IMAGE and
 action_module_sha256 in ("testSHA1","testSHA2")| fields agent_hostname, agent_ip_addresses, agent_id,
 actor_effective_username, action_module_sha256, action_module_path, action_module_file_info,
 action_module_file_create_time, actor_process_image_name, actor_process_image_path, actor_process_command_line,
 actor_process_image_sha256, actor_process_instance_id, actor_process_causality_id'''


def test_get_network_connection_query():
    """
    Given:
    - ENDPOINT_IDS, local_ip_list, remote_ip_list and port_list (as a string).

    When:
    - Calling get_network_connection_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'local_ip': '1.1.1.1,2.2.2.2',
        'remote_ip': '3.3.3.3,4.4.4.4',
        'port': '7777,8888'
    }
    response = CoreXQLApiModule.get_network_connection_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter agent_id in ("test1","test2") and event_type = STORY
 and action_local_ip in("1.1.1.1","2.2.2.2") and action_remote_ip in("3.3.3.3","4.4.4.4") and action_remote_port in(7777,8888)|
 fields agent_hostname, agent_ip_addresses, agent_id, actor_effective_username, action_local_ip, action_remote_ip,
 action_remote_port, dst_action_external_hostname, action_country, actor_process_image_name, actor_process_image_path,
 actor_process_command_line, actor_process_image_sha256, actor_process_instance_id, actor_process_causality_id'''


def test_get_network_connection_query_only_remote_ip():
    """
    Given:
    - ENDPOINT_IDS and remote_ip_list (as a string).

    When:
    - Calling get_network_connection_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'remote_ip': '3.3.3.3,4.4.4.4',
    }
    response = CoreXQLApiModule.get_network_connection_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter agent_id in ("test1","test2") and event_type = STORY
  and action_remote_ip in("3.3.3.3","4.4.4.4") |
 fields agent_hostname, agent_ip_addresses, agent_id, actor_effective_username, action_local_ip, action_remote_ip,
 action_remote_port, dst_action_external_hostname, action_country, actor_process_image_name, actor_process_image_path,
 actor_process_command_line, actor_process_image_sha256, actor_process_instance_id, actor_process_causality_id'''


def test_get_registry_query():
    """
    Given:
    - ENDPOINT_IDS and reg_key_name list (as a string).

    When:
    - Calling get_registry_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'reg_key_name': 'testARG1,testARG2'
    }
    response = CoreXQLApiModule.get_registry_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter agent_id in ("test1","test2") and event_type = REGISTRY and
 action_registry_key_name in ("testARG1","testARG2") | fields agent_hostname, agent_id, agent_ip_addresses, agent_os_type,
 agent_os_sub_type, event_type, event_sub_type, action_registry_key_name, action_registry_value_name,
 action_registry_data'''


def test_get_event_log_query():
    """
    Given:
    - ENDPOINT_IDS and get_event_log list (as a string).

    When:
    - Calling get_event_log_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'event_id': '1234,4321'
    }
    response = CoreXQLApiModule.get_event_log_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter agent_id in ("test1","test2") and event_type = EVENT_LOG and
 action_evtlog_event_id in (1234,4321) | fields agent_hostname, agent_id, agent_ip_addresses, agent_os_type,
 agent_os_sub_type, action_evtlog_event_id, event_type, event_sub_type, action_evtlog_message,
 action_evtlog_provider_name'''


def test_get_dns_query():
    """
    Given:
    - ENDPOINT_IDS, external_domain and dns_query list (as a string).

    When:
    - Calling get_dns_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'external_domain': 'testARG1,testARG2',
        'dns_query': 'testARG3,testARG4',
    }
    response = CoreXQLApiModule.get_dns_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter (agent_id in ("test1","test2") and event_type = STORY) and
 (dst_action_external_hostname in ("testARG1","testARG2") or dns_query_name in ("testARG3","testARG4"))| fields
 agent_hostname, agent_id, agent_ip_addresses, agent_os_type, agent_os_sub_type, action_local_ip, action_remote_ip,
 action_remote_port, dst_action_external_hostname, dns_query_name, action_app_id_transitions, action_total_download,
 action_total_upload, action_country, action_as_data, os_actor_process_image_path, os_actor_process_command_line,
 os_actor_process_instance_id, os_actor_process_causality_id'''


def test_get_dns_query_no_external_domain_arg():
    """
    Given:
    - ENDPOINT_IDS and dns_query list (as a string).

    When:
    - Calling get_dns_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'dns_query': 'testARG3,testARG4',
    }
    response = CoreXQLApiModule.get_dns_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter (agent_id in ("test1","test2") and event_type = STORY) and
 (dst_action_external_hostname in ("") or dns_query_name in ("testARG3","testARG4"))| fields
 agent_hostname, agent_id, agent_ip_addresses, agent_os_type, agent_os_sub_type, action_local_ip, action_remote_ip,
 action_remote_port, dst_action_external_hostname, dns_query_name, action_app_id_transitions, action_total_download,
 action_total_upload, action_country, action_as_data, os_actor_process_image_path, os_actor_process_command_line,
 os_actor_process_instance_id, os_actor_process_causality_id'''


def test_get_file_dropper_query():
    """
    Given:
    - ENDPOINT_IDS, file_path and file_sha256 list (as a string).

    When:
    - Calling get_file_dropper_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'file_path': 'testARG1,testARG2',
        'file_sha256': 'testARG3,testARG4',
    }
    response = CoreXQLApiModule.get_file_dropper_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter (agent_id in ("test1","test2") and event_type = FILE and event_sub_type in (
 FILE_WRITE, FILE_RENAME)) and (action_file_path in ("testARG1","testARG2") or action_file_sha256 in ("testARG3","testARG4")) |
 fields agent_hostname, agent_ip_addresses, agent_id, action_file_sha256, action_file_path, actor_process_image_name,
 actor_process_image_path, actor_process_image_path, actor_process_command_line, actor_process_signature_vendor,
 actor_process_signature_product, actor_process_image_sha256, actor_primary_normalized_user,
 os_actor_process_image_path, os_actor_process_command_line, os_actor_process_signature_vendor,
 os_actor_process_signature_product, os_actor_process_image_sha256, os_actor_effective_username,
 causality_actor_remote_host,causality_actor_remote_ip'''


def test_get_file_dropper_query_no_file_path_arg():
    """
    Given:
    - ENDPOINT_IDS and file_sha256 list (as a string).

    When:
    - Calling get_file_dropper_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'file_sha256': 'testARG3,testARG4',
    }
    response = CoreXQLApiModule.get_file_dropper_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter (agent_id in ("test1","test2") and event_type = FILE and event_sub_type in (
 FILE_WRITE, FILE_RENAME)) and (action_file_path in ("") or action_file_sha256 in ("testARG3","testARG4")) |
 fields agent_hostname, agent_ip_addresses, agent_id, action_file_sha256, action_file_path, actor_process_image_name,
 actor_process_image_path, actor_process_image_path, actor_process_command_line, actor_process_signature_vendor,
 actor_process_signature_product, actor_process_image_sha256, actor_primary_normalized_user,
 os_actor_process_image_path, os_actor_process_command_line, os_actor_process_signature_vendor,
 os_actor_process_signature_product, os_actor_process_image_sha256, os_actor_effective_username,
 causality_actor_remote_host,causality_actor_remote_ip'''


def test_get_process_instance_network_activity_query():
    """
    Given:
    - ENDPOINT_IDS and process_instance_id list (as a string).

    When:
    - Calling get_process_instance_network_activity_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'process_instance_id': 'testARG1,testARG2',
    }
    response = CoreXQLApiModule.get_process_instance_network_activity_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter agent_id in ("test1","test2") and event_type = NETWORK and
 actor_process_instance_id in ("testARG1","testARG2") | fields agent_hostname, agent_ip_addresses, agent_id,
 action_local_ip, action_remote_ip, action_remote_port, dst_action_external_hostname, dns_query_name,
 action_app_id_transitions, action_total_download, action_total_upload, action_country, action_as_data,
 actor_process_image_sha256, actor_process_image_name , actor_process_image_path, actor_process_signature_vendor,
 actor_process_signature_product, actor_causality_id, actor_process_image_command_line, actor_process_instance_id'''


def test_get_process_causality_network_activity_query():
    """
    Given:
    - ENDPOINT_IDS and process_causality_id list (as a string).

    When:
    - Calling get_process_causality_network_activity_query function.

    Then:
    - Ensure the returned query is correct.
    """

    args = {
        'process_causality_id': 'testARG1,testARG2',
    }
    response = CoreXQLApiModule.get_process_causality_network_activity_query(endpoint_ids=ENDPOINT_IDS, args=args)

    assert response == '''dataset = xdr_data | filter agent_id in ("test1","test2") and event_type = NETWORK
 and actor_process_causality_id in ("testARG1","testARG2") | fields agent_hostname, agent_ip_addresses,agent_id,
 action_local_ip, action_remote_ip, action_remote_port, dst_action_external_hostname,dns_query_name,
 action_app_id_transitions, action_total_download, action_total_upload, action_country,action_as_data,
 actor_process_image_sha256, actor_process_image_name , actor_process_image_path,actor_process_signature_vendor,
 actor_process_signature_product, actor_causality_id,actor_process_image_command_line, actor_process_instance_id'''


# =========================================== TEST Helper Functions ===========================================#

@pytest.mark.parametrize(
    'time_to_convert,expected',
    [("3 seconds", {'relativeTime': 3000}),
     ("7 minutes", {'relativeTime': 420000}),
     ("5 hours", {'relativeTime': 18000000}),
     ("7 months", {'relativeTime': 18316800000}),
     ("2 years", {'relativeTime': 63158400000}),
     ("between 2021-01-01 00:00:00Z and 2021-02-01 12:34:56Z", {'from': 1609459200000, 'to': 1612182896000}),
     ]
)
@freeze_time('2021-08-26')
def test_convert_timeframe_string_to_json(time_to_convert, expected):
    """
    Given:
    - A relative time or time range to convert.

    When:
    - Calling convert_timeframe_string_to_json function.

    Then:
    - Ensure the returned timestamp is correct.
    """

    response = CoreXQLApiModule.convert_timeframe_string_to_json(time_to_convert=time_to_convert)

    assert response == expected


def test_start_xql_query_valid(mocker):
    """
    Given:
    - A valid query to search.

    When:
    - Calling start_xql_query function.

    Then:
    - Ensure the returned execution_id is correct.
    """
    args = {
        'query': 'test_query',
        'time_frame': '1 year'
    }
    mocker.patch.object(CLIENT, 'start_xql_query', return_value='execution_id')
    response = CoreXQLApiModule.start_xql_query(CLIENT, args=args)
    assert response == 'execution_id'


@pytest.mark.parametrize('tenant_id,expected', [
    ({'tenant_id': 'test_tenant_1'}, 'test_tenant_1'),
    ({'tenant_ids': 'test_tenants_2'}, 'test_tenants_2'),
    ({'tenant_id': 'test_tenant_3', 'tenant_ids': 'test_tenants_4'}, 'test_tenant_3')])
def test_start_xql_query_with_tenant_id_and_tenant_ids(mocker, tenant_id, expected):
    """
    This test is to ensure a fix of a bug will not be removed in the future.
    The bug was that the arg name is 'tenant_id', but the code was 'args.get('tenant_ids')'
    in order to fix that without BC in case someone is using it with the wrong arg name, we added support for both.
    Given:
    - A valid query to search.
    1. 'tenant_id' is the name of the key given in the args.
    2. 'tenant_ids' is the name of the key given in the args.
    3.both 'tenant_id' and 'tenant_ids' are given in the args.

    When:
    - Calling start_xql_query function.

    Then:
    - Ensure the call to start_xql_query is sent with the correct tenant_id.
    """
    args = {
        'query': 'test_query',
        'time_frame': '1 year',
    }
    args |= tenant_id

    res = mocker.patch.object(CLIENT, 'start_xql_query', return_value='execution_id')
    CoreXQLApiModule.start_xql_query(CLIENT, args=args)
    assert res.call_args[0][0].get('request_data').get('tenants')[0] == expected


def test_get_xql_query_results_success_under_1000(mocker):
    """
    Given:
    - a query ID which has 1 result.

    When:
    - Calling get_xql_query_results function.

    Then:
    - Ensure the results were retrieved properly.
    """
    args = {
        'query_id': 'query_id_mock',
        'time_frame': '1 year'
    }
    mock_response = {
        'status': 'SUCCESS',
        'number_of_results': 1,
        'query_cost': {
            "376699223": 0.0031591666666666665
        },
        'remaining_quota': 1000.0,
        'results': {
            'data': [{'x': 'test1'}]
        }
    }
    mocker.patch.object(CLIENT, 'get_xql_query_results', return_value=mock_response)
    response, file_data = CoreXQLApiModule.get_xql_query_results(CLIENT, args=args)
    assert response == {'status': 'SUCCESS',
                        'number_of_results': 1,
                        'query_cost': {'376699223': 0.0031591666666666665},
                        'remaining_quota': 1000.0,
                        'results': [{'x': 'test1'}],
                        'execution_id': 'query_id_mock'}
    assert file_data is None


def test_get_xql_query_results_success_more_than_1000(mocker):
    """
    Given:
    - a query ID which has more than 1000 results.

    When:
    - Calling get_xql_query_results function.

    Then:
    - Ensure the results were retrieved properly and a stream ID was returned.
    """
    args = {
        'query_id': 'query_id_mock',
        'time_frame': '1 year'
    }
    mock_response = {
        'status': 'SUCCESS',
        'number_of_results': 1500,
        'query_cost': {
            "376699223": 0.0031591666666666665
        },
        'remaining_quota': 1000.0,
        'results': {
            "stream_id": "test_stream_id"
        }
    }
    mocker.patch.object(CLIENT, 'get_xql_query_results', return_value=mock_response)
    mocker.patch.object(CLIENT, 'get_query_result_stream', return_value='FILE DATA')
    response, file_data = CoreXQLApiModule.get_xql_query_results(CLIENT, args=args)
    assert response == {'status': 'SUCCESS',
                        'number_of_results': 1500,
                        'query_cost': {'376699223': 0.0031591666666666665},
                        'remaining_quota': 1000.0,
                        'results': {'stream_id': 'test_stream_id'},
                        'execution_id': 'query_id_mock'}
    assert file_data == 'FILE DATA'


def test_get_xql_query_results_pending(mocker):
    """
    Given:
    - a query ID which will cause a pending status.

    When:
    - Calling get_xql_query_results function.

    Then:
    - Ensure the results were retrieved properly.
    """
    args = {
        'query_id': 'query_id_mock',
        'time_frame': '1 year'
    }
    mock_response = {
        "status": "PENDING"
    }
    mocker.patch.object(CLIENT, 'get_xql_query_results', return_value=mock_response)
    response, _ = CoreXQLApiModule.get_xql_query_results(CLIENT, args=args)
    assert response == {'status': 'PENDING',
                        'execution_id': 'query_id_mock',
                        'results': None}


def test_get_query_result_stream(mocker):
    """
    Given:
    - a stream_id.

    When:
    - Calling get_query_result_stream function.

    Then:
    - Ensure the results were retrieved properly.
    """
    stream_id = 'mock_stream_id'
    mocker.patch.object(CLIENT, 'get_query_result_stream', return_value='Raw Data')
    response = CoreXQLApiModule.get_query_result_stream(CLIENT, stream_id=stream_id)
    assert response == 'Raw Data'


def test_format_results_remove_empty_fields():
    """
    Given:
    - a list to format with remove_empty_fields flag turned on.

    When:
    - Calling format_results function.

    Then:
    - Ensure the list was formatted properly.
    """
    list_to_format = [
        {'h': 4},
        {'x': 1,
         'e': None,
         'y': 'FALSE',
         'z': {
             'w': 'NULL',
             'x': None,
         },
         's': {
             'a': 5,
             'b': None,
             'c': {
                 'time': 1629619736000,
                 'd': 3,
                 'v': 'TRUE'
             }
         }
         }
    ]
    expected = [
        {'h': 4},
        {'x': 1,
         'y': False,
         's': {
             'a': 5,
             'c': {
                 'time': '2021-08-22T08:08:56.000Z',
                 'd': 3,
                 'v': True
             }
         }
         }
    ]
    response = CoreXQLApiModule.format_results(list_to_format, remove_empty_fields=True)
    assert expected == response


def test_format_results_do_not_remove_empty_fields():
    """
    Given:
    - A list to format with remove_empty_fields flag turned off.

    When:
    - Calling format_results function.

    Then:
    - Ensure the list was formatted properly.
    """
    list_to_format = [
        {'h': 4},
        {'x': 1,
         'e': None,
         'y': 'FALSE',
         'z': {
             'w': 'NULL',
             'x': None,
         },
         's': {
             'a': 5,
             'b': None,
             'c': {
                 'time': 1629619736000,
                 'd': 3,
                 'v': 'TRUE'
             }
         }
         }
    ]
    expected = [
        {'h': 4},
        {'x': 1,
         'e': None,
         'y': False,
         'z': {
             'w': None,
             'x': None,
         },
         's': {
             'a': 5,
             'b': None,
             'c': {
                 'time': '2021-08-22T08:08:56.000Z',
                 'd': 3,
                 'v': True
             }
         }
         }
    ]
    response = CoreXQLApiModule.format_results(list_to_format, remove_empty_fields=False)
    assert expected == response


def test_start_xql_query_polling_not_supported(mocker):
    """
    Given:
    - A query that has a pending status.

    When:
    - Calling get_xql_query_results_polling_command function but polling is not supported.

    Then:
    - Ensure returned command results are correct.

    """
    query = 'MOCK_QUERY'
    mock_response = {'status': 'PENDING',
                     'execution_id': 'query_id_mock',
                     'results': None}
    mocker.patch.object(CLIENT, 'start_xql_query', return_value='1234')
    mocker.patch('CoreXQLApiModule.get_xql_query_results', return_value=(mock_response, None))
    mocker.patch('CoreXQLApiModule.is_demisto_version_ge', return_value=False)
    mocker.patch.object(demisto, 'command', return_value='xdr-xql-generic-query')
    command_results = CoreXQLApiModule.start_xql_query_polling_command(CLIENT, {'query': query, 'query_name': 'mock_name'})
    assert command_results.outputs == {'status': 'PENDING',
                                       'execution_id': 'query_id_mock',
                                       'results': None,
                                       'query_name': 'mock_name'}

# ================================ TEST Generic Query Functions version 6.2 and above ================================#


def test_start_xql_query_polling_command(mocker):
    """
    Given:
    - A query that has a successful status and the number of results is under 1000.

    When:
    - Calling get_xql_query_results_polling_command function.

    Then:
    - Ensure returned command results are correct and integration_context was cleared.

    """
    query = 'MOCK_QUERY'
    context = {
        'mock_id': {
            'query': 'mock_query',
            'time_frame': '3 days',
            'command_name': 'previous command',
            'query_name': 'mock_name',
        }
    }
    set_integration_context(context)
    mock_response = {'status': 'SUCCESS',
                     'number_of_results': 1,
                     'query_cost': {'376699223': 0.0031591666666666665},
                     'remaining_quota': 1000.0,
                     'results': [{'x': 'test1', 'y': None}],
                     'execution_id': 'query_id_mock'}
    mocker.patch.object(CLIENT, 'start_xql_query', return_value='1234')
    mocker.patch('CoreXQLApiModule.get_xql_query_results', return_value=(mock_response, None))
    mocker.patch.object(demisto, 'command', return_value='xdr-xql-generic-query')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    command_results = CoreXQLApiModule.start_xql_query_polling_command(CLIENT, {'query': query, 'query_name': 'mock_name'})
    assert command_results.outputs == {'status': 'SUCCESS', 'number_of_results': 1, 'query_name': 'mock_name',
                                       'query_cost': {'376699223': 0.0031591666666666665}, 'remaining_quota': 1000.0,
                                       'execution_id': 'query_id_mock', 'results': [{'x': 'test1'}]}
    assert '| query_id_mock | 1 | MOCK_QUERY | 376699223: 0.0031591666666666665 | mock_name | 1000.0 | SUCCESS |' in \
           command_results.readable_output
    assert 'y' in command_results.raw_response['results'][0]
    assert get_integration_context() == context


def test_start_xql_query_polling_command_http_request_failure(mocker):
    """
    Given:
    - A query that failed to start due to reaching the max allowed amount of parallel running queries.
    When:
    - Calling start_xql_query_polling_command function.
    Then:
    - Ensure the command will run again in the next polling interval instead of returning error.
    """
    from CoreXQLApiModule import start_xql_query_polling_command
    query = 'MOCK_QUERY'
    mocker.patch.object(CLIENT, 'start_xql_query', return_value='FAILURE')
    command_results = start_xql_query_polling_command(CLIENT, {'query': query, 'query_name': 'mock_name'})
    assert command_results.scheduled_command
    assert 'The maximum allowed number of parallel running queries has been reached.' in command_results.readable_output


def test_get_xql_query_results_polling_command_success_under_1000(mocker):
    """
    Given:
    - A query that has a successful status and the number of results is under 1000.

    When:
    - Calling get_xql_query_results_polling_command function.

    Then:
    - Ensure returned command results are correct and integration_context was cleared.

    """
    query = 'MOCK_QUERY'
    mock_response = {'status': 'SUCCESS',
                     'number_of_results': 1,
                     'query_cost': {'376699223': 0.0031591666666666665},
                     'remaining_quota': 1000.0,
                     'results': [{'x': 'test1', 'y': None}],
                     'execution_id': 'query_id_mock'}
    mocker.patch('CoreXQLApiModule.get_xql_query_results', return_value=(mock_response, None))
    mocker.patch.object(demisto, 'command', return_value='xdr-xql-generic-query')
    command_results = CoreXQLApiModule.get_xql_query_results_polling_command(CLIENT, {'query': query, })
    assert command_results.outputs == {'status': 'SUCCESS', 'number_of_results': 1, 'query_name': '',
                                       'query_cost': {'376699223': 0.0031591666666666665}, 'remaining_quota': 1000.0,
                                       'execution_id': 'query_id_mock', 'results': [{'x': 'test1'}]}
    assert '| query_id_mock | 1 | MOCK_QUERY | 376699223: 0.0031591666666666665 | 1000.0 | SUCCESS |' in \
           command_results.readable_output
    assert 'y' in command_results.raw_response['results'][0]


def test_get_xql_query_results_clear_integration_context_on_success(mocker):
    """
    Given:
    - A query that has a successful status and the number of results is under 1000.

    When:
    - Calling get_xql_query_results_polling_command function.

    Then:
    - Ensure the integration context was cleared.

    """
    query = 'MOCK_QUERY'
    mock_response = {'status': 'SUCCESS',
                     'number_of_results': 1,
                     'query_cost': {'376699223': 0.0031591666666666665},
                     'remaining_quota': 1000.0,
                     'results': [{'x': 'test1', 'y': None}],
                     'execution_id': 'query_id_mock'}
    mocker.patch('CoreXQLApiModule.get_xql_query_results', return_value=(mock_response, None))
    mocker.patch.object(demisto, 'command', return_value='xdr-xql-generic-query')
    command_results = CoreXQLApiModule.get_xql_query_results_polling_command(CLIENT, {'query': query})
    assert command_results.outputs == {'status': 'SUCCESS', 'number_of_results': 1, 'query_name': '',
                                       'query_cost': {'376699223': 0.0031591666666666665}, 'remaining_quota': 1000.0,
                                       'execution_id': 'query_id_mock', 'results': [{'x': 'test1'}]}
    assert '| query_id_mock | 1 | MOCK_QUERY | 376699223: 0.0031591666666666665 | 1000.0 | SUCCESS |' in \
           command_results.readable_output
    assert 'y' in command_results.raw_response['results'][0]


def test_get_xql_query_results_polling_command_success_more_than_1000(mocker):
    """
    Given:
    - A query that has a successful status and the number of results is more than 1000.

    When:
    - Calling get_xql_query_results_polling_command function.

    Then:
    - Ensure returned command results are correct.

    """
    query = 'MOCK_QUERY'
    mock_response = {'status': 'SUCCESS',
                     'number_of_results': 1500,
                     'query_cost': {'376699223': 0.0031591666666666665},
                     'remaining_quota': 1000.0,
                     'results': {'stream_id': 'test_stream_id'},
                     'execution_id': 'query_id_mock'}
    mocker.patch('CoreXQLApiModule.get_xql_query_results', return_value=(mock_response, 'File Data'))
    mocker.patch.object(demisto, 'command', return_value='xdr-xql-generic-query')
    mocker.patch('CoreXQLApiModule.fileResult',
                 return_value={'Contents': '', 'ContentsFormat': 'text', 'Type': 3, 'File': 'results.gz',
                               'FileID': '12345'})
    results = CoreXQLApiModule.get_xql_query_results_polling_command(CLIENT, {'query': query})
    assert results[0] == {'Contents': '', 'ContentsFormat': 'text', 'Type': 3, 'File': 'results.gz', 'FileID': '12345'}
    command_result = results[1]
    assert command_result.outputs == {'status': 'SUCCESS', 'number_of_results': 1500, 'query_name': '',
                                      'query_cost': {'376699223': 0.0031591666666666665}, 'remaining_quota': 1000.0,
                                      'results': {'stream_id': 'test_stream_id'}, 'execution_id': 'query_id_mock'}


def test_get_xql_query_results_polling_command_success_more_than_1000_results_parse_to_context(mocker):
    """
    Given:
    - A query that has a successful status and the number of results is more than 1000.

    When:
    - Calling get_xql_query_results_polling_command function with 'parse_result_file_to_context' argument set to True.

    Then:
    - Ensure returned command results are correct.
    - Ensure the results were parsed to context instead of being extracted to a file.

    """
    query = 'MOCK_QUERY'
    mock_response = {'status': 'SUCCESS',
                     'number_of_results': 1500,
                     'query_cost': {'376699223': 0.0031591666666666665},
                     'remaining_quota': 1000.0,
                     'results': {'stream_id': 'test_stream_id'},
                     'execution_id': 'query_id_mock'}
    # The results that should be parsed to context instead of being extracted to a file:
    expected_results_in_context = [
        {"_time": "2021-10-14 03:59:09.793 UTC", "event_id": "123", "_vendor": "PANW", "_product": "XDR agent",
         "insert_timestamp": "2021-10-14 04:02:12.883114 UTC"},
        {"_time": "2021-10-14 03:59:09.809 UTC", "event_id": "234", "_vendor": "PANW", "_product": "XDR agent",
         "insert_timestamp": "2021-10-14 04:02:12.883114 UTC"},
        {"_time": "2021-10-14 04:00:27.78 UTC", "event_id": "456", "_vendor": "PANW", "_product": "XDR agent",
         "insert_timestamp": "2021-10-14 04:04:34.332563 UTC"},
        {"_time": "2021-10-14 04:00:27.797 UTC", "event_id": "567", "_vendor": "PANW", "_product": "XDR agent",
         "insert_timestamp": "2021-10-14 04:04:34.332563 UTC"}
    ]
    # Creates the mocked data which returns from 'CoreXQLApiModule.get_xql_query_results' command:
    mock_file_data = b''
    for item in expected_results_in_context:
        mock_file_data += json.dumps(item).encode('utf-8')
        mock_file_data += b'\n'
    compressed_mock_file_data = gzip.compress(mock_file_data)

    mocker.patch('CoreXQLApiModule.get_xql_query_results', return_value=(mock_response, compressed_mock_file_data))
    mocker.patch.object(demisto, 'command', return_value='xdr-xql-generic-query')
    results = CoreXQLApiModule.get_xql_query_results_polling_command(CLIENT, {'query': query,
                                                                              'parse_result_file_to_context': True})

    assert results.outputs.get('results', []) == expected_results_in_context, \
        'There might be a problem in parsing the results into the context'
    assert results.outputs == {'status': 'SUCCESS', 'number_of_results': 1500, 'query_name': '',
                               'query_cost': {'376699223': 0.0031591666666666665}, 'remaining_quota': 1000.0,
                               'results': expected_results_in_context, 'execution_id': 'query_id_mock'}


def test_get_xql_query_results_polling_command_pending(mocker):
    """
    Given:
    - A query that has a pending status.

    When:
    - Calling get_xql_query_results_polling_command function.

    Then:
    - Ensure returned command results are correct and the scheduled_command is set properly.

    """
    query = 'MOCK_QUERY'
    mock_response = {'status': 'PENDING',
                     'execution_id': 'query_id_mock',
                     'results': None}
    mocker.patch('CoreXQLApiModule.get_xql_query_results', return_value=(mock_response, None))
    mocker.patch('CoreXQLApiModule.is_demisto_version_ge', return_value=True)
    mocker.patch.object(demisto, 'command', return_value='xdr-xql-generic-query')
    mocker.patch('CoreXQLApiModule.ScheduledCommand', return_value=None)
    command_results = CoreXQLApiModule.get_xql_query_results_polling_command(CLIENT, {'query': query})
    assert command_results.readable_output == 'Query is still running, it may take a little while...'
    assert command_results.outputs == {'status': 'PENDING', 'execution_id': 'query_id_mock', 'results': None, 'query_name': ''}


def test_get_xql_quota_command(mocker):
    """
    Given:
    - A client object.

    When:
    - Calling get_xql_quota_command function.

    Then:
    - Ensure returned command results are correct.

    """
    mock_response = {
        "reply": {
            "license_quota": 1000,
            "additional_purchased_quota": 0,
            "used_quota": 0.0
        }
    }
    mocker.patch.object(CLIENT, 'get_xql_quota', return_value=mock_response)
    response = CoreXQLApiModule.get_xql_quota_command(CLIENT, {})
    assert '|Additional Purchased Quota|License Quota|Used Quota|' in response.readable_output
    assert response.outputs == {'license_quota': 1000, 'additional_purchased_quota': 0, 'used_quota': 0.0}


# =========================================== TEST Built-In Queries ===========================================#


def test_get_built_in_query_results_polling_command(mocker):
    """
    Given:
    - A user arguments.

    When:
    - Calling get_built_in_query_results_polling_command function.

    Then:
    - Ensure start_xql_query_polling_command function was called with the right query and argument.

    """
    args = {
        'endpoint_id': '123456,654321',
        'file_sha256': 'abcde,edcba,p1p2p3',
        'extra_fields': 'EXTRA1, EXTRA2',
        'limit': '400',
        'tenants': "tenantID,tenantID",
        'time_frame': '7 days'
    }
    res = mocker.patch('CoreXQLApiModule.start_xql_query_polling_command')
    mocker.patch.object(demisto, 'command', return_value='xdr-xql-file-event-query')
    CoreXQLApiModule.get_built_in_query_results_polling_command(CLIENT, args)
    assert (
        res.call_args.args[1]["query"]
        == """dataset = xdr_data | filter agent_id in ("123456","654321") and event_type = FILE and action_file_sha256
 in ("abcde","edcba","p1p2p3")| fields agent_hostname, agent_ip_addresses, agent_id, action_file_path, action_file_sha256,
 actor_process_file_create_time, EXTRA1, EXTRA2 | limit 400"""
    )
    assert res.call_args.args[1]['tenants'] == ["tenantID", "tenantID"]
    assert res.call_args.args[1]['time_frame'] == '7 days'
