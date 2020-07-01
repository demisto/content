import pytest
from ServiceDeskPlus import Client, create_request_command, update_request_command, list_requests_command, \
    linked_request_command, get_resolutions_list_command, delete_request_command, assign_request_command, \
    pickup_request_command, modify_linked_request_command, add_resolution_command, generate_refresh_token, \
    create_output, args_to_query, create_modify_linked_input_data, create_human_readable, resolution_human_readable, \
    create_requests_list_info, create_fetch_list_info, fetch_incidents, close_request_command, create_udf_field
from test_data.response_constants import RESPONSE_CREATE_REQUEST, RESPONSE_UPDATE_REQUEST, \
    RESPONSE_LIST_SINGLE_REQUEST, RESPONSE_LIST_MULTIPLE_REQUESTS, RESPONSE_LINKED_REQUEST_LIST, \
    RESPONSE_RESOLUTION_LIST, RESPONSE_NO_RESOLUTION_LIST, RESPONSE_LINK_REQUEST, RESPONSE_UNLINK_REQUEST, \
    RESPONSE_GENERATE_REFRESH_TOKEN, RESPONSE_FETCH_INCIDENTS
from test_data.result_constants import EXPECTED_CREATE_REQUEST, EXPECTED_UPDATE_REQUEST, EXPECTED_LIST_SINGLE_REQUEST, \
    EXPECTED_LIST_MULTIPLE_REQUESTS, EXPECTED_LINKED_REQUEST_LIST, EXPECTED_RESOLUTION_LIST, EXPECTED_NO_RESOLUTION_LIST


# test commands with context:
@pytest.mark.parametrize('command, args, response, expected_result', [
    (create_request_command, {'subject': 'Create request test', 'mode': 'E-Mail', 'requester': 'First Last',
                              'level': 'Tier 1', 'impact': 'Affects Group', 'priority': 'High', 'status': 'On Hold',
                              'request_type': 'Incident', 'description': 'The description of the request',
                              'urgency': 'Normal', 'group': 'Network'}, RESPONSE_CREATE_REQUEST,
     EXPECTED_CREATE_REQUEST),
    (update_request_command, {'request_id': '123640000000240013', 'description': 'Update the description',
                              'impact': 'Affects Business'}, RESPONSE_UPDATE_REQUEST, EXPECTED_UPDATE_REQUEST),
    (list_requests_command, {'request_id': '123640000000240013'}, RESPONSE_LIST_SINGLE_REQUEST,
     EXPECTED_LIST_SINGLE_REQUEST),
    (list_requests_command, {'page_size': '3'}, RESPONSE_LIST_MULTIPLE_REQUESTS, EXPECTED_LIST_MULTIPLE_REQUESTS),
    (linked_request_command, {'request_id': '123640000000246001'}, RESPONSE_LINKED_REQUEST_LIST,
     EXPECTED_LINKED_REQUEST_LIST),
    (get_resolutions_list_command, {'request_id': '123640000000241001'}, RESPONSE_RESOLUTION_LIST,
     EXPECTED_RESOLUTION_LIST),
    (get_resolutions_list_command, {'request_id': '123640000000241001'}, RESPONSE_NO_RESOLUTION_LIST,
     EXPECTED_NO_RESOLUTION_LIST)
])
def test_commands(command, args, response, expected_result, mocker):
    """Unit test
    Given
    - command main func
    - command args
    - command raw response
    When
    - mock the ServiceDeskPlus response
    Then
    - convert the result to human readable table
    - create the context
    validate the entry context
    """
    mocker.patch('ServiceDeskPlus.Client.get_access_token')
    client = Client('server_url', 'use_ssl', 'use_proxy', 'client_id', 'client_secret', 'refresh_token')
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]


# test commands without context:
@pytest.mark.parametrize('command, args, response, expected_result', [
    (delete_request_command, {'request_id': '1234'}, {}, "### Successfully deleted request(s) ['1234']"),
    (delete_request_command, {'request_id': '1234,5678'}, {}, "### Successfully deleted request(s) ['1234', '5678']"),
    (close_request_command, {'request_id': '1234'}, {}, '### Successfully closed request 1234'),
    (assign_request_command, {'request_id': '1234'}, {}, '### Service Desk Plus request 1234 was successfully assigned'),
    (pickup_request_command, {'request_id': '1234'}, {}, '### Service Desk Plus request 1234 was successfully picked up'),
    (modify_linked_request_command, {'action': 'Link', 'request_id': '1234', 'linked_requests_id': '5678'},
     RESPONSE_LINK_REQUEST, '## Request successfully linked'),
    (modify_linked_request_command, {'action': 'Link', 'request_id': '1234', 'linked_requests_id': '5678'},
     RESPONSE_LINK_REQUEST, '## Request successfully linked'),
    (modify_linked_request_command, {'action': 'Unlink', 'request_id': '1234', 'linked_requests_id': '5678'},
     RESPONSE_UNLINK_REQUEST, '## The request[s] link are removed successfully.'),
    (add_resolution_command, {'request_id': '1234', 'resolution_content': 'resolution message',
                              'add_to_linked_requests': 'true'}, RESPONSE_UNLINK_REQUEST,
     '### Resolution was successfully added to 1234 and the linked requests'),
    (add_resolution_command, {'request_id': '1234', 'resolution_content': 'resolution message',
                              'add_to_linked_requests': 'false'}, RESPONSE_UNLINK_REQUEST,
     '### Resolution was successfully added to 1234'),
    (generate_refresh_token, {'code': '147852369'}, RESPONSE_GENERATE_REFRESH_TOKEN, '### Refresh Token: 987654321\n '
                                                                                     'Please paste the Refresh Token in'
                                                                                     ' the instance configuration and '
                                                                                     'save it for future use.')

])
def test_command_hr(command, args, response, expected_result, mocker):
    """Unit test
    Given
    - command main func
    - command args
    - command raw response
    When
    - mock the ServiceDeskPlus response
    Then
    - convert the result to human readable table
    validate the human readable output
    """
    mocker.patch('ServiceDeskPlus.Client.get_access_token')
    client = Client('server_url', 'use_ssl', 'use_proxy', 'client_id', 'client_secret', 'refresh_token')
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[0]


# test helper functions:
def test_create_output():
    input = RESPONSE_CREATE_REQUEST.get('request')
    expected_output = EXPECTED_CREATE_REQUEST.get('ServiceDeskPlus(val.ID===obj.ID)').get('Request')
    assert create_output(input) == expected_output


def test_args_to_query():
    assign_input = {'group': 'group1', 'technician': 'tech name'}
    expected_assign_output = {'request': {'group': {'name': 'group1'}, 'technician': {'name': 'tech name'}}}
    assert args_to_query(assign_input) == expected_assign_output

    create_input = {'subject': 'request subject', 'group': 'group1', 'impact': 'Affects Business', 'requester': 'name'}
    expected_create_output = {'request': {'subject': 'request subject', 'group': {'name': 'group1'},
                                          'impact': {'name': 'Affects Business'}, 'requester': {'name': 'name'}}}
    assert args_to_query(create_input) == expected_create_output


def test_create_modify_linked_input_data():
    linked_request_id = ['1234']
    comment = 'testing one request'
    expected_output = {'link_requests': [{'linked_request': {'id': '1234'}, 'comments': 'testing one request'}]}
    assert create_modify_linked_input_data(linked_request_id, comment) == expected_output

    linked_request_id = ['1234', '5678']
    comment = 'testing two request'
    expected_output = {'link_requests': [{'linked_request': {'id': '1234'}, 'comments': 'testing two request'},
                                         {'linked_request': {'id': '5678'}, 'comments': 'testing two request'}]}
    assert create_modify_linked_input_data(linked_request_id, comment) == expected_output

    linked_request_id = ['1234', '5678', '0912']
    expected_output = {'link_requests': [{'linked_request': {'id': '1234'}},
                                         {'linked_request': {'id': '5678'}},
                                         {'linked_request': {'id': '0912'}}]}
    assert create_modify_linked_input_data(linked_request_id, '') == expected_output


def test_create_human_readable():
    input = {'CreatedTime': 'creation_time', 'Id': '1234', 'Requester': {'name': 'First Last', 'mobile': None,
                                                                         'id': '123640000000244019', 'photo_url': 'url',
                                                                         'is_vip_user': False, 'department': None},
             'Technician': {'email_id': 'i@id', 'cost_per_hour': '0', 'phone': None, 'name': 'tech1'}, 'Status': 'Open',
             'Subject': 'test human readable'}
    expected_output = {'CreatedTime': 'creation_time', 'Id': '1234', 'Requester': 'First Last', 'Technician': 'tech1',
                       'Status': 'Open', 'Subject': 'test human readable'}
    assert create_human_readable(input) == expected_output


def test_resolution_human_readable():
    input = {'Content': 'res contents', 'SubmittedOn': 'submittion_date', 'SubmittedBy': {'email_id': 'i@id',
                                                                                          'phone': None,
                                                                                          'name': 'submitter'}}
    expected_output = {'Content': 'res contents', 'SubmittedOn': 'submittion_date', 'SubmittedBy': 'submitter'}
    assert resolution_human_readable(input) == expected_output


def test_create_requests_list_info():
    start_index, row_count, search_fields, filter_by = '0', '15', 'a, b, c', 'filter'
    expected_output = {'list_info': {'start_index': '0', 'row_count': '15', 'search_fields': 'a, b, c',
                                     'filter_by': 'filter'}}
    assert create_requests_list_info(start_index, row_count, search_fields, filter_by) == expected_output


def test_create_fetch_list_info():
    time_from, time_to, status, fetch_filter, fetch_limit = 'from', 'to', 'status', '', 10
    expected_output = {'list_info': {'search_criteria': [{'field': 'created_time', 'values': ['from', 'to'],
                                                          'condition': 'between'},
                                                         {'field': 'status.name', 'values': ['status'],
                                                          'condition': 'is', 'logical_operator': 'AND'}],
                                     'sort_field': 'created_time', 'sort_order': 'asc', 'row_count': 10}}
    assert create_fetch_list_info(time_from, time_to, status, fetch_filter, fetch_limit) == expected_output

    time_from, time_to, status, fetch_limit = 'from', 'to', 'status', 15
    fetch_filter = "{'field': 'technician.name', 'values': 'tech1,tech2', 'condition': 'is', 'logical_operator':'AND'}"
    expected_output = {'list_info': {'search_criteria': [{'field': 'created_time', 'values': ['from', 'to'],
                                                          'condition': 'between'},
                                                         {'field': 'technician.name', 'condition': 'is',
                                                          'values': ['tech1', 'tech2'], 'logical_operator': 'AND'}],
                                     'sort_field': 'created_time', 'sort_order': 'asc', 'row_count': 15}}
    assert create_fetch_list_info(time_from, time_to, status, fetch_filter, fetch_limit) == expected_output

    time_from, time_to, status, fetch_limit = 'from', 'to', 'status', 20
    fetch_filter = "{'field':'technician.name','values':'tech1,tech2','condition':'is','logical_operator':'AND'}," \
                   "{'field':'group.name','values':'group1','condition':'is','logical_operator':'AND'}"
    expected_output = {'list_info': {'search_criteria': [{'field': 'created_time', 'values': ['from', 'to'],
                                                          'condition': 'between'},
                                                         {'field': 'technician.name', 'condition': 'is',
                                                          'values': ['tech1', 'tech2'], 'logical_operator': 'AND'},
                                                         {'field': 'group.name', 'condition': 'is',
                                                          'values': ['group1'], 'logical_operator': 'AND'}],
                                     'sort_field': 'created_time', 'sort_order': 'asc', 'row_count': 20}}
    assert create_fetch_list_info(time_from, time_to, status, fetch_filter, fetch_limit) == expected_output


def test_create_udf_field():
    udf_input = 'key1;val1'
    expected_output = {'key1': 'val1'}
    assert create_udf_field(udf_input) == expected_output

    udf_input = 'key1;val1,key2;val2'
    expected_output = {'key1': 'val1', 'key2': 'val2'}
    assert create_udf_field(udf_input) == expected_output

    invalid_udf_inputs = ['key1;val1,key2', 'key1,val1', 'key1', ';val1']
    for udf_input in invalid_udf_inputs:
        try:
            create_udf_field(udf_input)
        except Exception as e:
            assert 'Illegal udf fields format' in e.args[0]


def test_fetch_incidents(mocker):
    """
    Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the parse_date_range.
    - mock the Client's get_requests command.
    Then
    - run the fetch incidents command using the Client.
    Validate the length of the results and the different fields of the fetched incidents.
    """
    mocker.patch('ServiceDeskPlus.Client.get_access_token')
    client = Client('server_url', 'use_ssl', 'use_proxy', 'client_id', 'client_secret', 'refresh_token')
    mocker.patch('ServiceDeskPlus.parse_date_range', return_value=('2020-06-23 04:18:00', 'never mind'))
    mocker.patch('ServiceDeskPlus.date_to_timestamp', return_value='1592918317168')
    mocker.patch('ServiceDeskPlus.create_fetch_list_info', return_value={})
    mocker.patch.object(client, 'get_requests', return_value=RESPONSE_FETCH_INCIDENTS)

    incidents = fetch_incidents(client, fetch_time='1 hour', fetch_limit=10, status='Open', fetch_filter='')
    assert len(incidents) == 3

    incidents = fetch_incidents(client, fetch_time='1 hour', fetch_limit=2, status='Open', fetch_filter='')
    assert len(incidents) == 2
    assert incidents[0].get('name') == 'Test fetch incidents - 1234'

    incidents = fetch_incidents(client, fetch_time='1 hour', fetch_limit=1, status='Open', fetch_filter='')
    assert len(incidents) == 1
    assert incidents[0].get('name') == 'Test fetch incidents - 1234'

    incidents = fetch_incidents(client, fetch_time='1 hour', fetch_limit=0, status='Open', fetch_filter='')
    assert len(incidents) == 0


def test_test_module(mocker):
    """
    Unit test
    Given
    - test module command
    - command raw response
    When
    - mock the parse_date_range.
    - mock the Client's send_request.
    Then
    - run the test module command using the Client
    Validate the content of the HumanReadable.
    """
    from ServiceDeskPlus import test_module as module
    mocker.patch('ServiceDeskPlus.Client.get_access_token')
    client = Client('server_url', 'use_ssl', 'use_proxy', 'client_id', 'client_secret', 'refresh_token')

    mocker.patch('ServiceDeskPlus.parse_date_range', return_value=('2020-06-23 04:18:00', 'never mind'))
    mocker.patch.object(client, 'http_request', return_value=RESPONSE_FETCH_INCIDENTS)
    result = module(client)
    assert result == 'ok'
