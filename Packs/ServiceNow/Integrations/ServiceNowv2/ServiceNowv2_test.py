import pytest
from ServiceNowv2 import get_server_url, get_ticket_context, get_ticket_human_readable, \
    generate_body, split_fields, Client, update_ticket_command, create_ticket_command, delete_ticket_command, \
    query_tickets_command, add_link_command, add_comment_command, upload_file_command, get_ticket_notes_command, \
    get_record_command, update_record_command, create_record_command, delete_record_command, query_table_command, \
    list_table_fields_command, query_computers_command, get_table_name_command, add_tag_command, query_items_command, \
    get_item_details_command, create_order_item_command, document_route_to_table, fetch_incidents, main, \
    get_mapping_fields_command, get_remote_data_command, update_remote_system_command, build_query_for_request_params, \
    ServiceNowClient, oauth_test_module, login_command
from ServiceNowv2 import test_module as module
from test_data.response_constants import RESPONSE_TICKET, RESPONSE_MULTIPLE_TICKET, RESPONSE_UPDATE_TICKET, \
    RESPONSE_UPDATE_TICKET_SC_REQ, RESPONSE_CREATE_TICKET, RESPONSE_QUERY_TICKETS, RESPONSE_ADD_LINK, \
    RESPONSE_ADD_COMMENT, RESPONSE_UPLOAD_FILE, RESPONSE_GET_TICKET_NOTES, RESPONSE_GET_RECORD, \
    RESPONSE_UPDATE_RECORD, RESPONSE_CREATE_RECORD, RESPONSE_QUERY_TABLE, RESPONSE_LIST_TABLE_FIELDS, \
    RESPONSE_QUERY_COMPUTERS, RESPONSE_GET_TABLE_NAME, RESPONSE_UPDATE_TICKET_ADDITIONAL, \
    RESPONSE_QUERY_TABLE_SYS_PARAMS, RESPONSE_ADD_TAG, RESPONSE_QUERY_ITEMS, RESPONSE_ITEM_DETAILS, \
    RESPONSE_CREATE_ITEM_ORDER, RESPONSE_DOCUMENT_ROUTE, RESPONSE_FETCH, RESPONSE_FETCH_ATTACHMENTS_FILE, \
    RESPONSE_FETCH_ATTACHMENTS_TICKET, RESPONSE_TICKET_MIRROR, MIRROR_COMMENTS_RESPONSE, \
    RESPONSE_MIRROR_FILE_ENTRY, RESPONSE_ASSIGNMENT_GROUP, RESPONSE_MIRROR_FILE_ENTRY_FROM_XSOAR, \
    MIRROR_COMMENTS_RESPONSE_FROM_XSOAR, MIRROR_ENTRIES, RESPONSE_CLOSING_TICKET_MIRROR, RESPONSE_TICKET_ASSIGNED, \
    OAUTH_PARAMS
from test_data.result_constants import EXPECTED_TICKET_CONTEXT, EXPECTED_MULTIPLE_TICKET_CONTEXT, \
    EXPECTED_TICKET_HR, EXPECTED_MULTIPLE_TICKET_HR, EXPECTED_UPDATE_TICKET, EXPECTED_UPDATE_TICKET_SC_REQ, \
    EXPECTED_CREATE_TICKET, EXPECTED_QUERY_TICKETS, EXPECTED_ADD_LINK_HR, EXPECTED_ADD_COMMENT_HR, \
    EXPECTED_UPLOAD_FILE, EXPECTED_GET_TICKET_NOTES, EXPECTED_GET_RECORD, EXPECTED_UPDATE_RECORD, \
    EXPECTED_CREATE_RECORD, EXPECTED_QUERY_TABLE, EXPECTED_LIST_TABLE_FIELDS, EXPECTED_QUERY_COMPUTERS, \
    EXPECTED_GET_TABLE_NAME, EXPECTED_UPDATE_TICKET_ADDITIONAL, EXPECTED_QUERY_TABLE_SYS_PARAMS, EXPECTED_ADD_TAG, \
    EXPECTED_QUERY_ITEMS, EXPECTED_ITEM_DETAILS, EXPECTED_CREATE_ITEM_ORDER, EXPECTED_DOCUMENT_ROUTE, EXPECTED_MAPPING

import demistomock as demisto


def test_get_server_url():
    assert "http://www.demisto.com/" == get_server_url("http://www.demisto.com//")


def test_get_ticket_context():
    assert EXPECTED_TICKET_CONTEXT == get_ticket_context(RESPONSE_TICKET)

    assert EXPECTED_MULTIPLE_TICKET_CONTEXT[0] in get_ticket_context(RESPONSE_MULTIPLE_TICKET)
    assert EXPECTED_MULTIPLE_TICKET_CONTEXT[1] in get_ticket_context(RESPONSE_MULTIPLE_TICKET)


def test_get_ticket_human_readable():
    assert EXPECTED_TICKET_HR == get_ticket_human_readable(RESPONSE_TICKET, 'incident')

    assert EXPECTED_MULTIPLE_TICKET_HR[0] in get_ticket_human_readable(RESPONSE_MULTIPLE_TICKET, 'incident')
    assert EXPECTED_MULTIPLE_TICKET_HR[1] in get_ticket_human_readable(RESPONSE_MULTIPLE_TICKET, 'incident')


def test_generate_body():
    fields = {'a_field': 'test'}
    custom_fields = {'a_custom_field': 'test'}
    expected_body = {'a_field': 'test', 'u_a_custom_field': 'test'}
    assert expected_body == generate_body(fields, custom_fields)


def test_split_fields():
    expected_dict_fields = {'a': 'b', 'c': 'd'}
    assert expected_dict_fields == split_fields('a=b;c=d')

    expected_custom_field = {'u_customfield': "<a href=\'https://google.com\'>Link text</a>"}
    assert expected_custom_field == split_fields("u_customfield=<a href=\'https://google.com\'>Link text</a>")

    expected_custom_sys_params = {
        "sysparm_display_value": 'all',
        "sysparm_exclude_reference_link": 'True',
        "sysparm_query": 'number=TASK0000001'
    }

    assert expected_custom_sys_params == split_fields(
        "sysparm_display_value=all;sysparm_exclude_reference_link=True;sysparm_query=number=TASK0000001")

    try:
        split_fields('a')
    except Exception as err:
        assert "must contain a '=' to specify the keys and values" in str(err)
        return
    assert False


@pytest.mark.parametrize('command, args, response, expected_result, expected_auto_extract', [
    (update_ticket_command, {'id': '1234', 'impact': '2'}, RESPONSE_UPDATE_TICKET, EXPECTED_UPDATE_TICKET, True),
    (update_ticket_command, {'id': '1234', 'ticket_type': 'sc_req_item', 'approval': 'requested'},
     RESPONSE_UPDATE_TICKET_SC_REQ, EXPECTED_UPDATE_TICKET_SC_REQ, True),
    (update_ticket_command, {'id': '1234', 'severity': '3', 'additional_fields': "approval=rejected"},
     RESPONSE_UPDATE_TICKET_ADDITIONAL, EXPECTED_UPDATE_TICKET_ADDITIONAL, True),
    (create_ticket_command, {'active': 'true', 'severity': "3", 'description': "creating a test ticket",
                             'sla_due': "2020-10-10 10:10:11"}, RESPONSE_CREATE_TICKET, EXPECTED_CREATE_TICKET, True),
    (query_tickets_command, {'limit': "3", 'query': "impact<2^short_descriptionISNOTEMPTY", 'ticket_type': "incident"},
     RESPONSE_QUERY_TICKETS, EXPECTED_QUERY_TICKETS, True),
    (upload_file_command, {'id': "sys_id", 'file_id': "entry_id", 'file_name': 'test_file'}, RESPONSE_UPLOAD_FILE,
     EXPECTED_UPLOAD_FILE, True),
    (get_ticket_notes_command, {'id': "sys_id"}, RESPONSE_GET_TICKET_NOTES, EXPECTED_GET_TICKET_NOTES, True),
    (get_record_command, {'table_name': "alm_asset", 'id': "sys_id", 'fields': "asset_tag,display_name"},
     RESPONSE_GET_RECORD, EXPECTED_GET_RECORD, True),
    (update_record_command, {'name': "alm_asset", 'id': "1234", 'custom_fields': "display_name=test4"},
     RESPONSE_UPDATE_RECORD, EXPECTED_UPDATE_RECORD, True),
    (create_record_command, {'table_name': "alm_asset", 'fields': "asset_tag=P4325434;display_name=my_test_record"},
     RESPONSE_CREATE_RECORD, EXPECTED_CREATE_RECORD, True),
    (query_table_command, {'table_name': "alm_asset", 'fields': "asset_tag,sys_updated_by,display_name",
                           'query': "display_nameCONTAINSMacBook", 'limit': 3}, RESPONSE_QUERY_TABLE,
     EXPECTED_QUERY_TABLE, False),
    (query_table_command, {
        'table_name': "sc_task", 'system_params':
            'sysparm_display_value=all;sysparm_exclude_reference_link=True;sysparm_query=number=TASK0000001',
        'fields': "approval,state,escalation,number,description"
    }, RESPONSE_QUERY_TABLE_SYS_PARAMS, EXPECTED_QUERY_TABLE_SYS_PARAMS, False),
    (list_table_fields_command, {'table_name': "alm_asset"}, RESPONSE_LIST_TABLE_FIELDS, EXPECTED_LIST_TABLE_FIELDS,
     False),
    (query_computers_command, {'computer_id': '1234'}, RESPONSE_QUERY_COMPUTERS, EXPECTED_QUERY_COMPUTERS, False),
    (get_table_name_command, {'label': "ACE"}, RESPONSE_GET_TABLE_NAME, EXPECTED_GET_TABLE_NAME, False),
    (add_tag_command, {'id': "123", 'tag_id': '1234', 'title': 'title'}, RESPONSE_ADD_TAG, EXPECTED_ADD_TAG, True),
    (query_items_command, {'name': "ipad", 'limit': '2'}, RESPONSE_QUERY_ITEMS, EXPECTED_QUERY_ITEMS, True),
    (get_item_details_command, {'id': "1234"}, RESPONSE_ITEM_DETAILS, EXPECTED_ITEM_DETAILS, True),
    (create_order_item_command, {'id': "1234", 'quantity': "3",
                                 'variables': "Additional_software_requirements=best_pc"},
     RESPONSE_CREATE_ITEM_ORDER, EXPECTED_CREATE_ITEM_ORDER, True),
    (document_route_to_table, {'queue_id': 'queue_id', 'document_id': 'document_id'}, RESPONSE_DOCUMENT_ROUTE,
     EXPECTED_DOCUMENT_ROUTE, True),
])  # noqa: E124
def test_commands(command, args, response, expected_result, expected_auto_extract, mocker):
    """Unit test
    Given
    - command main func
    - command args
    - command raw response
    When
    - mock the ServiceNow response
    Then
    - convert the result to human readable table
    - create the context
    validate the entry context
    """
    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments',
                    'incident_name')
    mocker.patch.object(client, 'send_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
    assert expected_auto_extract == result[3]  # ignore_auto_extract is in the 4th place in the result of the command


@pytest.mark.parametrize('command, args, response, expected_hr, expected_auto_extract', [
    (delete_ticket_command, {'id': '1234'}, {}, 'Ticket with ID 1234 was successfully deleted.', True),
    (add_link_command, {'id': '1234', 'link': "http://www.demisto.com", 'text': 'demsito_link'}, RESPONSE_ADD_LINK,
     EXPECTED_ADD_LINK_HR, True),
    (add_comment_command, {'id': "1234", 'comment': "Nice work!"}, RESPONSE_ADD_COMMENT, EXPECTED_ADD_COMMENT_HR, True),
    (delete_record_command, {'table_name': "alm_asset", 'id': '1234'}, {},
     'ServiceNow record with ID 1234 was successfully deleted.', True),
])  # noqa: E124
def test_no_ec_commands(command, args, response, expected_hr, expected_auto_extract, mocker):
    """Unit test
    Given
    - command main func
    - command args
    - command raw response
    When
    - mock the ServiceNow response
    Then
    - convert the result to human readable table
    - create the context
    validate the human readable
    """
    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments',
                    'incident_name')
    mocker.patch.object(client, 'send_request', return_value=response)
    result = command(client, args)
    assert expected_hr in result[0]  # HR is found in the 1st place in the result of the command
    assert expected_auto_extract == result[3]  # ignore_auto_extract is in the 4th place in the result of the command


def test_fetch_incidents(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the parse_date_range.
    - mock the Client's send_request.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results.
    """
    mocker.patch('ServiceNowv2.parse_date_range', return_value=("2019-02-23 08:14:21", 'never mind'))
    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='number')
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH)
    incidents = fetch_incidents(client)
    assert len(incidents) == 2
    assert incidents[0].get('name') == 'ServiceNow Incident INC0000040'


def test_fetch_incidents_with_attachments(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the parse_date_range.
    - mock the Client's send_request.
    - mock the Client's get_ticket_attachment_entries.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results and the attachment content.
    """
    mocker.patch('ServiceNowv2.parse_date_range', return_value=("2016-10-10 15:19:57", 'never mind'))
    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=True, incident_name='number')
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH_ATTACHMENTS_TICKET)
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=RESPONSE_FETCH_ATTACHMENTS_FILE)

    incidents = fetch_incidents(client)

    assert len(incidents) == 1
    assert incidents[0].get('attachment')[0]['name'] == 'wireframe'
    assert incidents[0].get('attachment')[0]['path'] == 'file_id'


def test_fetch_incidents_with_incident_name(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the parse_date_range.
    - mock the Client's send_request.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results.
    """
    mocker.patch('ServiceNowv2.parse_date_range', return_value=("2019-02-23 08:14:21", 'never mind'))
    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH)
    incidents = fetch_incidents(client)
    assert incidents[0].get('name') == 'ServiceNow Incident Unable to access Oregon mail server. Is it down?'


def test_incident_name_is_initialized(mocker, requests_mock):
    """
    Given:
     - Integration instance initialized with fetch enabled and without changing incident name

    When:
     - Clicking on Test button (running test-module)

    Then:
     - Verify expected exception is raised as default incident name value is not in response
    """
    url = 'https://test.service-now.com'
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'isFetch': True,
            'url': url,
            'credentials': {
                'identifier': 'identifier',
                'password': 'password',
            },
            'incident_name': None
        }
    )
    mocker.patch.object(demisto, 'command', return_value='test-module')

    def return_error_mock(message, error):
        raise

    mocker.patch('ServiceNowv2.return_error', side_effect=return_error_mock)
    requests_mock.get(
        f'{url}/api/now/table/incident?sysparm_limit=1',
        json={
            'result': [{
                'opened_at': 'sometime'
            }]
        }
    )
    with pytest.raises(ValueError) as e:
        main()
    assert str(e.value) == 'The field [number] does not exist in the ticket.'


def test_not_authenticated_retry_positive(requests_mock, mocker):
    """
    Given
    - ServiceNow client

    When
    - Sending HTTP request and getting 401 status code (not authenticated) twice, followed by 200 status code (success)

    Then
    - Verify debug messages
    - Ensure the send_request function runs successfully without exceptions
    """
    mocker.patch.object(demisto, 'debug')
    client = Client('http://server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments',
                    'incident_name')
    requests_mock.get('http://server_url', [
        {
            'status_code': 401,
            'json': {
                'error': {'message': 'User Not Authenticated', 'detail': 'Required to provide Auth information'},
                'status': 'failure'
            }
        },
        {
            'status_code': 401,
            'json': {
                'error': {'message': 'User Not Authenticated', 'detail': 'Required to provide Auth information'},
                'status': 'failure'
            }
        },
        {
            'status_code': 200,
            'json': {}
        }
    ])
    assert client.send_request('') == {}
    assert demisto.debug.call_count == 2
    debug = demisto.debug.call_args_list
    expected_debug_msg = "Got status code 401 - {'error': {'message': 'User Not Authenticated', " \
                         "'detail': 'Required to provide Auth information'}, 'status': 'failure'}. Retrying ..."
    assert debug[0][0][0] == expected_debug_msg
    assert debug[1][0][0] == expected_debug_msg


def test_not_authenticated_retry_negative(requests_mock, mocker):
    """
    Given
    - ServiceNow client

    When
    - Sending HTTP request and getting 401 status code (not authenticated) 3 times

    Then
    - Verify debug messages
    - Ensure the send_request function fails and raises expected error message
    """
    mocker.patch.object(demisto, 'debug')
    client = Client('http://server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments',
                    'incident_name')
    requests_mock.get('http://server_url', [
        {
            'status_code': 401,
            'json': {
                'error': {'message': 'User Not Authenticated', 'detail': 'Required to provide Auth information'},
                'status': 'failure'
            }
        },
        {
            'status_code': 401,
            'json': {
                'error': {'message': 'User Not Authenticated', 'detail': 'Required to provide Auth information'},
                'status': 'failure'
            }
        },
        {
            'status_code': 401,
            'json': {
                'error': {'message': 'User Not Authenticated', 'detail': 'Required to provide Auth information'},
                'status': 'failure'
            }
        }
    ])
    with pytest.raises(Exception) as ex:
        client.send_request('')
    assert str(ex.value) == "Got status code 401 with url http://server_url with body b'{\"error\": {\"message\": " \
                            "\"User Not Authenticated\", \"detail\": \"Required to provide Auth information\"}, " \
                            "\"status\": \"failure\"}' with headers {}"
    assert demisto.debug.call_count == 3
    debug = demisto.debug.call_args_list
    expected_debug_msg = "Got status code 401 - {'error': {'message': 'User Not Authenticated', " \
                         "'detail': 'Required to provide Auth information'}, 'status': 'failure'}. Retrying ..."
    assert debug[0][0][0] == expected_debug_msg
    assert debug[1][0][0] == expected_debug_msg
    assert debug[2][0][0] == expected_debug_msg


def test_oauth_authentication(mocker, requests_mock):
    """
    Given:
     - Integration instance, initialized with the `Use OAuth Login` checkbox selected.

    When:
     - Clicking on running the !servicenow-oauth-test command.

    Then:
     - Verify that oauth authorization flow is used by checking that the get_access_token is called.
    """
    from unittest.mock import MagicMock
    url = 'https://test.service-now.com'
    mocker.patch.object(demisto, 'command', return_value='servicenow-oauth-test')
    mocker.patch.object(ServiceNowClient, 'get_access_token')
    requests_mock.get(
        f'{url}/api/now/table/incident?sysparm_limit=1',
        json={
            'result': [{
                'opened_at': 'sometime'
            }]
        }
    )

    # Assert that get_access_token is called when `Use OAuth Login` checkbox is selected:
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'url': url,
            'credentials': {
                'identifier': 'client_id',
                'password': 'client_secret'
            },
            'use_oauth': True
        }
    )
    ServiceNowClient.get_access_token = MagicMock()
    main()
    assert ServiceNowClient.get_access_token.called


def test_test_module(mocker):
    """Unit test
    Given
    - test module command
    - command args
    - command raw response
    When
    (a)
        - mock the parse_date_range.
        - mock the Client's send_request.
    (b) - calling the test module when using OAuth 2.0 authorization.
    Then
    (a)
        - run the test module command using the Client
        Validate the content of the HumanReadable.
    (b)
        Validate that an error is returned, indicating that the `Test` button can't be used when using OAuth 2.0.
    """
    mocker.patch('ServiceNowv2.parse_date_range', return_value=("2019-02-23 08:14:21", 'never mind'))
    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH)
    result = module(client)
    assert result[0] == 'ok'

    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at', ticket_type='incident',
                    get_attachments=False, incident_name='description', oauth_params=OAUTH_PARAMS)

    try:
        module(client)
    except Exception as e:
        assert 'Test button cannot be used when using OAuth 2.0' in e.args[0]


def test_oauth_test_module(mocker):
    """
    Given:
    - oauth_test_module command
    When:
    - (a) trying to call the command when using basic auth.
    - (b)
        - trying to call the command when using OAuth 2.0
        - mock the parse_date_range.
        - mock the Client's send_request.
    Then:
    - (a) validate that an error is returned, indicating that the function should be called when using OAuth only.
    - (b) Validate that the instance was configured successfully.
    """
    mocker.patch('ServiceNowv2.parse_date_range', return_value=("2019-02-23 08:14:21", 'never mind'))
    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at', ticket_type='incident',
                    get_attachments=False, incident_name='description')
    try:
        oauth_test_module(client)
    except Exception as e:
        assert 'command should be used only when using OAuth 2.0 authorization.' in e.args[0]

    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at', ticket_type='incident',
                    get_attachments=False, incident_name='description', oauth_params=OAUTH_PARAMS)
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH)
    result = oauth_test_module(client)
    assert '### Instance Configured Successfully.' in result[0]


def test_oauth_login_command(mocker):
    """
    Given:
    - login command
    When:
    - (a) trying to call the command when using basic auth.
    - (b)
        - trying to call the command when using OAuth 2.0.
        - mocking the login command of ServiceNowClient.
    Then:
    - (a) validate that an error is returned, indicating that the function should be called when using OAuth only.
    - (b) Validate that the login was successful.
    """
    mocker.patch('ServiceNowv2.ServiceNowClient.login')
    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at', ticket_type='incident',
                    get_attachments=False, incident_name='description')
    try:
        login_command(client, args={'username': 'username', 'password': 'password'})
    except Exception as e:
        assert '!servicenow-oauth-login command can be used only when using OAuth 2.0 authorization' in e.args[0]

    client = Client('server_url', 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at', ticket_type='incident',
                    get_attachments=False, incident_name='description', oauth_params=OAUTH_PARAMS)
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH)
    result = login_command(client, args={'username': 'username', 'password': 'password'})
    assert '### Logged in successfully.' in result[0]


def test_sysparm_input_display_value(mocker, requests_mock):
    """Unit test
    Given
    - create_record_command function
    - command args, including input_display_value
    - command raw response
    When
    - mock the requests url destination.
    Then
    - run the create command using the Client
    Validate that the sysparm_input_display_value parameter has the correct value
    """

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')

    mocker.patch.object(demisto, 'args', return_value={'input_display_value': 'true',
                                                       'table_name': "alm_asset",
                                                       'fields': "asset_tag=P4325434;display_name=my_test_record"
                                                       }
                        )
    requests_mock.post('https://server_url.com/table/alm_asset?sysparm_input_display_value=True', json={})
    # will raise a requests_mock.exceptions.NoMockAddress if the url address will not be as given in the requests_mock
    create_record_command(client, demisto.args())
    assert requests_mock.request_history[0].method == 'POST'

    mocker.patch.object(demisto, 'args', return_value={'input_display_value': 'false',
                                                       'table_name': "alm_asset",
                                                       'fields': "asset_tag=P4325434;display_name=my_test_record"
                                                       }
                        )
    requests_mock.post('https://server_url.com/table/alm_asset?sysparm_input_display_value=False', json={})
    # will raise a requests_mock.exceptions.NoMockAddress if the url address will not be as given in the requests_mock
    create_record_command(client, demisto.args())
    assert requests_mock.request_history[1].method == 'POST'


def test_get_mapping_fields():
    """
    Given:
        -  ServiceNow client
        -  ServiceNow mapping fields
    When
        - running get_mapping_fields_command
    Then
        - the result fits the expected mapping.
    """
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')
    res = get_mapping_fields_command(client)
    assert EXPECTED_MAPPING == res.extract_mapping()


def test_get_remote_data(mocker):
    """
    Given:
        -  ServiceNow client
        -  arguments: id and LastUpdate(set to lower then the modification time).
        -  ServiceNow ticket
    When
        - running get_remote_data_command.
    Then
        - The ticket was updated with the entries.
    """

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')

    args = {'id': 'sys_id', 'lastUpdate': 0}
    params = {}
    mocker.patch.object(client, 'get', return_value=RESPONSE_TICKET_MIRROR)
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=RESPONSE_MIRROR_FILE_ENTRY)
    mocker.patch.object(client, 'query', return_value=MIRROR_COMMENTS_RESPONSE)
    mocker.patch.object(client, 'get', return_value=RESPONSE_ASSIGNMENT_GROUP)

    res = get_remote_data_command(client, args, params)

    assert res[1]['File'] == 'test.txt'
    assert res[2]['Contents'] == 'This is a comment'


CLOSING_RESPONSE = {'dbotIncidentClose': True, 'closeReason': 'From ServiceNow: Test'}


def test_get_remote_data_closing_incident(mocker):
    """
    Given:
        -  ServiceNow client
        -  arguments: id and LastUpdate(set to lower then the modification time).
        -  ServiceNow ticket
    When
        - running get_remote_data_command.
    Then
        - The closed_at field exists in the ticket data.
        - dbotIncidentClose exists.
        - Closed notes exists.
    """

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='sc_task', get_attachments=False, incident_name='description')

    args = {'id': 'sys_id', 'lastUpdate': 0}
    params = {'close_incident': True}
    mocker.patch.object(client, 'get', return_value=RESPONSE_CLOSING_TICKET_MIRROR)
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=[])
    mocker.patch.object(client, 'query', return_value=MIRROR_COMMENTS_RESPONSE)

    res = get_remote_data_command(client, args, params)
    assert 'closed_at' in res[0]
    assert CLOSING_RESPONSE == res[2]['Contents']


def test_get_remote_data_no_attachment(mocker):
    """
    Given:
        -  ServiceNow client
        -  arguments: id and LastUpdate(set to lower then the modification time).
        -  ServiceNow ticket
    When
        - running get_remote_data_command.
    Then
        - The ticket was updated with no attachment.
    """

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')

    args = {'id': 'sys_id', 'lastUpdate': 0}
    params = {}
    mocker.patch.object(client, 'get', return_value=RESPONSE_TICKET_MIRROR)
    mocker.patch.object(client, 'get_ticket_attachments', return_value=[])
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=[])
    mocker.patch.object(client, 'query', return_value=MIRROR_COMMENTS_RESPONSE)
    mocker.patch.object(client, 'get', return_value=RESPONSE_ASSIGNMENT_GROUP)

    res = get_remote_data_command(client, args, params)
    assert res[1]['Contents'] == 'This is a comment'
    assert len(res) == 2


def test_get_remote_data_no_entries(mocker):
    """
    Given:
        -  ServiceNow client
        -  arguments: id and LastUpdate(set to lower then the modification time).
        -  ServiceNow ticket
        -  File and comment entries sent from XSOAR.
    When
        - running get_remote_data_command.
    Then
        - The checked entries was not returned.
    """

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')

    args = {'id': 'sys_id', 'lastUpdate': 0}
    params = {}
    mocker.patch.object(client, 'get', return_value=[RESPONSE_TICKET_MIRROR, RESPONSE_ASSIGNMENT_GROUP])
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=RESPONSE_MIRROR_FILE_ENTRY_FROM_XSOAR)
    mocker.patch.object(client, 'query', return_value=MIRROR_COMMENTS_RESPONSE_FROM_XSOAR)

    res = get_remote_data_command(client, args, params)

    assert 'This is a comment\n\n Mirrored from Cortex XSOAR' not in res
    assert 'test_mirrored_from_xsoar.txt' not in res


def upload_file_request(*args):
    assert 'test_mirrored_from_xsoar.txt' == args[2]
    return {'id': "sys_id", 'file_id': "entry_id", 'file_name': 'test.txt'}


def add_comment_request(*args):
    assert '(dbot): This is a comment\n\n Mirrored from Cortex XSOAR' == args[3]
    return {'id': "1234", 'comment': "This is a comment"}


def test_upload_entries_update_remote_system_command(mocker):
    """
    Given:
        -  ServiceNow client
        -  File and comment entries sent from XSOAR.
    When
        - running update_remote_system_command.
    Then
        - The checked entries was sent as expected with suffix.
    """
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')
    params = {}
    args = {'remoteId': '1234', 'data': {}, 'entries': MIRROR_ENTRIES, 'incidentChanged': False, 'delta': {}}
    mocker.patch.object(client, 'upload_file', side_effect=upload_file_request)
    mocker.patch.object(client, 'add_comment', side_effect=add_comment_request)

    update_remote_system_command(client, args, params)


TICKET_FIELDS = {'close_notes': 'This is closed', 'closed_at': '2020-10-29T13:19:07.345995+02:00', 'impact': '3',
                 'priority': '4', 'resolved_at': '2020-10-29T13:19:07.345995+02:00', 'severity': '1 - Low',
                 'short_description': 'Post parcel', 'sla_due': '0001-01-01T00:00:00Z', 'urgency': '3', 'state': '1',
                 'work_start': '0001-01-01T00:00:00Z'}


def ticket_fields(*args, **kwargs):
    assert {'close_notes': 'This is closed', 'closed_at': '2020-10-29T13:19:07.345995+02:00', 'impact': '3',
            'priority': '4', 'resolved_at': '2020-10-29T13:19:07.345995+02:00', 'severity': '1 - Low',
            'short_description': 'Post parcel', 'sla_due': '0001-01-01T00:00:00Z', 'urgency': '3', 'state': '3',
            'work_start': '0001-01-01T00:00:00Z'} == args[0]

    return {'close_notes': 'This is closed', 'closed_at': '2020-10-29T13:19:07.345995+02:00', 'impact': '3',
            'priority': '4', 'resolved_at': '2020-10-29T13:19:07.345995+02:00', 'severity': '1 - Low',
            'short_description': 'Post parcel', 'sla_due': '0001-01-01T00:00:00Z', 'urgency': '3', 'state': '1',
            'work_start': '0001-01-01T00:00:00Z'}


def update_ticket(*args):
    return {'short_description': 'Post parcel', 'close_notes': 'This is closed',
            'closed_at': '2020-10-29T13:19:07.345995+02:00', 'impact': '3', 'priority': '4',
            'resolved_at': '2020-10-29T13:19:07.345995+02:00', 'severity': '1 - High - Low',
            'sla_due': '0001-01-01T00:00:00Z', 'state': '3', 'urgency': '3', 'work_start': '0001-01-01T00:00:00Z'}


def test_update_remote_data_sc_task(mocker):
    """
    Given:
    -  ServiceNow client
    -  ServiceNow ticket of type sc_task
    When
        - running update_remote_system_command.
    Then
        - The state is changed to 3 (closed) after update.
    """
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='sc_task', get_attachments=False, incident_name='description')
    params = {'ticket_type': 'sc_task', 'close_ticket': True}
    args = {'remoteId': '1234', 'data': TICKET_FIELDS, 'entries': [], 'incidentChanged': True, 'delta': {},
            'status': 2}
    mocker.patch('ServiceNowv2.get_ticket_fields', side_effect=ticket_fields)
    mocker.patch.object(client, 'update', side_effect=update_ticket)
    update_remote_system_command(client, args, params)


@pytest.mark.parametrize('query, expected', [
    ("id=5&status=pi", ["id=5", "status=pi"]),
    ("id=5&status=pi&name=bobby", ["id=5", "status=pi", "name=bobby"]),
    ("&status=pi", ["status=pi"]),
    ("status=pi&", ["status=pi"]),
])
def test_build_query_for_request_params(query, expected):
    """
    Given:
     - Query with multiple arguments

    When:
     - Running Cilent.query function

    Then:
     - Verify the query was split to a list of sub queries according to the &.
    """
    sub_queries = build_query_for_request_params(query)
    assert sub_queries == expected


@pytest.mark.parametrize('command, args', [
    (query_tickets_command, {'limit': "50", 'query': "assigned_to=123&active=true", 'ticket_type': "sc_task"}),
    (query_table_command, {'limit': "50", 'query': "assigned_to=123&active=true", 'table_name': "sc_task"})
])
def test_multiple_query_params(requests_mock, command, args):
    """
    Given:
     - Query with multiple arguments

    When:
     - Using servicenow-query-tickets command with multiple sysparm_query arguments.
     - Using servicenow-query-table command with multiple sysparm_query arguments.

    Then:
     - Verify the right request is called with '&' distinguishing different arguments.
    """
    url = 'https://test.service-now.com/api/now/v2/'
    client = Client(url, 'sc_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments',
                    'incident_name')
    requests_mock.request('GET', f'{url}table/sc_task?sysparm_limit=50&sysparm_offset=0&'
                                 'sysparm_query=assigned_to%3D123&sysparm_query=active%3Dtrue',
                          json=RESPONSE_TICKET_ASSIGNED)
    human_readable, entry_context, result, bol = command(client, args)

    assert result == RESPONSE_TICKET_ASSIGNED
