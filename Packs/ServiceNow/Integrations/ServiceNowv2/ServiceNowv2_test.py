import re
from unittest.mock import MagicMock

from pytest_mock import MockerFixture
from requests_mock import MockerCore
import pytest
import json
from datetime import datetime, timedelta
from freezegun import freeze_time
import ServiceNowv2
import requests
from CommonServerPython import CommandResults, DemistoException, EntryType
from ServiceNowv2 import get_server_url, get_ticket_context, get_ticket_human_readable, MAX_RETRY, \
    generate_body, parse_dict_ticket_fields, split_fields, Client, update_ticket_command, create_ticket_command, \
    query_tickets_command, add_link_command, add_comment_command, upload_file_command, get_ticket_notes_command, \
    get_record_command, update_record_command, create_record_command, delete_record_command, query_table_command, \
    list_table_fields_command, query_computers_command, get_table_name_command, add_tag_command, query_items_command, \
    get_item_details_command, create_order_item_command, document_route_to_table, fetch_incidents, main, \
    get_mapping_fields_command, get_remote_data_command, update_remote_system_command, delete_ticket_command, \
    ServiceNowClient, oauth_test_module, login_command, get_modified_remote_data_command, \
    get_ticket_fields, check_assigned_to_field, generic_api_call_command, get_closure_case, get_timezone_offset, \
    converts_close_code_or_state_to_close_reason, split_notes, DATE_FORMAT, convert_to_notes_result, DATE_FORMAT_OPTIONS, \
    format_incidents_response_with_display_values, get_entries_for_notes, is_time_field, delete_attachment_command, \
    get_attachment_command, is_new_incident
from ServiceNowv2 import test_module as module
from test_data.response_constants import RESPONSE_TICKET, RESPONSE_MULTIPLE_TICKET, RESPONSE_UPDATE_TICKET, \
    RESPONSE_UPDATE_TICKET_SC_REQ, RESPONSE_CREATE_TICKET, RESPONSE_CREATE_TICKET_WITH_OUT_JSON, RESPONSE_QUERY_TICKETS, \
    RESPONSE_ADD_LINK, RESPONSE_ADD_COMMENT, RESPONSE_UPLOAD_FILE, RESPONSE_GET_TICKET_NOTES, RESPONSE_GET_RECORD, \
    RESPONSE_UPDATE_RECORD, RESPONSE_CREATE_RECORD, RESPONSE_QUERY_TABLE, RESPONSE_LIST_TABLE_FIELDS, \
    RESPONSE_QUERY_COMPUTERS, RESPONSE_GET_TABLE_NAME, RESPONSE_UPDATE_TICKET_ADDITIONAL, \
    RESPONSE_QUERY_TABLE_SYS_PARAMS, RESPONSE_ADD_TAG, RESPONSE_QUERY_ITEMS, RESPONSE_ITEM_DETAILS, \
    RESPONSE_CREATE_ITEM_ORDER, RESPONSE_DOCUMENT_ROUTE, RESPONSE_FETCH, RESPONSE_FETCH_ATTACHMENTS_FILE, \
    RESPONSE_FETCH_ATTACHMENTS_TICKET, RESPONSE_TICKET_MIRROR, MIRROR_COMMENTS_RESPONSE, RESPONSE_MIRROR_FILE_ENTRY, \
    RESPONSE_ASSIGNMENT_GROUP, RESPONSE_MIRROR_FILE_ENTRY_FROM_XSOAR, MIRROR_COMMENTS_RESPONSE_FROM_XSOAR, \
    MIRROR_ENTRIES, RESPONSE_CLOSING_TICKET_MIRROR_CLOSED, RESPONSE_CLOSING_TICKET_MIRROR_RESOLVED, \
    RESPONSE_CLOSING_TICKET_MIRROR_CUSTOM, RESPONSE_TICKET_ASSIGNED, OAUTH_PARAMS, \
    RESPONSE_QUERY_TICKETS_EXCLUDE_REFERENCE_LINK, MIRROR_ENTRIES_WITH_EMPTY_USERNAME, USER_RESPONSE, \
    RESPONSE_GENERIC_TICKET, RESPONSE_COMMENTS_DISPLAY_VALUE_AFTER_FORMAT, RESPONSE_COMMENTS_DISPLAY_VALUE_NO_COMMENTS, \
    RESPONSE_COMMENTS_DISPLAY_VALUE, RESPONSE_FETCH_USE_DISPLAY_VALUE
from test_data.result_constants import EXPECTED_TICKET_CONTEXT, EXPECTED_MULTIPLE_TICKET_CONTEXT, \
    EXPECTED_TICKET_HR, EXPECTED_MULTIPLE_TICKET_HR, EXPECTED_UPDATE_TICKET, EXPECTED_UPDATE_TICKET_SC_REQ, \
    EXPECTED_CREATE_TICKET, EXPECTED_CREATE_TICKET_WITH_OUT_JSON, EXPECTED_QUERY_TICKETS, EXPECTED_ADD_LINK_HR, \
    EXPECTED_ADD_COMMENT_HR, EXPECTED_UPLOAD_FILE, EXPECTED_GET_TICKET_NOTES, EXPECTED_GET_RECORD, \
    EXPECTED_UPDATE_RECORD, EXPECTED_CREATE_RECORD, EXPECTED_QUERY_TABLE, EXPECTED_LIST_TABLE_FIELDS, \
    EXPECTED_QUERY_COMPUTERS, EXPECTED_GET_TABLE_NAME, EXPECTED_UPDATE_TICKET_ADDITIONAL, \
    EXPECTED_QUERY_TABLE_SYS_PARAMS, EXPECTED_ADD_TAG, EXPECTED_QUERY_ITEMS, EXPECTED_ITEM_DETAILS, \
    EXPECTED_CREATE_ITEM_ORDER, EXPECTED_DOCUMENT_ROUTE, EXPECTED_MAPPING, \
    EXPECTED_TICKET_CONTEXT_WITH_ADDITIONAL_FIELDS, EXPECTED_QUERY_TICKETS_EXCLUDE_REFERENCE_LINK, \
    EXPECTED_TICKET_CONTEXT_WITH_NESTED_ADDITIONAL_FIELDS, EXPECTED_GET_TICKET_NOTES_DISPLAY_VALUE
from test_data.created_ticket_context import CREATED_TICKET_CONTEXT_CREATE_CO_FROM_TEMPLATE_COMMAND, \
    CREATED_TICKET_CONTEXT_GET_TASKS_FOR_CO_COMMAND

import demistomock as demisto
from urllib.parse import urlencode


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_force_default_url_arg(mocker: MockerFixture, requests_mock: MockerCore):
    """Unit test
    Given
        - The argument force_default_url=true
    When
        - Calling the command servicenow-create-co-from-template
    Then
        - Validate that the api version configured as a parameter was not used in the API request
    """
    url = 'https://test.service-now.com'
    api_endpoint = '/api/sn_chg_rest/change/standard/dummy_template'
    api_version = '2'
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
            'api_version': api_version,  # << We test overriding this value
            'incident_name': None,
            'file_tag_from_service_now': 'FromServiceNow',
            'file_tag_to_service_now': 'ToServiceNow',
            'comment_tag': 'comments',
            'comment_tag_from_servicenow': 'CommentFromServiceNow',
            'work_notes_tag': 'work_notes',
            'work_notes_tag_from_servicenow': 'WorkNoteFromServiceNow'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'template': 'dummy_template',
            'force_default_url': 'true'
        }
    )
    mocker.patch.object(demisto, 'command', return_value='servicenow-create-co-from-template')
    requests_mock.post(f'{url}{api_endpoint}', json=util_load_json('test_data/create_co_from_template_result.json'))
    main()
    assert requests_mock.request_history[0].path == api_endpoint


def test_get_server_url():
    assert get_server_url("http://www.demisto.com//") == "http://www.demisto.com/"


def test_get_ticket_context():
    assert get_ticket_context(RESPONSE_TICKET) == EXPECTED_TICKET_CONTEXT

    assert EXPECTED_MULTIPLE_TICKET_CONTEXT[0] in get_ticket_context(RESPONSE_MULTIPLE_TICKET)
    assert EXPECTED_MULTIPLE_TICKET_CONTEXT[1] in get_ticket_context(RESPONSE_MULTIPLE_TICKET)


def test_get_ticket_context_additional_fields():
    """Unit test
    Given
        - additional keys of a ticket alongside regular keys.
    When
        - getting a ticket context
    Then
        - validate that all the details of the ticket were updated, and all the updated keys are shown in
        the context with do duplicates.
    """
    assert get_ticket_context(RESPONSE_TICKET,
                              ['Summary', 'sys_created_by']) == \
        EXPECTED_TICKET_CONTEXT_WITH_ADDITIONAL_FIELDS


def test_get_ticket_context_nested_additional_fields():
    """Unit test
    Given
        - nested additional keys of a ticket (in the form of a.b), alongside regular keys.
    When
        - getting a ticket context
    Then
        - validate that all the details of the ticket were updated, and all the updated keys are shown in
        the context with do duplicates.
    """
    assert get_ticket_context(RESPONSE_TICKET,
                              ['Summary', 'opened_by.link']) == \
        EXPECTED_TICKET_CONTEXT_WITH_NESTED_ADDITIONAL_FIELDS


def test_get_ticket_human_readable():
    assert get_ticket_human_readable(RESPONSE_TICKET, 'incident') == EXPECTED_TICKET_HR

    assert EXPECTED_MULTIPLE_TICKET_HR[0] in get_ticket_human_readable(RESPONSE_MULTIPLE_TICKET, 'incident')
    assert EXPECTED_MULTIPLE_TICKET_HR[1] in get_ticket_human_readable(RESPONSE_MULTIPLE_TICKET, 'incident')


def test_generate_body():
    fields = {'a_field': 'test'}
    custom_fields = {'a_custom_field': 'test'}
    expected_body = {'a_field': 'test', 'u_a_custom_field': 'test'}
    assert expected_body == generate_body(fields, custom_fields)


def test_split_fields():
    expected_dict_fields = {'a': 'b', 'c': 'd', 'e': ''}
    assert expected_dict_fields == split_fields('a=b;c=d;e=')

    expected_custom_field = {'u_customfield': "<a href=\'https://google.com\'>Link text</a>"}
    assert expected_custom_field == split_fields("u_customfield=<a href=\'https://google.com\'>Link text</a>")

    expected_custom_sys_params = {
        "sysparm_display_value": 'all',
        "sysparm_exclude_reference_link": 'True',
        "sysparm_query": 'number=TASK0000001'
    }

    assert expected_custom_sys_params == split_fields(
        "sysparm_display_value=all;sysparm_exclude_reference_link=True;sysparm_query=number=TASK0000001")

    with pytest.raises(Exception) as err:
        split_fields('a')
    assert "must contain a '=' to specify the keys and values" in str(err)


def test_split_fields_with_special_delimiter():
    """Unit test
    Given
    - split_fields method
    - the default delimiter is ;
    When
    - splitting values with a different delimiter - ','
    Then
    -  Validate the fields were created correctly
    """
    expected_dict_fields = {'a': 'b', 'c': 'd'}
    assert expected_dict_fields == split_fields('a=b,c=d', ',')

    expected_custom_field = {'u_customfield': "<a href=\'https://google.com\'>Link text<;/a>"}
    assert expected_custom_field == split_fields("u_customfield=<a href=\'https://google.com\'>Link text<;/a>", ',')

    with pytest.raises(Exception) as e:
        split_fields('a')
    assert "must contain a '=' to specify the keys and values" in str(e)


def test_convert_to_notes_result():
    """
    Given:
        - The full response for a ticket from SNOW.
    When:
        - Converting the comments and work notes to the format used in the integration.
    Then:
        - Verify that the expected notes are returned in the correct format.
    """
    # Note: the 'display_value' time is the local time of the SNOW instance, and the 'value' is in UTC.
    # The results returned for notes are expected to be in UTC time.

    expected_result = {'result': [{'sys_created_on': '2022-11-21 21:50:34',
                                   'value': 'Second comment\n\n Mirrored from Cortex XSOAR',
                                   'sys_created_by': 'System Administrator',
                                   'element': 'comments'
                                   },
                                  {'sys_created_on': '2022-11-21 20:45:37',
                                   'value': 'First comment',
                                   'sys_created_by': 'Test User',
                                   'element': 'comments'
                                   }]}
    assert convert_to_notes_result(RESPONSE_COMMENTS_DISPLAY_VALUE_AFTER_FORMAT,
                                   time_info={'display_date_format': DATE_FORMAT,
                                              'timezone_offset': timedelta(minutes=-60)}) == expected_result

    # Filter comments by creation time (filter is given in UTC):
    expected_result = {'result': [{'sys_created_on': '2022-11-21 21:50:34',
                                   'value': 'Second comment\n\n Mirrored from Cortex XSOAR',
                                   'sys_created_by': 'System Administrator',
                                   'element': 'comments'
                                   }]}
    assert convert_to_notes_result(RESPONSE_COMMENTS_DISPLAY_VALUE_AFTER_FORMAT,
                                   time_info={'display_date_format': DATE_FORMAT,
                                              'filter': datetime.strptime('2022-11-21 21:44:37', DATE_FORMAT),
                                              'timezone_offset': timedelta(minutes=-60)}) == expected_result

    ticket_response = {}
    assert convert_to_notes_result(ticket_response, time_info={'display_date_format': DATE_FORMAT}) == {}

    assert convert_to_notes_result(RESPONSE_COMMENTS_DISPLAY_VALUE_NO_COMMENTS,
                                   time_info={'display_date_format': DATE_FORMAT}) == {'result': []}


def test_split_notes():
    """
    Given:
        - Notes response from SNOW.
        - The type of the note (comment or work_note).
        - The UTC timezone offset and (optionally) a time filter.
    When:
        - Converting the given notes to the note format used in the integration with different time filters.
    Then:
        - Verify that the expected notes are returned in the correct format.
    """
    # Note: the timezone in the raw_notes should mimic the local time of the SNOW instance,
    # the time in the filter is in UTC (to mimic the behaviour of fetching).
    # timezone_offset is the difference between UTC and local time, e.g. offset = -60, means that local time is UTC+1.
    # The 'sys_created_on' time, returned by the command is normalized to UTC timezone.

    raw_notes = '2022-11-21 22:50:34 - System Administrator (Additional comments)\nSecond comment\n\n Mirrored from ' \
                'Cortex XSOAR\n\n2022-11-21 21:45:37 - Test User (Additional comments)\nFirst comment\n\n'

    time_info = {'timezone_offset': timedelta(minutes=0),
                 'filter': datetime.strptime('2022-11-21 21:44:37', DATE_FORMAT),
                 'display_date_format': DATE_FORMAT}
    notes = split_notes(raw_notes, 'comments', time_info)
    expected_notes = [{'sys_created_on': '2022-11-21 22:50:34',
                       'value': 'Second comment\n\n Mirrored from Cortex XSOAR',
                       'sys_created_by': 'System Administrator',
                       'element': 'comments'
                       },
                      {'sys_created_on': '2022-11-21 21:45:37',
                       'value': 'First comment',
                       'sys_created_by': 'Test User',
                       'element': 'comments'
                       }]
    assert notes == expected_notes

    raw_notes = '21/11/2022 22:50:34 - System Administrator (Additional comments)\nSecond comment\n\n Mirrored from ' \
                'Cortex XSOAR\n\n21/11/2022 21:45:37 - Test User (Additional comments)\nFirst comment\n\n'
    time_info = {'timezone_offset': timedelta(minutes=-60),
                 'filter': datetime.strptime('2022-11-21 21:44:37', DATE_FORMAT),
                 'display_date_format': DATE_FORMAT_OPTIONS.get('dd/MM/yyyy')}
    notes = split_notes(raw_notes, 'comments', time_info)
    expected_notes = [{'sys_created_on': '2022-11-21 21:50:34',
                       'value': 'Second comment\n\n Mirrored from Cortex XSOAR',
                       'sys_created_by': 'System Administrator',
                       'element': 'comments'
                       }]
    assert notes == expected_notes

    raw_notes = '21.11.2022 22:50:34 - System Administrator (Additional comments)\nSecond comment\n\n Mirrored from ' \
                'Cortex XSOAR\n\n21.11.2022 21:45:37 - Test User (Additional comments)\nFirst comment\n\n'
    time_info = {'timezone_offset': timedelta(minutes=-60),
                 'filter': datetime.strptime('2022-11-21 21:44:37', DATE_FORMAT),
                 'display_date_format': DATE_FORMAT_OPTIONS.get('dd.MM.yyyy')}
    notes = split_notes(raw_notes, 'comments', time_info)
    expected_notes = [{'sys_created_on': '2022-11-21 21:50:34',
                       'value': 'Second comment\n\n Mirrored from Cortex XSOAR',
                       'sys_created_by': 'System Administrator',
                       'element': 'comments'
                       }]
    assert notes == expected_notes

    raw_notes = '11-21-2022 22:50:34 - System Administrator (Additional comments)\nSecond comment\n\n Mirrored from ' \
                'Cortex XSOAR\n\n11-21-2022 21:45:37 - Test User (Additional comments)\nFirst comment\n\n'
    time_info = {'timezone_offset': timedelta(minutes=-120),
                 'filter': datetime.strptime('2022-11-21 21:44:37', DATE_FORMAT),
                 'display_date_format': DATE_FORMAT_OPTIONS.get('MM-dd-yyyy')}
    notes = split_notes(raw_notes, 'comments', time_info)
    assert len(notes) == 0


def test_get_timezone_offset():
    """
    Given:
        - A response from a SNOW ticket created with 'sysparm_display_value=all'.
    When:
        - Testing different instance and UTC times.
    Then:
        - Assert the offset between the UTC and the instance times are correct.
    """
    full_response = {'sys_created_on': {'display_value': '2022-12-07 05:38:52', 'value': '2022-12-07 13:38:52'}}
    offset = get_timezone_offset(full_response, display_date_format=DATE_FORMAT)
    assert offset == timedelta(minutes=480)

    full_response = {'sys_created_on': {'display_value': '12-07-2022 15:47:34', 'value': '2022-12-07 13:47:34'}}
    offset = get_timezone_offset(full_response, display_date_format=DATE_FORMAT_OPTIONS.get('MM-dd-yyyy'))
    assert offset == timedelta(minutes=-120)

    full_response = {'sys_created_on': {'display_value': '06/12/2022 23:38:52', 'value': '2022-12-07 09:38:52'}}
    offset = get_timezone_offset(full_response, display_date_format=DATE_FORMAT_OPTIONS.get('dd/MM/yyyy'))
    assert offset == timedelta(minutes=600)

    full_response = {'sys_created_on': {'display_value': '06/12/2022 23:38:52 PM', 'value': '2022-12-07 09:38:52'}}
    offset = get_timezone_offset(full_response, display_date_format=DATE_FORMAT_OPTIONS.get('dd/MM/yyyy'))
    assert offset == timedelta(minutes=600)

    full_response = {'sys_created_on': {'display_value': '07.12.2022 0:38:52', 'value': '2022-12-06 19:38:52'}}
    offset = get_timezone_offset(full_response, display_date_format=DATE_FORMAT_OPTIONS.get('dd.MM.yyyy'))
    assert offset == timedelta(minutes=-300)

    full_response = {'sys_created_on': {'display_value': 'Dec-07-2022 00:38:52', 'value': '2022-12-06 19:38:52'}}
    offset = get_timezone_offset(full_response, display_date_format=DATE_FORMAT_OPTIONS.get('mmm-dd-yyyy'))
    assert offset == timedelta(minutes=-300)

    full_response = {'sys_created_on': {'display_value': 'Dec-07-2022 00:38:52 AM', 'value': '2022-12-06 19:38:52'}}
    offset = get_timezone_offset(full_response, display_date_format=DATE_FORMAT_OPTIONS.get('mmm-dd-yyyy'))
    assert offset == timedelta(minutes=-300)

    full_response = {'sys_created_on': {'display_value': 'Dec-07-2022 00:38:52 AM    ', 'value': '2022-12-06 19:38:52'}}
    offset = get_timezone_offset(full_response, display_date_format=DATE_FORMAT_OPTIONS.get('mmm-dd-yyyy'))
    assert offset == timedelta(minutes=-300)


def test_get_ticket_notes_command_success(mocker):
    """
    Given
    - A mock client and args input to the get_ticket_notes_command function
    - A mock successful API response

    When
    - The get_ticket_notes_command function is called

    Then
    - Ensure the expected API call is made
    - Validate the expected CommandResults are returned
    """
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name')
    args = {'id': 'sys_id'}

    mock_send_request = mocker.patch.object(Client, 'send_request')
    mock_send_request.return_value = RESPONSE_GET_TICKET_NOTES
    result = get_ticket_notes_command(client, args, {})

    assert isinstance(result[0], CommandResults)
    assert mock_send_request.called
    assert len(result[0].raw_response.get("result")) == 5
    assert result[0].outputs_prefix == 'ServiceNow.Ticket'
    assert result[0].outputs == EXPECTED_GET_TICKET_NOTES


def test_get_ticket_notes_command_use_display_value(mocker):
    """
    Given
    - A mock client and args input to the get_ticket_notes_command function
    - A mock successful API response

    When
    - The get_ticket_notes_command function is called with use_display_value

    Then
    - Ensure the expected API call is made
    - Validate the expected CommandResults are returned
    """
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name', use_display_value=True,
                    display_date_format="yyyy-MM-dd")
    args = {'id': 'sys_id'}

    mock_send_request = mocker.patch.object(Client, 'send_request')
    mock_send_request.return_value = RESPONSE_COMMENTS_DISPLAY_VALUE
    result = get_ticket_notes_command(client, args, {})

    assert isinstance(result[0], CommandResults)
    assert mock_send_request.called
    assert len(result[0].raw_response.get("result")) == 2
    assert result[0].outputs_prefix == 'ServiceNow.Ticket'
    assert result[0].outputs == EXPECTED_GET_TICKET_NOTES_DISPLAY_VALUE


def test_get_ticket_notes_command_use_display_value_no_comments(mocker):
    """
    Given
    - A mock client and args input to the get_ticket_notes_command function
    - A mock successful API response

    When
    - The get_ticket_notes_command function is called with use_display_value but no comments

    Then
    - Ensure the expected API call is made
    - Validate the expected CommandResults are returned
    """
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name', use_display_value=True,
                    display_date_format="yyyy-MM-dd")
    args = {'id': 'sys_id'}

    mock_send_request = mocker.patch.object(Client, 'send_request')
    mock_send_request.return_value = RESPONSE_COMMENTS_DISPLAY_VALUE_NO_COMMENTS
    result = get_ticket_notes_command(client, args, {})

    assert isinstance(result[0], CommandResults)
    assert mock_send_request.called
    assert result[0].raw_response == "No comment found on ticket sys_id."


@pytest.mark.parametrize("notes, params, expected", [
    (
        [
            {
                "value": "First comment",
                "sys_created_by": "Test User",
                "sys_created_on": "2022-11-21 20:45:37",
                "element": "comments"
            }
        ],
        {
            "comment_tag_from_servicenow": "CommentFromServiceNow"
        },
        [
            {
                "Type": 1,
                "Category": None,
                "Contents": "Type: comments\nCreated By: Test User\nCreated On: 2022-11-21 20:45:37\nFirst comment",
                "ContentsFormat": None,
                "Tags": ["CommentFromServiceNow"],
                "Note": True,
                "EntryContext": {"comments_and_work_notes": "First comment"}
            }
        ]
    )
])
def test_get_entries_for_notes_with_comment(notes, params, expected):
    """
    Given
        - A list of notes
        - Params containing comment tag
    When
        - Calling get_entries_for_notes
    Then
        - Should return a list of entry contexts
    """
    assert get_entries_for_notes(notes, params) == expected


@pytest.mark.parametrize('command, args, response, expected_result, expected_auto_extract', [
    (update_ticket_command, {'id': '1234', 'impact': '2'}, RESPONSE_UPDATE_TICKET, EXPECTED_UPDATE_TICKET, True),
    (update_ticket_command, {'id': '1234', 'ticket_type': 'sc_req_item', 'approval': 'requested'},
     RESPONSE_UPDATE_TICKET_SC_REQ, EXPECTED_UPDATE_TICKET_SC_REQ, True),
    (update_ticket_command, {'id': '1234', 'severity': '3', 'additional_fields': "approval=rejected"},
     RESPONSE_UPDATE_TICKET_ADDITIONAL, EXPECTED_UPDATE_TICKET_ADDITIONAL, True),
    (create_ticket_command, {'active': 'true', 'severity': "3", 'description': "creating a test ticket",
                             'sla_due': "2020-10-10 10:10:11"}, RESPONSE_CREATE_TICKET, EXPECTED_CREATE_TICKET, True),
    (create_ticket_command, {'active': 'true', 'severity': "3", 'description': "creating a test ticket",
                             'sla_due': "2020-10-10 10:10:11"}, RESPONSE_CREATE_TICKET_WITH_OUT_JSON,
     EXPECTED_CREATE_TICKET_WITH_OUT_JSON, True),
    (query_tickets_command, {'limit': "3", 'query': "impact<2^short_descriptionISNOTEMPTY", 'ticket_type': "incident"},
     RESPONSE_QUERY_TICKETS, EXPECTED_QUERY_TICKETS, True),
    (query_tickets_command,
     {"ticket_type": "incident", "query": "number=INC0000001", "system_params": "sysparm_exclude_reference_link=true"},
     RESPONSE_QUERY_TICKETS_EXCLUDE_REFERENCE_LINK, EXPECTED_QUERY_TICKETS_EXCLUDE_REFERENCE_LINK, True),
    (upload_file_command, {'id': "sys_id", 'file_id': "entry_id", 'file_name': 'test_file'}, RESPONSE_UPLOAD_FILE,
     EXPECTED_UPLOAD_FILE, True),
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
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name', display_date_format='yyyy-MM-dd')
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
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name')
    mocker.patch.object(client, 'send_request', return_value=response)
    result = command(client, args)
    assert expected_hr in result[0]  # HR is found in the 1st place in the result of the command
    assert expected_auto_extract == result[3]  # ignore_auto_extract is in the 4th place in the result of the command


def test_delete_attachment_command(mocker):
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name')

    mocker.patch.object(client, 'delete_attachment', return_value=None)
    result = delete_attachment_command(client=client, args={"file_sys_id": "1234"})
    assert 'Attachment with Sys ID 1234 was successfully deleted.' in result[0]


def test_delete_attachment_command_failed(mocker):
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name')

    mocker.patch.object(client, 'delete_attachment', return_value="Error")
    with pytest.raises(DemistoException) as e:
        delete_attachment_command(client=client, args={"file_sys_id": "1234"})
    assert "Error: No record found. Record doesn't exist or ACL restricts the record retrieval." in str(e)


@freeze_time('2022-05-01 12:52:29')
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
    - run the fetch incidents command using the Client.
    - Validate The length of the results.
    - Ensure the incident sys IDs are stored in integration context for the first mirroring.
    """
    RESPONSE_FETCH['result'][0]['opened_at'] = (datetime.utcnow() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
    RESPONSE_FETCH['result'][1]['opened_at'] = (datetime.utcnow() - timedelta(minutes=8)).strftime('%Y-%m-%d %H:%M:%S')
    mocker.patch(
        'CommonServerPython.get_fetch_run_time_range', return_value=('2022-05-01 01:05:07', '2022-05-01 12:08:29')
    )
    mocker.patch('ServiceNowv2.parse_dict_ticket_fields', return_value=RESPONSE_FETCH['result'])
    mocker.patch.object(demisto, 'params', return_value={"mirror_notes_for_new_incidents": True})
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', '2 days', 'sysparm_query', sysparm_limit=10,
                    timestamp_field='opened_at', ticket_type='incident', get_attachments=False, incident_name='number')
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH)
    incidents = fetch_incidents(client)
    assert len(incidents) == 2
    assert incidents[0].get('name') == 'ServiceNow Incident INC0000040'
    assert demisto.getIntegrationContext()["last_fetched_incident_ids"] == ["sys_id1", "sys_id2"]


@freeze_time('2022-05-01 12:52:29')
def test_fetch_incidents_with_changed_fetch_limit(mocker):
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
    Validate The number of fetch_limit in the last_run
    """
    RESPONSE_FETCH['result'][0]['opened_at'] = (datetime.utcnow() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
    RESPONSE_FETCH['result'][1]['opened_at'] = (datetime.utcnow() - timedelta(minutes=8)).strftime('%Y-%m-%d %H:%M:%S')
    mocker.patch(
        'CommonServerPython.get_fetch_run_time_range', return_value=('2022-05-01 01:05:07', '2022-05-01 12:08:29')
    )
    mocker.patch('ServiceNowv2.parse_dict_ticket_fields', return_value=RESPONSE_FETCH['result'])
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', '2 days', 'sysparm_query', sysparm_limit=20,
                    timestamp_field='opened_at', ticket_type='incident', get_attachments=False, incident_name='number')
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH)
    mocker.patch.object(demisto, 'getLastRun', return_value={'limit': 10})
    set_last_run = mocker.patch.object(demisto, 'setLastRun')
    fetch_incidents(client)

    assert set_last_run.call_args[0][0].get('limit') == 20


@freeze_time('2022-05-01 12:52:29')
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
    RESPONSE_FETCH_ATTACHMENTS_TICKET['result'][0]['opened_at'] = (
        datetime.utcnow() - timedelta(minutes=15)
    ).strftime('%Y-%m-%d %H:%M:%S')
    mocker.patch(
        'CommonServerPython.get_fetch_run_time_range', return_value=('2022-05-01 01:05:07', '2022-05-01 12:08:29')
    )
    mocker.patch('ServiceNowv2.parse_dict_ticket_fields', return_value=RESPONSE_FETCH['result'])
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', '2 days', 'sysparm_query', sysparm_limit=10,
                    timestamp_field='opened_at', ticket_type='incident', get_attachments=True,
                    incident_name='number')
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH_ATTACHMENTS_TICKET)
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=RESPONSE_FETCH_ATTACHMENTS_FILE)

    incidents = fetch_incidents(client)

    assert len(incidents) == 1
    assert incidents[0].get('attachment')[0]['name'] == 'wireframe'
    assert incidents[0].get('attachment')[0]['path'] == 'file_id'


@freeze_time('2022-05-01 12:52:29')
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
    RESPONSE_FETCH['result'][0]['opened_at'] = (datetime.utcnow() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
    RESPONSE_FETCH['result'][1]['opened_at'] = (datetime.utcnow() - timedelta(minutes=8)).strftime('%Y-%m-%d %H:%M:%S')
    mocker.patch('ServiceNowv2.parse_dict_ticket_fields', return_value=RESPONSE_FETCH['result'])
    mocker.patch(
        'CommonServerPython.get_fetch_run_time_range', return_value=('2022-05-01 01:05:07', '2022-05-01 12:08:29')
    )
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', '2 days', 'sysparm_query', sysparm_limit=10,
                    timestamp_field='opened_at', ticket_type='incident',
                    get_attachments=False, incident_name='description')
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH)
    incidents = fetch_incidents(client)
    assert incidents[0].get('name') == 'ServiceNow Incident Unable to access Oregon mail server. Is it down?'


def start_freeze_time(timestamp):
    _start_freeze_time = freeze_time(timestamp)
    _start_freeze_time.start()
    return datetime.now()


class TestFetchIncidentsWithLookBack:
    LAST_RUN = {}

    API_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
    FREEZE_TIMESTAMP = '2022-05-01 12:52:29'

    def set_last_run(self, new_last_run):
        self.LAST_RUN = new_last_run

    @pytest.mark.parametrize(
        'start_incidents, phase2_incident, phase3_incident, look_back',
        [
            (
                {
                    'result': [
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(minutes=10)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '2',
                            'number': '2',
                            'sys_id': '2'
                        },
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(minutes=5)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '1',
                            'number': '4',
                            'sys_id': '4'
                        },
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(minutes=2)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '2',
                            'number': '5',
                            'sys_id': '5'
                        }
                    ]
                },
                {
                    'opened_at': (
                        start_freeze_time(FREEZE_TIMESTAMP) - timedelta(minutes=8)
                    ).strftime(API_TIME_FORMAT),
                    'severity': '1',
                    'number': '3',
                    'sys_id': '3'
                },
                {
                    'opened_at': (
                        start_freeze_time(FREEZE_TIMESTAMP) - timedelta(minutes=11)
                    ).strftime(API_TIME_FORMAT),
                    'severity': '1',
                    'number': '1',
                    'sys_id': '1'
                },
                15
            ),
            (
                {
                    'result': [
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(hours=3, minutes=20)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '2',
                            'number': '2',
                            'sys_id': '2'
                        },
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(hours=2, minutes=26)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '1',
                            'number': '4',
                            'sys_id': '4'
                        },
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(hours=1, minutes=20)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '2',
                            'number': '5',
                            'sys_id': '5'
                        }
                    ]
                },
                {
                    'opened_at': (
                        start_freeze_time(FREEZE_TIMESTAMP) - timedelta(hours=2, minutes=45)
                    ).strftime(API_TIME_FORMAT),
                    'severity': '1',
                    'number': '3',
                    'sys_id': '3'
                },
                {
                    'opened_at': (
                        start_freeze_time(FREEZE_TIMESTAMP) - timedelta(hours=3, minutes=50)
                    ).strftime(API_TIME_FORMAT),
                    'severity': '1',
                    'number': '1',
                    'sys_id': '1'
                },
                1000
            )
        ]
    )
    def test_fetch_incidents_with_look_back_greater_than_zero(
            self, mocker, start_incidents, phase2_incident, phase3_incident, look_back
    ):
        """
        Given
        - fetch incidents parameters including look back according to their opened time.
        - first scenario - fetching with minutes when look_back=60 minutes
        - second scenario - fetching with hours when look_back=1000 minutes

        When
        - trying to fetch incidents for 3 rounds.

        Then
        - first fetch - should fetch incidents 2, 4, 5 (because only them match the query)
        - second fetch - should fetch incident 3 (because now incident 2, 4, 5, 3 matches the query too)
        - third fetch - should fetch incident 1 (because now incident 2, 4, 5, 3, 1 matches the query too)
        - fourth fetch - should fetch nothing as there are not new incidents who match the query
        - make sure that incidents who were already fetched would not be fetched again.
        """
        client = Client(
            server_url='', sc_server_url='', cr_server_url='', username='', password='', verify=False,
            fetch_time='6 hours', sysparm_query='stateNOT IN6,7^assignment_group=123', sysparm_limit=10,
            timestamp_field='opened_at', ticket_type='incident', get_attachments=False, incident_name='number',
            look_back=look_back
        )

        # reset last run
        self.LAST_RUN = {}

        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        mocker.patch.object(demisto, 'setLastRun', side_effect=self.set_last_run)

        mocker.patch.object(client, 'send_request', return_value=start_incidents)

        # first fetch
        tickets = fetch_incidents(client=client)
        assert len(tickets) == 3
        for expected_incident_id, ticket in zip(['2', '4', '5'], tickets):
            assert ticket.get('name') == f'ServiceNow Incident {expected_incident_id}'

        # second fetch preparation
        start_incidents.get('result').append(phase2_incident)

        # second fetch
        tickets = fetch_incidents(client=client)
        assert len(tickets) == 1
        assert tickets[0].get('name') == 'ServiceNow Incident 3'

        # third fetch preparation
        start_incidents.get('result').append(phase3_incident)

        # third fetch
        tickets = fetch_incidents(client=client)
        assert len(tickets) == 1
        assert tickets[0].get('name') == 'ServiceNow Incident 1'

        # forth fetch
        tickets = fetch_incidents(client=client)
        assert len(tickets) == 0

    @pytest.mark.parametrize(
        'incidents, phase2_incident, phase3_incident',
        [
            (
                {
                    'result': [
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(minutes=10)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '2',
                            'number': '1',
                            'sys_id': '1'
                        },
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(minutes=8)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '1',
                            'number': '2',
                            'sys_id': '2'
                        },
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(minutes=7)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '2',
                            'number': '3',
                            'sys_id': '3'
                        }
                    ]
                },
                {
                    'result': [
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(minutes=5)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '1',
                            'number': '4',
                            'sys_id': '4'
                        }
                    ]
                },
                {
                    'result': [
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(minutes=4)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '1',
                            'number': '5',
                            'sys_id': '5'
                        }
                    ]
                },
            ),
            (
                {
                    'result': [
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(hours=8, minutes=51)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '2',
                            'number': '1',
                            'sys_id': '1'
                        },
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(hours=7, minutes=45)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '1',
                            'number': '2',
                            'sys_id': '2'
                        },
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(hours=7, minutes=44)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '2',
                            'number': '3',
                            'sys_id': '3'
                        }
                    ]
                },
                {
                    'result': [
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(hours=7, minutes=44)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '1',
                            'number': '4',
                            'sys_id': '4'
                        }
                    ]
                },
                {
                    'result': [
                        {
                            'opened_at': (
                                start_freeze_time(FREEZE_TIMESTAMP) - timedelta(hours=1, minutes=34)
                            ).strftime(API_TIME_FORMAT),
                            'severity': '1',
                            'number': '5',
                            'sys_id': '5'
                        }
                    ]
                }
            )
        ]
    )
    def test_fetch_incidents_with_look_back_equals_zero(
            self, mocker, incidents, phase2_incident, phase3_incident
    ):
        """
        Given
        - fetch incidents parameters with any look back according to their opened time (normal fetch incidents).
        - first scenario - fetching with minutes when look_back=0
        - second scenario - fetching with hours when look_back=0

        When
        - trying to fetch incidents for 3 rounds.

        Then
        - first fetch - should fetch incidents 1, 2, 3 (because only them match the query)
        - second fetch - should fetch incident 4
        - third fetch - should fetch incident 5
        - fourth fetch - should fetch nothing as there are not new incidents who match the query
        """
        client = Client(
            server_url='', sc_server_url='', cr_server_url='', username='', password='', verify=False,
            fetch_time='12 hours', sysparm_query='stateNOT IN6,7^assignment_group=123', sysparm_limit=10,
            timestamp_field='opened_at', ticket_type='incident', get_attachments=False, incident_name='number',
            look_back=0
        )

        # reset last fetch and tickets
        self.LAST_RUN = {}

        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        mocker.patch.object(demisto, 'setLastRun', side_effect=self.set_last_run)
        mocker.patch.object(client, 'send_request', return_value=incidents)

        # first fetch
        tickets = fetch_incidents(client=client)
        assert len(tickets) == 3
        for expected_incident_id, ticket in zip(['1', '2', '3'], tickets):
            assert ticket.get('name') == f'ServiceNow Incident {expected_incident_id}'

        # second fetch preparation
        incidents = phase2_incident
        mocker.patch.object(client, 'send_request', return_value=incidents)

        # second fetch
        tickets = fetch_incidents(client=client)
        assert len(tickets) == 1
        assert tickets[0].get('name') == 'ServiceNow Incident 4'

        # third fetch preparation
        incidents = phase3_incident
        mocker.patch.object(client, 'send_request', return_value=incidents)

        # third fetch
        tickets = fetch_incidents(client=client)
        assert len(tickets) == 1
        assert tickets[0].get('name') == 'ServiceNow Incident 5'

        # forth fetch preparation
        incidents = {'result': []}
        mocker.patch.object(client, 'send_request', return_value=incidents)

        # forth fetch
        tickets = fetch_incidents(client=client)
        assert len(tickets) == 0


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
            'incident_name': None,
            'file_tag_from_service_now': 'FromServiceNow',
            'file_tag_to_service_now': 'ToServiceNow',
            'comment_tag': 'comments',
            'comment_tag_from_servicenow': 'CommentFromServiceNow',
            'work_notes_tag': 'work_notes',
            'work_notes_tag_from_servicenow': 'WorkNoteFromServiceNow'
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


def test_file_tags_names_are_the_same_main_flow(mocker):
    """
    Given:
     - file tags from service now & file tag to service now that are identical

    When:
     - running main flow

    Then:
     - make sure an exception is raised
    """
    import ServiceNowv2
    mocker.patch.object(
        demisto,
        'params',
        return_value={'file_tag_from_service_now': 'ServiceNow', 'file_tag': 'ServiceNow'}
    )
    mocker.patch.object(ServiceNowv2, 'get_server_url', return_value='test')
    with pytest.raises(
            Exception,
            match=re.escape(
                'File Entry Tag To ServiceNow and File Entry Tag From ServiceNow cannot be the same name [ServiceNow].'
            )
    ):
        main()


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
    client = Client('http://server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name')
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
    debug = demisto.debug.call_args_list
    
    assert debug[0][0][0] == 'Sending request to ServiceNow. Method: GET, Path: '
    assert debug[1][0][0] == "Constructed URL: http://server_url\nRequest headers: {'Accept': 'application/json', 'Content-Type': 'application/json'}\nRequest params: {}"
    assert debug[2][0][0] == f'Request attempt 1 of {MAX_RETRY}'
    assert debug[3][0][0] == 'Sending regular request'
    assert debug[4][0][0] == 'Response status code: 401'
    assert debug[5][0][0] == f'Got status code 401. Retrying... (Attempt 1 of {MAX_RETRY})'
    assert debug[6][0][0] == f'Request attempt 2 of {MAX_RETRY}'
    assert debug[7][0][0] == 'Sending regular request'
    assert debug[8][0][0] == 'Response status code: 401'
    assert debug[9][0][0] == f'Got status code 401. Retrying... (Attempt 2 of {MAX_RETRY})' 
    assert debug[10][0][0] == f'Request attempt 3 of {MAX_RETRY}'
    assert debug[11][0][0] == 'Sending regular request'
    assert debug[12][0][0] == 'Response status code: 200'


def test_not_authenticated_retry_negative(requests_mock, mocker: MockerFixture):
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
    client = Client('http://server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name')
    requests_mock.get('http://server_url', [
        {
            'status_code': 401,
            'json': {
                'error': {'message': 'User Not Authenticated', 'detail': 'Required to provide Auth information'},
                'status': 'failure'
            }
        },
    ] * MAX_RETRY)
    with pytest.raises(Exception) as ex:
        client.send_request('')
    assert str(ex.value) == "Got status code 401 with url http://server_url with body b'{\"error\": {\"message\": " \
                            "\"User Not Authenticated\", \"detail\": \"Required to provide Auth information\"}, " \
                            "\"status\": \"failure\"}' with response headers {}"

    debug = demisto.debug.call_args_list

    assert debug[0][0][0] == 'Sending request to ServiceNow. Method: GET, Path: '
    assert debug[1][0][0] == "Constructed URL: http://server_url\nRequest headers: {'Accept': 'application/json', 'Content-Type': 'application/json'}\nRequest params: {}"
    assert debug[2][0][0] == f'Request attempt 1 of {MAX_RETRY}'
    assert debug[3][0][0] == 'Sending regular request'
    assert debug[4][0][0] == 'Response status code: 401'
    assert debug[5][0][0] == f'Got status code 401. Retrying... (Attempt 1 of {MAX_RETRY})'


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
            'use_oauth': True,
            'file_tag_from_service_now': 'FromServiceNow',
            'file_tag': 'ForServiceNow',
            'comment_tag': 'comments',
            'comment_tag_from_servicenow': 'CommentFromServiceNow',
            'work_notes_tag': 'work_notes',
            'work_notes_tag_from_servicenow': 'WorkNoteFromServiceNow'
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
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')
    mocker.patch.object(client, 'send_request', return_value=RESPONSE_FETCH)
    result = module(client)
    assert result[0] == 'ok'

    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at', ticket_type='incident',
                    get_attachments=False, incident_name='description', oauth_params=OAUTH_PARAMS)

    with pytest.raises(Exception) as e:
        module(client)
    assert 'Test button cannot be used when using OAuth 2.0' in str(e)


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
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at', ticket_type='incident',
                    get_attachments=False, incident_name='description')
    with pytest.raises(Exception) as e:
        oauth_test_module(client)
    assert 'command should be used only when using OAuth 2.0 authorization.' in str(e)

    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
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
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', sysparm_limit=10, timestamp_field='opened_at', ticket_type='incident',
                    get_attachments=False, incident_name='description')
    with pytest.raises(Exception) as e:
        login_command(client, args={'username': 'username', 'password': 'password'})
    assert '!servicenow-oauth-login command can be used only when using OAuth 2.0 authorization' in str(e)

    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
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

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url', cr_server_url='cr_server_url',
                    username='username', password='password', verify=False, fetch_time='fetch_time',
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
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url', cr_server_url='cr_server_url',
                    username='username', password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')
    res = get_mapping_fields_command(client)
    assert res.extract_mapping() == EXPECTED_MAPPING


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

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url='cr_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')

    args = {'id': 'sys_id', 'lastUpdate': 0}
    params = {"file_tag_from_service_now": "FromServiceNow"}
    mocker.patch.object(client, 'get', return_value=RESPONSE_TICKET_MIRROR)
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=RESPONSE_MIRROR_FILE_ENTRY)
    mocker.patch.object(client, 'query', return_value=MIRROR_COMMENTS_RESPONSE)
    mocker.patch.object(client, 'get', return_value=RESPONSE_ASSIGNMENT_GROUP)

    res = get_remote_data_command(client, args, params)

    assert res[1]['Tags'] == ['FromServiceNow']
    assert res[1]['File'] == 'test.txt'
    assert res[2]['Contents'] == 'Type: comments\nCreated By: admin\nCreated On: 2020-08-17 06:31:49\nThis is a comment'


def test_get_remote_data_last_fetched_incidents_entries(mocker):
    """
    Given:
        -  LastUpdate argument set to higher then the modification time.
        -  Integration context containing the last fetched ids to get their entries.
    When
        - running get_remote_data_command.
    Then
        - The ticket was updated with the entries even the lastUpdate is higher than modification time.
    """
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url='cr_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')

    args = {'id': 'sys_id', 'lastUpdate': 9999999999}
    params = {"file_tag_from_service_now": "FromServiceNow"}
    demisto.setIntegrationContext({"last_fetched_incident_ids": ["sys_id"]})
    mocker.patch.object(client, 'get', side_effect=[RESPONSE_TICKET_MIRROR, RESPONSE_ASSIGNMENT_GROUP])
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=[])
    client_query_mocker = mocker.patch.object(client, 'query', return_value=MIRROR_COMMENTS_RESPONSE)

    res = get_remote_data_command(client, args, params)

    assert 'sys_created_on' not in client_query_mocker.call_args[0][3]
    assert res[1]['Contents'] == 'Type: comments\nCreated By: admin\nCreated On: 2020-08-17 06:31:49\nThis is a comment'
    assert not demisto.getIntegrationContext()["last_fetched_incident_ids"]


def test_get_remote_data_no_last_fetched_incidents(mocker):
    """
    Given:
        -  LastUpdate argument set to higher then the modification time.
        -  Integration context does not containing the last fetched ids to get their entries.
    When
        - running get_remote_data_command.
    Then
        - The ticket is not updated with the entries.
    """
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url='cr_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')

    args = {'id': 'sys_id', 'lastUpdate': 9999999999}
    params = {"file_tag_from_service_now": "FromServiceNow"}
    demisto.setIntegrationContext({"last_fetched_incident_ids": []})
    mocker.patch.object(demisto, 'params', return_value={"isFetch": True})
    mocker.patch.object(client, 'get', side_effect=[RESPONSE_TICKET_MIRROR, RESPONSE_ASSIGNMENT_GROUP])
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=[])
    client_query_mocker = mocker.patch.object(client, 'query', return_value={'result': []})

    res = get_remote_data_command(client, args, params)

    assert 'sys_created_on' in client_query_mocker.call_args[0][3]
    assert len(res) == 1
    assert not res[0]


def test_get_remote_data_last_fetched_incidents_use_display_value(mocker):
    """
    Given:
        -  LastUpdate argument set to higher then the modification time.
        -  Integration context containing the last fetched ids to get their entries.
        -  Using display value.
    When
        - running get_remote_data_command.
    Then
        - The ticket was updated with the entries even the lastUpdate is higher than modification time.
    """
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url='cr_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description',
                    use_display_value=True, display_date_format='yyyy-MM-dd')

    args = {'id': 'sys_id', 'lastUpdate': 9999999999}
    params = {"file_tag_from_service_now": "FromServiceNow"}
    demisto.setIntegrationContext({"last_fetched_incident_ids": ["sys_id"]})
    mocker.patch.object(client, 'get', side_effect=[RESPONSE_QUERY_TABLE_SYS_PARAMS, RESPONSE_ASSIGNMENT_GROUP])
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=[])
    client_query_mocker = mocker.patch.object(ServiceNowv2, 'convert_to_notes_result', return_value=MIRROR_COMMENTS_RESPONSE)

    res = get_remote_data_command(client, args, params)

    assert 'filter' not in client_query_mocker.call_args[0][1]
    assert res[1]['Contents'] == 'Type: comments\nCreated By: admin\nCreated On: 2020-08-17 06:31:49\nThis is a comment'
    assert not demisto.getIntegrationContext()["last_fetched_incident_ids"]


def test_assigned_to_field_no_user():
    """
    Given:
        -  Client class
        -  Assigned_to field for user that doesn't exist in SNOW
    When
        - run check_assigned_to_field command
    Then
        - Check that assign_to value is empty
    """

    class Client:
        def get(self, table, value, no_record_found_res):
            return {'results': {}}

    assigned_to = {'link': 'https://test.service-now.com/api/now/table/sys_user/oscar@example.com',
                   'value': 'oscar@example.com'}
    res = check_assigned_to_field(Client(), assigned_to)
    assert res == ''


def test_assigned_to_field_user_exists():
    """
    Given:
        -  Client class
        -  Assigned_to field for user that does exist in SNOW
    When
        - run check_assigned_to_field command
    Then
        - Check that assign_to value is filled with the right email
    """

    class Client:
        def get(self, table, value, no_record_found_res):
            return USER_RESPONSE

    assigned_to = {'link': 'https://test.service-now.com/api/now/table/sys_user/oscar@example.com',
                   'value': 'oscar@example.com'}
    res = check_assigned_to_field(Client(), assigned_to)
    assert res == 'oscar@example.com'


CLOSING_RESPONSE = {'dbotIncidentClose': True, 'closeNotes': 'Test', 'closeReason': 'Resolved'}
CLOSING_RESPONSE_CUSTOM = {'dbotIncidentClose': True, 'closeNotes': 'Test', 'closeReason': 'Test'}

closed_ticket_state = (RESPONSE_CLOSING_TICKET_MIRROR_CLOSED, {
                       'close_incident': 'closed'}, 'closed_at', CLOSING_RESPONSE)
resolved_ticket_state = (RESPONSE_CLOSING_TICKET_MIRROR_RESOLVED, {
                         'close_incident': 'resolved'}, 'resolved_at', CLOSING_RESPONSE)
custom_ticket_state = (RESPONSE_CLOSING_TICKET_MIRROR_CUSTOM,
                       {'close_incident': 'closed', 'server_close_custom_state': '9=Test'}, '', CLOSING_RESPONSE_CUSTOM)


@pytest.mark.parametrize('response_closing_ticket_mirror, parameters, time, closing_response',
                         [closed_ticket_state, resolved_ticket_state, custom_ticket_state])
def test_get_remote_data_closing_incident(mocker, response_closing_ticket_mirror, parameters, time, closing_response):
    """
    Given:
        -  ServiceNow client
        -  arguments: id and LastUpdate(set to lower then the modification time).
        -  ServiceNow ticket in closed state
        -  close_incident parameter is set to closed
    When
        - running get_remote_data_command.
    Then
        - The closed_at field exists in the ticket data.
        - dbotIncidentClose exists.
        - Closed notes exists.
    """

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url="cr_server_url", username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='sc_task', get_attachments=False, incident_name='description')

    args = {'id': 'sys_id', 'lastUpdate': 0}
    params = parameters
    mocker.patch.object(client, 'get', return_value=response_closing_ticket_mirror)
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=[])
    mocker.patch.object(client, 'query', return_value=MIRROR_COMMENTS_RESPONSE)

    res = get_remote_data_command(client, args, params)
    if time:
        assert time in res[0]
    assert closing_response == res[2]['Contents']


def test_get_remote_data_closing_incident_with_different_closing_state(mocker):
    """
    Given:
        -  ServiceNow client
        -  arguments: id and LastUpdate(set to lower then the modification time).
        -  ServiceNow ticket in closed state
        -  close_incident parameter is set to closed
        -  server_close_custom_state parameter differs from the ticket's closing state
    When
        - running get_remote_data_command.
    Then
        - Validate that the incident does not get closed
    """

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url="cr_server_url", username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='sc_task', get_attachments=False, incident_name='description')

    args = {'id': 'sys_id', 'lastUpdate': 0}
    params = {'close_incident': 'closed', 'server_close_custom_state': '6=Design'}
    mocker.patch.object(client, 'get', return_value=RESPONSE_CLOSING_TICKET_MIRROR_CUSTOM)
    mocker.patch.object(client, 'get_ticket_attachment_entries', return_value=[])
    mocker.patch.object(client, 'query', return_value=MIRROR_COMMENTS_RESPONSE)
    res = get_remote_data_command(client, args, params)
    assert len(res) == 2
    # This means that the entry is of type Note, which does not indicate the closing of the incident
    assert res[1].get('Note', False) is True


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

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url="cr_server_url", username='username',
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
    assert res[1]['Contents'] == 'Type: comments\nCreated By: admin\nCreated On: 2020-08-17 06:31:49\nThis is a comment'
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

    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url='cr_server_url', username='username',
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
    assert args[2] == 'test_mirrored_from_xsoar.txt'
    return {'id': "sys_id", 'file_id': "entry_id", 'file_name': 'test.txt'}


def add_comment_request(*args):
    assert args[3] == '(dbot): This is a comment\n\n Mirrored from Cortex XSOAR'
    return {'id': "1234", 'comment': "This is a comment"}


@pytest.mark.parametrize('mirror_entries', [MIRROR_ENTRIES, MIRROR_ENTRIES_WITH_EMPTY_USERNAME])
def test_upload_entries_update_remote_system_command(mocker, mirror_entries):
    """
    Given:
        -  ServiceNow client
        -  File and comment entries sent from XSOAR.
    When
        - running update_remote_system_command.
    Then
        - The checked entries was sent as expected with suffix.
    """
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url='cr_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')
    params = {}
    args = {'remoteId': '1234', 'data': {}, 'entries': mirror_entries, 'incidentChanged': False, 'delta': {}}
    mocker.patch.object(client, 'upload_file', side_effect=upload_file_request)
    mocker.patch.object(client, 'add_comment', side_effect=add_comment_request)

    update_remote_system_command(client, args, params)


TICKET_FIELDS = {'close_notes': 'This is closed', 'closed_at': '2020-10-29T13:19:07.345995+02:00', 'impact': '3',
                 'priority': '4', 'resolved_at': '2020-10-29T13:19:07.345995+02:00', 'severity': '1 - Low',
                 'short_description': 'Post parcel', 'sla_due': '0001-01-01T00:00:00Z', 'urgency': '3', 'state': '1',
                 'work_start': '0001-01-01T00:00:00Z'}


def ticket_fields(*args, **kwargs):
    state = '7' if kwargs.get('ticket_type') == 'incident' else '3'
    assert args[0] == {'close_notes': 'This is closed', 'closed_at': '2020-10-29T13:19:07.345995+02:00', 'impact': '3',
                       'priority': '4', 'resolved_at': '2020-10-29T13:19:07.345995+02:00', 'severity': '1 - Low',
                       'short_description': 'Post parcel', 'sla_due': '0001-01-01T00:00:00Z', 'urgency': '3', 'state': state,
                       'work_start': '0001-01-01T00:00:00Z'}

    return {'close_notes': 'This is closed', 'closed_at': '2020-10-29T13:19:07.345995+02:00', 'impact': '3',
            'priority': '4', 'resolved_at': '2020-10-29T13:19:07.345995+02:00', 'severity': '1 - Low',
            'short_description': 'Post parcel', 'sla_due': '0001-01-01T00:00:00Z', 'urgency': '3', 'state': '1',
            'work_start': '0001-01-01T00:00:00Z'}


def update_ticket(*args):
    state = '7' if 'incident' in args else '3'
    return {'short_description': 'Post parcel', 'close_notes': 'This is closed',
            'closed_at': '2020-10-29T13:19:07.345995+02:00', 'impact': '3', 'priority': '4',
            'resolved_at': '2020-10-29T13:19:07.345995+02:00', 'severity': '1 - High - Low',
            'sla_due': '0001-01-01T00:00:00Z', 'state': state, 'urgency': '3', 'work_start': '0001-01-01T00:00:00Z'}


@pytest.mark.parametrize('ticket_type', ['sc_task', 'sc_req_item', 'incident'])
def test_update_remote_data_sc_task_sc_req_item(mocker, ticket_type):
    """
    Given:
    -  ServiceNow client
    -  ServiceNow ticket of type sc_task
    -  ServiceNow ticket of type sc_req_item
    -  ServiceNow ticket of type incident

    When
        - running update_remote_system_command.
    Then
        - The state is changed to 3 (closed) after update for sc_task and sc_req_item.
        - The state is changed to 7 (closed) after update for incident.
    """
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url='cr_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type=ticket_type, get_attachments=False, incident_name='description')
    params = {'ticket_type': ticket_type, 'close_ticket_multiple_options': 'None', 'close_ticket': True}
    args = {'remoteId': '1234', 'data': TICKET_FIELDS, 'entries': [], 'incidentChanged': True, 'delta': {},
            'status': 2}
    mocker.patch('ServiceNowv2.get_ticket_fields', side_effect=ticket_fields)
    mocker.patch.object(client, 'update', side_effect=update_ticket)
    update_remote_system_command(client, args, params)


@pytest.mark.parametrize('command, args', [
    (query_tickets_command, {'limit': "50", 'query': "assigned_to=123^active=true", 'ticket_type': "sc_task"}),
    (query_table_command, {'limit': "50", 'query': "assigned_to=123^active=true", 'table_name': "sc_task"})
])
def test_multiple_query_params(requests_mock, command, args):
    """
    Given:
     - Query with multiple arguments

    When:
     - Using servicenow-query-tickets command with multiple sysparm_query arguments.
     - Using servicenow-query-table command with multiple sysparm_query arguments.

    Then:
     - Verify the right request is called with '^' distinguishing different arguments.
    """
    url = 'https://test.service-now.com/api/now/v2/'
    client = Client(url, 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name')
    requests_mock.request('GET', f'{url}table/sc_task?sysparm_limit=50&sysparm_offset=0&'
                                 'sysparm_query=assigned_to%3D123^active%3Dtrue',
                          json=RESPONSE_TICKET_ASSIGNED)
    human_readable, entry_context, result, bol = command(client, args)

    assert result == RESPONSE_TICKET_ASSIGNED


@pytest.mark.parametrize('api_response', [
    ({'result': []}),
    ({'result': [{'sys_id': 'sys_id1'}, {'sys_id': 'sys_id2'}]}),
])
def test_get_modified_remote_data(requests_mock, mocker, api_response):
    """
    Given:
        - Case A: No updated records
        - Case B: 2 updated records

    When:
     - Running get-modified-remote-data

    Then:
        - Case A: Ensure no record IDs returned
        - Case B: Ensure the 2 records IDs returned
    """
    mocker.patch.object(demisto, 'debug')
    url = 'https://test.service-now.com/api/now/v2/'
    client = Client(url, 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments',
                    'incident_name')
    last_update = '2020-11-18T13:16:52.005381+02:00'
    params = {
        'sysparm_limit': '100',
        'sysparm_offset': '0',
        'sysparm_query': 'sys_updated_on>2020-11-18 11:16:52',
        'sysparm_fields': 'sys_id',
    }
    requests_mock.request(
        'GET',
        f'{url}table/ticket_type?{urlencode(params)}',
        json=api_response
    )
    result = get_modified_remote_data_command(client, {'lastUpdate': last_update})

    assert sorted(result.modified_incident_ids) == sorted([
        record.get('sys_id') for record in api_response.get('result') if 'sys_id' in record
    ])


@pytest.mark.parametrize('sys_created_on, expected', [
    (None, 'table_sys_id=id'),
    ('', 'table_sys_id=id'),
    ('2020-11-18 11:16:52', 'table_sys_id=id^sys_created_on>2020-11-18 11:16:52')
])
def test_get_ticket_attachments(mocker, sys_created_on, expected):
    """
    Given:
        - Cases A+B: sys_created_on argument was not provided
        - Case C: sys_created_on argument was provided

    When:
        - Getting a ticket attachments.

    Then:
        - Case A+B: Ensure that the query parameters do not include ^sys_created_on>
        - Case C: Ensure that the query parameters include ^sys_created_on>
    """
    client = Client("url", 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments',
                    'incident_name')
    mocker.patch.object(client, 'send_request', return_value=[])

    client.get_ticket_attachments('id', sys_created_on)
    client.send_request.assert_called_with('attachment', 'GET', params={'sysparm_query': f'{expected}'}, get_attachments=True)


@pytest.mark.parametrize('args,expected_ticket_fields', [
    ({'clear_fields': 'assigned_to,severity'}, {'assigned_to': '', 'severity': ''}),
    ({'clear_fields': 'assigned_to,severity', 'assigned_to': 'assigned@to.com'}, {'assigned_to': '', 'severity': ''}),
    ({}, {}),
])
def test_clear_fields_in_get_ticket_fields(args, expected_ticket_fields):
    if 'assigned_to' in args:
        with pytest.raises(DemistoException) as e:
            res = get_ticket_fields(args)
        assert str(e.value) == "Could not set a value for the argument 'assigned_to' and add it to the clear_fields. \
                You can either set or clear the field value."
    else:
        res = get_ticket_fields(args)
        assert res == expected_ticket_fields


def test_clear_fields_for_update_remote_system():
    """
    Given:
        - The fields from the parsed_args.data (from update_remote_system)
    When:
        - Run get_ticket_fields
    Then:
        - Validate that the ampty fields exists in the fields that returns.
    """
    parsed_args_data = {'assigned_to': '', 'category': 'Software', 'description': '', 'impact': '3 - Low',
                        'notify': '1 - Do Not Notify', 'priority': '5 - Planning', 'severity': '1 - High - Low',
                        'short_description': 'Testing 3', 'sla_due': '0001-01-01T02:22:42+02:20',
                        'state': '2 - In Progress', 'subcategory': '', 'urgency': '3 - Low',
                        'work_start': '0001-01-01T02:22:42+02:20'}

    res = get_ticket_fields(parsed_args_data)
    assert 'assigned_to' in res


def test_query_table_with_fields(mocker):
    """
    Given:
        - Fields for query table

    When:
        - Run query table command

    Then:
        - Validate the fields was sent as params in the request and sys_id appear in fields
    """

    # prepare
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments',
                    'incident_name')

    mocker.patch.object(client, 'send_request', return_value={
        "result": [
            {
                "sys_id": "test_id",
                "sys_updated_by": "test_updated_name",
                "opened_by.name": "test_opened_name"
            }
        ]})
    fields = "sys_updated_by,opened_by.name"
    fields_with_sys_id = f'{fields},sys_id'
    args = {'table_name': "alm_asset", 'fields': fields,
            'query': "display_nameCONTAINSMacBook", 'limit': 3}

    # run
    result = query_table_command(client, args)

    # validate
    assert client.send_request.call_args[1]['params']['sysparm_fields'] == fields_with_sys_id
    # validate that the '.' in the key was replaced to '_'
    assert result[1]['ServiceNow.Record(val.ID===obj.ID)'][0]['opened_by_name'] == 'test_opened_name'


def test_create_co_from_template_command(mocker):
    """
    Given:
        - template to create change request from it.

    When:
        - Using servicenow-create-co-from-template command.

    Then:
        - Validate the output is correct.
    """
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments',
                    'incident_name')

    args = {"template": "Add network switch to datacenter cabinet"}
    mocker.patch.object(client,
                        'send_request',
                        return_value=util_load_json('test_data/create_co_from_template_result.json'))
    result = ServiceNowv2.create_co_from_template_command(client, args)
    assert result.outputs_prefix == "ServiceNow.Ticket"
    assert result.outputs == {
        'Ticket(val.ID===obj.ID)': CREATED_TICKET_CONTEXT_CREATE_CO_FROM_TEMPLATE_COMMAND,
        'ServiceNow.Ticket(val.ID===obj.ID)': CREATED_TICKET_CONTEXT_CREATE_CO_FROM_TEMPLATE_COMMAND
    }
    assert result.raw_response == util_load_json('test_data/create_co_from_template_result.json')


def test_get_tasks_for_co_command(mocker):
    """
    Given:
        - id to get tasks from it.

    When:
        - Using servicenow-get-tasks-for-co command.

    Then:
        - Validate the output is correct.
    """
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'problem', 'get_attachments', 'incident_name')

    args = {"id": "a9e9c33dc61122760072455df62663d2"}
    mocker.patch.object(client,
                        'send_request',
                        return_value=util_load_json('test_data/get_tasks_for_co_command.json'))
    result = ServiceNowv2.get_tasks_for_co_command(client, args)
    assert result.outputs_prefix == "ServiceNow.Tasks"
    assert result.outputs == {
        'ServiceNow.Tasks(val.ID===obj.ID)': CREATED_TICKET_CONTEXT_GET_TASKS_FOR_CO_COMMAND
    }
    assert result.raw_response == util_load_json('test_data/get_tasks_for_co_command.json')


def test_get_ticket_attachment_entries_with_oauth_token(mocker):
    """
    The purpose of this test is to verify that it is possible to get a file attachment of a ServiceNow ticket by using
    an OAuth 2.0 client.

    Given:
        - A client with 'oauth_params' - i.e a client that is configured with an OAuth 2.0 Authorization.
        - Mock responses for 'get_ticket_attachments', 'get_access_token' and 'requests.get' functions.

    When:
        - Running the 'client.get_ticket_attachment_entries' function.

    Then:
        - Verify that the 'requests.get' function's arguments are arguments of a call with OAuth 2.0 Authorization.
    """
    # Preparations and mocking:
    client = Client("url", 'sc_server_url', 'cr_server_url', 'username', 'password', 'verify', 'fetch_time',
                    'sysparm_query', 'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments',
                    'incident_name', oauth_params={'oauth_params': ''})

    mock_res_for_get_ticket_attachments = \
        {'result': [
            {
                'file_name': 'attachment for test.txt',
                'download_link': 'https://ven03941.service-now.com/api/now/attachment/12b7ea411b15cd10042611b4bd4/file'
            }]}

    mock_res_for_get_access_token = 'access_token'

    mocker.patch.object(client, 'get_ticket_attachments', return_value=mock_res_for_get_ticket_attachments)
    mocker.patch.object(client.snow_client, 'get_access_token', return_value=mock_res_for_get_access_token)
    requests_get_mocker = mocker.patch('requests.get', return_value=None)

    # Running get_ticket_attachment_entries function:
    client.get_ticket_attachment_entries(ticket_id='id')

    # Validate Results are as expected:
    assert requests_get_mocker.call_args.kwargs.get('auth') is None, \
        "When An OAuth 2.0 client is configured the 'auth' argument shouldn't be passed to 'requests.get' function"
    assert requests_get_mocker.call_args.kwargs.get('headers').get('Authorization') == \
        f"Bearer {mock_res_for_get_access_token}", "When An OAuth 2.0 client is configured the 'Authorization'" \
        " Header argument should be passed to 'requests.get' function"


@pytest.mark.parametrize(
    'command, args, response',
    [
        (generic_api_call_command,
         {"method": "GET",
          "path": "table/sn_si_incident?sysparam_limit=1&sysparam_query=active=true^ORDERBYDESCnumber",
          "body": {},
          "headers": {},
          },
         RESPONSE_GENERIC_TICKET),
        (generic_api_call_command,
         {"method": "GET",
          "path": "/table/sn_si_incident?sysparam_limit=1&sysparam_query=active=true^ORDERBYDESCnumber",
          "body": {},
          "headers": {},
          "custom_api": "/api/custom"
          },
         RESPONSE_GENERIC_TICKET)
    ])
def test_generic_api_call_command(command, args, response, mocker):
    """test case for `generic_api_call_command`"""

    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name')

    mocker.patch.object(client, 'send_request', return_value=response)
    result = command(client, args)
    assert result.outputs == response


@pytest.mark.parametrize('file_type , expected',
                         [(EntryType.FILE, True),
                          (3, True),
                          (EntryType.IMAGE, True),
                          (EntryType.NOTE, False),
                          (15, False)])
def test_is_entry_type_mirror_supported(file_type, expected):
    """
    Given:
        - an entry file type
    When:
        - running the update_remote_system_command checking if the entry supports mirroring
    Then:
        - return True if the file entry type supports mirroring else return False
    """
    assert ServiceNowv2.is_entry_type_mirror_supported(file_type) == expected


@pytest.mark.parametrize('params, expected',
                         [({'close_ticket_multiple_options': 'None', 'close_ticket': True}, 'closed'),
                          ({'close_ticket_multiple_options': 'None', 'close_ticket': False}, None),
                          ({'close_ticket_multiple_options': 'resolved', 'close_ticket': True}, 'resolved'),
                          ({'close_ticket_multiple_options': 'resolved', 'close_ticket': False}, 'resolved'),
                          ({'close_ticket_multiple_options': 'closed', 'close_ticket': True}, 'closed'),
                          ({'close_ticket_multiple_options': 'closed', 'close_ticket': False}, 'closed')])
def test_get_closure_case(params, expected):
    """
    Given:
        - params dict with both old and new close_ticket integration params.
        - case 1: params dict with none configured new param and old param configured to True.
        - case 2: params dict with none configured new param and old param configured to False.
        - case 3: params dict with resolved configured new param and old param configured to True.
        - case 4: params dict with resolved configured new param and old param configured to False.
        - case 5: params dict with closed configured new param and old param configured to True.
        - case 6: params dict with closed configured new param and old param configured to False.
    When:
        - running get_closure_case method.
    Then:
        - Ensure the right closure method was returned.
        - case 1: Should return 'closed'
        - case 2: Should return None
        - case 3: Should return 'resolved'
        - case 4: Should return 'resolved'
        - case 5: Should return 'closed'
        - case 6: Should return 'closed'
    """
    assert get_closure_case(params) == expected


@pytest.mark.parametrize('ticket_state, ticket_close_code, server_close_custom_state, server_close_custom_code, expected_res',
                         [('1', 'default close code', '', '', 'Other'),
                          ('7', 'default close code', '', '', 'Resolved'),
                          ('6', 'default close code', '', '', 'Resolved'),
                          ('10', 'default close code', '10=Test', '', 'Test'),
                          ('10', 'default close code', '10=Test,11=Test2', '', 'Test'),
                          # If builtin state was override by custom.
                          ('6', 'default close code', '6=Test', '', 'Test'),
                          ('corrupt_state', 'default close code', '', '', 'Other'),
                          ('corrupt_state', 'default close code', 'custom_state=Test', '', 'Other'),
                          ('6', 'default close code', 'custom_state=Test', '', 'Resolved'),
                          # custom close_code overwrites custom sate.
                          ('10', 'custom close code', '10=Test,11=Test2', 'custom close code=Custom,90=90 Custom', 'Custom'),
                          ('10', '90', '10=Test,11=Test2', '80=Custom, 90=90 Custom', '90 Custom'),
                          ])
def test_converts_close_code_or_state_to_close_reason(ticket_state, ticket_close_code, server_close_custom_state,
                                                      server_close_custom_code, expected_res):
    """
    Given:
        - ticket_state: The state for the closed service now ticket
        - ticket_close_code: The Service now ticket close code
        - server_close_custom_state: The custom state for the closed service now ticket
        - server_close_custom_code: The custom close code for the closed service now ticket
    When:
        - closing a ticket on service now
    Then:
        - return the matching XSOAR incident state.
    """
    assert converts_close_code_or_state_to_close_reason(ticket_state, ticket_close_code, server_close_custom_state,
                                                        server_close_custom_code) == expected_res


def ticket_fields_mocker(*args, **kwargs):
    state = '88' if kwargs.get('ticket_type') == 'incident' else '90'
    fields = {'close_notes': 'This is closed', 'closed_at': '2020-10-29T13:19:07.345995+02:00', 'impact': '3',
              'priority': '4', 'resolved_at': '2020-10-29T13:19:07.345995+02:00', 'severity': '1 - Low',
              'short_description': 'Post parcel', 'sla_due': '0001-01-01T00:00:00Z', 'urgency': '3', 'state': state,
              'work_start': '0001-01-01T00:00:00Z'}
    assert fields == args[0]
    return fields


@pytest.mark.parametrize('file_name , expected',
                         [('123.png', 'image/png'),
                          ('123.gif', 'image/gif'),
                          ('123.jpeg', 'image/jpeg'),
                          ('123.pdf', 'application/pdf'),
                          ('123', '*/*')])
def test_upload_file_types(file_name, expected):
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url='cr_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    get_attachments=False, incident_name='description', ticket_type='incident')
    assert client.get_content_type(file_name) == expected


@pytest.mark.parametrize('ticket_type, ticket_state, close_custom_state, result_close_state, update_call_count',
                         [
                             # case 1 - SIR ticket closed by custom state
                             ('sn_si_incident', '16', '90', '90', 1),
                             # case 2 - custom state doesn't exist, closed by default state code - '3'
                             ('sn_si_incident', '16', '90', '3', 2),
                             # case 3 - ticket closed by custom state
                             ('incident', '1', '88', '88', 1),
                             # case 4 - custom state doesn't exist, closed by default state code - '7'
                             ('incident', '1', '88', '7', 2),
                         ], ids=['case - 1', 'case - 2', 'case - 3', 'case - 4'])
def test_update_remote_data_custom_state(mocker, ticket_type, ticket_state, close_custom_state, result_close_state,
                                         update_call_count):
    """
    Given:
    -  ServiceNow client
    -  ServiceNow ticket of type sn_si_incident
    -  ServiceNow ticket of type incident
    -  close_custom_state exist/not exist in ServiceNow
    When
        - running update_remote_system_command.
    Then
        - The state is changed accordingly
    """
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url='cr_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type=ticket_type, get_attachments=False, incident_name='description')
    params = {'ticket_type': ticket_type, 'close_ticket_multiple_options': 'None', 'close_ticket': True,
              'close_custom_state': close_custom_state}

    TICKET_FIELDS['state'] = ticket_state
    args = {'remoteId': '1234', 'data': TICKET_FIELDS, 'entries': [], 'incidentChanged': True, 'delta': {},
            'status': 2}

    def update_ticket_mocker(*args):
        # Represents only the response of the last call to client.update
        # In case the custom state doesn't exist -
        # in the first call will return the ticket's state as before (in case2 - '16', case4 - '1')
        return {'result': {'short_description': 'Post parcel', 'close_notes': 'This is closed',
                           'closed_at': '2020-10-29T13:19:07.345995+02:00', 'impact': '3', 'priority': '4',
                           'resolved_at': '2020-10-29T13:19:07.345995+02:00', 'severity': '1 - High - Low',
                           'sla_due': '0001-01-01T00:00:00Z', 'state': result_close_state, 'urgency': '3',
                           'work_start': '0001-01-01T00:00:00Z'}}

    mocker.patch('ServiceNowv2.get_ticket_fields', side_effect=ticket_fields_mocker)
    mocker_update = mocker.patch.object(client, 'update', side_effect=update_ticket_mocker)
    update_remote_system_command(client, args, params)
    # assert the state argument in the last call to client.update
    assert mocker_update.call_args[0][2]['state'] == result_close_state
    assert mocker_update.call_count == update_call_count


def test_update_remote_data_upload_file_exception(mocker):
    """
    Given:
        -  ServiceNow client
        -  Two file entries to sent from XSOAR which one of them is invalid.
    When
        - running update_remote_system_command.
    Then
        - The invalid entry raised an exception and function has continued.
    """
    client = Client(server_url='https://server_url.com/', sc_server_url='sc_server_url',
                    cr_server_url='cr_server_url', username='username',
                    password='password', verify=False, fetch_time='fetch_time',
                    sysparm_query='sysparm_query', sysparm_limit=10, timestamp_field='opened_at',
                    ticket_type='incident', get_attachments=False, incident_name='description')
    params = {}
    args = {'remoteId': '1234', 'data': {}, 'entries': [MIRROR_ENTRIES[0], MIRROR_ENTRIES[0]], 'incidentChanged': True,
            'delta': {}, 'status': 2}

    def upload_file_mock(*args):
        raise Exception("ERROR!!!")

    def add_comment_mock(*args):
        assert "An attempt to mirror a file from Cortex XSOAR was failed." in args[3]

    mocker.patch.object(client, 'update', side_effect=update_ticket)
    mocker.patch.object(client, 'upload_file', side_effect=upload_file_mock)
    mocker.patch.object(client, 'add_comment', side_effect=add_comment_mock)

    demisto_mocker = mocker.patch.object(demisto, 'error')
    res = update_remote_system_command(client, args, params)

    assert demisto_mocker.call_args[0][0] == "An attempt to mirror a file has failed. entry_id=entry-id, " \
                                             "file_name='test'\nERROR!!!"
    assert res == '1234'


@pytest.mark.parametrize('mock_json, expected_results',
                         [
                             ({'error': 'invalid client.'}, 'ServiceNow Error: invalid client.'),
                             ({'error': {'message': 'invalid client', 'detail': 'the client you have entered is invalid.'}},
                              'ServiceNow Error: invalid client, details: the client you have entered is invalid.')
                         ])
def test_send_request_with_str_error_response(mocker, mock_json, expected_results):
    """
    Given:
     - a client and a mock response.
     - case 1: a mock response where the error field is a string.
     - case 2: a mock response where the error field is a dict.

    When:
     - Running send_request function.

    Then:
     - Verify that the function extracted the data from the response without problems and the expected exception is raised.
     - case 1: Shouldn't attempt to extract inner fields from the error field, only present the error value.
     - case 2: Should attempt to extract inner fields from the error field, present the parsed extracted error values.
    """
    client = Client('server_url', 'sc_server_url', 'cr_server_url', 'username', 'password',
                    'verify', 'fetch_time', 'sysparm_query', 'sysparm_limit', 'timestamp_field',
                    'ticket_type', 'get_attachments', 'incident_name', display_date_format='yyyy-MM-dd')

    class MockResponse:
        def __init__(self, mock_json):
            self.text = 'some text'
            self.json_data = mock_json
            self.status_code = 400

        def json(self):
            return self.json_data
    mocker.patch.object(requests, 'request', return_value=MockResponse(mock_json))
    with pytest.raises(Exception) as e:
        client.send_request(path='table')
    assert str(e.value) == expected_results


@pytest.mark.parametrize('ticket, expected_ticket',
                         [
                             ({}, {}),
                             ({"assigned_to": ""}, {"assigned_to": ""}),
                             ({"assigned_to": {'link': 'https://test.service-now.com/api/now/table/sys_user/oscar@example.com',
                                               'value': 'oscar@example.com'}}, {'assigned_to': 'oscar@example.com'})
                         ])
def test_parse_dict_ticket_fields_empty_ticket(ticket, expected_ticket):
    """
    Given:
     - a ticket
     - case 1: Ticket is completely empty (obtained from the case where last_update > ticket_last_update).
     - case 2: Ticket contains assigned_to field with an empty string as a value.
     - case 3: Ticket contains assigned_to field with a user dict as a value.

    When:
     - Running parse_dict_ticket_fields function.

    Then:
     - Verify that the ticket fields were updated correctly.
     - case 1: Shouldn't add the assigned_to field to the obtained ticket.
     - case 2: Should add assigned_to field with an empty string as a value.
     - case 3: Should add assigned_to field with the user email as a value.
    """
    class Client:
        def get(self, table, value, no_record_found_res):
            return USER_RESPONSE
    parse_dict_ticket_fields(Client(), ticket)  # type: ignore
    assert ticket == expected_ticket


def test_format_incidents_response_with_display_values_with_no_incidents():
    """
    Given:
        No incidents
    When:
        Calling format_incidents_response_with_display_values
    Then:
        Returns empty list
    """
    incidents_res = []
    result = format_incidents_response_with_display_values(incidents_res)

    assert result == []


def test_format_incidents_response_with_display_values_with_incidents():
    """
    Given:
        Incidents response containing opened_by, sys_domain, assignment_group and other fields
    When:
        Calling format_incidents_response_with_display_values
    Then:
        Returns formatted incidents with display_value
    """
    incidents_res = RESPONSE_FETCH_USE_DISPLAY_VALUE["result"]
    result = format_incidents_response_with_display_values(incidents_res)

    assert len(result) == 2
    assert result[0]["sys_updated_on"] == "2024-02-29 13:09:46"
    assert result[0]["opened_at"] == "2024-02-29 13:08:46"
    assert result[0]["opened_by"] == incidents_res[0]["opened_by"]
    assert result[0]["sys_domain"] == incidents_res[0]["sys_domain"]
    assert result[0]["assignment_group"] == incidents_res[0]["assignment_group"]

    assert result[1]["sys_updated_on"] == "2024-02-29 11:08:44"
    assert result[1]["opened_at"] == "2024-02-29 11:07:48"
    assert result[1]["opened_by"] == incidents_res[1]["opened_by"]
    assert result[1]["sys_domain"] == incidents_res[1]["sys_domain"]
    assert result[1]["assignment_group"] == ""


@pytest.mark.parametrize("input_string, expected", [
    ("2023-02-15 10:30:45", True),
    ("invalid", False),
    ("15.02.2023 10:30:45", False),
    ("a2023-02-15 10:30:45", False),
    ("2023-02-15 10:30:45a", False),
    ("2023-02-15 10:30:45 a", False),
])
def test_is_time_field(input_string, expected):
    """
    Given:
        Input strings of varying validity
    When:
        is_time_field is called on those strings
    Then:
        It should return True if string contains valid datetime, False otherwise
    """
    assert is_time_field(input_string) is expected


def test_get_attachment_command_success():
    client = MagicMock()
    args = {'sys_id': '12345'}
    mock_attachments = [
        {'file_name': 'file1.txt', 'content': 'file1 content'},
        {'file_name': 'file2.txt', 'content': 'file2 content'}
    ]
    client.get_ticket_attachment_entries = MagicMock(return_value=mock_attachments)
    result = get_attachment_command(client, args)
    client.get_ticket_attachment_entries.assert_called_once_with('12345')
    assert isinstance(result, list)
    assert isinstance(result[0], CommandResults)
    assert result[0].readable_output == 'Successfully retrieved attachments for ticket with sys id 12345.'
    assert result[1] == mock_attachments


def test_get_attachment_command_missing_sys_id():
    client = MagicMock()
    args = {'sys_id': '12345'}
    mock_attachments = []
    client.get_ticket_attachment_entries = MagicMock(return_value=mock_attachments)
    result = get_attachment_command(client, args)
    client.get_ticket_attachment_entries.assert_called_once_with('12345')
    assert isinstance(result, CommandResults)
    assert result.readable_output == 'Ticket with sys id 12345 has no attachments to retrieve.'


def test_incident_id_in_last_fetched_updates_correctly(mocker):
    """
    Given:
        Ticket ID to remove
    When:
        is_new_incident is called
    Then:
        It should remove the id without modifying the existing integration context keys
    """
    mocker.patch.object(ServiceNowv2, 'get_integration_context',
                        return_value={"access_token": "token", "last_fetched_incident_ids": ['ABC123', 'XYZ789']})
    res = mocker.patch.object(ServiceNowv2, 'set_integration_context')

    # Executing the function with the incident id to be checked
    is_new_incident("XYZ789")

    # Setup verification context with wrapper to cover the whole integration context if necessary
    expected_context = {"access_token": "token", "last_fetched_incident_ids": ['ABC123']}

    # Verifying that set_integration_context was called with the correct new context
    res.assert_called_once_with(expected_context)


def test_incident_id_not_in_last_fetched(mocker):
    """
    Given:
        Ticket ID that should not be removed
    When:
        is_new_incident is called
    Then:
        It should not modify the integration context
    """
    # Mock the get_integration_context to return some incident IDs which does not include the tested ID
    mocker.patch.object(ServiceNowv2, 'get_integration_context',
                        return_value={"access_token": "token", "last_fetched_incident_ids": ['ABC123', 'XYZ789']})
    # Mock the set_integration_context to check it is not called
    res = mocker.patch.object(ServiceNowv2, 'set_integration_context')

    # Executing the function with an incident id that is not in the context's list
    is_new_incident("DEF456")

    # Assert that set_integration_context was never called because no incident ID was removed
    res.assert_not_called()
