import pytest
from ServiceNowv2 import get_server_url, get_ticket_context, get_ticket_human_readable, \
    generate_body, split_fields, Client, update_ticket_command, create_ticket_command, delete_ticket_command, \
    query_tickets_command, add_link_command, add_comment_command
from test_data.response_constants import RESPONSE_TICKET, RESPONSE_MULTIPLE_TICKET, RESPONSE_UPDATE_TICKET, \
    RESPONSE_CREATE_TICKET, RESPONSE_QUERY_TICKETS, RESPONSE_ADD_LINK, RESPONSE_ADD_COMMENT
from test_data.result_constants import EXPECTED_TICKET_CONTEXT, EXPECTED_MULTIPLE_TICKET_CONTEXT, \
    EXPECTED_TICKET_HR, EXPECTED_MULTIPLE_TICKET_HR, EXPECTED_UPDATE_TICKET, EXPECTED_CREATE_TICKET, \
    EXPECTED_QUERY_TICKETS, EXPECTED_ADD_LINK_HR, EXPECTED_ADD_COMMENT_HR


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
    expected_dict_fields == split_fields('a=b;c=d')


@pytest.mark.parametrize('command, args, response, expected_result', [
    (update_ticket_command, {'id': '1234', 'impact': '3 - Low'}, RESPONSE_UPDATE_TICKET, EXPECTED_UPDATE_TICKET),
    (create_ticket_command, {'active': 'true', 'severity': "2 - Medium", 'description': "creating a test ticket",
                             'sla_due': "2020-10-10 10:10:11"}, RESPONSE_CREATE_TICKET, EXPECTED_CREATE_TICKET),
    (query_tickets_command, {'limit': "3", 'query': "impact<2^short_descriptionISNOTEMPTY", 'ticket_type': "incident"},
     RESPONSE_QUERY_TICKETS, EXPECTED_QUERY_TICKETS)
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
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
    client = Client('server_url', 'username', 'password', 'verify', 'proxy', 'fetch_time', 'sysparm_query',
                    'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments')
    mocker.patch.object(client, 'send_request', return_value=response)
    result = command(client, args)
    # print('\n')
    # print(str(expected_result))
    # print('\n')
    # print(str(result[1]))
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command


@pytest.mark.parametrize('command, args, response, expected_hr', [
    (delete_ticket_command, {'id': '1234'}, {}, 'Ticket with ID 1234 was successfully deleted.'),
    (add_link_command, {'id': '1234', 'link': "http://www.demisto.com", 'text': 'demsito_link'}, RESPONSE_ADD_LINK,
     EXPECTED_ADD_LINK_HR),
    (add_comment_command, {'id': "1234", 'comment': "Nice work!"}, RESPONSE_ADD_COMMENT, EXPECTED_ADD_COMMENT_HR)
])  # noqa: E124
def test_no_ec_commands(command, args, response, expected_hr, mocker):
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
    client = Client('server_url', 'username', 'password', 'verify', 'proxy', 'fetch_time', 'sysparm_query',
                    'sysparm_limit', 'timestamp_field', 'ticket_type', 'get_attachments')
    mocker.patch.object(client, 'send_request', return_value=response)
    result = command(client, args)
    assert expected_hr in result[0]  # HR is found in the 1st place in the result of the command
