import pytest
from ServiceDeskPlus import Client, create_request_command, update_request_command, list_requests_command, \
    linked_request_command
from test_data.response_constants import RESPONSE_CREATE_REQUEST, RESPONSE_UPDATE_REQUEST, RESPONSE_LIST_SINGLE_REQUEST, \
    RESPONSE_LIST_MULTIPLE_REQUESTS, RESPONSE_LINKED_REQUEST
from test_data.result_constants import EXPECTED_CREATE_REQUEST, EXPECTED_UPDATE_REQUEST, EXPECTED_LIST_SINGLE_REQUEST, \
    EXPECTED_LIST_MULTIPLE_REQUESTS, EXPECTED_LINKED_REQUEST


@pytest.mark.parametrize('command, args, response, expected_result',[
    (create_request_command, {'subject': 'Create request test', 'mode': 'E-Mail', 'requester': 'First Last',
                              'level': 'Tier 1', 'impact': 'Affects Group', 'priority': 'High', 'status': 'On Hold',
                              'request_type': 'Incident', 'description': 'The description of the request',
                              'urgency': 'Normal', 'group': 'Network'}, RESPONSE_CREATE_REQUEST,
     EXPECTED_CREATE_REQUEST),
    (update_request_command, {'request_id': '123640000000240013', 'description': 'Update the description',
                              'impact': 'Affects Business'}, RESPONSE_UPDATE_REQUEST, EXPECTED_UPDATE_REQUEST),
    (list_requests_command, {'request_id': '123640000000240013'}, RESPONSE_LIST_SINGLE_REQUEST,
     EXPECTED_LIST_SINGLE_REQUEST),
    (list_requests_command, {'row_count': '3'}, RESPONSE_LIST_MULTIPLE_REQUESTS, EXPECTED_LIST_MULTIPLE_REQUESTS),
    (linked_request_command, {'request_id': '123640000000246001'}, RESPONSE_LINKED_REQUEST, EXPECTED_LINKED_REQUEST)
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
    mocker.patch('ServiceDeskPlus.Client.update_access_token')
    client = Client('server_url', 'use_ssl', 'use_proxy', 'client_id', 'client_secret', 'refresh_token')
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]


# # test requests-list-command:
# @pytest.mark.parametrize('command, args, response, expected_result',[
#     (list_requests_command, {'request_id': '123640000000240013'}, RESPONSE_LIST_SINGLE_REQUEST,
#      EXPECTED_LIST_SINGLE_REQUEST)
#
