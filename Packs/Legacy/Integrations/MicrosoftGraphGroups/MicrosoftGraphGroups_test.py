import pytest
from MicrosoftGraphGroups import epoch_seconds, parse_outputs, camel_case_to_readable, Client, list_groups_command,\
    get_group_command, create_group_command
from test_data.response_constants import RESPONSE_LIST_GROUPS, RESPONSE_GET_GROUP, RESPONSE_CREATE_GROUP
from test_data.result_constants import EXPECTED_LIST_GROUPS, EXPECTED_GET_GROUP, EXPECTED_CREATE_GROUP


def test_epoch_seconds():
    integer = epoch_seconds()
    assert isinstance(integer, int)


def test_camel_case_to_readable():
    assert camel_case_to_readable('id') == 'ID'
    assert camel_case_to_readable('createdDateTime') == 'Created Date Time'


def test_parse_outputs():
    outputs = {
        '@odata.context': 'a',
        'classification': 'myclass',
        'securityEnabled': 'true'
    }

    parsed_readable, parsed_outputs = parse_outputs(outputs)

    expected_readable = {
        'Classification': 'myclass',
        'Security Enabled': 'true'
    }
    expected_outputs = {
        'Classification': 'myclass',
        'SecurityEnabled': 'true'
    }
    assert parsed_readable == expected_readable
    assert parsed_outputs == expected_outputs


@pytest.mark.parametrize('command, args, response, expected_result', [
    (list_groups_command, {}, RESPONSE_LIST_GROUPS, EXPECTED_LIST_GROUPS),
    (get_group_command, {'group_id': '123'}, RESPONSE_GET_GROUP, EXPECTED_GET_GROUP),
    (create_group_command, {'group_id': '123', 'mail_nickname': 'nick', 'security_enabled': True},
     RESPONSE_CREATE_GROUP, EXPECTED_CREATE_GROUP),
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    client = Client('https://graph.microsoft.com/v1.0', 'tenant-id', 'auth_and_token_url', 'auth_id',
                    'token_retrieval_url', 'enc_key', 'use_ssl', 'proxies')
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
