import pytest
from MicrosoftGraphGroups import parse_outputs, camel_case_to_readable, MsGraphClient, list_groups_command, \
    get_group_command, create_group_command, list_members_command, demisto, main
from test_data.response_constants import RESPONSE_LIST_GROUPS, RESPONSE_GET_GROUP, RESPONSE_CREATE_GROUP, \
    RESPONSE_LIST_MEMBERS_UNDER_100, RESPONSE_LIST_MEMBERS_ABOVE_100
from test_data.result_constants import EXPECTED_LIST_GROUPS, EXPECTED_GET_GROUP, EXPECTED_CREATE_GROUP, \
    EXPECTED_LIST_MEMBERS


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
     RESPONSE_CREATE_GROUP, EXPECTED_CREATE_GROUP)
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    client = MsGraphClient(base_url='https://graph.microsoft.com/v1.0', tenant_id='tenant-id',
                           auth_id='auth_and_token_url', enc_key='enc_key', app_name='ms-graph-groups',
                           verify='use_ssl', proxy='proxies', self_deployed='self_deployed')
    mocker.patch.object(client.ms_client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command


@pytest.mark.parametrize('args, response, expected_result', [
    ({'group_id': 'under100'}, RESPONSE_LIST_MEMBERS_UNDER_100, EXPECTED_LIST_MEMBERS),
    ({'group_id': 'above100'}, RESPONSE_LIST_MEMBERS_ABOVE_100, EXPECTED_LIST_MEMBERS)
])  # noqa: E124
def test_list_members_command(args, response, expected_result, mocker):
    """
    Given:
      - a group ID with less than 100 members.
      - a group ID with more than 100 members.
    When:
      - calling list_members_command.
    Then:
      - ensure the command results are as expected (Members are found and MembersNextLink is shown when there are more
      than 100 members.
    """
    client = MsGraphClient(base_url='https://graph.microsoft.com/v1.0', tenant_id='tenant-id',
                           auth_id='auth_and_token_url', enc_key='enc_key', app_name='ms-graph-groups',
                           verify='use_ssl', proxy='proxies', self_deployed='self_deployed')
    mocker.patch.object(client.ms_client, 'http_request', return_value=response)
    mocker.patch.object(demisto, 'dt', return_value=RESPONSE_GET_GROUP)
    result = list_members_command(client, args)
    if args.get('group_id') == 'under100':
        assert 'MembersNextLink' not in result[1]['MSGraphGroups(val.ID === obj.ID)']
    else:  # above 100
        assert 'MembersNextLink' in result[1]['MSGraphGroups(val.ID === obj.ID)']

    assert expected_result == result[1]['MSGraphGroups(val.ID === obj.ID)'][
        'Members']  # entry context is found in the 2nd place in the result of the command


@pytest.mark.parametrize('params, expected_result', [
    ({'_tenant_id': '_tenant_id', '_auth_id': '_auth_id'}, 'Key must be provided.'),
    ({'_tenant_id': '_tenant_id', 'credentials': {'password': '1234'}}, 'Authentication ID must be provided.'),
    ({'credentials': {'password': '1234'}, '_auth_id': '_auth_id'}, 'Token must be provided.')
])
def test_params(mocker, params, expected_result):
    """
    Given:
      - Configuration parameters
    When:
      - One of the required parameters are missed.
    Then:
      - Ensure the exception message as expected.
    """

    mocker.patch.object(demisto, 'params', return_value=params)

    with pytest.raises(Exception) as e:
        main()

    assert expected_result in str(e.value)
