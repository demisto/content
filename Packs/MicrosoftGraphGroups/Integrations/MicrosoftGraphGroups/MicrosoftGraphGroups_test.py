import pytest
from MicrosoftGraphGroups import parse_outputs, camel_case_to_readable, MsGraphClient, list_groups_command, \
    get_group_command, create_group_command, list_members_command, add_member_command, delete_group_command, \
    remove_member_command, demisto, main
from test_data.response_constants import RESPONSE_LIST_GROUPS, RESPONSE_GET_GROUP, RESPONSE_CREATE_GROUP, \
    RESPONSE_LIST_MEMBERS_UNDER_100, RESPONSE_LIST_MEMBERS_ABOVE_100
from test_data.result_constants import EXPECTED_LIST_GROUPS, EXPECTED_GET_GROUP, EXPECTED_CREATE_GROUP, \
    EXPECTED_LIST_MEMBERS
from MicrosoftApiModule import NotFoundError, MicrosoftClient


def create_ms_graph_client():
    return MsGraphClient(base_url='https://graph.microsoft.com/v1.0', tenant_id='tenant-id',
                         auth_id='auth_and_token_url', enc_key='enc_key', app_name='ms-graph-groups',
                         verify='use_ssl', proxy='proxies', self_deployed='self_deployed', handle_error=False)


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
    client = create_ms_graph_client()
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
    client = create_ms_graph_client()
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


TEST_SUPPRESS_ERRORS = [
    (delete_group_command, 'delete_group', NotFoundError('404'), {'group_id': '123456789'},
     '#### Group id -> 123456789 does not exist'),
    (list_members_command, 'list_members', NotFoundError('404'), {'group_id': '123456789'},
     '#### Group id -> 123456789 does not exist'),
    (add_member_command, 'add_member', NotFoundError('404'), {'group_id': '123456789'},
     '#### Group id -> 123456789 does not exist'),
    (remove_member_command, 'remove_member', NotFoundError('404'), {'group_id': '123456789'},
     '#### Group id -> 123456789 does not exist')
]


@pytest.mark.parametrize('fun, mock_fun, mock_value, args, expected_result',
                         TEST_SUPPRESS_ERRORS)
def test_suppress_errors(mocker, fun, mock_fun, mock_value, args, expected_result):

    client = MsGraphClient(base_url='https://graph.microsoft.com/v1.0', tenant_id='tenant-id',
                           auth_id='auth_and_token_url', enc_key='enc_key', app_name='ms-graph-groups',
                           verify='use_ssl', proxy='proxies', self_deployed='self_deployed', handle_error=True)
    mocker.patch.object(client, mock_fun, side_effect=mock_value)
    results, _, _ = fun(client, args)
    assert results == expected_result


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """
    from MicrosoftGraphGroups import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import demistomock as demisto
    import re

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f'^{Resources.graph}.*'), json={})

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'url': Resources.graph
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in demisto.results.call_args[0][0]['Contents']
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


def test_list_members(mocker):
    """
    Given:
      - args with count=true.
    When:
      - calling list_members.
    Then:
      - ensure the command called the http_request with count=true in the params dict,
      and 'ConsistencyLevel'='eventual' in the headers dicts.
    """
    client = create_ms_graph_client()
    mocker.patch.object(demisto, 'args', return_value={'count': 'true'})
    http_request = mocker.patch.object(MicrosoftClient, 'http_request')
    client.list_members(group_id='123')
    http_request.assert_called_with(method='GET', url_suffix='groups/123/members',
                                    params={'$top': None, '$count': 'true'}, headers={'ConsistencyLevel': 'eventual'})
