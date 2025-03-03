import json
from MattermostV2 import (get_team_command, list_channels_command, create_channel_command, add_channel_member_command,
                          remove_channel_member_command, list_users_command, close_channel_command, send_file_command,
                          get_channel_id_to_send_notif, event_handler, handle_text_received_from_mm, get_channel_id_from_context,
                          extract_entitlement, answer_question, handle_posts, create_incidents, get_war_room_url,
                          mirror_investigation, send_notification, INCIDENT_NOTIFICATION_CHANNEL,
                          list_private_channels_for_user_command, list_groups_command, list_group_members_command,
                          add_group_member_command, remove_group_member_command, set_channel_role_command)
import pytest
import demistomock as demisto
from unittest.mock import patch
from freezegun import freeze_time


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def http_mock(method: str, url_suffix: str = "", full_url: str = "", params: dict = {},
              data: dict = {}, files: dict = {}, json_data: dict = {}, headers: dict = {}):

    if 'bot_access_token' in headers.get('Authorization', ''):
        if url_suffix == '/api/v4/users/me':
            return util_load_json('test_data/get_bot_response.json')
        if url_suffix == '/api/v4/posts':
            return util_load_json("test_data/create_post_response.json")

    if url_suffix == "/api/v4/teams/name/team_name":
        return util_load_json("test_data/get_team_response.json")
    elif url_suffix == '/api/v4/teams/team_id/channels' or url_suffix == '/api/v4/teams/team_id/channels/private':
        return util_load_json("test_data/list_channels_response.json")
    elif url_suffix == '/api/v4/users/user_id/teams/team_id/channels/members':
        return util_load_json("test_data/list_channels_response.json")
    elif url_suffix == '/api/v4/channels':
        return util_load_json("test_data/create_channel_response.json")
    elif url_suffix == '/api/v4/users':
        return util_load_json("test_data/list_users_response.json")
    elif url_suffix == '/api/v4/files':
        return util_load_json("test_data/send_file_response.json")
    elif (url_suffix == '/api/v4/users/email/user_email' or url_suffix == '/api/v4/users/username/username'
          or url_suffix == '/api/v4/users/me' or url_suffix == '/api/v4/users/user_id'):
        return util_load_json("test_data/list_users_response.json")[0]
    elif url_suffix == '/api/v4/channels/direct':
        channel = util_load_json("test_data/create_channel_response.json")
        channel["type"] = 'D'
        return channel
    elif url_suffix == '/api/v4/channels/group':
        channel = util_load_json("test_data/create_channel_response.json")
        channel["type"] = 'G'
        return channel
    elif url_suffix == '/api/v4/groups':
        return util_load_json("test_data/list_groups_response.json")
    else:
        return {}


@pytest.fixture(autouse=True)
def ws_client(mocker):
    from MattermostV2 import WebSocketClient

    return WebSocketClient(
        base_url='mock url',
        verify=True,
        proxy=False,
        token='personal_access_token',
    )


@pytest.fixture(autouse=True)
def http_client(mocker):
    from MattermostV2 import HTTPClient

    headers = {"Authorization": "Token mock"}
    http_client = HTTPClient(
        base_url='mock url',
        headers=headers,
        verify=True,
        proxy=False,
        bot_access_token='bot_access_token',
        personal_access_token='personal_access_token',
        team_name='team_name',
        notification_channel='notification_channel',
    )
    mocker.patch.object(http_client, "_http_request", side_effect=http_mock)
    return http_client


def test_get_team_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running get_team_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name'}
    results = get_team_command(http_client, args)
    assert results.outputs.get('name', '') == 'team_name'


def test_list_channels_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running list_channels_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'include_private_channels': True}
    results = list_channels_command(http_client, args)
    assert results.outputs[0].get('name') == 'name'
    assert len(results.outputs) == 2


def test_list_private_channels_for_user_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running list_private_channels_for_user_command with a team name and user id.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'user_id': 'user_id'}
    results = list_private_channels_for_user_command(http_client, args)
    assert results.outputs[0].get('name') == 'name'
    assert len(results.outputs) == 2


def test_create_channel_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running create_channel_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'name': 'channel_name',
            'display_name': 'display_name',
            'type': 'Public',
            'purpose': 'purpose',
            'header': 'header', }
    results = create_channel_command(http_client, args)
    assert results.outputs.get('name') == 'name'


def test_add_channel_member_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running add_channel_member_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_name': 'channel_name',
            'user_id': 'user_id', }
    results = add_channel_member_command(http_client, args)
    assert 'The member username was added to the channel successfully' in results.readable_output


def test_remove_channel_member_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running remove_channel_member_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_name': 'channel_name',
            'user_id': 'user_id', }
    results = remove_channel_member_command(http_client, args)
    assert 'The member username was removed from the channel successfully.' in results.readable_output


def test_list_users_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running list_users_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_id': 'channel_id', }
    results = list_users_command(http_client, args)
    assert results.outputs[0].get('first_name') == 'first_name'


def test_close_channel_command_no_mirror(http_client):
    """
    Given: A mock MatterMost client.
    When: Running close_channel_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel': 'channel_name', }
    results = close_channel_command(http_client, args)
    assert 'The channel channel_name was delete successfully.' in results.readable_output


def test_close_channel_command_mirror(http_client, mocker):
    """
    Given: A mock MatterMost client.
    When: Running close_channel_command with a team name.
    Then: Ensure we get the result, and  was called only once with the first mirror
    """
    args = {'team_name': 'team_name',
            'channel': 'channel_name', }

    import MattermostV2
    MattermostV2.CACHE_EXPIRY = False
    MattermostV2.CACHED_INTEGRATION_CONTEXT = ''
    mock_integration_context = {
        'mirrors': json.dumps([
            {'channel_name': 'Channel1', 'team_id': 'team_id', 'channel_id': 'channel_id', 'mirrored': False,
             'investigation_id': 'Incident123', 'mirror_direction': 'toDemisto', 'auto_close': True, 'mirror_type': 'all'},
            {'channel_name': 'Channel2', 'team_id': 'team_id', 'channel_id': 'channel_id_different_channel', 'mirrored': True,
             'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True, 'mirror_type': 'chat'},
        ])
    }
    mocker.patch('MattermostV2.get_integration_context', return_value=mock_integration_context)
    mocker.patch.object(demisto, 'investigation', return_value={'id': 'Incident123'})
    mocker.patch.object(demisto, 'mirrorInvestigation')
    results = close_channel_command(http_client, args)

    demisto.mirrorInvestigation.assert_called_once_with('Incident123', 'none:toDemisto', True)
    assert 'The channel channel_name was delete successfully.' in results.readable_output


def test_send_file_command(http_client, mocker):
    """
    Given: A mock MatterMost client.
    When: Running send_file_command with a team name.
    Then: Ensure we get the result.
    """
    expected_file_info = {
        'name': 'test_file.txt',
        'path': '/path/to/test_file.txt'
    }
    mocker.patch('MattermostV2.demisto.getFilePath', return_value=expected_file_info)
    mocker.patch.object(http_client, 'send_file_request', return_value=util_load_json("test_data/send_file_response.json"))

    args = {'team_name': 'team_name',
            'channel': 'channel_name', }
    send_file_command(http_client, args)


def test_get_channel_id_to_send_notif(http_client, mocker):
    """
    Given: A mock MatterMost client.
    When: Running get_channel_id_to_send_notif.
    Then: Ensure we get the result.
    """
    results = get_channel_id_to_send_notif(http_client, 'username', 'channel_name', 'investigation_id')
    assert results == 'id'


def test_get_channel_id_from_context(mocker):
    """
    Given: A mock MatterMost client.
    When: Running get_channel_id_from_context.
    Then: Ensure we get the result.
    """
    import MattermostV2
    MattermostV2.CACHE_EXPIRY = False
    MattermostV2.CACHED_INTEGRATION_CONTEXT = ''
    mock_integration_context = {
        'mirrors': json.dumps([
            {'channel_name': 'Channel1', 'team_id': 'team_id', 'channel_id': 'ID1',
             'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True},
            {'channel_name': 'Channel2', 'team_id': 'team_id', 'channel_id': 'ID2',
             'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True},
        ])
    }
    mocker.patch('MattermostV2.get_integration_context', return_value=mock_integration_context)
    results = get_channel_id_from_context('Channel1', 'Incident123')
    assert results


def test_save_entitlement():
    """
    Given:
    - arguments.
    When:
    - Calling the save_entitlement function.
    Then:
    - Validate that the mocked functions were called with the expected arguments
    """
    entitlement = "Test Entitlement"
    message_id = "123"
    reply = "Test Reply"
    expiry = "2023-09-09"
    default_response = "Default Response"
    to_id = "user@example.com"
    OBJECTS_TO_KEYS = {
        'mirrors': 'investigation_id',
        'messages': 'entitlement',
    }

    with patch('MattermostV2.get_integration_context') as mock_get_integration_context, \
            patch('MattermostV2.set_to_integration_context_with_retries') as mock_set_integration_context:

        mock_get_integration_context.return_value = {'messages': []}
        fixed_timestamp = '2023-09-09T20:08:50Z'

        with freeze_time(fixed_timestamp):
            from MattermostV2 import save_entitlement
            save_entitlement(entitlement, message_id, reply, expiry, default_response, to_id)

        expected_data = {
            'messages': [
                {
                    'root_id': message_id,
                    'entitlement': entitlement,
                    'reply': reply,
                    'expiry': expiry,
                    'sent': fixed_timestamp,
                    'default_response': default_response,
                    'to_id': to_id
                }
            ]
        }

        mock_get_integration_context.assert_called_once_with()
        mock_set_integration_context.assert_called_once_with(expected_data, OBJECTS_TO_KEYS)


@pytest.mark.parametrize("entitlement, expected_result", [
    ("guid123@incident456|task789", ("guid123", "incident456", "task789")),  # Scenario 1: Full entitlement
    ("guid123@incident456", ("guid123", "incident456", "")),  # Scenario 2: No task ID
    ("guid123@", ("guid123", "", "")),  # Scenario 3: No incident ID or task ID
])
def test_extract_entitlement(entitlement, expected_result):
    """
    Test the extract_entitlement function.
    Given:
    - Input entitlement string.
    When:
    - Calling the extract_entitlement function with the given input entitlement.
    Then:
    - Validate that the function correctly extracts the entitlement components: guid, incident_id, and task_id.
    """
    result = extract_entitlement(entitlement)

    assert result == expected_result


def test_mirror_investigation_create_new_channel(http_client, mocker):
    """
    Given a mock client and relevant arguments,
    When calling the mirror_investigation function to create a new channel,
    Then validate that the function returns the expected CommandResults.
    """
    import MattermostV2
    MattermostV2.MIRRORING_ENABLED = True
    MattermostV2.LONG_RUNNING = True
    MattermostV2.SYNC_CONTEXT = True
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'mock_server_url'})

    # Test data
    args = {
        'type': 'all',
        'direction': 'Both',
        'channelName': 'mirror-channel',
        'autoclose': True,
    }
    mock_integration_context = {
        'mirrors': json.dumps([
            {'channel_name': 'Channel1', 'team_id': 'team_id', 'channel_id': 'channel_id', 'mirrored': False,
             'investigation_id': 'Incident123', 'mirror_direction': 'toDemisto', 'auto_close': True, 'mirror_type': 'all'},
            {'channel_name': 'Channel2', 'team_id': 'team_id', 'channel_id': 'channel_id', 'mirrored': True,
             'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True, 'mirror_type': 'chat'},
        ])
    }
    mocker.patch('MattermostV2.get_integration_context', return_value=mock_integration_context)
    mocker.patch.object(demisto, 'mirrorInvestigation')
    # Call the function
    result = mirror_investigation(http_client, **args)

    # Assert the result

    demisto.mirrorInvestigation.assert_called_once_with('1', 'all:Both', True)
    assert 'Investigation mirrored successfully' in result.readable_output


def test_send_notification_command_with_not_permitted_notif_type(http_client, mocker):
    """
    Given -
        client
    When -
        send message to channel
    Then -
        Validate that
    """
    import MattermostV2
    MattermostV2.PERMITTED_NOTIFICATION_TYPES = []
    mocker.patch.object(http_client, "send_notification_request", return_value={'id': 'message_id'})
    result = send_notification(http_client,
                               user_id='user1',
                               message='Hello',
                               to='channel1',
                               messageType='not permitted'
                               )

    assert result == 'Message type is not in permitted options. Received: not permitted'


def test_send_notification_command_with_generic_notif_channel_name(http_client, mocker):
    """
    Given -
        client
    When -
        send message to channel
    Then -
        Validate that
    """
    import MattermostV2
    MattermostV2.PERMITTED_NOTIFICATION_TYPES = ['incidentOpened']
    mocker.patch.object(http_client, "send_notification_request", return_value={'id': 'message_id'})
    mocker.patch.object(MattermostV2, "get_channel_id_from_context", return_value='channel_id')
    result = send_notification(http_client,
                               user_id='user1',
                               message='Hello',
                               channel=INCIDENT_NOTIFICATION_CHANNEL,
                               messageType='incidentOpened'
                               )

    assert result.readable_output == 'Message sent to MatterMost successfully. Message ID is: message_id'


def test_send_notification_command(http_client, mocker):
    """
    Given -
        client
    When -
        send message to channel
    Then -
        Validate that
    """
    mocker.patch.object(http_client, "send_notification_request", return_value={'id': 'message_id'})
    result = send_notification(http_client,
                               user_id='user1',
                               message='Hello',
                               to='channel1',
                               )

    assert result.readable_output == 'Message sent to MatterMost successfully. Message ID is: message_id'


def test_send_notification_to_two_users(http_client, mocker):
    """
    Given -
        client
    When -
        send message to channel
    Then -
        Validate that
    """
    mocker.patch.object(http_client, "send_notification_request", return_value={'id': 'message_id'})
    result = send_notification(http_client,
                               user_id='user1',
                               message='Hello',
                               to='user1,user2',
                               )

    assert result.readable_output == 'Message sent to MatterMost successfully. Message ID is: message_id'


def test_list_groups_command(http_client):
    """
    Given -
        client
        arguments
    When -
        list user group
    Then -
        Validate that the function returns the expected CommandResults.
    """
    args = {'group': 'user_group', }
    results = list_groups_command(http_client, args)
    assert results.outputs[0].get('id') == 'abc1234'


def test_list_group_members_command(http_client):
    """
    Given -
        client
        arguments
    When -
        list user group members
    Then -
        Validate that the function returns the expected CommandResults.
    """
    args = {'group': 'user_group', }
    results = list_group_members_command(http_client, args)
    assert results.outputs[0].get('name') == 'user_group'


def test_add_group_member_command(http_client, mocker):
    """
    Given -
        client
        arguments
    When -
        add user group member
    Then -
        Validate that the function returns the expected CommandResults.
    """
    args = {'group': 'user_group', "user_ids": "user_id"}
    mocker.patch.object(http_client, "add_group_member_request", return_value=[{"group_id":"group_id", "create_at": 0,
                                                                                "delete_at": 0, "user_id": "user_id"}])
    results = add_group_member_command(http_client, args)
    assert results.readable_output == 'The member username was added to the user group successfully, with group ID: group_id'


def test_remove_group_member_command(http_client, mocker):
    """
    Given -
        client
        arguments
    When -
        remove user group member
    Then -
        Validate that the function returns the expected CommandResults.
    """
    args = {'group': 'user_group', "user_ids": "user_id"}
    mocker.patch.object(http_client, "remove_group_member_request", return_value=[{"group_id":"group_id", "create_at": 0,
                                                                                "delete_at": 0, "user_id": "user_id"}])
    results = add_group_member_command(http_client, args)
    assert results.readable_output == 'The member username was removed from the channel successfully, with group ID: group_id'


def test_set_channel_role_command(http_client, mocker):
    """
    Given -
        client
        arguments
    When -
        remove user group member
    Then -
        Validate that the function returns the expected CommandResults.
    """
    args = {'channel_id': 'channel_id', "user_id": "user_id", "role": "admin"}
    mocker.patch.object(http_client, "remove_group_member_request", return_value={"status": "ok"})
    results = set_channel_role_command(http_client, args)
    assert results.readable_output == 'Set channel role for username successfully to Admin.'

######### async tests #########


@pytest.mark.asyncio
async def test_handle_posts_regular_post(http_client, mocker):
    """
    Given:
    - Post payload.
    When:
    - Calling the handle_posts function.
    Then:
    - Validate that the mirror investigation func was called. only once, as one of the mirrors was already mirrored.
    """
    import MattermostV2
    payload = util_load_json("test_data/posted_data_user.json")
    mock_integration_context = {
        'mirrors': json.dumps([
            {'channel_name': 'Channel1', 'team_id': 'team_id', 'channel_id': 'channel_id', 'mirrored': False,
             'investigation_id': 'Incident123', 'mirror_direction': 'toDemisto', 'auto_close': True, 'mirror_type': 'all'},
            {'channel_name': 'Channel2', 'team_id': 'team_id', 'channel_id': 'channel_id', 'mirrored': True,
             'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True, 'mirror_type': 'chat'},
        ])
    }
    MattermostV2.CLIENT = http_client
    MattermostV2.CACHE_EXPIRY = False
    mocker.patch('MattermostV2.get_integration_context', return_value=mock_integration_context)
    mocker.patch('MattermostV2.handle_text_received_from_mm', return_value=None)
    mocker.patch.object(demisto, 'mirrorInvestigation')
    await handle_posts(payload)
    demisto.mirrorInvestigation.assert_called_once_with('Incident123', 'all:toDemisto', True)


@pytest.mark.asyncio
async def test_handle_text(mocker):
    """
    Given:
    - arguments.
    When:
    - Calling the handle_text_received_from_mm function.
    Then:
    - Validate that the `demisto.addEntry` method was called with the expected arguments
    """

    investigation_id = "123"
    text = "Hello, this is a test message"
    operator_email = "test@example.com"
    operator_name = "Test User"
    MESSAGE_FOOTER = '\n**From Mattermost**'

    with patch('MattermostV2.demisto') as mock_demisto:
        await handle_text_received_from_mm(investigation_id, text, operator_email, operator_name)
        mock_demisto.addEntry.assert_called_once_with(
            id=investigation_id,
            entry=text,
            username=operator_name,
            email=operator_email,
            footer=MESSAGE_FOOTER
        )


@pytest.mark.asyncio
async def test_event_handler_error(ws_client, mocker):
    """
    Given:
    - Error post payload.
    When:
    - Calling the handle_posts function.
    Then:
    - Validate that the demisto.error func was called.
    """
    error_payload = """{"status": "FAIL",
                     "seq_reply": 2,
                     "error": {"id": "some.error.id.here", "message": "Some error message here"
                               }
                     }"""
    error_mock = mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'updateModuleHealth')

    await event_handler(ws_client, error_payload)

    assert error_mock.call_count == 1


@pytest.mark.asyncio
async def test_event_handler_bot_message(http_client, mocker):
    """
    Given:
    - Bot post payload.
    When:
    - Calling the handle_posts function.
    Then:
    - Validate that the demisto.debug func was called.
    """
    import MattermostV2
    MattermostV2.CLIENT = http_client
    bot_payload = util_load_json("test_data/posted_data_bot.json")
    mocker.patch.object(demisto, 'updateModuleHealth')
    mocker.patch.object(demisto, 'debug')

    await handle_posts(bot_payload)
    demisto.debug.assert_called_once_with(
        "MM: Got a bot message. Will not mirror."
    )


@pytest.mark.asyncio
async def test_event_handler_direct_message(http_client, mocker):
    """
    Given:
    - dm post payload.
    When:
    - Calling the handle_posts function.
    Then:
    - Validate that the demisto.debug func was called.
    """
    import MattermostV2
    MattermostV2.CLIENT = http_client
    MattermostV2.ALLOW_INCIDENTS = True

    payload = util_load_json("test_data/posted_data_user.json")
    payload["data"]["channel_type"] = "D"
    mocker.patch.object(demisto, 'updateModuleHealth')
    mocker.patch.object(demisto, 'directMessage', return_value={})

    await handle_posts(payload)
    demisto.directMessage.assert_called_once_with(
        "message", "", "", True
    )


def test_answer_question(http_client, mocker):
    """
    Test the answer_question function.
    Given:
    - A mocked question dictionary.
    When:
    - Calling the answer_question function with the mocked question.
    Then:
    - Validate that the function correctly handles the entitlement and returns the incident_id.
    """
    import MattermostV2
    MattermostV2.CLIENT = http_client
    mock_question = {
        'entitlement': 'guid123@incident456|task789',
        'to_id': '123'
    }

    mocker.patch('MattermostV2.process_entitlement_reply')

    result = answer_question("Answer123", mock_question, "user@example.com")
    assert result == 'incident456'


@pytest.mark.asyncio
async def test_create_incidents(mocker):
    """
    Given:
    - Incidents
    When:
    - Calling the create_incidents function.
    Then:
    - Validate that the demisto.createIncidents func was called.
    """

    mocker.patch.object(demisto, 'createIncidents', return_value='nice')

    incidents = [{"name": "xyz", "details": "1.1.1.1,8.8.8.8"}]

    incidents_with_labels = [{'name': 'xyz', 'details': '1.1.1.1,8.8.8.8',
                              'labels': [{'type': 'Reporter', 'value': 'spengler'},
                                         {'type': 'ReporterEmail', 'value': 'test@test.com'},
                                         {'type': 'Source', 'value': 'Slack'}]}]

    data = await create_incidents(incidents, 'spengler', 'test@test.com', 'demisto_user')

    incident_arg = demisto.createIncidents.call_args[0][0]
    user_arg = demisto.createIncidents.call_args[1]['userID']

    assert incident_arg == incidents_with_labels
    assert user_arg == 'demisto_user'
    assert data == 'nice'


class TestGetWarRoomURL:

    def test_get_war_room_url_with_xsiam_from_incident_war_room(self, mocker):
        url = "https://example.com/WarRoom/INCIDENT-2930"
        expected_war_room_url = "https://example.com/incidents/war_room?caseId=2930"
        mocker.patch('MattermostV2.is_xsiam', return_value=True)
        mocker.patch.dict(demisto.callingContext, {'context': {'Inv': {'id': 'INCIDENT-2930'}}})

        assert get_war_room_url(url) == expected_war_room_url

    def test_get_war_room_url_without_xsiam_from_incident_war_room(self, mocker):
        url = "https://example.com/WarRoom/INCIDENT-2930"
        mocker.patch('MattermostV2.is_xsiam', return_value=False)
        expected_war_room_url = "https://example.com/WarRoom/INCIDENT-2930"
        assert get_war_room_url(url) == expected_war_room_url

    def test_get_war_room_url_with_xsiam_from_alert_war_room(self, mocker):
        url = "https://example.com/WarRoom/ALERT-1234"
        mocker.patch('MattermostV2.is_xsiam', return_value=True)
        mocker.patch.dict(demisto.callingContext, {'context': {'Inv': {'id': '1234'}}})
        expected_war_room_url = \
            "https://example.com/incidents/alerts_and_insights?caseId=1234&action:openAlertDetails=1234-warRoom"
        assert get_war_room_url(url) == expected_war_room_url
