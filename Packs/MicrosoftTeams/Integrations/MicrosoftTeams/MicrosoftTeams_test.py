import demistomock as demisto
import json
import pytest
from CommonServerPython import entryTypes

entryTypes['warning'] = 11

bot_id: str = '9bi5353b-md6a-4458-8321-e924af433amb'

tenant_id: str = 'pbae9ao6-01ql-249o-5me3-4738p3e1m941'

team_id: str = '19:21f27jk08d1a487fa0f5467779619827@thread.skype'

team_aad_id: str = '7d8efdf8-0c5a-42e3-a489-5ef5c3fc7a2b'

team_name: str = 'The-A-Team'

service_url: str = 'https://smba.trafficmanager.net/emea'

mirrored_channels: list = [
    {
        'channel_id': '19:2cbad0d78c624400ef83a5750539998g@thread.skype',
        'investigation_id': '1',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'auto_close': 'true',
        'mirrored': True,
        'channel_name': 'incident-1'
    },
    {
        'channel_id': '19:2cbad0d78c624400ef83a5750534448g@thread.skype',
        'investigation_id': '10',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'auto_close': 'true',
        'mirrored': True,
        'channel_name': 'incident-10'
    }
]

team_members: list = [
    {
        'id': '29:1KZccCJRTxlPdHnwcKfxHAtYvPLIyHgkSLhFSnGXLGVFlnltovdZPmZAduPKQP6NrGqOcde7FXAF7uTZ_8FQOqg',
        'objectId': '359d2c3c-162b-414c-b2eq-386461e5l050',
        'name': 'Bruce Willis',
        'givenName': 'Bruce',
        'surname': 'Willis',
        'userPrincipalName': 'bwillis@email.com',
        'tenantId': tenant_id
    },
    {
        'id': '29:1pBMMC85IyjM3tr_MCZi7KW4pw4EULxLN4C7R_xoi3Wva_lOn3VTf7xJlCLK-r-pMumrmoz9agZxsSrCf7__u9R',
        'objectId': '2826c1p7-bdb6-4529-b57d-2598me968631',
        'name': 'Denzel Washington',
        'givenName': 'Denzel',
        'surname': 'Washington',
        'email': 'dwashinton@email.com',
        'userPrincipalName': 'dwashinton@email.com',
        'tenantId': tenant_id
    }
]

integration_context: dict = {
    'bot_name': 'DemistoBot',
    'service_url': service_url,
    'tenant_id': tenant_id,
    'teams': json.dumps([{
        'mirrored_channels': mirrored_channels,
        'team_id': team_id,
        'team_aad_id': team_aad_id,
        'team_members': team_members,
        'team_name': team_name
    }])
}


@pytest.fixture(autouse=True)
def get_integration_context(mocker):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context)


@pytest.fixture(autouse=True)
def get_graph_access_token(requests_mock):
    requests_mock.post(
        f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
        json={
            'access_token': 'token'
        },
        status_code=200
    )


@pytest.fixture(autouse=True)
def get_bot_access_token(requests_mock):
    requests_mock.post(
        'https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token',
        json={
            'access_token': 'token'
        }
    )


def test_mentioned_users_to_entities():
    from MicrosoftTeams import mentioned_users_to_entities
    mentioned_users = ['Bruce Willis', 'Denzel Washington']
    bruce_entity = {
        'type': 'mention',
        'mentioned': {
            'id': '29:1KZccCJRTxlPdHnwcKfxHAtYvPLIyHgkSLhFSnGXLGVFlnltovdZPmZAduPKQP6NrGqOcde7FXAF7uTZ_8FQOqg',
            'name': 'Bruce Willis'
        },
        'text': '<at>@Bruce Willis</at>'
    }
    denzel_entity = {
        'type': 'mention',
        'mentioned': {
            'id': '29:1pBMMC85IyjM3tr_MCZi7KW4pw4EULxLN4C7R_xoi3Wva_lOn3VTf7xJlCLK-r-pMumrmoz9agZxsSrCf7__u9R',
            'name': 'Denzel Washington'
        },
        'text': '<at>@Denzel Washington</at>'
    }
    assert mentioned_users_to_entities(mentioned_users, integration_context) == [bruce_entity, denzel_entity]

    mentioned_users = ['Bruce Willis', 'demisto']
    with pytest.raises(ValueError, match='Team member demisto was not found'):
        mentioned_users_to_entities(mentioned_users, integration_context)


def test_process_mentioned_users_in_message():
    from MicrosoftTeams import process_mentioned_users_in_message
    raw_message = '@demisto dev; @demisto; a@demisto.com; a@demisto.com hi; @hi @wow;'
    parsed_message = '<at>@demisto dev</at> <at>@demisto</at> a@demisto.com; a@demisto.com hi; @hi <at>@wow</at>'
    users, message = process_mentioned_users_in_message(raw_message)
    assert users == ['demisto dev', 'demisto', 'wow']
    assert message == parsed_message


def test_message_handler(mocker):
    from MicrosoftTeams import message_handler
    mocker.patch.object(demisto, 'addEntry')
    request_body: dict = {
        'from': {
            'id': '29:1KZccCJRTxlPdHnwcKfxHAtYvPLIyHgkSLhFSnGXLGVFlnltovdZPmZAduPKQP6NrGqOcde7FXAF7uTZ_8FQOqg',
            'aadObjectId': '359d2c3c-162b-414c-b2eq-386461e5l050',
            'name': 'Bruce Willis'
        }
    }
    channel_data: dict = {
        'channel': {
            'id': '19:2cbad0d78c624400ef83a5750539998g@thread.skype'
        },
        'team': {
            'id': team_id
        }
    }
    message_handler(integration_context, request_body, channel_data, 'waz up')
    assert demisto.addEntry.call_count == 1
    add_entry_args = demisto.addEntry.call_args[1]
    assert add_entry_args == {
        'id': '1',
        'entry': 'waz up',
        'username': 'Bruce Willis',
        'email': 'bwillis@email.com',
        'footer': '\n**From Microsoft Teams**'
    }


def test_member_added_handler(mocker, requests_mock):
    from MicrosoftTeams import member_added_handler
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(demisto, 'params', return_value={'bot_id': bot_id})
    requests_mock.get(
        f'{service_url}/v3/conversations/{team_id}/members',
        json=team_members
    )
    request_body: dict = {
        'recipient': {
            'id': f'28:{bot_id}',
            'name': 'DemistoBot'
        },
        'membersAdded': [{
            'id': f'28:{bot_id}'
        }]
    }
    channel_data: dict = {
        'team': {
            'id': team_id,
            'name': team_name,
            'aadGroupId': team_aad_id
        },
        'eventType': 'teamMemberAdded',
        'tenant': {
            'id': tenant_id
        }
    }
    member_added_handler(integration_context, request_body, channel_data)
    expected_integration_context: dict = {
        'bot_name': 'DemistoBot',
        'teams': json.dumps([{
            'mirrored_channels': mirrored_channels,
            'team_id': team_id,
            'team_aad_id': team_aad_id,
            'team_members': team_members,
            'team_name': team_name
        }]),
        'tenant_id': tenant_id,
        'service_url': service_url
    }
    assert demisto.setIntegrationContext.call_count == 2
    set_integration_context = demisto.setIntegrationContext.call_args[0]
    assert len(set_integration_context) == 1
    assert set_integration_context[0] == expected_integration_context


def test_mirror_investigation(mocker, requests_mock):
    from MicrosoftTeams import mirror_investigation

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'team': 'The-A-Team'
        }
    )

    # verify command cannot be executed in the war room
    mocker.patch.object(
        demisto,
        'investigation',
        return_value={
            'type': 9
        }
    )
    with pytest.raises(ValueError) as e:
        mirror_investigation()
    assert str(e.value) == 'Can not perform this action in playground.'

    # verify channel is mirrored successfully and a message is sent to it
    mocker.patch.object(
        demisto,
        'investigation',
        return_value={
            'id': '2'
        }
    )
    channel_id: str = 'channel-id'
    # create channel mock request
    requests_mock.post(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels',
        json={
            'id': channel_id
        }
    )
    # send message mock request
    requests_mock.post(
        f'{service_url}/v3/conversations/{channel_id}/activities',
        json={}
    )
    mirror_investigation()
    updated_mirrored_channels: list = mirrored_channels[:]
    updated_mirrored_channels.append({
        'channel_id': 'channel-id',
        'investigation_id': '2',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'auto_close': 'true',
        'mirrored': False,
        'channel_name': 'incident-2'
    })
    expected_integration_context: dict = {
        'bot_name': 'DemistoBot',
        'tenant_id': tenant_id,
        'service_url': service_url,
        'teams': json.dumps([{
            'mirrored_channels': updated_mirrored_channels,
            'team_id': team_id,
            'team_aad_id': team_aad_id,
            'team_members': team_members,
            'team_name': 'The-A-Team'
        }])
    }
    assert requests_mock.request_history[1].json() == {
        'displayName': 'incident-2',
        'description': 'Channel to mirror incident 2'
    }
    assert requests_mock.request_history[3].json() == {
        'text': 'This channel was created to mirror [incident 2](https://test-address:8443#/WarRoom/2) between '
                'Teams and Demisto. In order for your Teams messages to be mirrored in Demisto, you need to'
                ' mention the Demisto Bot in the message.',
        'type': 'message'
    }

    assert demisto.setIntegrationContext.call_count == 3
    set_integration_context = demisto.setIntegrationContext.call_args[0]
    assert len(set_integration_context) == 1
    set_integration_context[0].pop('graph_access_token')
    set_integration_context[0].pop('graph_valid_until')
    set_integration_context[0].pop('bot_access_token')
    set_integration_context[0].pop('bot_valid_until')
    assert set_integration_context[0] == expected_integration_context
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Investigation mirrored successfully in channel incident-2.'

    # verify channel mirror is updated successfully
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'mirror_type': 'chat',
            'direction': 'FromDemisto',
            'autoclose': 'false'
        }
    )
    mocker.patch.object(
        demisto,
        'investigation',
        return_value={
            'id': '1'
        }
    )
    mirror_investigation()
    assert demisto.setIntegrationContext.call_count == 1
    set_integration_context = demisto.setIntegrationContext.call_args[0]
    assert len(set_integration_context) == 1
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Investigation mirror was updated successfully.'

    # verify channel with custom channel name is mirrored successfully
    mocker.patch.object(
        demisto,
        'investigation',
        return_value={
            'id': '14'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'channel_name': 'booya'
        }
    )

    mirror_investigation()
    assert requests_mock.request_history[5].json() == {
        'displayName': 'booya',
        'description': 'Channel to mirror incident 14'
    }
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Investigation mirrored successfully in channel booya.'


def test_send_message(mocker, requests_mock):
    from MicrosoftTeams import send_message
    mocker.patch.object(demisto, 'results')

    # verify that a mirrored message is skipped
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'messageType': 'mirrorEntry',
            'originalMessage': 'a mirrored message\n**From Microsoft Teams**'
        }
    )
    assert send_message() is None

    # verify notification from server with severity below threshold is not sent
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'min_incident_severity': 'Medium',
            'team': 'The-A-Team'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'messageType': 'incidentOpened',
            'severity': 1
        }
    )
    assert send_message() is None

    # verify error is raised if no user/channel were provided
    mocker.patch.object(
        demisto,
        'args',
        return_value={}
    )
    with pytest.raises(ValueError) as e:
        send_message()
    assert str(e.value) == 'No channel or team member to send message were provided.'

    # verify error is raised if both user and channel were provided
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'channel': 'somechannel',
            'team_member': 'someuser'
        }
    )
    with pytest.raises(ValueError) as e:
        send_message()
    assert str(e.value) == 'Provide either channel or team member to send message to, not both.'

    # verify message is sent properly given user to send to
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'bot_id': bot_id
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_member': 'Denzel Washington',
            'message': 'MESSAGE'
        }
    )
    requests_mock.post(
        f'{service_url}/v3/conversations',
        json={
            'id': 'conversation-id'
        }
    )
    requests_mock.post(
        f'{service_url}/v3/conversations/conversation-id/activities',
        json={}
    )
    expected_create_personal_conversation_data: dict = {
        'bot': {
            'id': f'28:{bot_id}',
            'name': 'DemistoBot'
        },
        'members': [{
            'id': '29:1pBMMC85IyjM3tr_MCZi7KW4pw4EULxLN4C7R_xoi3Wva_lOn3VTf7xJlCLK-r-pMumrmoz9agZxsSrCf7__u9R'
        }],
        'channelData': {
            'tenant': {
                'id': tenant_id
            }
        }
    }
    send_message()
    assert requests_mock.request_history[0].json() == expected_create_personal_conversation_data
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Message was sent successfully.'

    # verify message is sent properly given channel
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'team': 'The-A-Team'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'channel': 'incident-1',
            'message': 'MESSAGE'
        }
    )
    requests_mock.post(
        f"{service_url}/v3/conversations/{mirrored_channels[0]['channel_id']}/activities",
        json={}
    )
    send_message()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Message was sent successfully.'

    # verify message is sent properly given entitlement
    message: dict = {
        'message_text': 'is this really working?',
        'options': ['yes', 'no', 'maybe'],
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8',
        'investigation_id': '72',
        'task_id': '23'
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_member': 'dwashinton@email.com',
            'message': json.dumps(message)
        }
    )
    expected_ask_user_message: dict = {
        'attachments': [{
            'content': {
                '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
                'actions': [
                    {
                        'data': {
                            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8',
                            'investigation_id': '72',
                            'response': 'yes',
                            'task_id': '23'
                        },
                        'title': 'yes',
                        'type': 'Action.Submit'
                    },
                    {
                        'data': {
                            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8',
                            'investigation_id': '72',
                            'response': 'no',
                            'task_id': '23'
                        },
                        'title': 'no',
                        'type': 'Action.Submit'
                    },
                    {
                        'data': {
                            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8',
                            'investigation_id': '72',
                            'response': 'maybe',
                            'task_id': '23'
                        },
                        'title': 'maybe',
                        'type': 'Action.Submit'
                    }
                ],
                'body': [{
                    'text': 'is this really working?',
                    'type': 'TextBlock'
                }],
                'type': 'AdaptiveCard',
                'version': '1.0'
            },
            'contentType': 'application/vnd.microsoft.card.adaptive'
        }],
        'type': 'message'
    }

    send_message()
    assert requests_mock.request_history[4].json() == expected_ask_user_message
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Message was sent successfully.'

    # verify proper error is raised if invalid JSON provided as adaptive card
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'channel': 'channel',
            'adaptive_card': 'THISisSTRINGnotJSON'
        }
    )
    with pytest.raises(ValueError) as e:
        send_message()
    assert str(e.value) == 'Given adaptive card is not in valid JSON format.'

    # verify proper error is raised if both message and adaptive card were provided
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'channel': 'channel',
            'message': 'message',
            'adaptive_card': '{"a":"b"}'
        }
    )
    with pytest.raises(ValueError) as e:
        send_message()
    assert str(e.value) == 'Provide either message or adaptive to send, not both.'

    # verify proper error is raised if neither message or adaptive card were provided
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'channel': 'channel'
        }
    )
    with pytest.raises(ValueError) as e:
        send_message()
    assert str(e.value) == 'No message or adaptive card to send were provided.'

    # verify adaptive card sent successfully

    adaptive_card: dict = {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.0",
            "body": [
                {
                    "type": "Container",
                    "items": [{
                        "type": "TextBlock",
                        "text": "What a pretty adaptive card"
                    }]
                }
            ]
        }
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_member': 'bwillis@email.com',
            'adaptive_card': json.dumps(adaptive_card)
        }
    )
    expected_conversation: dict = {
        'type': 'message',
        'attachments': [adaptive_card]
    }
    send_message()
    assert requests_mock.request_history[6].json() == expected_conversation
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Message was sent successfully.'


def test_send_message_server_notifications_incident_opened(mocker, requests_mock):
    """
    Given:
     - Notification from server of an incident opened.

    When:
     - Sending notification message of the incident opened.

    Then:
     - Ensure message is sent successfully.
     - Verify the message is sent to the dedicated notifications channel.
    """
    from MicrosoftTeams import send_message
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'team': 'The-A-Team',
            'min_incident_severity': 'Low',
            'incident_notifications_channel': 'General'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'channel': 'incidentNotificationChannel',
            'message': 'user has reported an incident tadam.\nView it on https://server#/WarRoom/3247',
            'messageType': 'incidentOpened',
            'severity': 1,
            'to': ''
        }
    )
    requests_mock.get(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels',
        json={
            'value': [
                {
                    'description': 'general channel',
                    'displayName': 'General',
                    'id': '19:67pd3966e74g45f28d0c65f1689132bb@thread.skype'
                }
            ]
        }
    )
    requests_mock.post(
        f'{service_url}/v3/conversations/19:67pd3966e74g45f28d0c65f1689132bb@thread.skype/activities',
        json={}
    )
    send_message()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Message was sent successfully.'


def test_send_message_server_notifications_incident_changed(mocker, requests_mock):
    """
    Given:
     - Notification from server of an updated incident.

    When:
     - Sending notification message of the updated incident.

    Then:
     - Ensure message is sent successfully.
     - Verify the message is sent to the dedicated notifications channel.
    """
    from MicrosoftTeams import send_message
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'team': 'The-A-Team',
            'min_incident_severity': 'Low',
            'incident_notifications_channel': 'General'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'channel': 'incidentNotificationChannel',
            'message': 'DBot has updated an incident tadam.\nView it on https://server#/WarRoom/3247',
            'messageType': 'incidentChanged',
            'severity': 1,
            'to': ''
        }
    )
    requests_mock.get(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels',
        json={
            'value': [
                {
                    'description': 'general channel',
                    'displayName': 'General',
                    'id': '19:67pd3966e74g45f28d0c65f1689132bb@thread.skype'
                }
            ]
        }
    )
    requests_mock.post(
        f'{service_url}/v3/conversations/19:67pd3966e74g45f28d0c65f1689132bb@thread.skype/activities',
        json={}
    )
    send_message()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Message was sent successfully.'


def test_get_channel_id(requests_mock):
    from MicrosoftTeams import get_channel_id
    # get channel which is in the integration context
    assert get_channel_id('incident-1', team_aad_id) == '19:2cbad0d78c624400ef83a5750539998g@thread.skype'
    # get channel which is not in the integration context
    requests_mock.get(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels',
        json={
            'value': [
                {
                    'description': 'channel for incident 1',
                    'displayName': 'incident-1',
                    'id': '19:67pd3967e74g45f28d0c65f1689132bb@thread.skype'
                },
                {
                    'description': 'channel for incident 2',
                    'displayName': 'incident-3',
                    'id': '19:67pd3967e74g45f28d0c65f1689132bo@thread.skype'
                }
            ]
        }
    )
    assert get_channel_id('incident-3', team_aad_id) == '19:67pd3967e74g45f28d0c65f1689132bo@thread.skype'
    # Try a channel which does not exit
    with pytest.raises(ValueError) as e:
        get_channel_id('incident-4', team_aad_id)
    assert str(e.value) == 'Could not find channel: incident-4'


def test_close_channel(mocker, requests_mock):
    from MicrosoftTeams import close_channel
    requests_mock.delete(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels/19:2cbad0d78c624400ef83a5750539998g@thread.skype',
        status_code=204
    )
    requests_mock.delete(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels/19:2cbad0d78c624400ef83a5750534448g@thread.skype',
        status_code=204
    )
    mocker.patch.object(demisto, 'results')

    # close channel without given channel name
    mocker.patch.object(demisto, 'investigation', return_value={'id': '1'})
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    close_channel()
    assert requests_mock.request_history[0].method == 'DELETE'
    assert demisto.setIntegrationContext.call_count == 1
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Channel was successfully closed.'

    # try to close channel without given channel name, which does not exist in the integration context
    mocker.patch.object(demisto, 'investigation', return_value={'id': '5'})
    with pytest.raises(ValueError) as e:
        close_channel()
    assert str(e.value) == 'Could not find Microsoft Teams channel to close.'

    # close channel given channel name
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'setIntegrationContext')
    requests_mock.get(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels',
        json={
            'value': [
                {
                    'description': 'channel for incident 1',
                    'displayName': 'incident-1',
                    'id': '19:67pd3967e74g45f28d0c65f1689132bb@thread.skype'
                },
                {
                    'description': 'channel for incident 6',
                    'displayName': 'incident-6',
                    'id': '19:67pd3967e74g45f28d0c65f1689132bo@thread.skype'
                }
            ]
        }
    )
    requests_mock.delete(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels/19:67pd3967e74g45f28d0c65f1689132bb@thread.skype',
        status_code=204
    )
    mocker.patch.object(demisto, 'params', return_value={'team': 'The-A-Team'})
    mocker.patch.object(demisto, 'args', return_value={'channel': 'incident-1'})

    close_channel()
    assert requests_mock.request_history[0].method == 'DELETE'
    assert demisto.setIntegrationContext.call_count == 0
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Channel was successfully closed.'


def test_entitlement_handler(mocker, requests_mock):
    from MicrosoftTeams import entitlement_handler
    mocker.patch.object(demisto, 'handleEntitlementForUser')
    conversation_id: str = 'f:3005393407786078157'
    activity_id: str = '1:1vW2mx4iDZf05lk18yskL64Wkfwraa76YTGNgDiIi-_5'
    requests_mock.put(
        f'{service_url}/v3/conversations/{conversation_id}/activities/{activity_id}',
        json={'id': 'updateid'}
    )
    request_body: dict = {
        'from': {
            'id': '29:1KZccCJRTxlPdHnwcKfxHAtYvPLIyHgkSLhFSnGXLGVFlnltovdZPmZAduPKQP6NrGqOcde7FXAF7uTZ_8FQOqg',
            'aadObjectId': '359d2c3c-162b-414c-b2eq-386461e5l050',
            'name': 'Bruce Willis'
        },
        'replyToId': activity_id
    }
    value: dict = {
        'response': 'Approve!',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8',
        'investigation_id': '100',
        'task_id': '4'
    }
    entitlement_handler(integration_context, request_body, value, conversation_id)
    assert demisto.handleEntitlementForUser.call_count == 1
    handle_entitlement_args = demisto.handleEntitlementForUser.call_args[1]
    assert handle_entitlement_args == {
        'incidentID': '100',
        'guid': '4404dae8-2d45-46bd-85fa-64779c12abe8',
        'taskID': '4',
        'email': 'bwillis@email.com',
        'content': 'Approve!'
    }


def test_translate_severity():
    from MicrosoftTeams import translate_severity
    assert translate_severity('Low') == 1
    assert translate_severity('NotRealSeverity') == 0


def test_is_investigation_mirrored():
    from MicrosoftTeams import is_investigation_mirrored
    existing_investigation_id: str = '1'
    non_existing_investigation_id: str = '2'

    assert is_investigation_mirrored(existing_investigation_id, mirrored_channels) == 0
    assert is_investigation_mirrored(non_existing_investigation_id, mirrored_channels) == -1


def test_urlify_hyperlinks():
    from MicrosoftTeams import urlify_hyperlinks
    message: str = 'Visit https://www.demisto.com and http://www.demisto.com'
    formatted_message: str = 'Visit [https://www.demisto.com](https://www.demisto.com) ' \
                             'and [http://www.demisto.com](http://www.demisto.com)'
    assert urlify_hyperlinks(message) == formatted_message


def test_get_team_aad_id(mocker, requests_mock):
    from MicrosoftTeams import get_team_aad_id

    # verify team ID for team which is in integration context
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'team': 'The-A-Team'
        }
    )
    assert get_team_aad_id('The-A-Team') == '7d8efdf8-0c5a-42e3-a489-5ef5c3fc7a2b'

    # verify non existing team raises value error
    requests_mock.get(
        "https://graph.microsoft.com/beta/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')",
        json={
            '@odata.context': 'https://graph.microsoft.com/beta/$metadata#groups',
            'value': [
                {
                    'id': '02bd9fd6-8f93-4758-87c3-1fb73740a315',
                    'displayName': 'MyGreatTeam',
                    'groupTypes': [
                        'Unified'
                    ],
                    'mailEnabled': True,
                    'resourceBehaviorOptions': [],
                    'resourceProvisioningOptions': [
                        'Team'
                    ],
                    'securityEnabled': False,
                    'visibility': 'Private'
                },
                {
                    'id': '8090c93e-ba7c-433e-9f39-08c7ba07c0b3',
                    'displayName': 'WooahTeam',
                    'groupTypes': [
                        'Unified'
                    ],
                    'mailEnabled': True,
                    'mailNickname': 'X1050LaunchTeam',
                    'resourceBehaviorOptions': [],
                    'resourceProvisioningOptions': [
                        'Team'
                    ],
                    'securityEnabled': False,
                    'visibility': 'Private'
                }
            ]
        }
    )
    with pytest.raises(ValueError) as e:
        get_team_aad_id('The-B-Team')
    assert str(e.value) == 'Could not find requested team.'

    # verify team ID for team which is not in integration context
    assert get_team_aad_id('MyGreatTeam') == '02bd9fd6-8f93-4758-87c3-1fb73740a315'


def test_get_team_member():
    from MicrosoftTeams import get_team_member
    user_id: str = '29:1KZccCJRTxlPdHnwcKfxHAtYvPLIyHgkSLhFSnGXLGVFlnltovdZPmZAduPKQP6NrGqOcde7FXAF7uTZ_8FQOqg'
    team_member: dict = {
        'username': 'Bruce Willis',
        'user_email': 'bwillis@email.com'
    }
    assert get_team_member(integration_context, user_id) == team_member
    with pytest.raises(ValueError) as e:
        get_team_member(integration_context, 'NotRealUser')
    assert str(e.value) == 'Team member was not found'


def test_get_team_member_id():
    from MicrosoftTeams import get_team_member_id
    requested_team_member: str = 'Denzel Washington'
    expected_user_id: str = '29:1pBMMC85IyjM3tr_MCZi7KW4pw4EULxLN4C7R_xoi3Wva_lOn3VTf7xJlCLK-r-pMumrmoz9agZxsSrCf7__u9R'
    assert get_team_member_id(requested_team_member, integration_context) == expected_user_id

    requested_team_member = 'dwashinton@email.com'
    assert get_team_member_id(requested_team_member, integration_context) == expected_user_id
    requested_team_member = 'TheRock'
    with pytest.raises(ValueError) as e:
        get_team_member_id(requested_team_member, integration_context)
    assert str(e.value) == 'Team member TheRock was not found'


def test_create_adaptive_card():
    from MicrosoftTeams import create_adaptive_card
    body: list = [{
        'type': 'TextBlock',
        'size': 'Medium',
        'weight': 'Bolder',
        'text': 'What a beautiful text'
    }]
    expected_adaptive_card: dict = {
        'contentType': 'application/vnd.microsoft.card.adaptive',
        'content': {
            '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
            'version': '1.0',
            'type': 'AdaptiveCard',
            'body': body
        }
    }
    assert create_adaptive_card(body) == expected_adaptive_card
    actions: list = [{
        'type': 'Action.OpenUrl',
        'title': 'DEMISTO',
        'url': 'https://www.demisto.com'
    }]
    expected_adaptive_card['content']['actions'] = actions
    assert create_adaptive_card(body, actions) == expected_adaptive_card


def test_process_tasks_list():
    from MicrosoftTeams import process_tasks_list
    data_by_line: list = [
        'Task                                     | Incident                       | Due                 | Link ',
        '=========================================|================================|=====================|=====',
        'Manually review the incident             | 21 - nnn                       | 0001-01-01 00:00:00 | '
        'https://demisto.com/#/WorkPlan/21'
    ]
    expected_adaptive_card: dict = {
        'contentType': 'application/vnd.microsoft.card.adaptive',
        'content': {
            '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
            'version': '1.0',
            'type': 'AdaptiveCard',
            'body': [{
                'type': 'FactSet',
                'facts': [
                    {
                        'title': 'Task:',
                        'value': 'Manually review the incident'
                    },
                    {
                        'title': 'Incident:',
                        'value': '21 - nnn'
                    },
                    {
                        'title': 'Due:',
                        'value': '0001-01-01 00:00:00'
                    },
                    {
                        'title': 'Link:',
                        'value': '[https://demisto.com/#/WorkPlan/21](https://demisto.com/#/WorkPlan/21)'
                    }
                ]
            }]
        }
    }
    assert process_tasks_list(data_by_line) == expected_adaptive_card


def test_process_incidents_list():
    from MicrosoftTeams import process_incidents_list
    data_by_line: list = [
        'ID         | Name                 | Status      | Type        | Owner       | Created             | Link ',
        '===========|======================|=============|=============|=============|=====================|=====',
        '257        | w                    | Active      | Unclassifie | god         | 2019-07-28 16:42:40 | '
        'https://demisto.com/#/WarRoom/257',
        '250        | gosa                 | Active      | Unclassifie | mozes       | 2019-07-28 16:16:49 | '
        'https://demisto.com/#/WarRoom/250 '
    ]
    expected_adaptive_card: dict = {
        'contentType': 'application/vnd.microsoft.card.adaptive',
        'content': {
            '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
            'version': '1.0',
            'type': 'AdaptiveCard',
            'body': [
                {
                    'type': 'FactSet',
                    'facts': [
                        {
                            'title': 'ID:',
                            'value': '257'
                        },
                        {
                            'title': 'Name:',
                            'value': 'w'
                        },
                        {
                            'title': 'Status:',
                            'value': 'Active'
                        },
                        {
                            'title': 'Type:',
                            'value': 'Unclassifie'
                        },
                        {
                            'title': 'Owner:',
                            'value': 'god'
                        },
                        {
                            'title': 'Created:',
                            'value': '2019-07-28 16:42:40'
                        },
                        {
                            'title': 'Link:',
                            'value': '[https://demisto.com/#/WarRoom/257](https://demisto.com/#/WarRoom/257)'
                        }
                    ]
                },
                {
                    'type': 'FactSet',
                    'facts': [
                        {
                            'title': 'ID:',
                            'value': '250'
                        },
                        {
                            'title': 'Name:',
                            'value': 'gosa'
                        },
                        {
                            'title': 'Status:',
                            'value': 'Active'
                        },
                        {
                            'title': 'Type:',
                            'value': 'Unclassifie'
                        },
                        {
                            'title': 'Owner:',
                            'value': 'mozes'
                        },
                        {
                            'title': 'Created:',
                            'value': '2019-07-28 16:16:49'
                        },
                        {
                            'title': 'Link:',
                            'value': '[https://demisto.com/#/WarRoom/250](https://demisto.com/#/WarRoom/250)'
                        }
                    ]
                }
            ]
        }
    }
    assert process_incidents_list(data_by_line) == expected_adaptive_card


def test_process_mirror_or_unknown_message():
    from MicrosoftTeams import process_mirror_or_unknown_message
    message: str = 'I can understand the following commands:\nlist incidents [page x]\nlist my incidents [page x]\n' \
                   'list my tasks\nlist closed incidents\nnew incident [details]\nmirror incident-id'
    expected_adaptive_card: dict = {
        'contentType': 'application/vnd.microsoft.card.adaptive',
        'content': {
            '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
            'version': '1.0',
            'type': 'AdaptiveCard',
            'body': [{
                'type': 'TextBlock',
                'text': 'I can understand the following commands:\n\nlist incidents [page x]\n\nlist my incidents [page'
                        ' x]\n\nlist my tasks\n\nlist closed incidents\n\nnew incident [details]\n\nmirror incident-id',
                'wrap': True
            }]
        }
    }
    assert process_mirror_or_unknown_message(message) == expected_adaptive_card


def test_create_channel(requests_mock):
    from MicrosoftTeams import create_channel
    requests_mock.post(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels',
        json={
            'id': '19:67pd3967e74g45f28d0c65f1689132bb@thread.skype'
        }
    )
    channel_name: str = 'CrazyChannel'
    response = create_channel(team_aad_id, channel_name)
    assert response == '19:67pd3967e74g45f28d0c65f1689132bb@thread.skype'


def test_get_team_members(requests_mock):
    from MicrosoftTeams import get_team_members
    requests_mock.get(
        f'{service_url}/v3/conversations/{team_aad_id}/members',
        json=team_members
    )
    assert get_team_members(service_url, team_aad_id) == team_members


def test_update_message(requests_mock):
    from MicrosoftTeams import update_message
    activity_id: str = '1:1vW2mx4iDZf05lk18yskL64Wkfwraa76YTGNgDiIi-_5'
    conversation_id: str = 'f:3005393407786078157'
    requests_mock.put(
        f'{service_url}/v3/conversations/{conversation_id}/activities/{activity_id}',
        json={'id': 'updateid'}
    )
    expected_conversation: dict = {
        'type': 'message',
        'attachments': [{
            'contentType': 'application/vnd.microsoft.card.adaptive',
            'content': {
                '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
                'version': '1.0', 'type': 'AdaptiveCard',
                'body': [{
                    'type': 'TextBlock', 'text': 'OMG!'
                }]
            }
        }]
    }
    update_message(service_url, conversation_id, activity_id, 'OMG!')
    assert requests_mock.request_history[0].method == 'PUT'
    assert json.loads(requests_mock.request_history[0].body) == expected_conversation


def test_direct_message_handler(mocker, requests_mock):
    from MicrosoftTeams import direct_message_handler
    mocker.patch.object(
        demisto,
        'createIncidents',
        return_value={
            'id': '4',
            'name': 'incidentnumberfour'
        }
    )
    requests_mock.post(
        f'{service_url}/v3/conversations/conversation-id/activities',
        json={}
    )
    request_body: dict = {
        'from': {
            'id': '29:1KZccCJRTxlPdHnwcKfxHAtYvPLIyHgkSLhFSnGXLGVFlnltovdZPmZAduPKQP6NrGqOcde7FXAF7uTZ_8FQOqg'
        }
    }
    conversation: dict = {
        'id': 'conversation-id'
    }

    # verify create incident fails on un allowed external incident creation and non found user
    message: str = 'create incident name=GoFish type=Phishing'
    mocker.patch.object(demisto, 'findUser', return_value=None)
    direct_message_handler(integration_context, request_body, conversation, message)
    assert requests_mock.request_history[0].json() == {
        'text': 'You are not allowed to create incidents.', 'type': 'message'
    }

    # verify create incident successfully
    mocker.patch.object(demisto, 'findUser', return_value={'id': 'nice-demisto-id'})
    direct_message_handler(integration_context, request_body, conversation, message)
    assert requests_mock.request_history[1].json() == {
        'text': "Successfully created incident incidentnumberfour.\n"
                "View it on: [https://test-address:8443#/WarRoom/4](https://test-address:8443#/WarRoom/4)",
        'type': 'message'
    }

    # verify get my incidents
    my_incidents: str = "```ID         | Name                 | Status      | Type        | Owner       | Created" \
                        "             | Link\n ===========|======================|=============|=============|====" \
                        "=========|=====================|=====\n257        | w                    | Active      | " \
                        "Unclassifie | god         | 2019-07-28 16:42:40 | https://demisto.com/#/WarRoom/257```"
    mocker.patch.object(demisto, 'directMessage', return_value=my_incidents)
    message = 'list my incidents'
    direct_message_handler(integration_context, request_body, conversation, message)
    assert requests_mock.request_history[2].json() == {
        'attachments': [{
            'content': {
                '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
                'body': [{
                    'facts': [
                        {
                            'title': 'ID:',
                            'value': '257'
                        },
                        {
                            'title': 'Name:',
                            'value': 'w'
                        },
                        {
                            'title': 'Status:',
                            'value': 'Active'
                        },
                        {
                            'title': 'Type:',
                            'value': 'Unclassifie'
                        },
                        {
                            'title': 'Owner:',
                            'value': 'god'
                        },
                        {
                            'title': 'Created:',
                            'value': '2019-07-28 16:42:40'
                        },
                        {
                            'title': 'Link:',
                            'value': '[https://demisto.com/#/WarRoom/257](https://demisto.com/#/WarRoom/257)'
                        }
                    ],
                    'type': 'FactSet'
                }],
                'type': 'AdaptiveCard',
                'version': '1.0'
            },
            'contentType': 'application/vnd.microsoft.card.adaptive'
        }],
        'type': 'message'
    }

    # verify error message raised by Demisto server is sent as message as expectec
    mocker.patch.object(
        demisto,
        'directMessage',
        side_effect=ValueError(
            'I\'m sorry but I was unable to find you as a Demisto user for email [johnnydepp@gmail.com]'
        )
    )
    direct_message_handler(integration_context, request_body, conversation, message)
    assert requests_mock.request_history[3].json() == {
        'type': 'message',
        'text': 'I\'m sorry but I was unable to find you as a Demisto user for email [johnnydepp@gmail.com]'
    }


def test_error_parser():
    from MicrosoftTeams import error_parser

    class MockResponse:
        def __init__(self, json_data, status_code, text=''):
            self.json_data = json_data
            self.status_code = status_code
            self.text = text

        def json(self):
            return self.json_data

    # verify bot framework error parsed as expected
    error_description: str = "AADSTS700016: Application with identifier '2bc5202b-ad6a-4458-8821-e104af433bbb' " \
                             "was not found in the directory 'botframework.com'. This can happen if the application " \
                             "has not been installed by the administrator of the tenant or consented to by any user " \
                             "in the tenant. You may have sent your authentication request to the wrong tenant.\r\n" \
                             "Trace ID: 9eaeeec8-7f9e-4fb8-b319-5413581f0a00\r\nCorrelation ID: " \
                             "138cb511-2484-410e-b9c1-14b15accbeba\r\nTimestamp: 2019-08-28 13:18:44Z"

    bot_error_json_response: dict = {
        'error': 'unauthorized_client',
        'error_description': error_description,
        'error_codes': [
            700016
        ],
        'timestamp': '2019-08-28 13:18:44Z',
        'trace_id': '9eaeeec8-7f9e-4fb8-b319-5413581f0a11',
        'correlation_id': '138cb111-2484-410e-b9c1-14b15accbeba',
        'error_uri': 'https://login.microsoftonline.com/error?code=700016'
    }

    bot_error_json_response = MockResponse(bot_error_json_response, 400)
    assert error_parser(bot_error_json_response, 'bot') == error_description

    # verify graph error parsed as expected
    error_code: str = 'InvalidAuthenticationToken'
    error_message: str = 'Access token validation failure.'
    graph_error_json_response: dict = {
        'error': {
            'code': error_code,
            'message': error_message,
            'innerError': {
                'request-id': 'c240ab22-4463-4a1f-82bc-8509d8190a77',
                'date': '2019-08-28T13:37:14'
            }
        }
    }
    graph_error_json_response = MockResponse(graph_error_json_response, 401)
    assert error_parser(graph_error_json_response) == f'{error_code}: {error_message}'


def test_integration_health(mocker):
    from MicrosoftTeams import integration_health
    mocker.patch.object(demisto, 'results')
    expected_results = """### Microsoft API Health
|Bot Framework API Health|Graph API Health|
|---|---|
| Operational | Operational |
### Microsoft Teams Mirrored Channels
|Channel|Investigation ID|Team|
|---|---|---|
| incident-10 | 10 | The-A-Team |
| incident-2 | 2 | The-A-Team |
| booya | 14 | The-A-Team |
"""
    integration_health()

    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['HumanReadable'] == expected_results


def test_create_team(requests_mock, mocker):
    """
    Given:
        - Team display name and owner ID to create team of

    When:
        - Creating a team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    from MicrosoftTeams import create_team
    requests_mock.post('https://graph.microsoft.com/v1.0/teams', status_code=202)
    display_name = 'TestTeamName'
    owner = 'uuid'
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'display_name': display_name,
            'owner': owner,
        }
    )
    mocker.patch.object(demisto, 'results')
    create_team()
    assert requests_mock.request_history[0].json() == {
        'template@odata.bind': "https://graph.microsoft.com/v1.0/teamsTemplates('standard')",
        'displayName': display_name,
        'description': None,
        'visibility': 'public',
        'members': [{
            '@odata.type': '#microsoft.graph.aadUserConversationMember',
            'roles': ['owner'],
            'user@odata.bind': f"https://graph.microsoft.com/v1.0/users('{owner}')",
        }],
        'guestSettings': {
            'allowCreateUpdateChannels': False,
            'allowDeleteChannels': False,
        },
        'memberSettings': {
            'allowCreatePrivateChannels': False,
            'allowCreateUpdateChannels': False,
            'allowDeleteChannels': False,
            'allowAddRemoveApps': False,
            'allowCreateUpdateRemoveTabs': False,
            'allowCreateUpdateRemoveConnectors': False,
        },
        'messagingSettings': {
            'allowUserEditMessages': False,
            'allowUserDeleteMessages': False,
            'allowOwnerDeleteMessages': False,
            'allowTeamMentions': False,
            'allowChannelMentions': False,
        },
    }
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == f'Team {display_name} was created successfully.'


def test_create_team_from_group(requests_mock, mocker):
    """
    Given:
        - Team display name and owner ID to create team of

    When:
        - Creating a team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    from MicrosoftTeams import create_team_from_group
    group_id = 'uuid'
    requests_mock.put(f'https://graph.microsoft.com/v1.0/groups/{group_id}/team', status_code=202)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'group_id': group_id,
        }
    )
    mocker.patch.object(demisto, 'results')
    create_team_from_group()
    assert requests_mock.request_history[0].json() == {
        'displayName': None,
        'description': None,
        'visibility': 'public',
        'guestSettings': {
            'allowCreateUpdateChannels': False,
            'allowDeleteChannels': False,
        },
        'memberSettings': {
            'allowCreatePrivateChannels': False,
            'allowCreateUpdateChannels': False,
            'allowDeleteChannels': False,
            'allowAddRemoveApps': False,
            'allowCreateUpdateRemoveTabs': False,
            'allowCreateUpdateRemoveConnectors': False,
        },
        'messagingSettings': {
            'allowUserEditMessages': False,
            'allowUserDeleteMessages': False,
            'allowOwnerDeleteMessages': False,
            'allowTeamMentions': False,
            'allowChannelMentions': False,
        },
    }
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == f'The team was created from group {group_id} successfully.'


def test_list_teams(requests_mock, mocker):
    """
    Given:
        - Teams list

    When:
        - Listing teams

    Then:
        - Verify entry context is populated as expected
    """
    from MicrosoftTeams import list_teams
    teams = {
        '@odata.context': 'https://graph.microsoft.com/beta/$metadata#groups',
        'value': [
            {
                'id': '02bd9fd6-8f93-4758-87c3-1fb73740a315',
                'displayName': 'MyGreatTeam',
                'groupTypes': [
                    'Unified'
                ],
                'mailEnabled': True,
                'resourceBehaviorOptions': [],
                'resourceProvisioningOptions': [
                    'Team'
                ],
                'securityEnabled': False,
                'visibility': 'Private'
            },
            {
                'id': '8090c93e-ba7c-433e-9f39-08c7ba07c0b3',
                'displayName': 'WooahTeam',
                'groupTypes': [
                    'Unified'
                ],
                'mailEnabled': True,
                'mailNickname': 'X1050LaunchTeam',
                'resourceBehaviorOptions': [],
                'resourceProvisioningOptions': [
                    'Team'
                ],
                'securityEnabled': False,
                'visibility': 'Private'
            }
        ]
    }
    requests_mock.get(
        "https://graph.microsoft.com/beta/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')",
        json=teams
    )
    mocker.patch.object(demisto, 'results')
    list_teams()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['EntryContext']['MicrosoftTeams.Team(val.id == obj.id)'] == teams['value']


def test_update_team(requests_mock, mocker):
    """
    Given:
        - Team ID, display name and member setting to update team with

    When:
        - Updating a team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    from MicrosoftTeams import update_team
    team_id = 'uuid'
    display_name = 'UpdatedDisplayName'
    requests_mock.patch(f'https://graph.microsoft.com/v1.0/teams/{team_id}', status_code=204)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
            'display_name': display_name,
            'allow_channel_mentions': 'true',
        }
    )
    mocker.patch.object(demisto, 'results')
    update_team()
    assert requests_mock.request_history[0].json() == {
        'displayName': display_name,
        'description': None,
        'visibility': None,
        'guestSettings': {
            'allowCreateUpdateChannels': None,
            'allowDeleteChannels': None,
        },
        'memberSettings': {
            'allowCreatePrivateChannels': None,
            'allowCreateUpdateChannels': None,
            'allowDeleteChannels': None,
            'allowAddRemoveApps': None,
            'allowCreateUpdateRemoveTabs': None,
            'allowCreateUpdateRemoveConnectors': None,
        },
        'messagingSettings': {
            'allowUserEditMessages': None,
            'allowUserDeleteMessages': None,
            'allowOwnerDeleteMessages': None,
            'allowTeamMentions': None,
            'allowChannelMentions': True,
        },
    }
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == f'Team {team_id} was updated successfully.'


def test_delete_team(requests_mock, mocker):
    """
    Given:
        - ID of team to delete

    When:
        - Deleting a team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    from MicrosoftTeams import delete_team
    team_id = 'uuid'
    requests_mock.delete(f'https://graph.microsoft.com/v1.0/groups/{team_id}', status_code=204)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
        }
    )
    mocker.patch.object(demisto, 'results')
    delete_team()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == f'Team {team_id} was deleted successfully.'


def test_get_team(requests_mock, mocker):
    """
    Given:
        - ID of team to get

    When:
        - Getting a team

    Then:
        - Ensure expected request body is sent
        - Verify entry context output
    """
    from MicrosoftTeams import get_team
    team = {
        'isArchived': False,
        'discoverySettings': {
            'showInTeamsSearchAndSuggestions': True
        },
        'memberSettings': {
            'allowCreateUpdateChannels': True,
            'allowDeleteChannels': True,
            'allowAddRemoveApps': True,
            'allowCreateUpdateRemoveTabs': True,
            'allowCreateUpdateRemoveConnectors': True
        },
        'guestSettings': {
            'allowCreateUpdateChannels': True,
            'allowDeleteChannels': True
        },
        'messagingSettings': {
            'allowUserEditMessages': True,
            'allowUserDeleteMessages': True,
            'allowOwnerDeleteMessages': True,
            'allowTeamMentions': True,
            'allowChannelMentions': True
        },
        'funSettings': {
            'allowGiphy': True,
            'giphyContentRating': 'strict',
            'allowStickersAndMemes': True,
            'allowCustomMemes': True
        }
    }
    team_id = 'uuid'
    requests_mock.get(f'https://graph.microsoft.com/v1.0/teams/{team_id}', json=team)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
        }
    )
    mocker.patch.object(demisto, 'results')
    get_team()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['EntryContext']['MicrosoftTeams.Team(val.id == obj.id)'] == team


def test_list_members(requests_mock, mocker):
    """
    Given:
        - Team members

    When:
        - Listing team members

    Then:
        - Verify entry context is populated as expected
    """
    from MicrosoftTeams import list_members
    team_id = 'ee0f5ae2-8bc6-4ae5-8466-7daeebb'
    members = {
        '@odata.context': f"https://graph.microsoft.com/v1.0/$metadata#teams('{team_id}')/members",
        '@odata.count': 3,
        'value': [
            {
                '@odata.type': '#microsoft.graph.aadUserConversationMember',
                'id': 'ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM3Mzc2MWYwNi0yYWM5LTQ2OWMtOWYxMC0yNzlhjY3Zjk=',
                'roles': [],
                'displayName': 'Adele Vance',
                'userId': '73761f06-2ac9-469c-9f10-279a8cc267f9',
                'email': 'AdeleV@M365x987948.OnMicrosoft.com'
            },
            {
                '@odata.type': '#microsoft.graph.aadUserConversationMember',
                'id': 'ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM1OThlZmNkNC1lNTQ5LTQwMmEtOTYwMi0MjAxZmFlYmU=',
                'roles': [
                    'owner'
                ],
                'displayName': 'MOD Administrator',
                'userId': '598efcd4-e549-402a-9602-0b50201faebe',
                'email': 'admin@M365x987948.OnMicrosoft.com'
            },
            {
                '@odata.type': '#microsoft.graph.aadUserConversationMember',
                'id': 'MmFiOWM3OTYtMjkwMi00NWY4LWI3MTItN2M1YTYzY2Y0MWM0IyM3NTJmNTBiNy0yNTZmLTQ1MzktYjc3QxMmYyZTQ3MjI=',
                'roles': [],
                'displayName': 'Harry Johnson',
                'userId': '752f50b7-256f-4539-b775-c4d12f2e4722',
                'email': 'harry@M365x987948.OnMicrosoft.com'
            }
        ]
    }
    requests_mock.get(
        f'https://graph.microsoft.com/v1.0/teams/{team_id}/members',
        json=members
    )
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
        }
    )
    list_members()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['EntryContext']['MicrosoftTeams.TeamMember(val.id == obj.id)'] == members['value']


def test_get_member(requests_mock, mocker):
    """
    Given:
        - ID of member to get

    When:
        - Getting a memeber

    Then:
        - Verify entry context output
    """
    from MicrosoftTeams import get_member
    team_id = 'uuid'
    membership_id = 'id'
    member = {
        '@odata.context': f"https://graph.microsoft.com/v1.0/$metadata#teams('{team_id}')/"
                          f"members/microsoft.graph.aadUserConversationMember/$entity",
        '@odata.type': '#microsoft.graph.aadUserConversationMember',
        'id': '/ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM3Mzc2MWYwNi0yYWM5LTQ2OWMtOWYxMC0yNzlhOGNjMjY3Zjk=',
        'roles': ['owner'],
        'displayName': 'John Doe',
        'userId': '8b081ef6-4792-4def-b2c9-c363a1bf41d5',
        'email': None
    }
    requests_mock.get(f'https://graph.microsoft.com/v1.0/teams/{team_id}/members/{membership_id}', json=member)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
            'membership_id': membership_id
        }
    )
    mocker.patch.object(demisto, 'results')
    get_member()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['EntryContext']['MicrosoftTeams.TeamMember(val.id == obj.id)'] == member


def test_add_member(requests_mock, mocker):
    """
    Given:
        - ID of team to the add a user to
        - ID of user to add to a team
    When:
        - Adding a user to the team

    Then:
        - Ensure expected request body is sent
        - Verify entry context output
    """
    from MicrosoftTeams import add_member
    team_id = 'uuid'
    user_id = 'user_id'
    added_member = {
        '@odata.type': '#microsoft.graph.aadUserConversationMember',
        'id': 'ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM3Mzc2MWYwNi0yYWM5LTQ2OWMtOWYxMC0yNzlhOGNjMjY3Zjk=',
        'roles': [
            'owner'
        ],
        'userId': user_id,
        'displayName': 'Cameron White',
        'email': 'CameronW@M365x987948.OnMicrosoft.com'
    }
    requests_mock.post(
        f'https://graph.microsoft.com/v1.0/teams/{team_id}/members',
        json=added_member,
        status_code=201
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
            'user_id': user_id,
            'is_owner': 'true',
        }
    )
    mocker.patch.object(demisto, 'results')
    add_member()
    assert requests_mock.request_history[0].json() == {
        '@odata.type': '#microsoft.graph.aadUserConversationMember',
        'roles': ['owner'],
        'user@odata.bind': f"https://graph.microsoft.com/v1.0/users('{user_id}')"
    }
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['EntryContext']['MicrosoftTeams.TeamMember(val.id == obj.id)'] == added_member


def test_remove_member(requests_mock, mocker):
    """
    Given:
        - ID of team to remove the member from
        - ID of member to remove

    When:
        - Removing a member from team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    from MicrosoftTeams import remove_member
    team_id = 'uuid'
    membership_id = 'id'
    requests_mock.delete(f'https://graph.microsoft.com/v1.0/teams/{team_id}/members/{membership_id}', status_code=204)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
            'membership_id': membership_id,
        }
    )
    mocker.patch.object(demisto, 'results')
    remove_member()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == f'Team member {membership_id} was removed from the team {team_id} successfully.'


def test_update_member(requests_mock, mocker):
    """
    Given:
        - ID of team to update the member in
        - ID of member to update

    When:
        - Updating a member to be team owner

    Then:
        - Ensure expected request body is sent
        - Verify entry context output
    """
    from MicrosoftTeams import update_member
    team_id = 'uuid'
    membership_id = 'id'
    updated_member = {
        "@odata.context": f"https://graph.microsoft.com/v1.0/$metadata#teams('{team_id}')/members/"
                          f"microsoft.graph.aadUserConversationMember/$entity",
        '@odata.type': '#microsoft.graph.aadUserConversationMember',
        'id': 'ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM3Mzc2MWYwNi0yYWM5LTQ2OWMtOWYxMC0yNzlhOGNjMjY3Zjk=',
        'roles': ['owner'],
        'displayName': 'John Doe',
        'userId': '8b081ef6-4792-4def-b2c9-c363a1bf41d5',
        'email': None
    }
    requests_mock.patch(
        f'https://graph.microsoft.com/v1.0/teams/{team_id}/members/{membership_id}',
        json=updated_member
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
            'membership_id': membership_id,
            'is_owner': 'true',
        }
    )
    mocker.patch.object(demisto, 'results')
    update_member()
    assert requests_mock.request_history[0].json() == {
        '@odata.type': '#microsoft.graph.aadUserConversationMember',
        'roles': ['owner']
    }
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['EntryContext']['MicrosoftTeams.TeamMember(val.id == obj.id)'] == updated_member


def test_archive_team(requests_mock, mocker):
    """
    Given:
        - ID of team to archive

    When:
        - Archiving a team

    Then:
        - Verify human readable output
    """
    from MicrosoftTeams import archive_team
    team_id = 'uuid'
    requests_mock.post(f'https://graph.microsoft.com/v1.0/teams/{team_id}/archive', status_code=202)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
        }
    )
    mocker.patch.object(demisto, 'results')
    archive_team()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == f'Team {team_id} was archived successfully.'


def test_unarchive_team(requests_mock, mocker):
    """
    Given:
        - ID of team to unarchive

    When:
        - Unarchiving a team

    Then:
        - Verify human readable output
    """
    from MicrosoftTeams import unarchive_team
    team_id = 'uuid'
    requests_mock.post(f'https://graph.microsoft.com/v1.0/teams/{team_id}/unarchive', status_code=202)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
        }
    )
    mocker.patch.object(demisto, 'results')
    unarchive_team()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == f'Team {team_id} was unarchived successfully.'


def test_clone_team(requests_mock, mocker):
    """
    Given:
        - ID of team to clone
        - Display name of cloned team

    When:
        - Cloning a team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    from MicrosoftTeams import clone_team
    team_id = 'uuid'
    display_name = 'TestClonedTeam'
    requests_mock.post(f'https://graph.microsoft.com/v1.0/teams/{team_id}/clone', status_code=202)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_id': team_id,
            'display_name': display_name,
        }
    )
    mocker.patch.object(demisto, 'results')
    clone_team()
    assert requests_mock.request_history[0].json() == {
        'displayName': display_name,
        'mailNickname': display_name,
        'description': None,
        'visibility': None,
        'partsToClone': 'apps,tabs,settings,channels',
    }
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == f'Team {team_id} was cloned successfully.'


def test_list_joined_teams(requests_mock, mocker):
    """
    Given:
        - ID of user to get teams for

    When:
        - Listing user teams

    Then:
        - Verify entry context is populated as expected
    """
    from MicrosoftTeams import list_joined_teams
    user_id = 'id'
    teams = {
        '@odata.context': 'https://graph.microsoft.com/beta/$metadata#groups',
        'value': [
            {
                'id': '02bd9fd6-8f93-4758-87c3-1fb73740a315',
                'displayName': 'MyGreatTeam',
                'groupTypes': [
                    'Unified'
                ],
                'mailEnabled': True,
                'resourceBehaviorOptions': [],
                'resourceProvisioningOptions': [
                    'Team'
                ],
                'securityEnabled': False,
                'visibility': 'Private'
            },
            {
                'id': '8090c93e-ba7c-433e-9f39-08c7ba07c0b3',
                'displayName': 'WooahTeam',
                'groupTypes': [
                    'Unified'
                ],
                'mailEnabled': True,
                'mailNickname': 'X1050LaunchTeam',
                'resourceBehaviorOptions': [],
                'resourceProvisioningOptions': [
                    'Team'
                ],
                'securityEnabled': False,
                'visibility': 'Private'
            }
        ]
    }
    requests_mock.get(
        f'https://graph.microsoft.com/v1.0/users/{user_id}/joinedTeams',
        json=teams
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'user_id': user_id,
        }
    )
    mocker.patch.object(demisto, 'results')
    list_joined_teams()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['EntryContext']['MicrosoftTeams.Team(val.id == obj.id)'] == teams['value']
