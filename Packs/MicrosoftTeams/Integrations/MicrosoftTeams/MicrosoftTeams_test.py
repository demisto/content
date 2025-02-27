import demistomock as demisto
import pytest
from CommonServerPython import *  # noqa: F401
from requests import Response

entryTypes['warning'] = 11

GRAPH_BASE_URL: str = 'https://graph.microsoft.com'

BASE_URL = "https://graph.microsoft.com/v1.0/groups"

bot_id: str = '9bi5353b-md6a-4458-8321-e924af433amb'

tenant_id: str = 'pbae9ao6-01ql-249o-5me3-4738p3e1m941'

team_id: str = '19:21f27jk08d1a487fa0f5467779619827@thread.skype'

channel_id: str = "19:4b6bed8d24574f6a9e436813cb2617d8@thread.tacv2"

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
        'email': 'bwillis@email.com',
        'tenantId': tenant_id
    },
    {
        'id': '29:1pBMMC85IyjM3tr_MCZi7KW4pw4EULxLN4C7R_xoi3Wva_lOn3VTf7xJlCLK-r-pMumrmoz9agZxsSrCf7__u9R',
        'objectId': '2826c1p7-bdb6-4529-b57d-2598me968631',
        'name': 'Denzel Washington',
        'givenName': 'Denzel',
        'surname': 'Washington',
        'email': 'DwashintoN@email.com',
        'userPrincipalName': 'DwashintoN@email.com',
        'tenantId': tenant_id
    }
]

channel_members: dict = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#teams('2ab9c796-2902-45f8-b712-7c5a63cf41c4')/"
                      "channels('19%3A20bc1df46b1148e9b22539b83bc66809%40thread.skype')/members",
    "@odata.count": 2,
    "value": [
        {
            "@odata.type": "#microsoft.graph.aadUserConversationMember",
            "id": "MmFiOWM3OTYtMjkwMi00NWY4LWI3MTItN2M1YTYzY2Y0MWM0IyNlZWY5Y2IzNi0wNmRlLTQ2OWItODdjZC03MGY0Y2JlMzJkMTQ=",
            "roles": [],
            "displayName": "Jane Doe",
            "userId": "eef9cb36-06de-469b-87cd-70f4cbe32d14",
            "email": "jdoe@teamsip.onmicrosoft.com",
            "tenantId": tenant_id,
            "visibleHistoryStartDateTime": "0001-01-01T00:00:00Z"
        },
        {
            "@odata.type": "#microsoft.graph.aadUserConversationMember",
            "id": "MmFiOWM3OTYtMjkwMi00NWY4LWI3MTItN2M1YTYzY2Y0MWM0IyNiMzI0NmY0NC1jMDkxLTQ2MjctOTZjNi0yNWIxOGZhMmM5MTA=",
            "roles": [
                "owner"
            ],
            "displayName": "Ace John",
            "userId": "b3246f44-c091-4627-96c6-25b18fa2c910",
            "email": "ajohn@teamsip.onmicrosoft.com",
            "tenantId": tenant_id,
            "visibleHistoryStartDateTime": "0001-01-01T00:00:00Z"
        }
    ]
}

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

CLIENT_CREDENTIALS_FLOW = 'Client Credentials'
AUTHORIZATION_CODE_FLOW = 'Authorization Code'
ONEONONE_CHAT_ID = "19:09ddc990-3821-4ceb-8019-24d39998f93e_48d31887-5fad-4d73-a9f5-3c356e68a038@unq.gbl.spaces"
GROUP_CHAT_ID = "19:2da4c29f6d7041eca70b638b43d45437@thread.v2"


def util_load_json(path: str):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


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
        'current_refresh_token': '',
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
        'description': 'Channel to mirror incident 2',
        'membershipType': 'standard'
    }
    assert requests_mock.request_history[3].json() == {
        'text': 'This channel was created to mirror [incident 2](https://test-address:8443/#/WarRoom/2) between '
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
        'description': 'Channel to mirror incident 14',
        'membershipType': 'standard'
    }
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'Investigation mirrored successfully in channel booya.'


@pytest.mark.parametrize('args', [
    ({'messageType': 'mirrorEntry', 'originalMessage': 'a mirrored message\n**From Microsoft Teams**'}),
    ({'messageType': 'incidentOpened', 'severity': 1})])
def test_send_message_with_mirrored_message_or_low_severity(mocker, args):
    # verify that a mirrored message is skipped
    # verify notification from server with severity below threshold is not sent
    from MicrosoftTeams import send_message
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'min_incident_severity': 'Medium',
            'team': 'The-A-Team'
        }
    )
    mocker.patch.object(demisto, 'args', return_value=args)
    assert send_message() is None


# def test_send_message_with_low_severity(mocker):
#     # verify notification from server with severity below threshold is not sent
#     mocker.patch.object(
#         demisto,
#         'params',
#         return_value={
#             'min_incident_severity': 'Medium',
#             'team': 'The-A-Team'
#         }
#     )
#     mocker.patch.object(
#         demisto,
#         'args',
#         return_value={
#             'messageType': 'incidentOpened',
#             'severity': 1
#         }
#     )
#     assert send_message() is None


@pytest.mark.parametrize('args, result', [({}, 'No channel or team member to send message were provided.'),
                                          ({'channel': 'somechannel', 'team_member': 'someuser'},
                                           'Provide either channel or team member to send message to, not both.'),
                                          ({'channel': 'channel', 'adaptive_card': 'THISisSTRINGnotJSON'},
                                           'Given adaptive card is not in valid JSON format.'),
                                          ({'channel': 'channel', 'message': 'message', 'adaptive_card': '{"a":"b"}'},
                                           'Provide either message or adaptive to send, not both.'),
                                          ({'channel': 'channel'},
                                           'No message or adaptive card to send were provided.')])
def test_send_message_raising_errors(mocker, args, result):
    # verify error is raised if no user/channel were provided.
    # verify error is raised if user and channel provided.
    # verify proper error is raised if invalid JSON provided as adaptive card.
    # verify proper error is raised if both message and adaptive card were provided.
    # verify proper error is raised if neither message or adaptive card were provided.

    from MicrosoftTeams import send_message
    mocker.patch.object(demisto, 'args', return_value=args)
    with pytest.raises(ValueError) as e:
        send_message()
    assert str(e.value) == result


@pytest.mark.parametrize('message', ['MESSAGE', '891f1e9d-b8c3-4e24-bfbb-c44bcca4d586',
                                     'testing 891f1e9d-b8c3-4e24-bfbb-c44bcca4d586 testing'])
def test_send_message_with_user(mocker, requests_mock, message):
    """
    Given:
        - a message as a basic string and a  message that contains GUID.
    When:
        - running send message function.
    Then:
        - The message is sent successfully in both cases.
    """
    # verify message is sent properly given user to send to
    from MicrosoftTeams import send_message
    mocker.patch.object(demisto, 'results')

    expected = util_load_json('test_data/send_message/expected_generic.json')
    raw = util_load_json('test_data/send_message/raw_generic.json')

    mocker.patch("MicrosoftTeams.BOT_ID", new=bot_id)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_member': 'Denzel Washington',
            'message': message
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
        json=raw
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
    assert results[0] == expected


def test_send_message_with_channel(mocker, requests_mock):
    # verify message is sent properly given channel
    from MicrosoftTeams import send_message
    mocker.patch.object(demisto, 'results')
    mocker.patch('MicrosoftTeams.get_channel_type', return_value='standard')

    expected = util_load_json('test_data/send_message/expected_generic.json')
    raw = util_load_json('test_data/send_message/raw_generic.json')

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
        json=raw
    )
    send_message()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == expected


def test_send_message_with_entitlement(mocker, requests_mock):
    # verify message is sent properly given entitlement
    from MicrosoftTeams import send_message
    mocker.patch.object(demisto, 'results')

    expected = util_load_json('test_data/send_message/expected_generic.json')
    raw = util_load_json('test_data/send_message/raw_generic.json')

    message: dict = {
        'message_text': 'is this really working?',
        'options': ['yes', 'no', 'maybe'],
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8',
        'investigation_id': '72',
        'task_id': '23',
        'form_type': 'predefined-options'
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_member': 'dwashinton@email.com',
            'message': json.dumps(message)
        }
    )
    requests_mock.post(
        f'{service_url}/v3/conversations',
        json={'id': 'conversation-id'})
    requests_mock.post(
        f'{service_url}/v3/conversations/conversation-id/activities',
        json=raw
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
                    'type': 'TextBlock',
                    'wrap': True
                }],
                'type': 'AdaptiveCard',
                'msteams': {
                    'width': 'Full'
                },
                'version': '1.0'
            },
            'contentType': 'application/vnd.microsoft.card.adaptive'
        }],
        'type': 'message'
    }

    send_message()

    assert requests_mock.request_history[1].json() == expected_ask_user_message
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == expected


def test_send_message_with_adaptive_card(mocker, requests_mock):
    # verify adaptive card sent successfully
    from MicrosoftTeams import send_message
    mocker.patch.object(demisto, 'results')

    expected = util_load_json('test_data/send_message/expected_generic.json')
    raw = util_load_json('test_data/send_message/raw_generic.json')

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
    requests_mock.post(
        f'{service_url}/v3/conversations',
        json={'id': 'conversation-id'})
    requests_mock.post(
        f'{service_url}/v3/conversations/conversation-id/activities',
        json=raw
    )
    send_message()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == expected


def test_sending_message_using_email_address(mocker, requests_mock):
    from MicrosoftTeams import send_message
    mocker.patch.object(demisto, 'results')

    expected = util_load_json('test_data/send_message/expected_generic.json')
    raw = util_load_json('test_data/send_message/raw_generic.json')

    # verify message is sent properly given email with uppercase letters to send to
    mocker.patch("MicrosoftTeams.BOT_ID", new=bot_id)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'team_member': 'DwashinTon@email.com',
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
        json=raw
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
    assert results[0] == expected


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
    mocker.patch('MicrosoftTeams.get_channel_type', return_value='standard')

    expected = util_load_json('test_data/send_message/expected_generic.json')
    raw = util_load_json('test_data/send_message/raw_generic.json')

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
            'message': 'user has reported an incident tadam.\nView it on https://server/#/WarRoom/3247',
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
        json=raw
    )

    send_message()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == expected


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
    mocker.patch('MicrosoftTeams.get_channel_type', return_value='standard')

    expected = util_load_json('test_data/send_message/expected_generic.json')
    raw = util_load_json('test_data/send_message/raw_generic.json')

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
            'message': 'DBot has updated an incident tadam.\nView it on https://server/#/WarRoom/3247',
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
        json=raw
    )
    send_message()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == expected


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


@pytest.mark.parametrize('message, expected_result', [
    ("Visit https://github.com/demisto/content and https://xsoar.pan.dev",
     "Visit [https://github.com/demisto/content](https://github.com/demisto/content) and "
     "[https://xsoar.pan.dev](https://xsoar.pan.dev)"),
    ("Link: https://xsoar.pan.dev/page?parametized=true",
     "Link: [https://xsoar.pan.dev/page?parametized=true](https://xsoar.pan.dev/page?parametized=true)"),
    ("This is a link https://paloaltonetworks.com/. This is a [Custom URL](https://paloaltonetworks.com/)",
     "This is a link [https://paloaltonetworks.com/.](https://paloaltonetworks.com/.) This is a [Custom URL]("
     "https://paloaltonetworks.com/)"),
    ("This is a [Custom URL](https://paloaltonetworks.com/), This is a link https://paloaltonetworks.com/",
     "This is a [Custom URL](https://paloaltonetworks.com/), "
     "This is a link [https://paloaltonetworks.com/](https://paloaltonetworks.com/)"),
])
def test_urlify_hyperlinks(message: str, expected_result: str):
    from MicrosoftTeams import urlify_hyperlinks
    assert urlify_hyperlinks(message) == expected_result


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

    json_response = {
        '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#groups',
        'value': [
            {
                'id': '02bd9fd6-8f93-4758-87c3-1fb73740a315',
                'displayName': 'MyGreat #Team',
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
    # verify non existing team raises value error
    url_a = f"{BASE_URL}?$filter=displayName eq 'The-B-Team' and resourceProvisioningOptions/Any(x:x eq 'Team')"
    requests_mock.get(url_a, json=json_response)
    with pytest.raises(ValueError) as e:
        get_team_aad_id('The-B-Team')
    assert str(e.value) == 'Could not find requested team.'

    url_b = f"{BASE_URL}?$filter=displayName eq 'MyGreat%20%23Team' and resourceProvisioningOptions/Any(x:x eq 'Team')"
    requests_mock.get(url_b, json=json_response)

    # verify team ID for team which is not in integration context
    assert get_team_aad_id('MyGreat #Team') == '02bd9fd6-8f93-4758-87c3-1fb73740a315'


def test_get_team_member():
    from MicrosoftTeams import get_team_member
    user_id: str = '29:1KZccCJRTxlPdHnwcKfxHAtYvPLIyHgkSLhFSnGXLGVFlnltovdZPmZAduPKQP6NrGqOcde7FXAF7uTZ_8FQOqg'
    team_member: dict = {
        'username': 'Bruce Willis',
        'user_email': 'bwillis@email.com',
        'user_principal_name': 'bwillis@email.com',
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
            'msteams': {
                'width': 'Full'
            },
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
            'msteams': {
                'width': 'Full'
            },
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
            'msteams': {
                'width': 'Full'
            },
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
            'msteams': {
                'width': 'Full'
            },
            'body': [{
                'type': 'TextBlock',
                'text': 'I can understand the following commands:\n\nlist incidents [page x]\n\nlist my incidents [page'
                        ' x]\n\nlist my tasks\n\nlist closed incidents\n\nnew incident [details]\n\nmirror incident-id',
                'wrap': True
            }]
        }
    }
    assert process_mirror_or_unknown_message(message) == expected_adaptive_card


def test_get_participant_info():
    from MicrosoftTeams import get_participant_info
    participants = {'organizer': {'upn': 'mail.com', 'role': 'presenter',
                                  'identity': {'phone': None, 'guest': None, 'encrypted': None,
                                               'onPremises': None, 'applicationInstance': None,
                                               'application': None, 'device': None,
                                               'user':
                                                   {'id': 'id_identifier',
                                                    'displayName': 'best_user',
                                                    'tenantId': 'tenantId_identifier',
                                                    'identityProvider': 'AAD'}}}, 'attendees': []}
    participant_id, participant_display_name = get_participant_info(participants)
    assert participant_id == 'id_identifier'
    assert participant_display_name == 'best_user'


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


def test_create_meeting_command(requests_mock, mocker):
    from MicrosoftTeams import create_meeting_command
    mocker.patch.object(demisto, 'args', return_value={"subject": "Best_Meeting", "member": "username"})
    mocker.patch.object(demisto, 'results')
    requests_mock.get(
        'https://graph.microsoft.com/v1.0/users',
        json={"value": [{"id": "userid1"}]}
    )

    requests_mock.post(
        'https://graph.microsoft.com/v1.0/users/userid1/onlineMeetings',
        json={
            "chatInfo": {
                "threadId": "19:@thread.skype",
                "messageId": "0",
                "replyChainMessageId": "0"
            },
            "creationDateTime": "2019-07-11T02:17:17.6491364Z",
            "startDateTime": "2019-07-11T02:17:17.6491364Z",
            "endDateTime": "2019-07-11T02:47:17.651138Z",
            "id": "id_12345",
            "joinWebUrl": "https://teams.microsoft.com/l/meetup-join/12345",
            "participants": {
                "organizer": {
                    "identity": {
                        "user": {
                            "id": "user_id_12345",
                            "displayName": "Demisto"
                        }
                    },
                    "upn": "upn-value"
                }
            },
            "subject": "User Token Meeting"
        }
    )

    expected_results = 'The meeting "Best_Meeting" was created successfully'
    create_meeting_command()
    results = demisto.results.call_args[0]

    assert len(results) == 1
    assert results[0]['HumanReadable'] == expected_results
    assert results[0]['Contents'].get('id') == 'id_12345'


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
                'msteams': {
                    'width': 'Full'
                },
                'body': [{
                    'type': 'TextBlock', 'text': 'OMG!'
                }]
            }
        }]
    }
    update_message(service_url, conversation_id, activity_id, 'OMG!')
    assert requests_mock.request_history[0].method == 'PUT'
    assert json.loads(requests_mock.request_history[0].body) == expected_conversation


# def test_create_team(mocker, requests_mock):
#     from MicrosoftTeams import create_team
#     mocker.patch.object(
#         demisto,
#         'args',
#         return_value={
#             'display_name': 'OhMyTeam',
#             'mail_nickname': 'NoNicknamesPlease',
#             'owner': 'nonexistingmmember@demisto.com',
#             'mail_enabled': 'true',
#             'security_enabled': 'false'
#         }
#     )
#     requests_mock.get(
#         f'https://graph.microsoft.com/v1.0/users',
#         json={
#             'value': team_members
#         }
#     )
#     with pytest.raises(ValueError) as e:
#         create_team()
#     assert str(e.value) == 'Could not find given users to be Team owners.'
#     mocker.patch.object(
#         demisto,
#         'args',
#         return_value={
#             'display_name': 'OhMyTeam',
#             'mail_nickname': 'NoNicknamesPlease',
#             'owner': 'dwashinton@email.com'
#         }
#     )


def test_direct_message_handler(mocker, requests_mock):
    from MicrosoftTeams import direct_message_handler

    mocker.patch('MicrosoftTeams.get_graph_access_token', return_value="token")
    mocker.patch('MicrosoftTeams.get_bot_access_token', return_value="token")

    create_incidents_mocker = mocker.patch.object(
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

    expected_created_incident: list = [
        {
            'name': 'GoFish',
            'type': 'Phishing',
            'rawJSON': '{"from": {"id": '
                       '"29:1KZccCJRTxlPdHnwcKfxHAtYvPLIyHgkSLhFSnGXLGVFlnltovdZPmZAduPKQP6NrGqOcde7FXAF7uTZ_8FQOqg", '
                       '"username": "Bruce Willis", "user_email": "bwillis@email.com", '
                       '"user_principal_name": "bwillis@email.com"}}'
        }
    ]
    expected_assigned_user = 'nice-demisto-id'

    # verify create incident fails on un allowed external incident creation and non found user
    message: str = 'create incident name=GoFish type=Phishing'
    mocker.patch.object(demisto, 'findUser', return_value=None)
    direct_message_handler(integration_context, request_body, conversation, message)

    response = requests_mock.request_history[0].json()

    assert response['type'] == "message"
    assert response['text'] == \
        "I\'m sorry but I was unable to find you as a Cortex XSOAR user for bwillis@email.com. " \
        "You're not allowed to run any command"

    # verify create incident successfully
    mocker.patch.object(demisto, 'findUser', return_value={'id': 'nice-demisto-id'})
    direct_message_handler(integration_context, request_body, conversation, message)
    response = requests_mock.request_history[1].json()

    assert response['type'] == "message"
    assert response['text'] == "Successfully created incident incidentnumberfour.\n" \
                               "View it on: [https://test-address:8443/#/WarRoom/4]" \
                               "(https://test-address:8443/#/WarRoom/4)"

    create_incidents_mocker.assert_called_with(expected_created_incident, userID=expected_assigned_user)

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
                'msteams': {
                    'width': 'Full'
                },
                'version': '1.0'
            },
            'contentType': 'application/vnd.microsoft.card.adaptive'
        }],
        'type': 'message'
    }

    # verify error message raised by Demisto server is sent as message as expected
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


def load_test_data(path):
    with open(path) as f:
        return json.load(f)


@pytest.mark.parametrize('args, mock_res_create_channel', [
    ({'channel_name': 'Private Channel', 'description': 'Private Channel test', 'team': 'TestTeam',
      'membership_type': 'private'}, {"id": 'channel_id'}),
    ({'channel_name': 'Shared Channel', 'description': 'Shared Channel test', 'team': 'TestTeam',
      'membership_type': 'shared'}, {}),
    ({'channel_name': 'Default Standard Channel', 'description': 'Standard Channel test', 'team': 'TestTeam'},
     {"id": 'channel_id'}),
    ({'channel_name': 'Standard Channel', 'description': 'Standard Channel test', 'team': 'TestTeam',
      'membership_type': 'standard', 'owner_user': 'jacob@contoso.com'}, {"id": 'channel_id'}),
])
def test_create_channel_command(mocker, requests_mock, args, mock_res_create_channel):
    """
    Given:
      - case 1: request to create private channel without specify owner_user
      - case 2: request to create shared channel without specify owner_user
      - case 3: request to create standard channel without specify owner_user and membership_type
      - case 4: request to create standard channel with specify owner_user
    When:
      -  Executing the 'microsoft-teams-create-channel' command.
    Then:
        - Ensure expected request body (in the post request to create channel) is sent.
        - Verify human-readable output
     """
    from MicrosoftTeams import create_channel_command
    mocker.patch.object(demisto, 'args', return_value=args)

    owner_user = demisto.args().get('owner_user')
    channel_name = demisto.args().get('channel_name')
    channel_description = demisto.args().get('description')
    membership_type = demisto.args().get('membership_type', 'standard')

    mocker.patch('MicrosoftTeams.get_user', return_value=[{'id': 'user_id', 'userType': 'Member'}])
    mocker.patch('MicrosoftTeams.get_team_aad_id', return_value=team_aad_id)
    mocker.patch("MicrosoftTeams.AUTH_TYPE", new=AUTHORIZATION_CODE_FLOW)

    # create_channel mock request
    requests_mock.post(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels',
        json=mock_res_create_channel  # The response object shown here is shortened.
    )

    expected_json = {
        'displayName': channel_name,
        'description': channel_description,
        'membershipType': membership_type
    }
    if owner_user:
        expected_json['members'] = [
            {
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "user@odata.bind": "https://graph.microsoft.com/v1.0/users('user_id')",
                "roles": ["owner"]
            }]

    mocker.patch.object(demisto, 'results')
    create_channel_command()
    assert requests_mock.request_history[0].json() == expected_json

    expected_results = f'The channel "{channel_name}" was created successfully'
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == expected_results


@pytest.mark.parametrize("args, expected_error", [
    ({"channel_name": "test private", "team": "TeamTest", "membership_type": 'private'},
     "When using the 'Client Credentials flow', you must specify an 'owner_user'."),
    ({"channel_name": "test private", "team": "TeamTest", "membership_type": 'private', "owner_user": 'no_user'},
     "The given owner_user \"no_user\" was not found")])
def test_create_channel_command_errors(mocker, args, expected_error):
    """
   Given:
     - The command arguments without the 'owner_user' argument using the 'Client Credentials flow'
     - The command arguments with 'owner_user' that doesn't exist
   When:
      -  Executing the 'microsoft-teams-create-channel' command.
   Then:
     - The expected error is raised
   """
    from MicrosoftTeams import create_channel_command
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('MicrosoftTeams.get_user', return_value=[])

    with pytest.raises(ValueError) as e:
        create_channel_command()
    assert str(e.value) == expected_error


expected_hr_user_list = ('### Channel "Test Channel" Members List:\n'
                         '|User Id|Email|Tenant Id|Membership id|User roles|Display Name|Start '
                         'DateTime|\n'
                         '|---|---|---|---|---|---|---|\n'
                         '| eef9cb36-06de-469b-87cd-70f4cbe32d14 | jdoe@teamsip.onmicrosoft.com | '
                         'pbae9ao6-01ql-249o-5me3-4738p3e1m941 | '
                         'MmFiOWM3OTYtMjkwMi00NWY4LWI3MTItN2M1YTYzY2Y0MWM0IyNlZWY5Y2IzNi0wNmRlLTQ2OWItODdjZC03MGY0Y2JlMzJkMTQ= '
                         '|  | Jane Doe | 0001-01-01T00:00:00Z |\n'
                         '| b3246f44-c091-4627-96c6-25b18fa2c910 | ajohn@teamsip.onmicrosoft.com | '
                         'pbae9ao6-01ql-249o-5me3-4738p3e1m941 | '
                         'MmFiOWM3OTYtMjkwMi00NWY4LWI3MTItN2M1YTYzY2Y0MWM0IyNiMzI0NmY0NC1jMDkxLTQ2MjctOTZjNi0yNWIxOGZhMmM5MTA= '
                         '| owner | Ace John | 0001-01-01T00:00:00Z |\n')


def test_channel_user_list_command(mocker):
    """
    Given:
      - The command arguments
    When:
      - Executing the 'microsoft-teams-channel-user-list' command.
    Then:
      - Verify human-readable output
      - Verify entry context output
    """
    from MicrosoftTeams import channel_user_list_command
    mocker.patch.object(demisto, 'args', return_value={"channel_name": "Test Channel", "team": "TestTeam"})

    return_results = mocker.patch('MicrosoftTeams.return_results')

    mocker.patch('MicrosoftTeams.get_team_aad_id', return_value=team_aad_id)
    mocker.patch('MicrosoftTeams.get_channel_id', return_value=channel_id)
    get_channel_members_expected_response = channel_members.get('value', [])
    mocker.patch('MicrosoftTeams.get_channel_members', return_value=get_channel_members_expected_response)

    channel_user_list_command()

    results_hr = return_results.call_args[0][0].readable_output
    results_outputs = return_results.call_args[0][0].outputs
    assert results_hr == expected_hr_user_list
    [member.pop('@odata.type', None) for member in get_channel_members_expected_response]
    expected_outputs = {'channelName': "Test Channel", "channelId": channel_id,
                        'members': get_channel_members_expected_response}
    assert results_outputs == expected_outputs


def test_get_channel_members(requests_mock):
    """
    Given:
      - The function arguments team_id, channel_id
    When:
      - Calling the get_channel_members function
    Then:
      - The function returns the expected value
    """
    from MicrosoftTeams import get_channel_members
    requests_mock.get(
        f'{GRAPH_BASE_URL}/v1.0/teams/{team_aad_id}/channels/{channel_id}/members',
        json=channel_members
    )
    assert get_channel_members(team_aad_id, channel_id) == channel_members.get('value', [])


membership_id = "ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM3Mzc2MWYwNi0yYWM5LTQ2OWMtOWYxMC0yNzlhOGNjMjY3Zjk="


@pytest.mark.parametrize("channel_type, expected_exception, mock_get_membership_id, expected_error_value", [
    ('private', None, membership_id, None),
    ('shared', None, membership_id, None),
    ('standard', ValueError, None, 'Removing a member is allowed only for private or shared channels.'),
    ('shared', ValueError, '', 'User \"itayadmin\" was not found in channel \"test channel\".')
])
def test_user_remove_from_channel_command(mocker, requests_mock, channel_type, expected_exception,
                                          mock_get_membership_id, expected_error_value):
    """
       Given:
         - The commands arguments
       When:
         - Executing the 'microsoft-teams-user-remove-from-channel' command.
       Then:
        - Verify human-readable output
        - Verify the expected error is raised.
       """
    from MicrosoftTeams import user_remove_from_channel_command

    mocker.patch.object(demisto, 'args',
                        return_value={"channel_name": "test channel", "team": "test team", "member": "itayadmin"})

    mocker.patch('MicrosoftTeams.get_team_aad_id', return_value=team_aad_id)
    mocker.patch('MicrosoftTeams.get_channel_id', return_value=channel_id)
    mocker.patch('MicrosoftTeams.get_channel_type', return_value=channel_type)
    mocker.patch('MicrosoftTeams.get_user_membership_id', return_value=mock_get_membership_id)
    return_results = mocker.patch('MicrosoftTeams.return_results')
    requests_mock.delete(
        f'https://graph.microsoft.com/v1.0/teams/{team_aad_id}/channels/{channel_id}/members/{membership_id}',
        status_code=204
    )

    if expected_exception:
        with pytest.raises(ValueError) as e:
            user_remove_from_channel_command()
        assert str(e.value) == expected_error_value

    else:
        user_remove_from_channel_command()
        assert requests_mock.request_history[0].method == 'DELETE'
        results_hr = return_results.call_args[0][0]
        assert results_hr == 'The user "itayadmin" has been removed from channel "test channel" successfully.'


# All the responses based on: https://learn.microsoft.com/en-us/graph/api/
test_data = load_test_data('./test_data/chats_test_data.json')


def test_chat_create_command(mocker):
    """
    Given:
      - The command arguments to create group chat
    When:
      - Executing the 'microsoft-teams-chat-create' command.
    Then:
        - Verify human-readable output
        - Verify entry context output
    """
    from MicrosoftTeams import chat_create_command
    mocker.patch.object(demisto, 'args', return_value={"chat_type": "group", "chat_name": "Group_chat",
                                                       "member": "testuser1@example.com"})

    api_response = test_data.get('create_group_chat')
    expected_hr_create_chat = test_data.get('expected_hr_create_chat')
    return_results = mocker.patch('MicrosoftTeams.return_results')

    mocker.patch('MicrosoftTeams.get_user', return_value=[{'id': 'user1', 'userType': "Member"}])
    mocker.patch('MicrosoftTeams.create_chat', return_value=api_response)
    mocker.patch('MicrosoftTeams.add_bot_to_chat', return_value='')

    chat_create_command()

    results_hr = return_results.call_args[0][0].readable_output
    results_outputs = return_results.call_args[0][0].outputs
    assert results_hr == expected_hr_create_chat
    api_response.pop('@odata.context', '')
    assert results_outputs == api_response


@pytest.mark.parametrize('chat_type, users, expected_request_json, chat_response', [
    ("group", [("8b081ef6-4792-4def-b2c9-c363a1bf41d5", "Member"), ("82af01c5-f7cc-4a2e-a728-3a5df21afd9d", "Guest")],
     "group_request_json", "create_group_chat"),
    ("oneOnOne", [("8b081ef6-4792-4def-b2c9-c363a1bf41d5", "Member")], "oneOnOne_request_json", "create_oneOnOne_chat")
])
def test_creat_chat(mocker, requests_mock, chat_type, users, expected_request_json, chat_response):
    """
    Given:
      - The function arguments chat_type, users
    When:
      - Calling the create_chat function
    Then:
      - Ensure expected request body is sent
    """
    from MicrosoftTeams import create_chat
    signed_in_response = test_data.get('signed_in_user')
    mocker.patch('MicrosoftTeams.get_signed_in_user', return_value=signed_in_response)

    requests_mock.post(
        'https://graph.microsoft.com/v1.0/chats',
        json=chat_response
    )
    create_chat(chat_type, users, "Group chat title")  # the chat name will not be used in oneOnOne chats - only in group

    assert requests_mock.request_history[0].json() == test_data.get(expected_request_json)


def test_message_send_to_chat_command(mocker, requests_mock):
    """
    Given:
      - The command arguments
    When:
      - Executing the 'microsoft-teams-message-send-to-chat' command.
    Then:
      - Assert the request url is as expected
      - Verify human-readable output
      - Verify entry context output
    """
    from MicrosoftTeams import message_send_to_chat_command
    mocker.patch.object(demisto, 'args', return_value={"content": "Hello World"})
    return_results = mocker.patch('MicrosoftTeams.return_results')

    mock_response = test_data.get('send_message_chat')

    mocker.patch('MicrosoftTeams.get_chat_id_and_type', return_value=(GROUP_CHAT_ID, 'group'))
    mocker.patch('MicrosoftTeams.add_bot_to_chat', return_value='')
    requests_mock.post(
        f'{GRAPH_BASE_URL}/v1.0/chats/{GROUP_CHAT_ID}/messages',
        json=mock_response
    )
    message_send_to_chat_command()

    assert requests_mock.request_history[0].json() == {"body": {"content": "Hello World", "contentType": "text"},
                                                       "messageType": "message"}
    results_hr = return_results.call_args[0][0].readable_output
    results_outputs = return_results.call_args[0][0].outputs
    assert results_hr == test_data.get('expected_hr_send_message')
    mock_response.pop('@odata.context', '')
    expected_outputs = {'chatId': GROUP_CHAT_ID, 'messages': mock_response}
    assert results_outputs == expected_outputs


def test_chat_member_list_command(mocker, requests_mock):
    """
    Given:
      - The command arguments
    When:
      - Executing the 'microsoft-teams-chat-member-list' command.
    Then:
      - Assert the request url is as expected
      - Verify human-readable output
      - Verify entry context output
    """
    from MicrosoftTeams import chat_member_list_command
    mocker.patch.object(demisto, 'args', return_value={"chat": ONEONONE_CHAT_ID})
    return_results = mocker.patch('MicrosoftTeams.return_results')

    mock_response = test_data.get('list_members')
    expected_hr_chat_member_list = test_data.get('expected_hr_chat_member_list')
    get_chat_members_expected_response = mock_response.get('value', [])

    mocker.patch('MicrosoftTeams.get_chat_id_and_type', return_value=(ONEONONE_CHAT_ID, 'oneOnOne'))

    requests_mock.get(
        f'{GRAPH_BASE_URL}/v1.0/chats/{ONEONONE_CHAT_ID}/members',
        json=mock_response
    )
    chat_member_list_command()

    results_hr = return_results.call_args[0][0].readable_output
    results_outputs = return_results.call_args[0][0].outputs
    assert results_hr == expected_hr_chat_member_list
    [member.pop('@odata.type', None) for member in get_chat_members_expected_response]
    expected_outputs = {'chatId': ONEONONE_CHAT_ID, 'members': get_chat_members_expected_response}
    assert results_outputs == expected_outputs


@pytest.mark.parametrize('chat_id, chat_type, expected_exception',
                         [(GROUP_CHAT_ID, "group", False), (ONEONONE_CHAT_ID, 'oneOnOne', True)])
def test_chat_update_command(mocker, requests_mock, chat_id, chat_type, expected_exception):
    """
    Given:
      - The command arguments:
        - GROUP_CHAT_ID, group -> updates the title
        - ONEONONE_CHAT_ID, oneOnOne -> raise ValueError
    When:
      - Executing the 'microsoft-teams-chat-update' command.
    Then:
      - Assert the request url is as expected
      - Verify human-readable output
    """
    from MicrosoftTeams import chat_update_command
    mocker.patch.object(demisto, 'args', return_value={"chat": chat_id, "chat_name": "XsoarChat"})
    mocker.patch('MicrosoftTeams.get_chat_id_and_type', return_value=(chat_id, chat_type))
    return_results = mocker.patch('MicrosoftTeams.return_results')
    mock_response = test_data.get('update_chat')
    requests_mock.patch(
        f'{GRAPH_BASE_URL}/v1.0/chats/{chat_id}',
        json=mock_response
    )

    if expected_exception:
        with pytest.raises(ValueError) as e:
            chat_update_command()
        assert str(e.value) == "Setting chat name is allowed only on group chats."

    else:
        chat_update_command()
        assert requests_mock.request_history[0].method == 'PATCH'
        assert requests_mock.request_history[0].json() == {'topic': 'XsoarChat'}
        results_hr = return_results.call_args[0][0]
        assert results_hr == f"The name of chat '{chat_id}' has been successfully changed to 'XsoarChat'."


@pytest.mark.parametrize("chat, member, expected_exit, expected_warning, expected_result, mocked_get_user", [
    ('group', 'user1', False, None, 'The User "user1" has been added to chat "group" successfully.',
     [[{'id': 1, 'userType': 'Member'}]]),
    ('group', 'user1,user2', False, None, 'The Users "user1, user2" have been added to chat "group" successfully.',
     [[{'id': 1, 'userType': 'Member'}], [{'id': 2, 'userType': 'Member'}]]),
    ('group', 'user1,unknown', False, 'The following members were not found: unknown',
     'The User "user1" has been added to chat "group" successfully.', [[{'id': 1, 'userType': 'Member'}], []]),
    ('group', 'unknown1,unknown2', True, 'The following members were not found: unknown1, unknown2',
     None, [[], []]),
    ('oneOnOne', 'user1', True, ValueError, "Adding a member is allowed only on group chat.", []),
])
def test_chat_add_user_command(mocker, chat, member, expected_exit, expected_warning, expected_result, mocked_get_user):
    """
    Given:
      - Adding a single member to a group chat
      - Adding multiple members to a group chat
      - Adding a non-existing member to a group chat
      - Adding multiple non-existing members to a group chat
      - Adding a member to a oneOnOne chat
    When:
      - Executing the 'microsoft-teams-chat-add-user' command.
    Then:
      - verify that the relevant functions are called correctly based on the inputs and expected results.
      - checks if the correct warning or result is returned, or if the correct exception is raised,
        based on the inputs and expected outcomes.
    """
    import MicrosoftTeams
    from MicrosoftTeams import chat_add_user_command
    mocker.patch.object(demisto, 'args', return_value={'chat': chat, 'member': member})
    mocker.patch.object(demisto, 'results')
    warning = mocker.patch.object(MicrosoftTeams, 'return_warning')

    get_chat_id_and_type_mock = mocker.patch('MicrosoftTeams.get_chat_id_and_type', return_value=(chat, chat))
    get_user_mock = mocker.patch('MicrosoftTeams.get_user', side_effect=mocked_get_user)
    add_user_to_chat_mock = mocker.patch('MicrosoftTeams.add_user_to_chat')

    if expected_warning is ValueError:
        with pytest.raises(ValueError) as e:
            chat_add_user_command()
        assert str(e.value) == expected_result

    else:
        chat_add_user_command()
        if expected_warning:
            warning.assert_called_once_with(expected_warning, exit=expected_exit)
        if expected_result:
            demisto.results.assert_called_once_with(expected_result)

    get_chat_id_and_type_mock.assert_called_once_with(chat)
    if not expected_warning:
        get_user_mock.assert_called()
        add_user_to_chat_mock.assert_called()


def test_add_user_to_chat(requests_mock):
    """
    Given:
      - The function arguments
    When:
      - Calling the add_user_to_chats function
    Then:
      - Ensure expected request body is sent
    """
    from MicrosoftTeams import add_user_to_chat
    expected_request_json = test_data.get('add_member_request')

    requests_mock.post(
        f'https://graph.microsoft.com/v1.0/chats/{GROUP_CHAT_ID}/members',
        status_code=201
    )
    add_user_to_chat(GROUP_CHAT_ID, 'Member', '8b081ef6-4792-4def-b2c9-c363a1bf41d5', True)
    assert requests_mock.request_history[0].json() == expected_request_json


@pytest.mark.parametrize(
    "args, expected_response, expected_request_url, expected_outputs",
    [
        ({"chat": "test group 1", "filter": "test_filter"}, ValueError, "", ""),
        ({"chat": "test group 1"},
         'get_chat', f"https://graph.microsoft.com/v1.0/chats/{GROUP_CHAT_ID}",
         'expected_outputs_get_chat'),
        ({"expand": 'members', "limit": 3}, 'list_chats_with_members',
         "https://graph.microsoft.com/v1.0/chats/?%24expand=members&%24top=3",
         'expected_outputs_list_chats_with_members'),
        ({"expand": 'lastMessagePreview', "limit": 3}, 'list_chats_with_lastMessagePreview',
         "https://graph.microsoft.com/v1.0/chats/?%24expand=lastMessagePreview&%24top=3",
         'expected_outputs_list_chats_with_lastMessagePreview'),
        ({"limit": 3}, 'list_chats', "https://graph.microsoft.com/v1.0/chats/?%24top=3", 'expected_outputs_list_chats'),
        ({}, 'list_chats', "https://graph.microsoft.com/v1.0/chats/?%24top=50", 'expected_outputs_list_chats'),
        ({"next_link": "https://graph.microsoft.com/v1.0/chats/test_next_link", "page_size": 3},
         'list_chats', "https://graph.microsoft.com/v1.0/chats/test_next_link", 'expected_outputs_list_chats'),
    ]
)
def test_chat_list_command(mocker, requests_mock, args, expected_response, expected_request_url, expected_outputs):
    """
    Given:
      - The command arguments
    When:
      - Executing the 'microsoft-teams-chat-list' command.
    Then:
      - Assert the request url is as expected
      - Verify that the context outputs is as expected
    """
    from MicrosoftTeams import chat_list_command

    mocker.patch('MicrosoftTeams.get_chat_id_and_type', return_value=(GROUP_CHAT_ID, 'group'))
    return_results = mocker.patch('MicrosoftTeams.return_results')
    mocker.patch.object(demisto, 'args', return_value=args)

    if expected_response is ValueError:
        with pytest.raises(ValueError) as e:
            chat_list_command()
        assert str(e.value) == "Retrieve a single chat does not support the 'filter' ODate query parameter."
    else:
        requests_mock.get(
            expected_request_url,
            json=test_data.get(expected_response)
        )
        chat_list_command()
        assert return_results.call_args[0][0].outputs == test_data.get(expected_outputs)


@pytest.mark.parametrize(
    "args, expected_response, expected_request_url, expected_outputs",
    [
        ({"limit": 2, "order_by": "createdDateTime"}, 'list_messages',
         f'https://graph.microsoft.com/v1.0/chats/{GROUP_CHAT_ID}/messages?$top=2&$orderBy=createdDateTime desc',
         'expected_outputs_list_messages'),
        ({"next_link": "https://graph.microsoft.com/v1.0/chats/test_next_link", "page_size": 2},
         'list_messages', "https://graph.microsoft.com/v1.0/chats/test_next_link", 'expected_outputs_list_messages'),

    ]
)
def test_chat_message_list_command(mocker, requests_mock, args, expected_response, expected_request_url,
                                   expected_outputs):
    """
    Given:
      - The command arguments
    When:
      - Executing the 'microsoft-teams-chat-message-list' command.
    Then:
      - Assert the request url is as expected
      - Verify that the context outputs is as expected
    """
    from MicrosoftTeams import chat_message_list_command
    mocker.patch('MicrosoftTeams.get_chat_id_and_type', return_value=(GROUP_CHAT_ID, 'group'))
    return_results = mocker.patch('MicrosoftTeams.return_results')
    mocker.patch.object(demisto, 'args', return_value=args)

    requests_mock.get(
        expected_request_url,
        json=test_data.get(expected_response)
    )
    chat_message_list_command()
    assert return_results.call_args[0][0].outputs == test_data.get(expected_outputs)


def test_pages_puller(requests_mock):
    """
    Given:
      - The function arguments: response, limit:
          - The response has a nextLink URL.
          - The limit is greater than the number of results in the first response.
    When:
      - Calling the 'pages_puller' function.
    Then:
      - Assert the request url is as expected - make an API request using the nextLink URL.
      - Verify the function output is as expected
    """
    from MicrosoftTeams import pages_puller
    response = test_data.get('list_messages')  # contains 2 results
    limit = 4
    expected_result = response.get('value') * 2

    requests_mock.get(
        response.get('@odata.nextLink'),
        json=response
    )

    result, last_next_link = pages_puller(response, limit)
    assert requests_mock.call_count == 1
    assert result == expected_result
    assert last_next_link == response.get('@odata.nextLink')


def test_get_chat_id_and_type(mocker, requests_mock):
    """
    Given:
        The 'chat' argument as:
      - case 1: chat ID -> returns the given ID and the chat_type
      - case 2: chat_name (topic) -> returns the ID and 'group' chat_type
      - case 3: member -> returns the ID of a one-on-one chat and 'oneOnOne' chat_type
      - case 4: non-existing member/chat_name (topic)  -> raise ValueError
    When:
      - Calling the 'get_chat_id_and_type' function.
    Then:
      - Assert the request url is as expected
      - Verify the function output is as expected
    """

    from MicrosoftTeams import get_chat_id_and_type

    # case 1: chat = chat_id [= GROUP_CHAT_ID]
    requests_mock.get(
        f"{GRAPH_BASE_URL}/v1.0/chats/{GROUP_CHAT_ID}",
        json=test_data.get('get_chat')
    )
    assert get_chat_id_and_type(GROUP_CHAT_ID) == (GROUP_CHAT_ID, 'group')

    # case 2: chat = chat_name (topic) [= "test"]
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/chats/?$select=id, chatType&$filter=topic eq 'test'",
        json=test_data.get('get_chat_id_and_type_response')
    )
    assert get_chat_id_and_type("test") == (GROUP_CHAT_ID, 'group')

    # case 3: chat = member [= "test_admin"]
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/chats/?$select=id, chatType&$filter=topic eq 'test_admin'",
        json=test_data.get('get_chat_id_and_type_no_chat_response')
    )
    get_user_mock = mocker.patch('MicrosoftTeams.get_user', return_value=[{'id': 'user_id', 'userType': 'Member'}])
    create_chat_mock = mocker.patch('MicrosoftTeams.create_chat', return_value=test_data.get('create_oneOnOne_chat'))

    assert get_chat_id_and_type("test_admin") == \
        ("19:82fe7758-5bb3-4f0d-a43f-e555fd399c6f_8c0a1a67-50ce-4114-bb6c-da9c5dbcf6ca@unq.gbl.spaces", 'oneOnOne')
    assert create_chat_mock.call_args.args == ('oneOnOne', [('user_id', 'Member')])
    assert get_user_mock.call_count == 1
    assert create_chat_mock.call_count == 1

    # case 4: chat = non-existing member or chat_name (topic)  [= "unknown"]
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/chats/?$select=id, chatType&$filter=topic eq 'unknown'",
        json=test_data.get('get_chat_id_and_type_no_chat_response')
    )
    get_user_mock = mocker.patch('MicrosoftTeams.get_user', return_value=[])
    with pytest.raises(ValueError) as e:
        get_chat_id_and_type('unknown')
    assert str(e.value) == "Could not find chat: unknown"


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function microsoft-teams-generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from MicrosoftTeams import main
    import MicrosoftTeams

    redirect_uri = 'redirect_uri'
    tenant_id = 'tenant_id'
    client_id = 'client_id'
    mocked_params = {
        'REDIRECT_URI': redirect_uri,
        'AUTH_TYPE': 'Authorization Code',
        'BOT_ID': client_id
    }
    mocker.patch.dict(MicrosoftTeams.__dict__, MicrosoftTeams.__dict__ | mocked_params)
    mocker.patch.object(MicrosoftTeams, "get_integration_context", return_value={'tenant_id': 'tenant_id'})
    mocker.patch.object(MicrosoftTeams, 'return_results')
    mocker.patch.object(MicrosoftTeams, 'support_multithreading')
    mocker.patch.object(demisto, 'command', return_value='microsoft-teams-generate-login-url')

    # call
    main()

    # assert
    expected_url = f'[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                   'response_type=code&scope=offline_access%20https://graph.microsoft.com/.default' \
                   f'&client_id={client_id}&redirect_uri={redirect_uri})'
    res = MicrosoftTeams.return_results.call_args[0][0].readable_output
    assert expected_url in res


def test_is_bot_in_chat_parameters(mocker, requests_mock):
    """
    Given: some chat ID and bot ID
    When: calling is_bot_in_chat() to check if the bot is already a member of the chat
    Then: validate that the request is sent correctly and specifically that the BOT_ID is part of the query
    """
    request_mock = requests_mock.get(f'{GRAPH_BASE_URL}/v1.0/chats/{GROUP_CHAT_ID}/installedApps', json={})
    mocker.patch("MicrosoftTeams.BOT_ID", new=bot_id)
    from MicrosoftTeams import is_bot_in_chat
    is_bot_in_chat(GROUP_CHAT_ID)
    filters = request_mock.last_request.qs.get('$filter')[0]
    assert f"eq '{bot_id}'" in filters


@pytest.mark.parametrize('error_content, status_code, expected_response', [
    (b'{"error": "invalid_grant", "error_description": "AADSTS700082: The refresh token has expired due to inactivity.'
     b'\\u00a0The token was issued on 2023-02-06T12:26:14.6448497Z and was inactive for 90.00:00:00.'
     b'\\r\\nTrace ID: test\\r\\nCorrelation ID: test\\r\\nTimestamp: 2023-07-02 06:40:26Z", '
     b'"error_codes": [700082], "timestamp": "2023-07-02 06:40:26Z", "trace_id": "test", "correlation_id": "test",'
     b' "error_uri": "https://login.microsoftonline.com/error?code=700082"}', 400,
     'The refresh token has expired due to inactivity. Please regenerate the '
     "'Authorization code' parameter and then run !microsoft-teams-auth-test to "
     're-authenticate')])
def test_error_parser_with_exception(mocker, error_content, status_code, expected_response):
    """
    Given:
        - The error_content, status_code, and expected_response for testing the error_parser function.
    When:
        - The error_parser function is called with the given error_content and status_code.
    Then:
        - Assert that the error_parser function raises a DemistoException with the expected_response.
    """
    from MicrosoftTeams import error_parser
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(demisto, 'error')
    err = Response()
    err.status_code = status_code
    err._content = error_content

    with pytest.raises(DemistoException) as ex:
        error_parser(err)

    assert demisto.getIntegrationContext.call_count == 1
    assert demisto.setIntegrationContext.call_count == 1

    assert str(ex.value) == expected_response


@pytest.mark.parametrize('is_xsoar_8, expected_result', [
    (True, ({"http": "xsoar_8_proxy", "https": "xsoar_8_proxy"}, True)),
    (False, (None, False))
])
def test_handle_teams_proxy_and_ssl(mocker, is_xsoar_8, expected_result):
    """
    Given:
        - If the xsoar version is greater or less than 8, and the expected reuslts of the integration proxies.
    When:
        - The version of xsoar is greater than 8 or less than 8
    Then:
        - Assert that when the version is greater than 8, proxies dict is not empty and use_ssl is true
        - Assert that when the version is less than 8, proxies dict is empty and use_ssl is false.
    """
    import MicrosoftTeams as ms_teams
    os.environ['CRTX_HTTP_PROXY'] = 'xsoar_8_proxy'
    mocker.patch.object(ms_teams, 'is_demisto_version_ge', return_value=is_xsoar_8)
    mocker.patch.object(ms_teams, 'PARAMS', return_value={'insecure': True})

    proxies, use_ssl = ms_teams.handle_teams_proxy_and_ssl()
    assert (proxies, use_ssl) == expected_result


DUMMY_ASK_MESSAGE = {"message_text": "message", "options": [
    "option"], "entitlement": "id", "investigation_id": "inv_id", "task_id": "task", "form_type": "form"}


@pytest.mark.parametrize('message, result', [
    (json.dumps(DUMMY_ASK_MESSAGE), True),
    (json.dumps(DUMMY_ASK_MESSAGE | {"extra_key": "extra"}), False),
    ("non json message", False)
])
def test_is_teams_ask_message(message, result):
    """
    Given:
        - input message string
    When:
        - Running is_teams_ask_message.
    Then:
        - Assert only ask_teams messages return True
    If the test fails, please update the first message param in the test to have the same keys as MS_TEAMS_ASK_MESSAGE_KEYS
     constant in MicrosoftTeams.
    """
    from MicrosoftTeams import is_teams_ask_message

    assert is_teams_ask_message(message) == result


def test_add_data_to_actions_simple_card():
    from MicrosoftTeams import add_data_to_actions
    card_json = {
        "type": "Action.Submit",
        "title": "Submit"
    }
    data_value = {"key": "value"}
    add_data_to_actions(card_json, data_value)
    assert card_json["data"] == data_value


def test_add_data_to_actions_nested_card():
    from MicrosoftTeams import add_data_to_actions
    card_json = {
        "type": "AdaptiveCard",
        "actions": [
            {
                "type": "Action.Submit",
                "title": "Submit 1"
            },
            {
                "type": "Action.Execute",
                "title": "Execute 1"
            }
        ]
    }
    data_value = {"key": "value"}
    add_data_to_actions(card_json, data_value)
    assert card_json["actions"][0]["data"] == data_value
    assert card_json["actions"][1]["data"] == data_value


def test_add_data_to_actions_show_card():
    from MicrosoftTeams import add_data_to_actions
    card_json = {
        "type": "Action.ShowCard",
        "title": "Show Card",
        "card": {
            "type": "AdaptiveCard",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Nested Submit"
                }
            ]
        }
    }
    data_value = {"key": "value"}
    add_data_to_actions(card_json, data_value)
    assert card_json["card"]["actions"][0]["data"] == data_value


def test_add_data_to_actions_mixed_types():
    from MicrosoftTeams import add_data_to_actions
    card_json = [
        {
            "type": "Action.Submit",
            "title": "Submit"
        },
        {
            "type": "TextBlock",
            "text": "Some text"
        },
        {
            "type": "Action.Execute",
            "title": "Execute"
        }
    ]
    data_value = {"key": "value"}
    add_data_to_actions(card_json, data_value)
    assert card_json[0]["data"] == data_value
    assert "data" not in card_json[1]
    assert card_json[2]["data"] == data_value


def test_add_data_to_actions_empty_input():
    from MicrosoftTeams import add_data_to_actions
    card_json = {}
    data_value = {"key": "value"}
    add_data_to_actions(card_json, data_value)
    assert card_json == {}


def test_add_data_to_actions_non_dict_data():
    from MicrosoftTeams import add_data_to_actions
    card_json = {
        "type": "Action.Submit",
        "title": "Submit"
    }
    data_value = "string_data"
    add_data_to_actions(card_json, data_value)
    assert card_json["data"] == data_value


@pytest.mark.parametrize('token, decoded_token, auth_type, expected_hr', [
    ('dummy_token',
     {'aud': 'url', 'exp': '1111', 'roles': ['AppCatalog.Read.All', 'Group.ReadWrite.All', 'User.Read.All']},
     'Client Credentials',
     'The current API permissions in the Teams application are'),
    ('dummy_token',
     {'aud': 'url', 'exp': '1111', 'roles': []},
     'Client Credentials',
     'No permissions obtained for the used graph access token.'),
    ('dummy_token',
     {'aud': 'url', 'exp': '1111', 'scp': 'AppCatalog.Read.All Group.ReadWrite.All User.Read.All'},
     'Authorization Code',
     'The current API permissions in the Teams application are'),
    ('dummy_token',
     {'aud': 'url', 'exp': '1111', 'scp': ''},
     'Authorization Code',
     'No permissions obtained for the used graph access token.'),
    ('',
     {'roles': []},
     'Client Credentials',
     'Graph access token is not set.')
], ids=["Test token permissions list command - client credentials auth flow",
        "Test token permissions list command - client credentials auth flow - no permissions set",
        "Test token permissions list command - auth code auth flow",
        "Test token permissions list command - client auth code flow - no permissions set",
        "Test token permissions list command - missing token"
        ])
def test_token_permissions_list_command(mocker, token, decoded_token, auth_type, expected_hr):
    """
    Tests the 'token_permissions_list_command' logic:
    For client credentials auth flow, the API permissions are found under the 'roles' key in the decoded token data,
    while for the auth code flow they are found under the 'scp' key.
    This test checks that we extract the API permissions from the graph access token successfully for both auth types.

    Given:
        1. A dummy token, mocked response of the jet.decode func with API permissions roles under the 'roles' key -
           (auth type is client credentials).
        2. A dummy token, mocked response of the jet.decode func without API permissions roles under the 'roles' key -
           (auth type is client credentials).
        3. A dummy token, mocked response of the jet.decode func with API permissions roles under the 'scp' key -
           (auth type is Authorization Code).
        4. A dummy token, mocked response of the jet.decode func without API permissions roles under the 'scp' key -
           (auth type is Authorization Code).
        5. Missing token.
    When:
        - Running the token_permissions_list_command.
    Then:
        Verify that the human readable output is as expected:
        1. API permissions list.
        2. No permissions obtained for the used graph access token.
        3. API permissions list.
        4. No permissions obtained for the used graph access token.
        5. Graph access token is not set.
    """
    from MicrosoftTeams import token_permissions_list_command
    import MicrosoftTeams
    mocker.patch('MicrosoftTeams.get_graph_access_token', return_value=token)
    mocker.patch('MicrosoftTeams.AUTH_TYPE', new=auth_type)
    mocker.patch('jwt.decode', return_value=decoded_token)
    results = mocker.patch.object(MicrosoftTeams, 'return_results')

    token_permissions_list_command()

    assert expected_hr in results.call_args[0][0].readable_output


@pytest.mark.parametrize('xsoar_server, is_xsoar_on_prem, is_xsiam, expected_hr', [
    ('https://dns-test.name:443', True, False, 'https://dns-test.name:443/instance/execute/teams'),
    ('https://viso-test-dummy.crtx-qa-ttt.ss.paloaltonetworks.com', False, False,
     'https://ext-viso-test-dummy.crtx-qa-ttt.ss.paloaltonetworks.com/xsoar/instance/execute/teams'),
    ('http://viso-test-dummy.crtx-qa-ttt.ss.paloaltonetworks.com', False, False,
     'http://ext-viso-test-dummy.crtx-qa-ttt.ss.paloaltonetworks.com/xsoar/instance/execute/teams'),
    ('https://viso-test-dummy.xdr-qa-ttt.ss.paloaltonetworks.com', False, True,
     'https://ext-viso-test-dummy.crtx-qa-ttt.ss.paloaltonetworks.com/xsoar/instance/execute/teams'),
    ('http://viso-test-dummy.xdr.qa-ttt.ss.paloaltonetworks.com', False, True,
     'http://ext-viso-test-dummy.crtx.qa-ttt.ss.paloaltonetworks.com/xsoar/instance/execute/teams'),
    ('http://viso-test-dummy.crtx-qa-ttt.ss.paloaltonetworks.com', False, True,
     'http://ext-viso-test-dummy.crtx-qa-ttt.ss.paloaltonetworks.com/xsoar/instance/execute/teams'),
],
    ids=["Test xsoar 6 server url",
         "Test xsoar 8 server url (with https:// prefix)",
         "Test xsoar 8 server url (with http:// prefix)",
         "Test xsiam server url (with https:// prefix)",
         "Test xsiam server url (with http:// prefix)",
         "Test xsiam server url without the 'xdr' string in the dns name"
         ])
def test_create_messaging_endpoint_command(mocker, xsoar_server, is_xsoar_on_prem, is_xsiam, expected_hr):
    """
    Tests the 'create_messaging_endpoint_command' logic.

    Given:
        1. An xsoar 6 server url.
        2. An xsoar 8 server url (with https:// prefix).
        3. An xsoar 8 server url (with http:// prefix).
        4. An xsiam server url (with https:// prefix).
        5. An xsiam server url (with http:// prefix).
        6. An xsiam server url without the 'xdr' string in the dns name.

    When:
        - Running the create_messaging_endpoint_command.
    Then:
        Verify that the messaging endpoint was created as expected:
        1. The 'instance/execute/teams' suffix was added.
        2. The 'ext' prefix was added to the dns name, and the 'xsoar/instance/execute/teams' suffix was added.
        3. The 'ext' prefix was added to the dns name, and the 'xsoar/instance/execute/teams' suffix was added.
        4. The 'ext' prefix was added to the dns name, the 'xdr' was replaced with 'crtx' and the 'xsoar/instance/execute/teams'
           suffix was added.
        5. The 'ext' prefix was added to the dns name, the 'xdr' was replaced with 'crtx' and the 'xsoar/instance/execute/teams'
           suffix was added.
        6. The 'ext' prefix was added to the dns name, and the 'xsoar/instance/execute/teams' suffix was added.
    """
    from MicrosoftTeams import create_messaging_endpoint_command
    import MicrosoftTeams
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': xsoar_server})
    mocker.patch.object(demisto, 'integrationInstance', return_value="teams")
    mocker.patch.object(demisto, 'args', return_value={'engine_url': ''})
    mocker.patch('MicrosoftTeams.is_xsoar_on_prem', return_value=is_xsoar_on_prem)
    mocker.patch('MicrosoftTeams.is_xsiam', return_value=is_xsiam)
    mocker.patch('MicrosoftTeams.is_using_engine', return_value=False)
    results = mocker.patch.object(MicrosoftTeams, 'return_results')

    create_messaging_endpoint_command()

    assert expected_hr in results.call_args[0][0].readable_output


@pytest.mark.parametrize('engine_url, is_xsoar_on_prem, is_xsiam, expected_hr', [
    ('https://my-engine.com:333', True, False, 'https://my-engine.com:333'),
    ('https://my-engine.com:333', False, False, 'https://my-engine.com:333'),
    ('https://my-engine.com:333', False, True, 'https://my-engine.com:333'),
    ('https://1.1.1.1:333', False, True, 'https://1.1.1.1:333')
],
    ids=["Test xsoar 6 engine url",
         "Test xsoar 8 engine url",
         "Test xsiam engine url",
         "Test xsoar engine url - with IP",
         ])
def test_create_messaging_endpoint_command_for_xsoar_engine(mocker, engine_url, is_xsoar_on_prem, is_xsiam, expected_hr):
    """
    Tests the 'create_messaging_endpoint_command' logic when the user uses an xsoar engine.

    Given:
      - An xsoar engine url.

    When:
        - Running the create_messaging_endpoint_command on:
            1. xsoar 6
            2. xsoar 8
            3. xsiam
        4. The engine url include an IP and not a DNS name.
    Then:
        Verify that the messaging endpoint was created as expected - only the engine url and port (without any suffix).
    """
    from MicrosoftTeams import create_messaging_endpoint_command
    import MicrosoftTeams
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://test-server.com:443'})
    mocker.patch.object(demisto, 'integrationInstance', return_value="teams")
    mocker.patch.object(demisto, 'args', return_value={'engine_url': engine_url})
    mocker.patch('MicrosoftTeams.is_xsoar_on_prem', return_value=is_xsoar_on_prem)
    mocker.patch('MicrosoftTeams.is_xsiam', return_value=is_xsiam)
    mocker.patch('MicrosoftTeams.is_using_engine', return_value=True)
    results = mocker.patch.object(MicrosoftTeams, 'return_results')

    create_messaging_endpoint_command()

    assert expected_hr in results.call_args[0][0].readable_output


@pytest.mark.parametrize('engine_url', [
    ('https://my-engine.com'),
    ('my-engine.com:333'),
    ('https://my engine.com:433'),
],
    ids=["Test engine url without a port",
         "Test engine url without an http or https prefix",
         "Test engine url with spaces in the dns name",
         ])
def test_create_messaging_endpoint_command_invalid_xsoar_engine(mocker, engine_url):
    """
    Tests the 'create_messaging_endpoint_command' logic when the user uses an xsoar engine, and provides an invalid engine url.

    Given:
      - An invalid engine URL:
        1. without a port.
        2. without an http:// or https:// prefix
        3. with a space in the dns name

    When:
        - Running the create_messaging_endpoint_command.

    Then:
        Verify that a valueError exception is raised with the error description.
    """
    from MicrosoftTeams import create_messaging_endpoint_command
    import MicrosoftTeams
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://test-server.com:443'})
    mocker.patch.object(demisto, 'integrationInstance', return_value="teams")
    mocker.patch.object(demisto, 'args', return_value={'engine_url': engine_url})
    mocker.patch('MicrosoftTeams.is_using_engine', return_value=True)
    mocker.patch.object(MicrosoftTeams, 'return_results')

    with pytest.raises(ValueError) as e:
        create_messaging_endpoint_command()
    assert 'Invalid engine URL -' in str(e.value)


def test_switch_auth_type_to_client_credentials(mocker):
    """
    Tests the 'auth_type_switch_handling' logic when the user switched the auth type in the instance parameters from Auth Code
    Flow to the Client Credentials Flow.

    Given:
        - Auth type instance parameter is now 'Client Credentials'.

    When:
        - Running the 'auth_type_switch_handling' function.

    Then:
        - Verify that the integration context was updated as follows:
            1. current_auth_type =  'Client Credentials'.
            2. graph token related values were deleted.
        - Verify that the debug logs are as expected.
    """
    from MicrosoftTeams import auth_type_switch_handling
    mocker.patch('MicrosoftTeams.get_integration_context', return_value={'current_auth_type': 'Authorization Code',
                                                                         'current_refresh_token': 'test_refresh_token',
                                                                         'graph_access_token': 'test_graph_token',
                                                                         'graph_valid_until': 'test_valid_until'})
    set_integration_context_mocker = mocker.patch('MicrosoftTeams.set_integration_context', return_value={})
    debug_log_mocker = mocker.patch.object(demisto, 'debug')
    mocker.patch('MicrosoftTeams.AUTH_TYPE', new='Client Credentials')

    auth_type_switch_handling()

    assert set_integration_context_mocker.call_count == 2
    assert set_integration_context_mocker.call_args[0][0] == {
        'current_auth_type': 'Client Credentials', 'current_refresh_token': '',
        'graph_access_token': '', 'graph_valid_until': ''}
    assert 'Setting the current_auth_type in the integration context to Client Credentials' in debug_log_mocker.call_args[0][0]
    assert debug_log_mocker.call_count == 4


def test_switch_auth_type_to_authorization_code_flow(mocker):
    """
    Tests the 'auth_type_switch_handling' logic when the user switched the auth type in the instance parameters from the
    Client Credentials Flow to the Auth Code Flow.

    Given:
        - Auth type instance parameter is now 'Authorization Code'.

    When:
        - Running the 'auth_type_switch_handling' function.

    Then:
        - Verify that the integration context was updated as follows:
            1. current_auth_type = 'Authorization Code'.
            2. graph token related values were deleted.
        - Verify that the debug logs are as expected.
    """
    from MicrosoftTeams import auth_type_switch_handling
    mocker.patch('MicrosoftTeams.get_integration_context', return_value={'current_auth_type': 'Client Credentials',
                                                                         'current_refresh_token': 'test_refresh_token',
                                                                         'graph_access_token': 'test_graph_token',
                                                                         'graph_valid_until': 'test_valid_until'})
    set_integration_context_mocker = mocker.patch('MicrosoftTeams.set_integration_context', return_value={})
    debug_log_mocker = mocker.patch.object(demisto, 'debug')
    mocker.patch('MicrosoftTeams.AUTH_TYPE', new='Authorization Code')

    auth_type_switch_handling()

    assert set_integration_context_mocker.call_count == 2
    assert set_integration_context_mocker.call_args[0][0] == {
        'current_auth_type': 'Authorization Code', 'current_refresh_token': '',
        'graph_access_token': '', 'graph_valid_until': ''}
    assert 'Setting the current_auth_type in the integration context to Authorization Code' in debug_log_mocker.call_args[0][0]
    assert debug_log_mocker.call_count == 4


def test_auth_type_handling_for_first_run_of_the_instance(mocker):
    """
    Tests the 'auth_type_switch_handling' logic in the first run of the integration instance/

    Given:
        - Auth type instance parameter is now 'Authorization Code'.

    When:
        - Running the 'auth_type_switch_handling' function.

    Then:
        - Verify that the integration context was updated as follows:
            1. current_auth_type = 'Authorization Code'.
        - Verify that the debug logs are as expected.
    """
    from MicrosoftTeams import auth_type_switch_handling
    mocker.patch('MicrosoftTeams.get_integration_context', return_value={})
    set_integration_context_mocker = mocker.patch('MicrosoftTeams.set_integration_context', return_value={})
    debug_log_mocker = mocker.patch.object(demisto, 'debug')
    mocker.patch('MicrosoftTeams.AUTH_TYPE', new='Authorization Code')

    auth_type_switch_handling()

    assert set_integration_context_mocker.call_count == 1
    assert set_integration_context_mocker.call_args[0][0] == {'current_auth_type': 'Authorization Code'}
    assert 'This is the first run of the integration instance' in debug_log_mocker.call_args[0][0]
    assert debug_log_mocker.call_count == 1


def test_message_update(mocker, requests_mock):
    """
    Given:
        - a message as a basic string and a  message that contains GUID.
    When:
        - running send message function.
    Then:
        - The message is sent successfully in both cases.
    """
    from MicrosoftTeams import message_update_command
    mocker.patch.object(demisto, 'results')
    mocker.patch('MicrosoftTeams.get_channel_type', return_value='standard')

    expected = util_load_json('test_data/send_message/expected_generic.json')
    raw = util_load_json('test_data/send_message/raw_generic.json')

    activity_id: str = '1730232813350'
    conversation_id: str = '19:2cbad0d78c624400ef83a5750534448g@thread.skype'
    mocker.patch("MicrosoftTeams.BOT_ID", new=bot_id)
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'message_id': activity_id,
            'team': team_name,
            'channel': 'incident-10',
            'message': "Updated message",
            'format_as_card': False
        }
    )

    requests_mock.put(
        f'{service_url}/v3/conversations/{conversation_id}/activities/{activity_id}',
        json={'id': activity_id}
    )

    requests_mock.post(
        f"{service_url}/v3/conversations/{mirrored_channels[0]['channel_id']}/activities",
        json=raw
    )
    message_update_command()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == expected
