import slack
import pytest
import asyncio
import demistomock as demisto
import json as js
import datetime
from unittest.mock import mock_open

USERS = '''[{
    "id": "U012A3CDE",
    "team_id": "T012AB3C4",
    "name": "spengler",
    "deleted": false,
    "color": "9f69e7",
    "real_name": "spengler",
    "tz": "America/Los_Angeles",
    "tz_label": "Pacific Daylight Time",
    "tz_offset": -25200,
    "profile": {
        "avatar_hash": "ge3b51ca72de",
        "status_text": "Print is dead",
        "status_emoji": ":books:",
        "real_name": "Egon Spengler",
        "display_name": "spengler",
        "real_name_normalized": "Egon Spengler",
        "display_name_normalized": "spengler",
        "email": "spengler@ghostbusters.example.com",
        "team": "T012AB3C4"
    },
    "is_admin": true,
    "is_owner": false,
    "is_primary_owner": false,
    "is_restricted": false,
    "is_ultra_restricted": false,
    "is_bot": false,
    "updated": 1502138686,
    "is_app_user": false,
    "has_2fa": false
},
{
    "id": "U07QCRPA4",
    "team_id": "T0G9PQBBK",
    "name": "glinda",
    "deleted": false,
    "color": "9f69e7",
    "real_name": "Glinda Southgood",
    "tz": "America/Los_Angeles",
    "tz_label": "Pacific Daylight Time",
    "tz_offset": -25200,
    "profile": {
        "avatar_hash": "8fbdd10b41c6",
        "first_name": "Glinda",
        "last_name": "Southgood",
        "title": "Glinda the Good",
        "phone": "",
        "skype": "",
        "real_name": "Glinda Southgood",
        "real_name_normalized": "Glinda Southgood",
        "display_name": "Glinda the Fairly Good",
        "display_name_normalized": "Glinda the Fairly Good",
        "email": "Glenda@south.oz.coven"
    },
    "is_admin": true,
    "is_owner": false,
    "is_primary_owner": false,
    "is_restricted": false,
    "is_ultra_restricted": false,
    "is_bot": false,
    "updated": 1480527098,
    "has_2fa": false
}]'''

CONVERSATIONS = '''[{
    "id": "C012AB3CD",
    "name": "general",
    "is_channel": true,
    "is_group": false,
    "is_im": false,
    "created": 1449252889,
    "creator": "U012A3CDE",
    "is_archived": false,
    "is_general": true,
    "unlinked": 0,
    "name_normalized": "general",
    "is_shared": false,
    "is_ext_shared": false,
    "is_org_shared": false,
    "pending_shared": [],
    "is_pending_ext_shared": false,
    "is_member": true,
    "is_private": false,
    "is_mpim": false,
    "topic": {
        "value": "Company-wide announcements and work-based matters",
        "creator": "",
        "last_set": 0
    },
    "purpose": {
        "value": "This channel is for team-wide communication and announcements. All team members are in this channel.",
        "creator": "",
        "last_set": 0
    },
    "previous_names": [],
    "num_members": 4
},
{
    "id": "C061EG9T2",
    "name": "random",
    "is_channel": true,
    "is_group": false,
    "is_im": false,
    "created": 1449252889,
    "creator": "U061F7AUR",
    "is_archived": false,
    "is_general": false,
    "unlinked": 0,
    "name_normalized": "random",
    "is_shared": false,
    "is_ext_shared": false,
    "is_org_shared": false,
    "pending_shared": [],
    "is_pending_ext_shared": false,
    "is_member": true,
    "is_private": false,
    "is_mpim": false,
    "topic": {
        "value": "Non-work banter and water cooler conversation",
        "creator": "",
        "last_set": 0
    },
    "purpose": {
        "value": "A place for non-work-related flimflam.",
        "creator": "",
        "last_set": 0
    },
    "previous_names": [],
    "num_members": 4
}]'''


BOT = '''{
    "ok": true,
    "url": "https://subarachnoid.slack.com/",
    "team": "Subarachnoid Workspace",
    "user": "grace",
    "team_id": "T12345678",
    "user_id": "W12345678"
}'''

MIRRORS = '''
   [{
     "channel_id":"GKQ86DVPH",
     "channel_name": "incident-681",
     "channel_topic": "incident-681",
     "investigation_id":"681",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GKB19PA3V",
     "channel_name": "group2",
     "channel_topic": "cooltopic",
     "investigation_id":"684",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GKB19PA3V",
     "channel_name": "group2",
     "channel_topic": "cooltopic",
     "investigation_id":"692",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GKNEJU4P9",
     "channel_name": "group3",
     "channel_topic": "incident-713",
     "investigation_id":"713",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GL8GHC0LV",
     "channel_name": "group5",
     "channel_topic": "incident-734",
     "investigation_id":"734",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  }]
'''

BLOCK_JSON = [{
    'type': 'section',
    'text': {
        'type': 'mrkdwn',
        'text': 'text'
    }
}, {
    'type': 'actions',
    'elements': [{
            'type': 'button',
            'text': {
                'type': 'plain_text',
                'emoji': True,
                'text': 'yes'
            },
        'style': 'primary',
        'value': '{\"entitlement\": \"e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43\", \"reply\": \"Thanks bro\"}',
    }, {
        'type': 'button',
        'text': {
            'type': 'plain_text',
            'emoji': True,
            'text': 'no'
        },
        'style': 'danger',
        'value': '{\"entitlement\": \"e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43\", \"reply\": \"Thanks bro\"}',
    }]}]

PAYLOAD_JSON = r'''
 {
     "type":"block_actions",
     "team":{
        "id":"T9XJ4RGNQ",
        "domain":"dombo60"
     },
     "user":{
        "id":"U012A3CDE",
        "username":"spengler",
        "name":"spengler",
        "team_id":"T9XJ4RGNQ"
     },
     "api_app_id":"AMU4M2QL8",
     "token":"GBGG7mn61zg0a62MT9blXJnn",
     "container":{
        "type":"message",
        "message_ts":"1567945126.000100",
        "channel_id":"DMGSNFCSX",
        "is_ephemeral":false
     },
     "trigger_id":"754598374743.337616866772.8c4b2dc28ca7fd4c8941247c1a01c7dd",
     "channel":{
        "id":"DMGSNFCSX",
        "name":"directmessage"
     },
     "message":{
        "type":"message",
        "subtype":"bot_message",
        "text":"This content can't be displayed.",
        "ts":"1567945126.000100",
        "username":"BlockTest",
        "bot_id":"BMWFS6KSA",
        "blocks":[
           {
              "type":"section",
              "block_id":"F9iYK",
              "text":{
                 "type":"mrkdwn",
                 "text":"Hopa this is a test. ",
                 "verbatim":false
              },
              "accessory":{
                 "type":"button",
                 "text":{
                    "type":"plain_text",
                    "text":"Eyy",
                    "emoji":true
                 },
                 "value":"{\"entitlement\": \"e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43\", \"reply\": \"Thanks bro\"}",
                 "action_id":"W9J"
              }
           }
        ]
     },
     "response_url":"hooks.slack.com",
     "actions":[
        {
           "action_id":"W9J",
           "block_id":"F9iYK",
           "text":{
              "type":"plain_text",
              "text":"Eyy",
              "emoji":true
           },
           "value":"{\"entitlement\": \"e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43\", \"reply\": \"Thanks bro\"}",
           "type":"button",
           "action_ts":"1567949681.728426"
        }
     ]
  }
'''


def get_integration_context():
    return INTEGRATION_CONTEXT


def set_integration_context(integration_context):
    global INTEGRATION_CONTEXT
    INTEGRATION_CONTEXT = integration_context


RETURN_ERROR_TARGET = 'Slack.return_error'


@pytest.fixture(autouse=True)
def setup():
    from Slack import init_globals

    set_integration_context({
        'mirrors': MIRRORS,
        'users': USERS,
        'conversations': CONVERSATIONS,
        'bot_id': 'W12345678'
    })

    init_globals()


@pytest.mark.asyncio
async def test_get_slack_name_user(mocker):
    from Slack import get_slack_name

    # Set
    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.info':
            user = params['user']
            if user != 'alexios':
                return {'user': js.loads(USERS)[0]}
        elif method == 'conversations.info':
            return {'channel': js.loads(CONVERSATIONS)[0]}
        return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    # Assert

    # User in integration context
    user_id = 'U012A3CDE'
    name = await get_slack_name(user_id, slack.WebClient)
    assert name == 'spengler'
    assert slack.WebClient.api_call.call_count == 0

    # User not in integration context
    unknown_user = 'USASSON'
    name = await get_slack_name(unknown_user, slack.WebClient)
    assert name == 'spengler'
    assert slack.WebClient.api_call.call_count == 1

    # User does not exist
    nonexisting_user = 'alexios'
    name = await get_slack_name(nonexisting_user, slack.WebClient)
    assert name == ''
    assert slack.WebClient.api_call.call_count == 1


@pytest.mark.asyncio
async def test_get_slack_name_channel(mocker):
    from Slack import get_slack_name

    # Set

    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.info':
            user = params['user']
            if user != 'alexios':
                return {'user': js.loads(USERS)[0]}
        elif method == 'conversations.info':
            return {'channel': js.loads(CONVERSATIONS)[0]}
        return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    # Assert

    # Channel in integration context
    channel_id = 'C012AB3CD'
    name = await get_slack_name(channel_id, slack.WebClient)
    assert name == 'general'
    assert slack.WebClient.api_call.call_count == 0

    # Channel not in integration context
    unknown_channel = 'CSASSON'
    name = await get_slack_name(unknown_channel, slack.WebClient)
    assert name == 'general'
    assert slack.WebClient.api_call.call_count == 1

    # Channel doesn't exist
    nonexisting_channel = 'lulz'
    name = await get_slack_name(nonexisting_channel, slack.WebClient)
    assert name == ''
    assert slack.WebClient.api_call.call_count == 1


@pytest.mark.asyncio
async def test_clean_message(mocker):
    from Slack import clean_message

    # Set
    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.info':
            return {'user': js.loads(USERS)[0]}
        elif method == 'conversations.info':
            return {'channel': js.loads(CONVERSATIONS)[0]}
        return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    user_message = 'Hello <@U012A3CDE>!'
    channel_message = 'Check <#C012AB3CD>'
    link_message = 'Go to <https://www.google.com/lulz>'

    # Arrange

    clean_user_message = await clean_message(user_message, slack.WebClient)
    clean_channel_message = await clean_message(channel_message, slack.WebClient)
    clean_link_message = await clean_message(link_message, slack.WebClient)

    # Assert

    assert clean_user_message == 'Hello spengler!'
    assert clean_channel_message == 'Check general'
    assert clean_link_message == 'Go to https://www.google.com/lulz'


def test_get_user_by_name(mocker):
    from Slack import get_user_by_name
    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        users = {'members': js.loads(USERS)}
        new_user = {
            'name': 'perikles',
            'profile': {
                'email': 'perikles@acropoli.com',
            },
            'id': 'U012B3CUI'
        }

        users['members'].append(new_user)
        return users

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    # Assert

    # User name exists in integration context
    username = 'spengler'
    user = get_user_by_name(username)
    assert user['id'] == 'U012A3CDE'
    assert slack.WebClient.api_call.call_count == 0

    # User email exists in integration context
    email = 'spengler@ghostbusters.example.com'
    user = get_user_by_name(email)
    assert user['id'] == 'U012A3CDE'
    assert slack.WebClient.api_call.call_count == 0

    # User name doesn't exist in integration context
    username = 'perikles'
    user = get_user_by_name(username)
    assert user['id'] == 'U012B3CUI'
    assert slack.WebClient.api_call.call_count == 1

    set_integration_context({
        'mirrors': MIRRORS,
        'users': USERS,
        'conversations': CONVERSATIONS,
        'bot_id': 'W12345678'
    })

    # User email doesn't exist in integration context
    email = 'perikles@acropoli.com'
    user = get_user_by_name(email)
    assert user['id'] == 'U012B3CUI'
    assert slack.WebClient.api_call.call_count == 2

    # User doesn't exist
    username = 'alexios'
    user = get_user_by_name(username)
    assert user == {}
    assert slack.WebClient.api_call.call_count == 3


def test_get_user_by_name_paging(mocker):
    from Slack import get_user_by_name
    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if len(params) == 1:
            return {'members': js.loads(USERS), 'response_metadata': {
                'next_cursor': 'dGVhbTpDQ0M3UENUTks='
            }}
        else:
            return {'members': [{
                'id': 'U248918AB',
                'name': 'alexios'
            }], 'response_metadata': {
                'next_cursor': ''
            }}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    # Arrange
    user = get_user_by_name('alexios')
    args = slack.WebClient.api_call.call_args_list
    first_args = args[0][1]
    second_args = args[1][1]

    # Assert
    assert len(first_args['params']) == 1
    assert first_args['params']['limit'] == 200
    assert len(second_args['params']) == 2
    assert second_args['params']['cursor'] == 'dGVhbTpDQ0M3UENUTks='
    assert user['id'] == 'U248918AB'
    assert slack.WebClient.api_call.call_count == 2


def test_mirror_investigation_new_mirror(mocker):
    from Slack import mirror_investigation

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        if method == 'channels.create':
            return {'channel': {
                'id': 'new_channel', 'name': 'incident-999'
            }}
        if method == 'groups.create':
            return {'group': {
                'id': 'new_group', 'name': 'incident-999'
            }}
        else:
            return {}

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999', 'users': ['spengler', 'alexios']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://www.eizelulz.com:8443'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    new_mirror = {
        'channel_id': 'new_group',
        'channel_name': 'incident-999',
        'channel_topic': 'incident-999',
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': False
    }
    # Arrange

    mirror_investigation()
    error_results = demisto.results.call_args_list[0][0]
    success_results = demisto.results.call_args_list[1][0]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    new_conversations = js.loads(new_context['conversations'])
    our_conversation_filter = list(filter(lambda c: c['id'] == 'new_group', new_conversations))
    our_conversation = our_conversation_filter[0]
    our_mirror_filter = list(filter(lambda m: '999' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert

    calls = slack.WebClient.api_call.call_args_list

    groups_call = [c for c in calls if c[0][0] == 'groups.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']
    chat_call = [c for c in calls if c[0][0] == 'chat.postMessage']

    message_args = chat_call[0][1]['json']

    assert len(groups_call) == 1
    assert len(users_call) == 1
    assert len(invite_call) == 2
    assert len(topic_call) == 1
    assert len(chat_call) == 1

    assert error_results[0]['Contents'] == 'User alexios not found in Slack'
    assert success_results[0] == 'Investigation mirrored successfully, channel: incident-999'
    assert message_args['channel'] == 'new_group'
    assert message_args['text'] == 'This channel was created to mirror incident 999.' \
                                   ' \n View it on: https://www.eizelulz.com:8443#/WarRoom/999'

    assert len(our_conversation_filter) == 1
    assert len(our_mirror_filter) == 1
    assert our_conversation == {'id': 'new_group', 'name': 'incident-999'}
    assert our_mirror == new_mirror


def test_mirror_investigation_new_mirror_with_name(mocker):
    from Slack import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        if method == 'channels.create':
            return {'channel': {
                'id': 'new_channel', 'name': 'coolname'
            }}
        if method == 'groups.create':
            return {'group': {
                'id': 'new_group', 'name': 'coolname'
            }}
        else:
            return {}

    mocker.patch.object(demisto, 'args', return_value={'channelName': 'coolname'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999', 'users': ['spengler', 'alexios']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://www.eizelulz.com:8443'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    new_mirror = {
        'channel_id': 'new_group',
        'channel_name': 'coolname',
        'channel_topic': 'incident-999',
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': False
    }
    # Arrange

    mirror_investigation()
    error_results = demisto.results.call_args_list[0][0]
    success_results = demisto.results.call_args_list[1][0]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    new_conversations = js.loads(new_context['conversations'])
    our_conversation_filter = list(filter(lambda c: c['id'] == 'new_group', new_conversations))
    our_conversation = our_conversation_filter[0]
    our_mirror_filter = list(filter(lambda m: '999' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert

    calls = slack.WebClient.api_call.call_args_list

    groups_call = [c for c in calls if c[0][0] == 'groups.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']
    chat_call = [c for c in calls if c[0][0] == 'chat.postMessage']

    message_args = chat_call[0][1]['json']

    assert len(groups_call) == 1
    assert len(users_call) == 1
    assert len(invite_call) == 2
    assert len(topic_call) == 1
    assert len(chat_call) == 1

    assert error_results[0]['Contents'] == 'User alexios not found in Slack'
    assert success_results[0] == 'Investigation mirrored successfully, channel: coolname'
    assert message_args['channel'] == 'new_group'
    assert message_args['text'] == 'This channel was created to mirror incident 999.' \
                                   ' \n View it on: https://www.eizelulz.com:8443#/WarRoom/999'

    assert len(our_conversation_filter) == 1
    assert len(our_mirror_filter) == 1
    assert our_conversation == {'id': 'new_group', 'name': 'coolname'}
    assert our_mirror == new_mirror


def test_mirror_investigation_new_mirror_with_topic(mocker):
    from Slack import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        if method == 'channels.create':
            return {'channel': {
                'id': 'new_channel', 'name': 'coolname'
            }}
        if method == 'groups.create':
            return {'group': {
                'id': 'new_group', 'name': 'coolname'
            }}
        else:
            return {}

    mocker.patch.object(demisto, 'args', return_value={'channelName': 'coolname', 'channelTopic': 'cooltopic'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999', 'users': ['spengler', 'alexios']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://www.eizelulz.com:8443'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    new_mirror = {
        'channel_id': 'new_group',
        'channel_name': 'coolname',
        'channel_topic': 'cooltopic',
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': False
    }
    # Arrange

    mirror_investigation()

    success_results = demisto.results.call_args_list[1][0]
    error_results = demisto.results.call_args_list[0][0]
    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    new_conversations = js.loads(new_context['conversations'])
    our_conversation_filter = list(filter(lambda c: c['id'] == 'new_group', new_conversations))
    our_conversation = our_conversation_filter[0]
    our_mirror_filter = list(filter(lambda m: '999' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    calls = slack.WebClient.api_call.call_args_list
    groups_call = [c for c in calls if c[0][0] == 'groups.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']
    chat_call = [c for c in calls if c[0][0] == 'chat.postMessage']

    message_args = chat_call[0][1]['json']
    topic_args = topic_call[0][1]['json']

    # Assert

    assert len(groups_call) == 1
    assert len(users_call) == 1
    assert len(invite_call) == 2
    assert len(topic_call) == 1
    assert len(chat_call) == 1

    assert error_results[0]['Contents'] == 'User alexios not found in Slack'
    assert success_results[0] == 'Investigation mirrored successfully, channel: coolname'
    assert message_args['channel'] == 'new_group'
    assert message_args['text'] == 'This channel was created to mirror incident 999.' \
                                   ' \n View it on: https://www.eizelulz.com:8443#/WarRoom/999'

    assert topic_args['channel'] == 'new_group'
    assert topic_args['topic'] == 'cooltopic'
    assert len(our_conversation_filter) == 1
    assert len(our_mirror_filter) == 1
    assert our_conversation == {'id': 'new_group', 'name': 'coolname'}
    assert our_mirror == new_mirror


def test_mirror_investigation_existing_mirror_error_type(mocker):
    from Slack import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}

    mocker.patch.object(demisto, 'args', return_value={'type': 'chat', 'autoclose': 'false',
                                                       'direction': 'FromDemisto', 'mirrorTo': 'channel'})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681', 'users': ['spengler']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    # Arrange
    with pytest.raises(InterruptedError):
        mirror_investigation()

    err_msg = return_error_mock.call_args[0][0]

    calls = slack.WebClient.api_call.call_args_list
    groups_call = [c for c in calls if c[0][0] == 'groups.create']
    channels_call = [c for c in calls if c[0][0] == 'channels.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']

    # Assert
    assert len(topic_call) == 0
    assert len(groups_call) == 0
    assert len(users_call) == 0
    assert len(channels_call) == 0

    assert return_error_mock.call_count == 1
    assert err_msg == 'Cannot change the Slack channel type from Demisto.'


def test_mirror_investigation_existing_mirror_error_name(mocker):
    from Slack import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}

    mocker.patch.object(demisto, 'args', return_value={'channelName': 'eyy'})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681', 'users': ['spengler']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    # Arrange

    with pytest.raises(InterruptedError):
        mirror_investigation()

    err_msg = return_error_mock.call_args[0][0]

    calls = slack.WebClient.api_call.call_args_list
    groups_call = [c for c in calls if c[0][0] == 'groups.create']
    channels_call = [c for c in calls if c[0][0] == 'channels.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']

    # Assert

    assert len(groups_call) == 0
    assert len(channels_call) == 0
    assert len(users_call) == 0

    assert return_error_mock.call_count == 1
    assert err_msg == 'Cannot change the Slack channel name.'


def test_mirror_investigation_existing_investigation(mocker):
    from Slack import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}

    mocker.patch.object(demisto, 'args', return_value={'type': 'chat', 'autoclose': 'false',
                                                       'direction': 'FromDemisto', 'mirrorTo': 'group'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681', 'users': ['spengler']})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    new_mirror = {
        'channel_id': 'GKQ86DVPH',
        'investigation_id': '681',
        'channel_name': 'incident-681',
        'channel_topic': 'incident-681',
        'mirror_type': 'chat',
        'mirror_direction': 'FromDemisto',
        'mirror_to': 'group',
        'auto_close': False,
        'mirrored': False
    }
    # Arrange

    mirror_investigation()

    calls = slack.WebClient.api_call.call_args_list
    groups_call = [c for c in calls if c[0][0] == 'groups.create']
    channels_call = [c for c in calls if c[0][0] == 'channels.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']

    # Assert

    assert len(groups_call) == 0
    assert len(channels_call) == 0
    assert len(users_call) == 0
    assert len(invite_call) == 2
    assert len(topic_call) == 0

    success_results = demisto.results.call_args_list[0][0]
    assert success_results[0] == 'Investigation mirrored successfully, channel: incident-681'

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: '681' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror


def test_mirror_investigation_existing_channel(mocker):
    from Slack import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}

    mocker.patch.object(demisto, 'args', return_value={'channelName': 'group3', 'type': 'chat', 'autoclose': 'false',
                                                       'direction': 'FromDemisto', 'mirrorTo': 'group'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999', 'users': ['spengler']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    new_mirror = {
        'channel_id': 'GKNEJU4P9',
        'channel_name': 'group3',
        'investigation_id': '999',
        'channel_topic': 'incident-713, incident-999',
        'mirror_type': 'chat',
        'mirror_direction': 'FromDemisto',
        'mirror_to': 'group',
        'auto_close': False,
        'mirrored': False
    }
    # Arrange

    mirror_investigation()

    calls = slack.WebClient.api_call.call_args_list
    groups_call = [c for c in calls if c[0][0] == 'groups.create']
    channels_call = [c for c in calls if c[0][0] == 'channels.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']

    # Assert

    assert len(groups_call) == 0
    assert len(channels_call) == 0
    assert len(users_call) == 0
    assert len(invite_call) == 2
    assert len(topic_call) == 1

    success_results = demisto.results.call_args_list[0][0]
    assert success_results[0] == 'Investigation mirrored successfully, channel: group3'

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: '999' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror


def test_mirror_investigation_existing_channel_remove_mirror(mocker):
    from Slack import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}

    mirrors = js.loads(MIRRORS)
    mirrors.append({
        'channel_id': 'GKB19PA3V',
        'channel_name': 'group2',
        'channel_topic': 'cooltopic',
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': True
    })

    set_integration_context({
        'mirrors': js.dumps(mirrors),
        'users': USERS,
        'conversations': CONVERSATIONS,
        'bot_id': 'W12345678'
    })

    mocker.patch.object(demisto, 'investigation', return_value={'id': '999', 'users': ['spengler']})
    mocker.patch.object(demisto, 'args', return_value={'type': 'none'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    new_mirror = {
        'channel_id': 'GKB19PA3V',
        'channel_name': 'group2',
        'channel_topic': 'cooltopic',
        'investigation_id': '999',
        'mirror_type': 'none',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': False
    }
    # Arrange

    mirror_investigation()

    calls = slack.WebClient.api_call.call_args_list
    groups_call = [c for c in calls if c[0][0] == 'groups.create']
    channels_call = [c for c in calls if c[0][0] == 'channels.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']

    # Assert

    assert len(groups_call) == 0
    assert len(channels_call) == 0
    assert len(users_call) == 0
    assert len(invite_call) == 0
    assert len(topic_call) == 0

    success_results = demisto.results.call_args_list[0][0]
    assert success_results[0] == 'Investigation mirrored successfully, channel: group2'

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: '999' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror


def test_mirror_investigation_existing_channel_with_topic(mocker):
    from Slack import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}

    mocker.patch.object(demisto, 'args', return_value={'channelName': 'group2', 'type': 'chat', 'autoclose': 'false',
                                                       'direction': 'FromDemisto', 'mirrorTo': 'group'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999', 'users': ['spengler']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    new_mirror = {
        'channel_id': 'GKB19PA3V',
        'channel_name': 'group2',
        'channel_topic': 'cooltopic',
        'investigation_id': '999',
        'mirror_type': 'chat',
        'mirror_direction': 'FromDemisto',
        'mirror_to': 'group',
        'auto_close': False,
        'mirrored': False,
    }
    # Arrange

    mirror_investigation()

    calls = slack.WebClient.api_call.call_args_list
    groups_call = [c for c in calls if c[0][0] == 'groups.create']
    channels_call = [c for c in calls if c[0][0] == 'channels.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']

    # Assert

    assert len(groups_call) == 0
    assert len(channels_call) == 0
    assert len(users_call) == 0
    assert len(invite_call) == 2
    assert len(topic_call) == 0

    success_results = demisto.results.call_args_list[0][0]
    assert success_results[0] == 'Investigation mirrored successfully, channel: group2'

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: '999' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror


def test_check_for_mirrors(mocker):
    from Slack import check_for_mirrors

    # Set
    mirrors = js.loads(MIRRORS)
    mirrors.append({
        'channel_id': 'new_group',
        'channel_name': 'channel',
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': False
    })

    set_integration_context({
        'mirrors': js.dumps(mirrors),
        'users': USERS,
        'conversations': CONVERSATIONS,
        'bot_id': 'W12345678'
    })

    new_mirror = {
        'channel_id': 'new_group',
        'channel_name': 'channel',
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': True
    }

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'mirrorInvestigation')

    # Arrange

    check_for_mirrors()

    mirror_id = demisto.mirrorInvestigation.call_args[0][0]
    mirror_type = demisto.mirrorInvestigation.call_args[0][1]
    auto_close = demisto.mirrorInvestigation.call_args[0][2]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: '999' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror

    assert mirror_id == '999'
    assert mirror_type == 'all:both'
    assert auto_close is True


@pytest.mark.asyncio
async def test_slack_loop_should_exit(mocker):
    from Slack import slack_loop

    # Set
    class MyFuture:
        @staticmethod
        def done():
            return True

        @staticmethod
        def exception():
            return None

    @asyncio.coroutine
    def yeah_im_not_going_to_run(time):
        return "sup"

    mocker.patch.object(demisto, 'info')
    mocker.patch.object(asyncio, 'sleep', side_effect=yeah_im_not_going_to_run)

    with pytest.raises(InterruptedError):
        mocker.patch.object(slack.RTMClient, 'start', side_effect=[MyFuture()])
        # Exits the while True
        mocker.patch.object(slack.RTMClient, 'stop', side_effect=InterruptedError())

        # Arrange
        await slack_loop()

    # Assert
    assert slack.RTMClient.start.call_count == 1


@pytest.mark.asyncio
async def test_handle_dm_create_demisto_user(mocker):
    import Slack

    # Set
    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'im.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        else:
            return 'sup'

    @asyncio.coroutine
    def fake_translate(demisto_user, message):
        return "sup"

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value={'id': 'demisto_id'})
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'translate_create', side_effect=fake_translate)

    user = js.loads(USERS)[0]

    # Arrange
    await Slack.handle_dm(user, 'open 123 incident', slack.WebClient)
    await Slack.handle_dm(user, 'new incident abu ahmad', slack.WebClient)
    await Slack.handle_dm(user, 'incident create 817', slack.WebClient)
    await Slack.handle_dm(user, 'incident open', slack.WebClient)
    await Slack.handle_dm(user, 'incident new', slack.WebClient)
    await Slack.handle_dm(user, 'create incident name=abc type=Access', slack.WebClient)

    # Assert
    assert Slack.translate_create.call_count == 6

    demisto_user = Slack.translate_create.call_args[0][0]
    incident_string = Slack.translate_create.call_args[0][1]
    assert demisto_user == {'id': 'demisto_id'}
    assert incident_string == 'create incident name=abc type=Access'


@pytest.mark.asyncio
async def test_handle_dm_nondemisto_user_shouldnt_create(mocker):
    import Slack

    # Set

    @asyncio.coroutine
    def fake_translate(demisto_user, message):
        return "sup"

    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'im.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        else:
            return 'sup'

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value=None)
    mocker.patch.object(Slack, 'translate_create', side_effect=fake_translate)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    user = js.loads(USERS)[0]

    # Arrange
    await Slack.handle_dm(user, 'create incident abc', slack.WebClient)

    # Assert
    assert Slack.translate_create.call_count == 0


@pytest.mark.asyncio
async def test_handle_dm_nondemisto_user_should_create(mocker):
    import Slack

    mocker.patch.object(demisto, 'params', return_value={'allow_incidents': 'true'})

    Slack.init_globals()

    # Set

    @asyncio.coroutine
    def fake_translate(demisto_user, message):
        return "sup"

    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'im.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        else:
            return 'sup'

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value=None)
    mocker.patch.object(Slack, 'translate_create', side_effect=fake_translate)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    user = js.loads(USERS)[0]

    # Arrange
    await Slack.handle_dm(user, 'create incident abc', slack.WebClient)

    # Assert
    assert Slack.translate_create.call_count == 1

    demisto_user = Slack.translate_create.call_args[0][0]
    assert demisto_user is None


@pytest.mark.asyncio
async def test_handle_dm_non_create_nonexisting_user(mocker):
    from Slack import handle_dm

    # Set

    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'im.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        else:
            return 'sup'

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value=None)
    mocker.patch.object(demisto, 'directMessage', return_value=None)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    user = js.loads(USERS)[0]

    # Arrange
    await handle_dm(user, 'wazup', slack.WebClient)

    message = demisto.directMessage.call_args[0][0]
    username = demisto.directMessage.call_args[0][1]
    email = demisto.directMessage.call_args[0][2]
    allow = demisto.directMessage.call_args[0][3]

    # Assert
    assert message == 'wazup'
    assert username == 'spengler'
    assert email == 'spengler@ghostbusters.example.com'
    assert allow is False


@pytest.mark.asyncio
async def test_handle_dm_empty_message(mocker):
    from Slack import handle_dm

    # Set
    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'im.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        elif method == 'chat.postMessage':
            text = json['text']
            if not text:
                raise InterruptedError()
        else:
            return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value=None)
    mocker.patch.object(demisto, 'directMessage', return_value=None)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    user = js.loads(USERS)[0]

    # Arrange
    await handle_dm(user, 'wazup', slack.WebClient)

    calls = slack.WebClient.api_call.call_args_list
    chat_call = [c for c in calls if c[0][0] == 'chat.postMessage']
    message_args = chat_call[0][1]['json']

    # Assert
    assert message_args['text'] == 'Sorry, I could not perform the selected operation.'


@pytest.mark.asyncio
async def test_handle_dm_create_with_error(mocker):
    import Slack

    # Set

    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'im.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        else:
            return 'sup'

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value={'id': 'demisto_id'})
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'translate_create', side_effect=InterruptedError('omg'))

    user = js.loads(USERS)[0]

    # Arrange
    await Slack.handle_dm(user, 'open 123 incident', slack.WebClient)

    # Assert
    assert Slack.translate_create.call_count == 1

    demisto_user = Slack.translate_create.call_args[0][0]
    incident_string = Slack.translate_create.call_args[0][1]
    calls = slack.WebClient.api_call.call_args_list
    chat_call = [c for c in calls if c[0][0] == 'chat.postMessage']
    message_args = chat_call[0][1]['json']

    assert demisto_user == {'id': 'demisto_id'}
    assert incident_string == 'open 123 incident'
    assert message_args == {'channel': 'ey', 'text': 'Failed creating incidents: omg'}


@pytest.mark.asyncio
async def test_translate_create(mocker):
    # Set
    import Slack

    @asyncio.coroutine
    def this_doesnt_create_incidents(demisto_user, incidents_json):
        return {
            'id': 'new_incident',
            'name': 'New Incident'
        }

    mocker.patch.object(Slack, 'create_incidents', side_effect=this_doesnt_create_incidents)
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://www.eizelulz.com:8443'})

    demisto_user = {'id': 'demisto_user'}

    json_message = 'create incident json={“name”: “xyz”, “role”: “Analyst”}'
    wrong_json_message = 'create incident json={"name": "xyz"} name=abc'
    name_message = 'create incident name=eyy'
    name_type_message = 'create incident name= eyy type= Access'
    type_name_message = 'create incident  type= Access name= eyy'
    type_message = 'create incident type= Phishing'

    success_message = 'Successfully created incident New Incident.\n' \
                      ' View it on: https://www.eizelulz.com:8443#/WarRoom/new_incident'

    # Arrange
    json_data = await Slack.translate_create(demisto_user, json_message)
    wrong_json_data = await Slack.translate_create(demisto_user, wrong_json_message)
    name_data = await Slack.translate_create(demisto_user, name_message)
    name_type_data = await Slack.translate_create(demisto_user, name_type_message)
    type_name_data = await Slack.translate_create(demisto_user, type_name_message)
    type_data = await Slack.translate_create(demisto_user, type_message)

    create_args = Slack.create_incidents.call_args_list
    json_args = create_args[0][0][1]
    name_args = create_args[1][0][1]
    name_type_args = create_args[2][0][1]
    type_name_args = create_args[3][0][1]

    # Assert

    assert Slack.create_incidents.call_count == 4

    assert json_args == [{"name": "xyz", "role": "Analyst"}]
    assert name_args == [{"name": "eyy"}]
    assert name_type_args == [{"name": "eyy", "type": "Access"}]
    assert type_name_args == [{"name": "eyy", "type": "Access"}]

    assert json_data == success_message
    assert wrong_json_data == 'No other properties other than json should be specified.'
    assert name_data == success_message
    assert name_type_data == success_message
    assert type_name_data == success_message
    assert type_data == 'Please specify arguments in the following manner: name=<name> type=[type] or json=<json>.'


@pytest.mark.asyncio
async def test_translate_create_newline_json(mocker):
    # Set
    import Slack

    @asyncio.coroutine
    def this_doesnt_create_incidents(demisto_user, incidents_json):
        return {
            'id': 'new_incident',
            'name': 'New Incident'
        }

    mocker.patch.object(Slack, 'create_incidents', side_effect=this_doesnt_create_incidents)
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://www.eizelulz.com:8443'})

    demisto_user = {'id': 'demisto_user'}

    json_message =\
        '''```
            create incident json={
            "name":"xyz",
            "details": "1.1.1.1,8.8.8.8"
            ```
        }'''

    success_message = 'Successfully created incident New Incident.\n' \
                      ' View it on: https://www.eizelulz.com:8443#/WarRoom/new_incident'

    # Arrange
    json_data = await Slack.translate_create(demisto_user, json_message)

    create_args = Slack.create_incidents.call_args
    json_args = create_args[0][1]

    # Assert

    assert Slack.create_incidents.call_count == 1

    assert json_args == [{"name": "xyz", "details": "1.1.1.1,8.8.8.8"}]

    assert json_data == success_message


@pytest.mark.asyncio
async def test_get_user_by_id_async_user_exists(mocker):
    from Slack import get_user_by_id_async

    # Set

    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.info':
            return {'user': js.loads(USERS)[0]}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    user_id = 'U012A3CDE'

    # Arrange
    user = await get_user_by_id_async(slack.WebClient, demisto.getIntegrationContext(), user_id)

    # Assert
    assert slack.WebClient.api_call.call_count == 0
    assert demisto.setIntegrationContext.call_count == 0
    assert user['name'] == 'spengler'


@pytest.mark.asyncio
async def test_get_user_by_id_async_user_doesnt_exist(mocker):
    from Slack import get_user_by_id_async

    # Set

    @asyncio.coroutine
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.info':
            return {'user': js.loads(USERS)[0]}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    user_id = 'XXXXXXX'

    # Arrange
    user = await get_user_by_id_async(slack.WebClient, demisto.getIntegrationContext(), user_id)

    # Assert

    assert slack.WebClient.api_call.call_count == 1
    assert demisto.setIntegrationContext.call_count == 1
    assert user['name'] == 'spengler'


@pytest.mark.asyncio
async def test_handle_text(mocker):
    import Slack

    # Set

    @asyncio.coroutine
    def fake_clean(text, client):
        return 'מה הולך'

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'addEntry')
    mocker.patch.object(Slack, 'clean_message', side_effect=fake_clean)

    user = js.loads(USERS)[0]
    investigation_id = '999'
    text = 'מה הולך'

    # Arrange
    await Slack.handle_text(slack.WebClient, investigation_id, text, user)
    entry_args = demisto.addEntry.call_args[1]

    # Assert
    assert demisto.addEntry.call_count == 1
    assert entry_args['id'] == '999'
    assert entry_args['entry'] == 'מה הולך'
    assert entry_args['username'] == 'spengler'
    assert entry_args['email'] == 'spengler@ghostbusters.example.com'
    assert entry_args['footer'] == '\n**From Slack**'


def test_check_for_answers(mocker, requests_mock):
    import Slack

    # Set

    mocker.patch.object(demisto, 'handleEntitlementForUser')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)

    requests_mock.post(
        'https://oproxy.demisto.ninja/slack-poll',
        json={'payload': PAYLOAD_JSON}
    )

    integration_context = get_integration_context()
    integration_context['questions'] = js.dumps([{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:34:25'
    }])

    set_integration_context(integration_context)

    # Arrange
    Slack.check_for_answers(datetime.datetime(2019, 9, 26, 18, 38, 25))

    result_args = demisto.handleEntitlementForUser.call_args_list[0][0]

    # Assert
    assert demisto.handleEntitlementForUser.call_count == 1

    assert result_args[0] == '22'
    assert result_args[1] == 'e95cb5a1-e394-4bc5-8ce0-508973aaf298'
    assert result_args[2] == 'spengler@ghostbusters.example.com'
    assert result_args[3] == 'Eyy'
    assert result_args[4] == '43'

    # Should delete the question
    assert demisto.getIntegrationContext()['questions'] == js.dumps([])


def test_check_for_answers_continue(mocker, requests_mock):
    import Slack

    # Set
    mocker.patch.object(demisto, 'handleEntitlementForUser')
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)

    requests_mock.post(
        'https://oproxy.demisto.ninja/slack-poll',
        [{'json': {}, 'status_code': 200},
         {'json': 'error', 'status_code': 401},
         {'json': {'payload': PAYLOAD_JSON}, 'status_code': 200}]

    )

    integration_context = get_integration_context()
    integration_context['questions'] = js.dumps([{
        'thread': 'notcool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:34:25'
    }, {
        'thread': 'notcool2',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:34:25'
    }, {
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:34:25'
    }])

    set_integration_context(integration_context)

    # Arrange
    Slack.check_for_answers(datetime.datetime(2019, 9, 26, 18, 38, 25))

    result_args = demisto.handleEntitlementForUser.call_args_list[0][0]

    # Assert
    assert demisto.handleEntitlementForUser.call_count == 1
    assert demisto.error.call_count == 1

    assert result_args[0] == '22'
    assert result_args[1] == 'e95cb5a1-e394-4bc5-8ce0-508973aaf298'
    assert result_args[2] == 'spengler@ghostbusters.example.com'
    assert result_args[3] == 'Eyy'
    assert result_args[4] == '43'

    # Should delete the question
    assert demisto.getIntegrationContext()['questions'] == js.dumps([{
        'thread': 'notcool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:38:25'
    }, {
        'thread': 'notcool2',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:38:25'
    }])


def test_check_for_answers_no_answer(mocker, requests_mock):
    import Slack

    # Set
    mocker.patch.object(demisto, 'handleEntitlementForUser')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)

    requests_mock.post(
        'https://oproxy.demisto.ninja/slack-poll',
        json={}
    )

    integration_context = get_integration_context()
    integration_context['questions'] = js.dumps([{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:34:25'
    }, {
        'thread': 'notcool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:34:25'
    }])

    set_integration_context(integration_context)

    # Arrange
    Slack.check_for_answers(datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Assert

    assert demisto.handleEntitlementForUser.call_count == 0

    # Should not delete the question
    assert demisto.getIntegrationContext()['questions'] == js.dumps([{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:38:25'
    }, {
        'thread': 'notcool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:38:25'
    }])


def test_check_for_answers_no_answer_expires(mocker, requests_mock):
    import Slack

    # Set
    mocker.patch.object(demisto, 'handleEntitlementForUser')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)

    requests_mock.post(
        'https://oproxy.demisto.ninja/slack-poll',
        json={}
    )

    integration_context = get_integration_context()
    integration_context['questions'] = js.dumps([{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:34:25'
    }, {
        'thread': 'notcool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44',
        'reply': 'Thanks bro',
        'expiry': '2019-09-26 18:35:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:34:25'
    }])

    set_integration_context(integration_context)

    # Arrange
    Slack.check_for_answers(datetime.datetime(2019, 9, 26, 18, 38, 25))

    result_args = demisto.handleEntitlementForUser.call_args_list[0][0]

    # Assert
    assert demisto.handleEntitlementForUser.call_count == 1

    assert result_args[0] == '30'
    assert result_args[1] == '4404dae8-2d45-46bd-85fa-64779c12abe8'
    assert result_args[2] == ''
    assert result_args[3] == 'NoResponse'
    assert result_args[4] == '44'

    # Should not delete the question
    assert demisto.getIntegrationContext()['questions'] == js.dumps([{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:38:25'
    }])


def test_check_for_answers_error(mocker, requests_mock):
    import Slack

    # Set
    mocker.patch.object(demisto, 'handleEntitlementForUser')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'error')

    requests_mock.post(
        'https://oproxy.demisto.ninja/slack-poll',
        json='error',
        status_code=401
    )

    integration_context = get_integration_context()
    integration_context['questions'] = js.dumps([{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse'
    }, {
        'thread': 'notcool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse'
    }])

    set_integration_context(integration_context)

    # Arrange
    Slack.check_for_answers(datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Assert

    assert demisto.handleEntitlementForUser.call_count == 0
    assert demisto.error.call_count == 2

    # Should not delete the question
    assert demisto.getIntegrationContext()['questions'] == js.dumps([{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:38:25'
    }, {
        'thread': 'notcool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse',
        'last_poll_time': '2019-09-26 18:38:25'
    }])


def test_check_for_answers_handle_entitlement_error(mocker, requests_mock):
    import Slack

    # Set
    mocker.patch.object(demisto, 'handleEntitlementForUser', side_effect=InterruptedError())
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'error')

    requests_mock.post(
        'https://oproxy.demisto.ninja/slack-poll',
        json={'payload': PAYLOAD_JSON},
        status_code=200
    )

    integration_context = get_integration_context()
    integration_context['questions'] = js.dumps([{
        'thread': 'notcool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44',
        'expiry': '3000-09-26 18:38:25',
        'default_response': 'NoResponse'
    }])

    set_integration_context(integration_context)

    # Arrange
    Slack.check_for_answers(datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Assert

    assert demisto.handleEntitlementForUser.call_count == 1
    assert demisto.error.call_count == 1

    # Should not delete the question
    assert demisto.getIntegrationContext()['questions'] == js.dumps([])


@pytest.mark.asyncio
async def test_check_entitlement(mocker):
    from Slack import check_and_handle_entitlement

    # Set
    mocker.patch.object(demisto, 'handleEntitlementForUser')

    user = {
        'id': 'U123456',
        'name': 'test',
        'profile': {
            'email': 'test@demisto.com'
        }
    }

    message1 = 'hi test@demisto.com 4404dae8-2d45-46bd-85fa-64779c12abe8@e093ba05-3f3c-402e-81a7-149db969be5d goodbye'
    message2 = 'hi test@demisto.com 4404dae8-2d45-46bd-85fa-64779c12abe8@22 goodbye'
    message3 = 'hi test@demisto.com 4404dae8-2d45-46bd-85fa-64779c12abe8@e093ba05-3f3c-402e-81a7-149db969be5d|4 goodbye'
    message4 = 'hi test@demisto.com 4404dae8-2d45-46bd-85fa-64779c12abe8@22|43 goodbye'
    message5 = 'hi test@demisto.com 43434@e093ba05-3f3c-402e-81a7-149db969be5d goodbye'
    message6 = 'hi test@demisto.com name-of-someone@mail-of-someone goodbye'

    # Arrange
    result1 = await check_and_handle_entitlement(message1, user, '')
    result2 = await check_and_handle_entitlement(message2, user, '')
    result3 = await check_and_handle_entitlement(message3, user, '')
    result4 = await check_and_handle_entitlement(message4, user, '')
    result5 = await check_and_handle_entitlement(message5, user, '')
    result6 = await check_and_handle_entitlement(message6, user, '')

    result1_args = demisto.handleEntitlementForUser.call_args_list[0][0]
    result2_args = demisto.handleEntitlementForUser.call_args_list[1][0]
    result3_args = demisto.handleEntitlementForUser.call_args_list[2][0]
    result4_args = demisto.handleEntitlementForUser.call_args_list[3][0]

    assert result1 == 'Thank you for your response.'
    assert result2 == 'Thank you for your response.'
    assert result3 == 'Thank you for your response.'
    assert result4 == 'Thank you for your response.'
    assert result5 == ''
    assert result6 == ''

    assert demisto.handleEntitlementForUser.call_count == 4

    assert result1_args[0] == 'e093ba05-3f3c-402e-81a7-149db969be5d'  # incident ID
    assert result1_args[1] == '4404dae8-2d45-46bd-85fa-64779c12abe8'  # GUID
    assert result1_args[2] == 'test@demisto.com'  # email
    assert result1_args[3] == 'hi test@demisto.com  goodbye'  # content
    assert result1_args[4] == ''  # task id

    assert result2_args[0] == '22'
    assert result2_args[1] == '4404dae8-2d45-46bd-85fa-64779c12abe8'
    assert result2_args[2] == 'test@demisto.com'
    assert result2_args[3] == 'hi test@demisto.com  goodbye'
    assert result2_args[4] == ''

    assert result3_args[0] == 'e093ba05-3f3c-402e-81a7-149db969be5d'
    assert result3_args[1] == '4404dae8-2d45-46bd-85fa-64779c12abe8'
    assert result3_args[2] == 'test@demisto.com'
    assert result3_args[3] == 'hi test@demisto.com  goodbye'
    assert result3_args[4] == '4'

    assert result4_args[0] == '22'
    assert result4_args[1] == '4404dae8-2d45-46bd-85fa-64779c12abe8'
    assert result4_args[2] == 'test@demisto.com'
    assert result4_args[3] == 'hi test@demisto.com  goodbye'
    assert result4_args[4] == '43'


@pytest.mark.asyncio
async def test_check_entitlement_with_context(mocker):
    from Slack import check_and_handle_entitlement

    # Set
    mocker.patch.object(demisto, 'handleEntitlementForUser')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)

    user = {
        'id': 'U123456',
        'name': 'test',
        'profile': {
            'email': 'test@demisto.com'
        }
    }

    integration_context = get_integration_context()
    integration_context['questions'] = js.dumps([{
        'thread': 'cool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22|43'
    }, {
        'thread': 'notcool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44'
    }])

    set_integration_context(integration_context)

    # Arrange
    await check_and_handle_entitlement('hola', user, 'cool')

    result_args = demisto.handleEntitlementForUser.call_args_list[0][0]

    # Assert
    assert demisto.handleEntitlementForUser.call_count == 1

    assert result_args[0] == '22'
    assert result_args[1] == '4404dae8-2d45-46bd-85fa-64779c12abe8'
    assert result_args[2] == 'test@demisto.com'
    assert result_args[3] == 'hola'
    assert result_args[4] == '43'

    # Should delete the question
    assert demisto.getIntegrationContext()['questions'] == js.dumps([{
        'thread': 'notcool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@30|44'
    }])


def test_send_request(mocker):
    import Slack

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_file', return_value='neat')
    mocker.patch.object(Slack, 'send_message', return_value='cool')

    # Arrange

    user_res = Slack.slack_send_request('spengler', None, None, message='Hi')
    channel_res = Slack.slack_send_request(None, 'general', None, file='file')

    user_args = Slack.send_message.call_args[0]
    channel_args = Slack.send_file.call_args[0]

    calls = slack.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert Slack.send_message.call_count == 1
    assert Slack.send_file.call_count == 1

    assert user_args[0] == ['im_channel']
    assert user_args[1] == ''
    assert user_args[2] is False
    assert user_args[4] == 'Hi'
    assert user_args[5] == ''

    assert channel_args[0] == ['C012AB3CD']
    assert channel_args[1] == 'file'
    assert channel_args[3] == ''

    assert user_res == 'cool'
    assert channel_res == 'neat'


def test_send_request_different_name(mocker):
    import Slack

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_message', return_value='cool')

    # Arrange
    channel_res = Slack.slack_send_request(None, 'incident-684', None, message='Hi')

    channel_args = Slack.send_message.call_args[0]

    calls = slack.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert Slack.send_message.call_count == 1

    assert channel_args[0] == ['GKB19PA3V']
    assert channel_args[1] == ''
    assert channel_args[2] is False
    assert channel_args[4] == 'Hi'
    assert channel_args[5] == ''

    assert channel_res == 'cool'


def test_send_request_with_severity(mocker):
    import Slack

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High', 'notify_incidents': True})

    Slack.init_globals()

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'severity': '3', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_message', return_value={'ts': 'cool'})

    # Arrange
    Slack.slack_send()

    send_args = Slack.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']
    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert Slack.send_message.call_count == 1

    assert send_args[0] == ['C012AB3CD']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == '!!!'
    assert send_args[5] == ''

    assert results[0]['Contents'] == 'Message sent to Slack successfully.\nThread ID is: cool'


def test_send_request_with_notification_channel(mocker):
    import Slack

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High', 'notify_incidents': True})

    Slack.init_globals()

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'channel': 'incidentNotificationChannel',
                                                       'severity': '4', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_message', return_value={'ts': 'cool'})

    # Arrange
    Slack.slack_send()

    send_args = Slack.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert Slack.send_message.call_count == 1

    assert send_args[0] == ['C012AB3CD']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == '!!!'
    assert send_args[5] == ''

    assert results[0]['Contents'] == 'Message sent to Slack successfully.\nThread ID is: cool'


def test_send_request_with_entitlement(mocker):
    import Slack

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={
        'message': js.dumps({
            'message': 'hi test@demisto.com',
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22|43',
            'reply': 'Thanks bro',
            'expiry': '2019-09-26 18:38:25',
            'default_response': 'NoResponse'}),
        'to': 'spengler'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_message', return_value={'ts': 'cool'})

    questions = [{
        'thread': 'cool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22|43',
        'reply': 'Thanks bro',
        'expiry': '2019-09-26 18:38:25',
        'default_response': 'NoResponse'
    }]

    # Arrange
    Slack.slack_send()

    send_args = Slack.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert Slack.send_message.call_count == 1

    assert send_args[0] == ['im_channel']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == 'hi test@demisto.com'
    assert send_args[5] == ''

    assert results[0]['Contents'] == 'Message sent to Slack successfully.\nThread ID is: cool'

    assert demisto.getIntegrationContext()['questions'] == js.dumps(questions)


def test_send_request_with_entitlement_blocks(mocker):
    import Slack

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={
        'blocks': js.dumps({
            'blocks': js.dumps(BLOCK_JSON),
            'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
            'reply': 'Thanks bro',
            'expiry': '2019-09-26 18:38:25',
            'default_response': 'NoResponse'}),
        'to': 'spengler'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_message', return_value={'ts': 'cool'})

    questions = [{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '2019-09-26 18:38:25',
        'default_response': 'NoResponse'
    }]

    # Arrange
    Slack.slack_send()

    send_args = Slack.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert Slack.send_message.call_count == 1

    assert send_args[0] == ['im_channel']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == ''
    assert send_args[6] == js.dumps(BLOCK_JSON)

    assert results[0]['Contents'] == 'Message sent to Slack successfully.\nThread ID is: cool'

    assert demisto.getIntegrationContext()['questions'] == js.dumps(questions)


def test_send_request_with_entitlement_blocks_message(mocker):
    import Slack

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={
        'message': 'wat up',
        'blocks': js.dumps({
            'blocks': js.dumps(BLOCK_JSON),
            'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
            'reply': 'Thanks bro',
            'expiry': '2019-09-26 18:38:25',
            'default_response': 'NoResponse'}),
        'to': 'spengler'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_message', return_value={'ts': 'cool'})

    questions = [{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '2019-09-26 18:38:25',
        'default_response': 'NoResponse'
    }]

    # Arrange
    Slack.slack_send()

    send_args = Slack.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert Slack.send_message.call_count == 1

    assert send_args[0] == ['im_channel']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == 'wat up'
    assert send_args[6] == js.dumps(BLOCK_JSON)

    assert results[0]['Contents'] == 'Message sent to Slack successfully.\nThread ID is: cool'

    assert demisto.getIntegrationContext()['questions'] == js.dumps(questions)


def test_send_to_user_lowercase(mocker):
    import Slack

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'args', return_value={'to': 'glenda@south.oz.coven', 'message': 'hi'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_file', return_value='neat')
    mocker.patch.object(Slack, 'send_message', return_value={'ts': 'cool'})

    # Arrange

    Slack.slack_send()

    send_args = Slack.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert Slack.send_message.call_count == 1

    assert send_args[0] == ['im_channel']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == 'hi'
    assert send_args[5] == ''

    assert results[0]['Contents'] == 'Message sent to Slack successfully.\nThread ID is: cool'


def test_send_request_with_severity_user_doesnt_exist(mocker, capfd):
    import Slack

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High', 'notify_incidents': True})

    Slack.init_globals()

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'severity': '3', 'message': '!!!',
                                                       'messageType': 'incidentOpened', 'to': 'alexios'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_message', return_value={'ts': 'cool'})

    # Arrange
    with capfd.disabled():
        Slack.slack_send()

    send_args = Slack.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]
    calls = slack.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 1
    assert len(conversations_call) == 0
    assert Slack.send_message.call_count == 1

    assert send_args[0] == ['C012AB3CD']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == '!!!'
    assert send_args[5] == ''

    assert results[0]['Contents'] == 'Message sent to Slack successfully.\nThread ID is: cool'


def test_send_request_no_user(mocker, capfd):
    import Slack

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_file', return_value='neat')
    mocker.patch.object(Slack, 'send_message', return_value='cool')

    # Arrange

    with capfd.disabled():
        with pytest.raises(InterruptedError):
            Slack.slack_send_request('alexios', None, None, message='Hi')
    err_msg = return_error_mock.call_args[0][0]

    calls = slack.WebClient.api_call.call_args_list
    users_call = [c for c in calls if c[0][0] == 'users.list']

    # Assert

    assert return_error_mock.call_count == 1
    assert err_msg == 'Could not find any destination to send to.'
    assert len(users_call) == 1
    assert Slack.send_message.call_count == 0
    assert Slack.send_file.call_count == 0


def test_send_request_no_severity(mocker):
    import Slack

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High', 'notify_incidents': True})

    Slack.init_globals()

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'severity': '2', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_message', return_value={'ts': 'cool'})

    # Arrange
    with pytest.raises(InterruptedError):
        Slack.slack_send()

    err_msg = return_error_mock.call_args[0][0]

    calls = slack.WebClient.api_call.call_args_list
    users_call = [c for c in calls if c[0][0] == 'users.list']

    # Assert

    assert return_error_mock.call_count == 1
    assert err_msg == 'Either a user, group or channel must be provided.'
    assert len(users_call) == 0
    assert Slack.send_message.call_count == 0


def test_send_request_zero_severity(mocker):
    import Slack

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High', 'notify_incidents': True})

    Slack.init_globals()

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'im.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'severity': '0', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(Slack, 'send_message', return_value={'ts': 'cool'})

    # Arrange
    with pytest.raises(InterruptedError):
        Slack.slack_send()

    err_msg = return_error_mock.call_args[0][0]

    calls = slack.WebClient.api_call.call_args_list
    users_call = [c for c in calls if c[0][0] == 'users.list']

    # Assert

    assert return_error_mock.call_count == 1
    assert err_msg == 'Either a user, group or channel must be provided.'
    assert len(users_call) == 0
    assert Slack.send_message.call_count == 0


def test_send_message(mocker):
    import Slack
    # Set

    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(Slack, 'send_message_to_destinations')
    mocker.patch.object(Slack, 'invite_users_to_conversation')

    # Arrange
    Slack.send_message(['channel'], None, None, demisto.getIntegrationContext(), 'yo', None, '')

    args = Slack.send_message_to_destinations.call_args[0]

    # Assert
    assert Slack.send_message_to_destinations.call_count == 1

    assert args[0] == ['channel']
    assert args[1] == 'yo' + '\nView it on: ' + link
    assert args[2] is None


def test_send_message_retry(mocker):
    import Slack
    from slack.errors import SlackApiError
    # Set

    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'invite_users_to_conversation')

    # Arrange
    mocker.patch.object(Slack, 'send_message_to_destinations',
                        side_effect=[SlackApiError('not_in_channel', None), 'ok'])
    Slack.send_message(['channel'], None, None, demisto.getIntegrationContext(), 'yo', None, '')

    args = Slack.send_message_to_destinations.call_args_list[1][0]

    # Assert
    assert Slack.send_message_to_destinations.call_count == 2

    assert args[0] == ['channel']
    assert args[1] == 'yo' + '\nView it on: ' + link
    assert args[2] is None


def test_send_file_retry(mocker):
    import Slack
    from slack.errors import SlackApiError
    # Set

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(Slack, 'invite_users_to_conversation')

    # Arrange
    mocker.patch.object(Slack, 'send_file_to_destinations',
                        side_effect=[SlackApiError('not_in_channel', None), 'ok'])
    Slack.send_file(['channel'], 'file', demisto.getIntegrationContext(), None)

    args = Slack.send_file_to_destinations.call_args_list[1][0]

    # Assert
    assert Slack.send_file_to_destinations.call_count == 2

    assert args[0] == ['channel']
    assert args[1] == 'file'
    assert args[2] is None


def test_close_channel_with_name(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')

    # Arrange
    Slack.close_channel()

    close_args = slack.WebClient.api_call.call_args
    success_results = demisto.results.call_args[0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 1
    assert slack.WebClient.api_call.call_count == 1
    assert success_results[0] == 'Channel successfully archived.'
    assert close_args[0][0] == 'conversations.archive'
    assert close_args[1]['json']['channel'] == 'C012AB3CD'


def test_close_channel_should_delete_mirror(mocker):
    from Slack import close_channel
    # Set

    mirrors = js.loads(MIRRORS)
    mirrors.pop(0)

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(slack.WebClient, 'api_call')

    # Arrange
    close_channel()

    archive_args = slack.WebClient.api_call.call_args
    context_args = demisto.setIntegrationContext.call_args[0][0]
    context_args_mirrors = js.loads(context_args['mirrors'])

    # Assert
    assert archive_args[0][0] == 'conversations.archive'
    assert archive_args[1]['json']['channel'] == 'GKQ86DVPH'
    assert context_args_mirrors == mirrors


def test_close_channel_should_delete_mirrors(mocker):
    from Slack import close_channel
    # Set

    mirrors = js.loads(MIRRORS)
    mirrors.pop(1)
    mirrors.pop(1)

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '684'})
    mocker.patch.object(slack.WebClient, 'api_call')

    # Arrange
    close_channel()

    archive_args = slack.WebClient.api_call.call_args
    context_args = demisto.setIntegrationContext.call_args[0][0]
    context_args_mirrors = js.loads(context_args['mirrors'])

    # Assert
    assert archive_args[0][0] == 'conversations.archive'
    assert archive_args[1]['json']['channel'] == 'GKB19PA3V'
    assert context_args_mirrors == mirrors


def test_get_conversation_by_name_paging(mocker):
    from Slack import get_conversation_by_name
    # Set

    def api_call(method: str, http_verb: str = 'POST', file: dict = None, params=None, json=None, data=None):
        if method == 'conversations.list':
            if len(params) == 2:
                return {'channels': js.loads(CONVERSATIONS), 'response_metadata': {
                    'next_cursor': 'dGVhbTpDQ0M3UENUTks='
                }}
            else:
                return {'channels': [{
                    'id': 'C248918AB',
                    'name': 'lulz'
                }], 'response_metadata': {
                    'next_cursor': ''
                }}

    mocker.patch.object(slack.WebClient, 'api_call', side_effect=api_call)

    # Arrange
    channel = get_conversation_by_name('lulz')
    args = slack.WebClient.api_call.call_args_list
    first_args = args[0][1]
    second_args = args[1][1]

    # Assert
    assert args[0][0][0] == 'conversations.list'
    assert len(first_args['params']) == 2
    assert first_args['params']['limit'] == 200
    assert len(second_args['params']) == 3
    assert second_args['params']['cursor'] == 'dGVhbTpDQ0M3UENUTks='
    assert channel['id'] == 'C248918AB'
    assert slack.WebClient.api_call.call_count == 2


def test_send_file_no_args_investigation(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'path', 'name': 'name'})
    mocker.patch('builtins.open', mock_open(read_data="data"))
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(Slack, 'slack_send_request', return_value='cool')

    # Arrange
    Slack.slack_send_file()

    send_args = Slack.slack_send_request.call_args
    success_results = demisto.results.call_args[0]

    # Assert
    assert Slack.slack_send_request.call_count == 1
    assert success_results[0] == 'File sent to Slack successfully.'

    assert send_args[0][1] == 'incident-681'
    assert send_args[1]['file'] == {
        'data': 'data',
        'name': 'name',
        'comment': ''
    }


def test_send_file_no_args_no_investigation(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'slack_send_request', return_value='cool')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        Slack.slack_send_file()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert Slack.slack_send_request.call_count == 0
    assert err_msg == 'Either a user, group or channel must be provided.'


def test_set_topic(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general', 'topic': 'ey'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')

    # Arrange
    Slack.set_channel_topic()

    send_args = slack.WebClient.api_call.call_args
    success_results = demisto.results.call_args[0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 1
    assert slack.WebClient.api_call.call_count == 1
    assert success_results[0] == 'Topic successfully set.'
    assert send_args[0][0] == 'conversations.setTopic'
    assert send_args[1]['json']['channel'] == 'C012AB3CD'
    assert send_args[1]['json']['topic'] == 'ey'


def test_set_topic_no_args_investigation(mocker):
    import Slack

    # Set

    new_mirror = {
        'channel_id': 'GKQ86DVPH',
        'channel_name': 'incident-681',
        'channel_topic': 'ey',
        'investigation_id': '681',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': True
    }

    mocker.patch.object(demisto, 'args', return_value={'topic': 'ey'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')

    # Arrange
    Slack.set_channel_topic()

    send_args = slack.WebClient.api_call.call_args
    success_results = demisto.results.call_args[0]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: '681' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 0
    assert slack.WebClient.api_call.call_count == 1
    assert success_results[0] == 'Topic successfully set.'
    assert send_args[0][0] == 'conversations.setTopic'
    assert send_args[1]['json']['channel'] == 'GKQ86DVPH'
    assert send_args[1]['json']['topic'] == 'ey'
    assert new_mirror == our_mirror


def test_set_topic_no_args_no_investigation(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'topic': 'ey'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '9999'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        Slack.set_channel_topic()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 0
    assert err_msg == 'Channel not found - the Demisto app needs to be a member of the channel in order to look it up.'


def test_invite_users(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general', 'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(Slack, 'invite_users_to_conversation')
    mocker.patch.object(demisto, 'results')

    # Arrange
    Slack.invite_to_channel()

    send_args = Slack.invite_users_to_conversation.call_args[0]
    success_results = demisto.results.call_args[0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 1
    assert Slack.invite_users_to_conversation.call_count == 1
    assert success_results[0] == 'Successfully invited users to the channel.'
    assert send_args[0] == 'C012AB3CD'
    assert send_args[1] == ['U012A3CDE', 'U07QCRPA4']


def test_invite_users_no_channel(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'GKQ86DVPH'})
    mocker.patch.object(Slack, 'invite_users_to_conversation')
    mocker.patch.object(demisto, 'results')

    # Arrange
    Slack.invite_to_channel()

    send_args = Slack.invite_users_to_conversation.call_args[0]
    success_results = demisto.results.call_args[0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 0
    assert Slack.invite_users_to_conversation.call_count == 1
    assert success_results[0] == 'Successfully invited users to the channel.'
    assert send_args[0] == 'GKQ86DVPH'
    assert send_args[1] == ['U012A3CDE', 'U07QCRPA4']


def test_invite_users_no_channel_doesnt_exist(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '777'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'GKQ86DVPH'})
    mocker.patch.object(Slack, 'invite_users_to_conversation')
    mocker.patch.object(demisto, 'results')

    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        Slack.invite_to_channel()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 0
    assert Slack.invite_users_to_conversation.call_count == 0
    assert err_msg == 'Channel not found - the Demisto app needs to be a member of the channel in order to look it up.'


def test_kick_users(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general', 'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(Slack, 'kick_users_from_conversation')
    mocker.patch.object(demisto, 'results')

    # Arrange
    Slack.kick_from_channel()

    send_args = Slack.kick_users_from_conversation.call_args[0]
    success_results = demisto.results.call_args[0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 1
    assert Slack.kick_users_from_conversation.call_count == 1
    assert success_results[0] == 'Successfully kicked users from the channel.'
    assert send_args[0] == 'C012AB3CD'
    assert send_args[1] == ['U012A3CDE', 'U07QCRPA4']


def test_kick_users_no_channel(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'GKQ86DVPH'})
    mocker.patch.object(Slack, 'kick_users_from_conversation')
    mocker.patch.object(demisto, 'results')

    # Arrange
    Slack.kick_from_channel()

    send_args = Slack.kick_users_from_conversation.call_args[0]
    success_results = demisto.results.call_args[0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 0
    assert Slack.kick_users_from_conversation.call_count == 1
    assert success_results[0] == 'Successfully kicked users from the channel.'
    assert send_args[0] == 'GKQ86DVPH'
    assert send_args[1] == ['U012A3CDE', 'U07QCRPA4']


def test_kick_users_no_channel_doesnt_exist(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '777'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'GKQ86DVPH'})
    mocker.patch.object(Slack, 'invite_users_to_conversation')
    mocker.patch.object(demisto, 'results')

    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        Slack.kick_from_channel()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 0
    assert Slack.invite_users_to_conversation.call_count == 0
    assert err_msg == 'Channel not found - the Demisto app needs to be a member of the channel in order to look it up.'


def test_rename_channel(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general', 'name': 'ey'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')

    # Arrange
    Slack.rename_channel()

    send_args = slack.WebClient.api_call.call_args
    success_results = demisto.results.call_args[0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 1
    assert slack.WebClient.api_call.call_count == 1
    assert success_results[0] == 'Channel renamed successfully.'
    assert send_args[0][0] == 'conversations.rename'
    assert send_args[1]['json']['channel'] == 'C012AB3CD'
    assert send_args[1]['json']['name'] == 'ey'


def test_rename_no_args_investigation(mocker):
    import Slack

    # Set

    new_mirror = {
        'channel_id': 'GKQ86DVPH',
        'channel_name': 'ey',
        'channel_topic': 'incident-681',
        'investigation_id': '681',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': True
    }

    mocker.patch.object(demisto, 'args', return_value={'name': 'ey'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')

    # Arrange
    Slack.rename_channel()

    send_args = slack.WebClient.api_call.call_args
    success_results = demisto.results.call_args[0]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: '681' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 0
    assert slack.WebClient.api_call.call_count == 1
    assert success_results[0] == 'Channel renamed successfully.'
    assert send_args[0][0] == 'conversations.rename'
    assert send_args[1]['json']['channel'] == 'GKQ86DVPH'
    assert send_args[1]['json']['name'] == 'ey'
    assert new_mirror == our_mirror


def test_rename_no_args_no_investigation(mocker):
    import Slack

    # Set

    mocker.patch.object(demisto, 'args', return_value={'name': 'ey'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '9999'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(Slack, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        Slack.rename_channel()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert Slack.get_conversation_by_name.call_count == 0
    assert err_msg == 'Channel not found - the Demisto app needs to be a member of the channel in order to look it up.'


def test_get_user(mocker):
    from Slack import get_user

    # Set

    mocker.patch.object(demisto, 'args', return_value={'user': 'spengler'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')

    # Arrange

    get_user()
    user_results = demisto.results.call_args[0]

    assert user_results[0]['EntryContext'] == {'Slack.User(val.ID === obj.ID)': {
        'ID': 'U012A3CDE',
        'Username': 'spengler',
        'Name': 'Egon Spengler',
        'DisplayName': 'spengler',
        'Email': 'spengler@ghostbusters.example.com',
    }}


def test_get_user_by_name_paging_rate_limit(mocker):
    from Slack import get_user_by_name, init_globals
    from slack.errors import SlackApiError
    from slack.web.slack_response import SlackResponse

    # Set
    init_globals()
    err_response: SlackResponse = SlackResponse(api_url='', client=None, http_verb='GET', req_args={},
                                                data={'ok': False}, status_code=429, headers={'Retry-After': 0.001})
    first_call = {'members': js.loads(USERS), 'response_metadata': {'next_cursor': 'dGVhbTpDQ0M3UENUTks='}}
    second_call = SlackApiError('Rate limit reached!', err_response)
    third_call = {'members': [{'id': 'U248918AB', 'name': 'alexios'}], 'response_metadata': {'next_cursor': ''}}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=[first_call, second_call, third_call])

    # Arrange
    user = get_user_by_name('alexios')
    args = slack.WebClient.api_call.call_args_list
    first_args = args[0][1]
    second_args = args[2][1]

    # Assert
    assert len(first_args['params']) == 1
    assert first_args['params']['limit'] == 200
    assert len(second_args['params']) == 2
    assert second_args['params']['cursor'] == 'dGVhbTpDQ0M3UENUTks='
    assert user['id'] == 'U248918AB'
    assert slack.WebClient.api_call.call_count == 3


def test_get_user_by_name_paging_rate_limit_error(mocker):
    from Slack import get_user_by_name, init_globals
    from slack.errors import SlackApiError
    from slack.web.slack_response import SlackResponse

    # Set
    init_globals()
    err_response: SlackResponse = SlackResponse(api_url='', client=None, http_verb='GET', req_args={},
                                                data={'ok': False}, status_code=429, headers={'Retry-After': 61})
    first_call = {'members': js.loads(USERS), 'response_metadata': {'next_cursor': 'dGVhbTpDQ0M3UENUTks='}}
    second_call = SlackApiError('Rate limit reached!', err_response)
    third_call = {'members': [{'id': 'U248918AB', 'name': 'alexios'}], 'response_metadata': {'next_cursor': ''}}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=[first_call, second_call, third_call])

    # Arrange
    with pytest.raises(SlackApiError):
        get_user_by_name('alexios')
    args = slack.WebClient.api_call.call_args_list
    first_args = args[0][1]

    # Assert
    assert len(first_args['params']) == 1
    assert first_args['params']['limit'] == 200
    assert slack.WebClient.api_call.call_count == 2


def test_get_user_by_name_paging_normal_error(mocker):
    from Slack import get_user_by_name, init_globals
    from slack.errors import SlackApiError
    from slack.web.slack_response import SlackResponse

    # Set
    init_globals()
    err_response: SlackResponse = SlackResponse(api_url='', client=None, http_verb='GET', req_args={},
                                                data={'ok': False}, status_code=500, headers={})
    first_call = {'members': js.loads(USERS), 'response_metadata': {'next_cursor': 'dGVhbTpDQ0M3UENUTks='}}
    second_call = SlackApiError('Whoops!', err_response)
    third_call = {'members': [{'id': 'U248918AB', 'name': 'alexios'}], 'response_metadata': {'next_cursor': ''}}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack.WebClient, 'api_call', side_effect=[first_call, second_call, third_call])

    # Arrange
    with pytest.raises(SlackApiError):
        get_user_by_name('alexios')
    args = slack.WebClient.api_call.call_args_list
    first_args = args[0][1]

    # Assert
    assert len(first_args['params']) == 1
    assert first_args['params']['limit'] == 200
    assert slack.WebClient.api_call.call_count == 2
